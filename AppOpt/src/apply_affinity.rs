use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::FileExt;
use std::sync::Mutex;

use crate::{diag, lock_ignore_poison, MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::config::AppConfig;
use crate::cpuset::{base_cpuset, create_cpuset_dir, CpuSet, CpuTopology};

/// 栈上构建 /proc/{pid}/{suffix} 路径读取文件
fn read_proc_file<'a>(pid: i32, suffix: &str, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    let mut path = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut path[..]);
    write!(cur, "/proc/{}/{}", pid, suffix).ok()?;
    let len = cur.position() as usize;
    let path_str = std::str::from_utf8(&path[..len]).ok()?;
    let file = fs::File::open(path_str).ok()?;
    let n = file.read_at(buf, 0).ok()?;
    (n > 0).then_some(&buf[..n])
}

pub(crate) fn read_cmdline(pid: i32) -> Option<String> {
    let mut buf = [0u8; MAX_PKG_LEN];
    let bytes = read_proc_file(pid, "cmdline", &mut buf)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let cmdline = std::str::from_utf8(&bytes[..end]).ok()?;
    let name = cmdline.rsplit('/').next().unwrap_or(cmdline);
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub(crate) fn tid_comm(tid: i32) -> Option<String> {
    let mut buf = [0u8; MAX_THREAD_LEN];
    let bytes = read_proc_file(tid, "comm", &mut buf)?;
    let end = bytes
        .iter()
        .position(|&b| b == 0 || b == b'\n')
        .unwrap_or(bytes.len());
    let name = std::str::from_utf8(&bytes[..end]).ok()?;
    Some(name.trim().to_string())
}

pub(crate) fn task_tids(pid: i32) -> Option<Vec<i32>> {
    let mut path_buf = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut path_buf[..]);
    write!(cur, "/proc/{}/task", pid).ok()?;
    let len = cur.position() as usize;
    let task_path = std::str::from_utf8(&path_buf[..len]).unwrap();
    let task_dir = fs::read_dir(task_path).ok()?;
    Some(
        task_dir
            .flatten()
            .filter_map(|tent| tent.file_name().to_string_lossy().parse::<i32>().ok())
            .collect(),
    )
}

/// 已就绪的 cpuset 子目录名。目录名由 CPU 集合派生，建成后内容不变，
/// 每个线程每次命中都重复 mkdir/chmod/chown/写 cpus+mems 是纯浪费（5 次系统调用）
static READY_DIRS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// 判断子目录是否就绪，未就绪则创建一次；base cpuset 由 init_cpu_topo 负责，不在此重建
fn dir_ready(dir: &str, topo: &CpuTopology) -> bool {
    if dir.is_empty() {
        return true;
    }
    let mut guard = lock_ignore_poison(&READY_DIRS);
    let ready = guard.get_or_insert_with(HashSet::new);
    if ready.contains(dir) {
        return true;
    }
    let path = format!("{}/{}", base_cpuset(), dir);
    if create_cpuset_dir(&path, dir, &topo.mems_str) {
        ready.insert(dir.to_string());
        true
    } else {
        false
    }
}

/// 目录被外部删除后失效缓存，下次事件重建
fn dir_invalidate(dir: &str) {
    if dir.is_empty() {
        return;
    }
    let mut guard = lock_ignore_poison(&READY_DIRS);
    if let Some(ready) = guard.as_mut() {
        ready.remove(dir);
    }
}

/// base cpuset 改名后旧路径全部失效
pub fn reset_cpuset_dir_cache() {
    let mut guard = lock_ignore_poison(&READY_DIRS);
    if let Some(ready) = guard.as_mut() {
        ready.clear();
    }
}

/// 把 tid 挂到 cpuset 子目录，目录缺失时重建一次（外部删除兜底）。
/// 失败原因必须带出去：cpuset 写不进去时只剩 sched_setaffinity 兜底，
/// 这往往就是「有时绑得住、有时绑不住」的那一半
fn write_task(dir: &str, tid: i32, topo: &CpuTopology) -> Result<(), i32> {
    let base = base_cpuset();
    let path = if dir.is_empty() {
        format!("{}/tasks", base)
    } else {
        format!("{}/{}/tasks", base, dir)
    };
    let append = |p: &str| {
        fs::OpenOptions::new()
            .append(true)
            .open(p)
            .and_then(|mut f| writeln!(f, "{}", tid))
    };
    let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(0);

    // base 目录由 init_cpu_topo 负责，这里只追加 tasks
    if dir.is_empty() {
        return append(&path).map_err(errno);
    }
    if !dir_ready(dir, topo) {
        // 建不出目录（只读/权限），按原行为仅靠 sched_setaffinity
        return Err(0);
    }
    if append(&path).is_ok() {
        return Ok(());
    }
    // 目录被外部删除：先失效再重建一次，重建后补写
    dir_invalidate(dir);
    if dir_ready(dir, topo) {
        append(&path).map_err(errno)
    } else {
        Err(0)
    }
}

/// 亲和性写入结果。必须把「线程已退出」和「设置失败」分开：
/// 前者要清理状态，后者必须保留旧状态，绝不能当成迁移成功
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AffinityOutcome {
    /// 内核已接受该集合，或线程本来就在目标集合上（短路）
    Set,
    /// ESRCH：线程已退出，调用方应清理缓存与调度状态
    Gone,
    /// EPERM、EINVAL 等：亲和性未改变，调用方不得提交新状态
    Failed,
}

/// 写入原因。诊断需要把「规则重扫」「定期校验」「S7 迁移」分开计数，
/// 否则 once 一个失败，根本不知道是哪条路径在写
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApplyReason {
    Rule,
    Sync,
    Sched,
}

/// 对单线程应用亲和性。cpuset 目录只是辅助手段，成败以内核返回为准。
/// 返回 `(结果, 是否真的写入)`：短路的「已一致」不算写入，
/// 定期校验可以据此判断线程是否被外部改写
pub fn affinity_apply(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: Option<&str>,
    topo: &CpuTopology,
    reason: ApplyReason,
    comm: &str,
) -> (AffinityOutcome, bool) {
    // sched_getaffinity 短路，已符合目标零开销返回
    if let Some(curr) = CpuSet::get_affinity(tid)
        && curr == *cpus
    {
        diag::note(reason, &AffinityOutcome::Set, false);
        return (AffinityOutcome::Set, false);
    }
    // None 表示这条路径明确不碰 cpuset（S7 迁移）。cgroup 迁移比
    // sched_setaffinity 重得多，每次动态迁移都做一遍只会放大抖动
    if topo.cpuset_enabled
        && let Some(dir) = cpuset_dir
        && let Err(e) = write_task(dir, tid, topo)
    {
        diag::note_cpuset_failure(
            if dir.is_empty() { "<base>" } else { dir },
            (e != 0).then_some(e),
        );
    }
    match cpus.set_affinity(tid) {
        Ok(()) => {
            diag::note(reason, &AffinityOutcome::Set, true);
            (AffinityOutcome::Set, true)
        }
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(0);
            if errno == libc::ESRCH {
                diag::note(reason, &AffinityOutcome::Gone, false);
                (AffinityOutcome::Gone, false)
            } else {
                diag::note(reason, &AffinityOutcome::Failed, false);
                diag::note_failure(tid, comm, cpus, errno);
                (AffinityOutcome::Failed, false)
            }
        }
    }
}


/// 遍历 /proc 匹配目标进程，返回 匹配数与总进程数。
/// 是否读线程名交给调用方用 `cfg.needs_comm` 判断，这里不再传旧的包级标记
pub(crate) fn proc_walk(
    cfg: &AppConfig,
    filter: impl Fn(i32) -> bool,
    mut f: impl FnMut(i32, &str),
) -> (usize, i32) {
    let Some(entries) = fs::read_dir("/proc").ok() else { return (0, 0) };
    let mut count = 0;
    let mut total: i32 = 0;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
        total += 1;
        if !filter(pid) { continue; }
        let Some(pkg) = read_cmdline(pid).or_else(|| tid_comm(pid)) else { continue };
        if !cfg.pkgs.contains(&pkg) { continue; }
        f(pid, &pkg);
        count += 1;
    }
    (count, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内核 pid_max 上限 4194304，更大的 tid 必然不存在
    const GHOST: i32 = 2_000_000_000;

    fn self_tid() -> i32 {
        unsafe { libc::syscall(libc::SYS_gettid) as i32 }
    }

    /// 已经符合目标集合时短路返回，不产生任何系统调用
    #[test]
    fn matching_set_short_circuits_to_set() {
        let topo = CpuTopology::empty();
        let tid = self_tid();
        let curr = CpuSet::get_affinity(tid).expect("读取自身亲和性失败");
        assert_eq!(
            affinity_apply(tid, &curr, None, &topo, ApplyReason::Rule, "").0,
            AffinityOutcome::Set
        );
    }

    /// EINVAL 等失败必须如实报告，不能被当成设置成功
    #[test]
    fn invalid_set_is_reported_as_failed() {
        let topo = CpuTopology::empty();
        let tid = self_tid();
        // 空集合对内核是非法参数（EINVAL），不会改变当前亲和性
        assert_eq!(
            affinity_apply(tid, &CpuSet::new(), None, &topo, ApplyReason::Rule, "").0,
            AffinityOutcome::Failed
        );
    }

    /// 线程已退出与设置失败要分开，前者要清状态
    #[test]
    fn vanished_thread_is_reported_as_gone() {
        let topo = CpuTopology::empty();
        let mut one = CpuSet::new();
        one.set(0);
        assert_eq!(
            affinity_apply(GHOST, &one, None, &topo, ApplyReason::Rule, "").0,
            AffinityOutcome::Gone
        );
    }
}
