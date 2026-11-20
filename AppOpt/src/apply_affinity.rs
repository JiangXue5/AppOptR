use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::FileExt;
use std::sync::Mutex;

use crate::{lock_ignore_poison, MAX_PKG_LEN, MAX_THREAD_LEN};
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

/// 把 tid 挂到 cpuset 子目录，目录缺失时重建一次（外部删除兜底）
fn write_task(dir: &str, tid: i32, topo: &CpuTopology) {
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
            .is_ok()
    };

    // base 目录由 init_cpu_topo 负责，这里只追加 tasks
    if dir.is_empty() {
        let _ = append(&path);
        return;
    }
    if !dir_ready(dir, topo) {
        // 建不出目录（只读/权限），按原行为仅靠 sched_setaffinity
        return;
    }
    if append(&path) {
        return;
    }
    // 目录被外部删除：先失效再重建一次，重建后补写
    dir_invalidate(dir);
    if dir_ready(dir, topo) {
        let _ = append(&path);
    }
}

/// 对单线程应用亲和性，返回 true 表示 ESRCH 线程已退出
pub fn affinity_set(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    topo: &CpuTopology,
) -> bool {
    // sched_getaffinity 短路，已符合目标零开销返回
    if let Some(curr) = CpuSet::get_affinity(tid)
        && curr == *cpus {
            return false;
        }
    if topo.cpuset_enabled {
        write_task(cpuset_dir, tid, topo);
    }
    if let Err(e) = cpus.set_affinity(tid) {
        return e.raw_os_error() == Some(libc::ESRCH);
    }

    false
}

/// 遍历 /proc 匹配目标进程，返回 匹配数与总进程数
pub(crate) fn proc_walk(
    cfg: &AppConfig,
    filter: impl Fn(i32) -> bool,
    mut f: impl FnMut(i32, &str, bool),
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
        f(pid, &pkg, cfg.has_thread_rules.contains(&pkg));
        count += 1;
    }
    (count, total)
}
