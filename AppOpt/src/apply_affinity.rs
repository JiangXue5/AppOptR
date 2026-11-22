use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::FileExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology, base_cpuset, create_cpuset_dir};
use crate::{MAX_PKG_LEN, MAX_THREAD_LEN, diag, lock_ignore_poison};

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

/// 进程的 real uid。`/proc/<pid>` 目录属主就是它，一次 stat 即可；
/// dumpable=0 的进程属主会变成 root，此时按「非应用进程」放行，方向是保守的
pub(crate) fn proc_uid(pid: i32) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(format!("/proc/{}", pid)).ok().map(|m| m.uid())
}

/// 包名是否真属于这个进程。`cmdline` 与 `comm` 都是进程自己写的，改个名字就能
/// 蹭到目标游戏的大核规则，甚至按 `@rt` 拿到 SCHED_RR。包目录的属主由 installd
/// 建立、应用本身改不了，用它做交叉校验。
///
/// 判定不了时（读不到 uid、包目录不存在、系统进程）返回 true：这是一道加分项，
/// 不能因为某个 ROM 目录布局不同就把正常应用全部拒掉
pub(crate) fn pkg_owned(pid: i32, pkg: &str) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Some(uid) = proc_uid(pid) else {
        return true;
    };
    // 10000 以下是非应用 uid（root/system/shell），不参与包名匹配
    if uid < 10_000 {
        return true;
    }
    // 多用户：uid = userId * 100000 + appId，包目录在 /data/user/<userId>/ 下
    let path = format!("/data/user/{}/{}", uid / 100_000, pkg);
    match fs::metadata(&path) {
        Ok(md) => md.uid() == uid,
        Err(_) => true,
    }
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

/// 连续失败多少次后暂停尝试
const CPUSET_TRIP_FAILS: u32 = 3;
/// 首次暂停时长。半开放行一次试探，避免设备只是短暂异常就永久放弃 cpuset
const CPUSET_PAUSE: Duration = Duration::from_secs(120);
/// 暂停上限：真机上「组不可用」是静态事实，每分钟试探一次纯属噪音，
/// 退到 10 分钟一次，既保留自愈能力又不占日志
const CPUSET_PAUSE_MAX: Duration = Duration::from_secs(600);

struct Breaker {
    fails: u32,
    until: Option<Instant>,
    tripped: bool,
    /// 已经熔断过几次。每多一次，暂停时长翻倍
    trips: u32,
}

impl Breaker {
    const fn new() -> Self {
        Self {
            fails: 0,
            until: None,
            tripped: false,
            trips: 0,
        }
    }

    /// 本轮应暂停多久：120 s → 240 → 480 → 600 封顶。
    /// 半开再失败说明不是瞬时抖动，缩短间隔只会持续撞同一个失败路径
    fn pause(&self) -> Duration {
        let secs = CPUSET_PAUSE.as_secs() << self.trips.min(3);
        Duration::from_secs(secs.min(CPUSET_PAUSE_MAX.as_secs()))
    }

    /// 是否允许再尝试写 cpuset。暂停到期后放行一次（半开），成功则彻底恢复
    fn gate(&mut self, now: Instant) -> bool {
        match self.until {
            Some(t) if now < t => false,
            Some(_) => {
                self.until = None;
                true
            }
            None => true,
        }
    }

    /// 记一次失败，返回是否需要打熔断日志（只在首次熔断时）
    fn failed(&mut self, now: Instant) -> bool {
        self.fails = self.fails.saturating_add(1);
        if self.fails < CPUSET_TRIP_FAILS {
            return false;
        }
        // 半开试探再失败只延长暂停，不重复刷同一条熔断日志
        let announce = !self.tripped;
        self.tripped = true;
        let pause = self.pause();
        self.trips = self.trips.saturating_add(1);
        self.until = Some(now + pause);
        announce
    }

    fn ok(&mut self) {
        *self = Self::new();
    }

    fn paused(&self, now: Instant) -> bool {
        self.until.is_some_and(|t| now < t)
    }
}

static BREAKER: Mutex<Breaker> = Mutex::new(Breaker::new());

fn cpuset_gate() -> bool {
    lock_ignore_poison(&BREAKER).gate(Instant::now())
}

fn cpuset_ok() {
    lock_ignore_poison(&BREAKER).ok();
}

fn cpuset_failed(err: Option<i32>) {
    let mut b = lock_ignore_poison(&BREAKER);
    let announce = b.failed(Instant::now());
    let pause = b.pause();
    drop(b);
    if announce {
        diag::note_cpuset_tripped(err, CPUSET_TRIP_FAILS, pause);
    }
}

/// cpuset 是否处于熔断暂停中，供摘要行说明「没在重试」而不是「没失败」
pub fn cpuset_paused() -> bool {
    lock_ignore_poison(&BREAKER).paused(Instant::now())
}

/// 写进去又被裁掉的线程。这类线程每轮都会「读回不一致 → 再写 → 还是不一致」，
/// 几百个线程反复迁移会持续打断正在跑渲染的核，是 S7 之外最大的抖动源。
/// 对它们暂停重绑，保留内核当前值，等 cpuset 侧修好或线程重建
pub(crate) const STUCK_PAUSE: Duration = Duration::from_secs(300);
const STUCK_CAP: usize = 2048;

static STUCK: Mutex<Option<std::collections::HashMap<i32, Instant>>> = Mutex::new(None);

fn stuck_hit(tid: i32) -> bool {
    let mut guard = lock_ignore_poison(&STUCK);
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    match map.get(&tid) {
        Some(&until) if Instant::now() < until => true,
        Some(_) => {
            map.remove(&tid);
            false
        }
        None => false,
    }
}

fn stuck_mark(tid: i32) {
    let mut guard = lock_ignore_poison(&STUCK);
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    if map.len() >= STUCK_CAP {
        let now = Instant::now();
        map.retain(|_, &mut until| until > now);
    }
    map.insert(tid, Instant::now() + STUCK_PAUSE);
}

/// 被暂停重绑的线程数，Web 诊断展示用
pub fn stuck_count() -> usize {
    let guard = lock_ignore_poison(&STUCK);
    let now = Instant::now();
    guard
        .as_ref()
        .map(|m| m.values().filter(|&&until| until > now).count())
        .unwrap_or(0)
}

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

/// 线程当前所在的 cpuset 目录（绝对路径）。cgroup 里记录的是相对层级根的路径，
/// Android 把 cpuset 层级挂在 `/dev/cpuset`，所以 `/background` 要补前缀
fn cgroup_dir(tid: i32) -> Option<String> {
    // 线程同时属于多个子系统，每行一个；512 字节在层数多时会截断
    let mut buf = [0u8; 1024];
    let bytes = read_proc_file(tid, "cgroup", &mut buf)?;
    let s = std::str::from_utf8(bytes).ok()?;
    for line in s.lines() {
        let mut it = line.splitn(3, ':');
        let _ = it.next()?;
        let ctrl = it.next()?;
        let path = it.next()?.trim();
        if !ctrl.split(',').any(|c| c == "cpuset") {
            continue;
        }
        if path == "/" || path.is_empty() {
            return Some("/dev/cpuset".to_string());
        }
        return Some(if path.starts_with("/dev/cpuset/") {
            path.to_string()
        } else {
            format!("/dev/cpuset{}", path)
        });
    }
    None
}

/// 把 tid 挂到 cpuset 子目录，目录缺失时重建一次（外部删除兜底）。
/// 失败原因必须带出去：cpuset 写不进去时只剩 sched_setaffinity 兜底，
/// 这往往就是「有时绑得住、有时绑不住」的那一半
fn write_task(dir: &str, tid: i32, topo: &CpuTopology) -> Result<(), CpusetFail> {
    let base = base_cpuset();
    let path = if dir.is_empty() {
        format!("{}/tasks", base)
    } else {
        format!("{}/{}/tasks", base, dir)
    };
    // 必须一次性写完整数字：带换行会被内核当成两段，第二段（只有 `\n`）
    // 直接被判 EINVAL，于是「已经迁进去了」被读成「EINVAL 失败」
    let append = |p: &str| crate::cpuset::attach_task(p, tid);
    let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(0);

    // base 目录由 init_cpu_topo 负责，这里只追加 tasks
    if dir.is_empty() {
        return append(&path).map_err(|e| CpusetFail::Base(errno(e)));
    }
    if !dir_ready(dir, topo) {
        // 建不出目录（只读/权限），按原行为仅靠 sched_setaffinity
        return Err(CpusetFail::NoDir);
    }
    let first = match append(&path) {
        Ok(()) => return Ok(()),
        Err(e) => errno(e),
    };
    // 目录被外部删除：先失效再重建一次，重建后补写
    if first == libc::ENOENT {
        dir_invalidate(dir);
        return if dir_ready(dir, topo) {
            append(&path).map_err(|e| CpusetFail::Target(errno(e)))
        } else {
            Err(CpusetFail::NoDir)
        };
    }
    // EINVAL 不是权限问题：内核 cpuset_can_attach 要求线程「当前允许的 CPU」
    // 与目标组的生效集合有交集，否则直接拒绝。线程被系统放在 background(0-3)、
    // 规则却要 4-6 时交集为空，写一万次都是 EINVAL。
    // 先写 base（全核，与任何线程都有交集，必然成功）把线程抬出来，
    // 第二次写目标组就有交集了。中间是毫秒级窗口，好过一直绑不上
    if first == libc::EINVAL {
        // 连 base 都失败，说明问题在挂载或权限，与目标集合无关；
        // 这一区分决定了用户该改规则还是改模块安装方式
        // 先记下原组，目标组仍失败时要能原路退回
        let orig = cgroup_dir(tid);
        if append(&format!("{}/tasks", base)).is_err() {
            return Err(CpusetFail::Base(first));
        }
        return match append(&path) {
            Ok(()) => Ok(()),
            Err(e) => {
                // 抬到 base 之后目标组还是写不进去：必须把线程写回原组。
                // 否则它就一直留在全核 base 上，等于绕过系统对后台线程的限制，
                // 比「没绑上」更糟
                if let Some(o) = orig.filter(|o| *o != base) {
                    let _ = append(&format!("{}/tasks", o));
                }
                Err(CpusetFail::Target(errno(e)))
            }
        };
    }
    Err(CpusetFail::Target(first))
}

/// cpuset 写入失败的三种形态。它们的处理方式完全不同，混成一句
/// 「写入失败」等于什么都没说：
/// - `NoDir`：模块没权限建组，重试无用，只能改安装或 SELinux
/// - `Base`：连全核 base 都写不进去，是挂载/权限问题
/// - `Target`：base 成功而目标组仍拒绝，说明该组的生效集合为空，
///   或与线程原组无交集——改规则或迁出原组才有出路
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CpusetFail {
    NoDir,
    Base(i32),
    Target(i32),
}

impl CpusetFail {
    pub(crate) fn errno(self) -> Option<i32> {
        match self {
            CpusetFail::NoDir => None,
            CpusetFail::Base(e) | CpusetFail::Target(e) => Some(e),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            CpusetFail::NoDir => "目录未建成（权限或只读挂载）",
            CpusetFail::Base(_) => "连 base 全核都写不进去（挂载或权限）",
            CpusetFail::Target(_) => "已抬到 base 组，目标组仍拒绝（生效集合为空或与原组无交集）",
        }
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
    // 上一轮已经证明「写进去也会被裁」，这一轮别再动它：
    // 反复迁移只会把线程在簇之间踢来踢去
    if reason == ApplyReason::Sync && stuck_hit(tid) {
        diag::note_stuck();
        return (AffinityOutcome::Set, false);
    }
    // sched_getaffinity 短路，已符合目标零开销返回
    if let Some(curr) = CpuSet::get_affinity(tid) {
        if curr == *cpus {
            diag::note(reason, &AffinityOutcome::Set, false);
            return (AffinityOutcome::Set, false);
        }
        // 只有定期校验能说明「绑定没坏、是被别人改回去了」。
        // 记下期望/实际/所在 cpuset，才能区分被 cpuset 裁剪和被整体重置
        if reason == ApplyReason::Sync {
            diag::note_drift(tid, comm, cpus, &curr);
        }
    }
    // None 表示这条路径明确不碰 cpuset（S7 迁移）。cgroup 迁移比
    // sched_setaffinity 重得多，每次动态迁移都做一遍只会放大抖动
    if topo.cpuset_enabled
        && let Some(dir) = cpuset_dir
        && cpuset_gate()
    {
        match write_task(dir, tid, topo) {
            Ok(()) => cpuset_ok(),
            Err(f) => {
                diag::note_cpuset_failure(tid, if dir.is_empty() { "<base>" } else { dir }, f);
                // 只有全局性失败才计入熔断。`Target(EINVAL)` 是单个线程与目标组
                // 无交集（规则要 4-6、线程被压在 0-3），几十个线程各撞一次就把
                // 整条 cpuset 通道停 2 分钟，是明显的误伤
                if !matches!(f, CpusetFail::Target(_)) {
                    cpuset_failed(f.errno());
                }
            }
        }
    }
    match cpus.set_affinity(tid) {
        Ok(()) => {
            diag::note(reason, &AffinityOutcome::Set, true);
            // 定期校验必须回读确认：内核返回 0 不代表生效，cpuset 会把
            // 写入的集合和 effective_cpus 求交，交集不足时下一次读回还是旧值
            if reason == ApplyReason::Sync
                && let Some(after) = CpuSet::get_affinity(tid)
                && after != *cpus
            {
                stuck_mark(tid);
                diag::note_ineffective(tid, comm, cpus, &after);
            }
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
    let Some(entries) = fs::read_dir("/proc").ok() else {
        return (0, 0);
    };
    let mut count = 0;
    let mut total: i32 = 0;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        total += 1;
        if !filter(pid) {
            continue;
        }
        let Some(pkg) = read_cmdline(pid).or_else(|| tid_comm(pid)) else {
            continue;
        };
        if !cfg.pkgs.contains(&pkg) {
            continue;
        }
        // 名字可以自己改，属主不能。放在 here 而不是匹配函数里，
        // 是因为这条路径要拿 pid 才能校验
        if !pkg_owned(pid, &pkg) {
            continue;
        }
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

    /// 身份校验是加分项：判不了的情况必须放行，不能因为某个 ROM 目录布局不同
    /// 就把正常应用全部拒掉
    #[test]
    fn pkg_owned_fails_open_when_unknown() {
        let pid = std::process::id() as i32;
        // 测试进程是 root（uid < 10000），不参与包名校验
        assert!(proc_uid(pid).is_some());
        assert!(pkg_owned(pid, "com.example.anything"));
        // 不存在的 pid 读不到 uid，同样放行
        assert!(pkg_owned(GHOST, "com.example.anything"));
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

    /// 熔断必须「第三次失败才播报、暂停期满半开、半开再失败不重复刷屏」
    #[test]
    fn breaker_trips_after_three_failures_and_recovers() {
        let mut b = Breaker::new();
        let t0 = Instant::now();
        assert!(b.gate(t0));
        assert!(!b.failed(t0));
        assert!(!b.failed(t0));
        assert!(b.failed(t0), "第三次失败才熔断并播报");
        assert!(!b.gate(t0));
        assert!(b.paused(t0));

        // 暂停期满放行一次试探
        let later = t0 + CPUSET_PAUSE + Duration::from_secs(1);
        assert!(b.gate(later));
        // 试探再失败：重新计时，但不重复播报同一条熔断日志
        assert!(!b.failed(later));
        assert!(b.paused(later));

        // 成功一次即彻底恢复
        b.ok();
        assert!(b.gate(later));
        assert!(!b.paused(later));
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
