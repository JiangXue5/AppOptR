use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

use crate::apply_affinity::{AffinityOutcome, proc_walk, read_cmdline, task_tids, tid_comm};
use crate::cache::ProcCache;
use crate::config::AppConfig;
use crate::rt;

/// 全量校验周期：兜底 PID 复用、tid 复用与差分漏检
const FULL_CHECK: Duration = Duration::from_secs(60);
/// 每轮重读 comm 的线程数。引擎通常在创建线程后才改名，而 /proc 模式
/// 没有 rename 事件；发现线程时若还没命名，线程规则就会永远落不上。
/// 按游标轮转，常见规模（<200 线程）几轮内覆盖一遍
const COMM_RECHECK: usize = 32;

pub struct ProcScanState {
    pub cache: ProcCache,
    /// 被管理 pid 到包名，用于增量线程发现与进程退出清理
    pub tracked_pids: HashMap<i32, String>,
    /// 上一轮 /proc PID 快照，用于差分
    pub known_pids: HashSet<i32>,
    /// 已评估过的 tid 及其归属 pid，避免每轮重复读取 comm 与重复决策
    pub known_tids: HashMap<i32, i32>,
    pub force_affinity: bool,
    /// 请求一次全量重建（配置变更、模式切换、eBPF 回退）
    pub rescan_all: bool,
    last_full: Instant,
    /// comm 轮转抽查游标
    recheck_cursor: usize,
}

impl ProcScanState {
    pub fn new() -> Self {
        Self {
            cache: ProcCache::new(),
            tracked_pids: HashMap::new(),
            known_pids: HashSet::new(),
            known_tids: HashMap::new(),
            force_affinity: true,
            rescan_all: true,
            last_full: Instant::now(),
            recheck_cursor: 0,
        }
    }

    pub fn request_full_scan(&mut self) {
        self.rescan_all = true;
        self.force_affinity = true;
    }
}

/// 单轮扫描。全量校验走完整 /proc；其余轮次只处理新增 PID 与已跟踪进程的新线程，
/// 不再用系统线程总数变化推测新进程（该字段是线程数，轻量进程会被漏掉）
pub fn cache_sync(cfg: &AppConfig, state: &mut ProcScanState) {
    if state.rescan_all || state.last_full.elapsed() >= FULL_CHECK {
        proc_scan(cfg, state);
        return;
    }

    let current = read_pid_set();

    let new_pids: Vec<i32> = current
        .iter()
        .filter(|pid| !state.known_pids.contains(pid))
        .copied()
        .collect();
    let gone_pids: Vec<i32> = state
        .known_pids
        .iter()
        .filter(|pid| !current.contains(pid))
        .copied()
        .collect();

    // 只有新增 PID 需要读 cmdline，未变化的进程不再解析包名
    for pid in new_pids {
        let Some(pkg) = read_cmdline(pid).or_else(|| tid_comm(pid)) else {
            continue;
        };
        if !cfg.pkgs.contains(&pkg) {
            continue;
        }
        state.tracked_pids.insert(pid, pkg.clone());
        if proc_tasks(pid, &pkg, cfg.needs_comm(&pkg), cfg, state) > 0 {
            state.force_affinity = true;
        }
    }

    for pid in gone_pids {
        state.tracked_pids.remove(&pid);
        state.cache.purge_pid(pid);
        state.known_tids.retain(|_, owner| *owner != pid);
        rt::release_pid(pid);
    }

    // 已跟踪进程的新线程：新线程会在创建后立刻命名，需在下一个周期内纳入管理。
    // 这里必须用 needs_comm 而不是 has_thread_rules：只有包级规则的应用
    // 也可能启用 S7 / RT，同样要发现新线程
    for pid in discover_targets(&state.tracked_pids, cfg) {
        let Some(pkg) = state.tracked_pids.get(&pid).cloned() else {
            continue;
        };
        if proc_tasks(pid, &pkg, cfg.needs_comm(&pkg), cfg, state) > 0 {
            state.force_affinity = true;
        }
    }

    state.known_pids = current;
    recheck_names(cfg, state);
}

/// 轮转重读线程名，补上没有 rename 事件时漏掉的改名。
/// 只读 comm 与规则重算，不在扫描线程里直接写亲和性，避免双写竞争
fn recheck_names(cfg: &AppConfig, state: &mut ProcScanState) {
    let mut tids: Vec<i32> = state.known_tids.keys().copied().collect();
    if tids.is_empty() {
        return;
    }
    tids.sort_unstable();
    let total = tids.len();
    let n = total.min(COMM_RECHECK);
    let start = state.recheck_cursor % total;
    state.recheck_cursor = (start + n) % total;

    let mut changed = 0;
    for k in 0..n {
        let tid = tids[(start + k) % total];
        let Some(&pid) = state.known_tids.get(&tid) else {
            continue;
        };
        let Some(e) = state.cache.tasks.get(&tid) else {
            continue;
        };
        let pkg = e.pkg.clone();
        let Some(comm) = tid_comm(tid) else { continue };
        if comm == e.comm {
            continue;
        }
        if state
            .cache
            .task_apply(tid, pid, &pkg, &comm, cfg, |_, _, _, _| {
                AffinityOutcome::Failed
            })
        {
            changed += 1;
            if let Some(e) = state.cache.tasks.get(&tid) {
                rt::note(tid, pid, &e.pkg, &e.comm, &e.cpus, cfg);
            }
        } else if let Some(e) = state.cache.tasks.get_mut(&tid) {
            // 改名后没命中任何规则：亲和性保持不变，但名字要更新，
            // 否则 S7 角色判定会一直拿旧名字当 Unknown
            e.comm = comm;
        }
    }
    if changed > 0 {
        state.force_affinity = true;
    }
}

/// 需要每轮发现新线程的进程：只有消费线程名的功能（线程规则 / S7 / RT）
/// 启用时才需要。纯包级绑定靠继承与 affinity_sync 维持，不必逐轮遍历 task
fn discover_targets(tracked: &HashMap<i32, String>, cfg: &AppConfig) -> Vec<i32> {
    tracked
        .iter()
        .filter(|(_, pkg)| cfg.needs_comm(pkg))
        .map(|(&pid, _)| pid)
        .collect()
}

/// 全量重建：清空缓存与跟踪状态后遍历 /proc
fn proc_scan(cfg: &AppConfig, state: &mut ProcScanState) {
    let current = read_pid_set();
    state.cache.clear();
    state.tracked_pids.clear();
    state.known_tids.clear();

    let _ = proc_walk(
        cfg,
        |_| true,
        |pid, pkg| {
            state.tracked_pids.insert(pid, pkg.to_string());
            proc_tasks(pid, pkg, cfg.needs_comm(pkg), cfg, state);
        },
    );

    state.known_pids = current;
    state.rescan_all = false;
    state.last_full = Instant::now();
    state.force_affinity = true;
    // 缓存已重建，再对账 RT：进程在扫描窗口内退出、包被移出配置时，
    // 旧的 RT 记录不能留着。仍符合条件的线程不受影响
    rt::reconcile(cfg, &state.cache);
}

fn read_pid_set() -> HashSet<i32> {
    let mut set = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                set.insert(pid);
            }
        }
    }
    set
}

/// 扫描 task 下 tid 仅填充缓存，返回新纳入的 tid 数
/// 已评估过的 tid 直接跳过，避免每轮重复读取 comm 与重复规则决策
fn proc_tasks(
    pid: i32,
    pkg: &str,
    need_comm: bool,
    cfg: &AppConfig,
    state: &mut ProcScanState,
) -> usize {
    let Some(tids) = task_tids(pid) else { return 0 };
    let mut added = 0;
    for tid in tids {
        if state.known_tids.insert(tid, pid).is_some() {
            continue;
        }
        let thread_name = if need_comm {
            tid_comm(tid).unwrap_or_default()
        } else {
            String::new()
        };
        let ok = state
            .cache
            .task_apply(tid, pid, pkg, &thread_name, cfg, |_, _, _, _| {
                AffinityOutcome::Failed
            });
        if ok {
            if let Some(e) = state.cache.tasks.get(&tid) {
                rt::note(tid, pid, &e.pkg, &e.comm, &e.cpus, cfg);
            }
            added += 1;
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SchedMode;

    /// 只需要包级规则、但开启了动态调度的应用：必须能被发现新线程
    #[test]
    fn dynamic_pkg_is_discovered_without_thread_rules() {
        let mut cfg = AppConfig::empty();
        cfg.pkgs.insert("com.a".into());
        cfg.sched = SchedMode::On;
        cfg.sched_pkgs.insert("com.a".into());

        let mut tracked = HashMap::new();
        tracked.insert(100, "com.a".to_string());
        assert_eq!(discover_targets(&tracked, &cfg), vec![100]);
    }

    /// 关闭 S7 / RT 后不再为包级应用逐轮遍历 task
    #[test]
    fn static_pkg_is_not_rescanned() {
        let mut cfg = AppConfig::empty();
        cfg.pkgs.insert("com.a".into());
        cfg.sched_pkgs.insert("com.a".into());

        let mut tracked = HashMap::new();
        tracked.insert(100, "com.a".to_string());
        assert!(discover_targets(&tracked, &cfg).is_empty());
    }

    /// 有线级规则的包始终需要线程名
    #[test]
    fn thread_rule_pkg_is_always_discovered() {
        let mut cfg = AppConfig::empty();
        cfg.has_thread_rules.insert("com.b".into());
        let mut tracked = HashMap::new();
        tracked.insert(200, "com.b".to_string());
        assert_eq!(discover_targets(&tracked, &cfg), vec![200]);
    }
}
