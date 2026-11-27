use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::apply_affinity::{
    AffinityOutcome, ApplyErrorKind, pkg_owned, proc_walk_set, read_cmdline, task_tids, tid_comm,
};
use crate::cache::ProcCache;
use crate::config::AppConfig;
use crate::rt;

/// 全量校验周期：兜底 PID 复用、tid 复用与差分漏检
const FULL_CHECK: Duration = Duration::from_secs(60);
/// 每轮重读 comm 的线程数。引擎通常在创建线程后才改名，而 /proc 模式
/// 没有 rename 事件；发现线程时若还没命名，线程规则就会永远落不上。
/// 按游标轮转，常见规模（<200 线程）几轮内覆盖一遍
const COMM_RECHECK: usize = 32;
/// 全量扫描超过这个耗时才打一行分解：正常情况下它只有几十毫秒，
/// 每轮都报只会让日志变吵
const SLOW_SCAN_US: u64 = 200_000;

/// 一轮扫描的耗时分解。回答的是「卡在哪」：`/proc` 目录与 cmdline 读取，
/// 还是 task 目录 + 规则计算。没有这两个数，「扫描很慢」只能靠猜
#[derive(Clone, Copy, Default, Debug)]
pub struct ScanCost {
    pub procs: usize,
    pub threads: usize,
    /// 遍历 /proc 与读 cmdline 的耗时
    pub walk_us: u64,
    /// 遍历 task 目录、读线程名、跑规则与写缓存的耗时
    pub tasks_us: u64,
    pub total_us: u64,
}

/// 累计指标，Web 诊断读取
#[derive(Clone, Copy, Default, Debug)]
pub struct ScanMetrics {
    pub last_full: ScanCost,
    pub full_scans: u64,
    pub incremental: u64,
    pub worst_full_us: u64,
}

const EMPTY_METRICS: ScanMetrics = ScanMetrics {
    last_full: ScanCost {
        procs: 0,
        threads: 0,
        walk_us: 0,
        tasks_us: 0,
        total_us: 0,
    },
    full_scans: 0,
    incremental: 0,
    worst_full_us: 0,
};

static METRICS: Mutex<ScanMetrics> = Mutex::new(EMPTY_METRICS);

/// 最近一次全量扫描的成本与累计次数
pub fn metrics() -> ScanMetrics {
    *crate::lock_ignore_poison(&METRICS)
}

fn publish(full: bool, cost: ScanCost) {
    {
        let mut m = crate::lock_ignore_poison(&METRICS);
        if full {
            m.full_scans = m.full_scans.saturating_add(1);
            m.last_full = cost;
            m.worst_full_us = m.worst_full_us.max(cost.total_us);
        } else {
            m.incremental = m.incremental.saturating_add(1);
        }
    }
    // 只有明显偏慢才播报：这两个数就是「该不该继续优化扫描」的依据
    if full && cost.total_us >= SLOW_SCAN_US {
        crate::diag_say!(
            "全量扫描 {:.0} ms（进程 {}、线程 {}；遍历 {} ms、建表 {} ms）",
            cost.total_us as f64 / 1000.0,
            cost.procs,
            cost.threads,
            cost.walk_us as f64 / 1000.0,
            cost.tasks_us as f64 / 1000.0
        );
    }
}

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

    let started = Instant::now();
    let current = read_pid_set();
    let walk_us = started.elapsed().as_micros() as u64;

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
        // 新增进程才做一次属主校验，后续复用它缓存的 pid→pkg
        if !pkg_owned(pid, &pkg) {
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
    let total_us = started.elapsed().as_micros() as u64;
    publish(
        false,
        ScanCost {
            procs: state.known_pids.len(),
            threads: state.known_tids.len(),
            walk_us,
            tasks_us: total_us.saturating_sub(walk_us),
            total_us,
        },
    );
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
            .task_apply(tid, pid, &pkg, &comm, cfg, |_, _, _, _, _| {
                AffinityOutcome::Failed(ApplyErrorKind::Other)
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

/// 全量重建：清空缓存与跟踪状态后遍历 /proc。
///
/// 遍历只做一趟：`proc_walk_set` 在读 cmdline 的同时把 PID 集合带回，
/// 不再像以前那样先用 `read_pid_set()` 读一遍、再整棵 /proc 走一遍
fn proc_scan(cfg: &AppConfig, state: &mut ProcScanState) {
    let started = Instant::now();
    state.cache.clear();
    state.tracked_pids.clear();
    state.known_tids.clear();

    // 回调里累计建表耗时：整趟只记一个总时间的话，无法区分
    // 「/proc 读得慢」与「规则算得慢」
    let mut tasks_ns: u128 = 0;
    let (procs, current) = proc_walk_set(cfg, |pid, pkg| {
        let t = Instant::now();
        state.tracked_pids.insert(pid, pkg.to_string());
        proc_tasks(pid, pkg, cfg.needs_comm(pkg), cfg, state);
        tasks_ns = tasks_ns.saturating_add(t.elapsed().as_nanos());
    });

    state.known_pids = current;
    state.rescan_all = false;
    state.last_full = Instant::now();
    state.force_affinity = true;
    // 缓存已重建，再对账 RT：进程在扫描窗口内退出、包被移出配置时，
    // 旧的 RT 记录不能留着。仍符合条件的线程不受影响
    rt::reconcile(cfg, &state.cache);

    let total_us = started.elapsed().as_micros() as u64;
    let tasks_us = (tasks_ns / 1000) as u64;
    publish(
        true,
        ScanCost {
            procs,
            threads: state.known_tids.len(),
            walk_us: total_us.saturating_sub(tasks_us),
            tasks_us,
            total_us,
        },
    );
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
            .task_apply(tid, pid, pkg, &thread_name, cfg, |_, _, _, _, _| {
                AffinityOutcome::Failed(ApplyErrorKind::Other)
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

    /// 扫描指标要能累计：全量次数、最坏耗时、最近一次分解
    #[test]
    fn scan_metrics_accumulate() {
        let before = metrics();
        publish(
            true,
            ScanCost {
                procs: 320,
                threads: 812,
                walk_us: 12_000,
                tasks_us: 40_000,
                total_us: 52_000,
            },
        );
        let after = metrics();
        assert_eq!(after.full_scans, before.full_scans + 1);
        assert!(after.worst_full_us >= 52_000);
        assert_eq!(after.last_full.procs, 320);
        assert_eq!(after.last_full.threads, 812);
        assert_eq!(
            after.last_full.total_us,
            after.last_full.walk_us + after.last_full.tasks_us
        );
    }
}
