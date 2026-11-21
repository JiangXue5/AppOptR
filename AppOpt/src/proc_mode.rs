use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

use crate::apply_affinity::{proc_walk, read_cmdline, task_tids, tid_comm};
use crate::cache::ProcCache;
use crate::config::AppConfig;
use crate::rt;

/// 全量校验周期：兜底 PID 复用、tid 复用与差分漏检
const FULL_CHECK: Duration = Duration::from_secs(60);

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
        let has_thread_rules = cfg.has_thread_rules.contains(&pkg);
        state.tracked_pids.insert(pid, pkg.clone());
        if proc_tasks(pid, &pkg, has_thread_rules, cfg, state) > 0 {
            state.force_affinity = true;
        }
    }

    for pid in gone_pids {
        state.tracked_pids.remove(&pid);
        state.cache.purge_pid(pid);
        state.known_tids.retain(|_, owner| *owner != pid);
        rt::release_pid(pid);
    }

    // 已跟踪进程的新线程：新线程会在创建后立刻命名，需在下一个周期内纳入管理
    let targets: Vec<i32> = state
        .tracked_pids
        .iter()
        .filter(|(_, pkg)| cfg.has_thread_rules.contains(pkg.as_str()))
        .map(|(&pid, _)| pid)
        .collect();
    for pid in targets {
        let Some(pkg) = state.tracked_pids.get(&pid).cloned() else {
            continue;
        };
        if proc_tasks(pid, &pkg, true, cfg, state) > 0 {
            state.force_affinity = true;
        }
    }

    state.known_pids = current;
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
        |pid, pkg, has_thread_rules| {
            state.tracked_pids.insert(pid, pkg.to_string());
            proc_tasks(pid, pkg, has_thread_rules, cfg, state);
        },
    );

    state.known_pids = current;
    state.rescan_all = false;
    state.last_full = Instant::now();
    state.force_affinity = true;
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
    has_thread_rules: bool,
    cfg: &AppConfig,
    state: &mut ProcScanState,
) -> usize {
    let Some(tids) = task_tids(pid) else { return 0 };
    let mut added = 0;
    for tid in tids {
        if state.known_tids.insert(tid, pid).is_some() {
            continue;
        }
        let thread_name = if has_thread_rules {
            tid_comm(tid).unwrap_or_default()
        } else {
            String::new()
        };
        let ok = state
            .cache
            .task_apply(tid, pid, pkg, &thread_name, cfg, |_, _, _| false);
        if ok {
            if let Some(e) = state.cache.tasks.get(&tid) {
                rt::note(tid, pid, &e.comm, &e.cpus, cfg);
            }
            added += 1;
        }
    }
    added
}
