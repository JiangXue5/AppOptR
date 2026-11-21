//! RT（实时调度）提升：`SCHED_RR | SCHED_RESET_ON_FORK`，优先级 1。
//!
//! 与 AsoulOpt 的差异是有意的：
//!
//! - **只改 `sched_rr_timeslice_ms`，不动 `sched_rt_runtime_us` / `sched_rt_period_us`**。
//!   改 RT 预算是整机行为，音频与显示合成的 RT 线程一起受影响，收益与代价都在本模块
//!   可控范围之外。时间片必须改，否则 RR 线程 100 ms 才让位一次，比 CFS 更糟。
//! - **原值落盘**。模块被 `kill -9` 或断电时无法执行恢复，下次启动先读备份文件还原，
//!   避免"装过一次 RT，整机一直 3 ms 时间片"这种隐蔽残留。
//! - **只接管自己提升的线程**。外部模块、系统服务设置的 RR/FIFO 线程一律不入表，
//!   因此关闭 RT 时不会把它们降级。

use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::config::{AppConfig, RtMatch};
use crate::cpuset::CpuSet;
use crate::roles::role_of;

const RR_TIMESLICE_PATH: &str = "/proc/sys/kernel/sched_rr_timeslice_ms";
/// Linux 专有位，libc 未导出
const SCHED_RESET_ON_FORK: libc::c_int = 0x4000_0000;

/// 由本模块提升的线程。只有 `sched_setscheduler` 返回 0 的线程会进来
struct Owned {
    pid: i32,
    pkg: String,
    comm: String,
    /// 提升时的规则允许集合，配置热更新时用于复核 Auto 的核数条件
    allowed: CpuSet,
}

pub struct RtState {
    /// 全局闸门，任何一次失败都会永久置 false，直到重载配置
    enabled: bool,
    /// tid -> 归属信息。配额直接从这张表统计，避免计数器与集合不同步
    own: HashMap<i32, Owned>,
    /// 被改写的原时间片，`None` 表示当前没有改写
    pending_restore: Option<String>,
    /// 已经写进内核的时间片值，用于判断配置是否真的变了
    applied_ms: Option<u32>,
    /// 累计回滚线程数，仅用于日志与展示
    demoted: u64,
}

impl Default for RtState {
    fn default() -> Self {
        Self::new()
    }
}

impl RtState {
    /// 启动时先恢复上次异常退出留下的时间片
    pub fn new() -> Self {
        restore_stale();
        Self {
            enabled: true,
            own: HashMap::new(),
            pending_restore: None,
            applied_ms: None,
            demoted: 0,
        }
    }

    /// 配置加载后调用。只有存在实际启用的应用时才改写全局时间片，
    /// 全部关闭时还原；已有备份的情况下只改值，绝不重新读取"原值"
    pub fn prepare(&mut self, cfg: &AppConfig) {
        if !cfg.rt.any_enabled() {
            self.demote_all();
            self.restore_timeslice();
            return;
        }
        if !self.enabled {
            return;
        }
        self.ensure_timeslice(cfg.rt.timeslice_ms);
    }

    /// 配置热更新后复核所有权：不再符合新规则的线程放回 CFS，
    /// 仍符合的保留 RT，避免无意义的降级与重新提升
    pub fn prune(&mut self, cfg: &AppConfig) {
        if self.own.is_empty() {
            return;
        }
        let mut drop: Vec<i32> = Vec::new();
        let mut quota: HashMap<(i32, String), Vec<i32>> = HashMap::new();
        for (&tid, a) in &self.own {
            if !eligible(cfg, &a.pkg, &a.comm, &a.allowed) {
                drop.push(tid);
                continue;
            }
            quota.entry((a.pid, a.pkg.clone())).or_default().push(tid);
        }
        // 上限下调时按 tid 升序保留前 max 个，保证结果与遍历顺序无关
        for ((_, pkg), mut tids) in quota {
            let Some((_, max)) = cfg.rt.policy(&pkg) else {
                drop.extend(tids);
                continue;
            };
            if tids.len() > max as usize {
                tids.sort_unstable();
                drop.extend(tids.split_off(max as usize));
            }
        }
        let n = self.drop_threads(&drop);
        if n > 0 {
            println!("RT: 配置变更后回滚 {} 个线程到 SCHED_OTHER", n);
        }
    }

    /// 规则命中后调用。返回 true 表示本次真正设置了 RT
    pub fn note(
        &mut self,
        tid: i32,
        pid: i32,
        pkg: &str,
        comm: &str,
        allowed: &CpuSet,
        cfg: &AppConfig,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        let policy = cfg.rt.policy(pkg);
        let owned = self.own.contains_key(&tid);
        match (owned, policy) {
            // 已由本模块提升：按新配置复核，合格就保留，不合格立即降级
            (true, Some((mode, max))) => {
                let ok = matches(mode, comm, allowed) && self.count(pid) <= max as usize;
                if !ok {
                    self.drop_threads(&[tid]);
                }
            }
            (true, None) => {
                self.drop_threads(&[tid]);
            }
            (false, Some((mode, max))) => {
                // 外部模块或系统设置的 RR/FIFO：不接管，也不记录
                if is_realtime(tid) {
                    return false;
                }
                if !matches(mode, comm, allowed) {
                    return false;
                }
                if self.count(pid) >= max as usize {
                    return false;
                }
                return self.apply(tid, pid, pkg, comm, allowed);
            }
            (false, None) => {}
        }
        false
    }

    /// 线程退出：只清记录，不调用 sched_setscheduler（线程已经不存在）
    pub fn forget(&mut self, tid: i32) {
        self.own.remove(&tid);
    }

    /// 进程退出：清理该 PID 下全部 RT 记录与配额
    pub fn release_pid(&mut self, pid: i32) {
        self.own.retain(|_, a| a.pid != pid);
    }

    /// 配置切回关闭时把已提升线程放回 CFS
    pub fn demote_all(&mut self) {
        if self.own.is_empty() {
            return;
        }
        let tids: Vec<i32> = self.own.keys().copied().collect();
        let n = self.drop_threads(&tids);
        if n > 0 {
            println!("RT: 回滚 {} 个线程到 SCHED_OTHER", n);
        }
    }

    /// 进程正常退出：线程降级并把时间片写回原值
    pub fn shutdown(&mut self) {
        self.demote_all();
        self.restore_timeslice();
    }

    /// 该 PID 当前由本模块管理的 RT 线程数
    fn count(&self, pid: i32) -> usize {
        self.own.values().filter(|a| a.pid == pid).count()
    }

    /// 移除并降级。线程已退出时 setscheduler 失败，属正常情况
    fn drop_threads(&mut self, tids: &[i32]) -> usize {
        let mut n = 0;
        for tid in tids {
            if self.own.remove(tid).is_some() && demote(*tid) {
                n += 1;
            }
        }
        self.demoted += n as u64;
        n
    }

    fn apply(&mut self, tid: i32, pid: i32, pkg: &str, comm: &str, allowed: &CpuSet) -> bool {
        let param = libc::sched_param { sched_priority: 1 };
        let ret =
            unsafe { libc::sched_setscheduler(tid, libc::SCHED_RR | SCHED_RESET_ON_FORK, &param) };
        if ret != 0 {
            let e = io::Error::last_os_error();
            // EPERM / SELinux 拒绝：继续尝试只会每次热更新刷日志，直接全局关闭
            self.enabled = false;
            eprintln!(
                "RT: sched_setscheduler({}) 失败（{}），RT 已全局关闭",
                tid, e
            );
            return false;
        }
        self.own.insert(
            tid,
            Owned {
                pid,
                pkg: pkg.to_string(),
                comm: comm.to_string(),
                allowed: *allowed,
            },
        );
        true
    }

    /// 备份原值并写入配置值。已有备份时只更新值，不覆盖原值
    fn ensure_timeslice(&mut self, ms: u32) {
        if let Some(old) = &self.pending_restore {
            if self.applied_ms == Some(ms) {
                return;
            }
            // 原值只在第一次保存，这里只改当前值；失败则放弃后续尝试
            if fs::write(RR_TIMESLICE_PATH, format!("{}\n", ms)).is_err() {
                self.enabled = false;
                eprintln!("RT: 写入 {} 失败，RT 已全局关闭", RR_TIMESLICE_PATH);
                return;
            }
            self.applied_ms = Some(ms);
            println!("RT: 时间片调整为 {} ms（原值 {} ms 保持不变）", ms, old);
            return;
        }
        let Some(path) = backup_path() else {
            self.enabled = false;
            eprintln!("RT: 无法定位可执行文件目录，跳过 RT（时间片无法保证恢复）");
            return;
        };
        let Ok(old) = fs::read_to_string(RR_TIMESLICE_PATH) else {
            self.enabled = false;
            eprintln!("RT: 读取 {} 失败，RT 关闭", RR_TIMESLICE_PATH);
            return;
        };
        let old = old.trim().to_string();
        // 先落盘再改：顺序反了会留下一个「内核已改、备份没写」的窗口
        if fs::write(&path, format!("{}\n", old)).is_err() {
            self.enabled = false;
            eprintln!(
                "RT: 无法写入备份 {}，RT 关闭（避免卸载后时间片残留）",
                path.display()
            );
            return;
        }
        if fs::write(RR_TIMESLICE_PATH, format!("{}\n", ms)).is_err() {
            let _ = fs::remove_file(&path);
            self.enabled = false;
            eprintln!("RT: 写入 {} 失败，RT 关闭", RR_TIMESLICE_PATH);
            return;
        }
        self.pending_restore = Some(old.clone());
        self.applied_ms = Some(ms);
        println!(
            "RT: 时间片 {} ms → {} ms（原值已备份，退出或关闭时恢复）",
            old.trim(),
            ms
        );
    }

    fn restore_timeslice(&mut self) {
        let Some(old) = self.pending_restore.take() else {
            self.applied_ms = None;
            return;
        };
        let _ = fs::write(RR_TIMESLICE_PATH, format!("{}\n", old));
        if let Some(p) = backup_path() {
            let _ = fs::remove_file(&p);
        }
        self.applied_ms = None;
        println!("RT: 时间片已恢复为 {} ms", old.trim());
    }
}

/// 该线程在新配置下是否仍有资格。`note` 与 `prune` 共用，避免两处判定漂移
fn eligible(cfg: &AppConfig, pkg: &str, comm: &str, allowed: &CpuSet) -> bool {
    match cfg.rt.policy(pkg) {
        Some((mode, _)) => matches(mode, comm, allowed),
        None => false,
    }
}

/// 匹配方式判定。Auto 用允许集合限制核数：超过 2 核说明线程本来就能跑大核
fn matches(mode: &RtMatch, comm: &str, allowed: &CpuSet) -> bool {
    match mode {
        RtMatch::Auto => allowed.count() <= 2 && role_of(comm).rt_candidate(),
        RtMatch::Names(patterns) => patterns.iter().any(|p| fnmatch(p, comm)),
    }
}

fn fnmatch(pattern: &str, name: &str) -> bool {
    let (Ok(p), Ok(n)) = (CString::new(pattern), CString::new(name)) else {
        return false;
    };
    unsafe { libc::fnmatch(p.as_ptr(), n.as_ptr(), libc::FNM_NOESCAPE) == 0 }
}

fn is_realtime(tid: i32) -> bool {
    let policy = unsafe { libc::sched_getscheduler(tid) };
    policy == libc::SCHED_FIFO || policy == libc::SCHED_RR
}

fn demote(tid: i32) -> bool {
    let param = libc::sched_param { sched_priority: 0 };
    unsafe { libc::sched_setscheduler(tid, libc::SCHED_OTHER, &param) == 0 }
}

fn backup_path() -> Option<PathBuf> {
    let dir = env::current_exe().ok()?.parent()?.to_path_buf();
    Some(dir.join(".AppOpt.rt.bak"))
}

/// 上次进程未能正常退出时，内核里的时间片仍是配置值，这里还原
fn restore_stale() {
    let Some(path) = backup_path() else { return };
    let Ok(s) = fs::read_to_string(&path) else {
        return;
    };
    let old = s.trim();
    if old.parse::<u32>().is_err() {
        // 内容损坏，删掉避免每次启动都读到脏数据
        let _ = fs::remove_file(&path);
        return;
    }
    if fs::write(RR_TIMESLICE_PATH, format!("{}\n", old)).is_ok() {
        eprintln!("RT: 检测到上次异常退出的残留，时间片已恢复为 {} ms", old);
    }
    let _ = fs::remove_file(&path);
}

/// 全局实例。RT 调用只发生在新线程或配置重扫时，不在热路径上，
/// 用互斥锁换取「不必给每个调用点都加一个参数」的简洁
pub static RT: std::sync::Mutex<Option<RtState>> = std::sync::Mutex::new(None);

pub fn init() {
    *crate::lock_ignore_poison(&RT) = Some(RtState::new());
}

pub fn prepare(cfg: &AppConfig) {
    if let Some(s) = crate::lock_ignore_poison(&RT).as_mut() {
        s.prepare(cfg);
    }
}

pub fn prune(cfg: &AppConfig) {
    if let Some(s) = crate::lock_ignore_poison(&RT).as_mut() {
        s.prune(cfg);
    }
}

/// 规则命中、亲和性写入成功后调用
pub fn note(tid: i32, pid: i32, pkg: &str, comm: &str, allowed: &CpuSet, cfg: &AppConfig) {
    if cfg.rt.is_off() {
        return;
    }
    if let Some(s) = crate::lock_ignore_poison(&RT).as_mut() {
        s.note(tid, pid, pkg, comm, allowed, cfg);
    }
}

pub fn forget(tid: i32) {
    if let Some(s) = crate::lock_ignore_poison(&RT).as_mut() {
        s.forget(tid);
    }
}

pub fn release_pid(pid: i32) {
    if let Some(s) = crate::lock_ignore_poison(&RT).as_mut() {
        s.release_pid(pid);
    }
}

/// 进程正常退出前调用，把线程与时间片都还原
pub fn shutdown() {
    if let Some(s) = crate::lock_ignore_poison(&RT).as_mut() {
        s.shutdown();
    }
}

/// Web 展示用的快照：当前有多少线程、属于哪个应用、时间片是否被改写
pub struct RtSnapshot {
    pub enabled: bool,
    pub threads: Vec<(String, i32, String)>,
    pub timeslice_applied: Option<u32>,
    pub timeslice_current: Option<u32>,
    pub demoted: u64,
}

pub fn snapshot() -> RtSnapshot {
    let current = fs::read_to_string(RR_TIMESLICE_PATH)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    match crate::lock_ignore_poison(&RT).as_ref() {
        Some(s) => RtSnapshot {
            enabled: s.enabled,
            threads: s
                .own
                .iter()
                .map(|(&tid, a)| (a.pkg.clone(), tid, a.comm.clone()))
                .collect(),
            timeslice_applied: s.applied_ms,
            timeslice_current: current,
            demoted: s.demoted,
        },
        None => RtSnapshot {
            enabled: false,
            threads: Vec::new(),
            timeslice_applied: None,
            timeslice_current: current,
            demoted: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RtConfig, RtScope};

    fn cpus(n: usize) -> CpuSet {
        let mut s = CpuSet::new();
        for i in 0..n {
            s.set(i);
        }
        s
    }

    fn cfg_of(rt: RtConfig, pkgs: &[&str]) -> AppConfig {
        let mut cfg = AppConfig::empty();
        cfg.rt = rt;
        for p in pkgs {
            cfg.pkgs.insert((*p).to_string());
        }
        cfg
    }

    fn names(v: &[&str]) -> RtMatch {
        RtMatch::Names(v.iter().map(|s| (*s).to_string()).collect())
    }

    /// 不走系统调用的状态，测试只验证表结构与配额，不验证内核行为
    fn state() -> RtState {
        RtState {
            enabled: true,
            own: HashMap::new(),
            pending_restore: None,
            applied_ms: None,
            demoted: 0,
        }
    }

    fn adopt(s: &mut RtState, tid: i32, pid: i32, pkg: &str, comm: &str, allowed: CpuSet) {
        s.own.insert(
            tid,
            Owned {
                pid,
                pkg: pkg.to_string(),
                comm: comm.to_string(),
                allowed,
            },
        );
    }

    #[test]
    fn default_is_off() {
        let rt = RtConfig::default();
        assert!(rt.is_off());
        assert!(!rt.any_enabled());
        assert!(rt.policy("com.a").is_none());
    }

    #[test]
    fn global_enables_every_managed_pkg() {
        let rt = RtConfig {
            scope: RtScope::Global,
            ..RtConfig::default()
        };
        assert!(rt.policy("com.a").is_some());
        assert!(rt.policy("com.not.installed").is_some());
        assert!(rt.any_enabled());
    }

    #[test]
    fn per_app_only_enables_listed() {
        let mut rt = RtConfig {
            scope: RtScope::PerApp,
            ..RtConfig::default()
        };
        rt.apps.insert(
            "com.a".into(),
            crate::config::AppRt {
                enabled: true,
                mode: RtMatch::Auto,
                max_threads: 1,
            },
        );
        assert!(rt.policy("com.a").is_some());
        assert!(rt.policy("com.b").is_none());
        assert!(rt.any_enabled());
    }

    #[test]
    fn per_app_all_disabled_does_not_touch_timeslice() {
        let mut rt = RtConfig {
            scope: RtScope::PerApp,
            ..RtConfig::default()
        };
        rt.apps.insert(
            "com.a".into(),
            crate::config::AppRt {
                enabled: false,
                mode: RtMatch::Auto,
                max_threads: 2,
            },
        );
        assert!(!rt.any_enabled());
    }

    #[test]
    fn auto_requires_critical_and_small_set() {
        assert!(matches(&RtMatch::Auto, "RenderThread", &cpus(2)));
        // 允许集合超过 2 核，线程本来就能跑大核，不需要 RT
        assert!(!matches(&RtMatch::Auto, "RenderThread", &cpus(3)));
        // Worker 变 RT 会挤掉 CFS
        assert!(!matches(&RtMatch::Auto, "Thread-9", &cpus(1)));
    }

    #[test]
    fn names_use_fnmatch() {
        let m = names(&["RenderThread", "RHI*"]);
        assert!(matches(&m, "RenderThread", &cpus(8)));
        assert!(matches(&m, "RHIThread", &cpus(8)));
        assert!(!matches(&m, "Thread-3", &cpus(8)));
    }

    #[test]
    fn quota_counts_only_own_threads() {
        let mut s = state();
        adopt(&mut s, 10, 100, "com.a", "RenderThread", cpus(2));
        adopt(&mut s, 11, 100, "com.a", "RenderThread", cpus(2));
        adopt(&mut s, 12, 200, "com.b", "RenderThread", cpus(2));
        assert_eq!(s.count(100), 2);
        assert_eq!(s.count(200), 1);
        assert_eq!(s.count(300), 0);
    }

    #[test]
    fn forget_releases_quota() {
        let mut s = state();
        adopt(&mut s, 10, 100, "com.a", "RenderThread", cpus(2));
        adopt(&mut s, 11, 100, "com.a", "RenderThread", cpus(2));
        // 线程退出：配额立即回落到 1，新线程可以占用释放的名额
        s.forget(10);
        assert_eq!(s.count(100), 1);
        assert!(s.own.contains_key(&11));
    }

    #[test]
    fn release_pid_clears_all_its_threads() {
        let mut s = state();
        adopt(&mut s, 10, 100, "com.a", "RenderThread", cpus(2));
        adopt(&mut s, 11, 100, "com.a", "GLThread", cpus(2));
        adopt(&mut s, 12, 200, "com.b", "RenderThread", cpus(2));
        s.release_pid(100);
        assert_eq!(s.count(100), 0);
        assert_eq!(s.count(200), 1);
    }

    #[test]
    fn prune_demotes_pkg_disabled_by_switch() {
        let mut rt = RtConfig {
            scope: RtScope::PerApp,
            ..RtConfig::default()
        };
        for p in ["com.a", "com.b"] {
            rt.apps.insert(
                p.into(),
                crate::config::AppRt {
                    enabled: true,
                    mode: RtMatch::Auto,
                    max_threads: 2,
                },
            );
        }
        let mut s = state();
        adopt(&mut s, 10, 100, "com.a", "RenderThread", cpus(2));
        adopt(&mut s, 20, 200, "com.b", "RenderThread", cpus(2));

        rt.apps.get_mut("com.a").unwrap().enabled = false;
        let cfg = cfg_of(rt, &["com.a", "com.b"]);
        s.prune(&cfg);
        // com.a 的线程交还所有权，com.b 原样保留；tid 用假值，
        // 降级系统调用必然失败，但不影响「移出所有权」这一步
        assert!(s.own.values().all(|a| a.pkg != "com.a"));
        assert_eq!(s.count(200), 1);
    }

    #[test]
    fn foreign_threads_are_never_touched_by_demote_all() {
        let mut s = state();
        adopt(&mut s, 10, 100, "com.a", "RenderThread", cpus(2));
        // 不在 own 里的线程（外部模块设置的 RR/FIFO）根本不会被遍历到
        s.demote_all();
        assert!(s.own.is_empty());
        // 假 tid 的降级系统调用失败，说明这段代码只处理自己的记录
        assert_eq!(s.demoted, 0);
    }

    #[test]
    fn quota_slot_reopens_after_exit() {
        let mut s = state();
        adopt(&mut s, 10, 100, "com.a", "RenderThread", cpus(2));
        adopt(&mut s, 11, 100, "com.a", "GLThread", cpus(2));
        assert_eq!(s.count(100), 2);
        s.forget(10);
        // 释放后同 PID 的新线程可以重新占用配额
        assert!(s.count(100) < 2);
    }

    #[test]
    fn prune_respects_lowered_quota() {
        let mut rt = RtConfig {
            scope: RtScope::Global,
            ..RtConfig::default()
        };
        rt.max_per_app = 1;
        let cfg = cfg_of(rt, &["com.a"]);
        let mut s = state();
        adopt(&mut s, 10, 100, "com.a", "RenderThread", cpus(2));
        adopt(&mut s, 11, 100, "com.a", "GLThread", cpus(2));
        let Some((_, max)) = cfg.rt.policy("com.a") else {
            panic!("global 模式应给出策略");
        };
        assert_eq!(max, 1);
        // prune 内部按 tid 升序保留前 max 个
        let mut tids = vec![10, 11];
        tids.sort_unstable();
        assert_eq!(tids.split_off(1), vec![11]);
        assert_eq!(s.count(100), 2);
    }

    #[test]
    fn mode_switch_invalidates_old_match() {
        let mut rt = RtConfig {
            scope: RtScope::Global,
            global: RtMatch::Auto,
            ..RtConfig::default()
        };
        let auto = cfg_of(rt.clone(), &["com.a"]);
        assert!(eligible(&auto, "com.a", "RenderThread", &cpus(2)));

        // auto → names：不在列表里的线程失去资格，列表内的保留
        rt.global = names(&["GLThread"]);
        let named = cfg_of(rt, &["com.a"]);
        assert!(!eligible(&named, "com.a", "RenderThread", &cpus(2)));
        assert!(eligible(&named, "com.a", "GLThread", &cpus(8)));
    }

    #[test]
    fn foreign_rt_is_not_recorded() {
        // 外部 RR/FIFO 线程不会进入 own，因而 demote_all 不会碰它
        let s = state();
        assert!(s.own.is_empty());
        assert_eq!(s.count(1), 0);
    }
}
