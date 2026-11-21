//! RT（实时调度）提升：`SCHED_RR | SCHED_RESET_ON_FORK`，优先级 1。
//!
//! 与 AsoulOpt 的差异是有意的：
//!
//! - **只改 `sched_rr_timeslice_ms`，不动 `sched_rt_runtime_us` / `sched_rt_period_us`**。
//!   改 RT 预算是整机行为，音频与显示合成的 RT 线程一起受影响，收益与代价都在本模块
//!   可控范围之外。时间片必须改，否则 RR 线程 100 ms 才让位一次，比 CFS 更糟。
//! - **原值落盘**。模块被 `kill -9` 或断电时无法执行恢复，下次启动先读备份文件还原，
//!   避免"装过一次 RT，整机一直 3 ms 时间片"这种隐蔽残留。
//! - **三重闸门**：首次 `sched_setscheduler` 失败即全局关闭；单进程上限 2 个 RT 线程；
//!   已经是 RR/FIFO 的线程直接跳过。

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::config::{AppConfig, RtMode};
use crate::cpuset::CpuSet;
use crate::roles::role_of;

const RR_TIMESLICE_PATH: &str = "/proc/sys/kernel/sched_rr_timeslice_ms";
const RR_TIMESLICE_MS: &str = "3";
/// 单进程 RT 线程上限：再多就拿不到 CFS 的公平性了
const MAX_RT_PER_PID: u8 = 2;
/// Linux 专有位，libc 未导出
const SCHED_RESET_ON_FORK: libc::c_int = 0x4000_0000;

pub struct RtState {
    /// 全局闸门，任何一次失败都会永久置 false，直到重载配置
    enabled: bool,
    /// pid -> 已提升线程数
    per_pid: HashMap<i32, u8>,
    /// 由本模块设置为 RT 的 tid
    applied: HashSet<i32>,
    /// 被改写的原时间片，`None` 表示未改写
    pending_restore: Option<String>,
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
            per_pid: HashMap::new(),
            applied: HashSet::new(),
            pending_restore: None,
        }
    }

    /// 配置加载后调用：`@rt` 非 off 时备份原值并改写时间片
    pub fn prepare(&mut self, cfg: &AppConfig) {
        if cfg.rt.is_off() {
            // 从 on 切回 off：把已提升的线程放回 CFS，并恢复时间片
            self.demote_all();
            return;
        }
        // 失败过一次就不再重试：环境不支持（只读 /proc/sys、缺备份目录）改配置也修不好，
        // 反复重试只会每次热更新刷一行日志
        if !self.enabled || self.pending_restore.is_some() {
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
        if fs::write(RR_TIMESLICE_PATH, format!("{}\n", RR_TIMESLICE_MS)).is_err() {
            let _ = fs::remove_file(&path);
            self.enabled = false;
            eprintln!("RT: 写入 {} 失败，RT 关闭", RR_TIMESLICE_PATH);
            return;
        }
        self.pending_restore = Some(old.clone());
        println!(
            "RT: 时间片 {} ms → {} ms（原值已备份，退出或关闭时恢复）",
            old.trim(),
            RR_TIMESLICE_MS
        );
    }

    /// 规则命中后调用。返回 true 表示本次真正设置了 RT
    pub fn maybe_apply(
        &mut self,
        tid: i32,
        pid: i32,
        comm: &str,
        allowed: &CpuSet,
        cfg: &AppConfig,
    ) -> bool {
        if !self.enabled || cfg.rt.is_off() {
            return false;
        }
        if self.applied.contains(&tid) {
            return false;
        }
        if is_realtime(tid) {
            // 已经是 RR/FIFO，记下来避免每轮重复 getscheduler
            self.applied.insert(tid);
            return false;
        }
        if self.per_pid.get(&pid).copied().unwrap_or(0) >= MAX_RT_PER_PID {
            return false;
        }
        if !mode_matches(&cfg.rt, comm, allowed) {
            return false;
        }
        self.apply(tid, pid)
    }

    pub fn forget(&mut self, tid: i32) {
        self.applied.remove(&tid);
    }

    /// 进程退出时释放配额
    pub fn release_pid(&mut self, pid: i32) {
        self.per_pid.remove(&pid);
    }

    /// 配置切回 off 时把已提升线程放回 CFS
    pub fn demote_all(&mut self) {
        if self.pending_restore.is_none() && self.applied.is_empty() {
            return;
        }
        let mut n = 0;
        for tid in self.applied.drain() {
            if demote(tid) {
                n += 1;
            }
        }
        if n > 0 {
            println!("RT: 回滚 {} 个线程到 SCHED_OTHER", n);
        }
        self.per_pid.clear();
        if let Some(old) = self.pending_restore.take() {
            let _ = fs::write(RR_TIMESLICE_PATH, format!("{}\n", old));
            if let Some(p) = backup_path() {
                let _ = fs::remove_file(&p);
            }
            println!("RT: 时间片已恢复为 {} ms", old.trim());
        }
    }

    fn apply(&mut self, tid: i32, pid: i32) -> bool {
        let param = libc::sched_param { sched_priority: 1 };
        let ret =
            unsafe { libc::sched_setscheduler(tid, libc::SCHED_RR | SCHED_RESET_ON_FORK, &param) };
        if ret != 0 {
            let e = io::Error::last_os_error();
            // EPERM / SELinux 拒绝：继续尝试只会每秒刷日志，直接全局关闭
            self.enabled = false;
            eprintln!(
                "RT: sched_setscheduler({}) 失败（{}），RT 已全局关闭",
                tid, e
            );
            return false;
        }
        self.applied.insert(tid);
        *self.per_pid.entry(pid).or_insert(0) += 1;
        true
    }
}

/// 判定是否该提升。`allowed` 是规则给出的允许集合，`Auto` 用它限制核数。
fn mode_matches(mode: &RtMode, comm: &str, allowed: &CpuSet) -> bool {
    match mode {
        RtMode::Off => false,
        RtMode::Auto => {
            // 允许集合超过 2 核说明线程本来就能在大核上跑，不需要 RT
            allowed.count() <= 2 && role_of(comm).rt_candidate()
        }
        RtMode::Names(patterns) => patterns.iter().any(|p| fnmatch(p, comm)),
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

/// 上次进程未能正常退出时，内核里的时间片仍是 3 ms，这里还原
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

/// 规则命中、亲和性写入成功后调用
pub fn note(tid: i32, pid: i32, comm: &str, allowed: &CpuSet, cfg: &AppConfig) {
    if cfg.rt.is_off() {
        return;
    }
    if let Some(s) = crate::lock_ignore_poison(&RT).as_mut() {
        s.maybe_apply(tid, pid, comm, allowed, cfg);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cpus(n: usize) -> CpuSet {
        let mut s = CpuSet::new();
        for i in 0..n {
            s.set(i);
        }
        s
    }

    #[test]
    fn auto_requires_critical_and_small_set() {
        assert!(mode_matches(&RtMode::Auto, "RenderThread", &cpus(2)));
        // 允许集合超过 2 核，线程本来就能跑大核，不需要 RT
        assert!(!mode_matches(&RtMode::Auto, "RenderThread", &cpus(3)));
        // Worker 变 RT 会挤掉 CFS
        assert!(!mode_matches(&RtMode::Auto, "Thread-9", &cpus(1)));
        assert!(!mode_matches(&RtMode::Auto, "unknown", &cpus(1)));
    }

    #[test]
    fn names_use_fnmatch() {
        let m = RtMode::Names(vec!["RenderThread".into(), "RHI*".into()]);
        assert!(mode_matches(&m, "RenderThread", &cpus(8)));
        assert!(mode_matches(&m, "RHIThread", &cpus(8)));
        assert!(!mode_matches(&m, "Thread-3", &cpus(8)));
    }

    #[test]
    fn off_matches_nothing() {
        assert!(!mode_matches(&RtMode::Off, "RenderThread", &cpus(1)));
    }
}
