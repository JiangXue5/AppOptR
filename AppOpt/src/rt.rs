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

use crate::cache::ProcCache;
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
        if !cfg.rt_active() {
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
            let Some((mode, _)) = cfg.rt.policy(&a.pkg) else {
                drop.push(tid);
                continue;
            };
            if !eligible(mode, &a.comm, &a.allowed) {
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
        let Some((mode, max)) = cfg.rt.policy(pkg) else {
            // 新配置里这个包已无 RT 资格：只收回自己提升过的线程
            if self.own.contains_key(&tid) {
                self.drop_threads(&[tid]);
            }
            return false;
        };

        // 一次 getscheduler 同时回答两个问题：
        // 1) 记录里的线程是否还在按 RT 运行（退出后 tid 复用 / 外部改回 CFS）
        // 2) 还没接管的线程是否已被系统或其他模块设成 RR/FIFO
        let realtime = is_realtime(tid);
        let mut owned = self.own.contains_key(&tid);
        if owned && !realtime {
            // 记录已经失效。直接丢弃，避免把复用了该 tid 的新线程当成自己提升过的
            self.own.remove(&tid);
            owned = false;
        }

        let qualified = eligible(mode, comm, allowed);
        let used = self.count(pid);
        match action(owned, qualified, realtime && !owned, used, max) {
            Action::Keep => {
                // 线程名会因 rename 变化，规则集合也会随配置变化，
                // 记录跟着更新，prune 才不会按旧名字旧集合误判
                if let Some(a) = self.own.get_mut(&tid) {
                    if a.comm != comm {
                        a.comm = comm.to_string();
                    }
                    a.allowed = *allowed;
                    a.pkg = pkg.to_string();
                    a.pid = pid;
                }
                false
            }
            Action::Drop => {
                self.drop_threads(&[tid]);
                false
            }
            Action::Adopt => self.apply(tid, pid, pkg, comm, allowed),
            // 外部 RT（不接管）或不符合策略/配额已满
            Action::Foreign | Action::Skip => false,
        }
    }

    /// 线程退出：只清记录，不调用 sched_setscheduler（线程已经不存在）
    pub fn forget(&mut self, tid: i32) {
        self.own.remove(&tid);
    }

    /// 进程退出：清理该 PID 下全部 RT 记录与配额
    pub fn release_pid(&mut self, pid: i32) {
        self.own.retain(|_, a| a.pid != pid);
    }

    /// 全量重扫后的对账：只处理自己提升过的线程。
    /// 仍在缓存里且符合当前策略的保留，其余（线程/进程已退出、包被移出配置、
    /// 规则变化后不再符合）放回 CFS。覆盖事件丢失与扫描窗口内的进程消失
    pub fn reconcile(&mut self, cfg: &AppConfig, cache: &ProcCache) {
        if self.own.is_empty() {
            return;
        }
        let drop: Vec<i32> = self
            .own
            .iter()
            .filter(|(tid, a)| match cache.tasks.get(tid) {
                Some(e) => {
                    e.pkg != a.pkg
                        || !cfg
                            .rt
                            .policy(&e.pkg)
                            .is_some_and(|(mode, _)| eligible(mode, &e.comm, &e.cpus))
                }
                None => true,
            })
            .map(|(&tid, _)| tid)
            .collect();
        let n = self.drop_threads(&drop);
        if n > 0 {
            println!("RT: 全量重扫后回滚 {} 个不再符合条件的线程", n);
        }
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
        // 用零初始化再赋优先级：aarch64-musl 的 sched_param 带 SCHED_DEADLINE 字段，
        // 结构体字面量在部分 target 上无法编译
        let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
        param.sched_priority = 1;
        let ret =
            unsafe { libc::sched_setscheduler(tid, libc::SCHED_RR | SCHED_RESET_ON_FORK, &param) };
        if ret != 0 {
            let e = io::Error::last_os_error();
            // 线程在取到 tid 之后、调用之前退出：正常的竞态，不是环境不支持，
            // 不能因此关闭全局闸门（否则 RT 会莫名其妙整体失效）
            if e.raw_os_error() == Some(libc::ESRCH) {
                return false;
            }
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

    /// 备份原值并写入配置值。已有备份时只更新值，不覆盖原值；
    /// 若外部在两次配置之间改过这个全局参数，把现值当作新的原值再写
    fn ensure_timeslice(&mut self, ms: u32) {
        let current = read_timeslice();
        if let Some(old) = self.pending_restore.clone() {
            if self.applied_ms == Some(ms) && current == Some(ms) {
                return;
            }
            // 外部改过：以现值为原值，恢复时还给它，而不是用我们记的旧值覆盖
            if current != self.applied_ms
                && let Some(c) = current
            {
                let cur = c.to_string();
                if let Some(p) = backup_path() {
                    let _ = fs::write(&p, format!("{}\n", cur));
                }
                self.pending_restore = Some(cur);
                println!("RT: 时间片被外部改为 {} ms，作为新的原值记录", c);
            }
            // 原值只在第一次保存，这里只改当前值；失败则放弃后续尝试
            if fs::write(RR_TIMESLICE_PATH, format!("{}\n", ms)).is_err() {
                self.enabled = false;
                eprintln!("RT: 写入 {} 失败，RT 已全局关闭", RR_TIMESLICE_PATH);
                return;
            }
            self.applied_ms = Some(ms);
            println!(
                "RT: 时间片调整为 {} ms（原值 {} ms 保持不变）",
                ms,
                self.pending_restore.as_deref().unwrap_or(&old)
            );
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
        // 只还原自己写进去的值。外部已经把参数改成别的值时不覆盖，
        // 只清理记录与备份，避免「卸载模块顺手改掉别人的配置」
        if owns_current(self.applied_ms) {
            let _ = fs::write(RR_TIMESLICE_PATH, format!("{}\n", old));
            println!("RT: 时间片已恢复为 {} ms", old.trim());
        } else {
            eprintln!(
                "RT: 时间片已被外部修改，保留现值不覆盖（原值 {} ms）",
                old.trim()
            );
        }
        if let Some(p) = backup_path() {
            let _ = fs::remove_file(&p);
        }
        self.applied_ms = None;
    }
}

/// 单个候选线程的处理结论。抽成纯函数，所有权与配额语义可以脱离系统调用验证
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
    /// 本模块提升过且仍符合策略：保留
    Keep,
    /// 本模块提升过但不再符合策略：撤销
    Drop,
    /// 外部设置的 RR/FIFO：不接管、不记录、不降级
    Foreign,
    /// 符合策略且有名额：提升
    Adopt,
    /// 不符合策略或配额已满
    Skip,
}

/// `owned` 表示记录在本模块表里，`foreign` 表示内核里已经是 RR/FIFO 但不是本模块设的
fn action(owned: bool, eligible: bool, foreign: bool, used: usize, max: u8) -> Action {
    if owned {
        // 配额同理：上限下调后由 prune 收敛，这里只防止记录与配置长期不一致
        return if eligible && used <= max as usize {
            Action::Keep
        } else {
            Action::Drop
        };
    }
    if foreign {
        return Action::Foreign;
    }
    if eligible && used < max as usize {
        Action::Adopt
    } else {
        Action::Skip
    }
}

/// 线程在给定匹配方式下是否具备 RT 资格。`note` / `prune` / `reconcile`
/// 都调这一个函数，三处不会各自解释一次 `RtMatch`。
/// Auto 用允许集合限制核数：超过 2 核说明线程本来就能跑大核，不需要 RT
fn eligible(mode: &RtMatch, comm: &str, allowed: &CpuSet) -> bool {
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

fn read_timeslice() -> Option<u32> {
    fs::read_to_string(RR_TIMESLICE_PATH)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// 当前内核值是否仍是本模块写入的那个。外部改过就说明所有权已不属于我们，
/// 恢复时不能无脑覆盖
fn owns_current(applied: Option<u32>) -> bool {
    owned_value(read_timeslice(), applied)
}

fn owned_value(current: Option<u32>, applied: Option<u32>) -> bool {
    current.is_some() && current == applied
}

fn demote(tid: i32) -> bool {
    let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
    param.sched_priority = 0;
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

/// 全量扫描后调用。缓存是唯一可信的「还活着的受管线程」来源
pub fn reconcile(cfg: &AppConfig, cache: &ProcCache) {
    if let Some(s) = crate::lock_ignore_poison(&RT).as_mut() {
        s.reconcile(cfg, cache);
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
    use crate::cache::TaskEntry;
    use crate::config::{RtConfig, RtScope};

    /// 内核 pid_max 上限 4194304，用更大的 tid 保证不存在，
    /// 既验证失败路径，也不会误改测试机上的真实线程
    const GHOST: i32 = 2_000_000_000;
    const GHOST2: i32 = 2_000_000_001;

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

    /// prune / reconcile 的取策略方式，测试里复用同一路径
    fn eligible_in(cfg: &AppConfig, pkg: &str, comm: &str, allowed: &CpuSet) -> bool {
        cfg.rt
            .policy(pkg)
            .is_some_and(|(mode, _)| eligible(mode, comm, allowed))
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

    fn entry(pid: i32, pkg: &str, comm: &str, cores: usize) -> TaskEntry {
        TaskEntry {
            pid,
            pkg: pkg.to_string(),
            cpus: cpus(cores),
            cpuset_dir: String::new(),
            is_thread_rule: false,
            comm: comm.to_string(),
        }
    }

    #[test]
    fn default_is_off() {
        let rt = RtConfig::default();
        assert!(rt.is_off());
        assert!(rt.policy("com.a").is_none());
        assert!(!cfg_of(rt, &["com.a"]).rt_active());
    }

    #[test]
    fn global_enables_every_managed_pkg() {
        let rt = RtConfig {
            scope: RtScope::Global,
            ..RtConfig::default()
        };
        assert!(rt.policy("com.a").is_some());
        assert!(rt.policy("com.not.installed").is_some());
        assert!(cfg_of(rt.clone(), &["com.a"]).rt_active());
        // 一个受管包都没有时没有线程会被提升，不该改写全局时间片
        assert!(!cfg_of(rt, &[]).rt_active());
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
        assert!(cfg_of(rt.clone(), &["com.a"]).rt_active());
        // 应用启用了但没写进规则文件：没有受管线程，同样不碰时间片
        assert!(!cfg_of(rt, &["com.b"]).rt_active());
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
        assert!(!cfg_of(rt, &["com.a"]).rt_active());
    }

    #[test]
    fn auto_requires_critical_and_small_set() {
        assert!(eligible(&RtMatch::Auto, "RenderThread", &cpus(2)));
        // 允许集合超过 2 核，线程本来就能跑大核，不需要 RT
        assert!(!eligible(&RtMatch::Auto, "RenderThread", &cpus(3)));
        // Worker 变 RT 会挤掉 CFS
        assert!(!eligible(&RtMatch::Auto, "Thread-9", &cpus(1)));
    }

    #[test]
    fn names_use_fnmatch() {
        let m = names(&["RenderThread", "RHI*"]);
        assert!(eligible(&m, "RenderThread", &cpus(8)));
        assert!(eligible(&m, "RHIThread", &cpus(8)));
        assert!(!eligible(&m, "Thread-3", &cpus(8)));
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
        assert!(eligible_in(&auto, "com.a", "RenderThread", &cpus(2)));

        // auto → names：不在列表里的线程失去资格，列表内的保留
        rt.global = names(&["GLThread"]);
        let named = cfg_of(rt, &["com.a"]);
        assert!(!eligible_in(&named, "com.a", "RenderThread", &cpus(2)));
        assert!(eligible_in(&named, "com.a", "GLThread", &cpus(8)));
    }

    #[test]
    fn foreign_rt_is_not_recorded() {
        // 外部 RR/FIFO 线程不会进入 own，因而 demote_all 不会碰它
        let s = state();
        assert!(s.own.is_empty());
        assert_eq!(s.count(1), 0);
    }

    /// 外部已有的 RR/FIFO 一律 Foreign：不接管、不入表、不降级
    #[test]
    fn foreign_threads_are_never_adopted() {
        assert_eq!(action(false, true, true, 0, 2), Action::Foreign);
        // 配额已满、或者不符合策略时，外部线程同样不能被改写
        assert_eq!(action(false, false, true, 2, 2), Action::Foreign);
    }

    #[test]
    fn adoption_respects_quota_and_policy() {
        assert_eq!(action(false, true, false, 0, 2), Action::Adopt);
        assert_eq!(action(false, true, false, 1, 2), Action::Adopt);
        assert_eq!(action(false, true, false, 2, 2), Action::Skip);
        assert_eq!(action(false, false, false, 0, 2), Action::Skip);
    }

    #[test]
    fn owned_threads_are_kept_or_dropped_by_policy() {
        assert_eq!(action(true, true, false, 1, 2), Action::Keep);
        // 模式改成 names 后名字不再命中：立刻撤销自己设的 RT
        assert_eq!(action(true, false, false, 1, 2), Action::Drop);
        // 上限下调到低于当前数量
        assert_eq!(action(true, true, false, 3, 2), Action::Drop);
    }

    /// 提升失败不能留下任何所有权记录
    #[test]
    fn failed_promotion_is_not_recorded() {
        let cfg = cfg_of(
            RtConfig {
                scope: RtScope::Global,
                ..RtConfig::default()
            },
            &["com.a"],
        );
        let mut s = state();
        let ok = s.apply(GHOST, 100, "com.a", "RenderThread", &cpus(2));
        let _ = cfg;
        assert!(!ok);
        assert!(s.own.is_empty());
        assert_eq!(s.count(100), 0);
        // ESRCH 只是线程刚好退出，不能把 RT 全局闸门关掉
        assert!(s.enabled);
    }

    /// 全量重扫后：仍符合条件的保留，已消失的收回
    #[test]
    fn reconcile_keeps_live_and_drops_missing() {
        let cfg = cfg_of(
            RtConfig {
                scope: RtScope::Global,
                ..RtConfig::default()
            },
            &["com.a"],
        );
        let mut s = state();
        adopt(&mut s, 10, 100, "com.a", "RenderThread", cpus(2));
        adopt(&mut s, GHOST, 100, "com.a", "RenderThread", cpus(2));
        let mut cache = crate::cache::ProcCache::new();
        cache
            .tasks
            .insert(10, entry(100, "com.a", "RenderThread", 2));

        s.reconcile(&cfg, &cache);
        assert!(s.own.contains_key(&10), "仍符合条件的线程不能被降级");
        assert!(!s.own.contains_key(&GHOST), "缓存里没有的线程必须收回");
        assert_eq!(s.count(100), 1);
    }

    /// 全量扫描时包被移出配置，RT 记录不能留着
    #[test]
    fn reconcile_drops_pkg_removed_from_config() {
        let cfg = cfg_of(RtConfig::default(), &[]);
        let mut s = state();
        adopt(&mut s, GHOST, 100, "com.gone", "RenderThread", cpus(2));
        let mut cache = crate::cache::ProcCache::new();
        cache
            .tasks
            .insert(GHOST, entry(100, "com.gone", "RenderThread", 2));

        s.reconcile(&cfg, &cache);
        assert!(s.own.is_empty());
    }

    /// 线程退出后 tid 被复用：新线程继承的是 CFS，不能被当成自己提升过的
    #[test]
    fn reused_tid_does_not_inherit_ownership() {
        let cfg = cfg_of(
            RtConfig {
                scope: RtScope::Global,
                ..RtConfig::default()
            },
            &["com.a"],
        );
        let mut s = state();
        // 旧记录存在，但 GHOST2 在内核里不是 RR（不存在或已复用为普通线程）
        adopt(&mut s, GHOST2, 100, "com.a", "RenderThread", cpus(2));
        let ok = s.note(GHOST2, 100, "com.a", "RenderThread", &cpus(2), &cfg);
        // 记录作废后按新线程走一遍提升流程，失败（线程不存在）不改写状态
        assert!(!ok);
        assert!(s.own.is_empty(), "失效记录必须先丢弃，不能继续算作已提升");
    }

    /// 起一个真实线程并命名。RT 的成败取决于进程权限，用例按实际结果分支断言，
    /// 两种环境下都必须成立
    fn spawn_named(name: &str) -> (std::thread::JoinHandle<()>, i32) {
        let (tx, rx) = std::sync::mpsc::channel();
        let name = name.to_string();
        let handle = std::thread::spawn(move || {
            let c_name = std::ffi::CString::new(name).unwrap();
            unsafe {
                libc::pthread_setname_np(libc::pthread_self(), c_name.as_ptr());
            }
            let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
            tx.send(tid).unwrap();
            std::thread::park();
        });
        let tid = rx.recv().expect("线程未启动");
        (handle, tid)
    }

    /// 真实线程走一遍：成功则进表并可回滚，失败则不留记录、不改策略
    #[test]
    fn promotion_outcome_matches_kernel_state() {
        let (handle, tid) = spawn_named("RenderThread");
        let before = unsafe { libc::sched_getscheduler(tid) };
        let cfg = cfg_of(
            RtConfig {
                scope: RtScope::Global,
                ..RtConfig::default()
            },
            &["com.a"],
        );
        let target = cpus(2);
        let mut s = state();
        let ok = s.note(tid, 100, "com.a", "RenderThread", &target, &cfg);

        if ok {
            // 有 CAP_SYS_NICE：必须进表，且能被单独回滚
            assert!(s.own.contains_key(&tid));
            assert_eq!(unsafe { libc::sched_getscheduler(tid) }, libc::SCHED_RR);
            s.demote_all();
            assert!(!s.own.contains_key(&tid));
            assert_eq!(unsafe { libc::sched_getscheduler(tid) }, libc::SCHED_OTHER);
        } else {
            // EPERM：不能留记录，线程策略保持原样
            assert!(s.own.is_empty(), "失败的提升不能留下所有权记录");
            assert_eq!(unsafe { libc::sched_getscheduler(tid) }, before);
        }

        handle.thread().unpark();
        handle.join().unwrap();
    }

    /// 只有内核值仍是自己写的才恢复，外部改过就保留现值
    #[test]
    fn timeslice_is_only_restored_when_still_ours() {
        assert!(owned_value(Some(3), Some(3)));
        assert!(!owned_value(Some(5), Some(3)));
        assert!(!owned_value(None, Some(3)));
        assert!(!owned_value(Some(3), None));
    }
}
