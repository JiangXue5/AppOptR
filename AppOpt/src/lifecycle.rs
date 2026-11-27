//! 线程生命周期：记下我们接管过谁、接管前是什么样子、什么时候可以还回去。
//!
//! 与 `cache::TaskEntry` 分工明确：
//! - `TaskEntry` 是「这一轮该绑到哪」的缓存，全量重建时可以整体丢掉；
//! - `ManagedTask` 是「我们动过别人的什么」的账本，必须活到线程退出或规则撤销。
//!
//! 没有这本账，删掉一条规则只会清缓存，线程仍然留在 `AppOpt/4-6` 里——
//! 内核里的 cpuset 归属不是缓存，清不掉。

use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

use crate::apply_affinity::{read_cmdline, tid_comm};
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, SysGroup, attach_task, base_cpuset, classify_group, thread_cgroup};
use crate::lock_ignore_poison;
use crate::rule_match::{comm_to_pkg, thread_affinity};

/// 线程身份。内核会复用 tid，只有 starttime 能把「同一个号」区分成
/// 「同一个线程」。少了它，游戏重启后的新主线程会被当成旧线程去释放，
/// 结果是把别人的线程扔进一个陌生的组
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TaskIdentity {
    pub tid: i32,
    /// 线程组 ID，也就是进程的 PID。`/proc/<tid>/stat` 的第一列给的是
    /// 线程自己的号（TGID 只有主线程才等于它），所以这里单独从
    /// `/proc/<tid>/status` 的 `Tgid:` 取。0 表示没读——热路径只读 stat，
    /// 多一次 open 只为清账不合算
    pub tgid: i32,
    pub start_time: u64,
}

impl TaskIdentity {
    /// 「同一个号还是不是同一条线程」的唯一判据。
    ///
    /// 全项目只用这一处：生命周期账本、S7 落点、RT 所有权都拿它比对。
    /// 以前三处各自写 `start_time !=`，其中 RT 和落点还退化成只比 pid/tid，
    /// 于是同一个进程里复用的 TID 会继承上一条线程的调度状态。
    ///
    /// `tgid` 不参与判定：它回答的是「属于哪个进程」，用于退出时批量清账，
    /// 与线程同一性无关（`identity_of` 热路径也不读它）
    pub fn same_thread(&self, other: &Self) -> bool {
        self.tid == other.tid && self.start_time == other.start_time
    }
}

/// 线程的托管状态。切换都发生在同一次调用里，但保留成显式状态是为了让
/// 「为什么这个线程没被释放」在日志和后续排查里能直接回答
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ManagedState {
    /// 刚发现并即将接管
    Discovered,
    /// 已接管：组或亲和性至少有一项是我们写的
    Managed,
    /// 正在释放
    Releasing,
    /// 已释放（记录随即删除，保留这个值只为让流转完整）
    Released,
    /// 该释放但缺少可靠信息：原组未知、原组已消失、写入被拒。
    /// 这类线程我们放着不动，宁可留着限制也不猜
    RecoveryRequired,
}

/// 本模块在这条线程上做过的 RT 提升。
///
/// 与 `ManagedState` 分开记：`RecoveryRequired` 说的是「还原没做成，等重试」，
/// 而一条线程可能压根没提升过 RT。反过来 `pending_demote` 只描述 RT 这一项，
/// 它出现的原因和亲和性还原失败一样（写入被拒），所以两者共用同一个重试通道
/// `retry_recovery`——但原因要能分开说，日志里不能把「RR 没降下来」说成
/// 「亲和性没还回去」
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtTag {
    /// 提升时的规则允许集合。配置热更新后据此复核核数条件
    pub allowed: CpuSet,
    /// 撤销时 `sched_setscheduler` 失败：记录留着等下一轮重试。
    /// 以前是先删记录再降级，失败就等于「这条 RT 从此无人认领」——
    /// 线程一直停在 RR，模块却以为已经放手
    pub pending_demote: bool,
}

/// 一次接管的完整上下文。
pub struct ManagedTask {
    pub identity: TaskIdentity,
    /// 线程名。释放时重读一次，这里只作为读不到时的兜底
    pub comm: String,
    /// 接管前所在组（cgroup 相对路径，形如 `/top-app`）。`None` 表示
    /// 当时没读到——释放时不能拿「现在的组」当原组，那等于把一次意外
    /// 说成用户意图
    pub original_cpuset: Option<String>,
    /// 接管前的亲和性。空集合表示没读到，释放时跳过恢复
    pub original_affinity: CpuSet,
    /// 最后一次成功写入的组目录名（空表示 base），只用于日志里说清
    /// 「从哪个集合回到哪个组」
    pub last_applied_cpuset: String,
    /// 最后一次成功写入的亲和性。释放前拿它和当前值比对，只用于判断
    /// 「我们在这条线程上还有没有痕迹」；不一致不代表要放手——
    /// 系统改写亲和性是常态，该还原的仍然还原
    pub last_applied_affinity: CpuSet,
    pub owner_pkg: String,
    /// 这条线程由本模块提升到 RT 的记录。`None` 表示没提升过，或者已经降回去了。
    ///
    /// 放进账本而不是 RT 模块自己存一份：两者记的是同一件事——「我在那条线程上
    /// 动过手，要负责还回去」。分开存时，撤销 RT 失败的重试（`pending_demote`）
    /// 和还原亲和性失败的重试（`RecoveryRequired`）各写了一套，同一类失败
    /// 要维护两个通道，还容易一边成功一边失败留下中间态
    pub rt: Option<RtTag>,
    pub state: ManagedState,
}

impl Clone for ManagedTask {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity,
            comm: self.comm.clone(),
            original_cpuset: self.original_cpuset.clone(),
            original_affinity: self.original_affinity,
            last_applied_cpuset: self.last_applied_cpuset.clone(),
            last_applied_affinity: self.last_applied_affinity,
            owner_pkg: self.owner_pkg.clone(),
            rt: self.rt,
            state: self.state,
        }
    }
}

type Ledger = HashMap<i32, ManagedTask>;

/// 账本按 tid 索引。`Option` 只是为了让 `HashMap::new` 能出现在 static 里，
/// 首次使用时初始化
static LEDGER: Mutex<Option<Ledger>> = Mutex::new(None);

fn with_ledger<R>(f: impl FnOnce(&mut Ledger) -> R) -> R {
    let mut guard = lock_ignore_poison(&LEDGER);
    f(guard.get_or_insert_with(HashMap::new))
}

/// 全局账本是单例：跨模块（lifecycle / rt / cache）的用例都会动它，
/// 涉及清账的必须串行，否则互相把对方的记录清掉
#[cfg(test)]
pub static LEDGER_TEST_LOCK: Mutex<()> = Mutex::new(());

/// 测试用：直接塞一条「亲和性 + RT」记录。`note_rt` 要读真实 /proc，
/// 造不出不存在的 tid，而配额、对账这类逻辑只需要表内容
#[cfg(test)]
pub fn seed_rt(tid: i32, tgid: i32, start_time: u64, pkg: &str, comm: &str, allowed: &CpuSet) {
    with_ledger(|l| {
        l.insert(
            tid,
            ManagedTask {
                identity: TaskIdentity {
                    tid,
                    tgid,
                    start_time,
                },
                comm: comm.to_string(),
                original_cpuset: Some("/top-app".to_string()),
                original_affinity: CpuSet::default(),
                last_applied_cpuset: String::new(),
                last_applied_affinity: CpuSet::default(),
                owner_pkg: pkg.to_string(),
                rt: Some(RtTag {
                    allowed: *allowed,
                    pending_demote: false,
                }),
                state: ManagedState::Managed,
            },
        );
    });
}

#[cfg(test)]
pub fn ledger_clear() {
    with_ledger(|l| l.clear());
}

#[cfg(test)]
pub fn ledger_has(tid: i32) -> bool {
    with_ledger(|l| l.contains_key(&tid))
}

#[cfg(test)]
pub fn ledger_pkgs() -> Vec<String> {
    with_ledger(|l| l.values().map(|m| m.owner_pkg.clone()).collect())
}

#[cfg(test)]
pub fn ledger_state(tid: i32) -> Option<ManagedState> {
    with_ledger(|l| l.get(&tid).map(|m| m.state))
}

/// 读 `/proc/<tid>/stat` 拿身份。
///
/// 只取 `pid` 与 `starttime`（第 22 列）。字段切分必须从最后一个 `)` 之后
/// 开始：`comm` 允许出现空格和括号（`(Web Content)`、`(a (b))`），
/// 整体 `split_whitespace` 会把 comm 里的空格算成字段，后面全部错位
pub fn identity_of(tid: i32) -> Option<TaskIdentity> {
    let raw = fs::read_to_string(format!("/proc/{}/stat", tid)).ok()?;
    parse_stat(tid, &raw)
}

/// 连 TGID 一起读。多一次 open，只给「登记账本」「启动对账」这类
/// 一次性路径用；每轮校验只要 starttime，用 `identity_of` 就够
fn identity_full(tid: i32) -> Option<TaskIdentity> {
    let mut id = identity_of(tid)?;
    id.tgid = read_tgid(tid).unwrap_or(0);
    Some(id)
}

/// `/proc/<tid>/status` 的 `Tgid:` 一行
fn read_tgid(tid: i32) -> Option<i32> {
    let raw = fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    raw.lines().find_map(|l| {
        l.strip_prefix("Tgid:")
            .and_then(|v| v.trim().parse::<i32>().ok())
    })
}

fn parse_stat(tid: i32, raw: &str) -> Option<TaskIdentity> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close < open {
        return None;
    }
    let pid: i32 = raw.get(..open)?.trim().parse().ok()?;
    // 第一列是线程自己的号。和请求的号不一致说明中途被复用/退出了，
    // 拿这份数据去对账会把新线程当成旧线程
    if pid != tid {
        return None;
    }
    let rest = raw.get(close + 1..)?;
    // `)` 之后第一个字段是 state（第 3 列），starttime 是第 22 列 → nth(19)
    let start_time: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    Some(TaskIdentity {
        tid,
        // stat 里没有 TGID，只有线程自己的号。调用方要 TGID 时用
        // `identity_full` 补，这里留 0 表示未知
        tgid: 0,
        start_time,
    })
}

/// 首次成功接管时登记。
///
/// 只在「真的写成功了」之后调用：匹配到规则但没写进去不算接管，把这种
/// 情况记成已接管，规则一删就会去释放一个我们从没动过的线程
pub fn note_managed(
    tid: i32,
    pkg: &str,
    comm: &str,
    original: (Option<String>, CpuSet),
    applied: &CpuSet,
    cpuset_dir: &str,
) {
    let Some(identity) = identity_full(tid) else {
        return;
    };
    with_ledger(|l| {
        if let Some(old) = l.get(&tid)
            && old.identity.start_time == identity.start_time
        {
            // 已登记过：只更新「最后写入」的那两格，原始状态不能覆盖
            let m = l.get_mut(&tid).expect("刚刚确认存在");
            m.state = ManagedState::Managed;
            m.last_applied_affinity = *applied;
            m.last_applied_cpuset = cpuset_dir.to_string();
            return;
        }
        // 没登记过，或 tid 被复用：旧账作废，按新线程重新记。
        // RT 提升可能先于亲和性接管发生（RT-only 记录），同一条线程的
        // 记录必须把 rt 带过来——覆盖成 None 等于账本忘了它还停在 RR
        let kept_rt = l
            .get(&tid)
            .filter(|old| old.identity.same_thread(&identity))
            .and_then(|old| old.rt);
        l.insert(
            tid,
            ManagedTask {
                identity,
                comm: comm.to_string(),
                original_cpuset: original.0,
                original_affinity: original.1,
                last_applied_cpuset: cpuset_dir.to_string(),
                last_applied_affinity: *applied,
                owner_pkg: pkg.to_string(),
                rt: kept_rt,
                // 登记与接管是同一件事，这里让状态机从「发现」推进到「已接管」
                state: ManagedState::Discovered,
            },
        );
        if let Some(m) = l.get_mut(&tid) {
            m.state = ManagedState::Managed;
        }
    });
}

/// 已接管线程又写了一次（S7 迁移、规则变更后的重绑）。
/// 原始状态不动，只把「最后写入」更新到当前值——释放前的比对靠它
pub fn note_applied(tid: i32, applied: &CpuSet, cpuset_dir: &str) {
    with_ledger(|l| {
        if let Some(m) = l.get_mut(&tid) {
            m.last_applied_affinity = *applied;
            m.last_applied_cpuset = cpuset_dir.to_string();
            m.state = ManagedState::Managed;
        }
    });
}

/// RT 提升成功。线程可能还没有亲和性接管记录（规则只写了 RT、或亲和性
/// 那次写入失败），这时补一条只含 RT 的账：撤销 RR 时同样需要知道原样。
///
/// 收完整身份而不是自己去读：调用方刚为别的判断读过一次 stat，
/// 这里再读一遍等于每个新线程多两次 open
pub fn note_rt(identity: TaskIdentity, pkg: &str, comm: &str, allowed: &CpuSet) {
    let tid = identity.tid;
    with_ledger(|l| {
        match l.get_mut(&tid) {
            // 同一条线程：只动 rt 这一格，原始状态与最后写入一概不碰。
            // 线程名与包名要跟着更新——`prune` 按它们判断是否仍符合策略，
            // 改名后不更新会把「已经不该提升」的线程一直留着
            Some(m) if m.identity.same_thread(&identity) => {
                m.comm = comm.to_string();
                m.owner_pkg = pkg.to_string();
                m.rt = Some(RtTag {
                    allowed: *allowed,
                    pending_demote: false,
                });
            }
            // 没记录，或号被复用：旧账作废，按新线程重记
            _ => {
                l.insert(
                    tid,
                    ManagedTask {
                        identity,
                        comm: comm.to_string(),
                        // 亲和性从没被我们改过：这两个空值让 `judge` 跳过恢复
                        original_cpuset: None,
                        original_affinity: CpuSet::default(),
                        last_applied_cpuset: String::new(),
                        last_applied_affinity: CpuSet::default(),
                        owner_pkg: pkg.to_string(),
                        rt: Some(RtTag {
                            allowed: *allowed,
                            pending_demote: false,
                        }),
                        state: ManagedState::Managed,
                    },
                );
            }
        }
    });
}

/// 一次查出「这个号是不是被复用了」和「本线程的 RT 记录」。
/// 分成两次调用要拿两次锁，而这两件事本来就是同一条记录的两种答案
pub fn rt_lookup(tid: i32, id: &TaskIdentity) -> (bool, Option<RtTag>) {
    with_ledger(|l| match l.get(&tid) {
        Some(m) if !m.identity.same_thread(id) => (true, None),
        Some(m) => (false, m.rt),
        None => (false, None),
    })
}

/// 不做身份校验的版本。只给「已经核对过身份、或线程已经不在了」的路径用
pub fn rt_owned_raw(tid: i32) -> Option<RtTag> {
    with_ledger(|l| l.get(&tid).and_then(|m| m.rt))
}

/// 降级成功：只清 rt 这一格。记录本身要留着——亲和性可能还被我们握着
pub fn clear_rt(tid: i32) {
    with_ledger(|l| {
        let Some(m) = l.get_mut(&tid) else {
            return;
        };
        let was_pending = m.rt.is_some_and(|r| r.pending_demote);
        m.rt = None;
        // RT 待降是这条记录进入 RecoveryRequired 的唯一原因时，降下来
        // 就该退出来：否则 `recovery_required()` 永远大于 0，30 秒一次
        // 的重试通道一直空转，还会把日志签名压住
        if was_pending && m.state == ManagedState::RecoveryRequired {
            m.state = ManagedState::Managed;
        }
        // 只提过 RT、亲和性从没被我们动过的记录，清完 rt 就什么都不剩了。
        // 留着会让账本越攒越长，`managed_count` 也跟着虚高
        if m.rt.is_none() && m.original_cpuset.is_none() && m.original_affinity.count() == 0 {
            l.remove(&tid);
        }
    });
}

/// 撤销 RT 失败：打上待重试标记，交给 `retry_recovery` 的 30 秒通道。
///
/// 以前 RT 自己有一个 `pending_demote` 和一套「等下次全量扫描再试」，
/// 跟账本的 `RecoveryRequired` 是同一件事的两份实现。合并后只有一条重试通道，
/// 且不必等下一次全量扫描（proc 模式 60 秒、eBPF 只在配置变更时）
pub fn mark_rt_pending(tid: i32) {
    with_ledger(|l| {
        if let Some(m) = l.get_mut(&tid)
            && let Some(rt) = m.rt.as_mut()
        {
            rt.pending_demote = true;
            m.state = ManagedState::RecoveryRequired;
        }
    });
}

/// 一条 RT 记录的完整快照。对账时要拿去判断策略与配额，但闭包里不能
/// 直接改账本：降级是系统调用，持锁做几十次 `sched_setscheduler` 会把
/// web 线程一起卡住
pub struct RtRecord {
    pub tid: i32,
    pub identity: TaskIdentity,
    pub pkg: String,
    pub comm: String,
    pub tag: RtTag,
}

/// 当前由本模块提升的线程快照
pub fn rt_records() -> Vec<RtRecord> {
    with_ledger(|l| {
        l.iter()
            .filter_map(|(&tid, m)| {
                Some(RtRecord {
                    tid,
                    identity: m.identity,
                    pkg: m.owner_pkg.clone(),
                    comm: m.comm.clone(),
                    tag: m.rt?,
                })
            })
            .collect()
    })
}

/// 某进程名下被提升的线程数。配额判断用，直接数账本，不另存计数器——
/// 计数器与集合不同步时，配额会算错，且错的方向是「多提升几条」
pub fn rt_count(tgid: i32) -> usize {
    with_ledger(|l| {
        l.values()
            .filter(|m| m.rt.is_some() && m.identity.tgid == tgid)
            .count()
    })
}

/// 线程退出或缓存清理时删记录。这里只删账，不动内核——线程都没了，无组可还
pub fn forget(tid: i32) {
    with_ledger(|l| {
        l.remove(&tid);
    });
}

/// 进程退出：它名下的线程全都不会再回来，按 tgid 一并清掉。
/// 只删 tid 不够：进程退出事件的时机可能早于线程退出事件被消费。
///
/// 账本里存的是线程自己的号（TID），不是进程号，所以必须比 `tgid`：
/// 以前比的是从 stat 第一列读出的「pid」，那其实还是 TID，一个进程只有
/// 主线程能匹配上，其余线程的账要等下一轮扫描才发现线程没了
pub fn forget_pid(pid: i32) {
    with_ledger(|l| {
        l.retain(|_, m| m.identity.tgid != pid && m.identity.tid != pid);
    });
}

/// 当前接管的线程数。Web 诊断与启动对账用
pub fn managed_count() -> usize {
    with_ledger(|l| l.len())
}

/// 处于 RecoveryRequired 的线程数
pub fn recovery_required() -> usize {
    with_ledger(|l| {
        l.values()
            .filter(|m| m.state == ManagedState::RecoveryRequired)
            .count()
    })
}

/// 释放判定。抽成纯函数是为了能脱离真实 cgroup 单测：
/// 这套判断错一次，轻则线程被扔进错误的组，重则覆盖掉别人的调度结果
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    /// 可以释放。参数表示线程此刻是否还在我们自己的组里：
    /// 在，才需要迁回原组；不在，只恢复亲和性
    Release(bool),
    /// 只收 RT，组与亲和性一概不动：线程仍在规则管理下（亲和性该维持），
    /// 但已经不符合 RT 策略了。整条 Release 会把还在用的绑核一起撤掉
    DemoteRt,
    /// 只删记录：线程没了、号被复用、组与亲和性都不在我们手里
    Drop(&'static str),
    /// 仍受管，不释放
    Keep,
    /// 该放但放不了，保留记录等下一次
    Hold(&'static str),
}

fn judge(
    rec: &ManagedTask,
    now: Option<TaskIdentity>,
    cgroup: Option<&str>,
    affinity: Option<CpuSet>,
    still_managed: bool,
    force: bool,
) -> Verdict {
    let Some(id) = now else {
        return Verdict::Drop("线程已退出");
    };
    // starttime 是同一性判据：tid 由账本键保证已相同，只有它能把
    // 「同一个号」区分成「同一个线程」
    if !rec.identity.same_thread(&id) {
        return Verdict::Drop("tid 已被复用");
    }
    if still_managed && !force {
        // 线程仍受管，但 RT 撤销失败过：只补收 RT，不释放亲和性。
        // 这是 RT 从自己那套 `pending_demote` 并进账本后的统一重试入口——
        // 以前它等下一次全量扫描（proc 60 秒、eBPF 只在配置变更时），
        // 现在走 30 秒通道
        if rec.rt.is_some_and(|r| r.pending_demote) {
            return Verdict::DemoteRt;
        }
        return Verdict::Keep;
    }
    // 之前恢复失败的记录不参与「什么都没留下」的判定：组和亲和性都不在
    // 我们手里，只能说明系统在这期间改写过，不能说明原值不用还原了。
    // 按 Drop 处理等于把恢复依据连同记录一起扔掉，线程永远停在限制里
    let recovering = rec.state == ManagedState::RecoveryRequired;
    let Some(path) = cgroup else {
        return if recovering {
            Verdict::Hold("读不到 cgroup，稍后重试")
        } else {
            Verdict::Drop("读不到 cgroup")
        };
    };
    let in_own = classify_group(path) == SysGroup::Own;
    // `ours` 只用来判断「我们有没有在这条线程上留下痕迹」，不再作为
    // 「别人接管了、我们别动」的理由：本模块是唯一的绑核方，系统改写
    // 亲和性是常态（切后台收敛、热插拔、厂商 HAL）。留下的限制一律撤销
    //
    // RT 也算痕迹：提升过的线程即使亲和性被系统改写、也从没迁过组，
    // 撤销时必须先把 RR 收回来。少了这一项，一条只提了 RT 的记录会因为
    // 「组和亲和性都不在我们手里」被当成空账删掉，线程永久停在 RR
    let ours = affinity.is_none_or(|cur| cur == rec.last_applied_affinity) || rec.rt.is_some();
    // 组与亲和性都不在我们手里：没留下任何限制，连记录一起清掉
    if !in_own && !ours && !recovering {
        return Verdict::Drop("组与亲和性都不在我们手里");
    }
    if in_own {
        // 组是我们的，规则一撤就得还。迁组时内核会按原组允许集合重算
        // 亲和性，被系统改写过的掩码也就跟着覆盖掉了
        if rec.original_cpuset.is_none() {
            // 只有 RT 记录、组不是我们迁进来的（规则写入失败的那一类）：
            // 迁回去没有依据，但 RR 必须收掉
            if rec.rt.is_some() {
                return Verdict::Release(false);
            }
            return Verdict::Hold("接管前的组未知");
        }
        return Verdict::Release(true);
    }
    // 不在我们组里，组从没被我们动过：只把亲和性还原
    if rec.original_affinity.count() == 0 {
        // 从没接管过亲和性、只提升过 RT：把 RR 收回来就行。
        // 没有这条，RT 记录会停在「接管前的亲和性未知」上被 Drop，
        // 而它压根不需要还原亲和性
        if rec.rt.is_some() {
            return Verdict::Release(false);
        }
        return Verdict::Drop("接管前的亲和性未知");
    }
    Verdict::Release(false)
}

/// 释放结果。用计数而不是逐行日志：删掉一条包级规则可能同时放开上百个线程
#[derive(Default, Debug, PartialEq, Eq)]
pub struct ReleaseReport {
    pub released: usize,
    pub dropped: usize,
    pub kept: usize,
    pub failed: usize,
    /// 只收回了 RT、亲和性仍然维持的线程数。与 `released` 分开：
    /// 前者是「还在管、只降了 RT」，后者是「彻底还回去了」
    pub rt_demoted: usize,
}

/// cgroup 相对路径 → 挂载点下的绝对路径
fn abs_cgroup(rel: &str) -> String {
    let p = rel.trim_end_matches('/');
    if p.is_empty() || p == "/" {
        "/dev/cpuset".to_string()
    } else if p.starts_with("/dev/cpuset") {
        p.to_string()
    } else {
        format!("/dev/cpuset{}", p)
    }
}

/// 把线程还回去：先收 RT，再迁组（需要时），最后恢复亲和性。
///
/// 顺序有两条约束：
/// 1. RT 必须先收。提升过的线程如果降级失败而我们又把亲和性放开到全核，
///    一个 RR 线程跑满全机，比留在小核更糟。失败就整条记录置为
///    `RecoveryRequired`，下一轮连亲和性一起重试
/// 2. 迁组必须在恢复亲和性之前：`cgroup.procs` 一写，内核会把线程亲和性
///    重置成新组允许的集合，先恢复再迁组等于白写
fn restore(rec: &ManagedTask, in_own: bool) -> Result<(), (i32, &'static str)> {
    // 只做内核操作，不碰账本：`clear_rt` 要再进一次账本的锁，而调用方
    // 可能在持锁状态里（std 的 Mutex 不可重入）。清账由 `release_list` 负责
    if rec.rt.is_some() {
        crate::rt::demote_one(rec.identity.tid).map_err(|errno| {
            if errno == libc::ESRCH {
                (errno, "线程已退出")
            } else if errno == libc::EPERM || errno == libc::EACCES {
                (errno, "撤销 RT 被拒（权限）")
            } else {
                (errno, "撤销 RT 失败")
            }
        })?;
    }
    // 只有线程还在我们组里才谈得上「迁回去」。它从来没被迁进来过
    // （cpuset 不可用 / 熔断期间只写了亲和性）时硬写原组反而是乱搬
    if in_own
        && let Some(orig) = rec.original_cpuset.as_deref()
        && classify_group(orig) != SysGroup::Own
    {
        let path = format!("{}/tasks", abs_cgroup(orig));
        attach_task(&path, rec.identity.tid).map_err(|e| {
            let errno = e.raw_os_error().unwrap_or(0);
            if errno == libc::ENOENT {
                (errno, "原组已不存在")
            } else if errno == libc::EINVAL {
                (errno, "原组与线程当前允许的核没有交集")
            } else {
                (errno, "写回原组被拒")
            }
        })?;
    }
    // 原亲和性读不到（空集合）就交给系统按组重新给，不猜一个集合写进去。
    // 读到就写：不管当前值是不是我们留下的，都按原值覆盖——系统改写过的
    // 掩码同样要还原，这是「删除规则即解除限制」的一部分。
    //
    // 写失败必须往上抛：以前这里是 `let _ =`，写不进去也返回成功，外层
    // 随即删掉账本，这条线程就再也回不到接管前的集合了。线程已退出
    // （ESRCH）不算失败，下一轮身份检查会把它清掉
    if rec.original_affinity.count() > 0 {
        rec.original_affinity
            .set_affinity(rec.identity.tid)
            .map_err(|e| {
                let errno = e.raw_os_error().unwrap_or(0);
                if errno == libc::ESRCH {
                    (errno, "线程已退出")
                } else if errno == libc::EINVAL {
                    (errno, "原集合与当前可用核没有交集")
                } else if errno == libc::EPERM || errno == libc::EACCES {
                    (errno, "恢复亲和性被拒（权限）")
                } else {
                    (errno, "恢复亲和性失败")
                }
            })?;
    }
    Ok(())
}

/// 释放所有「已经不受任何规则管理」的受管线程。
///
/// `force` 为真时跳过规则检查（退出前调用）：规则还在，但模块要走，
/// 线程不该留在我们的组里。身份与组归属两项检查照做——这两项判断的是
/// 「这个号还是不是那条线程」，不是「别人有没有动过它」。
pub fn release_unmanaged(cfg: &AppConfig, force: bool) -> ReleaseReport {
    let list: Vec<ManagedTask> = with_ledger(|l| l.values().cloned().collect());
    release_list(cfg, force, list)
}

/// 只重试处于 `RecoveryRequired` 的记录。
///
/// 主循环每 30 秒调一次。以前这里复用 `release_unmanaged`，等于为了几条卡住
/// 的记录把整套账本连字符串一起克隆，再对每个健康线程各读一次 stat 与 comm——
/// 受管线程一多，这份白工就是每秒几十次 open。重试只需要待恢复的那几条。
pub fn retry_recovery(cfg: &AppConfig) -> ReleaseReport {
    let list: Vec<ManagedTask> = with_ledger(|l| {
        l.values()
            .filter(|m| m.state == ManagedState::RecoveryRequired)
            .cloned()
            .collect()
    });
    if list.is_empty() {
        return ReleaseReport::default();
    }
    release_list(cfg, false, list)
}

/// 对给定的记录做一遍释放判定。`force` 为真时跳过规则检查（退出前调用）
fn release_list(cfg: &AppConfig, force: bool, list: Vec<ManagedTask>) -> ReleaseReport {
    let mut rep = ReleaseReport::default();
    let mut samples: Vec<String> = Vec::new();
    let mut held: Vec<String> = Vec::new();
    // 丢弃原因按种类计数：只报「清理了 N 条」无法回答「为什么没释放」，
    // 而这恰恰是排查「删了规则线程还钉着」时第一眼要看的东西
    let mut why: Vec<(&'static str, usize)> = Vec::new();
    for rec in list {
        let tid = rec.identity.tid;
        // 先确认线程还在：退出事件丢失时账本里会留一批已退出的号，
        // 这是最常见的一类，一次 stat 就能清掉
        let Some(now) = identity_of(tid) else {
            with_ledger(|l| {
                l.remove(&tid);
            });
            rep.dropped += 1;
            note_why(&mut why, "线程已退出");
            continue;
        };
        // 包整个被删掉时连 comm 都不用读：一定不受管
        let pkg_alive = cfg.pkgs.contains(&rec.owner_pkg);
        let comm = if pkg_alive {
            // 线程名可能已经改过（rename 事件丢了），重读一次再判是否仍受管：
            // 拿旧名字判会把「已不再匹配」的线程当成仍受管，白白不释放
            tid_comm(tid).unwrap_or_else(|| rec.comm.clone())
        } else {
            rec.comm.clone()
        };
        let still = pkg_alive && thread_affinity(&rec.owner_pkg, &comm, cfg).is_some();
        // 日志里的名字：包级规则接管的线程 comm 是空的，用包名才能说清是谁
        let label = if comm.is_empty() {
            rec.owner_pkg.as_str()
        } else {
            comm.as_str()
        };
        // 仍受管时到此为止：稳态只花两次 open（stat + comm），不读组与亲和性。
        // 配置变更可能只是一条无关规则，不该为此扫一遍所有受管线程的 cgroup。
        //
        // 例外是 RT 待撤销：这类线程仍匹配规则（亲和性要维持），但 RR 必须
        // 收回来。放它过去，下一句 judge 会返回 `DemoteRt`
        if still && !force && !rec.rt.is_some_and(|r| r.pending_demote) {
            rep.kept += 1;
            continue;
        }
        let cgroup = thread_cgroup(tid);
        let affinity = CpuSet::get_affinity(tid);
        match judge(&rec, Some(now), cgroup.as_deref(), affinity, still, force) {
            Verdict::Keep => rep.kept += 1,
            Verdict::DemoteRt => {
                match crate::rt::demote_one(tid) {
                    Ok(()) => {
                        clear_rt(tid);
                        rep.rt_demoted += 1;
                    }
                    // 线程已退出也会走到这里（Ok），Err 只剩真正的写入失败：
                    // 标记保持，等下一轮
                    Err(_) => rep.failed += 1,
                }
            }
            Verdict::Drop(reason) => {
                with_ledger(|l| {
                    l.remove(&tid);
                });
                rep.dropped += 1;
                note_why(&mut why, reason);
            }
            Verdict::Hold(why) => {
                with_ledger(|l| {
                    if let Some(m) = l.get_mut(&tid) {
                        m.state = ManagedState::RecoveryRequired;
                    }
                });
                rep.failed += 1;
                if held.len() < 3 {
                    held.push(format!("{}({}) {}", label, tid, why));
                }
            }
            Verdict::Release(in_own) => {
                with_ledger(|l| {
                    if let Some(m) = l.get_mut(&tid) {
                        m.state = ManagedState::Releasing;
                    }
                });
                match restore(&rec, in_own) {
                    Ok(()) => {
                        with_ledger(|l| {
                            if let Some(m) = l.get_mut(&tid) {
                                m.state = ManagedState::Released;
                            }
                            l.remove(&tid);
                        });
                        rep.released += 1;
                        if samples.len() < 3 {
                            let from = if rec.last_applied_cpuset.is_empty() {
                                "base".to_string()
                            } else {
                                rec.last_applied_cpuset.clone()
                            };
                            let to = rec
                                .original_cpuset
                                .as_deref()
                                .map(|o| o.trim_matches('/').to_string())
                                .unwrap_or_else(|| "-".to_string());
                            samples.push(format!("{}({}) {}→{}", label, tid, from, to));
                        }
                    }
                    Err((_errno, why)) => {
                        with_ledger(|l| {
                            if let Some(m) = l.get_mut(&tid) {
                                m.state = ManagedState::RecoveryRequired;
                            }
                        });
                        rep.failed += 1;
                        if held.len() < 3 {
                            held.push(format!("{}({}) {}", label, tid, why));
                        }
                    }
                }
            }
        }
    }
    report(&rep, samples, held, &why, force);
    rep
}

fn note_why(list: &mut Vec<(&'static str, usize)>, reason: &'static str) {
    match list.iter_mut().find(|(r, _)| *r == reason) {
        Some((_, n)) => *n += 1,
        None => list.push((reason, 1)),
    }
}

/// 上一次打过的失败/待恢复签名。待恢复记录按周期重试，同一个失败会反复
/// 走到这里；日志只在「状态变了」时打一行，否则 30 秒一条会盖住别的事件
static LAST_WARN: Mutex<Option<String>> = Mutex::new(None);

/// 签名与上次不同才返回 true，并记下这一次
fn first_time(key: String) -> bool {
    let mut g = lock_ignore_poison(&LAST_WARN);
    if g.as_deref() == Some(key.as_str()) {
        return false;
    }
    *g = Some(key);
    true
}

fn report(
    rep: &ReleaseReport,
    samples: Vec<String>,
    held: Vec<String>,
    why: &[(&'static str, usize)],
    force: bool,
) {
    if rep.released > 0 {
        // 有线程真正还回去了，说明状态在好转：清掉签名，下次再失败要重新报
        *lock_ignore_poison(&LAST_WARN) = None;
        crate::diag::tag(
            "事件",
            &format!(
                "已释放 {} 个线程回原组（{}）：{}{}",
                rep.released,
                if force {
                    "退出前还原"
                } else {
                    "规则已撤销"
                },
                samples.join("、"),
                if rep.released > samples.len() {
                    " 等"
                } else {
                    ""
                }
            ),
        );
    }
    if rep.rt_demoted > 0 {
        crate::diag::tag(
            "配置",
            &format!("{} 个线程已撤销 RT（绑核维持不变）", rep.rt_demoted),
        );
    }
    if rep.failed > 0 {
        let key = format!("f:{}:{}", rep.failed, held.join("、"));
        if first_time(key) {
            crate::diag::tag(
                "警告",
                &format!(
                    "{} 个线程无法安全释放（账本共 {} 条），保持现状留待重试：{}{}",
                    rep.failed,
                    managed_count(),
                    held.join("、"),
                    if rep.failed > held.len() { " 等" } else { "" }
                ),
            );
        }
    }
    if rep.dropped > 0 {
        let detail = why
            .iter()
            .map(|(r, n)| format!("{} {}", r, n))
            .collect::<Vec<_>>()
            .join("、");
        crate::diag::tag(
            "配置",
            &format!("清理 {} 条失效的接管记录：{}", rep.dropped, detail),
        );
    }
    let pending = recovery_required();
    if pending > 0 && rep.failed == 0 && first_time(format!("p:{}", pending)) {
        crate::diag::tag(
            "警告",
            &format!(
                "仍有 {} 个线程处于待恢复状态，接管前的组未知，不做处理",
                pending
            ),
        );
    }
}

/// 启动对账结果
#[derive(Default, Debug)]
pub struct OrphanReport {
    /// AppOpt 各组里挂着的线程总数
    pub found: usize,
    /// 仍匹配规则、交给正常扫描重新接管
    pub managed: usize,
    /// 已不匹配规则、已从子组移到主体（全核）解除限制
    pub freed: usize,
    /// 仍在主体组或无法判断，记录但不移动
    pub unknown: usize,
    pub samples: Vec<String>,
}

/// 启动时的安全对账。
///
/// 上个进程若是被 `kill -9` 结束的，账本随进程消失，而线程仍留在
/// `AppOpt/<集合>` 里。这时不能凭「当前组」反推原始组——那等于把一次意外
/// 说成用户意图。能安全做的只有两件事：
/// 1. 仍匹配规则的线程交给正常扫描重新接管（这里只统计）；
/// 2. 已不匹配任何规则、却还挂在子组里的线程，移到 `AppOpt` 主体。
///    base 的 cpus 是在线全核，移过去等于解除限制，且不伪装成「还原原组」
pub fn sweep_orphans(cfg: &AppConfig) -> OrphanReport {
    let mut rep = OrphanReport::default();
    for (dir, tasks_path) in tasks_dirs() {
        let Ok(raw) = fs::read_to_string(&tasks_path) else {
            continue;
        };
        for line in raw.lines() {
            let Ok(tid) = line.trim().parse::<i32>() else {
                continue;
            };
            // 内核在任务退出时会把 tid 从 tasks 里摘掉，读到不存在的号说明
            // 是两次读之间的窗口，跳过即可
            let Some(id) = identity_full(tid) else {
                continue;
            };
            rep.found += 1;
            let comm = tid_comm(tid).unwrap_or_default();
            // 主线程的 comm 会被内核截到 15 字节，直接和包名比会漏掉长包名；
            // `comm_to_pkg` 带截断键与属主校验，是现成的正确判据。
            // cmdline 属于进程，必须用 TGID 读：拿 TID 去读工作线程，
            // 内核给的是空的，长包名就永远认不出来
            let owner = if id.tgid > 0 { id.tgid } else { id.tid };
            let pkg = read_cmdline(owner)
                .filter(|p| cfg.pkgs.contains(p))
                .or_else(|| comm_to_pkg(owner, &comm, cfg));
            let still = pkg
                .as_ref()
                .is_some_and(|p| thread_affinity(p, &comm, cfg).is_some());
            if still {
                rep.managed += 1;
                continue;
            }
            if dir.is_empty() {
                // 已经在主体组，再往上没有「更安全的地方」了
                rep.unknown += 1;
                continue;
            }
            let base_tasks = format!("{}/tasks", base_cpuset());
            if attach_task(&base_tasks, tid).is_ok() {
                rep.freed += 1;
                if rep.samples.len() < 5 {
                    rep.samples.push(format!("{}>{}", comm, dir));
                }
            } else {
                rep.unknown += 1;
            }
        }
    }
    if rep.found > 0 {
        let mut line = format!(
            "上次运行遗留 {} 个线程在 AppOpt 组：{} 个仍匹配规则（将重新接管），{} 个已不匹配",
            rep.found,
            rep.managed,
            rep.found - rep.managed
        );
        if rep.freed > 0 {
            line.push_str(&format!(
                "，其中 {} 个已从子组移到主体全核（{}）",
                rep.freed,
                rep.samples.join("、")
            ));
        }
        if rep.unknown > 0 {
            line.push_str(&format!("，{} 个无法判断（保持原样）", rep.unknown));
        }
        crate::diag::tag("环境", &line);
    }
    rep
}

/// `AppOpt` 主体与每个子目录的 tasks 路径。顺序上主体在前：
/// 先看主体里有没有残留，再看子组，日志读起来与目录结构一致
fn tasks_dirs() -> Vec<(String, String)> {
    let base = base_cpuset();
    let mut out = vec![(String::new(), format!("{}/tasks", base))];
    let Ok(entries) = fs::read_dir(&base) else {
        return out;
    };
    for entry in entries.flatten() {
        // cgroupfs 里每个控制文件也在目录列表里，只认子目录
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.is_empty() {
            continue;
        }
        out.push((name.clone(), format!("{}/{}/tasks", base, name)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpuset::parse_cpu_ranges;

    fn set(spec: &str) -> CpuSet {
        parse_cpu_ranges(spec, None)
    }

    /// 起一条常住线程，返回它的 tid。恢复失败要靠真实线程才能触发
    /// （`sched_setaffinity` 只认真实存在的号）
    fn spawn_named(name: &str) -> (std::thread::JoinHandle<()>, i32) {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
                tx.send(tid).expect("回传 tid");
                std::thread::park();
            })
            .expect("起线程");
        let tid = rx.recv().expect("拿 tid");
        (handle, tid)
    }

    /// 全局账本是单例：涉及清账的用例必须串行，否则互相把对方的记录清掉
    use super::LEDGER_TEST_LOCK;

    fn rec(orig: Option<&str>, applied: &str, aff: &CpuSet) -> ManagedTask {
        ManagedTask {
            identity: TaskIdentity {
                tid: 42,
                tgid: 42,
                start_time: 9_000,
            },
            comm: "UnityMain".to_string(),
            original_cpuset: orig.map(|s| s.to_string()),
            original_affinity: set("0-7"),
            last_applied_cpuset: applied.to_string(),
            last_applied_affinity: *aff,
            owner_pkg: "com.test.game".to_string(),
            rt: None,
            state: ManagedState::Managed,
        }
    }

    /// comm 允许含空格和括号，从最后一个 `)` 之后切字段才不会错位
    #[test]
    fn stat_parses_comm_with_spaces_and_parens() {
        let raw = "1234 (Web Content (x)) S 1 1234 1234 0 -1 4194560 100 0 0 0 10 20 0 0 20 0 1 0 987654 0 0";
        let id = parse_stat(1234, raw).expect("应能解析");
        assert_eq!(id.start_time, 987_654);
        assert_eq!(id.tid, 1234);
    }

    /// 字段不够（进程刚退出，stat 被截断）必须返回 None，不能猜一个 0
    #[test]
    fn truncated_stat_is_rejected() {
        assert!(parse_stat(1, "1 (sh) S 1 1").is_none());
        assert!(parse_stat(1, "1 (sh)").is_none());
        assert!(parse_stat(1, "garbage").is_none());
    }

    /// 真实进程的自身身份可读，且 starttime 非零
    #[test]
    fn identity_of_self_is_readable() {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
        let id = identity_of(tid).expect("读自身 stat 失败");
        assert_eq!(id.tid, tid);
        assert!(id.start_time > 0);
        // identity_of 只读 stat，TGID 留空；要 TGID 的路径用 identity_full
        assert_eq!(id.tgid, 0);
    }

    /// tid 被复用：只删记录，绝不按旧账去动新线程
    #[test]
    fn reused_tid_is_dropped_not_released() {
        let r = rec(Some("/top-app"), "4-6", &set("4-6"));
        let fresh = TaskIdentity {
            tid: 42,
            tgid: 42,
            start_time: 9_001,
        };
        assert!(matches!(
            judge(
                &r,
                Some(fresh),
                Some("/AppOpt/4-6"),
                Some(set("4-6")),
                false,
                false
            ),
            Verdict::Drop(_)
        ));
    }

    /// 线程已经不在自己组里：外部接管了，只清理记录
    #[test]
    fn thread_moved_away_is_not_touched() {
        let r = rec(Some("/top-app"), "4-6", &set("4-6"));
        assert!(matches!(
            judge(
                &r,
                Some(r.identity),
                Some("/top-app"),
                Some(set("0-7")),
                false,
                false
            ),
            Verdict::Drop(_)
        ));
    }

    /// 亲和性被外部改过（组还在）：照常释放，不因「有人动过」而保留限制。
    ///
    /// 这里曾经返回 Drop，理由是「别覆盖别人的决定」。但系统自己也会改写
    /// 亲和性（切后台收敛、热插拔、厂商 HAL），与第三方调度模块的写入在
    /// 代码里无法区分；按 Drop 处理的代价是线程永久留在已经没有规则对应的
    /// 组里——规则删了限制还在，正是 M0 要修的那个洞。
    /// 本模块是唯一的绑核方，留下的痕迹一律撤销
    #[test]
    fn rewritten_affinity_still_returns_group() {
        let r = rec(Some("/top-app"), "4-6", &set("4-6"));
        assert_eq!(
            judge(
                &r,
                Some(r.identity),
                Some("/AppOpt/4-6"),
                Some(set("0-3")),
                false,
                false
            ),
            Verdict::Release(true)
        );
        // 退出时同理：模块要走，线程不能留在我们建的组里
        assert_eq!(
            judge(
                &r,
                Some(r.identity),
                Some("/AppOpt/4-6"),
                Some(set("0-7")),
                true,
                true
            ),
            Verdict::Release(true)
        );
    }

    /// 之前恢复失败的记录，不能因为「组与亲和性都不在我们手里」被判死。
    /// 那只说明系统在这期间改写过，不说明原值不用还原了；按 Drop 处理
    /// 等于把恢复依据连同记录一起扔掉
    #[test]
    fn recovery_required_is_retried_not_dropped() {
        let mut r = rec(Some("/top-app"), "4-6", &set("4-6"));
        r.state = ManagedState::RecoveryRequired;
        assert_eq!(
            judge(
                &r,
                Some(r.identity),
                Some("/top-app"),
                Some(set("0-3")),
                false,
                false
            ),
            Verdict::Release(false)
        );
    }

    /// 恢复亲和性失败必须往上报。以前这里 `let _ =` 吞掉错误，外层照样
    /// 删账本，线程就永久停在接管前的限制之外
    #[test]
    fn affinity_restore_failure_is_reported() {
        let (handle, tid) = spawn_named("AppOpt-test-restore");
        let id = identity_of(tid).expect("读线程身份");
        // 只含不存在的核：内核按空掩码处理，返回 EINVAL
        let mut bogus = CpuSet::new();
        bogus.set(900);
        let mut r = rec(Some("/top-app"), "4-6", &bogus);
        // rec 的第三个参数只设 last_applied，原亲和性要单独换成非法集合
        r.original_affinity = bogus;
        r.identity = id;
        let res = restore(&r, false);
        handle.thread().unpark();
        let _ = handle.join();
        assert!(res.is_err(), "写不进去必须报错，不能当成已恢复");
    }

    /// 进程退出时按 TGID 清账：一个进程里只有主线程的 TID 等于 TGID，
    /// 只比 TID 会漏掉其余所有工作线程
    #[test]
    fn forget_pid_clears_every_thread_of_the_process() {
        let _guard = LEDGER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_ledger(|l| l.clear());
        for (tid, tgid) in [(100, 9_000), (101, 9_000), (102, 7_777)] {
            let mut m = rec(Some("/top-app"), "4-6", &set("4-6"));
            m.identity = TaskIdentity {
                tid,
                tgid,
                start_time: 1,
            };
            with_ledger(|l| {
                l.insert(tid, m);
            });
        }
        forget_pid(9_000);
        let left: Vec<i32> = with_ledger(|l| l.keys().copied().collect());
        with_ledger(|l| l.clear());
        assert_eq!(left, vec![102], "只该剩下别的进程那条");
    }

    /// 线程仍受管、只是 RT 撤销失败过：必须只收 RR，绑核记录不能动。
    /// 整条 Release 会把还在用的绑核一起撤掉，线程反而跑得更开
    #[test]
    fn pending_rt_is_demoted_without_releasing_affinity() {
        let mut task = rec(Some("/top-app"), "4-6", &set("4-6"));
        task.rt = Some(RtTag {
            allowed: set("4-6"),
            pending_demote: true,
        });
        task.state = ManagedState::RecoveryRequired;
        let id = task.identity;
        assert_eq!(
            judge(
                &task,
                Some(id),
                Some("/top-app"),
                Some(set("4-6")),
                true,
                false
            ),
            Verdict::DemoteRt
        );

        // 没打过待撤销标记时，仍受管的线程照旧 Keep
        task.rt = Some(RtTag {
            allowed: set("4-6"),
            pending_demote: false,
        });
        task.state = ManagedState::Managed;
        assert_eq!(
            judge(
                &task,
                Some(id),
                Some("/top-app"),
                Some(set("4-6")),
                true,
                false
            ),
            Verdict::Keep
        );
    }

    /// 30 秒一次的重试只碰待恢复记录：健康记录不参与克隆与判定，
    /// 否则为了几条卡住的记录要对整套账本重读一遍 /proc
    #[test]
    fn retry_recovery_only_touches_pending_records() {
        let _guard = LEDGER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_ledger(|l| l.clear());
        let mut healthy = rec(Some("/top-app"), "4-6", &set("4-6"));
        healthy.identity = TaskIdentity {
            tid: 900_001,
            tgid: 900_000,
            start_time: 1,
        };
        let mut pending = rec(Some("/top-app"), "4-6", &set("4-6"));
        pending.identity = TaskIdentity {
            tid: 900_002,
            tgid: 900_000,
            start_time: 1,
        };
        pending.state = ManagedState::RecoveryRequired;
        with_ledger(|l| {
            l.insert(900_001, healthy);
            l.insert(900_002, pending);
        });

        // 两个 tid 都不存在：真要做判定，两条都会被清掉。
        // 只清一条才说明过滤生效
        let rep = retry_recovery(&AppConfig::empty());
        let left: Vec<i32> = with_ledger(|l| l.keys().copied().collect());
        with_ledger(|l| l.clear());
        assert_eq!(left, vec![900_001], "健康记录不该被重试路径碰到");
        assert_eq!(rep.dropped, 1);
    }

    /// 仍匹配其他规则：不释放，交给正常流程重算目标
    #[test]
    fn still_managed_is_kept() {
        let r = rec(Some("/top-app"), "4-6", &set("4-6"));
        assert_eq!(
            judge(
                &r,
                Some(r.identity),
                Some("/AppOpt/4-6"),
                Some(set("4-6")),
                true,
                false
            ),
            Verdict::Keep
        );
        // 退出时 force 才越过这条
        assert_eq!(
            judge(
                &r,
                Some(r.identity),
                Some("/AppOpt/4-6"),
                Some(set("4-6")),
                true,
                true
            ),
            Verdict::Release(true)
        );
    }

    /// 原组未知：宁可留着限制也不猜一个组写进去
    #[test]
    fn unknown_original_group_is_held() {
        let r = rec(None, "4-6", &set("4-6"));
        assert!(matches!(
            judge(
                &r,
                Some(r.identity),
                Some("/AppOpt/4-6"),
                Some(set("4-6")),
                false,
                false
            ),
            Verdict::Hold(_)
        ));
    }

    /// 正常可释放：身份一致、还在自己组、亲和性未被改、原组已知
    #[test]
    fn clean_case_is_released() {
        let r = rec(Some("/top-app"), "4-6", &set("4-6"));
        assert_eq!(
            judge(
                &r,
                Some(r.identity),
                Some("/AppOpt/4-6"),
                Some(set("4-6")),
                false,
                false
            ),
            Verdict::Release(true)
        );
    }

    /// cpuset 不可用（或熔断期间只写了亲和性）：线程从没进过我们的组，
    /// 释放只恢复亲和性，不能把它从系统组里再搬一次
    #[test]
    fn affinity_only_takeover_is_released_without_moving_group() {
        let r = rec(Some("/top-app"), "4-6", &set("4-6"));
        assert_eq!(
            judge(
                &r,
                Some(r.identity),
                Some("/init.scope"),
                Some(set("4-6")),
                false,
                false
            ),
            Verdict::Release(false)
        );
    }

    /// cgroup 相对路径到挂载点的换算，几种写法都要对
    #[test]
    fn abs_cgroup_maps_relative_paths() {
        assert_eq!(abs_cgroup("/top-app"), "/dev/cpuset/top-app");
        assert_eq!(abs_cgroup("/"), "/dev/cpuset");
        assert_eq!(abs_cgroup("/dev/cpuset/top-app"), "/dev/cpuset/top-app");
    }
}
