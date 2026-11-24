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
    pub pid: i32,
    pub start_time: u64,
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

/// 读 `/proc/<tid>/stat` 拿身份。
///
/// 只取 `pid` 与 `starttime`（第 22 列）。字段切分必须从最后一个 `)` 之后
/// 开始：`comm` 允许出现空格和括号（`(Web Content)`、`(a (b))`），
/// 整体 `split_whitespace` 会把 comm 里的空格算成字段，后面全部错位
pub fn identity_of(tid: i32) -> Option<TaskIdentity> {
    let raw = fs::read_to_string(format!("/proc/{}/stat", tid)).ok()?;
    parse_stat(tid, &raw)
}

fn parse_stat(tid: i32, raw: &str) -> Option<TaskIdentity> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close < open {
        return None;
    }
    let pid: i32 = raw.get(..open)?.trim().parse().ok()?;
    let rest = raw.get(close + 1..)?;
    // `)` 之后第一个字段是 state（第 3 列），starttime 是第 22 列 → nth(19)
    let start_time: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    Some(TaskIdentity {
        tid,
        pid,
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
    let Some(identity) = identity_of(tid) else {
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
        // 没登记过，或 tid 被复用：旧账作废，按新线程重新记
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

/// 线程退出或缓存清理时删记录。这里只删账，不动内核——线程都没了，无组可还
pub fn forget(tid: i32) {
    with_ledger(|l| {
        l.remove(&tid);
    });
}

/// 进程退出：它名下的线程全都不会再回来，按 tgid 一并清掉。
/// 只删 tid 不够：进程退出事件的时机可能早于线程退出事件被消费
pub fn forget_pid(pid: i32) {
    with_ledger(|l| {
        l.retain(|_, m| m.identity.pid != pid);
    });
}

/// 当前接管的线程数。Web 诊断与启动对账用
pub fn managed_count() -> usize {
    with_ledger(|l| l.len())
}

/// 处于 RecoveryRequired 的线程数
fn recovery_required() -> usize {
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
    // starttime 与 tgid 都要对：只比 tid 会把复用的号当成同一线程
    if id.start_time != rec.identity.start_time || id.pid != rec.identity.pid {
        return Verdict::Drop("tid 已被复用");
    }
    if still_managed && !force {
        return Verdict::Keep;
    }
    let Some(path) = cgroup else {
        return Verdict::Drop("读不到 cgroup");
    };
    let in_own = classify_group(path) == SysGroup::Own;
    // `ours` 只用来判断「我们有没有在这条线程上留下痕迹」，不再作为
    // 「别人接管了、我们别动」的理由：本模块是唯一的绑核方，系统改写
    // 亲和性是常态（切后台收敛、热插拔、厂商 HAL）。留下的限制一律撤销
    let ours = affinity.is_none_or(|cur| cur == rec.last_applied_affinity);
    // 组与亲和性都不在我们手里：没留下任何限制，连记录一起清掉
    if !in_own && !ours {
        return Verdict::Drop("组与亲和性都不在我们手里");
    }
    if in_own {
        // 组是我们的，规则一撤就得还。迁组时内核会按原组允许集合重算
        // 亲和性，被系统改写过的掩码也就跟着覆盖掉了
        if rec.original_cpuset.is_none() {
            return Verdict::Hold("接管前的组未知");
        }
        return Verdict::Release(true);
    }
    // 不在我们组里，组从没被我们动过：只把亲和性还原
    if rec.original_affinity.count() == 0 {
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

/// 把线程还回去：先迁组（需要时），再恢复亲和性。
///
/// 顺序不能反：`cgroup.procs` 一写，内核会把线程亲和性重置成新组允许的集合，
/// 先恢复再迁组等于白写
fn restore(rec: &ManagedTask, in_own: bool) -> Result<(), (i32, &'static str)> {
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
    // 掩码同样要还原，这是「删除规则即解除限制」的一部分
    if rec.original_affinity.count() > 0 {
        let _ = rec.original_affinity.set_affinity(rec.identity.tid);
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
        // 配置变更可能只是一条无关规则，不该为此扫一遍所有受管线程的 cgroup
        if still && !force {
            rep.kept += 1;
            continue;
        }
        let cgroup = thread_cgroup(tid);
        let affinity = CpuSet::get_affinity(tid);
        match judge(&rec, Some(now), cgroup.as_deref(), affinity, still, force) {
            Verdict::Keep => rep.kept += 1,
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

fn report(
    rep: &ReleaseReport,
    samples: Vec<String>,
    held: Vec<String>,
    why: &[(&'static str, usize)],
    force: bool,
) {
    if rep.released > 0 {
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
    if rep.failed > 0 {
        crate::diag::tag(
            "警告",
            &format!(
                "{} 个线程无法安全释放（账本共 {} 条），保持现状不猜原组：{}{}",
                rep.failed,
                managed_count(),
                held.join("、"),
                if rep.failed > held.len() { " 等" } else { "" }
            ),
        );
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
    if pending > 0 && rep.failed == 0 {
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
            let Some(id) = identity_of(tid) else {
                continue;
            };
            rep.found += 1;
            let comm = tid_comm(tid).unwrap_or_default();
            // 主线程的 comm 会被内核截到 15 字节，直接和包名比会漏掉长包名；
            // `comm_to_pkg` 带截断键与属主校验，是现成的正确判据
            let pkg = read_cmdline(id.pid)
                .filter(|p| cfg.pkgs.contains(p))
                .or_else(|| comm_to_pkg(id.pid, &comm, cfg));
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

    fn rec(orig: Option<&str>, applied: &str, aff: &CpuSet) -> ManagedTask {
        ManagedTask {
            identity: TaskIdentity {
                tid: 42,
                pid: 42,
                start_time: 9_000,
            },
            comm: "UnityMain".to_string(),
            original_cpuset: orig.map(|s| s.to_string()),
            original_affinity: set("0-7"),
            last_applied_cpuset: applied.to_string(),
            last_applied_affinity: *aff,
            owner_pkg: "com.test.game".to_string(),
            state: ManagedState::Managed,
        }
    }

    /// comm 允许含空格和括号，从最后一个 `)` 之后切字段才不会错位
    #[test]
    fn stat_parses_comm_with_spaces_and_parens() {
        let raw = "1234 (Web Content (x)) S 1 1234 1234 0 -1 4194560 100 0 0 0 10 20 0 0 20 0 1 0 987654 0 0";
        let id = parse_stat(1234, raw).expect("应能解析");
        assert_eq!(id.pid, 1234);
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
        // 只有主线程 tgid == tid；测试线程并行执行时两者不同，不能直接比
        assert!(id.pid > 0);
        assert!(id.start_time > 0);
    }

    /// tid 被复用：只删记录，绝不按旧账去动新线程
    #[test]
    fn reused_tid_is_dropped_not_released() {
        let r = rec(Some("/top-app"), "4-6", &set("4-6"));
        let fresh = TaskIdentity {
            tid: 42,
            pid: 42,
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
