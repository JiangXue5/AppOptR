use std::collections::HashMap;

use crate::apply_affinity::{AffinityOutcome, ApplyReason, affinity_apply};
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology, SysGroup};
use crate::rule_match::{comm_to_pkg, thread_affinity};

pub struct TaskEntry {
    pub pid: i32,
    pub pkg: String,
    /// 规则算出来的集合，原样保留。它可能被系统组裁小（见 `cpus`），
    /// 但恢复接管后要能回到这个值，所以不能只存裁剪后的结果
    pub want: CpuSet,
    /// 本轮实际写入的集合。正常情况下等于 `want`；cpuset 不可用时是
    /// `want ∩ 组生效集合`
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
    /// 线程名。S7 判定角色、RT 匹配模式都要用，不再回读 /proc
    pub comm: String,
    /// 本进程是否成功把该线程写到过目标集合。为 false 时读回不一致是
    /// 「还没绑上」而不是「被外部改写」，不能记成漂移
    pub applied: bool,
    /// 线程所在的系统 cpuset 组。系统改组配置时会重置组内所有线程的亲和性，
    /// 只有接管到自己组里才不受影响
    pub group: SysGroup,
    /// 目标集合与所在组的生效集合没有交集：写 cpuset 与 sched_setaffinity
    /// 都会被内核拒绝，继续尝试只会产生无效迁移
    pub blocked: bool,
}

/// 目标集合与线程所在组的匹配结果
#[derive(PartialEq, Eq, Debug)]
enum GroupFit {
    /// 组不限制，或读不到生效集合（不猜）
    Open,
    /// 交集比目标小：写全集会被内核裁掉，只留下「成功但回读不一致」。
    /// 第二项是该组的生效集合，仅用于一次性说明
    Clamp(CpuSet, String),
    /// 交集为空：迁组与绑核都会被内核拒绝
    Blocked,
}

/// 本轮实际该绑的集合，以及是否该放弃
pub(crate) struct Target {
    pub cpus: CpuSet,
    /// 尊重系统分组且目标不可达：跳过，不计失败
    pub blocked: bool,
    /// 被组集合裁小时的原生效集合，仅用于一次性说明
    pub clipped: Option<String>,
}

/// 把「规则想要的集合」换算成「这台机器上做得到的集合」。
///
/// 三类结论对应三种完全不同的处理：直写、按交集写、直接放弃。
/// 读不到生效集合时一律算 Open——猜错方向的代价是把前台线程误判成不可绑，
/// 比多写一次大得多。
///
/// `migrate` 表示此刻能不能把线程迁进 AppOpt 自己的组：
/// - 能迁：线程会离开系统组，目标组就是我们建的那个集合，不必裁剪；
/// - 不能迁（cpuset 不可用或熔断中）：只有 sched_setaffinity 一条腿，
///   写全集必然被内核求交成 4-5，回读不一致又被判成「写了也白写」，
///   于是白停 300 秒。此时按交集绑，一次到位
fn plan_target(
    want: &CpuSet,
    group: SysGroup,
    eff: Option<&str>,
    respect: bool,
    migrate: bool,
) -> Target {
    match fit_rule(want, group, eff) {
        GroupFit::Open => Target {
            cpus: *want,
            blocked: false,
            clipped: None,
        },
        // 交集为空：respect 下不动它（迁组才算动），takeover 下交给两步迁组硬抬
        GroupFit::Blocked => Target {
            cpus: *want,
            blocked: respect,
            clipped: None,
        },
        GroupFit::Clamp(_, _) if migrate => Target {
            cpus: *want,
            blocked: false,
            clipped: None,
        },
        GroupFit::Clamp(inter, eff) => Target {
            cpus: inter,
            blocked: false,
            clipped: Some(eff),
        },
    }
}

/// 纯判定：给「规则要的集合」和「组的生效集合」，得出直写 / 取交集 / 放弃。
/// 抽出来是为了能脱离 /proc 与 /dev/cpuset 单测——这套判断错一次，
/// 日志里就会多出几百行 EINVAL 或几百次无效重绑
fn fit_rule(want: &CpuSet, group: SysGroup, eff: Option<&str>) -> GroupFit {
    if matches!(group, SysGroup::Own | SysGroup::Unknown) {
        return GroupFit::Open;
    }
    let Some(eff) = eff else {
        return GroupFit::Open;
    };
    let eff_set = crate::cpuset::parse_cpu_ranges(eff, None);
    if eff_set.count() == 0 {
        return GroupFit::Open;
    }
    let mut inter = *want;
    inter.and(&eff_set);
    if inter.count() == 0 {
        GroupFit::Blocked
    } else if inter == *want {
        GroupFit::Open
    } else {
        GroupFit::Clamp(inter, eff.to_string())
    }
}

/// S7 落点能否作为本轮基准：必须是当前规则集合的子集。
///
/// 这是 S7 与定期校验之间的唯一契约。`want` 永远是规则原值，定期校验若直接
/// 按 `want` 重算，S7 刚迁到 4-7 的线程下一个周期就被拉回 0-7，计数与落点
/// 全部对不上。规则改小时旧落点越界，这里返回 `None`，交回规则重算
fn landing_for(rule: &CpuSet, landing: Option<CpuSet>) -> Option<CpuSet> {
    landing.filter(|s| s.subset_of(rule))
}

/// 单条线程本轮的目标：能维持 S7 落点就维持，否则回到规则值。
///
/// 返回的第二个值是该落点是否仍然有效，调用方据此决定要不要删除记录。
/// 「落点有效」的判据有两条：仍在规则集合内，且这次规划没有把它裁小
/// （迁不进自己的组时，被裁小的落点 S7 自己也维持不住，交回规则更稳定）
fn plan_entry(
    rule: &CpuSet,
    landing: Option<CpuSet>,
    group: SysGroup,
    eff: Option<&str>,
    respect: bool,
    migrate: bool,
) -> (Target, Option<CpuSet>) {
    if let Some(s) = landing_for(rule, landing) {
        let t = plan_target(&s, group, eff, respect, migrate);
        if !t.blocked && (t.cpus == s || migrate) {
            return (t, Some(s));
        }
    }
    (plan_target(rule, group, eff, respect, migrate), None)
}

/// 双模式共用进程缓存，eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub tasks: HashMap<i32, TaskEntry>,
    /// S7 接管落点：tid → 上次迁移成功写入的集合。
    ///
    /// 必须单独存放，不能只记在 `TaskEntry` 里：proc 模式每 60 秒全量重建缓存，
    /// eBPF 模式配置变更也会 `clear()`，落点存在条目上会连同条目一起丢掉，
    /// 定期校验随后按规则原值重写，S7 的迁移活不过一个周期。
    /// 规则改小、组不再可达、线程退出时由 `landing_for` 与 `purge_*` 清掉。
    sched: HashMap<i32, CpuSet>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            sched: HashMap::new(),
        }
    }

    /// 只清线程条目，保留 S7 落点：全量重建后定期校验仍要按落点维持，
    /// 否则每 60 秒就会把动态迁移拉回规则值一次
    pub fn clear(&mut self) {
        self.tasks.clear();
    }

    pub fn task_del(&mut self, tid: i32) {
        self.tasks.remove(&tid);
        self.sched.remove(&tid);
    }

    /// S7 迁移成功。落点单独存，重建缓存后仍能维持
    pub fn note_sched(&mut self, tid: i32, cpus: CpuSet) {
        self.sched.insert(tid, cpus);
    }

    /// 关掉 S7 时清空全部落点，让线程按规则重新落地
    pub fn clear_sched(&mut self) {
        self.sched.clear();
    }

    /// 进程退出时清理其全部线程
    pub fn purge_pid(&mut self, pid: i32) {
        self.tasks.retain(|_, e| e.pid != pid);
        self.sched.retain(|tid, _| self.tasks.contains_key(tid));
    }

    /// 包规则变更时清理该包全部线程，返回被清理的 tid 供调用方同步内核表
    pub fn purge_pkg(&mut self, pkg: &str) -> Vec<i32> {
        let stale: Vec<i32> = self
            .tasks
            .iter()
            .filter(|(_, e)| e.pkg == pkg)
            .map(|(&tid, _)| tid)
            .collect();
        for tid in &stale {
            self.tasks.remove(tid);
            // 规则变了，按旧规则迁出来的落点不再有效
            self.sched.remove(tid);
        }
        stale
    }

    /// comm 匹配包名，线程名时回退主线程条目
    pub fn pkg_lookup_comm(&self, pid: i32, comm: &str, cfg: &AppConfig) -> Option<String> {
        comm_to_pkg(pid, comm, cfg).or_else(|| self.tasks.get(&pid).map(|e| e.pkg.clone()))
    }

    /// 计算并应用线程亲和性，保护已有线程规则绑定防止降级
    pub fn task_apply<F>(
        &mut self,
        tid: i32,
        pid: i32,
        pkg: &str,
        comm: &str,
        cfg: &AppConfig,
        apply_fn: F,
    ) -> bool
    where
        F: FnOnce(i32, &CpuSet, &str, bool) -> AffinityOutcome,
    {
        let thread_name = if cfg.has_thread_rules.contains(pkg) {
            comm
        } else {
            ""
        };
        let Some(result) = thread_affinity(pkg, thread_name, cfg) else {
            return false;
        };

        if !result.is_thread_rule && self.tasks.get(&tid).is_some_and(|old| old.is_thread_rule) {
            return true;
        }

        // 组归属只在首次接管时读一次：/proc/<tid>/cgroup 一次 open，
        // 之后跟着缓存走，不会变成每轮开销
        let prev = self.tasks.get(&tid);
        let path = crate::cpuset::thread_cgroup(tid);
        let group = prev.map_or_else(
            || {
                path.as_deref()
                    .map(crate::cpuset::classify_group)
                    .unwrap_or(SysGroup::Unknown)
            },
            |old| old.group,
        );
        let migrate = cfg.topo.cpuset_enabled && !crate::apply_affinity::cpuset_paused();
        let eff = path
            .as_deref()
            .and_then(crate::cpuset::group_effective_cached);
        // 规则变了（同一条目却算出不同集合）就丢掉旧的 S7 落点：
        // 事件重放或重扫可能在 purge 之前撞上同一个 tid
        if prev.is_some_and(|old| old.want != result.cpus) {
            self.sched.remove(&tid);
        }
        let (target, keep) = plan_entry(
            &result.cpus,
            self.sched.get(&tid).copied(),
            group,
            eff.as_deref(),
            cfg.sysgroup_respect,
            migrate,
        );
        if keep.is_none() {
            self.sched.remove(&tid);
        }
        if let Some(eff) = &target.clipped {
            crate::diag::note_group_clip(group, &result.cpus, &target.cpus, eff);
        }
        // 规则没变、且确实写过：这次不是「首次绑定」而是「复核」。
        // 复核必须走校验语义，才能把「被外部改写」记成漂移而不是正常写入
        let recheck = prev.is_some_and(|old| old.applied && old.cpus == target.cpus);
        let prev_applied = prev.is_some_and(|old| old.applied);
        if target.blocked {
            crate::diag::note_sysgroup_skip(tid, comm, group, &result.cpus);
            self.tasks.insert(
                tid,
                TaskEntry {
                    pid,
                    pkg: pkg.to_string(),
                    want: result.cpus,
                    cpus: target.cpus,
                    cpuset_dir: result.cpuset_dir,
                    is_thread_rule: result.is_thread_rule,
                    comm: comm.to_string(),
                    applied: false,
                    group,
                    blocked: true,
                },
            );
            return true;
        }
        let outcome = apply_fn(tid, &target.cpus, &result.cpuset_dir, recheck);
        if outcome == AffinityOutcome::Gone {
            self.tasks.remove(&tid);
            return false;
        }
        // 失败时不能把「之前绑上了」改成「没绑上」，否则下一轮又按首次绑定处理
        let applied = if outcome == AffinityOutcome::Set {
            true
        } else {
            prev_applied
        };

        self.tasks.insert(
            tid,
            TaskEntry {
                pid,
                pkg: pkg.to_string(),
                want: result.cpus,
                cpus: target.cpus,
                cpuset_dir: result.cpuset_dir,
                is_thread_rule: result.is_thread_rule,
                comm: comm.to_string(),
                applied,
                group,
                blocked: false,
            },
        );
        true
    }

    /// 遍历 tasks 应用亲和性，返回 dead_tids 供 eBPF 调用方清理 APPLIED_MAP。
    /// 只有 ESRCH 才算退出，设置失败（EPERM/EINVAL）的线程保留在缓存里等下一轮
    pub fn affinity_sync(&mut self, topo: &CpuTopology, respect: bool) -> Vec<i32> {
        let mut dead_tids: Vec<i32> = Vec::new();
        let mut blocked_now = 0u64;
        let migrate = topo.cpuset_enabled && !crate::apply_affinity::cpuset_paused();
        // 已退出的线程不会再有事件，落点留在这里只会慢慢堆积。
        // 每轮按在线条目裁剪一次，成本是一次哈希遍历
        self.sched.retain(|tid, _| self.tasks.contains_key(tid));
        let sched = &mut self.sched;
        for (tid, e) in self.tasks.iter_mut() {
            // 组归属每轮都重看，不只在「已被拦住」时看。应用切后台时系统会把
            // 线程从 top-app 搬进 background(0-3)，规则却仍要 4-6，交集为空。
            // 只在首次评估的话，线程一旦被判成「可绑」就再也不会重看，
            // 于是切后台后每轮都硬写一次——真机日志里 `+2599s` 之后
            // 每分钟 495 次 EINVAL、`挪簇 495` 就是这么来的。
            // 代价是每 60 秒每个受管线程读一次 /proc/<tid>/cgroup，
            // 相比几百次注定失败的 sched_setaffinity 便宜得多
            //
            // 目标集合也跟着重算：组把目标裁小时按交集绑，组放宽或接管恢复后
            // 再回到规则原值。只算一次的话，线程会在「裁剪值」上永久停住
            let path = crate::cpuset::thread_cgroup(*tid);
            let group = path
                .as_deref()
                .map(crate::cpuset::classify_group)
                .unwrap_or(SysGroup::Unknown);
            let eff = path
                .as_deref()
                .and_then(crate::cpuset::group_effective_cached);
            // S7 接管过的线程按落点维持，不按规则原值重算：`want` 是规则集，
            // 直接拿它算会把刚迁到 4-7 的线程拉回 0-7，迁移白做
            let (target, keep) = plan_entry(
                &e.want,
                sched.get(tid).copied(),
                group,
                eff.as_deref(),
                respect,
                migrate,
            );
            if keep.is_none() && sched.contains_key(tid) {
                // 落点已不可达（切后台、组收紧、规则改小）：接管作废
                sched.remove(tid);
            }
            e.group = group;
            e.cpus = target.cpus;
            e.blocked = target.blocked;
            if e.blocked {
                blocked_now += 1;
                continue;
            }
            // 还没绑上过的线程走首次绑定语义，只有绑定过的才做「被改写」判定
            let reason = if e.applied {
                ApplyReason::Sync
            } else {
                ApplyReason::Rule
            };
            // 只有「读回与期望不一致」才会真写，写入次数就是被外部改写的线程数
            let (outcome, wrote) =
                affinity_apply(*tid, &e.cpus, Some(&e.cpuset_dir), topo, reason, &e.comm);
            if wrote {
                e.applied = true;
            }
            // 线程已退出与设置失败要分开：前者清缓存，后者保留等下一轮
            if outcome == AffinityOutcome::Gone {
                e.applied = false;
                dead_tids.push(*tid);
            }
        }
        for tid in &dead_tids {
            self.task_del(*tid);
        }
        if blocked_now > 0 {
            crate::diag::note_sysgroup_batch(blocked_now);
        }
        dead_tids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_of(spec: &str) -> CpuSet {
        crate::cpuset::parse_cpu_ranges(spec, None)
    }

    /// 后台组 + 目标在大核 + 交集为空，是「写多少遍都 EINVAL」的那一类
    #[test]
    fn background_group_blocks_out_of_range_targets() {
        assert_eq!(
            fit_rule(&set_of("4-6"), SysGroup::Background, Some("0-3")),
            GroupFit::Blocked
        );
        // 目标本来就在该组范围内，没有理由动它
        assert_eq!(
            fit_rule(&set_of("0-2"), SysGroup::Background, Some("0-3")),
            GroupFit::Open
        );
        // 读不到生效集合时不猜，交给内核返回真实 errno
        assert_eq!(
            fit_rule(&set_of("4-6"), SysGroup::Background, None),
            GroupFit::Open
        );
        // 文件为空同样不猜
        assert_eq!(
            fit_rule(&set_of("4-6"), SysGroup::Background, Some("")),
            GroupFit::Open
        );
    }

    /// 前台组只到 0-5 的机型（真机 2.3.8 日志就是这样）：4-6 的交集是 4-5，
    /// 必须按交集绑。硬写 4-6 会「返回成功但回读 4-5」，被判成写了也白写，
    /// 白停 300 秒——真机每 60 秒 182 个线程全撞在这上面
    #[test]
    fn partial_group_limit_clamps_instead_of_writing_doomed_set() {
        assert_eq!(
            fit_rule(&set_of("4-6"), SysGroup::Foreground, Some("0-5")),
            GroupFit::Clamp(set_of("4-5"), "0-5".into())
        );
        // 目标 7 与 0-5 无交集：迁组和绑核都会被拒
        assert_eq!(
            fit_rule(&set_of("7"), SysGroup::Foreground, Some("0-5")),
            GroupFit::Blocked
        );

        // 迁不进自己的组时按交集绑，blocked 为假（这是能绑的部分，不是失败）
        let t = plan_target(
            &set_of("4-6"),
            SysGroup::Foreground,
            Some("0-5"),
            true,
            false,
        );
        assert!(!t.blocked);
        assert_eq!(t.cpus.to_range_string(), "4-5");
        assert_eq!(t.clipped.as_deref(), Some("0-5"));

        // 同一个组，能迁组时直写全集，由迁组把线程抬出系统组
        let t2 = plan_target(
            &set_of("4-6"),
            SysGroup::Foreground,
            Some("0-5"),
            true,
            true,
        );
        assert!(!t2.blocked);
        assert_eq!(t2.cpus.to_range_string(), "4-6");

        // 交集为空 + respect：跳过而不是每秒撞一次 EINVAL
        assert!(plan_target(&set_of("7"), SysGroup::Foreground, Some("0-5"), true, false).blocked);
        // takeover 下不拦，交给两步迁组硬抬
        assert!(
            !plan_target(
                &set_of("7"),
                SysGroup::Foreground,
                Some("0-5"),
                false,
                false
            )
            .blocked
        );
        // 自己建的组不受系统限制
        assert_eq!(
            fit_rule(&set_of("4-6"), SysGroup::Own, Some("0-3")),
            GroupFit::Open
        );
    }

    /// S7 与定期校验的契约：落点必须压过规则原值。
    /// 修复前 `affinity_sync` 用 `e.want` 重算，S7 刚迁到 4-7 的线程
    /// 下一个校验周期就被拉回 0-7，日志里 moved 在涨、落点却对不上
    #[test]
    fn sched_landing_survives_periodic_check() {
        let rule = set_of("0-7");
        let landing = landing_for(&rule, Some(set_of("4-7")));
        assert_eq!(landing, Some(set_of("4-7")));
        let t = plan_target(
            &landing.unwrap_or(rule),
            SysGroup::TopApp,
            Some("0-7"),
            true,
            true,
        );
        assert!(!t.blocked);
        assert_eq!(t.cpus.to_range_string(), "4-7");
    }

    /// 规则被改小后旧落点越界，必须交回规则重算，不能继续维持一个非法集合
    #[test]
    fn stale_landing_is_dropped_when_rule_shrinks() {
        assert_eq!(landing_for(&set_of("0-3"), Some(set_of("4-7"))), None);
        // 规则没变（或变大）时落点仍然有效
        assert_eq!(
            landing_for(&set_of("0-7"), Some(set_of("4-7"))),
            Some(set_of("4-7"))
        );
    }

    /// 落点被系统组挡住（应用切后台，组只剩 0-3）：接管作废，
    /// 本轮就回到规则值并按规则裁剪，而不是每秒撞一次 EINVAL
    #[test]
    fn unreachable_landing_falls_back_to_rule() {
        let rule = set_of("0-7");
        let landing = landing_for(&rule, Some(set_of("4-6"))).unwrap();
        assert!(plan_target(&landing, SysGroup::Background, Some("0-3"), true, false).blocked);
        let t = plan_target(&rule, SysGroup::Background, Some("0-3"), true, false);
        assert!(!t.blocked);
        assert_eq!(t.cpus.to_range_string(), "0-3");
    }

    /// 周期校验的完整决策：落点该留就留，该丢就丢，不能只对一半
    #[test]
    fn plan_entry_keeps_or_releases_landing_consistently() {
        // 规则没变、组能容纳：维持 S7 落点
        let (t, keep) = plan_entry(
            &set_of("0-7"),
            Some(set_of("4-7")),
            SysGroup::TopApp,
            Some("0-7"),
            true,
            true,
        );
        assert_eq!(keep, Some(set_of("4-7")));
        assert_eq!(t.cpus.to_range_string(), "4-7");

        // 规则改小：落点越界，回到规则值
        let (t2, keep2) = plan_entry(
            &set_of("0-3"),
            Some(set_of("4-7")),
            SysGroup::TopApp,
            Some("0-7"),
            true,
            true,
        );
        assert!(keep2.is_none());
        assert_eq!(t2.cpus.to_range_string(), "0-3");

        // 组收紧且迁不进自己的组：落点会被裁小，S7 自己也维持不住，交回规则
        let (t3, keep3) = plan_entry(
            &set_of("0-7"),
            Some(set_of("4-7")),
            SysGroup::Foreground,
            Some("0-5"),
            true,
            false,
        );
        assert!(keep3.is_none());
        assert_eq!(t3.cpus.to_range_string(), "0-5");

        // 能迁组时落点仍成立：迁进 AppOpt/4-7 后不再受系统组限制
        let (t4, keep4) = plan_entry(
            &set_of("0-7"),
            Some(set_of("4-7")),
            SysGroup::Foreground,
            Some("0-5"),
            true,
            true,
        );
        assert_eq!(keep4, Some(set_of("4-7")));
        assert_eq!(t4.cpus.to_range_string(), "4-7");
    }

    /// proc 模式每 60 秒全量重建缓存，eBPF 模式配置变更也会 `clear()`。
    /// 落点若只记在条目里，重建一次就被规则值覆盖，S7 的迁移活不过一个周期
    #[test]
    fn sched_landing_survives_cache_rebuild() {
        let mut cache = ProcCache::new();
        cache.note_sched(4321, set_of("4-7"));
        cache.clear();
        assert_eq!(cache.sched.get(&4321).copied(), Some(set_of("4-7")));
        // 线程退出后不再保留
        cache.task_del(4321);
        assert!(cache.sched.get(&4321).is_none());
    }
}
