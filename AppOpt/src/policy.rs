//! 目标解析：把「规则想要的集合」换算成「这台机器此刻做得到的集合」。
//!
//! 这里只有纯函数——不读 `/proc`、不碰 `/dev/cpuset`、不写内核。整套判断
//! 错一次，日志里就会多出几百行 EINVAL 或几百次无效重绑，所以每一步都要
//! 能脱离真机单测。
//!
//! 管线顺序（融合方案第十节）：
//!
//! ```text
//! 规则匹配 → 用户规则优先级 → S7 落点 → 其他策略建议
//!          → CPU 合法性裁剪 → 最终目标 → apply_affinity
//! ```
//!
//! 「其他策略建议」目前只有前后台降档一项，Render Guard 已在 beta5 下线。

use crate::cpuset::{CpuSet, SysGroup};

/// 建议来源。只用于日志说明「这个集合是谁定的」，不参与计算。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicySource {
    /// 用户写的规则（含 S7 之前的原始值）
    UserRule,
    /// S7 动态落点
    S7,
    /// 前后台降档
    Background,
    /// λmod 层配额
    Lambda,
}

impl PolicySource {
    pub fn label(self) -> &'static str {
        match self {
            PolicySource::UserRule => "规则",
            PolicySource::S7 => "S7 落点",
            PolicySource::Background => "后台降档",
            PolicySource::Lambda => "λmod 层",
        }
    }
}

/// 一步策略给出的建议
#[derive(Clone, Copy, Debug)]
pub struct TargetProposal {
    pub cpus: CpuSet,
    pub source: PolicySource,
    /// 一句话说明「为什么是这个集合」，只在首次绑定时进日志
    pub reason: &'static str,
}

/// 目标集合与线程所在组的匹配结果
#[derive(PartialEq, Eq, Debug)]
pub enum GroupFit {
    /// 组不限制，或读不到生效集合（不猜）
    Open,
    /// 交集比目标小：写全集会被内核裁掉，只留下「成功但回读不一致」。
    /// 第二项是该组的生效集合，仅用于一次性说明
    Clamp(CpuSet, String),
    /// 交集为空：迁组与绑核都会被内核拒绝
    Blocked,
}

/// 本轮实际该绑的集合，以及是否该放弃
#[derive(Clone, Debug)]
pub struct Target {
    pub cpus: CpuSet,
    /// 尊重系统分组且目标不可达：跳过，不计失败
    pub blocked: bool,
    /// 被组集合裁小时的原生效集合，仅用于一次性说明
    pub clipped: Option<String>,
    /// 最终集合由谁定的
    pub source: PolicySource,
    /// 为什么是这个集合（组限制 / 降档 / 落点），用于来源变化时的一行说明
    pub reason: &'static str,
}

impl Target {
    pub fn proposal(&self) -> TargetProposal {
        TargetProposal {
            cpus: self.cpus,
            source: self.source,
            reason: self.reason,
        }
    }
}

/// 纯判定：给「规则要的集合」和「组的生效集合」，得出直写 / 取交集 / 放弃。
///
/// 读不到生效集合时一律算 Open——猜错方向的代价是把前台线程误判成不可绑，
/// 比多写一次大得多。
pub fn fit_rule(want: &CpuSet, group: SysGroup, eff: Option<&str>) -> GroupFit {
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

/// 把「策略想要的集合」换算成「这台机器上做得到的集合」。
///
/// 三类结论对应三种完全不同的处理：直写、按交集写、直接放弃。
///
/// `migrate` 表示此刻能不能把线程迁进 AppOpt 自己的组：
/// - 能迁：线程会离开系统组，目标组就是我们建的那个集合，不必裁剪；
/// - 不能迁（cpuset 不可用或熔断中）：只有 `sched_setaffinity` 一条腿，
///   写全集必然被内核求交成 4-5，回读不一致又被判成「写了也白写」，
///   于是白停 300 秒。此时按交集绑，一次到位
pub fn plan_target(
    want: &CpuSet,
    group: SysGroup,
    eff: Option<&str>,
    respect: bool,
    migrate: bool,
    source: PolicySource,
) -> Target {
    match fit_rule(want, group, eff) {
        GroupFit::Open => Target {
            cpus: *want,
            blocked: false,
            clipped: None,
            source,
            reason: "组不限制",
        },
        // 交集为空：respect 下不动它（迁组才算动），takeover 下交给两步迁组硬抬
        GroupFit::Blocked => Target {
            cpus: *want,
            blocked: respect,
            clipped: None,
            source,
            reason: "与所在组无交集",
        },
        GroupFit::Clamp(_, _) if migrate => Target {
            cpus: *want,
            blocked: false,
            clipped: None,
            source,
            reason: "迁入自有组，不受系统组限制",
        },
        GroupFit::Clamp(inter, eff) => Target {
            cpus: inter,
            blocked: false,
            clipped: Some(eff),
            source,
            reason: "按所在组生效集合裁剪",
        },
    }
}

/// S7 落点能否作为本轮基准：必须是当前规则集合的子集。
///
/// 这是 S7 与定期校验之间的唯一契约。`want` 永远是规则原值，定期校验若直接
/// 按 `want` 重算，S7 刚迁到 4-7 的线程下一个周期就被拉回 0-7，计数与落点
/// 全部对不上。规则改小时旧落点越界，这里返回 `None`，交回规则重算
pub fn landing_for(rule: &CpuSet, landing: Option<CpuSet>) -> Option<CpuSet> {
    landing.filter(|s| s.subset_of(rule))
}

/// 前后台降档：把「规则集合」压到指定的小核集合。
///
/// 只在交集非空时降——规则本来就只写了大核、而小核集合完全不相交时，
/// 降档会得到空集合，写进去就是 EINVAL。这种情况保持原样，宁可多占几个核
pub fn demote(base: &CpuSet, floor: &CpuSet) -> Option<CpuSet> {
    if floor.count() == 0 {
        return None;
    }
    let mut inter = *base;
    inter.and(floor);
    if inter.count() == 0 || inter == *base {
        None
    } else {
        Some(inter)
    }
}

/// 单条线程本轮的目标：能维持 S7 落点就维持，否则回到规则值，
/// 最后按需降档。
///
/// 优先级（融合方案第十节，M2 收口后定案）：**降档 > S7 落点 > 规则值**。
/// 降档代表用户对前后台的显式约束，S7 只是按负载挑簇的优化；让 S7 赢会
/// 出现「降档到小核 → 下一轮 S7 觉得大核更空又迁回去 → 再降回来」的
/// 双周期抖动，日志上还会同时出现「S7 落点」和「后台降档」两个来源。
/// 反过来让降档赢，S7 对这类线程直接不参与（见 `sched::decide`），
/// 两个策略不会互相踩。
///
/// 返回的第二个值是该 S7 落点是否仍然有效，调用方据此决定要不要删除记录。
/// 「落点有效」的判据有两条：仍在规则集合内，且这次规划没有把它裁小
/// （迁不进自己的组时，被裁小的落点 S7 自己也维持不住，交回规则更稳定）
/// 一条线程进入规划所需的全部输入。
///
/// 之所以用结构体：`plan_entry` 原来七个位置参数已经很难读，再塞 λmod 的
/// 提示、RT 标记与冷却状态就是十一个——调用点写成一行谁也不知道第几位是什么
pub struct Entry<'a> {
    pub rule: &'a CpuSet,
    pub landing: Option<CpuSet>,
    pub group: SysGroup,
    pub eff: Option<&'a str>,
    pub respect: bool,
    pub migrate: bool,
    pub floor: Option<&'a CpuSet>,
    /// λmod 对这条线程的建议（可能为空）
    pub hint: Option<crate::arbiter::Hint>,
    /// λmod 执行闸门
    pub lambda_apply: bool,
    /// 已被 RT 提升：任何自动迁移都不碰
    pub rt: bool,
    /// 角色是否允许自动迁移
    pub movable: bool,
    /// 该线程是否已过 λmod 冷却
    pub cooling_ok: bool,
    /// 线程当前实际绑着的集合
    pub current: Option<CpuSet>,
    /// 当前目标是否由 λmod 定的
    pub owned_lambda: bool,
}

/// 规划：先由裁决层决定「听谁的」，再把选中的集合换算成机器做得到的集合。
///
/// 两层分开的原因：裁决是纯策略（谁优先），`plan_target` 是纯能力（组限制、
/// 迁移与否）。混在一起时，一个「S7 落点被组裁小」的失败会被误读成「S7 输了」。
pub fn plan(e: &Entry<'_>) -> (Target, Option<CpuSet>) {
    let demoted = e.floor.and_then(|f| demote(e.rule, f));
    let s7 = if demoted.is_none() {
        landing_for(e.rule, e.landing)
    } else {
        None
    };
    let ctx = crate::arbiter::Context {
        rule: e.rule,
        demoted: demoted.as_ref(),
        s7: s7.as_ref(),
        hint: e.hint.as_ref(),
        rt: e.rt,
        movable: e.movable,
        apply: e.lambda_apply,
        cooling_ok: e.cooling_ok,
        err_ok: crate::arbiter::CONVERGED_ERR,
    };
    let verdict = crate::arbiter::arbitrate(&ctx);
    let source = match verdict.owner {
        crate::arbiter::Owner::Demote => PolicySource::Background,
        crate::arbiter::Owner::S7 => PolicySource::S7,
        crate::arbiter::Owner::Lambda => PolicySource::Lambda,
        crate::arbiter::Owner::Rule => PolicySource::UserRule,
    };
    let mut t = plan_target(&verdict.cpus, e.group, e.eff, e.respect, e.migrate, source);
    match verdict.owner {
        // 降档即使被组拦住也照原样返回：调用方据此整条跳过，
        // 不能偷偷回落到规则值——那等于把用户的前后台约束丢了
        crate::arbiter::Owner::Demote => (t, None),
        crate::arbiter::Owner::S7 => {
            // 落点必须写得住：被组裁小又迁不进自有组时，S7 自己也维持不住，
            // 交回规则值更稳定（与 2.7.0 之前的行为一致）
            if !t.blocked && (t.cpus == verdict.cpus || e.migrate) {
                return (t, Some(verdict.cpus));
            }
            rule_target(e, demoted.as_ref())
        }
        crate::arbiter::Owner::Lambda => {
            if !t.blocked && (t.cpus == verdict.cpus || e.migrate) {
                return (t, None);
            }
            rule_target(e, demoted.as_ref())
        }
        crate::arbiter::Owner::Rule => {
            // 冷却不是「回退」：这条线程本来就落在 λmod 给的层上，冷却期内
            // 保持不动。否则冷却一到就按规则值拉回去，60 秒后再抬上来——
            // 一次防抖变成一次周期性抖动
            if matches!(verdict.veto, Some(crate::arbiter::Veto::Cooling))
                && e.owned_lambda
                && let Some(cur) = e.current.filter(|c| c.count() > 0 && c.subset_of(e.rule))
            {
                let mut t = plan_target(
                    &cur,
                    e.group,
                    e.eff,
                    e.respect,
                    e.migrate,
                    PolicySource::Lambda,
                );
                t.reason = "λmod 层（冷却保持）";
                return (t, None);
            }
            // 回落到规则值时把「为什么没听 λmod」写进 reason：日志里
            // 「规则 0-7」看不出是没建议还是被否决，这句能省一轮排查
            // 「本包未开」不是一次裁决结论（默认态），不该覆盖规则原因
            if matches!(verdict.veto, Some(v) if v != crate::arbiter::Veto::Disabled) {
                t.reason = verdict.why;
            }
            (t, None)
        }
    }
}

fn rule_target(e: &Entry<'_>, demoted: Option<&CpuSet>) -> (Target, Option<CpuSet>) {
    let (base, source) = match demoted {
        Some(small) => (*small, PolicySource::Background),
        None => (*e.rule, PolicySource::UserRule),
    };
    (
        plan_target(&base, e.group, e.eff, e.respect, e.migrate, source),
        None,
    )
}

/// 兼容旧调用点与既有单测：无 λmod、无 RT、无冷却约束时等价于规则 → 落点
#[cfg(test)]
pub fn plan_entry(
    rule: &CpuSet,
    landing: Option<CpuSet>,
    group: SysGroup,
    eff: Option<&str>,
    respect: bool,
    migrate: bool,
    floor: Option<&CpuSet>,
) -> (Target, Option<CpuSet>) {
    plan(&Entry {
        rule,
        landing,
        group,
        eff,
        respect,
        migrate,
        floor,
        hint: None,
        lambda_apply: false,
        rt: false,
        movable: true,
        cooling_ok: true,
        current: None,
        owned_lambda: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(cpus: &[usize]) -> CpuSet {
        let mut s = CpuSet::new();
        for &c in cpus {
            s.set(c);
        }
        s
    }

    fn range(spec: &str) -> CpuSet {
        crate::cpuset::parse_cpu_ranges(spec, None)
    }

    /// 原 cache.rs 的四个用例原样搬过来：抽取前后结论必须逐条一致
    #[test]
    fn sched_landing_survives_periodic_check() {
        let rule = range("0-7");
        let landing = landing_for(&rule, Some(set(&[4, 5, 6, 7])));
        assert_eq!(landing, Some(set(&[4, 5, 6, 7])));
        let (t, keep) = plan_entry(&rule, landing, SysGroup::Own, None, true, true, None);
        assert_eq!(t.cpus, set(&[4, 5, 6, 7]));
        assert_eq!(keep, Some(set(&[4, 5, 6, 7])));
    }

    #[test]
    fn stale_landing_is_dropped_when_rule_shrinks() {
        assert_eq!(
            landing_for(&set(&[0, 1, 2, 3]), Some(set(&[4, 5, 6, 7]))),
            None
        );
        let (t, keep) = plan_entry(
            &set(&[0, 1, 2, 3]),
            Some(set(&[4, 5, 6, 7])),
            SysGroup::Own,
            None,
            true,
            true,
            None,
        );
        assert_eq!(t.cpus, set(&[0, 1, 2, 3]));
        assert_eq!(keep, None);
    }

    #[test]
    fn unreachable_landing_falls_back_to_rule() {
        let rule = range("0-7");
        let landing = landing_for(&rule, Some(range("4-6"))).unwrap();
        // 落点 4-6 与后台组 0-3 无交集：作废，按规则 0-7 与组求交得 0-3
        let (t, keep) = plan_entry(
            &rule,
            Some(landing),
            SysGroup::Background,
            Some("0-3"),
            true,
            false,
            None,
        );
        assert!(!t.blocked);
        assert_eq!(t.cpus, range("0-3"));
        assert_eq!(keep, None);
    }

    /// 降档只在交集非空、且确实变小的时候生效
    #[test]
    fn demote_only_when_intersection_shrinks() {
        assert_eq!(demote(&range("0-7"), &range("0-3")), Some(range("0-3")));
        // 规则已经全在小核：不必改
        assert_eq!(demote(&range("0-3"), &range("0-7")), None);
        // 完全不相交：降档会得到空集合，保持原样
        assert_eq!(demote(&range("4-7"), &range("0-3")), None);
        // 空 floor（拓扑未分层）不降
        assert_eq!(demote(&range("0-7"), &CpuSet::new()), None);
    }

    #[test]
    fn background_source_is_reported() {
        let rule = range("0-7");
        let (t, keep) = plan_entry(
            &rule,
            None,
            SysGroup::Own,
            None,
            true,
            true,
            Some(&range("0-3")),
        );
        assert_eq!(t.cpus, range("0-3"));
        assert!(matches!(t.source, PolicySource::Background));
        assert_eq!(keep, None);
    }

    /// 降档优先于 S7 落点：否则 S7 会把刚降档的线程迁回大核，两轮一抖。
    /// 落点同时作废（`keep` 为 None），让 S7 状态跟着清掉
    #[test]
    fn demote_wins_over_s7_landing() {
        let rule = range("0-7");
        let (t, keep) = plan_entry(
            &rule,
            Some(range("4-7")),
            SysGroup::Own,
            None,
            true,
            true,
            Some(&range("0-3")),
        );
        assert_eq!(t.cpus, range("0-3"));
        assert!(matches!(t.source, PolicySource::Background));
        assert_eq!(keep, None, "降档生效时不能把落点判成有效");
    }

    /// 降档不成立（规则与 floor 无交集 / 本来就只在小核）时 S7 照常维持，
    /// 这是「优先」而不是「互斥」：没降档就不该影响 S7
    #[test]
    fn s7_landing_survives_when_demote_is_noop() {
        let rule = range("4-7");
        let (t, keep) = plan_entry(
            &rule,
            Some(range("4-5")),
            SysGroup::Own,
            None,
            true,
            true,
            Some(&range("0-3")),
        );
        assert_eq!(t.cpus, range("4-5"));
        assert!(matches!(t.source, PolicySource::S7));
        assert_eq!(keep, Some(range("4-5")));
    }

    fn lambda_hint(cpus: CpuSet, err: f64) -> crate::arbiter::Hint {
        crate::arbiter::Hint { cpus, err }
    }

    fn entry_lambda<'a>(rule: &'a CpuSet, hint: crate::arbiter::Hint, apply: bool) -> Entry<'a> {
        Entry {
            rule,
            landing: None,
            group: SysGroup::Own,
            eff: None,
            respect: true,
            migrate: true,
            floor: None,
            hint: Some(hint),
            lambda_apply: apply,
            rt: false,
            movable: true,
            cooling_ok: true,
            current: None,
            owned_lambda: false,
        }
    }

    /// 闸门打开、提示层落在规则内：采纳 λmod 的层
    #[test]
    fn lambda_tier_is_used_when_gate_open() {
        let rule = range("0-7");
        let e = entry_lambda(&rule, lambda_hint(range("4-7"), 0.02), true);
        let (t, keep) = plan(&e);
        assert_eq!(t.cpus, range("4-7"));
        assert!(matches!(t.source, PolicySource::Lambda));
        assert_eq!(keep, None);
    }

    /// 闸门关（默认）：照跑裁决但退回规则值，不能偷偷改绑核
    #[test]
    fn lambda_tier_is_ignored_when_gate_closed() {
        let rule = range("0-7");
        let e = entry_lambda(&rule, lambda_hint(range("4-7"), 0.02), false);
        let (t, _) = plan(&e);
        assert_eq!(t.cpus, rule);
        assert!(matches!(t.source, PolicySource::UserRule));
    }

    /// 冷却期内保持 λmod 落点，不回退规则值：否则 60 秒一次来回抖
    #[test]
    fn lambda_landing_is_kept_during_cooldown() {
        let rule = range("0-7");
        let mut e = entry_lambda(&rule, lambda_hint(range("0-3"), 0.02), true);
        e.cooling_ok = false;
        e.owned_lambda = true;
        e.current = Some(range("4-7"));
        let (t, keep) = plan(&e);
        assert_eq!(t.cpus, range("4-7"));
        assert!(matches!(t.source, PolicySource::Lambda));
        assert_eq!(t.reason, "λmod 层（冷却保持）");
        assert_eq!(keep, None);
    }

    /// RT 线程即使闸门开着也不采纳：迁走就是一次丢缓存
    #[test]
    fn rt_thread_ignores_lambda() {
        let rule = range("0-7");
        let mut e = entry_lambda(&rule, lambda_hint(range("4-7"), 0.02), true);
        e.rt = true;
        let (t, _) = plan(&e);
        assert_eq!(t.cpus, rule);
        assert!(matches!(t.source, PolicySource::UserRule));
    }

    /// 提示层越出规则集合：整层不能写，否则越过用户规则
    #[test]
    fn lambda_tier_outside_rule_falls_back() {
        let rule = range("0-3");
        let e = entry_lambda(&rule, lambda_hint(range("4-7"), 0.02), true);
        let (t, _) = plan(&e);
        assert_eq!(t.cpus, rule);
    }

    /// 迁组路径不受组生效集合裁剪：迁进自己的组后组就是我们建的那一个
    #[test]
    fn migrate_skips_group_clamp() {
        // 4-7 与 0-3 无交集属于 Blocked，不是 Clamp；能迁组时 Clamp 直写全集
        let t = plan_target(
            &range("0-7"),
            SysGroup::Background,
            Some("0-3"),
            true,
            true,
            PolicySource::UserRule,
        );
        assert_eq!(t.cpus, range("0-7"));
        assert!(!t.blocked);
        assert!(t.clipped.is_none());
    }

    /// 不能迁组时按交集写，避免「写全集—回读不一致—停 300 秒」
    #[test]
    fn no_migrate_clamps_to_group() {
        let t = plan_target(
            &range("0-7"),
            SysGroup::Background,
            Some("0-3"),
            true,
            false,
            PolicySource::UserRule,
        );
        assert_eq!(t.cpus, range("0-3"));
        assert_eq!(t.clipped.as_deref(), Some("0-3"));
    }

    /// 前台组只到 0-5 的机型（真机 2.3.8 日志就是这样）：4-6 的交集是 4-5，
    /// 必须按交集绑。硬写 4-6 会「返回成功但回读 4-5」，被判成写了也白写，
    /// 白停 300 秒——真机每 60 秒 182 个线程全撞在这上面
    #[test]
    fn partial_group_limit_clamps_instead_of_writing_doomed_set() {
        assert_eq!(
            fit_rule(&range("4-6"), SysGroup::Foreground, Some("0-5")),
            GroupFit::Clamp(range("4-5"), "0-5".into())
        );
        // 目标 7 与 0-5 无交集：迁组和绑核都会被拒
        assert_eq!(
            fit_rule(&range("7"), SysGroup::Foreground, Some("0-5")),
            GroupFit::Blocked
        );
        // 交集为空 + respect：跳过而不是每秒撞一次 EINVAL
        assert!(
            plan_target(
                &range("7"),
                SysGroup::Foreground,
                Some("0-5"),
                true,
                false,
                PolicySource::UserRule
            )
            .blocked
        );
        // takeover 下不拦，交给两步迁组硬抬
        assert!(
            !plan_target(
                &range("7"),
                SysGroup::Foreground,
                Some("0-5"),
                false,
                false,
                PolicySource::UserRule
            )
            .blocked
        );
        // 自己建的组不受系统限制
        assert_eq!(
            fit_rule(&range("4-6"), SysGroup::Own, Some("0-3")),
            GroupFit::Open
        );
    }
}
