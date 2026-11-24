//! 前后台降档（融合方案第十二节）。
//!
//! 只在用户显式打开 `@foreground_demote=on` 时参与决策，默认关闭——
//! 默认配置下的绑核结果必须与 2.6.1 逐核一致。
//!
//! 判据顺序按方案 12.2：Android 调度组优先，组信息被我们接管后丢失时
//! 回退 `oom_score_adj`。未知一律不动：把前台线程误降成小核的代价远大于
//! 少降一个后台线程。

use std::fs;

use crate::cpuset::{CpuSet, CpuTopology, SysGroup};

/// `oom_score_adj` 达到这个值视为后台。Android 的 `lmkd` 对 cached 进程
/// 用 900/950，前台应用通常在 0 以下
const BACKGROUND_OOM: i32 = 900;

/// 读 `oom_score_adj`。读不到返回 `None`，调用方按「不知道」处理，不猜
pub fn oom_score_adj(tid: i32) -> Option<i32> {
    fs::read_to_string(format!("/proc/{tid}/oom_score_adj"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// 线程此刻是不是后台。
///
/// 接管到 `AppOpt/<集合>` 之后系统组名就丢了（组是我们建的），只剩
/// `oom_score_adj` 还能回答「应用是不是被切到后台」。这也正是需要这一层
/// 的原因：`plan_target` 能处理「还在系统组里」的情形，处理不了「已经
/// 被我们接管、随后应用切后台」的情形
pub fn is_background(tid: i32, group: SysGroup) -> bool {
    match group {
        SysGroup::Background => true,
        SysGroup::Own => oom_score_adj(tid).is_some_and(|v| v >= BACKGROUND_OOM),
        // TopApp / Foreground / Other / Unknown 都不降：Other 可能是任何一种
        // 系统组，Unknown 表示没读到，两者猜错的代价都不对称
        _ => false,
    }
}

/// 降档目标（小核集合）。拓扑未分层时三档指向同一个全集，降档没有意义，
/// 返回 `None` 让调用方保持原集合
pub fn floor_of(topo: &CpuTopology) -> Option<CpuSet> {
    if topo.topo_degraded || topo.e_core.count() == 0 {
        return None;
    }
    // 小核集合可能含离线核，但执行层会按组生效集合/亲和性求交，
    // 这里不做额外裁剪：裁剪一次就要多维护一份「在线」快照
    Some(topo.e_core)
}

/// 该不该对这一条线程降档。
///
/// 三条硬条件，缺一不可：
/// - 用户开了开关
/// - 线程没有命中显式线程规则（用户写明的绑定优先于任何自动策略）
/// - 确实判成后台
pub fn should_demote(
    enabled: bool,
    is_thread_rule: bool,
    tid: i32,
    group: SysGroup,
) -> bool {
    enabled && !is_thread_rule && is_background(tid, group)
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

    fn topo(e: &[usize], p: &[usize], h: &[usize], degraded: bool) -> CpuTopology {
        CpuTopology {
            present_cpus: set(&[0, 1, 2, 3, 4, 5, 6, 7]),
            present_str: "0-7".into(),
            mems_str: "0".into(),
            cpuset_enabled: true,
            e_core: set(e),
            p_core: set(p),
            hp_core: set(h),
            all_tiers: vec![],
            topo_source: "capacity",
            topo_degraded: degraded,
        }
    }

    #[test]
    fn floor_is_e_core_when_layered() {
        let t = topo(&[0, 1, 2, 3], &[4, 5], &[6, 7], false);
        assert_eq!(floor_of(&t), Some(set(&[0, 1, 2, 3])));
    }

    /// 未分层时三档都是全集，降档会把全部核再写一遍，纯属浪费
    #[test]
    fn floor_is_none_when_degraded() {
        let t = topo(&[0, 1, 2, 3], &[0, 1, 2, 3], &[0, 1, 2, 3], true);
        assert_eq!(floor_of(&t), None);
    }

    #[test]
    fn background_group_is_demoted() {
        assert!(is_background(1, SysGroup::Background));
    }

    /// Own 组读不到 oom_score_adj 时不降：不知道就不动
    #[test]
    fn unknown_oom_does_not_demote() {
        assert!(!is_background(i32::MAX - 7, SysGroup::Own));
    }

    #[test]
    fn explicit_thread_rule_wins() {
        assert!(!should_demote(true, true, 1, SysGroup::Background));
        assert!(should_demote(true, false, 1, SysGroup::Background));
        assert!(!should_demote(false, false, 1, SysGroup::Background));
    }
}
