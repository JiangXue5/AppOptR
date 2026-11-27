//! 前后台降档（融合方案第十二节）。
//!
//! 只在用户显式打开 `@foreground_demote=on` 时参与决策，默认关闭——
//! 默认配置下的绑核结果必须与 2.6.1 逐核一致。
//!
//! 判据按「应用」而不是「线程」：同进程的所有线程共享一个 stune 组与一个
//! `oom_score_adj`，逐线程各判一次既浪费读取、又会在边界值上得出互相矛盾
//! 的结论（几百个线程里一半降一半不降）。
//!
//! 顺序上先看系统 schedtune 组，再看 `oom_score_adj`。cpuset 组名在接管后
//! 就丢了，stune 组是 AMS 每次切前后台都会同步改写、我们又从不碰的那份。
//! 未知一律不动：把前台线程误降成小核的代价远大于少降一个后台线程。

use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cpuset::{CpuSet, CpuTopology, SysGroup};
use crate::lock_ignore_poison;

/// `oom_score_adj` 达到这个值视为后台。
///
/// 不能取 900（cached）：游戏切到后台后往往先停在 previous app（700），
/// 要等系统真把它回收成 cached 才到 900，中间几分钟都判不出来——「切后台了
/// 还占着大核」就是这么来的。700 与 Android 的 `PREVIOUS_APP_ADJ` 对齐：
/// 应用不在前台就降，回到前台立刻恢复。可见（visible 100）、常驻通知
/// （perceptible 200）、前台服务（200~250）不降，分屏、画中画、后台播放
/// 这类「用户仍在使用」的进程因此不会被误压到小核
const BACKGROUND_OOM: i32 = 700;

/// 进程级判定的缓存时长。同进程所有线程共用一个结论，逐线程各读一次
/// `/proc/<tid>/cgroup` 纯属浪费；1 秒足够让切后台在下一个复核周期前被发现，
/// 又不会让几百个线程变成几百次 open
const APP_CACHE_TTL: Duration = Duration::from_secs(1);
const APP_CACHE_CAP: usize = 64;

static APP_CACHE: Mutex<Option<HashMap<i32, (Instant, bool)>>> = Mutex::new(None);

/// 读 `oom_score_adj`。读不到返回 `None`，调用方按「不知道」处理，不猜
pub fn oom_score_adj(tid: i32) -> Option<i32> {
    fs::read_to_string(format!("/proc/{tid}/oom_score_adj"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// 进程此刻是不是后台。缓存 1 秒，同进程的线程共用一次读取。
///
/// 返回 `None` 表示两个信号都读不到（进程刚退出、或内核没挂 stune）。
/// 调用方一律按「前台」处理：判错方向的代价不对称
pub fn app_background(pid: i32) -> Option<bool> {
    let now = Instant::now();
    {
        let mut guard = lock_ignore_poison(&APP_CACHE);
        let map = guard.get_or_insert_with(HashMap::new);
        if let Some(&(at, bg)) = map.get(&pid)
            && now.saturating_duration_since(at) < APP_CACHE_TTL
        {
            return Some(bg);
        }
    }
    let bg = probe_background(pid)?;
    let mut guard = lock_ignore_poison(&APP_CACHE);
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() >= APP_CACHE_CAP {
        map.retain(|_, (at, _)| now.saturating_duration_since(*at) < APP_CACHE_TTL);
    }
    map.insert(pid, (now, bg));
    Some(bg)
}

/// 真正的判定：stune 组优先，`oom_score_adj` 兜底。
///
/// 只认 stune 的三种明确结论（top-app / foreground / background）。
/// `default`、`system` 这类组名在部分 ROM 上与前后台无关，硬套会判反，
/// 交给下一层
fn probe_background(pid: i32) -> Option<bool> {
    if let Some(g) = crate::cpuset::stune_group(pid) {
        match g {
            SysGroup::Background => return Some(true),
            SysGroup::TopApp | SysGroup::Foreground => return Some(false),
            _ => {}
        }
    }
    oom_score_adj(pid).map(|v| v >= BACKGROUND_OOM)
}

/// 线程此刻是不是后台。
///
/// 系统组已经能直接回答时不再读 `/proc`：`Background` 是系统有意压在小核，
/// `TopApp` / `Foreground` 明确在前台。只有组被我们接管（`Own`）或读不到
/// （`Other` / `Unknown`）时才去问系统侧信号
pub fn is_background(pid: i32, group: SysGroup) -> bool {
    match group {
        SysGroup::Background => true,
        SysGroup::TopApp | SysGroup::Foreground => false,
        _ => app_background(pid).unwrap_or(false),
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
pub fn should_demote(enabled: bool, is_thread_rule: bool, pid: i32, group: SysGroup) -> bool {
    enabled && !is_thread_rule && is_background(pid, group)
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

    /// 前台组不必读 `/proc`：用不存在的 pid 也能立刻回答
    #[test]
    fn foreground_group_never_reads_proc() {
        assert!(!is_background(i32::MAX - 7, SysGroup::TopApp));
        assert!(!is_background(i32::MAX - 7, SysGroup::Foreground));
    }

    /// 接管组与未知组读不到任何信号时按前台处理：不知道就不动
    #[test]
    fn unknown_oom_does_not_demote() {
        assert!(!is_background(i32::MAX - 7, SysGroup::Own));
        assert!(!is_background(i32::MAX - 7, SysGroup::Unknown));
    }

    #[test]
    fn explicit_thread_rule_wins() {
        assert!(!should_demote(true, true, 1, SysGroup::Background));
        assert!(should_demote(true, false, 1, SysGroup::Background));
        assert!(!should_demote(false, false, 1, SysGroup::Background));
    }
}
