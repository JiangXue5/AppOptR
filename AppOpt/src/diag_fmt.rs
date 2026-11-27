//! 诊断日志的纯函数层：只做「判定」与「拼一行字」，不读 `/proc`、不碰全局状态。
//!
//! 拆出来的原因写在 2.6.0 的 CHANGELOG 里：2.3.8~2.5.8 有六次提交都在修
//! 「同一件事被日志说成两个结论」（裁剪 vs 组上限、此刻 vs 近 60 秒、
//! 受管 vs 符合）。根因不是措辞，而是「读现场 → 分类 → 计数 → 排版」揉在
//! 一个函数里，改一处要通读全段，也几乎没法单测。这里只保留能脱离本机
//! 拓扑与文件系统验证的部分：
//!
//! * `classify_clip`：差集为什么少了核（判定）
//! * `tally_line` / `combo_list` / `sample_tag` / `delta_desc`：输出格式化
//!
//! 采集（读 cgroup、读 online、counters 累加）留在 `diag.rs`。

use std::collections::HashMap;

use crate::cpuset::{CpuSet, SysGroup};

/// 改写明细里每种「期望→实际」最多列几行，其余合并成「另 N 种」
const COMBO_SHOW: usize = 3;

/// 一轮校验结束时的状态分布。`ok + rebound + failed + blocked` 加上本轮
/// 退出的线程就是受管总数；四个数相加对不上总数，说明有线程在中途消失
#[derive(Clone, Copy, Default)]
pub(crate) struct SyncTally {
    pub total: usize,
    pub ok: usize,
    pub rebound: usize,
    pub failed: usize,
    pub blocked: usize,
}

/// 一次「读回与期望不一致」的现场。期望/实际的组合能直接区分根因：
/// 实际是期望的子集＝被 cpuset 裁剪；实际是超集＝被整体重置；互不包含＝被挪簇
#[derive(Clone)]
pub(crate) struct Drift {
    pub tid: i32,
    pub comm: String,
    /// 线程所属包。日志里只印线程名时，`HWC release`、`dns-work-0` 这种
    /// 名字看不出是谁的线程，用户没法判断是不是模块管到了规则外的进程
    pub pkg: String,
    pub expect: String,
    pub actual: String,
    pub cpuset: String,
    /// 该 tid 就是进程主线程。主线程的 comm 被内核截到 15 字节，
    /// 日志里显示成包名残段，不标注会让读者以为出现了另一个进程
    pub is_main: bool,
}

/// 裁剪的差集归因。抽成纯函数是为了能脱离本机 CPU 拓扑单测：
/// 「少了一个核」到底是核下电还是组集合限制，决定了用户该等还是该改配置
#[derive(Debug, PartialEq)]
pub(crate) enum ClipWhy {
    /// 差集里至少有一个核当前不在线；内核会把掩码与在线集合求交
    Offline(CpuSet),
    /// 核都在线，差集只能来自线程所在 cpuset 组的可用集合
    GroupLimited,
}

/// 判定「少的核」是下电还是组限制。
///
/// `off_probe` 由调用方提供（生产是 `cpuset::cpu_is_online`，测试是闭包）：
/// 汇总位图和逐核 online 文件可能不同步，MTK/高通的 core_ctl 先改单核
/// 再刷新汇总，反过来也有。只信汇总就会在「实际 4-5」旁边写一句
/// 「4-6 都在线」，两边自相矛盾
pub(crate) fn classify_clip(
    want: &CpuSet,
    online: &CpuSet,
    off_probe: impl Fn(usize) -> bool,
) -> ClipWhy {
    let mut lost = *want;
    lost.and_not(online);
    if lost.count() > 0 {
        return ClipWhy::Offline(lost);
    }
    let mut dead = CpuSet::new();
    for cpu in 0..64 {
        if want.is_set(cpu) && !off_probe(cpu) {
            dead.set(cpu);
        }
    }
    if dead.count() > 0 {
        ClipWhy::Offline(dead)
    } else {
        ClipWhy::GroupLimited
    }
}

/// 读回比规则多出来的核，写成 `（多 7）` / `（多 0-5）`。
/// 只给两个集合让用户自己比，等于把判断成本推回去；差集才是「多了什么」
pub(crate) fn delta_desc(expect: &str, actual: &str) -> String {
    let mut extra = crate::cpuset::parse_cpu_ranges(actual, None);
    extra.and_not(&crate::cpuset::parse_cpu_ranges(expect, None));
    if extra.count() == 0 {
        String::new()
    } else {
        format!("（多 {}）", extra.to_range_string())
    }
}

/// 样例前缀：线程名 + tid + 所属包。带包名是为了让读者能自己判断
/// 「这条线程到底是不是我规则里的包」——`HWC release`、`dns-work-0`
/// 这类名字靠猜没用。包名为空说明没登记上，不是「不属于任何包」
pub(crate) fn sample_tag(d: &Drift) -> String {
    // 主线程的 comm 只是包名残段，后面已经跟着完整包名，再念一遍是噪音：
    // `主线程 ent.tmgp.osgame(13732)[com.tencent.tmgp.osgame]` 里那个残段
    // 只会让人去找「谁叫 ent.tmgp.osgame」。没有包名时才退回 comm
    let name = if d.is_main && !d.pkg.is_empty() {
        "主线程".to_string()
    } else if d.is_main {
        format!("主线程 {}", d.comm)
    } else {
        d.comm.clone()
    };
    if d.pkg.is_empty() {
        format!("{}({})", name, d.tid)
    } else {
        format!("{}({})[{}]", name, d.tid, d.pkg)
    }
}

/// 本周期「期望→实际」组合，按次数排序后给前三种。
/// `resets` 为真取超集（被外部改大），否则取子集（被裁小）。
///
/// 计数在采集层逐次累加，不依赖样例数组：真机上 7 次改写只留了 4 条样例，
/// 明细写成「7（4-6→4-7 ×4）」，另外 3 次凭空消失，读者最先怀疑统计本身。
/// 种类多于三种时把剩下的合并成「另 N 种 ×M」，保证列出的次数之和 = 总数
pub(crate) fn combo_list(combo: &HashMap<(bool, String), u32>, resets: bool) -> String {
    let mut v: Vec<(&String, u32)> = combo
        .iter()
        .filter(|((is_reset, _), _)| *is_reset == resets)
        .map(|((_, k), n)| (k, *n))
        .collect();
    if v.is_empty() {
        return "样例已略".to_string();
    }
    // 次数多的在前；同次数按组合字典序，输出稳定，便于逐次对比日志
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let head: Vec<String> = v
        .iter()
        .take(COMBO_SHOW)
        .map(|(k, n)| format!("{} ×{}", k, n))
        .collect();
    if v.len() <= COMBO_SHOW {
        return head.join("、");
    }
    let rest: u32 = v.iter().skip(COMBO_SHOW).map(|(_, n)| *n).sum();
    format!(
        "{}，另 {} 种 ×{}",
        head.join("、"),
        v.len() - COMBO_SHOW,
        rest
    )
}

/// 「此刻」与「近 60 秒」必须在一行里说清：只报后者，读者会把它当成当前状态。
/// 这条被误读过两次（「日志说没绑上，Scene 里却是对的」），所以抽成纯函数可回归
pub(crate) fn tally_line(
    t: SyncTally,
    ledger: Option<usize>,
    rewrites: u64,
    blocked_note: Option<&(SysGroup, String)>,
) -> String {
    // 主数字必须是「一致」，不能只给「符合」。真机上出现过
    // `受管 1 个线程 —— 符合 0、本轮重绑 1`，用户盯着那个 0 问「是不是没绑上」，
    // 而实际状态是重绑后已经一致。ok 与 rebound 只是「这次有没有动手」的区别
    let mut consistent = format!("一致 {}", t.ok + t.rebound);
    if t.rebound > 0 {
        // 重绑是「一致」的一部分（写了并被内核接受），并列写会被读成
        // 「1 个一致 + 1 个重绑 = 2 个线程」
        consistent.push_str(&format!("（其中重绑 {}）", t.rebound));
    }
    // 账本条数紧跟在受管数后面：两个数应当接近，差出来的部分就是
    // 「绑上了但没记账」——退出时不会还原的正是这些线程
    let head = match ledger {
        Some(n) => format!("受管 {}（账本 {}）", t.total, n),
        None => format!("受管 {}", t.total),
    };
    let mut parts = vec![head, consistent];
    if t.failed > 0 {
        parts.push(format!("失败 {}", t.failed));
    }
    if t.blocked > 0 {
        // 这一档是真的没绑，不能和「一致」混在一行里说得含糊。
        // 用户拿 Scene 对照时，缺的正是「哪些确实没绑」这句话
        // 再补一句它们在哪个组：180 个全在后台组是「切后台了」，
        // 散在多个组才是「规则要的核拼不出来」，两者处理方式相反
        let where_ = match blocked_note {
            Some((g, eff)) => format!("，{}可用 {}", g.label(), eff),
            None => String::new(),
        };
        parts.push(format!("被组限制 {}（确实没绑{}）", t.blocked, where_));
    }
    if rewrites > 0 {
        parts.push(format!("本周期改写 {}", rewrites));
    }
    parts.join(" ｜ ")
}

/// 只报「这段时间被改了几次」而不给「此刻」，是这套日志被误读的最老一处。
/// 拿不到当前状态时必须自己说出来，不能默认沉默——沉默会被读成「还是那样」
pub(crate) fn empty_state_hint(tally: Option<SyncTally>, ever_bound: bool) -> &'static str {
    match tally {
        None => "此刻还没有完成首轮校验",
        // 「还没启动」和「已经退出」是两件事：前者是正常状态（开机就装、
        // 游戏还没开），后者才需要看一眼。真机首条摘要在 +60s 说
        // 「目标进程已退出或未被扫描到」，可游戏 6 秒后才起来——把
        // 正常状态说成异常，用户第一反应是去查模块
        Some(t) if t.total == 0 && !ever_bound => {
            "自启动以来还没命中规则内的线程（游戏未启动时属正常），命中后立即接管"
        }
        Some(t) if t.total == 0 => "此刻没有受管线程（进程已退出或被系统回收），下次命中会重新接管",
        _ => "此刻没有受管线程",
    }
}

/// 一个受管线程在本周期内被外部改写的汇总。
///
/// 名字要记最新的：Android 上驱动与池化线程会改自己的 comm
/// （真机上 tid 14636 先叫 `HWC release`、后叫 `GPU completion`）。
/// 只留首次的名字，「共 3 次」就和逐条「改写」行对不上——读者 grep
/// 到的那个名字只出现过一次，最先怀疑的是统计本身
#[derive(Clone, Default)]
pub(crate) struct RewriteHit {
    /// 最近一次看到的线程名
    pub comm: String,
    /// 首次看到的线程名，与 comm 不同说明本周期内改过名
    pub first_comm: String,
    pub n: u32,
    /// 最近一次被改成的集合
    pub actual: String,
}

/// 同一线程一个周期内被反复改写时的汇总行。
///
/// 单条「改写」只说明被动过，聚合后才看得出「一直在被抢」：前者是偶发，
/// 后者是 HAL/boost 在周期覆盖，调规则解决不了。`pkg_of` 由调用方提供，
/// 免去把 `thread_pkg` 表也传进来
pub(crate) fn contra_line(
    hits: &HashMap<i32, RewriteHit>,
    threshold: u32,
    cap: usize,
    info_of: impl Fn(i32) -> Option<(String, bool)>,
) -> Option<String> {
    let mut v: Vec<(i32, &RewriteHit)> = hits
        .iter()
        .filter(|(_, h)| h.n >= threshold)
        .map(|(tid, h)| (*tid, h))
        .collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| b.1.n.cmp(&a.1.n).then(a.0.cmp(&b.0)));
    let total: u32 = v.iter().map(|c| c.1.n).sum();
    let n_threads = v.len();
    v.truncate(cap);
    let list: Vec<String> = v
        .iter()
        .map(|(tid, h)| {
            // 与 `sample_tag` 同口径：主线程不再念被截断的 comm，
            // 否则同一行里前面写「主线程(14572)」、这里写「ent.tmgp.osgame(14572)」，
            // 读者会以为是两个线程
            let who = match info_of(*tid) {
                Some((p, true)) if !p.is_empty() => format!("主线程({})[{}]", tid, p),
                Some((p, false)) if !p.is_empty() => format!("{}({})[{}]", h.comm, tid, p),
                _ => format!("{}({})", h.comm, tid),
            };
            // 改过名就把旧名带上：否则「3 次」与日志里唯一那行
            // 「HWC release 1 次」永远对不上
            let mut tail = String::new();
            if !h.first_comm.is_empty() && h.first_comm != h.comm {
                tail.push_str(&format!("本周期内由 {} 改名；", h.first_comm));
            }
            tail.push_str(&format!("最近被改成 {}", h.actual));
            format!("{} {} 次（{}）", who, h.n, tail)
        })
        .collect();
    Some(format!(
        "对抗 {} 个线程本周期被反复改写，共 {} 次：{} ｜ 每轮已按规则写回，不是绑定失败；\
         同一线程反复中招通常是有 HAL 或游戏 boost 在周期覆盖，调规则解决不了，要看是谁在写",
        n_threads,
        total,
        list.join("、")
    ))
}

pub(crate) fn errno_hint(errno: i32) -> String {
    match errno {
        libc::EPERM | libc::EACCES => {
            "权限被拒绝：SELinux、cgroup 限制或缺少 CAP_SYS_NICE".to_string()
        }
        libc::EINVAL => "目标集合非法，或与 cgroup cpuset 没有交集".to_string(),
        libc::ESRCH => "线程已退出".to_string(),
        libc::ENOSYS => "内核未实现该系统调用".to_string(),
        e => format!("errno {}", e),
    }
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

    /// 差集里的核全在线 → 只能是组限制；有一个离线 → 归因热插拔
    #[test]
    fn clip_blames_offline_cores_before_group_limits() {
        let want = set(&[4, 5, 6]);
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            classify_clip(&want, &online, |_| true),
            ClipWhy::GroupLimited
        );

        // 汇总位图写「6 在线」，单核文件却是 0：以逐核为准
        assert_eq!(
            classify_clip(&want, &online, |c| c != 6),
            ClipWhy::Offline(set(&[6]))
        );

        // 汇总位图本身就少 6，直接判离线
        assert_eq!(
            classify_clip(&want, &set(&[4, 5]), |_| true),
            ClipWhy::Offline(set(&[6]))
        );
    }

    #[test]
    fn combo_totals_add_up_to_the_kind_count() {
        let mut m: HashMap<(bool, String), u32> = HashMap::new();
        for (k, n) in [("4-6→4-7", 4), ("4-6→0-7", 2), ("7→4-7", 1)] {
            *m.entry((true, k.to_string())).or_insert(0) += n;
        }
        let line = combo_list(&m, true);
        assert!(line.contains("4-6→4-7 ×4"), "{}", line);
        assert!(line.contains("4-6→0-7 ×2"), "{}", line);
        assert!(line.contains("7→4-7 ×1"), "{}", line);

        // 种类超过上限时合并成「另 N 种 ×M」，不能丢
        for i in 0..4 {
            *m.entry((true, format!("1-{}→0-7", i))).or_insert(0) += 1;
        }
        assert!(
            combo_list(&m, true).contains("另 4 种 ×4"),
            "{}",
            combo_list(&m, true)
        );

        // 子集（被裁小）不能混进超集（被改大）的明细
        *m.entry((false, "1-7→0-3".to_string())).or_insert(0) += 5;
        assert!(combo_list(&m, true).contains("4-6→4-7 ×4"));
        let clip = combo_list(&m, false);
        assert!(clip.contains("1-7→0-3 ×5"), "{}", clip);
        assert!(!clip.contains("4-6→4-7"), "{}", clip);
    }

    /// 主线程的 comm 是包名残段，后面已有完整包名时不该再念一遍
    #[test]
    fn main_thread_sample_does_not_repeat_the_truncated_comm() {
        let d = Drift {
            tid: 13732,
            comm: "ent.tmgp.osgame".to_string(),
            pkg: "com.tencent.tmgp.osgame".to_string(),
            expect: "4-6".to_string(),
            actual: "4-7".to_string(),
            cpuset: "/top-app".to_string(),
            is_main: true,
        };
        assert_eq!(sample_tag(&d), "主线程(13732)[com.tencent.tmgp.osgame]");
        let orphan = Drift {
            pkg: String::new(),
            ..d
        };
        assert!(sample_tag(&orphan).contains("ent.tmgp.osgame"));
    }

    #[test]
    fn delta_desc_only_lists_extra_cores() {
        assert_eq!(delta_desc("4-6", "4-7"), "（多 7）");
        assert_eq!(delta_desc("4-7", "4-7"), "");
        assert_eq!(delta_desc("7", "4-7"), "（多 4-6）");
    }

    #[test]
    fn tally_line_puts_current_state_first() {
        let t = SyncTally {
            total: 173,
            ok: 173,
            rebound: 0,
            failed: 0,
            blocked: 0,
        };
        let line = tally_line(t, None, 171, None);
        assert!(line.contains("受管 173"), "{}", line);
        assert!(line.contains("一致 173"), "{}", line);
        let state = line.find("一致 173").unwrap();
        let history = line.find("本周期改写").unwrap();
        assert!(state < history, "状态必须在前：{}", line);
        assert!(!line.contains("组上限"), "明细不该挤进总账：{}", line);

        // 一次都没被改过时不要提「本周期改写 0」
        assert!(!tally_line(t, None, 0, None).contains("改写"));

        // 全部线程都是本轮重绑的：主数字仍必须是「一致 1」
        let rebound = tally_line(
            SyncTally {
                total: 1,
                ok: 0,
                rebound: 1,
                failed: 0,
                blocked: 0,
            },
            None,
            1,
            None,
        );
        assert!(rebound.contains("一致 1"), "{}", rebound);
        assert!(rebound.contains("重绑 1"), "{}", rebound);
        assert!(!rebound.contains("符合"), "{}", rebound);

        // 被系统组限制的线程要单独说清，并带上所在组
        let hint = (SysGroup::Background, "0-3".to_string());
        let blocked = tally_line(
            SyncTally {
                total: 170,
                ok: 0,
                rebound: 0,
                failed: 0,
                blocked: 170,
            },
            None,
            0,
            Some(&hint),
        );
        assert!(blocked.contains("被组限制 170（确实没绑"), "{}", blocked);
        assert!(blocked.contains("后台组可用 0-3"), "{}", blocked);
    }

    /// 同一线程反复被改要单独成行：偶发一次与「一分钟十几次」处置方式相反
    #[test]
    fn repeated_rewrites_of_one_thread_are_summarized() {
        let mut hits: HashMap<i32, RewriteHit> = HashMap::new();
        hits.insert(
            13920,
            RewriteHit {
                comm: "UnityMain".into(),
                first_comm: "UnityMain".into(),
                n: 7,
                actual: "4-7".into(),
            },
        );
        hits.insert(
            13732,
            RewriteHit {
                comm: "main".into(),
                first_comm: "main".into(),
                n: 1,
                actual: "0-7".into(),
            },
        );
        let line = contra_line(&hits, 3, 3, |tid| {
            (tid == 13920).then(|| ("com.tencent.tmgp.osgame".to_string(), false))
        })
        .expect("达到阈值必须出这一行");
        assert!(line.starts_with("对抗 1 个线程"), "{}", line);
        assert!(
            line.contains("UnityMain(13920)[com.tencent.tmgp.osgame] 7 次"),
            "{}",
            line
        );
        // 只被改过一次的线程不进这一行
        assert!(!line.contains("main(13732)"), "{}", line);

        // 没到阈值就完全不出声（偶发改写已经有一条独立的「改写」行）
        let quiet: HashMap<i32, RewriteHit> = [(
            1,
            RewriteHit {
                comm: "a".into(),
                first_comm: "a".into(),
                n: 2,
                actual: "0-7".into(),
            },
        )]
        .into_iter()
        .collect();
        assert!(contra_line(&quiet, 3, 3, |_| None).is_none());
    }

    /// 线程改名后要报最新名并把旧名带上：真机上 tid 14636 先叫
    /// `HWC release` 后叫 `GPU completion`，「共 3 次」若挂在旧名下，
    /// 读者 grep 到的那个名字只出现过一行，会以为统计错了
    #[test]
    fn rename_within_cycle_keeps_both_names() {
        let hits: HashMap<i32, RewriteHit> = [(
            14636,
            RewriteHit {
                comm: "GPU completion".into(),
                first_comm: "HWC release".into(),
                n: 3,
                actual: "0-7".into(),
            },
        )]
        .into_iter()
        .collect();
        let line = contra_line(&hits, 3, 3, |_| {
            Some(("com.tencent.tmgp.sgame".into(), false))
        })
        .unwrap();
        assert!(
            line.contains("GPU completion(14636)[com.tencent.tmgp.sgame] 3 次"),
            "{}",
            line
        );
        assert!(line.contains("本周期内由 HWC release 改名"), "{}", line);
    }

    /// 主线程在「对抗」行里也要写成 `主线程(tid)[包名]`：
    /// 逐条「改写」行用的是这个写法，同一份日志里不能两种叫法
    #[test]
    fn main_thread_keeps_the_same_name_in_contra_line() {
        let hits: HashMap<i32, RewriteHit> = [(
            14572,
            RewriteHit {
                comm: "ent.tmgp.osgame".into(),
                first_comm: "ent.tmgp.osgame".into(),
                n: 5,
                actual: "0-7".into(),
            },
        )]
        .into_iter()
        .collect();
        let line = contra_line(&hits, 3, 3, |_| {
            Some(("com.tencent.tmgp.osgame".into(), true))
        })
        .unwrap();
        assert!(
            line.contains("主线程(14572)[com.tencent.tmgp.osgame] 5 次"),
            "{}",
            line
        );
        assert!(!line.contains("ent.tmgp.osgame(14572)"), "{}", line);
    }

    #[test]
    fn empty_tally_never_stays_silent() {
        assert!(empty_state_hint(None, false).contains("首轮"));
        assert!(empty_state_hint(Some(SyncTally::default()), true).contains("没有受管线程"));
    }
}
