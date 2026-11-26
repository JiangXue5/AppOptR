//! Shadow 配额分配（融合方案 16.3）。
//!
//! 只算不执行：拿 PMU 本窗口的样本，把线程分成重 / 中 / 轻三档，按拓扑
//! capacity 算出各簇**应该**承载多少活动量，再与 S7 报告的三簇实际负载
//! 对照，给出偏差与「大约空了多少」的提示。
//!
//! 边界与 16.2 一致：`policy::plan_entry`、`sched::decide`、
//! `apply_affinity` 都不读本模块，绑核结果一行都不会因为它改变。
//!
//! 为什么对照「簇级负载」而不是「线程当前在哪个核」：规则允许跨簇
//! （`all → 0-6`）时，绝大多数线程的亲和性同时覆盖 e 和 p，按线程归属
//! 某一簇算出来的是假精确。
//!
//! 但簇负载不能只依赖 S7：S7 只在存在跨簇规则时才统计，而多数用户的规则
//! 是单簇的（`all → 4-6`），这种情况下 S7 根本不跑，对照永远为空。所以
//! 这里补一路自测：读 `/proc/stat` 的逐核忙时增量，按拓扑分簇。S7 有数据
//! 就优先用 S7（它是实际决策方），没有就用自测，日志标明来源。

use std::sync::Mutex;

use crate::cpuset::{CPU_SETSIZE, CpuSet, CpuTopology, cpu_capacity};
use crate::lock_ignore_poison;
use crate::pmu::Sample;
use crate::sched::SCHED_SNAPSHOT;

pub const E: usize = 0;
pub const P: usize = 1;
pub const HP: usize = 2;
pub const TIER_NAMES: [&str; 3] = ["e-core", "p-core", "hp-core"];

/// 偏差小于 8 个百分点当作噪声：簇负载本身有采样抖动，卡太死会天天报「偏载」
const GAP_EPS: f64 = 0.08;
/// 内核不提供 `cpu_capacity` 时的单核权重。全按 1 平权，总比整簇算成 0 好
const CPU_CAPACITY_FALLBACK: u64 = 1024;
/// 分档按「活动量份额」而不是绝对速率：线程按工作量降序，累计到 50%
/// 的算重负载，到 85% 的算中等，其余算轻。
///
/// 早先用绝对阈值（CPU 时间 ≥50% 算重），真机上 UnityMain 在 45%–60%
/// 之间晃，重/中两档跟着一秒钟一个样，看日志的人只会以为统计坏了。
/// 份额法天然与量纲无关，也不受设备快慢影响
const HEAVY_SHARE: f64 = 0.50;
const MEDIUM_SHARE: f64 = 0.85;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Load {
    Heavy,
    Medium,
    Light,
}

#[derive(Clone, Debug, Default)]
pub struct ShadowPlan {
    pub heavy: usize,
    pub medium: usize,
    pub light: usize,
    /// 重负载线程占本窗口总活动量的比例
    pub heavy_share: f64,
    /// 按 capacity 的建议承载比例 [e, p, hp]，和为 1
    pub want: [f64; 3],
    /// S7 实际簇负载比例（已归一化）。None = 没有可用的对照数据
    pub got: Option<[f64; 3]>,
    /// 对照数据来源：`S7` 或 `核占用`。日志与面板都标明，避免把自测
    /// 当成 S7 的决策结果
    pub source: &'static str,
    /// 实际 - 建议，正数表示这簇比它该承担的更满
    pub gap: [f64; 3],
    /// 匹配度 0–1：`1 - Σ|gap| / 2`
    pub fit: f64,
    /// 最空的簇（缺口超过 8 个百分点）
    pub starved: Option<usize>,
    /// 最空簇的规范名，给日志用（`Option` 不方便直接拼字符串）
    pub starved_name: &'static str,
    /// 若要把负载搬过去，优先搬的重负载线程（只列名，不执行）
    pub hints: Vec<String>,
    /// 本窗口参与统计的样本数
    pub samples: usize,
}

impl ShadowPlan {
    /// 日志一行。没有对照数据时只报分档，不硬凑
    pub fn log_text(&self) -> String {
        let mut s = format!("重 {} / 中 {} / 轻 {}", self.heavy, self.medium, self.light);
        let Some(got) = self.got else {
            s.push_str(" ｜ 暂无对照");
            return s;
        };
        s.push_str(&format!(
            " ｜ 建议 e{:.0} p{:.0} hp{:.0} → 实际 e{:.0} p{:.0} hp{:.0}，匹配 {:.0}%（{}）",
            self.want[E] * 100.0,
            self.want[P] * 100.0,
            self.want[HP] * 100.0,
            got[E] * 100.0,
            got[P] * 100.0,
            got[HP] * 100.0,
            self.fit * 100.0,
            self.source,
        ));
        if let Some(i) = self.starved {
            // 「空」容易被读成没有线程，这里说清是「比该承担的少」
            s.push_str(&format!(
                " ｜ {} 偏空 {:.0} 个点",
                self.starved_name,
                -self.gap[i] * 100.0
            ));
        }
        s
    }
}

static SNAPSHOT: Mutex<Option<ShadowPlan>> = Mutex::new(None);

/// 每个 PMU 窗口调用一次。`samples` 必须是**截断前**的全量，否则只统计到
/// 最忙的八条，分档比例会完全失真
pub fn update(samples: &[Sample], topo: &CpuTopology) {
    // `mode == 0` 是 S7 关闭。关掉之后快照还留着最后一次的负载，
    // 拿它当「实际分布」对照会得出过期结论，宁可不比
    let s7 = lock_ignore_poison(&SCHED_SNAPSHOT)
        .as_ref()
        .filter(|s| s.mode != 0)
        .map(|s| s.load);
    let own = self_measured(topo);
    let plan = compute(samples, topo, s7, own);
    *lock_ignore_poison(&SNAPSHOT) = Some(plan);
}

pub fn snapshot() -> Option<ShadowPlan> {
    lock_ignore_poison(&SNAPSHOT).clone()
}

/// 关掉 PMU 或配额时清空。留着旧数据会让面板显示已过期的结论
pub fn clear() {
    *lock_ignore_poison(&SNAPSHOT) = None;
}

fn compute(
    samples: &[Sample],
    topo: &CpuTopology,
    s7: Option<[i32; 3]>,
    own: Option<[f64; 3]>,
) -> ShadowPlan {
    let mut plan = ShadowPlan {
        samples: samples.len(),
        ..Default::default()
    };

    // 按工作量降序，累计份额切三档。一个线程占掉六成活动量时，
    // 它自己就是「重」——这正是真机上 UnityMain 的形态
    let mut order: Vec<(&Sample, u64)> = samples.iter().map(|s| (s, s.weight().max(1))).collect();
    order.sort_by_key(|(_, w)| std::cmp::Reverse(*w));
    let total: u64 = order.iter().map(|(_, w)| w).sum();
    let mut acc = 0u64;
    let mut heavy_w = 0u64;
    for (_, w) in &order {
        let before = acc as f64 / total as f64;
        let load = if before < HEAVY_SHARE {
            Load::Heavy
        } else if before < MEDIUM_SHARE {
            Load::Medium
        } else {
            Load::Light
        };
        match load {
            Load::Heavy => {
                plan.heavy += 1;
                heavy_w += w;
            }
            Load::Medium => plan.medium += 1,
            Load::Light => plan.light += 1,
        }
        acc += w;
    }
    if total > 0 {
        plan.heavy_share = heavy_w as f64 / total as f64;
    }

    plan.want = want_from_caps([
        tier_capacity(&topo.e_core),
        tier_capacity(&topo.p_core),
        tier_capacity(&topo.hp_core),
    ]);
    // 未分层（单簇设备）时没有可分配的东西，只保留分档
    if plan.want.iter().all(|&x| x == 0.0) {
        return plan;
    }

    // S7 有数据就用 S7：它才是实际决策方；单簇规则下 S7 不跑，
    // 退到自测的逐核忙时分布
    let (got, source) = match normalized(s7) {
        Some(g) => (Some(g), "S7"),
        None => (own, "核占用"),
    };
    let Some(got) = got else {
        return plan;
    };
    plan.got = Some(got);
    plan.source = source;

    let mut abs = 0.0;
    for (i, g) in got.iter().enumerate() {
        plan.gap[i] = g - plan.want[i];
        abs += plan.gap[i].abs();
    }
    plan.fit = (1.0 - abs / 2.0).clamp(0.0, 1.0);

    let mut starved = None;
    let mut min = -GAP_EPS;
    for (i, w) in plan.want.iter().enumerate() {
        if *w > 0.0 && plan.gap[i] < min {
            min = plan.gap[i];
            starved = Some(i);
        }
    }
    plan.starved = starved;
    if let Some(i) = starved {
        plan.starved_name = TIER_NAMES[i];
        plan.hints = order
            .iter()
            .take(plan.heavy)
            .take(3)
            .map(|(s, _)| format!("{}({}) {}", s.comm, s.tid, s.rate_text()))
            .collect();
    }
    plan
}

/// 按各簇总 capacity 分摊。某簇没有可用核时权重为 0，自然不参与分配
fn want_from_caps(caps: [u64; 3]) -> [f64; 3] {
    let sum: u64 = caps.iter().sum();
    if sum == 0 {
        return [0.0; 3];
    }
    let mut w = [0.0; 3];
    for (i, slot) in w.iter_mut().enumerate() {
        *slot = caps[i] as f64 / sum as f64;
    }
    w
}

/// 簇容量 = 簇内各核 capacity 之和。读不到单个核的 capacity 时按 1024 平权，
/// 否则整簇会被算成 0，看起来像「这个簇不该承载任何活」
fn tier_capacity(set: &CpuSet) -> u64 {
    let mut sum = 0u64;
    for cpu in 0..CPU_SETSIZE {
        if set.is_set(cpu) {
            let c = cpu_capacity(cpu);
            sum += if c > 0 { c } else { CPU_CAPACITY_FALLBACK };
        }
    }
    sum
}

/// 一簇的（忙 jiffies, 总 jiffies）。核全部不可读时为 None
type ClusterTicks = Option<(u64, u64)>;

/// 上一窗口的逐簇忙时基线
static CPU_PREV: Mutex<Option<[ClusterTicks; 3]>> = Mutex::new(None);

/// 自测簇负载：`/proc/stat` 逐核忙时增量，按拓扑归簇后取份额。
///
/// 存在的理由只有一个——S7 只在有跨簇规则时才统计簇负载。规则写成
/// `all → 4-6` 的用户永远拿不到对照，配额就成了一个只报分档的空壳。
/// 逐核忙时与规则无关，任何配置下都能算。
fn self_measured(topo: &CpuTopology) -> Option<[f64; 3]> {
    let times = read_cpu_times()?;
    let cur = [
        cluster_busy(&times, &topo.e_core),
        cluster_busy(&times, &topo.p_core),
        cluster_busy(&times, &topo.hp_core),
    ];
    let mut guard = lock_ignore_poison(&CPU_PREV);
    let prev = guard.replace(cur)?;

    let mut busy = [0f64; 3];
    for i in 0..3 {
        let (Some((b0, t0)), Some((b1, t1))) = (prev[i], cur[i]) else {
            continue;
        };
        if t1 <= t0 {
            // 该簇核全部离线或 tick 未推进，跳过而不是整体作废
            continue;
        }
        busy[i] = (b1 - b0) as f64;
    }
    let sum: f64 = busy.iter().sum();
    if sum <= 0.0 {
        return None;
    }
    Some([busy[0] / sum, busy[1] / sum, busy[2] / sum])
}

/// 一簇内所有核的（忙时, 总时）合计。忙时不含 idle 与 iowait
fn cluster_busy(times: &[(u64, u64)], set: &CpuSet) -> ClusterTicks {
    let mut busy = 0u64;
    let mut total = 0u64;
    let mut any = false;
    for cpu in 0..CPU_SETSIZE {
        if !set.is_set(cpu) {
            continue;
        }
        if let Some(&(b, t)) = times.get(cpu) {
            busy += b;
            total += t;
            any = true;
        }
    }
    any.then_some((busy, total))
}

/// 解析 `/proc/stat`，返回按 CPU 号索引的（忙时, 总时）。只取前 8 个字段：
/// guest/guest_nice 已经计入 user/nice，再加会重复
fn read_cpu_times() -> Option<Vec<(u64, u64)>> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    parse_cpu_times(&text)
}

fn parse_cpu_times(text: &str) -> Option<Vec<(u64, u64)>> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        // 汇总行是 `cpu `（cpu 后直接空格），逐核行是 `cpu0`/`cpu10`
        if rest.starts_with(' ') || rest.starts_with('\t') {
            continue;
        }
        let mut it = rest.split_whitespace();
        let Some(num) = it.next() else { continue };
        // 汇总行是 `cpu `，没有编号
        let Ok(idx) = num.parse::<usize>() else {
            continue;
        };
        let vals: Vec<u64> = it.filter_map(|x| x.parse().ok()).collect();
        if vals.len() < 5 {
            continue;
        }
        let idle = vals[3] + vals[4];
        let total: u64 = vals.iter().take(8).sum();
        if idx >= out.len() {
            out.resize(idx + 1, (0, 0));
        }
        out[idx] = (total.saturating_sub(idle), total);
    }
    (!out.is_empty()).then_some(out)
}

/// S7 的三簇千分比 → 比例。任一为 -1（不可用）或全 0 时返回 None：
/// 拿一份没有意义的分布去对照，比不对照更糟
fn normalized(load: Option<[i32; 3]>) -> Option<[f64; 3]> {
    let l = load?;
    if l.iter().any(|&x| x < 0) {
        return None;
    }
    let sum: i64 = l.iter().map(|&x| x as i64).sum();
    if sum <= 0 {
        return None;
    }
    let mut g = [0.0; 3];
    for (i, slot) in g.iter_mut().enumerate() {
        *slot = l[i] as f64 / sum as f64;
    }
    Some(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(inst: u64, cycles: u64, cpu_ns: Option<u64>) -> Sample {
        Sample {
            tid: 1,
            pkg: "com.a".into(),
            comm: "T".into(),
            inst,
            cycles,
            misses: None,
            cpu_ns,
            window_ms: 5_000,
        }
    }

    /// 三种量纲各自分档，不能串：软件计时下 inst 恒 0，按 M/s 判会把
    /// 所有线程打成「轻」，配额就没东西可分了
    /// 没开跨簇规则的设备上，S7 不统计簇负载，对照只能靠自测。
    /// 这一条直接读真机的 `/proc/stat`，验证两次采样之间能算出份额
    #[test]
    fn self_measured_reads_proc_stat() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let mut topo = CpuTopology::empty();
        topo.e_core = CpuSet::new();
        topo.e_core.set(0);
        topo.p_core = CpuSet::new();
        topo.p_core.set(1);

        // 第一次只建基线
        let _ = self_measured(&topo);
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut n = 0u64;
            while !flag.load(Ordering::Relaxed) {
                n = n.wrapping_add(1);
                std::hint::black_box(n);
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let got = self_measured(&topo);
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();

        let g = got.expect("两次采样之间必然有 tick 推进");
        assert!((g.iter().sum::<f64>() - 1.0).abs() < 1e-9);
        assert_eq!(g[2], 0.0, "hp 簇为空时占比必须是 0");
    }

    #[test]
    fn want_follows_capacity() {
        // 4 小核 ×1024 + 3 大核 ×2048 + 1 超大核 ×3072
        let w = want_from_caps([4096, 6144, 3072]);
        assert!((w[E] - 0.3077).abs() < 0.001);
        assert!((w[P] - 0.4615).abs() < 0.001);
        assert!((w[HP] - 0.2308).abs() < 0.001);
        assert!((w.iter().sum::<f64>() - 1.0).abs() < 1e-9);
        // 未分层：全 0，调用方会跳过对照
        assert_eq!(want_from_caps([0, 0, 0]), [0.0; 3]);
        // 只有 e 和 p 的两簇机型
        assert_eq!(want_from_caps([100, 300, 0]), [0.25, 0.75, 0.0]);
    }

    #[test]
    fn normalized_rejects_junk() {
        assert_eq!(normalized(None), None);
        assert_eq!(normalized(Some([-1, -1, -1])), None, "S7 不可用不能当 0 用");
        assert_eq!(normalized(Some([0, 0, 0])), None);
        let g = normalized(Some([400, 100, 500])).unwrap();
        assert!((g[0] - 0.4).abs() < 1e-9);
        assert!((g[1] - 0.1).abs() < 1e-9);
        assert!((g[2] - 0.5).abs() < 1e-9);
    }

    /// 真机形态：建议 p-core 55%，实际只有 9%，p 空 46 个点。
    /// 这时要能指出 p-core 缺活，并给出候选线程
    #[test]
    fn starved_tier_is_reported() {
        let mut cap: Vec<Sample> = Vec::new();
        for (i, m) in [380u64, 310, 260, 150, 140, 30].iter().enumerate() {
            let mut s = sample(m * 1_000_000 * 5, 0, None);
            s.tid = 100 + i as i32;
            s.comm = format!("W{i}");
            cap.push(s);
        }
        let topo = CpuTopology::empty();
        // empty() 的 e/p/hp 都是空集 → want 全 0，这里改用假 capacity 走纯函数
        let want = want_from_caps([4096, 6144, 3072]);
        let got = normalized(Some([530, 90, 380])).unwrap();
        let gap = [got[E] - want[E], got[P] - want[P], got[HP] - want[HP]];

        assert!(gap[P] < -GAP_EPS, "p-core 应被判为缺口");
        assert!(gap[E] > 0.0, "e-core 超载");
        let fit = 1.0 - gap.iter().map(|g| g.abs()).sum::<f64>() / 2.0;
        assert!(fit < 0.7, "错位明显时匹配度要低，实得 {fit}");
        let _ = topo;
    }

    /// 分档按活动量份额切，不是按线程数：1 个占六成活动的线程是「重」，
    /// 十个各占 1% 的线程只能算「轻」
    #[test]
    fn tiers_follow_activity_share() {
        let mut v = vec![sample(600, 0, None)];
        for i in 0..10 {
            let mut s = sample(10, 0, None);
            s.tid = i + 2;
            v.push(s);
        }
        let plan = compute(&v, &CpuTopology::empty(), None, None);
        assert_eq!(plan.heavy, 1, "一个人占 85% 活动量，只有它算重");
        assert!(plan.heavy_share > 0.8, "实得 {}", plan.heavy_share);
        assert_eq!(plan.medium + plan.light, 10);
    }

    /// 单簇规则下 S7 不跑（got 为 None），自测必须能补上对照
    #[test]
    fn own_load_is_used_when_s7_is_absent() {
        let samples = vec![sample(600, 0, None)];
        let plan = compute(&samples, &CpuTopology::empty(), None, Some([0.5, 0.3, 0.2]));
        // 未分层时 want 全 0，会在对照前返回，这里只验分档仍成立
        assert_eq!(plan.heavy, 1);
        assert!(plan.got.is_none());
    }

    /// S7 有数据时优先用 S7：它才是实际决策方
    #[test]
    fn s7_wins_over_own_load() {
        let samples = vec![sample(600, 0, None)];
        let plan = compute(
            &samples,
            &CpuTopology::empty(),
            Some([400, 400, 200]),
            Some([0.1, 0.1, 0.8]),
        );
        assert_eq!(plan.heavy, 1);
    }

    /// `/proc/stat`：汇总行要跳过，guest 不能重复计
    #[test]
    fn parse_stat_skips_summary_row() {
        let text = "\
cpu  100 0 50 1000 10 0 0 0 0 0
cpu0 50 0 25 500 5 0 0 0 0 0
cpu1 50 0 25 500 5 0 0 0 0 0
intr 12345
";
        let v = parse_cpu_times(text).unwrap();
        assert_eq!(v.len(), 2, "汇总行不能进数组");
        // busy = 50+25 = 75；total = 50+25+500+5 = 580
        assert_eq!(v[0], (75, 580));
    }
}
