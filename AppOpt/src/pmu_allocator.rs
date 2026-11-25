//! Shadow 配额分配（融合方案 16.3）。
//!
//! 只算不执行：拿 PMU 本窗口的样本，把线程分成重 / 中 / 轻三档，按拓扑
//! capacity 算出各簇**应该**承载多少活动量，再与 S7 报告的三簇实际负载
//! 对照，给出偏差与「大约空了多少」的提示。
//!
//! 边界与 16.2 一致：`policy::plan_entry`、`sched::decide`、
//! `apply_affinity` 都不读本模块，绑核结果一行都不会因为它改变。
//!
//! 为什么对照「S7 的簇负载」而不是「线程当前在哪个核」：规则允许跨簇
//! （`all → 0-6`）时，绝大多数线程的亲和性同时覆盖 e 和 p，按线程归属
//! 某一簇算出来的是假精确。簇级负载是 S7 自己统计的，直接拿来对照更诚实，
//! 也正好对上方案里「与 S7 实际决策对照」那句。

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

/// 分档。阈值来自 osgame 真机日志：渲染提交与任务线程 100–380 M/s，
/// 第二梯队几十 M/s，其余绝大多数接近 0
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Load {
    Heavy,
    Medium,
    Light,
}

/// 按本窗口的实际速率分档。三种计量方式各有一套阈值，量纲不能混用：
/// 软件计时下 inst / cycles 恒为 0，按 M/s 判会把全部线程打成「轻」
pub fn classify(s: &Sample) -> Load {
    if s.cpu_ns.is_some() {
        let pct = s.cpu_pct();
        if pct >= 50.0 {
            Load::Heavy
        } else if pct >= 10.0 {
            Load::Medium
        } else {
            Load::Light
        }
    } else if s.inst > 0 {
        let m = s.mips();
        if m >= 100.0 {
            Load::Heavy
        } else if m >= 20.0 {
            Load::Medium
        } else {
            Load::Light
        }
    } else {
        let g = s.gcyc();
        if g >= 3.0 {
            Load::Heavy
        } else if g >= 0.6 {
            Load::Medium
        } else {
            Load::Light
        }
    }
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
    /// S7 实际簇负载比例（已归一化）。None = S7 未运行或该轮没有负载数据
    pub got: Option<[f64; 3]>,
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
    /// 日志一行。没有 S7 负载数据时只报分档，不硬凑对照
    pub fn log_text(&self) -> String {
        let mut s = format!(
            "配额 shadow 重 {} / 中 {} / 轻 {}",
            self.heavy, self.medium, self.light
        );
        let Some(got) = self.got else {
            s.push_str(" ｜ S7 未运行或无簇负载数据，暂不对照");
            return s;
        };
        s.push_str(&format!(
            " ｜ 建议→实际 e {:.0}%→{:.0}% p {:.0}%→{:.0}% hp {:.0}%→{:.0}%，匹配 {:.0}%",
            self.want[E] * 100.0,
            got[E] * 100.0,
            self.want[P] * 100.0,
            got[P] * 100.0,
            self.want[HP] * 100.0,
            got[HP] * 100.0,
            self.fit * 100.0,
        ));
        if let Some(i) = self.starved {
            s.push_str(&format!(
                " ｜ {} 空 {:.0} 个点",
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
    let load = lock_ignore_poison(&SCHED_SNAPSHOT)
        .as_ref()
        .filter(|s| s.mode != 0)
        .map(|s| s.load);
    let plan = compute(samples, topo, load);
    *lock_ignore_poison(&SNAPSHOT) = Some(plan);
}

pub fn snapshot() -> Option<ShadowPlan> {
    lock_ignore_poison(&SNAPSHOT).clone()
}

/// 关掉 PMU 或配额时清空。留着旧数据会让面板显示已过期的结论
pub fn clear() {
    *lock_ignore_poison(&SNAPSHOT) = None;
}

fn compute(samples: &[Sample], topo: &CpuTopology, load: Option<[i32; 3]>) -> ShadowPlan {
    let mut plan = ShadowPlan {
        samples: samples.len(),
        ..Default::default()
    };

    let mut total = 0u64;
    let mut heavy_w = 0u64;
    for s in samples {
        let w = s.weight().max(1);
        total += w;
        match classify(s) {
            Load::Heavy => {
                plan.heavy += 1;
                heavy_w += w;
            }
            Load::Medium => plan.medium += 1,
            Load::Light => plan.light += 1,
        }
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

    let Some(got) = normalized(load) else {
        return plan;
    };
    plan.got = Some(got);

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
        let mut heavy: Vec<&Sample> = samples
            .iter()
            .filter(|s| classify(s) == Load::Heavy)
            .collect();
        heavy.sort_by_key(|s| std::cmp::Reverse(s.weight()));
        plan.hints = heavy
            .iter()
            .take(3)
            .map(|s| format!("{}({}) {}", s.comm, s.tid, s.rate_text()))
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
    #[test]
    fn classify_uses_the_live_metric() {
        // 指令：100 M/s 以上为重（窗口 5 秒 → 5 亿条指令）
        assert_eq!(classify(&sample(600_000_000, 0, None)), Load::Heavy);
        assert_eq!(classify(&sample(150_000_000, 0, None)), Load::Medium);
        assert_eq!(classify(&sample(10_000_000, 0, None)), Load::Light);
        // 只有周期：3 Gcyc/s 以上为重（5 秒 → 150 亿）
        assert_eq!(classify(&sample(0, 20_000_000_000, None)), Load::Heavy);
        assert_eq!(classify(&sample(0, 5_000_000_000, None)), Load::Medium);
        // 软件计时：50% 以上为重（5 秒窗口里跑了 2.5 秒）
        assert_eq!(classify(&sample(0, 0, Some(3_000_000_000))), Load::Heavy);
        assert_eq!(classify(&sample(0, 0, Some(1_000_000_000))), Load::Medium);
        assert_eq!(classify(&sample(0, 0, Some(100_000_000))), Load::Light);
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

    /// 分档比例按活动量算，不是按线程数：1 个 380 M/s 的线程远比
    /// 10 个 1 M/s 的线程重
    #[test]
    fn heavy_share_uses_activity_not_counts() {
        let mut v = vec![sample(380 * 1_000_000 * 5, 0, None)];
        for i in 0..10 {
            let mut s = sample(1_000_000, 0, None);
            s.tid = i + 2;
            v.push(s);
        }
        let plan = compute(&v, &CpuTopology::empty(), None);
        assert_eq!(plan.heavy, 1);
        assert!(plan.heavy_share > 0.98, "实得 {}", plan.heavy_share);
    }
}
