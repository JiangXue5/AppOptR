//! λmod —— 用拉格朗日乘子求解「线程该落在哪一层」。
//!
//! 与 `pmu_allocator` 的分工：那个按活动量份额把线程切成重/中/轻，再按
//! capacity 算各簇**应该**承担多少活动量，回答的是「簇间平不平衡」；这里
//! 把「每条线程选一层」建成带容量约束的效用最大化问题，解出每层的影子
//! 价格 λ 与每线程的落层概率，回答的是「谁该上大核」。
//!
//! ## 模型
//!
//! 层 k 的容量 `rho_k` = 该层核数 / 总核数（线程按「一个占一个核」计）。
//! 线程 i 对层 k 的代价 `π_ik = λ_k · sens_ik`，其中
//! `sens = 1 + (insn_share · cache_miss_rate) / L2_k`，即「这条线程在这层
//! 的访存压力相对 L2 有多大」。落层概率是 `softmax(-π/T)`：λ_k 越大表示
//! 第 k 层越挤，概率越低。每轮按 `λ_k += γ·η·(s_k - rho_k)` 对偶上升，
//! `s_k` 是实际分配占比——超载的层涨价，空闲的层降价。
//!
//! ## 与参考实现的三处不同
//!
//! 1. **层取自实测 `all_tiers`**，2+2+4 这类四层机不压成三档；
//! 2. **不做 perf_event_open**——样本由 `pmu.rs` 统一采集，本模块只消费，
//!    避免同一线程被两套 FD 各开一遍；
//! 3. **不执行**。`policy::plan_entry` / `sched::decide` / `apply_affinity`
//!    一行都不读本模块。S7 的落点算法经过真机验证，在拿到可重复收益之前
//!    不做第二套执行器（方案 16.4 的验收门槛还没过）。
//!
//! 参考实现的三个坑这里也照做：层按实测不硬编码、目标按在线核裁剪、
//! 层核数不足时并入更高层（而不是扩成全核，那等于放弃绑定）。

use std::sync::Mutex;

use crate::cpuset::{CPU_SETSIZE, CpuSet, CpuTopology, cpu_capacity, online_cpus};
use crate::lock_ignore_poison;
use crate::pmu::Sample;

/// softmax 温度。λ 的量级在 0–20，0.1 的温度让概率强烈偏向最优层，
/// 接近 argmax 但仍保留「次优层也有小概率」的梯度信息
const TEMP: f64 = 0.1;
/// 对偶上升的学习率
const ETA: f64 = 0.1;
/// 单步最大位移。窗口 5 秒、每窗口迭代 6 次，不限幅会让 λ 在两层之间
/// 反复过冲（参考实现里 γ 峰值 8 时单步 Δλ≈21，实测两小时不收敛）
const MAX_STEP: f64 = 0.5;
/// λ 上限。约束是「占比不超过 rho」，理论上 λ 有界；这个上界只是
/// 防止数值病态时指数爆炸
const MAX_LAMBDA: f64 = 20.0;
/// 每个采样窗口内部迭代几次。窗口之间相隔 5 秒，一窗只走一步要几分钟
/// 才收敛；固定点迭代不引入额外偏差，可以在一窗内多走几步
const ROUNDS_PER_WINDOW: usize = 6;
/// 参考 miss 率与参考 L2：sens 项的归一化基准，取自参考实现。
/// 改这两个数只影响各层之间的相对偏好强度，不影响收敛性
const REF_MISS: f64 = 0.05;
const REF_L2_KB: f64 = 1024.0;
/// 单核 L2 未知时的估值
const DEFAULT_L2_KB: f64 = 512.0;
/// 面板与日志展示的线程数
const MAX_PICKS: usize = 8;
/// 误差低于它算「已收敛」
const CONVERGED_ERR: f64 = 0.08;

#[derive(Clone, Debug)]
pub struct Tier {
    pub cpus: CpuSet,
    /// 该层单核 L2 估值（KB）。内核不导出 L2，按 capacity 比例估：
    /// 只保证「大核 L2 更大」这个单调关系，绝对值不可当真
    pub l2_kb: f64,
    /// 核数占比，即容量约束
    pub rho: f64,
}

#[derive(Clone, Debug, Default)]
pub struct LambdaPlan {
    /// 状态：「未启用」/「层数不足」/「收敛中」/「已收敛」
    pub state: &'static str,
    pub tiers: Vec<Tier>,
    pub lambda: Vec<f64>,
    /// 模型给出的分配占比，与 `rho` 同量纲
    pub share: Vec<f64>,
    /// capacity 加权占比。与 `pmu_allocator` 的 want 同口径，
    /// 两者不一致是正常的：λmod 按核数均分，capacity 加权更偏性能核
    pub cap_share: Vec<f64>,
    /// max |share - rho| / rho
    pub err: f64,
    /// 累计内部迭代次数
    pub rounds: u64,
    pub threads: usize,
    /// (线程名, tid, 建议层, 该层概率)，按概率降序
    pub picks: Vec<(String, i32, usize, f64)>,
}

impl LambdaPlan {
    /// 日志一行。不为「好看」省略误差：这个数就是收敛与否的唯一判据
    pub fn log_text(&self) -> String {
        if self.tiers.is_empty() {
            return self.state.to_string();
        }
        let lam = self
            .lambda
            .iter()
            .map(|v| format!("{v:.2}"))
            .collect::<Vec<_>>()
            .join("/");
        let sh = self
            .share
            .iter()
            .map(|v| format!("{:.0}", v * 100.0))
            .collect::<Vec<_>>()
            .join("/");
        let rho = self
            .tiers
            .iter()
            .map(|t| format!("{:.0}", t.rho * 100.0))
            .collect::<Vec<_>>()
            .join("/");
        format!(
            "{} 层 ｜ λ {} ｜ 分配 {sh}% → 容量 {rho}% ｜ 误差 {:.1}% ｜ {}",
            self.tiers.len(),
            lam,
            self.err * 100.0,
            self.state
        )
    }
}

struct Solver {
    tiers: Vec<Tier>,
    lambda: Vec<f64>,
    share: Vec<f64>,
    rounds: u64,
}

static SOLVER: Mutex<Option<Solver>> = Mutex::new(None);
static PLAN: Mutex<Option<LambdaPlan>> = Mutex::new(None);

/// 关闭 PMU 或配额时清空：留着旧 λ 会在下次启用时从过期状态起步
pub fn clear() {
    *lock_ignore_poison(&SOLVER) = None;
    *lock_ignore_poison(&PLAN) = None;
}

pub fn snapshot() -> Option<LambdaPlan> {
    lock_ignore_poison(&PLAN).clone()
}

/// 每个 PMU 窗口调用一次。`samples` 必须是截断前的全量
pub fn update(samples: &[Sample], topo: &CpuTopology) {
    let tiers = build_tiers(topo);
    if tiers.len() < 2 {
        // 单层设备没有「分配到哪一层」可言。不要硬凑一个解出来
        *lock_ignore_poison(&SOLVER) = None;
        *lock_ignore_poison(&PLAN) = Some(LambdaPlan {
            state: if tiers.is_empty() {
                "不可用"
            } else {
                "层数不足"
            },
            tiers,
            ..Default::default()
        });
        return;
    }

    let mut guard = lock_ignore_poison(&SOLVER);
    if guard.as_ref().is_none_or(|s| !same_tiers(&s.tiers, &tiers)) {
        *guard = Some(Solver {
            lambda: vec![1.0; tiers.len()],
            share: vec![0.0; tiers.len()],
            rounds: 0,
            tiers: tiers.clone(),
        });
    }
    let Some(s) = guard.as_mut() else {
        return;
    };
    if samples.is_empty() {
        // 没有活跃线程：s 全 0，继续迭代会把 λ 推到 0（所有层都「空闲」），
        // 下次一有线程就全部涌向 L2 最大的层。保持上一窗口的 λ 不动
        return;
    }

    let feats = features(samples);
    let k = s.tiers.len();
    let n = feats.len() as f64;
    let mut share = vec![0.0; k];
    for _ in 0..ROUNDS_PER_WINDOW {
        share.iter_mut().for_each(|v| *v = 0.0);
        for (insn_share, miss) in &feats {
            let probs = probs_of(s, *insn_share, *miss);
            for kk in 0..k {
                share[kk] += probs[kk];
            }
        }
        for kk in 0..k {
            share[kk] /= n;
        }
        for kk in 0..k {
            let err = share[kk] - s.tiers[kk].rho;
            let step = (ETA * err).clamp(-MAX_STEP, MAX_STEP);
            s.lambda[kk] = (s.lambda[kk] + step).clamp(0.0, MAX_LAMBDA);
        }
        s.rounds += 1;
    }
    s.share = share.clone();

    // 最终 λ 下的每线程建议。展示用 argmax：采样会让同一线程在两轮之间
    // 跳层，面板上看着像统计坏了
    let mut picks: Vec<(String, i32, usize, f64)> = samples
        .iter()
        .zip(feats.iter())
        .map(|(x, (insn_share, miss))| {
            let probs = probs_of(s, *insn_share, *miss);
            let (best, p) =
                probs
                    .iter()
                    .enumerate()
                    .fold(
                        (0usize, -1.0f64),
                        |(bi, bp), (i, &v)| {
                            if v > bp { (i, v) } else { (bi, bp) }
                        },
                    );
            (x.comm.clone(), x.tid, best, p)
        })
        .collect();
    picks.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
    picks.truncate(MAX_PICKS);

    let err = max_err(&share, &s.tiers);
    let plan = LambdaPlan {
        state: if err <= CONVERGED_ERR {
            "已收敛"
        } else {
            "收敛中"
        },
        tiers: s.tiers.clone(),
        lambda: s.lambda.clone(),
        share: share.clone(),
        cap_share: cap_share(&s.tiers),
        err,
        rounds: s.rounds,
        threads: samples.len(),
        picks,
    };
    drop(guard);
    *lock_ignore_poison(&PLAN) = Some(plan);
}

/// 层集合完全一致才复用旧 λ。热插拔/换设备后层数或边界会变，
/// 旧 λ 对应的是另一套约束，接着用等于从一个错误的起点开始
fn same_tiers(a: &[Tier], b: &[Tier]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.cpus == y.cpus)
}

fn max_err(share: &[f64], tiers: &[Tier]) -> f64 {
    tiers
        .iter()
        .zip(share)
        .map(|(t, &s)| (s - t.rho).abs() / t.rho.max(1e-6))
        .fold(0.0f64, f64::max)
}

/// 按实测拓扑构造层。在线核裁剪后为空的层直接丢掉（整层热下线），
/// 相同核集只留一份（单层设备的 e/p/hp 三档全等，留三份会让 λ 互相对打）
fn build_tiers(topo: &CpuTopology) -> Vec<Tier> {
    let online = online_cpus().unwrap_or(topo.present_cpus);
    let mut raw: Vec<CpuSet> = Vec::new();
    let src: Vec<CpuSet> = if topo.all_tiers.is_empty() {
        vec![topo.e_core, topo.p_core, topo.hp_core]
    } else {
        topo.all_tiers.clone()
    };
    for set in &src {
        let mut c = *set;
        c.and(&online);
        if c.count() == 0 || raw.contains(&c) {
            continue;
        }
        raw.push(c);
    }
    let total: usize = raw.iter().map(|c| c.count()).sum();
    if total == 0 {
        return Vec::new();
    }
    let max_cap = raw.iter().map(tier_cap).max().unwrap_or(0);
    raw.into_iter()
        .map(|cpus| {
            let n = cpus.count();
            Tier {
                l2_kb: tier_l2(tier_cap(&cpus), max_cap),
                rho: n as f64 / total as f64,
                cpus,
            }
        })
        .collect()
}

/// 层内最大单核 capacity。同层同构，取最大即可代表这一层
fn tier_cap(set: &CpuSet) -> u64 {
    let mut best = 0u64;
    for cpu in 0..CPU_SETSIZE {
        if set.is_set(cpu) {
            let c = cpu_capacity(cpu);
            if c > best {
                best = c;
            }
        }
    }
    best
}

/// 按 capacity 比例估 L2。内核只给 capacity（相对算力），不给 L2 大小；
/// 这里只要求单调：大核的 L2 不能比小核小，否则 sens 项会把重线程
/// 推到小核去。绝对值夹在 128KB–1MB 之间，避免算出 8MB 这种不现实的值
fn tier_l2(cap: u64, max_cap: u64) -> f64 {
    if cap == 0 || max_cap == 0 {
        return DEFAULT_L2_KB;
    }
    (DEFAULT_L2_KB * cap as f64 / max_cap as f64).clamp(128.0, 1024.0)
}

fn cap_share(tiers: &[Tier]) -> Vec<f64> {
    let caps: Vec<f64> = tiers
        .iter()
        .map(|t| (t.cpus.count() as f64) * tier_cap(&t.cpus).max(1) as f64)
        .collect();
    let sum: f64 = caps.iter().sum();
    if sum <= 0.0 {
        return vec![0.0; tiers.len()];
    }
    caps.into_iter().map(|c| c / sum).collect()
}

/// 每条线程的 (指令份额, cache miss 率)。
///
/// 软件计时模式下 `inst` 恒为 0，用 CPU 时间占比替；两者都没有时均分——
/// 均分等于「这轮看不出谁更重」，比全部算成 0 好（0 会让 sens 项失效）
fn features(samples: &[Sample]) -> Vec<(f64, f64)> {
    let total_inst: u64 = samples.iter().map(|s| s.inst).sum();
    let total_ns: u64 = samples.iter().filter_map(|s| s.cpu_ns).sum();
    let n = samples.len().max(1) as f64;
    samples
        .iter()
        .map(|s| {
            let share = if total_inst > 0 {
                s.inst as f64 / total_inst as f64
            } else if total_ns > 0 {
                s.cpu_ns.unwrap_or(0) as f64 / total_ns as f64
            } else {
                1.0 / n
            };
            // 设备不提供 cache-misses 时用参考值：sens 项退化成只随指令份额
            // 变化，仍然是「重线程更倾向大 L2 层」，只是少了访存强度的区分
            let miss = match s.misses {
                Some(m) if s.inst > 0 => (m as f64 / s.inst as f64).clamp(0.0005, 1.0),
                Some(_) => REF_MISS,
                None => REF_MISS,
            };
            (share, miss)
        })
        .collect()
}

/// `softmax(-π/T)`。π 只保留随层变化的项：λ_k 乘上该层的 sens。
fn probs_of(s: &Solver, insn_share: f64, miss: f64) -> Vec<f64> {
    let k = s.tiers.len();
    let mut pi = Vec::with_capacity(k);
    for (kk, t) in s.tiers.iter().enumerate() {
        let cap_kb = t.l2_kb.max(64.0);
        let pressure = (insn_share * miss) / cap_kb;
        let sens = (1.0 + pressure / (REF_MISS / REF_L2_KB)).max(1.0);
        pi.push(s.lambda[kk] * sens);
    }
    let min_pi = pi.iter().cloned().fold(f64::MAX, f64::min);
    let t = TEMP.max(1e-6);
    let mut out: Vec<f64> = pi.iter().map(|p| (-(p - min_pi) / t).exp()).collect();
    let sum: f64 = out.iter().sum();
    if sum <= 0.0 || !sum.is_finite() {
        return vec![1.0 / k as f64; k];
    }
    out.iter_mut().for_each(|v| *v /= sum);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(cpus: &[usize], l2: f64, rho: f64) -> Tier {
        let mut s = CpuSet::new();
        for &c in cpus {
            s.set(c);
        }
        Tier {
            cpus: s,
            l2_kb: l2,
            rho,
        }
    }

    fn solver(tiers: Vec<Tier>) -> Solver {
        Solver {
            lambda: vec![1.0; tiers.len()],
            share: vec![0.0; tiers.len()],
            rounds: 0,
            tiers,
        }
    }

    /// 概率归一化；λ 相同的两层、相同 sens 时应当各占一半
    #[test]
    fn probs_are_normalised() {
        let s = solver(vec![tier(&[0, 1], 256.0, 0.5), tier(&[2, 3], 256.0, 0.5)]);
        let p = probs_of(&s, 0.1, 0.05);
        assert!((p.iter().sum::<f64>() - 1.0).abs() < 1e-9);
        assert!((p[0] - 0.5).abs() < 1e-9, "同价同容量应各半：{p:?}");
    }

    /// λ 涨一层，该层概率必须降：这是对偶上升能起作用的唯一前提
    #[test]
    fn higher_lambda_lowers_probability() {
        let mut s = solver(vec![tier(&[0, 1], 256.0, 0.5), tier(&[2, 3], 256.0, 0.5)]);
        s.lambda[1] = 4.0;
        let p = probs_of(&s, 0.1, 0.05);
        assert!(p[1] < p[0], "λ 大的层概率必须更低：{p:?}");
    }

    /// L2 更大的层对同一线程更便宜：sens 小 → π 小 → 概率高。
    /// 这条要是反了，重线程会被赶到小核去
    #[test]
    fn bigger_l2_attracts_load() {
        let s = solver(vec![tier(&[0, 1], 256.0, 0.5), tier(&[2, 3], 1024.0, 0.5)]);
        // 指令份额 20%、miss 10%：pressure 显著
        let p = probs_of(&s, 0.2, 0.1);
        assert!(p[1] > p[0], "大 L2 层应更受偏好：{p:?}");
    }

    /// 迭代方向：初始 λ 全 1 时，容量大的一层会先被挤爆（s > rho），
    /// λ 随之上升，最终把分配压回 rho 附近
    #[test]
    fn iteration_pushes_share_back_to_capacity() {
        let mut s = solver(vec![
            tier(&[0, 1], 512.0, 0.25),
            tier(&[2, 3, 4, 5, 6, 7], 1024.0, 0.75),
        ]);
        let feats = vec![(0.1, 0.05); 10];
        for _ in 0..200 {
            let mut share = vec![0.0; 2];
            for (a, m) in &feats {
                let p = probs_of(&s, *a, *m);
                for k in 0..2 {
                    share[k] += p[k];
                }
            }
            for v in share.iter_mut() {
                *v /= feats.len() as f64;
            }
            for k in 0..2 {
                let err = share[k] - s.tiers[k].rho;
                s.lambda[k] =
                    (s.lambda[k] + (ETA * err).clamp(-MAX_STEP, MAX_STEP)).clamp(0.0, MAX_LAMBDA);
            }
        }
        // 收敛后大核层（rho=0.75）分到的线程应明显多于小核层
        let mut share = vec![0.0; 2];
        for (a, m) in &feats {
            let p = probs_of(&s, *a, *m);
            for k in 0..2 {
                share[k] += p[k];
            }
        }
        share.iter_mut().for_each(|v| *v /= feats.len() as f64);
        assert!(share[1] > share[0], "大容量层应承载更多：{share:?}");
        // 收敛判据是「分配回到容量」，不是「λ 谁大」：小核层 L2 小、
        // sens 天生更高，λ 反而可能略高却仍然分得少
        for (k, t) in s.tiers.iter().enumerate() {
            assert!(
                (share[k] - t.rho).abs() < 0.05,
                "第 {k} 层应回到 rho={:.2}，实得 {:.3}",
                t.rho,
                share[k]
            );
        }
    }

    /// 层数不足时不给解：单层设备上「分配到哪层」没有意义
    #[test]
    fn single_tier_has_no_plan() {
        let mut topo = CpuTopology::empty();
        topo.all_tiers = vec![{
            let mut s = CpuSet::new();
            s.set(0);
            s
        }];
        let tiers = build_tiers(&topo);
        assert_eq!(tiers.len(), 1);
    }

    /// 三档完全相同时（单层设备）合并成一层，否则 λ 会在三个同集层上互打
    #[test]
    fn identical_tiers_collapse() {
        let mut all = CpuSet::new();
        all.set(0);
        all.set(1);
        let mut topo = CpuTopology::empty();
        topo.e_core = all;
        topo.p_core = all;
        topo.hp_core = all;
        let tiers = build_tiers(&topo);
        assert_eq!(tiers.len(), 1, "同集合的三档必须合并");
        assert!((tiers[0].rho - 1.0).abs() < 1e-9);
    }

    /// 容量占比就是核数占比：2 小 + 6 大 → 25% / 75%
    #[test]
    fn rho_follows_core_count() {
        let mut a = CpuSet::new();
        a.set(0);
        a.set(1);
        let mut b = CpuSet::new();
        for c in 2..8 {
            b.set(c);
        }
        let mut topo = CpuTopology::empty();
        topo.all_tiers = vec![a, b];
        let tiers = build_tiers(&topo);
        if tiers.len() != 2 {
            return; // 容器里读不到 online 时退化，跳过
        }
        assert!((tiers[0].rho - 0.25).abs() < 1e-9, "{:?}", tiers);
        assert!((tiers[1].rho - 0.75).abs() < 1e-9);
    }

    /// 没开 cache 事件时不能把 miss 当 0：那会让 sens 恒为 1，
    /// 大 L2 层完全失去偏好
    #[test]
    fn missing_cache_event_uses_reference_rate() {
        let s = Sample {
            tid: 1,
            pkg: "com.a".into(),
            comm: "T".into(),
            inst: 100,
            cycles: 200,
            misses: None,
            cpu_ns: None,
            window_ms: 5_000,
        };
        let f = features(&[s]);
        assert!((f[0].1 - REF_MISS).abs() < 1e-9);
        assert!((f[0].0 - 1.0).abs() < 1e-9, "单线程占全部指令");
    }
}
