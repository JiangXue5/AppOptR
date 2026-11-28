//! λmod —— 基于拉格朗日乘子的绑核目标求解。
//!
//! 模型照搬 Aether_OptExt `src/lagrange.rs`（base `31a23c4`）：层 k 的容量
//! `rho_k` = 该层核数 / 总核数；线程 i 对层 k 的代价 `π_ik = λ_k · sens_ik`，
//! `sens = 1 + (insn_share · c_llc) / L2_k / (REF_MISS / REF_L2_KB)`；
//! 落层概率 `softmax(-π/T)`；每轮 `λ_k = max(0, λ_k + γ·η·(s_k - ρ_k))`，
//! γ 由拥塞度量（分配分布变化率 + 线程数变化率）经 EWMA 阻尼给出。
//!
//! ## 与上游的差异（只有三处，都是本仓库架构决定的）
//!
//! 1. **不自己开 perf fd**：样本由 `pmu.rs` 统一采集，本模块只消费 `Sample`。
//!    上游每线程 4 个 fd + 免 fd 预筛选 + fd 预算 + 空闲回收，那套逻辑在
//!    `pmu.rs` 里已经有一份，再搬一套等于每线程双份 fd。
//! 2. **不执行**：`policy::plan_entry` / `sched::decide` / `apply_affinity`
//!    一行都不读本模块。`tier_target` / `pick_tier` 按上游原样保留，等
//!    方案 16.4 的验收门槛过了再接。
//! 3. **`REF_MISS` 重标为 0.01**：上游 `c_llc` 是 LLC miss **率**（miss/访问），
//!    本仓库只有 `PERF_COUNT_HW_CACHE_MISSES / 指令数`，量级低一个数量级。
//!    公式不变，只换常数——否则 `sens` 恒 ≈1，大 L2 偏好整个失效。
//!
//! 另外保留两处上游没有的处理：层集合变化时重建 λ（热插拔后旧 λ 对应另一套
//! 约束）；相同核集的三档合并成一层（单层设备的 e/p/hp 全等，留三份会让 λ
//! 在三个同集层上互打）。
//!
//! 上游踩过的坑这里都继承：π 只保留随层变化的项（λ·sens），常数项因 softmax
//! 平移不变而零影响、却会无反馈漂移；`s` 按线程数占比而非指令量加权；λ 更新
//! 必须带 γ 阻尼，否则误差 26 时单步 Δλ≈21、两小时不收敛；`w = exp(-pi_lse)`
//! 的负号不能漏（漏了会 inf/NaN）；`tier_target` 的 min_cpus 只能向更高层并入，
//! 最高层不强扩（2 核性能簇扩到 6 核等于放弃绑定）。

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::arbiter::Hint;

use crate::cpuset::{CPU_SETSIZE, CpuSet, CpuTopology, cpu_capacity, online_cpus};
use crate::lock_ignore_poison;
use crate::pmu::Sample;

// ---- 代价模型常数（与上游 `lagrange.rs` 一致）----

const ETA_TIER: f64 = 0.1;
/// Λ 的归一化基准。上游取 0.05（LLC miss 率口径），本仓库口径见模块注释
const REF_MISS: f64 = 0.01;
const REF_L2_KB: f64 = 1024.0;
const TEMP: f64 = 0.1;
const FLOAT_EPS: f64 = 1e-12;
/// 单核 L2 未知时的估值
const DEFAULT_L2_KB: f64 = 512.0;
/// 最高频层的 L2 估值：上游只分两档，顶层给大值让 sens 形成正确偏好
const TOP_L2_KB: f64 = 1024.0;

// ---- 拥塞感知阻尼（抑制 λ 振荡）----
const CONGESTION_BETA: f64 = 1.0;
const V_FR_EWMA: f64 = 0.3;
const DZ_EWMA: f64 = 0.3;
const CONE_EWMA: f64 = 0.4;
const CONE_SCALE_MIN: f64 = 0.15;
const CONE_SCALE_MAX: f64 = 1.00;
const DZ_WEIGHT: f64 = 5.0;
/// 线程数变化在 dz 中的权重
const DN_WEIGHT: f64 = 1.0;

// ---- 本仓库自己的展示参数 ----
/// 面板与日志展示的线程数
const MAX_PICKS: usize = 8;

/// 一层核的静态属性。层序：e_core → p_core → hp_core（低性能在前）
#[derive(Clone, Debug)]
pub struct TierInfo {
    pub cpus: CpuSet,
    pub l2_kb: f64,
    /// 该层占总核数的比例，作为 λ 的容量约束
    pub rho: f64,
}

/// 跨周期的拥塞度量。signal 越大 → cone 越小 → γ 越小
#[derive(Default)]
struct Congestion {
    /// 权重的相对变化率 EWMA
    v_fr: f64,
    /// 约束量与线程数的变化 EWMA
    dz: f64,
    /// 拥塞缩放因子 EWMA
    cone: f64,
    /// 上轮的层分配分布，用于算 v_fr
    prev_tier: Vec<f64>,
    n: usize,
    init: bool,
}

/// 求解器。上游用 Atomic + DashMap 支持并行采样；这里样本是整窗一次给出、
/// 单线程消费，所以用普通可变状态，公式与迭代顺序一字不改
struct Lambda {
    tiers: Vec<TierInfo>,
    /// 每层的容量乘子
    lambda: Vec<f64>,
    gamma: f64,
    /// 累计推进轮数（展示用）
    rounds: u64,
    congestion: Congestion,
}

/// 一条线程的指纹。对应上游 `NodeData`：(c_llc, m_mem, insn_share)
#[derive(Clone)]
struct Feat {
    tid: i32,
    comm: String,
    c_llc: f64,
    m_mem: f64,
    insn_share: f64,
}

#[derive(Clone, Debug, Default)]
pub struct LambdaPlan {
    /// 状态：「未启用」/「层数不足」/「收敛中」/「已收敛」
    pub state: &'static str,
    pub tiers: Vec<TierInfo>,
    pub lambda: Vec<f64>,
    /// 模型给出的分配占比，与 `rho` 同量纲
    pub share: Vec<f64>,
    /// capacity 加权占比。与 `pmu_allocator` 的 want 同口径，
    /// 两者不一致是正常的：λmod 按核数均分，capacity 加权更偏性能核
    pub cap_share: Vec<f64>,
    /// max |share - rho| / rho
    pub err: f64,
    /// 当前学习率缩放（拥塞阻尼）
    pub gamma: f64,
    /// 累计推进轮数
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
            "{} 层 ｜ λ {} ｜ 分配 {sh}% → 容量 {rho}% ｜ 误差 {:.1}% ｜ γ {:.2} ｜ {}",
            self.tiers.len(),
            lam,
            self.err * 100.0,
            self.gamma,
            self.state
        )
    }
}

static LAMBDA: Mutex<Option<Lambda>> = Mutex::new(None);
static PLAN: Mutex<Option<LambdaPlan>> = Mutex::new(None);
/// tid → 该线程的建议层。面板只展示前 8 条，裁决层要查全部线程
static HINTS: Mutex<Option<HashMap<i32, Hint>>> = Mutex::new(None);
/// 每轮重新采样用的 salt，使时间平均收敛到 probs
static SALT: AtomicU64 = AtomicU64::new(0);

/// 关闭 PMU 或配额时清空：留着旧 λ 会在下次启用时从过期状态起步
pub fn clear() {
    *lock_ignore_poison(&LAMBDA) = None;
    *lock_ignore_poison(&PLAN) = None;
    *lock_ignore_poison(&HINTS) = None;
}

pub fn snapshot() -> Option<LambdaPlan> {
    lock_ignore_poison(&PLAN).clone()
}

/// 某条线程的建议层。无建议、或层数不足、或已清空时返回 None
pub fn hint(tid: i32) -> Option<Hint> {
    lock_ignore_poison(&HINTS)
        .as_ref()
        .and_then(|m| m.get(&tid).copied())
}

/// 每个 PMU 窗口调用一次。`samples` 必须是截断前的全量
pub fn update(samples: &[Sample], topo: &CpuTopology) {
    let tiers = build_tiers(topo);
    if tiers.len() < 2 {
        // 单层设备没有「分配到哪一层」可言。不要硬凑一个解出来
        *lock_ignore_poison(&LAMBDA) = None;
        *lock_ignore_poison(&HINTS) = None;
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

    let mut guard = lock_ignore_poison(&LAMBDA);
    if guard.as_ref().is_none_or(|l| !same_tiers(&l.tiers, &tiers)) {
        *guard = Some(Lambda {
            lambda: vec![1.0; tiers.len()],
            gamma: 1.0,
            rounds: 0,
            congestion: Congestion {
                cone: 1.0,
                ..Default::default()
            },
            tiers: tiers.clone(),
        });
    }
    let Some(lm) = guard.as_mut() else {
        return;
    };
    if samples.is_empty() {
        // 没有活跃线程：s 全 0，继续迭代会把 λ 推到 0（所有层都「空闲」），
        // 下次一有线程就全部涌向 L2 最大的层。保持上一窗口的 λ 不动
        return;
    }

    let feats = features(samples);
    if feats.is_empty() {
        // 全是空闲线程：与「没有活跃线程」同一处理，保持 λ 不动
        return;
    }
    let (_assign, s) = lm.solve(&feats);
    let err = lm.advance(&s, feats.len());

    // 最终 λ 下的每线程建议。展示用 argmax：pick_tier 每轮重采样会让同一
    // 线程在两轮之间跳层，面板上看着像统计坏了（上游只在真正绑核时才需要采样）
    let lambdas = lm.lambda.clone();
    let mut hints: HashMap<i32, Hint> = HashMap::with_capacity(feats.len());
    let mut picks: Vec<(String, i32, usize, f64)> = feats
        .iter()
        .map(|f| {
            let (_w, probs, _best) = lm.thread_w(&lambdas, f.c_llc, f.m_mem, f.insn_share);
            let (best, p) = argmax(&probs);
            // 裁决层要按 tid 查全部线程，面板只展示概率最高的几条
            hints.insert(
                f.tid,
                Hint {
                    cpus: lm.tiers[best].cpus,
                    err,
                },
            );
            (f.comm.clone(), f.tid, best, p)
        })
        .collect();
    picks.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
    picks.truncate(MAX_PICKS);

    let plan = LambdaPlan {
        state: if err <= crate::arbiter::CONVERGED_ERR {
            "已收敛"
        } else {
            "收敛中"
        },
        tiers: lm.tiers.clone(),
        lambda: lm.lambda.clone(),
        share: s,
        cap_share: cap_share(&lm.tiers),
        err,
        gamma: lm.gamma,
        rounds: lm.rounds,
        threads: feats.len(),
        picks,
    };
    drop(guard);
    *lock_ignore_poison(&HINTS) = Some(hints);
    *lock_ignore_poison(&PLAN) = Some(plan);
}

impl Lambda {
    fn m(&self) -> usize {
        self.tiers.len()
    }

    /// 各层的容量配额 = 该层核数占总核数的比例
    fn capacity(&self, r: usize) -> f64 {
        self.tiers.get(r).map(|t| t.rho).unwrap_or(0.0)
    }

    fn eta(&self, _r: usize) -> f64 {
        ETA_TIER
    }

    /// 迭代一次 λ。上游原式：`λ = max(0, λ + γ·η·err)`，没有单步限幅，
    /// 靠 γ 阻尼压过冲
    fn step_lambdas(&mut self, s: &[f64]) {
        let gamma = self.gamma;
        for r in 0..self.m() {
            let cap = self.capacity(r);
            let err = s[r] - cap;
            self.lambda[r] = (self.lambda[r] + gamma * self.eta(r) * err).max(0.0);
        }
    }

    /// 单线程：各层权重与最优层
    fn thread_w(
        &self,
        lambdas: &[f64],
        c_llc: f64,
        m_mem: f64,
        insn_share: f64,
    ) -> (f64, Vec<f64>, usize) {
        let k = self.tiers.len();
        let mut pi = Vec::with_capacity(k);
        // π 只保留「随层变化」的项。λ[0] + λ[1]·c_llc + λ[2]·m_mem 对所有层是
        // 同一个常数，而 softmax 具有平移不变性 —— 它们对层选择零影响，却因
        // 约束量 s 与层分配解耦而无反馈地单调漂移（实测 λ[1] 1h23min 从 0.002
        // 涨到 0.663 且无回落）。只有 λ[kk]·sens_kk 因 cap_kb 随层变化而真正驱动分配。
        let _ = m_mem;
        for (kk, t) in self.tiers.iter().enumerate() {
            let cap_kb = t.l2_kb.max(64.0);
            let pressure = (insn_share * c_llc) / cap_kb;
            let ref_pressure = REF_MISS / REF_L2_KB;
            let sens = (1.0 + pressure / ref_pressure).max(1.0);
            pi.push(lambdas[kk] * sens);
        }
        let min_pi = pi.iter().cloned().fold(f64::MAX, f64::min);
        let t_safe = TEMP.max(1e-6);
        let mut probs = Vec::with_capacity(k);
        let mut exp_sum = 0.0;
        let mut best_k = 0usize;
        let mut best_p = -1.0f64;
        for (kk, &p) in pi.iter().enumerate() {
            let e = (-(p - min_pi) / t_safe).exp();
            probs.push(e);
            exp_sum += e;
            if e > best_p {
                best_p = e;
                best_k = kk;
            }
        }
        for p in probs.iter_mut() {
            *p /= exp_sum;
        }
        // free energy：LSE 形式为 -T·ln(Σexp(-π/T))，其负值即 log-sum-exp 下界。
        // 权重取 w = exp(-pi_lse) —— 负号不可省：漏掉会写成 exp(+pi_lse)，
        // π 为大正数时指数爆炸，s[0]=Σw 发散并正反馈到 λ，最终 inf/NaN。
        let pi_lse = min_pi - t_safe * exp_sum.ln();
        let w = (-pi_lse).exp();
        (w, probs, best_k)
    }

    /// 全网求解：返回 (每 tid 的落层, 各约束累积量)
    /// 累积量按概率软累加 —— 与时间平均一致，硬取 argmax 表达不了 75/25
    fn solve(&self, feats: &[Feat]) -> (Vec<(i32, usize)>, Vec<f64>) {
        let k = self.tiers.len();
        let m = self.m();
        let lambdas = self.lambda.clone();
        let salt = SALT
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x2545F4914F6CDD1D);

        let mut s = vec![0.0f64; m];
        let mut assign = Vec::with_capacity(feats.len());
        for f in feats {
            let (_w, probs, _best) = self.thread_w(&lambdas, f.c_llc, f.m_mem, f.insn_share);
            // s[kk] 是各层的「线程数占比」，与 rho[k] 同量纲。
            // 它不能按指令量加权 —— cap 定义为核心数比例，按线程数配平才可收敛
            for kk in 0..k {
                s[kk] += probs[kk];
            }
            assign.push((f.tid, pick_tier(f.tid, &probs, salt)));
        }

        // 归一化为占比，消去线程数带来的线性增长（否则 s 随 N 线性增长，
        // 误差恒为正、λ 只能单调上升）
        let n = feats.len().max(1) as f64;
        for kk in 0..k {
            s[kk] /= n;
        }
        (assign, s)
    }

    /// 用 solve 的累积量推进 λ 与 gamma，返回最大相对误差
    fn advance(&mut self, s: &[f64], n_threads: usize) -> f64 {
        // 误差统计（先算，供 boost 使用）
        let mut max_rel = 0.0f64;
        for kk in 0..self.tiers.len() {
            let cap = self.capacity(kk).max(FLOAT_EPS);
            let rel = (s[kk] - cap).abs() / cap;
            if rel > max_rel {
                max_rel = rel;
            }
        }

        // 拥塞感知阻尼：系统变化剧烈时压低学习率。
        // 缺失时 γ 峰值达 8（误差 26 时单步 Δλ≈21）→ 必然过冲，
        // 表现为 λ 在约束间反复拉扯、长时间不收敛。
        let gamma = {
            let cg = &mut self.congestion;
            // v_fr：层分配分布的相对变化率（相邻周期 s 的归一化变化）
            let v_fr = if cg.prev_tier.len() == self.tiers.len() {
                let mut sq = 0.0f64;
                for kk in 0..self.tiers.len() {
                    let a = s[kk];
                    let b = cg.prev_tier[kk];
                    let avg = ((a + b) / 2.0).max(FLOAT_EPS);
                    let d = a - b;
                    sq += d * d / avg;
                }
                sq.sqrt()
            } else {
                0.0
            };
            cg.prev_tier = s.to_vec();
            // dz：约束量变化 + 线程数变化率
            let dn = if cg.init && cg.n > 0 {
                (n_threads as f64 - cg.n as f64).abs() / cg.n as f64
            } else {
                0.0
            };
            let dz = if cg.init { v_fr + DN_WEIGHT * dn } else { 0.0 };
            cg.n = n_threads;
            cg.init = true;

            cg.v_fr = (1.0 - V_FR_EWMA) * cg.v_fr + V_FR_EWMA * v_fr;
            cg.dz = (1.0 - DZ_EWMA) * cg.dz + DZ_EWMA * dz;

            let signal = cg.v_fr.max(cg.dz * DZ_WEIGHT);
            let cone_base =
                (1.0 / (1.0 + CONGESTION_BETA * signal)).clamp(CONE_SCALE_MIN, CONE_SCALE_MAX);
            cg.cone = (1.0 - CONE_EWMA) * cg.cone + CONE_EWMA * cone_base;

            // cone ≤ 1 起阻尼作用；boost 提供有限加速；总上限 2.0 防过冲
            let boost = 1.0 + max_rel.min(1.0);
            (cg.cone * boost).clamp(0.05, 2.0)
        };

        self.step_lambdas(s);
        self.gamma = gamma;
        self.rounds = self.rounds.saturating_add(1);
        max_rel
    }

    /// 层 → 绑核目标。
    /// 防护：按在线核裁剪；核数不足 min_cpus 时并入更高层（不越过目标层向上扩）
    #[allow(dead_code)]
    fn tier_target(&self, tier: usize, topo: &CpuTopology, min_cpus: usize) -> CpuSet {
        let online = online_cpus().unwrap_or(topo.present_cpus);
        let mut out = self.tiers.get(tier).map(|t| t.cpus).unwrap_or_default();
        out.and(&online);
        // 仅当存在更高层可并入时才做 min_cpus 扩容。
        // 最高性能层通常只有 2 核（如 2+2+4 的 6-7、6+2 的 6-7），若强扩到
        // min_cpus 会并成全核，等于放弃绑定；且该层是性能核，2 核本身合理。
        let is_top = tier + 1 >= self.tiers.len();
        if !is_top {
            let mut idx = tier;
            while out.count() < min_cpus && idx + 1 < self.tiers.len() {
                idx += 1;
                let mut up = self.tiers[idx].cpus;
                up.and(&online);
                out.or(&up);
            }
            if out.count() < min_cpus {
                out.or(&online);
            }
        }
        out.and(&online);
        out
    }
}

/// 按 probs 随机选层（Monte Carlo）。
/// 硬 argmax 只能整层选一个，无法表达 rho=0.75/0.25 这类中间分布，
/// 会导致 λ 在两极间过冲震荡；按概率采样则时间平均等于 probs，可收敛。
/// 用 tid + salt 派生的 splitmix 序列，避免引入额外随机数依赖。
#[allow(dead_code)]
fn pick_tier(tid: i32, probs: &[f64], salt: u64) -> usize {
    if probs.is_empty() {
        return 0;
    }
    let mut x = (tid as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(salt);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    let r = (x >> 11) as f64 / ((1u64 << 53) as f64);
    let mut acc = 0.0;
    for (i, p) in probs.iter().enumerate() {
        acc += p;
        if r < acc {
            return i;
        }
    }
    probs.len() - 1
}

fn argmax(probs: &[f64]) -> (usize, f64) {
    probs.iter().enumerate().fold(
        (0usize, -1.0f64),
        |(bi, bp), (i, &v)| {
            if v > bp { (i, v) } else { (bi, bp) }
        },
    )
}

/// 层集合完全一致才复用旧 λ。热插拔/换设备后层数或边界会变，
/// 旧 λ 对应的是另一套约束，接着用等于从一个错误的起点开始
fn same_tiers(a: &[TierInfo], b: &[TierInfo]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.cpus == y.cpus)
}

/// 按实测拓扑构造层。在线核裁剪后为空的层直接丢掉（整层热下线），
/// 相同核集只留一份（单层设备的 e/p/hp 三档全等，留三份会让 λ 互相对打）
fn build_tiers(topo: &CpuTopology) -> Vec<TierInfo> {
    let online = online_cpus().unwrap_or(topo.present_cpus);
    let src: Vec<CpuSet> = if topo.all_tiers.is_empty() {
        vec![topo.e_core, topo.p_core, topo.hp_core]
    } else {
        topo.all_tiers.clone()
    };
    let mut raw: Vec<CpuSet> = Vec::new();
    for set in &src {
        let mut c = *set;
        c.and(&online);
        if c.count() == 0 || raw.contains(&c) {
            continue;
        }
        raw.push(c);
    }
    if raw.len() < 2 {
        // 单层设备：L2 不再分档，直接给默认值，保持 rho=1
        return raw
            .into_iter()
            .map(|cpus| TierInfo {
                rho: 1.0,
                l2_kb: DEFAULT_L2_KB,
                cpus,
            })
            .collect();
    }
    let total: f64 = raw.iter().map(|c| c.count() as f64).sum();
    if total <= 0.0 {
        return Vec::new();
    }
    let last = raw.len() - 1;
    raw.into_iter()
        .enumerate()
        .map(|(i, cpus)| TierInfo {
            // 上游只分两档：顶层 1024，其余 512。层数已经过在线裁剪与合并，
            // 用裁剪后的下标判顶层，避免顶层整层下线时没人拿到大 L2
            l2_kb: if i == last { TOP_L2_KB } else { DEFAULT_L2_KB },
            rho: cpus.count() as f64 / total,
            cpus,
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

fn cap_share(tiers: &[TierInfo]) -> Vec<f64> {
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

/// 每条线程的指纹，字段与上游 `Handles::sample` 同口径：
/// `c_llc` = 每指令 cache miss 数（上游为 LLC miss 率），`m_mem` = miss 率 × CPI。
///
/// 软件计时模式下 `inst` 恒为 0，用 CPU 时间占比替 insn_share；两者都没有时
/// 均分——均分等于「这轮看不出谁更重」，比全部算成 0 好（0 会让 sens 项失效）
fn features(samples: &[Sample]) -> Vec<Feat> {
    let total_inst: u64 = samples.iter().map(|s| s.inst).sum();
    let total_ns: u64 = samples.iter().filter_map(|s| s.cpu_ns).sum();
    // 整轮没有指令增量的线程不参与分配：上游在 `sample_tids` 里就用
    // `/proc/{tid}/stat` 的 tick 增量把它们筛掉了（903 个持句柄线程里只有
    // 56 个有增量）。按「均分」算进来会让空闲线程也占一份配额，把重线程
    // 挤到小核去
    let active: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.inst > 0 || s.cpu_ns.unwrap_or(0) > 0)
        .collect();
    let n = active.len().max(1) as f64;
    active
        .into_iter()
        .map(|s| {
            let insn_share = if total_inst > 0 {
                s.inst as f64 / total_inst as f64
            } else if total_ns > 0 {
                s.cpu_ns.unwrap_or(0) as f64 / total_ns as f64
            } else {
                1.0 / n
            };
            // 设备不提供 cache-misses 时用参考值：sens 项退化成只随指令份额
            // 变化，仍然是「重线程更倾向大 L2 层」，只是少了访存强度的区分
            let c_llc = match s.misses {
                Some(m) if s.inst > 0 => (m as f64 / s.inst as f64).clamp(0.001, 1.0),
                _ => REF_MISS,
            };
            let cpi = if s.inst > 0 {
                (s.cycles as f64 / s.inst as f64).max(0.1)
            } else {
                1.0
            };
            Feat {
                tid: s.tid,
                comm: s.comm.clone(),
                c_llc,
                m_mem: (c_llc * cpi).max(0.001),
                insn_share,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(cpus: &[usize], l2: f64, rho: f64) -> TierInfo {
        let mut s = CpuSet::new();
        for &c in cpus {
            s.set(c);
        }
        TierInfo {
            cpus: s,
            l2_kb: l2,
            rho,
        }
    }

    fn solver(tiers: Vec<TierInfo>) -> Lambda {
        Lambda {
            lambda: vec![1.0; tiers.len()],
            gamma: 1.0,
            rounds: 0,
            congestion: Congestion {
                cone: 1.0,
                ..Default::default()
            },
            tiers,
        }
    }

    fn share_of(lm: &Lambda, feats: &[Feat]) -> Vec<f64> {
        let mut share = vec![0.0; lm.m()];
        for f in feats {
            let (_w, probs, _b) = lm.thread_w(&lm.lambda, f.c_llc, f.m_mem, f.insn_share);
            for k in 0..lm.m() {
                share[k] += probs[k];
            }
        }
        share.iter_mut().for_each(|v| *v /= feats.len() as f64);
        share
    }

    fn feat(insn_share: f64, miss: f64) -> Feat {
        Feat {
            tid: 1,
            comm: "T".into(),
            c_llc: miss,
            m_mem: miss * 2.0,
            insn_share,
        }
    }

    /// 概率归一化；λ 相同的两层、相同 sens 时应当各占一半
    #[test]
    fn probs_are_normalised() {
        let lm = solver(vec![tier(&[0, 1], 256.0, 0.5), tier(&[2, 3], 256.0, 0.5)]);
        let (_w, p, _b) = lm.thread_w(&lm.lambda, 0.05, 0.1, 0.1);
        assert!((p.iter().sum::<f64>() - 1.0).abs() < 1e-9);
        assert!((p[0] - 0.5).abs() < 1e-9, "同价同容量应各半：{p:?}");
    }

    /// λ 涨一层，该层概率必须降：这是对偶上升能起作用的唯一前提
    #[test]
    fn higher_lambda_lowers_probability() {
        let mut lm = solver(vec![tier(&[0, 1], 256.0, 0.5), tier(&[2, 3], 256.0, 0.5)]);
        lm.lambda[1] = 4.0;
        let (_w, p, _b) = lm.thread_w(&lm.lambda, 0.05, 0.1, 0.1);
        assert!(p[1] < p[0], "λ 大的层概率必须更低：{p:?}");
    }

    /// L2 更大的层对同一线程更便宜：sens 小 → π 小 → 概率高。
    /// 这条要是反了，重线程会被赶到小核去
    #[test]
    fn bigger_l2_attracts_load() {
        let lm = solver(vec![tier(&[0, 1], 256.0, 0.5), tier(&[2, 3], 1024.0, 0.5)]);
        let (_w, p, _b) = lm.thread_w(&lm.lambda, 0.1, 0.1, 0.2);
        assert!(p[1] > p[0], "大 L2 层应更受偏好：{p:?}");
    }

    /// 迭代方向：初始 λ 全 1 时，容量大的一层会先被挤爆（s > rho），
    /// λ 随之上升，最终把分配压回 rho 附近
    #[test]
    fn iteration_pushes_share_back_to_capacity() {
        let mut lm = solver(vec![
            tier(&[0, 1], 512.0, 0.25),
            tier(&[2, 3, 4, 5, 6, 7], 1024.0, 0.75),
        ]);
        let feats = vec![feat(0.1, 0.05); 10];
        for _ in 0..400 {
            let share = share_of(&lm, &feats);
            lm.advance(&share, feats.len());
        }
        let share = share_of(&lm, &feats);
        for (k, t) in lm.tiers.iter().enumerate() {
            assert!(
                (share[k] - t.rho).abs() < 0.05,
                "第 {k} 层应回到 rho={:.2}，实得 {:.3}（λ={:?}）",
                t.rho,
                share[k],
                lm.lambda
            );
        }
    }

    /// 拥塞阻尼必须真的起作用：分配分布连续剧变时 γ 要降到 1 以下，
    /// 否则就是上游那个「误差 26 单步 Δλ≈21」的过冲老路
    #[test]
    fn congestion_damps_gamma() {
        let mut lm = solver(vec![
            tier(&[0, 1], 512.0, 0.25),
            tier(&[2, 3, 4, 5], 1024.0, 0.75),
        ]);
        // 交替两极分布：v_fr 很大
        for i in 0..8 {
            let s = if i % 2 == 0 {
                vec![0.9, 0.1]
            } else {
                vec![0.1, 0.9]
            };
            lm.advance(&s, 20);
        }
        assert!(lm.gamma < 1.0, "剧变时 γ 应被压低，实得 {}", lm.gamma);
    }

    /// 分布稳定时 γ 应回到 1 附近，不能一直压着不收敛
    #[test]
    fn steady_state_restores_gamma() {
        let mut lm = solver(vec![
            tier(&[0, 1], 512.0, 0.25),
            tier(&[2, 3, 4, 5], 1024.0, 0.75),
        ]);
        for _ in 0..40 {
            lm.advance(&[0.25, 0.75], 20);
        }
        assert!(lm.gamma > 0.9, "稳定后 γ 应恢复，实得 {}", lm.gamma);
    }

    /// 按概率采样的长期分布必须等于 probs，否则执行时分配会系统性偏斜
    #[test]
    fn pick_tier_follows_probabilities() {
        let probs = [0.75, 0.25];
        let mut hit = [0usize; 2];
        let salt = 0x1234_5678_9ABC_DEF0u64;
        for tid in 0..4000 {
            hit[pick_tier(tid, &probs, salt.wrapping_add(tid as u64))] += 1;
        }
        let p0 = hit[0] as f64 / 4000.0;
        assert!((p0 - 0.75).abs() < 0.03, "采样分布应逼近 probs：{p0}");
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

    /// 顶层 L2 给大值、其余同值：sens 才能对高性能层形成偏好
    #[test]
    fn top_tier_gets_larger_l2() {
        let mut a = CpuSet::new();
        for c in 0..4 {
            a.set(c);
        }
        let mut b = CpuSet::new();
        for c in 4..6 {
            b.set(c);
        }
        let mut topo = CpuTopology::empty();
        topo.all_tiers = vec![a, b];
        let tiers = build_tiers(&topo);
        if tiers.len() != 2 {
            return;
        }
        assert_eq!(tiers[0].l2_kb, DEFAULT_L2_KB);
        assert_eq!(tiers[1].l2_kb, TOP_L2_KB);
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
        assert!((f[0].c_llc - REF_MISS).abs() < 1e-9);
        assert!((f[0].insn_share - 1.0).abs() < 1e-9, "单线程占全部指令");
        assert!((f[0].m_mem - REF_MISS * 2.0).abs() < 1e-9, "CPI=2");
    }

    /// min_cpus 扩容只能向更高层并入；最高层不强扩（强扩等于放弃绑定）
    #[test]
    fn tier_target_merges_upward_but_not_top() {
        let mut a = CpuSet::new();
        a.set(0);
        let mut b = CpuSet::new();
        b.set(1);
        b.set(2);
        let topo = {
            let mut t = CpuTopology::empty();
            t.all_tiers = vec![a, b];
            t.present_cpus = {
                let mut all = CpuSet::new();
                all.set(0);
                all.set(1);
                all.set(2);
                all
            };
            t
        };
        let tiers = build_tiers(&topo);
        if tiers.len() != 2 {
            return;
        }
        let lm = solver(tiers);
        // 底层只有 1 核，要求 2 核 → 并入上一层
        let t0 = lm.tier_target(0, &topo, 2);
        assert_eq!(t0.count(), 3, "小层应并入上一层直到够数");
        // 顶层保持原样，不被扩到全核
        let t1 = lm.tier_target(1, &topo, 2);
        assert_eq!(t1.count(), 2, "最高层不参与 min_cpus 扩容");
    }
}
