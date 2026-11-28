//! 综合裁决层：一条线程本轮的亲和性目标，到底听谁的。
//!
//! ## 为什么需要它
//!
//! λmod 与 S7 回答的是同一个问题（「这条线程该落在哪个核上」），但两套模型
//! 互不知情。只要两边都能写，就会有三类冲突：
//!
//! 1. **双执行器**：S7 每秒最多迁 1 个、单线程 90 秒反悔冷却、180 秒 3 次预算；
//!    λmod 每窗口按概率重新采样，同一线程会被两边各迁一次，冷却与预算都拦不住。
//! 2. **越界**：S7 只在规则允许集合**内部**换簇；λmod 的 `tier_target` 给的是
//!    整层核，直接写会把线程抬到用户规则之外。
//! 3. **边界被覆盖**：降档线程被 λmod 拽回大核，下一轮再降回来，两周期一抖；
//!    RT 线程（`SCHED_RR`）被迁走会丢缓存并和渲染抢核，延迟直接体现在帧上。
//!
//! ## 裁决顺序（定案）
//!
//! ```text
//! RT 屏蔽（λmod 与 S7 都不动）
//!   → 后台降档（用户显式约束，赢过一切自动策略）
//!   → S7 落点（已有冷却/预算/配额，先到先得）
//!   → λmod 层（无落点 + 已收敛 + 提示层 ⊆ 规则集合 + 线程可迁 + 冷却通过）
//!   → 规则值
//! ```
//!
//! 判据都放在这个纯函数里，`policy::plan` 只负责把选中的集合换算成「这台机器
//! 做得到的集合」。这样「为什么这条线程没听 λmod 的」只有一处答案。
//!
//! ## 执行闸门
//!
//! `Context::apply` 默认 false：λmod 的方案 16.4 验收（3 游戏 × 2 拓扑 ×
//! 重复测试 × 9 指标）还没过，裁决照跑但**不采纳** λmod 的结论。否决原因逐条
//! 计数，面板上能看到「本该采纳多少次、被谁否决多少次」——这就是冲突的量化，
//! 而不是等它偷偷改绑核之后才从帧时间上反推。

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::cpuset::CpuSet;
use crate::lock_ignore_poison;

/// 收敛阈值：分配占比回到容量的最大相对误差。
/// λmod 用它判「已收敛」，裁决层用它判「能不能采纳」——必须是同一个数，
/// 否则面板显示「已收敛」而裁决层仍认为没收敛
pub const CONVERGED_ERR: f64 = 0.08;

/// λmod 对同一条线程两次落层之间的最小间隔。比 S7 的 10 秒冷却长得多：
/// λmod 一窗 5 秒、分配占比在 rho 附近小幅摆动，边界上的线程会来回跳层
pub const LAMBDA_COOLDOWN: Duration = Duration::from_secs(60);
/// 冷却表上限。超过就整体清空——线程退出后条目不会自己消失，
/// 而这张表只是「最近迁过谁」，清空的代价是多迁一次
const MAX_TRACKED: usize = 512;

/// 最终目标由谁决定
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Owner {
    Rule,
    S7,
    Lambda,
    Demote,
}

impl Owner {
    fn idx(self) -> usize {
        match self {
            Owner::Rule => 0,
            Owner::S7 => 1,
            Owner::Lambda => 2,
            Owner::Demote => 3,
        }
    }
}

/// λmod 没被采纳的原因
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Veto {
    /// 执行闸门未开（验收未过，默认态）
    Disabled,
    /// RT 线程：迁走会丢缓存并与渲染抢核
    Rt,
    /// 角色不可迁（Critical / Latency / Unknown）
    NotMovable,
    /// 模型还没收敛，此时的分层是中间态
    NotConverged,
    /// 提示层不完全落在规则允许集合内
    OutsideRule,
    /// 该线程还在冷却里
    Cooling,
    /// 已有 S7 落点，先到先得
    S7Landed,
    /// 已被降档，用户约束优先
    Demoted,
}

impl Veto {
    pub fn label(self) -> &'static str {
        match self {
            Veto::Disabled => "闸门未开",
            Veto::Rt => "RT 线程",
            Veto::NotMovable => "角色不可迁",
            Veto::NotConverged => "未收敛",
            Veto::OutsideRule => "超出规则集合",
            Veto::Cooling => "冷却中",
            Veto::S7Landed => "S7 已有落点",
            Veto::Demoted => "已降档",
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

/// λmod 对一条线程的建议：该落哪一层（整层核集）与置信度
#[derive(Clone, Copy, Debug)]
pub struct Hint {
    pub cpus: CpuSet,
    /// 当前模型的分配误差，裁决层据此判断「收敛没收敛」
    pub err: f64,
}

pub struct Context<'a> {
    /// 规则给的原集合（用户意图的边界）
    pub rule: &'a CpuSet,
    /// 已按交集算好的降档集合
    pub demoted: Option<&'a CpuSet>,
    /// 仍然有效的 S7 落点（必须是规则子集）
    pub s7: Option<&'a CpuSet>,
    pub hint: Option<&'a Hint>,
    /// 线程已被 RT 提升
    pub rt: bool,
    /// 角色是否允许自动迁移（`Role::movable`）
    pub movable: bool,
    /// λmod 执行闸门
    pub apply: bool,
    /// 该线程本轮是否已过 λmod 冷却
    pub cooling_ok: bool,
    /// 收敛阈值
    pub err_ok: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct Verdict {
    pub owner: Owner,
    pub cpus: CpuSet,
    pub why: &'static str,
    /// λmod 有建议但没被采纳时的原因
    pub veto: Option<Veto>,
}

/// 裁决：纯函数，同样的输入永远给同样的结论
pub fn arbitrate(ctx: &Context) -> Verdict {
    // 1. 降档：用户对前后台的显式约束，赢过一切自动策略
    if let Some(d) = ctx.demoted {
        let veto = ctx.hint.map(|_| Veto::Demoted);
        count_owner(Owner::Demote);
        count_veto(veto);
        return Verdict {
            owner: Owner::Demote,
            cpus: *d,
            why: "前后台降档",
            veto,
        };
    }

    // 2. RT：λmod 与 S7 都不碰。S7 侧的筛选在 `sched::decide` 里，
    //    这里只负责把 λmod 挡在门外——RT 线程迁走，帧时间立刻能看出来
    if ctx.rt {
        let veto = ctx.hint.map(|_| Veto::Rt);
        count_owner(Owner::Rule);
        count_veto(veto);
        return Verdict {
            owner: Owner::Rule,
            cpus: *ctx.rule,
            why: "RT 线程不参与自动迁移",
            veto,
        };
    }

    // 3. S7 落点：它已经过驻留、冷却、配额、预算四道闸，而且只在允许集合
    //    内部挑簇。λmod 再抢一次就是两个执行器轮流改写同一条线程
    if let Some(s) = ctx.s7.filter(|s| s.count() > 0 && s.subset_of(ctx.rule)) {
        let veto = ctx.hint.map(|_| Veto::S7Landed);
        count_owner(Owner::S7);
        count_veto(veto);
        return Verdict {
            owner: Owner::S7,
            cpus: *s,
            why: "S7 落点维持",
            veto,
        };
    }

    // 4. λmod：只有全部前置条件成立才采纳
    if let Some(h) = ctx.hint {
        if let Some(veto) = lambda_veto(ctx, h) {
            count_owner(Owner::Rule);
            count_veto(Some(veto));
            return Verdict {
                owner: Owner::Rule,
                cpus: *ctx.rule,
                why: veto.label(),
                veto: Some(veto),
            };
        }
        count_owner(Owner::Lambda);
        return Verdict {
            owner: Owner::Lambda,
            cpus: h.cpus,
            why: "λmod 层配额",
            veto: None,
        };
    }

    // 5. 没有任何动态建议：规则原值
    count_owner(Owner::Rule);
    Verdict {
        owner: Owner::Rule,
        cpus: *ctx.rule,
        why: "规则原值",
        veto: None,
    }
}

fn lambda_veto(ctx: &Context, h: &Hint) -> Option<Veto> {
    // 顺序有讲究：先判「这条线程本来就不该动」，最后才判闸门。
    // 反过来的话，默认关闭时所有线程都记成「闸门未开」，真正有信号的
    // 越界/未收敛比例会被这个常数淹没
    if !ctx.movable {
        return Some(Veto::NotMovable);
    }
    if h.err > ctx.err_ok {
        return Some(Veto::NotConverged);
    }
    // 整层核集必须完整落在规则集合内：只取交集等于把「层」改成了「层的一部
    // 分」，λ 的容量约束跟着失真；直接写整层又越过了用户的规则
    if h.cpus.count() == 0 || !h.cpus.subset_of(ctx.rule) {
        return Some(Veto::OutsideRule);
    }
    if !ctx.cooling_ok {
        return Some(Veto::Cooling);
    }
    if !ctx.apply {
        return Some(Veto::Disabled);
    }
    None
}

// ---- 冷却表：只记「最近由 λmod 迁过谁」----

static GATE: Mutex<Option<HashMap<i32, Instant>>> = Mutex::new(None);

/// 这条线程此刻能不能被 λmod 迁
pub fn cooling_ok(tid: i32, now: Instant) -> bool {
    let guard = lock_ignore_poison(&GATE);
    match guard.as_ref().and_then(|m| m.get(&tid)) {
        Some(t) => now.duration_since(*t) >= LAMBDA_COOLDOWN,
        None => true,
    }
}

/// λmod 的迁移真的写下去了：开始计时
pub fn note_applied(tid: i32, now: Instant) {
    let mut guard = lock_ignore_poison(&GATE);
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_TRACKED {
        map.clear();
    }
    map.insert(tid, now);
}

pub fn clear() {
    *lock_ignore_poison(&GATE) = None;
}

// ---- 统计：让「冲突有多大」可量化 ----

static OWNERS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static VETOES: [AtomicU64; 8] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

fn count_owner(o: Owner) {
    OWNERS[o.idx()].fetch_add(1, Ordering::Relaxed);
}

fn count_veto(v: Option<Veto>) {
    if let Some(v) = v {
        VETOES[v.idx()].fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub rule: u64,
    pub s7: u64,
    pub lambda: u64,
    pub demote: u64,
    /// 被否决的 λmod 建议总数
    pub vetoed: u64,
    pub disabled: u64,
    pub rt: u64,
    pub not_movable: u64,
    pub not_converged: u64,
    pub outside_rule: u64,
    pub cooling: u64,
    pub s7_landed: u64,
    pub demoted: u64,
}

pub fn stats() -> Stats {
    let o = |i: usize| OWNERS[i].load(Ordering::Relaxed);
    let v = |i: usize| VETOES[i].load(Ordering::Relaxed);
    let vetoed: u64 = (0..8).map(v).sum();
    Stats {
        rule: o(0),
        s7: o(1),
        lambda: o(2),
        demote: o(3),
        vetoed,
        disabled: v(0),
        rt: v(1),
        not_movable: v(2),
        not_converged: v(3),
        outside_rule: v(4),
        cooling: v(5),
        s7_landed: v(6),
        demoted: v(7),
    }
}

/// 一行摘要。只列非零项，否则默认配置下会是一串 0
pub fn summary() -> String {
    let s = stats();
    let total = s.rule + s.s7 + s.lambda + s.demote;
    let mut out = format!(
        "裁决 {total}：规则 {} / S7 {} / λmod {} / 降档 {}",
        s.rule, s.s7, s.lambda, s.demote
    );
    if s.vetoed > 0 {
        let mut parts: Vec<String> = Vec::new();
        for (n, v) in [
            (s.disabled, "闸门未开"),
            (s.not_converged, "未收敛"),
            (s.outside_rule, "越界"),
            (s.not_movable, "角色"),
            (s.rt, "RT"),
            (s.s7_landed, "S7 先到"),
            (s.cooling, "冷却"),
            (s.demoted, "降档"),
        ] {
            if n > 0 {
                parts.push(format!("{v} {n}"));
            }
        }
        out.push_str(&format!("；λmod 否决 {}（{}）", s.vetoed, parts.join("、")));
    }
    out
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

    fn base_ctx<'a>(rule: &'a CpuSet, hint: &'a Hint) -> Context<'a> {
        Context {
            rule,
            demoted: None,
            s7: None,
            hint: Some(hint),
            rt: false,
            movable: true,
            apply: true,
            cooling_ok: true,
            err_ok: 0.08,
        }
    }

    fn hint(cpus: CpuSet, err: f64) -> Hint {
        Hint { cpus, err }
    }

    /// 全部条件成立时 λmod 才能赢过规则值
    #[test]
    fn lambda_wins_when_every_gate_is_open() {
        let rule = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let h = hint(set(&[4, 5, 6, 7]), 0.02);
        let v = arbitrate(&base_ctx(&rule, &h));
        assert_eq!(v.owner, Owner::Lambda);
        assert_eq!(v.cpus, set(&[4, 5, 6, 7]));
        assert!(v.veto.is_none());
    }

    /// 执行闸门默认关：结论退回规则值，但要记「本该采纳」
    #[test]
    fn disabled_gate_falls_back_to_rule() {
        let rule = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let h = hint(set(&[4, 5, 6, 7]), 0.02);
        let mut ctx = base_ctx(&rule, &h);
        ctx.apply = false;
        let v = arbitrate(&ctx);
        assert_eq!(v.owner, Owner::Rule);
        assert_eq!(v.veto, Some(Veto::Disabled));
    }

    /// RT 线程一律不动：这是延迟敏感路径，迁一次就是一次丢缓存
    #[test]
    fn rt_thread_is_never_moved() {
        let rule = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let h = hint(set(&[4, 5, 6, 7]), 0.02);
        let mut ctx = base_ctx(&rule, &h);
        ctx.rt = true;
        let v = arbitrate(&ctx);
        assert_eq!(v.owner, Owner::Rule);
        assert_eq!(v.veto, Some(Veto::Rt));
    }

    /// 降档赢过 λmod：否则「降到小核 → 被拉回大核 → 再降」两轮一抖
    #[test]
    fn demote_wins_over_lambda() {
        let rule = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let h = hint(set(&[4, 5, 6, 7]), 0.02);
        let floor = set(&[0, 1, 2, 3]);
        let mut ctx = base_ctx(&rule, &h);
        ctx.demoted = Some(&floor);
        let v = arbitrate(&ctx);
        assert_eq!(v.owner, Owner::Demote);
        assert_eq!(v.cpus, floor);
        assert_eq!(v.veto, Some(Veto::Demoted));
    }

    /// S7 落点先到先得：它已经过冷却与预算，λmod 再抢就是双执行器
    #[test]
    fn s7_landing_beats_lambda() {
        let rule = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let h = hint(set(&[4, 5, 6, 7]), 0.02);
        let landing = set(&[0, 1]);
        let mut ctx = base_ctx(&rule, &h);
        ctx.s7 = Some(&landing);
        let v = arbitrate(&ctx);
        assert_eq!(v.owner, Owner::S7);
        assert_eq!(v.cpus, landing);
        assert_eq!(v.veto, Some(Veto::S7Landed));
    }

    /// 落点越界（规则改小后残留）不算数，交回下面的候选
    #[test]
    fn out_of_rule_landing_is_ignored() {
        let rule = set(&[0, 1, 2, 3]);
        let h = hint(set(&[0, 1]), 0.02);
        let landing = set(&[6, 7]);
        let mut ctx = base_ctx(&rule, &h);
        ctx.s7 = Some(&landing);
        let v = arbitrate(&ctx);
        assert_eq!(v.owner, Owner::Lambda);
    }

    /// 提示层必须完整落在规则集合内：写整层会越过用户规则
    #[test]
    fn lambda_outside_rule_is_vetoed() {
        let rule = set(&[0, 1, 2, 3]);
        let h = hint(set(&[4, 5, 6, 7]), 0.02);
        let v = arbitrate(&base_ctx(&rule, &h));
        assert_eq!(v.owner, Owner::Rule);
        assert_eq!(v.veto, Some(Veto::OutsideRule));
    }

    /// 未收敛时不给结论：中间态的分配占比只是过程值
    #[test]
    fn not_converged_is_vetoed() {
        let rule = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let h = hint(set(&[4, 5, 6, 7]), 0.30);
        let v = arbitrate(&base_ctx(&rule, &h));
        assert_eq!(v.owner, Owner::Rule);
        assert_eq!(v.veto, Some(Veto::NotConverged));
    }

    /// 角色不可迁（Critical/Latency/Unknown）时不考虑 λmod
    #[test]
    fn immovable_role_is_vetoed() {
        let rule = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let h = hint(set(&[4, 5, 6, 7]), 0.02);
        let mut ctx = base_ctx(&rule, &h);
        ctx.movable = false;
        assert_eq!(arbitrate(&ctx).veto, Some(Veto::NotMovable));
    }

    /// 冷却内不重复迁
    #[test]
    fn cooling_blocks_lambda() {
        let rule = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let h = hint(set(&[4, 5, 6, 7]), 0.02);
        let mut ctx = base_ctx(&rule, &h);
        ctx.cooling_ok = false;
        assert_eq!(arbitrate(&ctx).veto, Some(Veto::Cooling));
    }

    /// 没有建议时就是规则值，不能凭空造一个 owner
    #[test]
    fn no_hint_means_rule() {
        let rule = set(&[0, 1, 2, 3]);
        let ctx = Context {
            rule: &rule,
            demoted: None,
            s7: None,
            hint: None,
            rt: false,
            movable: true,
            apply: true,
            cooling_ok: true,
            err_ok: 0.08,
        };
        let v = arbitrate(&ctx);
        assert_eq!(v.owner, Owner::Rule);
        assert!(v.veto.is_none());
    }

    /// 冷却表按线程隔离，且到期自动放行
    #[test]
    fn cooldown_expires_per_thread() {
        let now = Instant::now();
        clear();
        note_applied(101, now);
        assert!(!cooling_ok(101, now + Duration::from_secs(5)));
        assert!(cooling_ok(101, now + LAMBDA_COOLDOWN));
        assert!(cooling_ok(102, now), "别的线程不受影响");
        clear();
    }
}
