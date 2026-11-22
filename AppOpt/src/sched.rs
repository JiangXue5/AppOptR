//! S7 负载感知分配：采样、判定与受限让位。
//!
//! 设计见 `docs/S7_负载感知调度策略设计.md`。三档模式：
//!
//! - `off`（默认）：`tick` 立即返回，不读 `/proc/stat`、不产生系统调用。
//! - `shadow`：照常采样与判定，只把「本可迁移」记进计数与环形缓冲，不改亲和性，
//!   也**不产出** `Move`——决策层就把它截断，不依赖执行层再拦一次。
//! - `on`：返回候选 `Move`，但状态只在 `settle` 收到 `AffinityOutcome::Set`
//!   之后才提交，失败不会伪造 `moved` 与落点。
//!
//! 边界：只在规则给出的允许集合**内部**换簇，不扩大集合；只动 `Worker` / `Background`；
//! 不写 cpuset 目录；采样依附主循环，不新增线程。

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::apply_affinity::AffinityOutcome;
use crate::cache::ProcCache;
use crate::config::{AppConfig, SchedMode};
use crate::cpuset::{CpuSet, CpuTopology};
use crate::diag;
use crate::lock_ignore_poison;
use crate::roles::role_of;
use crate::rule_match::thread_affinity;

/// 采样周期。与 eBPF 主循环的 `recv_timeout(1s)` 同源
const SAMPLE_PERIOD: Duration = Duration::from_secs(1);
/// 同一方向连续确认次数，抑制单次采样抖动
const CONFIRM_TICKS: u8 = 3;
/// 线程进入候选池后的最小观察时间。刚创建的线程还在冷启动，
/// 立刻迁移只会把它的初始化代码从缓存里赶走
const MIN_DWELL: Duration = Duration::from_secs(5);
/// 同一线程两次迁移之间的冷却
const COOLDOWN: Duration = Duration::from_secs(10);
/// 目标簇相对基准的负载差门槛，千分比（15 个百分点）
const LOAD_GAP: i32 = 150;
/// 单轮迁移上限。每秒最多迁一个：跨簇迁移必然丢缓存，
/// 一次迁两个会让整帧的调度抖动叠加
const MAX_MOVES: usize = 1;
/// 单轮最多检查的线程数，超出部分由游标轮转覆盖
const MAX_PROBE: usize = 64;
/// 活跃判定最多读取的进程数，避免一次 tick 打爆 /proc
const MAX_ACTIVE_PIDS: usize = 8;
/// 决策环形缓冲保留条数
const RING_CAP: usize = 8;
/// 目标集合最小核数。1 核簇（常见于单超大核机型）也允许进入，
/// 但配额单独收紧：单核簇最多放 1 个被迁线程
const MIN_TARGET_CORES: usize = 1;
/// 反悔冷却：刚从某簇迁出，60 秒内不再迁回去。1 核目标簇负载会被
/// 单个线程瞬间打满，没有这道闸就会出现 p ↔ hp 每 10 秒来回跳
const REVERSE_COOLDOWN: Duration = Duration::from_secs(90);
/// 单线程迁移预算窗口
const MOVE_WINDOW: Duration = Duration::from_secs(180);
/// 窗口内允许的迁移次数，超过即冻结该线程直到它退出
const MAX_MOVES_WINDOW: u8 = 3;

/// 跳过原因下标，供 Web 与摘要读取
pub const SKIP_ALLOW: usize = 0;
pub const SKIP_ROLE: usize = 1;
pub const SKIP_LOAD: usize = 2;
pub const SKIP_DWELL: usize = 3;
pub const SKIP_COOLDOWN: usize = 4;
pub const SKIP_QUOTA: usize = 5;
pub const SKIP_LABELS: [&str; 6] = [
    "允许集合不足两层",
    "线程角色不可迁移",
    "目标没有明显更空",
    "驻留时间不足",
    "冷却中",
    "目标簇配额已满",
];

const CLUSTER_NAME: [&str; 3] = ["e-core", "p-core", "hp-core"];

/// 单核累计时间，单位 jiffies
#[derive(Clone, Copy, Default)]
struct CpuStat {
    busy: u64,
    total: u64,
}

#[derive(Clone, Copy, Default)]
struct ClusterTimes {
    busy: u64,
    total: u64,
}

/// 线程的 S7 视角状态
struct ThreadState {
    /// 上次判定的落点，`None` 表示从未迁移
    cur: Option<u8>,
    /// 是否由 `on` 模式真正写入过亲和性。只有真写过才允许判定「被规则重扫拉回」
    own: bool,
    /// 上次写入的集合，用于识别外部改写
    applied: CpuSet,
    /// 连续同向确认次数
    streak: u8,
    last_move: Option<Instant>,
    /// 最小驻留起点
    first_seen: Instant,
    /// 上一次迁移的出发簇，用于拦住立刻迁回去
    last_from: Option<u8>,
    /// 迁移预算窗口起点与窗口内次数
    window: Instant,
    window_moves: u8,
    /// 抖动过多被冻结：不再迁移，直到线程退出或规则重扫
    frozen: bool,
}

impl ThreadState {
    fn new(now: Instant) -> Self {
        Self {
            cur: None,
            own: false,
            applied: CpuSet::new(),
            streak: 0,
            last_move: None,
            first_seen: now,
            last_from: None,
            window: now,
            window_moves: 0,
            frozen: false,
        }
    }

    fn reset(&mut self) {
        self.cur = None;
        self.own = false;
        self.applied = CpuSet::new();
        self.streak = 0;
        self.last_move = None;
        self.last_from = None;
        self.window = Instant::now();
        self.window_moves = 0;
        self.frozen = false;
    }
}

/// 待提交的迁移。`tick` 只产出不执行，避免与缓存借用纠缠。
/// 目标簇与线程名一起带上，`settle` 提交状态时不必回读缓存
#[derive(Clone)]
pub struct Move {
    pub tid: i32,
    /// 目标簇下标，成功提交后写入 `ThreadState::cur`
    pub target: u8,
    pub cpus: CpuSet,
    /// 仅用于日志与环形缓冲
    pub comm: String,
}

/// 单个线程的判定结果。把「算」与「记」分开：`judge` 只碰线程状态，
/// 统计与产出由调用方处理，避免同时借用 `self.threads` 与 `self.skip`
enum Action {
    /// 本轮什么都不做（已是最优、或在等确认）
    Nothing,
    /// 因某个原因跳过，下标见 `SKIP_LABELS`
    Skip(usize),
    /// 刚迁出又要迁回去，被反悔冷却拦住
    Bounce,
    /// shadow：记录但不执行
    Shadow {
        target: u8,
        base: i32,
        target_load: i32,
    },
    Move {
        target: u8,
        cpus: CpuSet,
    },
}

/// 目标簇在 `placed` 已满时不再接收。单核簇只放一个，
/// 多核簇放宽到两倍核数：Worker 与渲染线程抢同一个核才是掉帧的常见原因
fn quota(target: u8, topo: &CpuTopology) -> u16 {
    let cores = cluster_cores(target as usize, topo);
    if cores <= 1 { 1 } else { (cores * 2) as u16 }
}

#[allow(clippy::too_many_arguments)]
fn judge(
    st: &mut ThreadState,
    home: &crate::rule_match::AffinityResult,
    allow: &[bool; 3],
    load: [i32; 3],
    base: i32,
    topo: &CpuTopology,
    now: Instant,
    placed: &[u16; 3],
    mode: SchedMode,
) -> Action {
    if base < 0 {
        return Action::Skip(SKIP_LOAD);
    }
    let Some(target) = pick_target(&load, allow, st.cur) else {
        return Action::Skip(SKIP_LOAD);
    };
    if Some(target) == st.cur {
        st.streak = 0;
        return Action::Skip(SKIP_LOAD);
    }
    if base - load[target as usize] < LOAD_GAP {
        st.streak = 0;
        return Action::Skip(SKIP_LOAD);
    }
    if !target_ok(target, &load, allow, &home.cpus, topo) {
        st.streak = 0;
        return Action::Skip(SKIP_LOAD);
    }
    if st.first_seen.elapsed() < MIN_DWELL {
        return Action::Skip(SKIP_DWELL);
    }
    if st
        .last_move
        .is_some_and(|t| now.duration_since(t) < COOLDOWN)
    {
        return Action::Skip(SKIP_COOLDOWN);
    }
    // 反悔冷却比普通冷却长：刚离开的簇不能马上回去
    if st.last_from == Some(target)
        && st
            .last_move
            .is_some_and(|t| now.duration_since(t) < REVERSE_COOLDOWN)
    {
        st.streak = 0;
        return Action::Bounce;
    }
    if placed[target as usize] >= quota(target, topo) {
        return Action::Skip(SKIP_QUOTA);
    }

    st.streak = st.streak.saturating_add(1);
    if st.streak < CONFIRM_TICKS {
        return Action::Nothing;
    }
    let Some(cpus) = target_cpus(target, &home.cpus, topo) else {
        return Action::Skip(SKIP_LOAD);
    };
    st.streak = 0;
    if mode == SchedMode::On {
        Action::Move { target, cpus }
    } else {
        Action::Shadow {
            target,
            base,
            target_load: load[target as usize],
        }
    }
}

/// 供 Web 与日志读取的只读快照
#[derive(Clone, Default)]
pub struct SchedSnapshot {
    /// 0=off 1=shadow 2=on
    pub mode: u8,
    pub state: &'static str,
    pub ticks: u64,
    /// shadow 下「本可迁移」累计次数
    pub would: u64,
    /// on 下真实提交成功的次数
    pub moved: u64,
    /// 系统调用失败（EPERM/EINVAL 等），不计入 moved
    pub failed: u64,
    /// 因角色、目标簇核数等约束被拒的线程次
    pub blocked: u64,
    /// 各跳过原因计数，下标见 `SKIP_LABELS`
    pub skip: [u64; 6],
    /// 被反悔冷却拦住的次数
    pub bounced: u64,
    /// 抖动过多被冻结的线程数
    pub frozen: u64,
    /// 三簇负载千分比，-1 为不可用
    pub load: [i32; 3],
    pub last: String,
}

/// 全局快照，由主循环低频更新，Web 侧直接读
pub static SCHED_SNAPSHOT: Mutex<Option<SchedSnapshot>> = Mutex::new(None);

pub struct SchedState {
    mode: SchedMode,
    ticks: u64,
    would: u64,
    moved: u64,
    failed: u64,
    blocked: u64,
    skip: [u64; 6],
    bounced: u64,
    frozen: u64,
    threads: HashMap<i32, ThreadState>,
    /// 上一轮每簇累计时间，用于差分
    prev: Option<[ClusterTimes; 3]>,
    /// 上一轮簇负载
    load: [i32; 3],
    /// pid -> utime+stime，用于活跃判定
    active: HashMap<i32, u64>,
    ring: VecDeque<String>,
    /// 轮转游标，保证线程数超过 MAX_PROBE 时仍能全覆盖
    cursor: usize,
    /// 活跃判定的轮转游标：被管理 pid 超过 MAX_ACTIVE_PIDS 时
    /// 固定取前 N 个会让高位 pid 永远不参与判定
    active_cursor: usize,
    state: &'static str,
}

impl Default for SchedState {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedState {
    pub fn new() -> Self {
        Self {
            mode: SchedMode::Off,
            ticks: 0,
            would: 0,
            moved: 0,
            failed: 0,
            blocked: 0,
            skip: [0; 6],
            bounced: 0,
            frozen: 0,
            threads: HashMap::new(),
            prev: None,
            load: [-1; 3],
            active: HashMap::new(),
            ring: VecDeque::new(),
            cursor: 0,
            active_cursor: 0,
            state: "off",
        }
    }

    /// 模式切换时清空状态：`on -> off` 必须让已迁移线程重新按规则落地，
    /// 否则线程停在上次的落点，回滚不彻底
    pub fn set_mode(&mut self, mode: SchedMode) {
        if self.mode == mode {
            return;
        }
        self.mode = mode;
        self.threads.clear();
        self.prev = None;
        self.load = [-1; 3];
        self.active.clear();
        self.state = match mode {
            SchedMode::Off => "off",
            _ => "采样预热",
        };
    }

    /// 主循环每轮调用。off 模式零开销直接返回。
    pub fn tick(&mut self, cfg: &AppConfig, cache: &ProcCache) -> Vec<Move> {
        if self.mode == SchedMode::Off {
            self.state = "off";
            return Vec::new();
        }
        // 单簇或降级拓扑下没有换簇的余地，明确「不适用」而不是假装工作
        if cfg.sched_scope.levels < 2 {
            self.state = "不适用";
            return Vec::new();
        }
        if cache.tasks.is_empty() {
            self.state = "等待被管理进程";
            self.prev = None;
            return Vec::new();
        }

        let Some(cur) = read_cluster_times(&cfg.topo) else {
            self.state = "采样预热";
            return Vec::new();
        };
        let Some(prev) = self.prev.replace(cur) else {
            self.state = "采样预热";
            return Vec::new();
        };

        let load = diff_load(&prev, &cur);
        if !self.any_active(cache) {
            self.state = "无活跃进程";
            self.load = load;
            return Vec::new();
        }
        self.state = "运行中";
        self.tick_at(cfg, cache, load, Instant::now())
    }

    /// 用给定负载推进一轮判定。测试直接调用，生产由 `tick` 采样后转发。
    pub fn tick_at(
        &mut self,
        cfg: &AppConfig,
        cache: &ProcCache,
        load: [i32; 3],
        now: Instant,
    ) -> Vec<Move> {
        self.ticks += 1;
        self.load = load;
        self.decide(cfg, cache, load, now)
    }

    /// 迁移执行结果回填。只有真正写入成功才提交落点、`own` 与 `moved`；
    /// 失败时保留旧状态并进入冷却，避免每秒重试同一个必然失败的调用
    pub fn settle(&mut self, m: &Move, outcome: AffinityOutcome) {
        match outcome {
            AffinityOutcome::Set => {
                let now = Instant::now();
                let mut from = None;
                let mut freeze = false;
                if let Some(st) = self.threads.get_mut(&m.tid) {
                    from = st.cur;
                    st.last_from = st.cur;
                    st.cur = Some(m.target);
                    st.own = true;
                    st.applied = m.cpus;
                    st.last_move = Some(now);
                    // 预算窗口按线程滚动；窗口内迁移超限后冻结，避免跨簇抖动
                    if st.window.elapsed() > MOVE_WINDOW {
                        st.window = now;
                        st.window_moves = 0;
                    }
                    st.window_moves = st.window_moves.saturating_add(1);
                    if st.window_moves >= MAX_MOVES_WINDOW {
                        st.frozen = true;
                        freeze = true;
                    }
                }
                self.moved += 1;
                let line = format!(
                    "S7: {}({}) {} → {}（{}‰ → {}‰）",
                    m.comm,
                    m.tid,
                    from.map(cluster_label).unwrap_or("规则集合"),
                    cluster_label(m.target),
                    from.map(|c| self.load[c as usize]).unwrap_or(-1),
                    self.load[m.target as usize]
                );
                println!("{}", line);
                self.push_ring(line.clone());
                diag::note_sched(line);
                if freeze {
                    self.frozen += 1;
                    let f = format!(
                        "S7: {}({}) {} 秒内迁移 {} 次，已冻结（继续换簇只会放大抖动）",
                        m.comm,
                        m.tid,
                        MOVE_WINDOW.as_secs(),
                        MAX_MOVES_WINDOW
                    );
                    println!("{}", f);
                    self.push_ring(f.clone());
                    diag::note_sched(f);
                }
            }
            AffinityOutcome::Gone => {
                // 线程已退出：连状态一起清掉，避免 tid 复用时继承旧落点
                self.threads.remove(&m.tid);
            }
            AffinityOutcome::Failed => {
                self.failed += 1;
                if let Some(st) = self.threads.get_mut(&m.tid) {
                    st.last_move = Some(Instant::now());
                }
                let line = format!(
                    "S7: {}({}) 迁移到 {} 失败，保持原亲和性（详见同一时刻的绑核失败行）",
                    m.comm,
                    m.tid,
                    cluster_label(m.target)
                );
                diag::note_sched_failure(line);
            }
        }
    }

    fn push_ring(&mut self, line: String) {
        if self.ring.len() >= RING_CAP {
            self.ring.pop_front();
        }
        self.ring.push_back(line);
    }

    pub fn snapshot(&self) -> SchedSnapshot {
        SchedSnapshot {
            mode: self.mode as u8,
            state: self.state,
            ticks: self.ticks,
            would: self.would,
            moved: self.moved,
            failed: self.failed,
            blocked: self.blocked,
            skip: self.skip,
            bounced: self.bounced,
            frozen: self.frozen,
            load: self.load,
            last: self.ring.back().cloned().unwrap_or_default(),
        }
    }

    pub fn publish(&self) {
        *lock_ignore_poison(&SCHED_SNAPSHOT) = Some(self.snapshot());
    }

    fn decide(
        &mut self,
        cfg: &AppConfig,
        cache: &ProcCache,
        load: [i32; 3],
        now: Instant,
    ) -> Vec<Move> {
        let mut tids: Vec<i32> = cache.tasks.keys().copied().collect();
        if tids.is_empty() {
            return Vec::new();
        }
        // HashMap 顺序不稳定，排序后游标才能保证公平轮转
        tids.sort_unstable();
        let total = tids.len();
        let start = self.cursor % total;
        self.cursor = (start + MAX_PROBE) % total;

        // 每个簇当前放了几个被迁线程。配额与核数挂钩：单核簇只放 1 个，
        // 其余簇放到 2 倍核数。没有这道闸，多个 Worker 挤进超大核会直接拖慢渲染
        let mut placed = [0u16; 3];
        for st in self.threads.values() {
            if let Some(c) = st.cur {
                placed[c as usize] = placed[c as usize].saturating_add(1);
            }
        }
        let mode = self.mode;

        let mut out = Vec::new();
        for k in 0..total.min(MAX_PROBE) {
            if out.len() >= MAX_MOVES {
                break;
            }
            let tid = tids[(start + k) % total];
            let Some(entry) = cache.tasks.get(&tid) else {
                continue;
            };

            // 允许集合必须按规则重算：entry.cpus 已被上次迁移改写成目标簇，
            // 用它算「与几个簇相交」只会得到 1，线程被误判成非跨簇
            let name = if cfg.has_thread_rules.contains(&entry.pkg) {
                entry.comm.as_str()
            } else {
                ""
            };
            let Some(home) = thread_affinity(&entry.pkg, name, cfg) else {
                continue;
            };
            let allow = cluster_mask(&home.cpus, &cfg.topo);
            if allow.iter().filter(|x| **x).count() < 2 {
                self.skip[SKIP_ALLOW] += 1;
                continue;
            }

            let role = role_of(&entry.comm);
            if !role.movable() {
                self.blocked += 1;
                self.skip[SKIP_ROLE] += 1;
                continue;
            }

            let action = {
                let st = self
                    .threads
                    .entry(tid)
                    .or_insert_with(|| ThreadState::new(now));
                // 只有真写过才能用「缓存里的集合与上次写入不一致」判定被规则重扫拉回
                if st.own && entry.cpus != st.applied {
                    st.reset();
                }
                if st.frozen {
                    Action::Nothing
                } else {
                    let base = if st.own {
                        st.cur.map(|c| load[c as usize]).unwrap_or(-1)
                    } else {
                        weighted_avg(&load, &allow, &cfg.topo)
                    };
                    judge(st, &home, &allow, load, base, &cfg.topo, now, &placed, mode)
                }
            };

            match action {
                Action::Nothing => {}
                Action::Skip(why) => {
                    self.skip[why] += 1;
                    if why == SKIP_ROLE {
                        self.blocked += 1;
                    }
                }
                Action::Bounce => self.bounced += 1,
                Action::Shadow {
                    target,
                    base,
                    target_load,
                } => {
                    self.would += 1;
                    if let Some(st) = self.threads.get_mut(&tid) {
                        st.cur = Some(target);
                        st.last_move = Some(now);
                    }
                    let line = format!(
                        "S7(影子): {}({}) 允许集合 → {}（负载 {}‰ → {}‰）",
                        entry.comm, tid, CLUSTER_NAME[target as usize], base, target_load
                    );
                    self.push_ring(line.clone());
                    diag::note_sched(line);
                }
                Action::Move { target, cpus } => {
                    // shadow 只把候选记进 would / 环形缓冲，绝不产出 Move；
                    // on 只产出候选，状态等 settle 确认后再提交
                    if let Some(st) = self.threads.get_mut(&tid) {
                        st.streak = 0;
                    }
                    placed[target as usize] = placed[target as usize].saturating_add(1);
                    out.push(Move {
                        tid,
                        target,
                        cpus,
                        comm: entry.comm.clone(),
                    });
                }
            }
        }

        // 缓存里已消失的线程不再保留状态。无条件清理而不是「超过阈值才清」：
        // 残留状态会被复用的 tid 继承，导致新线程带着旧的落点与冷却时间
        self.threads.retain(|tid, _| cache.tasks.contains_key(tid));
        out
    }

    /// 有 pid 的 utime+stime 增长才算活跃。无活跃进程时不做决策：
    /// 后台挂着不动的游戏没有迁移收益，只会白白产生系统调用
    fn any_active(&mut self, cache: &ProcCache) -> bool {
        let mut pids: Vec<i32> = cache.tasks.values().map(|e| e.pid).collect();
        pids.sort_unstable();
        pids.dedup();
        let total = pids.len();
        if total == 0 {
            self.active.clear();
            return false;
        }
        // 超过上限时轮转取样，避免高位 pid 永远轮不到
        let (start, next) = rotate_start(total, self.active_cursor, MAX_ACTIVE_PIDS);
        self.active_cursor = next;

        // 保留未被本轮检查的 pid 的上次值，否则它们下次被抽到时没有基准
        let mut next_active = std::mem::take(&mut self.active);
        next_active.retain(|pid, _| pids.binary_search(pid).is_ok());
        let mut active = false;
        for k in 0..total.min(MAX_ACTIVE_PIDS) {
            let pid = pids[(start + k) % total];
            let Some(t) = pid_ticks(pid) else { continue };
            if next_active.get(&pid).is_some_and(|prev| t > *prev) {
                active = true;
            }
            next_active.insert(pid, t);
        }
        self.active = next_active;
        active
    }
}

/// 取样窗口：返回本轮起始下标与下一轮游标。pid 数超过 `MAX_ACTIVE_PIDS` 时
/// 按窗口平移，保证所有 pid 在若干轮内都被检查到；增删 pid 只会改变取模基数，
/// 不会把游标重置回 0
fn rotate_start(total: usize, cursor: usize, max: usize) -> (usize, usize) {
    let start = cursor % total;
    (start, (start + max) % total)
}

/// 读取 `/proc/stat` 每个在线核的累计时间。汇总行 `cpu ` 的序号为空，自然被跳过。
fn parse_stat(content: &str) -> Vec<(usize, CpuStat)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        let Some((idx, rest)) = rest.split_once(' ') else {
            continue;
        };
        let Ok(idx) = idx.parse::<usize>() else {
            continue;
        };
        let mut it = rest
            .split_whitespace()
            .map(|v| v.parse::<u64>().unwrap_or(0));
        let user = it.next().unwrap_or(0);
        let nice = it.next().unwrap_or(0);
        let system = it.next().unwrap_or(0);
        let idle = it.next().unwrap_or(0);
        let iowait = it.next().unwrap_or(0);
        let irq = it.next().unwrap_or(0);
        let softirq = it.next().unwrap_or(0);
        let steal = it.next().unwrap_or(0);
        // guest/guest_nice 已包含在 user/nice 中，不重复计入
        let busy = user + nice + system + irq + softirq + steal;
        let total = busy + idle + iowait;
        out.push((idx, CpuStat { busy, total }));
    }
    out
}

fn read_cluster_times(topo: &CpuTopology) -> Option<[ClusterTimes; 3]> {
    let content = fs::read_to_string("/proc/stat").ok()?;
    let stats = parse_stat(&content);
    if stats.is_empty() {
        return None;
    }
    Some(cluster_times(&stats, topo))
}

fn cluster_times(stats: &[(usize, CpuStat)], topo: &CpuTopology) -> [ClusterTimes; 3] {
    let mut out = [ClusterTimes::default(); 3];
    let sets = [topo.e_core, topo.p_core, topo.hp_core];
    for (cpu, st) in stats {
        for (i, set) in sets.iter().enumerate() {
            if set.is_set(*cpu) {
                out[i].busy += st.busy;
                out[i].total += st.total;
            }
        }
    }
    out
}

/// 千分比差分。计数回绕、离核或 Δtotal 为 0 一律记 -1（不可用），
/// 绝不把缺失值当 0 参与排序
fn diff_load(prev: &[ClusterTimes; 3], cur: &[ClusterTimes; 3]) -> [i32; 3] {
    let mut out = [-1i32; 3];
    for i in 0..3 {
        if cur[i].busy < prev[i].busy || cur[i].total < prev[i].total {
            continue;
        }
        let db = cur[i].busy - prev[i].busy;
        let dt = cur[i].total - prev[i].total;
        if dt == 0 || db > dt {
            continue;
        }
        out[i] = (db * 1000 / dt) as i32;
    }
    out
}

fn cluster_mask(cpus: &CpuSet, topo: &CpuTopology) -> [bool; 3] {
    let mut m = [false; 3];
    for (i, set) in [topo.e_core, topo.p_core, topo.hp_core].iter().enumerate() {
        m[i] = set.count() > 0
            && cpus
                .bits
                .iter()
                .zip(set.bits.iter())
                .any(|(a, b)| a & b != 0);
    }
    m
}

fn cluster_cores(i: usize, topo: &CpuTopology) -> usize {
    match i {
        0 => topo.e_core.count(),
        1 => topo.p_core.count(),
        _ => topo.hp_core.count(),
    }
}

/// 未迁移时用在线核数加权平均衡量线程处境：
/// 规则 `p-core,hp-core` 让线程在 4 个核上浮动，拿单一簇当基准会失真
fn weighted_avg(load: &[i32; 3], allow: &[bool; 3], topo: &CpuTopology) -> i32 {
    let mut sb = 0i64;
    let mut sc = 0i64;
    for i in 0..3 {
        if !allow[i] || load[i] < 0 {
            continue;
        }
        let c = cluster_cores(i, topo) as i64;
        if c == 0 {
            continue;
        }
        sb += load[i] as i64 * c;
        sc += c;
    }
    if sc == 0 { -1 } else { (sb / sc) as i32 }
}

/// 负载最低的可用簇。当前簇已是最低时保持不动，避免同负载下来回跳。
fn pick_target(load: &[i32; 3], allow: &[bool; 3], cur: Option<u8>) -> Option<u8> {
    let mut best: Option<(i32, u8)> = None;
    // 只在小核之上的两层里挑。e-core 是最低层，迁进去没有收益，
    // 若先按全表选出 e-core 再被 target_ok 否决，整个线程这轮就白跑了
    for i in 1..3 {
        if !allow[i] || load[i] < 0 {
            continue;
        }
        match best {
            Some((b, _)) if load[i] >= b => {}
            _ => best = Some((load[i], i as u8)),
        }
    }
    let (min, idx) = best?;
    if let Some(c) = cur
        && allow[c as usize]
        && load[c as usize] == min
    {
        return Some(c);
    }
    Some(idx)
}

/// P1 硬约束：目标必须落在允许集合内、至少两个核、且只能是 p-core / hp-core。
/// 不允许往下迁（e-core 已经是兜底，再降没有收益），也不允许钉死单核超大核。
fn target_ok(
    target: u8,
    load: &[i32; 3],
    allow: &[bool; 3],
    allowed_cpus: &CpuSet,
    topo: &CpuTopology,
) -> bool {
    let t = target as usize;
    if t == 0 || !allow[t] || load[t] < 0 {
        return false;
    }
    let mut set = match t {
        1 => topo.p_core,
        _ => topo.hp_core,
    };
    set.and(allowed_cpus);
    set.count() >= MIN_TARGET_CORES
}

/// 目标簇与规则允许集合的交集。绝不能直接用簇全集，否则会越过规则给出的范围
fn target_cpus(target: u8, allowed: &CpuSet, topo: &CpuTopology) -> Option<CpuSet> {
    let mut set = match target {
        0 => topo.e_core,
        1 => topo.p_core,
        _ => topo.hp_core,
    };
    set.and(allowed);
    (set.count() > 0).then_some(set)
}

fn cluster_label(i: u8) -> &'static str {
    CLUSTER_NAME.get(i as usize).copied().unwrap_or("?")
}

/// 读 `/proc/<pid>/stat` 的 utime+stime。comm 可含空格与括号，从最后一个 `)` 之后解析。
fn pid_ticks(pid: i32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let rest = &s[s.rfind(')')? + 1..];
    let mut it = rest.split_whitespace();
    // 第一个 token 是 state（字段 3），utime 是字段 14，即再取第 12 个
    let utime = it.nth(11)?.parse::<u64>().ok()?;
    let stime = it.next()?.parse::<u64>().ok()?;
    Some(utime + stime)
}

/// 采样周期常量对外暴露，供主循环决定 tick 频率
pub const fn sample_period() -> Duration {
    SAMPLE_PERIOD
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SchedScope;

    fn topo() -> CpuTopology {
        let mut e = CpuSet::new();
        for i in 0..4 {
            e.set(i);
        }
        let mut p = CpuSet::new();
        for i in 4..7 {
            p.set(i);
        }
        let mut h = CpuSet::new();
        h.set(7);
        let mut all = CpuSet::new();
        for i in 0..8 {
            all.set(i);
        }
        CpuTopology {
            present_cpus: all,
            present_str: "0-7".into(),
            mems_str: "0".into(),
            cpuset_enabled: false,
            e_core: e,
            p_core: p,
            hp_core: h,
            topo_source: "capacity",
            topo_degraded: false,
        }
    }

    fn cfg_with(name: &str, conf: &str) -> AppConfig {
        let p = format!("/tmp/appopt_sched_{}.conf", name);
        std::fs::write(&p, conf).unwrap();
        let t = topo();
        let mut m = -1i64;
        let mut cfg = crate::config::load_config(&p, &t, &mut m).unwrap();
        cfg.topo = t;
        cfg.sched_scope = SchedScope {
            levels: 3,
            rules: 1,
            pkgs: 1,
        };
        cfg
    }

    fn task(pkg: &str, comm: &str, cpus: CpuSet) -> crate::cache::TaskEntry {
        crate::cache::TaskEntry {
            pid: 100,
            pkg: pkg.to_string(),
            cpus,
            cpuset_dir: String::new(),
            is_thread_rule: false,
            comm: comm.to_string(),
        }
    }

    fn cache_with(pkg: &str, comm: &str, cpus: CpuSet) -> ProcCache {
        let mut c = ProcCache::new();
        c.tasks.insert(1001, task(pkg, comm, cpus));
        c
    }

    /// 预置 `first_seen` 到过去，绕开 2s 最小驻留，让判定当轮就能成型
    fn state_for(cache: &ProcCache, mode: SchedMode) -> SchedState {
        let mut st = SchedState::new();
        st.set_mode(mode);
        let now = Instant::now();
        for &tid in cache.tasks.keys() {
            st.threads.insert(
                tid,
                ThreadState {
                    first_seen: now - Duration::from_secs(5),
                    ..ThreadState::new(now)
                },
            );
        }
        st
    }

    /// p-core + hp-core 的允许集合，负载让 hp 明显更低
    fn span_cache(name: &str) -> (AppConfig, ProcCache) {
        let cfg = cfg_with(name, "com.test.game=p-core,hp-core\n");
        let t = topo();
        let mut cpus = CpuSet::new();
        cpus.or(&t.p_core);
        cpus.or(&t.hp_core);
        let cache = cache_with("com.test.game", "Thread-7", cpus);
        (cfg, cache)
    }

    #[test]
    fn parse_stat_skips_summary_and_keeps_online() {
        let s = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 10 0 10 80 0 0 0 0 0 0\ncpu1 20 0 20 160 0 0 0 0 0 0\nintr 1\n";
        let rows = parse_stat(s);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, 0);
        assert_eq!(rows[0].1.busy, 20);
        assert_eq!(rows[0].1.total, 100);
    }

    #[test]
    fn diff_load_reports_thousandths() {
        let prev = [ClusterTimes {
            busy: 100,
            total: 1000,
        }; 3];
        let cur = [ClusterTimes {
            busy: 200,
            total: 1200,
        }; 3];
        // Δbusy=100 Δtotal=200 → 500‰
        assert_eq!(diff_load(&prev, &cur), [500, 500, 500]);
    }

    #[test]
    fn diff_load_zero_total_is_unavailable() {
        let prev = [ClusterTimes {
            busy: 100,
            total: 1000,
        }; 3];
        let cur = [ClusterTimes {
            busy: 100,
            total: 1000,
        }; 3];
        assert_eq!(diff_load(&prev, &cur), [-1, -1, -1]);
    }

    #[test]
    fn diff_load_wraparound_is_unavailable() {
        let prev = [ClusterTimes {
            busy: 900,
            total: 1000,
        }; 3];
        let cur = [ClusterTimes {
            busy: 10,
            total: 50,
        }; 3];
        assert_eq!(diff_load(&prev, &cur), [-1, -1, -1]);
    }

    #[test]
    fn pick_target_ignores_unavailable_and_prefers_idle() {
        let allow = [true, true, true];
        assert_eq!(pick_target(&[500, 200, 300], &allow, None), Some(1));
        assert_eq!(pick_target(&[-1, 400, 300], &allow, None), Some(2));
        assert_eq!(pick_target(&[-1, -1, -1], &allow, None), None);
    }

    #[test]
    fn pick_target_keeps_current_when_tied() {
        let allow = [false, true, true];
        // 当前在 hp，与 p 同负载时保持不动
        assert_eq!(pick_target(&[-1, 300, 300], &allow, Some(2)), Some(2));
    }

    #[test]
    fn weighted_avg_counts_cores() {
        let allow = [false, true, true];
        // p 有 3 核负载 400，hp 有 1 核负载 800 → (1200+800)/4 = 500
        assert_eq!(weighted_avg(&[-1, 400, 800], &allow, &topo()), 500);
        assert_eq!(weighted_avg(&[-1, -1, -1], &allow, &topo()), -1);
    }

    #[test]
    fn target_rejects_e_core_and_empty_intersection() {
        let t = topo();
        let allow = [true, true, true];
        let load = [100, 300, 200];
        // e-core 已经是最低层，再往下没有收益
        assert!(!target_ok(0, &load, &allow, &t.present_cpus, &t));
        // hp 单核允许进入，靠负载反馈自限
        assert!(target_ok(2, &load, &allow, &t.present_cpus, &t));
        assert!(target_ok(1, &load, &allow, &t.present_cpus, &t));
        // 交集为空
        let empty = CpuSet::new();
        assert!(!target_ok(1, &load, &allow, &empty, &t));
    }

    #[test]
    fn target_cpus_never_exceeds_allow_set() {
        let t = topo();
        let mut allowed = CpuSet::new();
        allowed.set(5);
        let got = target_cpus(1, &allowed, &t).unwrap();
        assert_eq!(got.count(), 1);
        assert!(got.is_set(5));
        assert_eq!(target_cpus(2, &allowed, &t), None);
    }

    #[test]
    fn judge_needs_three_confirms() {
        let cfg = cfg_with("judge", "com.test.game=p-core,hp-core\n");
        let t = topo();
        let mut cpus = CpuSet::new();
        cpus.or(&t.p_core);
        cpus.or(&t.hp_core);
        let cache = cache_with("com.test.game", "Thread-7", cpus);

        let mut st = SchedState::new();
        st.set_mode(SchedMode::On);
        let now = Instant::now();
        // 起始时刻设为过去，绕开 2s 最小驻留
        st.threads.insert(
            1001,
            ThreadState {
                first_seen: now - Duration::from_secs(5),
                ..ThreadState::new(now)
            },
        );
        let load = [-1, 600, 200];
        assert!(st.tick_at(&cfg, &cache, load, now).is_empty());
        assert!(st.tick_at(&cfg, &cache, load, now).is_empty());
        let mv = st.tick_at(&cfg, &cache, load, now);
        assert_eq!(mv.len(), 1);
        assert_eq!(mv[0].cpus.to_range_string(), "7");
    }

    #[test]
    fn shadow_counts_would_once() {
        let cfg = cfg_with("shadow", "com.test.game=p-core,hp-core\n");
        let t = topo();
        let mut cpus = CpuSet::new();
        cpus.or(&t.p_core);
        cpus.or(&t.hp_core);
        let cache = cache_with("com.test.game", "Thread-7", cpus);

        let mut st = SchedState::new();
        st.set_mode(SchedMode::Shadow);
        let now = Instant::now();
        st.threads.insert(
            1001,
            ThreadState {
                first_seen: now - Duration::from_secs(5),
                ..ThreadState::new(now)
            },
        );
        let load = [-1, 600, 300];
        for _ in 0..6 {
            st.tick_at(&cfg, &cache, load, now);
        }
        // shadow 不产生 Move，但 would 只累计一次
        assert_eq!(st.would, 1);
        assert_eq!(st.moved, 0);
    }

    /// 核心隔离断言：shadow 无论跑多少轮都不能产出可执行迁移，
    /// 也不能把自己标记成「写过亲和性」
    #[test]
    fn shadow_never_yields_moves() {
        let (cfg, cache) = span_cache("shadow_moves");
        let mut st = state_for(&cache, SchedMode::Shadow);
        let mut moves = 0;
        for _ in 0..12 {
            moves += st
                .tick_at(&cfg, &cache, [-1, 600, 300], Instant::now())
                .len();
        }
        assert_eq!(moves, 0, "shadow 不得产出任何 Move");
        assert_eq!(st.would, 1);
        assert_eq!(st.moved, 0);
        let th = st.threads.get(&1001).unwrap();
        assert!(!th.own, "shadow 不能把线程标记为已迁移");
        assert_eq!(th.applied.count(), 0, "shadow 不能记录写入过的集合");
    }

    /// on 模式照旧产出候选，但状态要等回填成功才提交
    #[test]
    fn on_mode_only_commits_after_confirmation() {
        let (cfg, cache) = span_cache("on_confirm");
        let mut st = state_for(&cache, SchedMode::On);
        let now = Instant::now();
        assert!(st.tick_at(&cfg, &cache, [-1, 600, 200], now).is_empty());
        assert!(st.tick_at(&cfg, &cache, [-1, 600, 200], now).is_empty());
        let mv = st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        assert_eq!(mv.len(), 1);
        assert_eq!(mv[0].cpus.to_range_string(), "7");
        // 尚未回填：moved 与落点都还是旧的
        assert_eq!(st.moved, 0);
        assert!(!st.threads[&1001].own);
        assert_eq!(st.threads[&1001].cur, None);

        st.settle(&mv[0], AffinityOutcome::Set);
        assert_eq!(st.moved, 1);
        let th = &st.threads[&1001];
        assert!(th.own);
        assert_eq!(th.cur, Some(2));
        assert_eq!(th.applied.to_range_string(), "7");
    }

    /// EPERM/EINVAL 这类失败不能伪装成迁移成功
    #[test]
    fn failed_move_keeps_old_state_and_counts_failure() {
        let (cfg, cache) = span_cache("move_failed");
        let mut st = state_for(&cache, SchedMode::On);
        let now = Instant::now();
        st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        let mv = st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        assert_eq!(mv.len(), 1);

        st.settle(&mv[0], AffinityOutcome::Failed);
        assert_eq!(st.moved, 0, "失败不能计入 moved");
        assert_eq!(st.failed, 1);
        let th = &st.threads[&1001];
        assert!(!th.own);
        assert_eq!(th.cur, None, "失败必须保留旧落点");
        // 冷却生效：下一轮不会立刻重试同一个注定失败的调用
        assert!(th.last_move.is_some());
    }

    #[test]
    fn gone_thread_is_forgotten_not_counted() {
        let (cfg, cache) = span_cache("move_gone");
        let mut st = state_for(&cache, SchedMode::On);
        let now = Instant::now();
        st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        let mv = st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        assert_eq!(mv.len(), 1);

        st.settle(&mv[0], AffinityOutcome::Gone);
        assert_eq!(st.moved, 0);
        assert!(!st.threads.contains_key(&1001));
    }

    /// 起一个真实线程并命名，用于验证「决策没有落到系统调用上」
    fn spawn_named(name: &str) -> (std::thread::JoinHandle<()>, i32) {
        let (tx, rx) = std::sync::mpsc::channel();
        let name = name.to_string();
        let handle = std::thread::spawn(move || {
            let c_name = std::ffi::CString::new(name).unwrap();
            unsafe {
                libc::pthread_setname_np(libc::pthread_self(), c_name.as_ptr());
            }
            let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
            tx.send(tid).unwrap();
            std::thread::park();
        });
        let tid = rx.recv().expect("线程未启动");
        (handle, tid)
    }

    /// 端到端：影子模式跑满 12 轮后，真实线程的亲和性必须一字未改
    #[test]
    fn shadow_never_touches_real_affinity() {
        let (handle, tid) = spawn_named("Thread-7");
        let t = topo();
        let mut allowed = CpuSet::new();
        allowed.or(&t.p_core);
        allowed.or(&t.hp_core);
        assert_eq!(
            crate::apply_affinity::affinity_apply(
                tid,
                &allowed,
                None,
                &t,
                crate::apply_affinity::ApplyReason::Rule,
                "Thread-7",
            )
            .0,
            AffinityOutcome::Set
        );

        let cfg = cfg_with("shadow_real", "com.test.game=p-core,hp-core\n");
        let mut cache = ProcCache::new();
        cache.tasks.insert(
            tid,
            crate::cache::TaskEntry {
                pid: 100,
                pkg: "com.test.game".to_string(),
                cpus: allowed,
                cpuset_dir: String::new(),
                is_thread_rule: false,
                comm: "Thread-7".to_string(),
            },
        );
        let mut st = state_for(&cache, SchedMode::Shadow);
        for _ in 0..12 {
            assert!(
                st.tick_at(&cfg, &cache, [-1, 600, 100], Instant::now())
                    .is_empty()
            );
        }
        // 判定确实成型（否则这条断言没有意义）
        assert_eq!(st.would, 1);
        // 但内核里的亲和性必须还是 p-core ∪ hp-core
        assert_eq!(CpuSet::get_affinity(tid).expect("读取亲和性失败"), allowed);

        handle.thread().unpark();
        handle.join().unwrap();
    }

    /// 超过 MAX_ACTIVE_PIDS 时所有 pid 都必须轮到
    #[test]
    fn active_pid_rotation_covers_all() {
        let total = 20;
        let mut cursor = 0;
        let mut seen = vec![false; total];
        for _ in 0..total.div_ceil(MAX_ACTIVE_PIDS) {
            let (start, next) = rotate_start(total, cursor, MAX_ACTIVE_PIDS);
            for k in 0..MAX_ACTIVE_PIDS {
                seen[(start + k) % total] = true;
            }
            cursor = next;
        }
        assert!(seen.iter().all(|v| *v), "存在永远轮不到的 pid");
    }

    #[test]
    fn rotation_survives_pid_count_change() {
        // 进程数变化只改变取模基数，游标不会退回 0 造成重复取样
        assert_eq!(rotate_start(10, 8, 8), (8, 6));
        assert_eq!(rotate_start(5, 9, 3), (4, 2));
        assert_eq!(rotate_start(12, 6, 8), (6, 2));
    }

    #[test]
    fn rule_rescan_resets_state() {
        let cfg = cfg_with("rescan", "com.test.game=p-core,hp-core\n");
        let t = topo();
        let mut cpus = CpuSet::new();
        cpus.or(&t.p_core);
        cpus.or(&t.hp_core);
        let mut cache = cache_with("com.test.game", "Thread-7", cpus);

        let mut st = SchedState::new();
        st.set_mode(SchedMode::On);
        let now = Instant::now();
        st.threads.insert(
            1001,
            ThreadState {
                cur: Some(2),
                own: true,
                applied: {
                    let mut s = CpuSet::new();
                    s.set(7);
                    s
                },
                streak: 0,
                last_move: Some(now),
                first_seen: now - Duration::from_secs(5),
                ..ThreadState::new(now)
            },
        );
        // 模拟规则重扫：缓存里的集合被改回允许集合
        cache.tasks.get_mut(&1001).unwrap().cpus = cpus;
        st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        let state = st.threads.get(&1001).unwrap();
        assert!(!state.own);
        assert_eq!(state.cur, None);
    }

    /// 刚从 hp 迁回 p，20 秒后又想回 hp：反悔冷却必须拦住，
    /// 否则单核簇会被单个线程反复打满又放空
    #[test]
    fn reverse_move_is_bounced() {
        let (cfg, cache) = span_cache("bounce");
        let mut st = state_for(&cache, SchedMode::On);
        let now = Instant::now();
        {
            let th = st.threads.get_mut(&1001).unwrap();
            th.own = true;
            th.cur = Some(1);
            th.last_from = Some(2);
            th.last_move = Some(now - Duration::from_secs(20));
            // 缓存里的集合必须与 applied 一致，否则会被当成规则重扫而清空状态
            th.applied = cache.tasks[&1001].cpus;
        }
        let mv = st.tick_at(&cfg, &cache, [-1, 600, 100], now);
        assert!(mv.is_empty(), "反悔冷却内不得迁回");
        assert_eq!(st.bounced, 1);
    }

    /// 预算窗口内迁移三次即冻结，且不再产出 Move
    #[test]
    fn repeated_moves_freeze_the_thread() {
        let (cfg, cache) = span_cache("freeze");
        let mut st = state_for(&cache, SchedMode::On);
        let now = Instant::now();
        for target in [2u8, 1, 2] {
            st.threads.get_mut(&1001).unwrap().streak = CONFIRM_TICKS - 1;
            let m = Move {
                tid: 1001,
                target,
                cpus: CpuSet::new(),
                comm: "Thread-7".into(),
            };
            st.settle(&m, AffinityOutcome::Set);
        }
        assert_eq!(st.frozen, 1);
        assert!(st.threads[&1001].frozen);
        assert!(
            st.tick_at(&cfg, &cache, [-1, 900, 10], now).is_empty(),
            "冻结后不得继续迁移"
        );
    }

    /// 单核簇配额为 1：已有线程占住 hp 时，第二个线程必须被挡住
    #[test]
    fn single_core_cluster_quota_blocks_second_thread() {
        let cfg = cfg_with("quota", "com.test.game=p-core,hp-core\n");
        let t = topo();
        let mut cpus = CpuSet::new();
        cpus.or(&t.p_core);
        cpus.or(&t.hp_core);
        let mut cache = cache_with("com.test.game", "Thread-7", cpus);
        cache.tasks.insert(
            1002,
            crate::cache::TaskEntry {
                pid: 100,
                pkg: "com.test.game".into(),
                cpus,
                cpuset_dir: String::new(),
                is_thread_rule: false,
                comm: "Thread-8".into(),
            },
        );
        let mut st = state_for(&cache, SchedMode::On);
        let now = Instant::now();
        {
            let th = st.threads.get_mut(&1002).unwrap();
            th.cur = Some(2);
            th.own = true;
        }
        for _ in 0..4 {
            for th in st.threads.values_mut() {
                th.first_seen = now - Duration::from_secs(5);
            }
            let _ = st.tick_at(&cfg, &cache, [-1, 700, 50], now);
        }
        assert!(st.skip[SKIP_QUOTA] >= 1, "单核簇配额没有生效");
        assert!(st.threads[&1001].cur.is_none());
    }

    #[test]
    fn critical_thread_is_blocked() {
        let cfg = cfg_with("critical", "com.test.game=p-core,hp-core\n");
        let t = topo();
        let mut cpus = CpuSet::new();
        cpus.or(&t.p_core);
        cpus.or(&t.hp_core);
        let cache = cache_with("com.test.game", "RenderThread", cpus);

        let mut st = SchedState::new();
        st.set_mode(SchedMode::On);
        let now = Instant::now();
        for _ in 0..4 {
            st.tick_at(&cfg, &cache, [-1, 600, 200], now);
        }
        assert_eq!(st.moved, 0);
        assert!(st.blocked >= 1);
    }
}
