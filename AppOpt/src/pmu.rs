//! PMU Observer（融合方案第十六节第一阶段）。
//!
//! 只采样、只输出观察数据，**不参与任何迁移决策**。执行路径
//! （`apply_affinity` / `policy::plan_entry` / S7 落点）不读本模块的任何
//! 状态：PMU 被内核拒绝、计数器不支持、FD 耗尽，绑核结果一行都不会变。
//!
//! 流程对应方案 16.2：
//!
//! ```text
//! 线程活动预筛（/proc/<tid>/stat 的 utime+stime 增量）
//!     ↓
//! RLIMIT_NOFILE 检查 → 算 FD 预算
//!     ↓
//! perf_event_open（instructions / cycles / cache-misses）
//!     ↓
//! 每窗口 read 计数器 → 算增量
//!     ↓
//! 输出观察数据（日志 + Web 快照）
//! ```
//!
//! 三个事件里 `cache-misses` 在部分 ARM 内核上不可用，方案要求「经设备
//! 核实」：打开失败就只降级这个事件，不牵连 instructions / cycles。
//!
//! 第二阶段的 Shadow 配额分配（`pmu_allocator.rs`）不在本文件范围内。

use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cache::ProcCache;
use crate::config::AppConfig;
use crate::lock_ignore_poison;

/// 采样窗口。与 S7 的采样周期独立：S7 要快，PMU 靠窗口差分才稳定
pub const SAMPLE_WINDOW: Duration = Duration::from_secs(5);
/// 方案 16.2：第一版最大采样线程数不超过 128
pub const MAX_THREADS: usize = 128;
/// 每个线程的事件数（instructions / cycles / cache-misses）
const EVENTS: usize = 3;
/// 给主程序其余 FD 留的余量：cpuset、日志、socket 都要用
const FD_RESERVE: u64 = 64;
/// 连续多少个窗口没有 tick 增长就关 FD（6 × 5s = 30s）
const IDLE_WINDOWS: u8 = 6;
/// 连续打开失败多少次就整体关闭，避免每轮都撞同一个错误
const MAX_OPEN_FAILS: u8 = 3;
/// 连续多少个窗口「线程在跑、计数器却一个都没涨」才判定设备不计数。
/// 3 × 5s：偶发的空窗口不会误判，真不计数也不会拖太久
const ZERO_WINDOWS: u8 = 3;
/// 日志里最多列几条最忙线程
const LOG_SAMPLES: usize = 3;
/// Web 快照里最多保留几条
const SNAP_SAMPLES: usize = 8;
/// 日志间隔：每 30 秒一行，5 秒一行等于刷屏
const LOG_GAP: Duration = Duration::from_secs(30);
/// 一个线程都没管的时候没有任何变化，5 分钟说一次「还是没事干」就够。
/// 否则挂着不动也会每 30 秒刷一行，日志里全是噪音
const IDLE_LOG_GAP: Duration = Duration::from_secs(300);

const INDEX_INST: usize = 0;
const INDEX_CYCLES: usize = 1;
const INDEX_MISS: usize = 2;

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
/// `PERF_ATTR_SIZE_VER0`：只声明第一版布局，老内核也能收
const PERF_ATTR_SIZE: u32 = 64;
/// `exclude_hv`：Android 上没有有意义的 hypervisor 时间
const FLAG_EXCLUDE_HV: u64 = 1 << 6;

/// `perf_event_attr` 的前 64 字节（`PERF_ATTR_SIZE_VER0`）。
///
/// libc crate 不提供这个结构，自己按内核 ABI 定义。只用到 `type` / `size` /
/// `config` / `flags` 四个字段，其余保持零值；`size` 传 64 时内核只读前
/// 64 字节，后面的字段不会被解释
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    /// bit0 disabled、bit1 inherit、bit5 exclude_kernel、bit6 exclude_hv
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
}

/// 一次窗口内的单线程增量
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub tid: i32,
    pub pkg: String,
    pub comm: String,
    /// 窗口内指令增量
    pub inst: u64,
    /// 窗口内周期增量
    pub cycles: u64,
    /// cache-misses 增量。设备不支持时为 `None`，不是 0
    pub misses: Option<u64>,
    /// 本样本覆盖的实际窗口长度（毫秒）。主循环是 2 秒一跳，采样窗口
    /// 实际会是 6 秒左右，用固定 5 秒算速率会系统性偏高
    pub window_ms: u64,
}

impl Sample {
    /// 每指令周期数。指令为 0 时没有意义，返回 0
    pub fn cpi(&self) -> f64 {
        if self.inst == 0 {
            return 0.0;
        }
        self.cycles as f64 / self.inst as f64
    }

    /// 每秒百万条指令（M/s）。窗口是毫秒，所以要多除 1000——
    /// 以前直接拿「每毫秒指令数」当 M/s 打印，数值虚高一千倍
    pub fn mips(&self) -> f64 {
        self.inst as f64 / (self.window_ms.max(1) as f64 * 1000.0)
    }

    /// 每秒十亿周期（Gcyc/s）。ARM64 上有设备只暴露 cycles、
    /// instructions 恒为 0，这时速率只能看这一项
    pub fn gcyc(&self) -> f64 {
        self.cycles as f64 / (self.window_ms.max(1) as f64 * 1_000_000.0)
    }

    /// 本窗口是否真的在干活。**不能只看 inst**：部分内核/厂商只放出
    /// cycles 计数，instructions 常读 0，按 inst 判活跃会把整台机器的
    /// 样本全丢掉，表现为「开了一堆 FD 却永远没有活跃线程」
    pub fn is_active(&self) -> bool {
        self.inst > 0 || self.cycles > 0
    }

    /// 日志里的速率描述：有指令就说指令速率，只有周期就说周期速率
    pub fn rate_text(&self) -> String {
        if self.inst > 0 {
            format!("{:.0} M/s CPI {:.2}", self.mips(), self.cpi())
        } else if self.cycles > 0 {
            format!("{:.2} Gcyc/s", self.gcyc())
        } else {
            "0".to_string()
        }
    }
}

/// Web / 日志用的只读视图
#[derive(Clone, Debug, Default)]
pub struct PmuSnapshot {
    /// 状态文案：「未启用」/「运行中」/「息屏暂停」/「不可用：…」
    pub state: String,
    pub fds: usize,
    pub budget: usize,
    pub threads: usize,
    pub windows: u64,
    pub miss_ok: bool,
    pub samples: Vec<Sample>,
}

struct Slot {
    /// 下标见 `INDEX_*`，-1 表示该事件未开
    fds: [i32; EVENTS],
    /// 打开时的 starttime，用来识破 tid 复用
    starttime: u64,
    /// 上一窗口的累计值，用于差分
    prev: [u64; EVENTS],
    /// 上一窗口的 utime+stime（jiffies），用于活跃预筛
    last_ticks: u64,
    /// 连续多少个窗口 tick 没有增长
    idle: u8,
    pkg: String,
    comm: String,
}

impl Slot {
    fn new(starttime: u64, last_ticks: u64, pkg: String, comm: String) -> Self {
        Self {
            fds: [-1; EVENTS],
            starttime,
            prev: [0; EVENTS],
            last_ticks,
            idle: 0,
            pkg,
            comm,
        }
    }

    fn any_fd(&self) -> bool {
        self.fds.iter().any(|&fd| fd >= 0)
    }

    fn fd_count(&self) -> usize {
        self.fds.iter().filter(|&&fd| fd >= 0).count()
    }

    fn close_all(&mut self) {
        for fd in &mut self.fds {
            if *fd >= 0 {
                unsafe { libc::close(*fd) };
                *fd = -1;
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.close_all();
    }
}

struct Pmu {
    /// 一旦置位就不再尝试：权限、内核不支持、FD 耗尽都属这一类
    off: Option<String>,
    slots: HashMap<i32, Slot>,
    /// 本轮最多允许打开多少个线程
    budget: usize,
    windows: u64,
    open_fails: u8,
    /// cache-misses 是否可用（只探测一次）
    miss_ok: bool,
    miss_probed: bool,
    samples: Vec<Sample>,
    last_log: Instant,
    /// 上一窗口是否采到了数据。状态翻转要立即出声：从「没有活跃线程」
    /// 变成「采到数据」正是用户想确认的那一刻，等 30 秒才说等于没说
    last_had_samples: bool,
    /// 上一窗口的开始时刻，用来算真实窗口长度
    last_tick: Option<Instant>,
    /// 连续多少个窗口「FD 开着、线程在跑，但计数器一个字节都没涨」。
    /// 这既不是「没线程」也不是「没权限」，是设备真的不计数，必须单独说
    zero_windows: u8,
    /// 已经报告过「计数器不计数」，不再重复刷屏
    blind_reported: bool,
    /// 最近一次读计数器的 errno，用来解释「Fd 开着但读不出来」
    read_err: Option<i32>,
    /// 连续读失败的窗口数
    read_fails: u8,
}

impl Pmu {
    fn new() -> Self {
        Self {
            off: None,
            slots: HashMap::new(),
            budget: 0,
            windows: 0,
            open_fails: 0,
            miss_ok: false,
            miss_probed: false,
            samples: Vec::new(),
            // 首轮就打印一次：30 秒后才出声，用户会以为开关没生效。
            // 往回拨最长的那档间隔，空闲场景下第一行也不会被压掉
            last_log: Instant::now()
                .checked_sub(IDLE_LOG_GAP)
                .unwrap_or_else(Instant::now),
            last_had_samples: false,
            last_tick: None,
            zero_windows: 0,
            blind_reported: false,
            read_err: None,
            read_fails: 0,
        }
    }

    /// 已打开计数器的线程数（决定还能不能再开）
    fn open_threads(&self) -> usize {
        self.slots.values().filter(|s| s.any_fd()).count()
    }

    /// 实际占用的 FD 数（每线程最多 3 个）。日志里说「FD」就该是它，
    /// 之前拿线程数当 FD 数，128 线程显示成「FD 128/128」会被读成用满
    fn open_fds(&self) -> usize {
        self.slots.values().map(Slot::fd_count).sum()
    }

    fn close_all(&mut self) {
        for s in self.slots.values_mut() {
            s.close_all();
        }
    }
}

static PMU: Mutex<Option<Pmu>> = Mutex::new(None);
static SNAPSHOT: Mutex<Option<PmuSnapshot>> = Mutex::new(None);

/// 当前快照。未启用过时返回默认值（state = 「未启用」）
pub fn snapshot() -> PmuSnapshot {
    lock_ignore_poison(&SNAPSHOT)
        .clone()
        .unwrap_or_else(|| PmuSnapshot {
            state: "未启用".to_string(),
            ..Default::default()
        })
}

/// 一个采样窗口。由主循环按 `SAMPLE_WINDOW` 调用，息屏时不调用
pub fn tick(cfg: &AppConfig, cache: &ProcCache) {
    if !cfg.pmu_observe {
        shutdown();
        return;
    }

    let mut guard = lock_ignore_poison(&PMU);
    let p = guard.get_or_insert_with(Pmu::new);
    p.windows += 1;

    // 真实窗口长度：主循环 2 秒一跳，调用方是「距上次 >= 5 秒」才进来，
    // 实际窗口 6 秒左右。速率按固定 5 秒算会系统性偏高两成
    let now = Instant::now();
    let span = p
        .last_tick
        .map(|t| now.saturating_duration_since(t))
        .unwrap_or(SAMPLE_WINDOW)
        .clamp(Duration::from_millis(100), Duration::from_secs(60));
    p.last_tick = Some(now);
    let window_ms = span.as_millis() as u64;

    if let Some(reason) = p.off.clone() {
        publish(p, format!("不可用：{reason}"));
        return;
    }

    if p.budget == 0 {
        p.budget = fd_budget();
        if p.budget == 0 {
            // FD 预算是硬约束：硬开会在下一次写日志时 EMFILE，连带把
            // 别的功能弄坏。这里直接放弃，比「打开一半」可解释
            let reason = "FD 预算不足".to_string();
            disable(p, reason.clone());
            publish(p, format!("不可用：{reason}"));
            return;
        }
    }

    // 线程退出：FD 指向已死线程，计数会冻结在最后值。不清掉就会一直
    // 出现在「采样中」，增量却永远是 0
    let live: std::collections::HashSet<i32> = cache.tasks.keys().copied().collect();
    p.slots.retain(|tid, _| live.contains(tid));

    let mut fresh: Vec<Sample> = Vec::new();
    let mut active_tids: Vec<i32> = Vec::new();

    for (tid, entry) in &cache.tasks {
        let Some(st) = read_stat(*tid) else {
            continue;
        };
        let slot = p.slots.entry(*tid).or_insert_with(|| {
            // 首次见到：先把当前 tick 记成基线。本轮不判活跃——
            // 没有上一轮做对比，「有增量」这件事根本无从谈起
            Slot::new(
                st.starttime,
                st.ticks,
                entry.pkg.clone(),
                entry.comm.clone(),
            )
        });

        // tid 复用：线程退出后编号被新线程拿走，旧 FD 会继续指向死线程
        if slot.starttime != st.starttime {
            slot.close_all();
            slot.starttime = st.starttime;
            slot.prev = [0; EVENTS];
            slot.idle = 0;
            slot.pkg = entry.pkg.clone();
            slot.comm = entry.comm.clone();
        }

        // 必须先算增量再更新基线，否则「本轮有没有干活」永远为假
        let grew = st.ticks > slot.last_ticks;
        slot.last_ticks = st.ticks;

        if slot.any_fd() {
            if grew {
                slot.idle = 0;
                active_tids.push(*tid);
            } else {
                slot.idle = slot.idle.saturating_add(1);
                if slot.idle >= IDLE_WINDOWS {
                    // 长期空闲：回收 FD。再活跃时会重新打开
                    slot.close_all();
                    slot.idle = 0;
                    continue;
                }
            }
            match read_sample(slot, *tid, window_ms) {
                ReadOut::Got(s) => {
                    p.read_fails = 0;
                    p.read_err = None;
                    fresh.push(s);
                }
                ReadOut::Flat => {
                    p.read_fails = 0;
                    p.read_err = None;
                }
                ReadOut::Err(errno) => {
                    p.read_err = Some(errno);
                    p.read_fails = p.read_fails.saturating_add(1);
                }
            }
        } else if grew {
            active_tids.push(*tid);
        }
    }

    // 「有线程在跑」与「计数器在涨」是两件事。线程在跑但连续几个窗口
    // 一个计数器都没涨，只能是设备没向用户态开放 PMU 计数（厂商独占、
    // 内核未编入硬件事件）。这种情况以前被当成「没有活跃线程」，
    // 日志看起来像功能正常，实际一条数据都没有
    let busy = active_tids.len();
    if busy > 0 && p.open_threads() > 0 && fresh.is_empty() && p.read_err.is_none() {
        p.zero_windows = p.zero_windows.saturating_add(1);
        if p.zero_windows >= ZERO_WINDOWS && !p.blind_reported {
            p.blind_reported = true;
            let reason = "硬件计数器读数为 0（线程在跑，instructions/cycles 都不涨；\
                          内核或厂商未向用户态开放 PMU 计数）";
            disable(p, reason.to_string());
            publish(p, format!("不可用：{reason}"));
            return;
        }
    } else {
        p.zero_windows = 0;
    }

    // 只给「有 tick 增量」的线程开 FD。方案 16.2：活跃线程才开，
    // 否则 128 个 FD 会被一堆睡着的线程占满
    active_tids.sort_unstable();
    active_tids.dedup();
    for tid in active_tids {
        if p.open_threads() >= p.budget {
            break;
        }
        let Some(slot) = p.slots.get(&tid) else {
            continue;
        };
        if slot.any_fd() {
            continue;
        }
        if let Err((reason, fatal)) = open_slot(p, tid) {
            // 线程刚退出的 ESRCH 是常态，不该让整台机器的 PMU 陪葬；
            // 权限 / 内核不支持 / FD 耗尽才是一次性放弃的理由
            if !fatal {
                p.open_fails = p.open_fails.saturating_add(1);
            }
            if fatal || p.open_fails >= MAX_OPEN_FAILS {
                let reason = if fatal {
                    reason
                } else {
                    format!("连续 {MAX_OPEN_FAILS} 次打开失败：{reason}")
                };
                disable(p, reason.clone());
                publish(p, format!("不可用：{reason}"));
                return;
            }
        }
    }

    // 读失败连着来：FD 可能已经坏了（线程退出与新建撞在同一 tid 上时
    // 常见）。一直重开没有意义，说清 errno 比空转有用
    if p.read_fails >= MAX_OPEN_FAILS {
        let errno = p.read_err.unwrap_or(0);
        let reason = format!("读计数器连续失败（errno {errno}）");
        disable(p, reason.clone());
        publish(p, format!("不可用：{reason}"));
        return;
    }

    // 计数器没有增量的线程不进样本：它们只是「FD 还开着但这一轮没干活」，
    // 混进来会把「采样线程数」抬高，看日志的人会以为它们正在消耗 CPU。
    // 判据是「任一计数器涨了」而不是「instructions 涨了」——只放出 cycles
    // 的设备上，按 inst 判会把全部样本丢掉
    fresh.retain(Sample::is_active);
    fresh.sort_by(|a, b| b.cycles.cmp(&a.cycles).then(b.inst.cmp(&a.inst)));
    fresh.truncate(SNAP_SAMPLES);
    p.samples = fresh;

    let had = !p.samples.is_empty();
    let gap = if had || p.open_threads() > 0 {
        LOG_GAP
    } else {
        IDLE_LOG_GAP
    };
    if p.last_log.elapsed() >= gap || had != p.last_had_samples {
        p.last_log = Instant::now();
        p.last_had_samples = had;
        log_line(p);
    }
    publish(p, "运行中".to_string());
}

/// 息屏时暂停：关掉全部 FD。亮屏后会按活跃度重开，
/// 与 S7「息屏不采样」同一取舍——这段时间的计数不代表前台体验
pub fn pause() {
    let mut guard = lock_ignore_poison(&PMU);
    if let Some(p) = guard.as_mut() {
        if p.off.is_some() {
            return;
        }
        p.close_all();
        p.samples.clear();
        // 亮屏后的第一个窗口不能按「息屏了多久」算速率
        p.last_tick = None;
        publish(p, "息屏暂停".to_string());
    }
}

/// 配置关掉时清空。重复调用要便宜：主循环每轮都会调
fn shutdown() {
    let mut guard = lock_ignore_poison(&PMU);
    let Some(mut p) = guard.take() else {
        return;
    };
    p.close_all();
    *lock_ignore_poison(&SNAPSHOT) = Some(PmuSnapshot {
        state: "未启用".to_string(),
        ..Default::default()
    });
}

/// 一次性放弃。必须打日志：只在 Web 面板里写原因，不看界面的人会以为
/// 开关没生效。文案要点明「不影响绑核」，否则会被当成故障去排查
fn disable(p: &mut Pmu, reason: String) {
    crate::diag::tag(
        "PMU",
        &format!("已关闭：{reason}（只影响观察数据，绑核结果不受影响）"),
    );
    p.off = Some(reason);
    p.close_all();
}

fn publish(p: &Pmu, state: String) {
    *lock_ignore_poison(&SNAPSHOT) = Some(PmuSnapshot {
        state,
        fds: p.open_fds(),
        budget: p.budget,
        threads: p.open_threads(),
        windows: p.windows,
        miss_ok: p.miss_ok,
        samples: p.samples.clone(),
    });
}

fn log_line(p: &Pmu) {
    if p.samples.is_empty() {
        // 「没有线程在跑」和「开了 FD 却没有读数」是两种完全不同的状态：
        // 前者正常，后者说明计数器没工作。日志混成一句会把故障说成正常
        let threads = p.open_threads();
        let text = if threads > 0 {
            format!(
                "采样 {} 轮，{} 个线程的 FD 已打开但本窗口计数没有增长（上限 {} 线程）",
                p.windows, threads, p.budget
            )
        } else if !p.slots.is_empty() {
            // 有受管线程但都在睡：这是最常态的一行，不能写成「没有线程」，
            // 否则用户会以为扫描没找到进程
            format!(
                "采样 {} 轮，{} 个受管线程本轮没有消耗 CPU（未开 FD，上限 {} 线程）",
                p.windows,
                p.slots.len(),
                p.budget
            )
        } else {
            format!(
                "采样 {} 轮，没有受管线程（FD 未占用，上限 {} 线程）",
                p.windows, p.budget
            )
        };
        crate::diag::tag("PMU", &text);
        return;
    }
    let top = p
        .samples
        .iter()
        .take(LOG_SAMPLES)
        .map(|s| format!("{}({}) {}", s.comm, s.tid, s.rate_text()))
        .collect::<Vec<_>>()
        .join("、");
    let miss = if p.miss_ok {
        let m: u64 = p.samples.iter().filter_map(|s| s.misses).sum();
        format!(" ｜ cache-miss {}", m)
    } else {
        " ｜ cache-miss 不可用".to_string()
    };
    let window = p
        .samples
        .first()
        .map(|s| s.window_ms)
        .unwrap_or(SAMPLE_WINDOW.as_millis() as u64);
    crate::diag::tag(
        "PMU",
        &format!(
            "采样 {} 线程（FD {}，{} 线程）｜ 第 {} 轮 / {} ms ｜ {}{}",
            p.samples.len(),
            p.open_fds(),
            p.open_threads(),
            p.windows,
            window,
            top,
            miss
        ),
    );
}

/// 打开一个线程的全部事件。任一必选事件失败就返回关闭原因
fn open_slot(p: &mut Pmu, tid: i32) -> Result<(), (String, bool)> {
    let Some(slot) = p.slots.get_mut(&tid) else {
        return Ok(());
    };
    let want_miss = !p.miss_probed || p.miss_ok;
    let configs = [
        (INDEX_INST, PERF_COUNT_HW_INSTRUCTIONS),
        (INDEX_CYCLES, PERF_COUNT_HW_CPU_CYCLES),
    ];
    for (idx, config) in configs {
        match open_counter(tid, config) {
            Ok(fd) => {
                slot.fds[idx] = fd;
                slot.prev[idx] = 0;
            }
            Err(errno) => return Err(classify_open_error(errno)),
        }
    }
    if want_miss {
        match open_counter(tid, PERF_COUNT_HW_CACHE_MISSES) {
            Ok(fd) => {
                slot.fds[INDEX_MISS] = fd;
                slot.prev[INDEX_MISS] = 0;
                p.miss_ok = true;
            }
            Err(_) => {
                // 方案 16.2 要求「经设备核实」：打不开就只降级这一个事件，
                // 并在下一次日志里说明，不假装有数据
                p.miss_ok = false;
            }
        }
        p.miss_probed = true;
    }
    p.open_fails = 0;
    Ok(())
}

/// 一次读取的结果。三种情况必须分开：读到了且涨了、读到了但没涨、
/// 根本读不出来。混成一个 `Option` 会把「设备不计数」说成「线程没干活」
enum ReadOut {
    Got(Sample),
    /// 读成功，但这一窗口两个计数器都没涨
    Flat,
    /// 一个都没读出来，附带最后一次 errno
    Err(i32),
}

fn read_sample(slot: &mut Slot, tid: i32, window_ms: u64) -> ReadOut {
    let mut got = [0u64; EVENTS];
    let mut read_any = false;
    let mut err = 0;
    for (idx, out) in got.iter_mut().enumerate() {
        let fd = slot.fds[idx];
        if fd < 0 {
            continue;
        }
        match read_counter(fd) {
            Ok(v) => {
                *out = delta(v, slot.prev[idx]);
                slot.prev[idx] = v;
                read_any = true;
            }
            Err(errno) => {
                // 读失败（线程刚退出）就关掉，下一轮按需重开
                err = errno;
                unsafe { libc::close(fd) };
                slot.fds[idx] = -1;
            }
        }
    }
    if !read_any {
        return ReadOut::Err(err);
    }
    let s = Sample {
        tid,
        pkg: slot.pkg.clone(),
        comm: slot.comm.clone(),
        inst: got[INDEX_INST],
        cycles: got[INDEX_CYCLES],
        misses: (slot.fds[INDEX_MISS] >= 0).then_some(got[INDEX_MISS]),
        window_ms,
    };
    if s.is_active() {
        ReadOut::Got(s)
    } else {
        ReadOut::Flat
    }
}

/// 计数器增量。回绕或线程重建导致的倒退按「从 0 重新计」处理，
/// 得出负数是绝对不能进统计的
fn delta(cur: u64, prev: u64) -> u64 {
    cur.saturating_sub(prev)
}

fn open_counter(tid: i32, config: u64) -> Result<i32, i32> {
    let attr = PerfEventAttr {
        type_: PERF_TYPE_HARDWARE,
        size: PERF_ATTR_SIZE,
        config,
        // disabled = 0：立即开始计数；exclude_kernel 不设，CPI 要看完整执行
        flags: FLAG_EXCLUDE_HV,
        ..Default::default()
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            tid as libc::pid_t,
            -1i32,
            -1i32,
            0u64,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL))
    } else {
        Ok(ret as i32)
    }
}

fn read_counter(fd: i32) -> Result<u64, i32> {
    let mut v: u64 = 0;
    let n = unsafe {
        libc::read(
            fd,
            &mut v as *mut u64 as *mut libc::c_void,
            std::mem::size_of::<u64>(),
        )
    };
    if n == std::mem::size_of::<u64>() as isize {
        Ok(v)
    } else {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    }
}

/// 打开失败分三类：权限、环境不支持、FD 不够。三类的处置完全不同，
/// 混成一句「打开失败」会让用户不知道该改 `perf_event_paranoid` 还是
/// 该放弃这个功能
fn classify_open_error(errno: i32) -> (String, bool) {
    match errno {
        libc::EACCES | libc::EPERM => (
            "权限不足（内核 perf_event_paranoid 或 SELinux 限制）".to_string(),
            true,
        ),
        libc::EINVAL | libc::ENOENT | libc::EOPNOTSUPP | libc::ENOSYS => {
            ("内核或设备不支持硬件计数器".to_string(), true)
        }
        libc::EMFILE | libc::ENFILE => ("FD 预算耗尽".to_string(), true),
        // 线程刚退出：下一轮 `retain` 会清掉它，不能算作环境问题
        libc::ESRCH => ("线程已退出".to_string(), false),
        other => (format!("打开计数器失败（errno {other}）"), false),
    }
}

/// 可打开的线程数：`(RLIMIT_NOFILE 剩余) / 每线程事件数`，再按方案上限截断
fn fd_budget() -> usize {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return 0;
    }
    let used = fs::read_dir("/proc/self/fd")
        .map(|d| d.count() as u64)
        .unwrap_or(0);
    let avail = rl.rlim_cur.saturating_sub(used).saturating_sub(FD_RESERVE);
    ((avail / EVENTS as u64).min(MAX_THREADS as u64)) as usize
}

struct StatLine {
    /// utime + stime，单位 jiffies
    ticks: u64,
    starttime: u64,
}

/// 读 `/proc/<tid>/stat`。comm 可能含空格与括号，必须从最后一个 `)` 之后解析
fn read_stat(tid: i32) -> Option<StatLine> {
    let s = fs::read_to_string(format!("/proc/{tid}/stat")).ok()?;
    let rest = &s[s.rfind(')')? + 1..];
    let mut it = rest.split_whitespace();
    // rest 的第一个 token 是字段 3（state），utime 是字段 14 → 第 12 个
    let utime: u64 = it.nth(11)?.parse().ok()?;
    let stime: u64 = it.next()?.parse().ok()?;
    // starttime 是字段 22：stime(15) 之后还有 6 个字段
    let starttime: u64 = it.nth(6)?.parse().ok()?;
    Some(StatLine {
        ticks: utime + stime,
        starttime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(inst: u64, cycles: u64) -> Sample {
        Sample {
            tid: 1,
            pkg: "com.a".into(),
            comm: "T".into(),
            inst,
            cycles,
            misses: None,
            window_ms: SAMPLE_WINDOW.as_millis() as u64,
        }
    }

    #[test]
    fn cpi_and_rate() {
        let s = sample(1_000, 2_000);
        assert!((s.cpi() - 2.0).abs() < 1e-9);
        // 5 秒窗口：1000 条指令 / 5 秒 = 200 条每秒 = 0.0002 M/s
        assert!((s.mips() - 0.0002).abs() < 1e-12);
        assert!((s.gcyc() - 0.0000004).abs() < 1e-12);
        // 指令为 0 时不能出现 inf / NaN
        let z = sample(0, 100);
        assert_eq!(z.cpi(), 0.0);
    }

    /// 计数器倒退只能是线程重建或回绕，绝不能算出负数
    #[test]
    fn delta_never_negative() {
        assert_eq!(delta(120, 100), 20);
        assert_eq!(delta(5, 100), 0);
        assert_eq!(delta(u64::MAX, u64::MAX - 1), 1);
    }

    /// 真机上出现过「128 个 FD 都开着，日志却永远写没有活跃线程」：
    /// 部分内核只放出 cycles，instructions 恒为 0，按 inst 判活跃会把
    /// 全部样本丢掉。活跃判据必须是「任一计数器涨了」
    #[test]
    fn cycles_only_still_counts_as_active() {
        let s = sample(0, 5_000_000);
        assert!(s.is_active(), "只有 cycles 的样本不能被丢掉");
        assert_eq!(s.cpi(), 0.0);
        assert!(s.rate_text().contains("Gcyc/s"));
        let idle = sample(0, 0);
        assert!(!idle.is_active());
    }

    /// 速率要按真实窗口算。主循环 2 秒一跳，实际窗口 6 秒，
    /// 固定按 5 秒除会系统性偏高
    #[test]
    fn rate_uses_actual_window() {
        let mut s = sample(6_000_000, 12_000_000_000);
        s.window_ms = 6_000;
        // 600 万条 / 6 秒 = 1 M/s；120 亿周期 / 6 秒 = 2 Gcyc/s
        assert!((s.mips() - 1.0).abs() < 1e-9);
        assert!((s.gcyc() - 2.0).abs() < 1e-9);
        s.window_ms = 0; // 除零不能出 inf
        assert!(s.mips().is_finite() && s.gcyc().is_finite());
    }

    /// 失败分类决定用户该改内核参数还是该放弃功能，不能混；
    /// ESRCH 必须是非致命——线程退出是常态
    #[test]
    fn open_errors_are_classified() {
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::EINVAL,
            libc::EOPNOTSUPP,
            libc::EMFILE,
        ] {
            let (_, fatal) = classify_open_error(errno);
            assert!(fatal, "errno {errno} 应判定为致命");
        }
        assert!(classify_open_error(libc::EACCES).0.contains("权限"));
        assert!(classify_open_error(libc::EINVAL).0.contains("不支持"));
        assert!(classify_open_error(libc::EMFILE).0.contains("FD"));
        assert!(
            !classify_open_error(libc::ESRCH).1,
            "线程退出不能拖垮整个 PMU"
        );
    }

    /// stat 字段偏移错一位，活跃预筛就会永远判成「不活跃」，
    /// 表现为 PMU 一个 FD 都不开。这里直接读自己的 stat 核对
    #[test]
    fn stat_fields_are_parsed_from_last_paren() {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        let a = read_stat(tid).expect("读不到自身 stat");
        let b = read_stat(tid).expect("读不到自身 stat");
        assert_eq!(a.starttime, b.starttime, "starttime 必须稳定");
        assert!(a.starttime > 0);
        // 同一线程的 tick 只增不减
        assert!(b.ticks >= a.ticks);
    }

    /// FD 预算是硬上限：每线程 3 个 FD + 预留，不能超过 128 线程
    #[test]
    fn fd_budget_is_capped() {
        let n = fd_budget();
        assert!(n <= MAX_THREADS, "方案上限 128，实得 {n}");
    }

    /// `perf_event_attr` 是我们手写的内核 ABI 结构：字段顺序或对齐错一位，
    /// 内核会把 `config` 读成别的值，`perf_event_open` 成功但计数器不计数。
    /// 真机上「FD 开着却没有读数」正是这个症状，所以布局要锁死
    #[test]
    fn perf_attr_layout_matches_kernel_abi() {
        use std::mem::{offset_of, size_of};
        assert_eq!(offset_of!(PerfEventAttr, type_), 0);
        assert_eq!(offset_of!(PerfEventAttr, size), 4);
        assert_eq!(offset_of!(PerfEventAttr, config), 8);
        assert_eq!(offset_of!(PerfEventAttr, flags), 40);
        assert_eq!(size_of::<PerfEventAttr>(), 72);
        // 声明 64 字节时内核只读前 64 字节，必须真的够长
        assert!(size_of::<PerfEventAttr>() >= PERF_ATTR_SIZE as usize);
    }

    /// 关掉开关后快照必须回到「未启用」，FD 全部关闭
    #[test]
    fn shutdown_resets_snapshot() {
        shutdown();
        let s = snapshot();
        assert_eq!(s.state, "未启用");
        assert_eq!(s.fds, 0);
    }
}
