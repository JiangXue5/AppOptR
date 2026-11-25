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
/// 日志里最多列几条最忙线程
const LOG_SAMPLES: usize = 3;
/// Web 快照里最多保留几条
const SNAP_SAMPLES: usize = 8;
/// 日志间隔：每 30 秒一行，5 秒一行等于刷屏
const LOG_GAP: Duration = Duration::from_secs(30);

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
}

impl Sample {
    /// 每指令周期数。指令为 0 时没有意义，返回 0
    pub fn cpi(&self) -> f64 {
        if self.inst == 0 {
            return 0.0;
        }
        self.cycles as f64 / self.inst as f64
    }

    /// 每毫秒指令数，用来横向比较线程的忙闲
    pub fn inst_per_ms(&self) -> f64 {
        self.inst as f64 / SAMPLE_WINDOW.as_millis() as f64
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
            // 首轮就打印一次：30 秒后才出声，用户会以为开关没生效
            last_log: Instant::now()
                .checked_sub(LOG_GAP)
                .unwrap_or_else(Instant::now),
            last_had_samples: false,
        }
    }

    fn fd_count(&self) -> usize {
        self.slots.values().filter(|s| s.any_fd()).count()
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
            if let Some(s) = read_sample(slot, *tid) {
                fresh.push(s);
            }
        } else if grew {
            active_tids.push(*tid);
        }
    }

    // 只给「有 tick 增量」的线程开 FD。方案 16.2：活跃线程才开，
    // 否则 128 个 FD 会被一堆睡着的线程占满
    active_tids.sort_unstable();
    active_tids.dedup();
    for tid in active_tids {
        if p.fd_count() >= p.budget {
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

    // 增量为 0 的线程不进样本：它们只是「FD 还开着但这一轮没干活」，
    // 混进来会把「采样线程数」抬高，看日志的人会以为它们正在消耗 CPU
    fresh.retain(|s| s.inst > 0);
    fresh.sort_by(|a, b| b.inst.cmp(&a.inst));
    fresh.truncate(SNAP_SAMPLES);
    p.samples = fresh;

    let had = !p.samples.is_empty();
    if p.last_log.elapsed() >= LOG_GAP || had != p.last_had_samples {
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
    let fds = p.slots.values().map(Slot::fd_count).sum();
    let threads = p.slots.values().filter(|s| s.any_fd()).count();
    *lock_ignore_poison(&SNAPSHOT) = Some(PmuSnapshot {
        state,
        fds,
        budget: p.budget,
        threads,
        windows: p.windows,
        miss_ok: p.miss_ok,
        samples: p.samples.clone(),
    });
}

fn log_line(p: &Pmu) {
    if p.samples.is_empty() {
        crate::diag::tag(
            "PMU",
            &format!(
                "采样 {} 轮，本窗口没有活跃线程（FD {}/{} 可用）",
                p.windows,
                p.fd_count(),
                p.budget
            ),
        );
        return;
    }
    let top = p
        .samples
        .iter()
        .take(LOG_SAMPLES)
        .map(|s| {
            format!(
                "{}({}) {:.1}M/s CPI {:.2}",
                s.comm,
                s.tid,
                s.inst_per_ms(),
                s.cpi()
            )
        })
        .collect::<Vec<_>>()
        .join("、");
    let miss = if p.miss_ok {
        let m: u64 = p.samples.iter().filter_map(|s| s.misses).sum();
        format!(" ｜ cache-miss {}", m)
    } else {
        " ｜ cache-miss 不可用".to_string()
    };
    crate::diag::tag(
        "PMU",
        &format!(
            "采样 {} 线程（FD {}/{}）｜ 第 {} 轮 ｜ {}{}",
            p.samples.len(),
            p.fd_count(),
            p.budget,
            p.windows,
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

fn read_sample(slot: &mut Slot, tid: i32) -> Option<Sample> {
    let mut got = [0u64; EVENTS];
    let mut any = false;
    for (idx, out) in got.iter_mut().enumerate() {
        let fd = slot.fds[idx];
        if fd < 0 {
            continue;
        }
        match read_counter(fd) {
            Ok(v) => {
                *out = delta(v, slot.prev[idx]);
                slot.prev[idx] = v;
                any = true;
            }
            Err(()) => {
                // 读失败（线程刚退出）就关掉，下一轮按需重开
                unsafe { libc::close(fd) };
                slot.fds[idx] = -1;
            }
        }
    }
    if !any {
        return None;
    }
    Some(Sample {
        tid,
        pkg: slot.pkg.clone(),
        comm: slot.comm.clone(),
        inst: got[INDEX_INST],
        cycles: got[INDEX_CYCLES],
        misses: (slot.fds[INDEX_MISS] >= 0).then_some(got[INDEX_MISS]),
    })
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

fn read_counter(fd: i32) -> Result<u64, ()> {
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
        Err(())
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
        }
    }

    #[test]
    fn cpi_and_rate() {
        let s = sample(1_000, 2_000);
        assert!((s.cpi() - 2.0).abs() < 1e-9);
        // 5 秒窗口
        assert!((s.inst_per_ms() - 0.2).abs() < 1e-9);
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

    /// 关掉开关后快照必须回到「未启用」，FD 全部关闭
    #[test]
    fn shutdown_resets_snapshot() {
        shutdown();
        let s = snapshot();
        assert_eq!(s.state, "未启用");
        assert_eq!(s.fds, 0);
    }
}
