//! 运行期诊断：把「绑了没绑上」「S7 为什么不动」「是不是在掉帧」变成可读日志。
//!
//! 三层信息，按开销从低到高：
//!
//! - **计数**：每次亲和性写入的结果与 errno 分桶，只是几个原子加。
//! - **事件环**：最近若干条失败 / 回弹 / 冻结，供 Web 与日志摘要读取。
//! - **线程表与卡顿采样**：由主循环低频刷新，读 `/proc/<tid>/schedstat`，
//!   只统计 Critical 线程，用来判断「S7 迁移之后渲染线程是不是在等 CPU」。
//!
//! 设计上不做采样线程、不写文件：诊断依附主循环，关掉 S7 后除计数外零开销。

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::apply_affinity::ApplyReason;
use crate::cache::ProcCache;
use crate::cpuset::{CpuSet, SysGroup};
use crate::lock_ignore_poison;
use crate::roles::{Role, role_of};
use crate::sched::{SKIP_ALLOW, SKIP_LABELS, SchedSnapshot};

/// 事件环上限。比 S7 的 8 条更宽一点，够看清一次抖动的前后因果
const EVENT_CAP: usize = 12;
/// 失败日志最小间隔，避免一个必然失败的线程每秒刷屏
const FAIL_LOG_GAP: Duration = Duration::from_secs(5);
/// 同一线程的同一 errno 单独节流。「线程在后台组、目标在大核」是持续状态，
/// 每 5 秒重复一遍只会把真正有用的行挤掉
const FAIL_LOG_GAP_TID: Duration = Duration::from_secs(60);
/// 周期摘要间隔
pub const SUMMARY_GAP: Duration = Duration::from_secs(60);
/// 卡顿信号阈值：Critical 线程单次就绪等待均值超过它才上报
const JANK_WARN_MS: f64 = 4.0;
/// 卡顿日志最小间隔
const JANK_LOG_GAP: Duration = Duration::from_secs(30);
/// 线程表最多保留的条目，避免 Web 一次拉太多
const THREAD_CAP: usize = 160;
/// 每个摘要周期最多保留的漂移样例，够看清模式即可
const DRIFT_CAP: usize = 4;
/// 漂移样例的即时打印间隔
const DRIFT_LOG_GAP: Duration = Duration::from_secs(30);
/// cpuset 失败后打印完整上下文的间隔
const CPUSET_DETAIL_GAP: Duration = Duration::from_secs(300);

static START: OnceLock<Instant> = OnceLock::new();

/// 进程启动至今的秒数。静态 musl 下 localtime 依赖 TZ/tzdata，Android 上会静默
/// 退化成 UTC，反而误导；相对时间零依赖，且能精确看出「两次失败隔了多久」
pub fn uptime() -> f64 {
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// 运行期日志统一出口：加相对时间戳。
/// 掉帧是时序问题，没有时间戳的日志无法回答「什么时候开始的、隔了多久」
pub fn emit(line: &str) {
    eprintln!("[+{:.1}s] {}", uptime(), line);
}

/// 一次亲和性写入的累计计数
#[derive(Clone, Default)]
pub struct AffinityStats {
    pub calls: u64,
    /// 内核真的接受了新的集合
    pub writes: u64,
    /// 读回已经一致，短路返回
    pub noop: u64,
    /// 线程已退出
    pub gone: u64,
    pub failed: u64,
    pub eperm: u64,
    pub einval: u64,
    pub enosys: u64,
    pub other: u64,
    /// cpuset 目录写入失败次数（此时仅靠 sched_setaffinity）
    pub cpuset_fail: u64,
    /// 校验时读回是期望的子集：被 cpuset 的 effective_cpus 裁掉
    pub clip: u64,
    /// 校验时读回是期望的超集：被整体重置（热插拔、别的组件写回了全核）
    pub reset: u64,
    /// 校验时读回与期望互不包含：被挪到了另一个簇
    pub shifted: u64,
    /// 写入成功后回读仍不一致：cpuset 把它裁掉了，重绑不会生效
    pub ineffective: u64,
    /// 因上述原因被跳过重绑的次数
    pub stuck_skip: u64,
    /// 线程被系统放在后台组、规则目标不在该组内而主动跳过的次数
    pub sysgroup_skip: u64,
    /// 目标集合与线程所在组的生效集合没有交集：内核必然拒绝，
    /// 计成「挪簇」会让人以为线程被搬了几百次，实际是几百次失败
    pub unreachable: u64,
    /// 按原因拆分
    pub rule: u64,
    pub sync: u64,
    pub sched: u64,
}

impl AffinityStats {
    pub fn errno_line(&self) -> String {
        let mut parts = Vec::new();
        for (n, v) in [
            ("EPERM", self.eperm),
            ("EINVAL", self.einval),
            ("ENOSYS", self.enosys),
            ("其他", self.other),
        ] {
            if v > 0 {
                parts.push(format!("{} {}", n, v));
            }
        }
        if parts.is_empty() {
            "无".to_string()
        } else {
            parts.join(" / ")
        }
    }
}

struct Sink {
    stats: AffinityStats,
    events: VecDeque<String>,
    last_fail_log: Option<(i32, Instant)>,
    /// 每条线程各自的最近一次失败播报，避免持续失败刷屏
    fail_tid: HashMap<(i32, i32), Instant>,
    last_summary: Instant,
    last_jank_log: Instant,
    /// 本轮摘要周期内新增的失败数，用于决定要不要打摘要
    fail_since_summary: u64,
    rewrite_since_summary: u64,
    cpuset_since_summary: u64,
    /// 本周期内的漂移样例（期望、实际、线程所在 cpuset）
    drift: Vec<Drift>,
    /// 本周期漂移的分类计数：裁剪 / 重置 / 挪簇
    drift_kind: [u64; 3],
    /// 本周期因系统后台组跳过的次数
    sysgroup_since_summary: u64,
    /// 本周期「目标与所在组无交集」的次数与首个样例
    unreachable_since_summary: u64,
    unreachable_sample: Option<(String, i32, String, String)>,
    /// 已经说明过的组，同类只播报一次
    sysgroup_announced: HashSet<SysGroup>,
    /// 本周期「写后回读仍不一致」的样本与计数
    ineffective: Vec<Drift>,
    ineffective_n: u64,
    stuck_skip: u64,
    /// 上一次 cpuset 完整上下文的打印时刻
    last_detail: Option<Instant>,
    /// 上一次看到的在线 CPU 集合，用于识别热插拔
    last_online: Option<String>,
    /// 上一次 S7 快照，摘要里做差得到本周期增量
    last_snap: Option<SchedSnapshot>,
    /// 上一次即时打印漂移样例的时刻
    last_drift_log: Instant,
    /// 「规则只覆盖一个簇」这条说明已经给过：它是静态结论，
    /// 每 60 秒重复一遍只会把真正变化的行挤掉
    allow_hint_shown: bool,
}

/// 一次「读回与期望不一致」的现场。期望/实际的组合能直接区分根因：
/// 实际是期望的子集＝被 cpuset 裁剪；实际是超集＝被整体重置；互不包含＝被挪簇
#[derive(Clone)]
pub struct Drift {
    pub tid: i32,
    pub comm: String,
    pub expect: String,
    pub actual: String,
    pub cpuset: String,
}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);
static INIT: AtomicBool = AtomicBool::new(false);

fn sink() -> std::sync::MutexGuard<'static, Option<Sink>> {
    let mut guard = lock_ignore_poison(&SINK);
    let now = Instant::now();
    guard.get_or_insert_with(|| Sink {
        stats: AffinityStats::default(),
        events: VecDeque::new(),
        last_fail_log: None,
        fail_tid: HashMap::new(),
        last_summary: now,
        last_jank_log: now,
        fail_since_summary: 0,
        rewrite_since_summary: 0,
        cpuset_since_summary: 0,
        drift: Vec::new(),
        drift_kind: [0; 3],
        sysgroup_since_summary: 0,
        unreachable_since_summary: 0,
        unreachable_sample: None,
        sysgroup_announced: HashSet::new(),
        ineffective: Vec::new(),
        ineffective_n: 0,
        stuck_skip: 0,
        last_detail: None,
        last_online: None,
        last_snap: None,
        // 首条漂移立即打印，不因初始化时刻被 30 秒节流挡住
        last_drift_log: now.checked_sub(DRIFT_LOG_GAP).unwrap_or(now),
        allow_hint_shown: false,
    });
    guard
}

/// 启动时打一次，让用户知道这些日志在哪、怎么看
pub fn announce() {
    if INIT.swap(true, Ordering::AcqRel) {
        return;
    }
    // 尽早占位，后面所有时间戳都以这里为零点
    let _ = uptime();
    emit(
        "诊断: 行首 [+秒] 是启动后耗时；绑核失败会带 errno 与 cpuset 现场，\
         校验发现被改写会给出「期望/实际/线程所在 cpuset」，S7 无动作时每个周期说明原因",
    );
}

/// 记录一次写入结果。`wrote` 为 true 表示内核真的接受了新集合
pub fn note(reason: ApplyReason, outcome: &crate::apply_affinity::AffinityOutcome, wrote: bool) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.calls += 1;
    match reason {
        ApplyReason::Rule => s.stats.rule += 1,
        ApplyReason::Sync => {
            s.stats.sync += 1;
            if wrote {
                s.rewrite_since_summary += 1;
            }
        }
        ApplyReason::Sched => s.stats.sched += 1,
    }
    if wrote {
        s.stats.writes += 1;
    }
    match outcome {
        crate::apply_affinity::AffinityOutcome::Set => {
            if !wrote {
                s.stats.noop += 1;
            }
        }
        crate::apply_affinity::AffinityOutcome::Gone => s.stats.gone += 1,
        crate::apply_affinity::AffinityOutcome::Failed => {}
    }
}

/// 失败明细。同一条线程 5 秒内只打一次，避免必然失败的调用刷屏；
/// errno 不同则各打一次，能看到「一会儿 EINVAL 一会儿 EPERM」这种混合原因
pub fn note_failure(tid: i32, comm: &str, want: &CpuSet, errno: i32) {
    let hint = errno_hint(errno);
    let line = if comm.is_empty() {
        format!(
            "绑核失败: tid {} → {}（{}）",
            tid,
            want.to_range_string(),
            hint
        )
    } else {
        format!(
            "绑核失败: {}({}) → {}（{}）",
            comm,
            tid,
            want.to_range_string(),
            hint
        )
    };

    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.failed += 1;
    s.fail_since_summary += 1;
    match errno {
        libc::EPERM | libc::EACCES => s.stats.eperm += 1,
        libc::EINVAL => s.stats.einval += 1,
        libc::ENOSYS => s.stats.enosys += 1,
        _ => s.stats.other += 1,
    }
    push_event(s, line.clone());

    // 两层节流：全局 5 秒一条防大面积刷屏；同一线程同一 errno 60 秒一条，
    // 因为「线程被系统固定在后台组」不会因为多写一次日志就改变
    let now = Instant::now();
    let global_due = s
        .last_fail_log
        .is_none_or(|(_, at)| now.duration_since(at) >= FAIL_LOG_GAP);
    let tid_due = s
        .fail_tid
        .get(&(tid, errno))
        .is_none_or(|at| now.duration_since(*at) >= FAIL_LOG_GAP_TID);
    if !(global_due && tid_due) {
        return;
    }
    emit(&line);
    s.last_fail_log = Some((errno, now));
    s.fail_tid.insert((tid, errno), now);
    if s.fail_tid.len() > 256 {
        s.fail_tid
            .retain(|_, at| now.duration_since(*at) < FAIL_LOG_GAP_TID);
    }
    // EINVAL 里最常见的一类不是权限，而是线程所在组的生效集合与目标无交集。
    // 只报「目标集合非法」等于没说，必须把线程被固定在哪一组写出来
    if errno == libc::EINVAL
        && let Some(why) = unreachable_note(tid, want)
    {
        push_event(s, why.clone());
        emit(&why);
    }
}

/// 线程「绑不上」的系统侧原因：所在 cgroup 的生效集合与目标没有交集时，
/// 内核会同时拒绝 cgroup 迁移与 sched_setaffinity，改规则之外没有别的出路
fn unreachable_note(tid: i32, want: &CpuSet) -> Option<String> {
    let path = crate::cpuset::thread_cgroup(tid)?;
    let eff = crate::cpuset::group_effective(&path)?;
    let eff_set = crate::cpuset::parse_cpu_ranges(&eff, None);
    if eff_set.count() == 0 {
        return None;
    }
    let mut inter = *want;
    inter.and(&eff_set);
    if inter.count() > 0 {
        return None;
    }
    let group = crate::cpuset::classify_group(&path);
    Some(format!(
        "原因: 线程在 {}({})，与目标 {} 无交集，属系统分组限制；要绑到大核必须先把线程迁出该组",
        path,
        eff,
        want.to_range_string()
    ))
    .map(|s| format!("{}（{}）", s, group.label()))
}

/// cpuset 目录写入失败。真相是「绑核还有 sched_setaffinity 兜底」，
/// 但如果设备上 cpuset 只读又叠加应用自己改亲和性，就会表现为绑不住。
/// 首次失败（以及每 5 分钟）打一次完整现场：只报 errno 说不清是目录没建成、
/// 父级 cpus 为空，还是线程原本就在别的 cpuset 里
pub fn note_cpuset_failure(tid: i32, dir: &str, fail: crate::apply_affinity::CpusetFail) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.cpuset_fail += 1;
    s.cpuset_since_summary += 1;
    let line = match fail.errno() {
        Some(e) => format!(
            "cpuset: 写入 {}/tasks 失败（{}；{}），本次只靠绑核",
            dir,
            errno_hint(e),
            fail.label()
        ),
        None => format!(
            "cpuset: 写入 {}/tasks 失败（{}），本次只靠绑核",
            dir,
            fail.label()
        ),
    };
    push_event(s, line.clone());
    // 这类失败通常是持续性的，只在首次与每 60 秒摘要里出现
    if s.stats.cpuset_fail == 1 {
        emit(&line);
    }
    let due = s
        .last_detail
        .is_none_or(|at| at.elapsed() >= CPUSET_DETAIL_GAP);
    if due {
        s.last_detail = Some(Instant::now());
        let detail = cpuset_detail(dir, tid);
        for l in detail {
            push_event(s, l.clone());
            emit(&l);
        }
    }
}

/// 读一次 cpuset 现场。这些文件都很小，只在失败时读，开销可以忽略
fn cpuset_detail(dir: &str, tid: i32) -> Vec<String> {
    let base = crate::cpuset::base_cpuset();
    let target = if dir.is_empty() {
        base.clone()
    } else {
        format!("{}/{}", base, dir)
    };
    let read = |p: &str| {
        fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "-".to_string())
    };
    // v1 与 v2 的生效集合文件名不同，只读一种会让这一格永远是 `-`，
    // 而它恰好是判断「内核为什么不接受」的唯一依据
    let eff = |p: &str| crate::cpuset::read_effective(p).unwrap_or_else(|| "-".to_string());
    let group_path = crate::cpuset::thread_cgroup(tid).unwrap_or_else(|| "-".to_string());
    let group_eff = crate::cpuset::group_effective(&group_path).unwrap_or_else(|| "-".to_string());
    let group = crate::cpuset::classify_group(&group_path);
    let target_cpus = read(&format!("{}/cpus", target));
    let reachable = if group_eff == "-" || target_cpus == "-" {
        "可达性未知（读不到生效集合）"
    } else {
        let mut inter = crate::cpuset::parse_cpu_ranges(&target_cpus, None);
        inter.and(&crate::cpuset::parse_cpu_ranges(&group_eff, None));
        if inter.count() == 0 {
            "与目标无交集，内核必然拒绝"
        } else {
            "与目标有交集"
        }
    };
    vec![
        format!(
            "cpuset 现场: 目标[{}] cpus={} mems={} effective={}",
            target,
            target_cpus,
            read(&format!("{}/mems", target)),
            eff(&target),
        ),
        format!(
            "cpuset 现场: 父[{}] cpus={} mems={} effective={}",
            base,
            read(&format!("{}/cpus", base)),
            read(&format!("{}/mems", base)),
            eff(&base),
        ),
        format!(
            "cpuset 现场: 线程 {} 所在组 {}({}，{}组) {}；根[/dev/cpuset] cpus={} mems={}",
            tid,
            group_path,
            group_eff,
            group.label(),
            reachable,
            read("/dev/cpuset/cpus"),
            read("/dev/cpuset/mems"),
        ),
    ]
}

/// cpuset 连续失败触发熔断。继续每秒重试既改变不了结果，又会在失败路径上
/// 反复进内核（open/write），反而加重本已紧张的调度
pub fn note_cpuset_tripped(err: Option<i32>, fails: u32, pause: Duration) {
    let line = format!(
        "cpuset: 连续 {} 次写入失败（{}），暂停 {} 秒不再尝试；绑定完全交给 sched_setaffinity",
        fails,
        err.map(errno_hint)
            .unwrap_or_else(|| "目录未建成".to_string()),
        pause.as_secs()
    );
    emit(&line);
    let mut guard = sink();
    if let Some(s) = guard.as_mut() {
        push_event(s, line);
    }
}

/// 目标集合与线程所在 cgroup 的生效集合是否完全无交集。
/// 无交集时内核在 `cpuset_can_attach` 与 `sched_setaffinity` 两处都返回
/// EINVAL，写多少次都不会生效，唯一的出路是改规则或把线程迁出该组
fn unreachable_group(tid: i32, want: &CpuSet) -> bool {
    let Some(path) = crate::cpuset::thread_cgroup(tid) else {
        return false;
    };
    let Some(eff) = crate::cpuset::group_effective(&path) else {
        return false;
    };
    let eff_set = crate::cpuset::parse_cpu_ranges(&eff, None);
    if eff_set.count() == 0 {
        return false;
    }
    let mut inter = *want;
    inter.and(&eff_set);
    inter.count() == 0
}

/// 校验时读回与期望不一致：记录分类与现场样本。
/// 分类比数字有用——「实际是期望的子集」和「实际变回全核」是两种完全不同的故障
pub fn note_drift(tid: i32, comm: &str, expect: &CpuSet, actual: &CpuSet) {
    let kind = if actual.subset_of(expect) {
        DriftKind::Clip
    } else if expect.subset_of(actual) {
        DriftKind::Reset
    } else {
        DriftKind::Shifted
    };
    // 判定要读 /proc 与 cgroup，放在持锁之前。只有「互不包含」才可能
    // 是「目标与所在组无交集」，另外两类本身就在同一个组里，不可能不可达
    let unreachable = kind == DriftKind::Shifted && unreachable_group(tid, expect);
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    if unreachable {
        s.stats.unreachable += 1;
        s.unreachable_since_summary += 1;
        if s.unreachable_sample.is_none() {
            s.unreachable_sample = Some((
                comm.to_string(),
                tid,
                expect.to_range_string(),
                read_thread_cpuset(tid),
            ));
        }
        return;
    }
    match kind {
        DriftKind::Clip => {
            s.stats.clip += 1;
            s.drift_kind[0] += 1;
        }
        DriftKind::Reset => {
            s.stats.reset += 1;
            s.drift_kind[1] += 1;
        }
        DriftKind::Shifted => {
            s.stats.shifted += 1;
            s.drift_kind[2] += 1;
        }
    }
    let sample = Drift {
        tid,
        comm: comm.to_string(),
        expect: expect.to_range_string(),
        actual: actual.to_range_string(),
        cpuset: read_thread_cpuset(tid),
    };
    if s.drift.len() < DRIFT_CAP {
        s.drift.push(sample.clone());
    }
    // 第一批异常当场打一条，不等 60 秒摘要：掉帧往往就在这几秒内
    if s.last_drift_log.elapsed() >= DRIFT_LOG_GAP {
        s.last_drift_log = Instant::now();
        let line = format!(
            "漂移: {}({}) 期望 {} 实际 {} cpuset={}",
            sample.comm, sample.tid, sample.expect, sample.actual, sample.cpuset
        );
        emit(&line);
        push_event(s, line);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DriftKind {
    /// 读回比期望小：被 cpuset 的 effective_cpus 裁掉
    Clip,
    /// 读回比期望大：被整体重置
    Reset,
    /// 互不包含：被挪到别的簇
    Shifted,
}

fn read_thread_cpuset(tid: i32) -> String {
    fs::read_to_string(format!("/proc/{}/cpuset", tid))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

/// 写入返回成功、回读却仍是别的集合：cpuset 的 effective_cpus 在起作用，
/// 这种线程再重绑一万次也没用，只会反复迁移
pub fn note_ineffective(tid: i32, comm: &str, want: &CpuSet, after: &CpuSet) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.ineffective += 1;
    s.ineffective_n += 1;
    if s.ineffective.len() < 2 {
        s.ineffective.push(Drift {
            tid,
            comm: comm.to_string(),
            expect: want.to_range_string(),
            actual: after.to_range_string(),
            cpuset: read_thread_cpuset(tid),
        });
    }
}

/// 因「写了也白写」而跳过的一次重绑
pub fn note_stuck() {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.stuck_skip += 1;
    s.stuck_skip += 1;
}

/// 线程被系统放在后台组、规则目标又不在该组生效集合内。
/// 这不是失败：内核对 cgroup 迁移和 sched_setaffinity 都会返回 EINVAL，
/// 硬试只会把线程在簇之间来回踢。同类组只说明一次，其余进 60 秒摘要
pub fn note_sysgroup_skip(tid: i32, comm: &str, group: SysGroup, want: &CpuSet) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.sysgroup_skip += 1;
    s.sysgroup_since_summary += 1;
    if !s.sysgroup_announced.insert(group) {
        return;
    }
    let name = if comm.is_empty() {
        format!("tid {}", tid)
    } else {
        format!("{}({})", comm, tid)
    };
    let line = format!(
        "系统分组: {} 在 {} 组，规则要求 {} 不在该组内，内核会拒绝绑定；已跳过（不计失败）。要强制接管写 @sysgroup=takeover",
        name,
        group.label(),
        want.to_range_string()
    );
    emit(&line);
    push_event(s, line);
}

/// 校验轮里整批因系统分组被跳过。逐线程播报会把日志刷满，
/// 这里只累加计数，并在首次给出一次结论
pub fn note_sysgroup_batch(n: u64) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.sysgroup_skip += n;
    s.sysgroup_since_summary += n;
    if !s.sysgroup_announced.insert(SysGroup::Background) {
        return;
    }
    let line = format!(
        "系统分组: {} 个线程被系统限定在后台组，规则要求的大核不在该组生效集合内，内核会拒绝绑定；已跳过（不计失败）。切回前台会自动恢复，要强制接管写 @sysgroup=takeover",
        n
    );
    emit(&line);
    push_event(s, line);
}

/// 比较一次在线 CPU 集合，变化说明发生了热插拔。
/// cpuset 会在这个时机重算 effective_cpus 并重置组内线程的亲和性，
/// 这是「刚才绑住了、过一会儿又散了」最常见的成因
pub fn watch_cpu_online() -> Option<(String, String)> {
    let now = fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    let mut guard = sink();
    let s = guard.as_mut()?;
    let prev = s.last_online.replace(now.clone());
    match prev {
        Some(old) if old != now => {
            let line = format!(
                "CPU 在线集合变化: [{}] → [{}]（热插拔会重置 cpuset 组内线程的亲和性，\
                 接下来一轮校验会把它们全部重绑）",
                old, now
            );
            emit(&line);
            push_event(s, line);
            Some((old, now))
        }
        _ => None,
    }
}

/// 记录一次 S7 事件（迁移成功、回弹、冻结、失败），只进环，不直接上屏
pub fn note_sched(line: impl Into<String>) {
    let mut guard = sink();
    if let Some(s) = guard.as_mut() {
        push_event(s, line.into());
    }
}

/// S7 迁移失败要上屏：它解释了「线程为什么还停在原簇」
pub fn note_sched_failure(line: impl Into<String>) {
    let line = line.into();
    emit(&line);
    note_sched(line);
}

fn push_event(s: &mut Sink, line: String) {
    if s.events.len() >= EVENT_CAP {
        s.events.pop_front();
    }
    s.events.push_back(line);
}

fn errno_hint(errno: i32) -> String {
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

/// 主循环低频调用：只在有事发生时打行摘要，无事保持安静。
/// `current` 是 S7 的最新快照，用来回答「开关开着，为什么一个线程都没动」
pub fn periodic_summary(current: &SchedSnapshot) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    if s.last_summary.elapsed() < SUMMARY_GAP {
        return;
    }
    s.last_summary = Instant::now();
    let fails = std::mem::take(&mut s.fail_since_summary);
    let rewrites = std::mem::take(&mut s.rewrite_since_summary);
    let cpuset = std::mem::take(&mut s.cpuset_since_summary);
    let sysgroup = std::mem::take(&mut s.sysgroup_since_summary);
    let unreach = std::mem::take(&mut s.unreachable_since_summary);
    let unreach_sample = s.unreachable_sample.take();
    let kinds = std::mem::take(&mut s.drift_kind);
    let drift = std::mem::take(&mut s.drift);
    let ineff_n = std::mem::take(&mut s.ineffective_n);
    let ineff = std::mem::take(&mut s.ineffective);
    let stuck = std::mem::take(&mut s.stuck_skip);
    let prev = s.last_snap.replace(current.clone());
    let st = &s.stats;

    if fails > 0 {
        emit(&format!(
            "绑核: 近 {} 秒失败 {} 次（累计 {}，EPERM/EACCES {}、EINVAL {}、ENOSYS {}、其他 {}）",
            SUMMARY_GAP.as_secs(),
            fails,
            st.failed,
            st.eperm,
            st.einval,
            st.enosys,
            st.other
        ));
    }
    if rewrites > 0 {
        emit(&format!(
            "校验: 近 {} 秒重绑 {} 个线程（裁剪 {}、重置 {}、挪簇 {}）",
            SUMMARY_GAP.as_secs(),
            rewrites,
            kinds[0],
            kinds[1],
            kinds[2]
        ));
        // 样例比计数更能说明问题：期望/实际的组合直接指向是哪一类故障
        if rewrites >= 8 {
            for d in drift {
                emit(&format!(
                    "校验样例: {}({}) 期望 {} 实际 {} cpuset={}",
                    d.comm, d.tid, d.expect, d.actual, d.cpuset
                ));
            }
        }
    }
    if ineff_n > 0 {
        emit(&format!(
            "校验: {} 个线程写入返回成功但回读仍不一致（cpuset 裁剪），已暂停对其重绑 {} 秒，本轮跳过 {} 次无效重绑",
            ineff_n,
            crate::apply_affinity::STUCK_PAUSE.as_secs(),
            stuck
        ));
        for d in ineff {
            emit(&format!(
                "无效绑定: {}({}) 期望 {} 实际 {} cpuset={}",
                d.comm, d.tid, d.expect, d.actual, d.cpuset
            ));
        }
    }
    if unreach > 0 {
        // 持续状态：只在首次给样例，之后只报计数，否则每 60 秒重复同一句
        match unreach_sample {
            Some((comm, tid, expect, cpuset)) => emit(&format!(
                "不可达: 近 {} 秒 {} 个线程的目标集合与所在组无交集（累计 {}），如 {}({}) 期望 {} cpuset={}；内核会同时拒绝迁组与绑核，已跳过",
                SUMMARY_GAP.as_secs(),
                unreach,
                st.unreachable,
                comm,
                tid,
                expect,
                cpuset
            )),
            None => emit(&format!(
                "不可达: 近 {} 秒另有 {} 个线程的目标集合与所在组无交集（累计 {}）",
                SUMMARY_GAP.as_secs(),
                unreach,
                st.unreachable
            )),
        }
    }
    if sysgroup > 0 {
        emit(&format!(
            "系统分组: 近 {} 秒 {} 次因后台组跳过（累计 {}）；这些线程被系统限定在小核，不改规则就绑不上",
            SUMMARY_GAP.as_secs(),
            sysgroup,
            st.sysgroup_skip
        ));
    }
    if cpuset > 0 {
        let tail = if crate::apply_affinity::cpuset_paused() {
            "已暂停重试，等半开试探"
        } else {
            "仍在重试"
        };
        emit(&format!(
            "cpuset: 近 {} 秒 {} 次目录写入失败（累计 {}），{}；绑核由 sched_setaffinity 单独维持",
            SUMMARY_GAP.as_secs(),
            cpuset,
            st.cpuset_fail,
            tail
        ));
    }
    let mut hint = std::mem::take(&mut s.allow_hint_shown);
    if let Some(line) = sched_period_line(prev.as_ref(), current, &mut hint) {
        // 先释放锁再打日志，避免写 stdout 阻塞时把诊断入口一起卡住
        s.allow_hint_shown = hint;
        emit(&line);
    } else {
        s.allow_hint_shown = hint;
    }
}

/// S7 周期说明。开着的策略必须能自证「在看、在判、为什么不动」，
/// 否则用户只能看到「开了 S7 就掉帧」，却没有任何可查的因果
fn sched_period_line(
    prev: Option<&SchedSnapshot>,
    cur: &SchedSnapshot,
    allow_hint: &mut bool,
) -> Option<String> {
    if cur.mode == 0 {
        return None;
    }
    let gap = SUMMARY_GAP.as_secs();
    let d = |now: u64, before: u64| now.saturating_sub(before);
    let (ticks, moved, would, bounced, frozen, probed) = match prev {
        Some(p) => (
            d(cur.ticks, p.ticks),
            d(cur.moved, p.moved),
            d(cur.would, p.would),
            d(cur.bounced, p.bounced),
            d(cur.frozen, p.frozen),
            d(cur.probed, p.probed),
        ),
        None => (
            cur.ticks,
            cur.moved,
            cur.would,
            cur.bounced,
            cur.frozen,
            cur.probed,
        ),
    };
    if ticks == 0 {
        // 一轮都没跑：状态本身就是要看的答案（off/不适用/等待进程）
        return Some(format!(
            "S7: 近 {} 秒未推进判定（状态：{}）",
            gap, cur.state
        ));
    }
    let skip = match prev {
        Some(p) => {
            let mut s = String::new();
            for (i, label) in SKIP_LABELS.iter().enumerate() {
                let v = d(cur.skip[i], p.skip[i]);
                if v > 0 {
                    if !s.is_empty() {
                        s.push_str(" / ");
                    }
                    s.push_str(&format!("{} {}", label, v));
                }
            }
            s
        }
        None => String::new(),
    };
    let load = format!("{}/{}/{}‰", cur.load[0], cur.load[1], cur.load[2]);
    let head = if cur.mode == 2 { "S7" } else { "S7(影子)" };
    let mut line = if cur.mode == 2 {
        format!(
            "{}: 近 {} 秒 {} 轮、探测 {} 线程、迁移 {} 次（累计 {}），回弹 {}、冻结 {}，簇负载 {}，状态 {}",
            head, gap, ticks, probed, moved, cur.moved, bounced, frozen, load, cur.state
        )
    } else {
        format!(
            "{}: 近 {} 秒 {} 轮、探测 {} 线程、本可迁移 {} 次（未执行），簇负载 {}，状态 {}",
            head, gap, ticks, probed, would, load, cur.state
        )
    };
    if !skip.is_empty() {
        line.push_str(&format!("；跳过：{}", skip));
    }
    // 一次都没动、且跳过几乎全是「允许集合不足两层」时，问题不在负载也不在策略，
    // 而是规则本身没跨簇。不明说这一句，用户只能看到「开着 S7 却完全没动」
    let allow_skip = match prev {
        Some(p) => d(cur.skip[SKIP_ALLOW], p.skip[SKIP_ALLOW]),
        None => cur.skip[SKIP_ALLOW],
    };
    if moved == 0 && would == 0 && probed > 0 && allow_skip * 10 >= probed * 9 && !*allow_hint {
        *allow_hint = true;
        line.push_str(
            "；说明：规则的允许集合都只覆盖一个簇，S7 没有可让位的目标，\
             规则写成跨簇（如 all-core）才会生效",
        );
    }
    Some(line)
}

/// Web 能看到的线程级诊断。`expect` 是规则算出的集合，`actual` 是内核当前值
#[derive(Clone)]
pub struct ThreadDiag {
    pub tid: i32,
    pub pkg: String,
    pub comm: String,
    pub expect: String,
    pub actual: String,
    pub ok: bool,
    pub role: &'static str,
}

static THREADS: Mutex<Vec<ThreadDiag>> = Mutex::new(Vec::new());

pub fn publish_threads(cache: &ProcCache) {
    let mut out: Vec<ThreadDiag> = Vec::new();
    for (&tid, e) in cache.tasks.iter().take(THREAD_CAP) {
        let actual = CpuSet::get_affinity(tid);
        let ok = actual.as_ref() == Some(&e.cpus);
        out.push(ThreadDiag {
            tid,
            pkg: e.pkg.clone(),
            comm: e.comm.clone(),
            expect: e.cpus.to_range_string(),
            actual: actual
                .map(|c| c.to_range_string())
                .unwrap_or_else(|| "已退出".to_string()),
            ok,
            role: role_label(role_of(&e.comm)),
        });
    }
    // 未绑住的排前面，其次按线程名，便于一眼看到异常项
    out.sort_by(|a, b| {
        a.ok.cmp(&b.ok)
            .then_with(|| a.comm.cmp(&b.comm))
            .then_with(|| a.tid.cmp(&b.tid))
    });
    *lock_ignore_poison(&THREADS) = out;
}

fn role_label(r: Role) -> &'static str {
    match r {
        Role::Critical => "关键",
        Role::Latency => "延迟",
        Role::Worker => "工作",
        Role::Background => "后台",
        Role::Unknown => "未知",
    }
}

/// 卡顿信号：Critical 线程在就绪队列上的平均等待
#[derive(Clone, Default)]
pub struct JankSample {
    pub tid: i32,
    pub comm: String,
    pub wait_ms: f64,
    pub switches: u64,
    /// 采样窗口内累计就绪等待，用于判断「等得久但次数少」这种假警报
    pub total_wait_ms: f64,
    /// 当前亲和性与最后一次运行的 CPU
    pub affinity: String,
    pub cpu: String,
}

static JANK: Mutex<Vec<JankSample>> = Mutex::new(Vec::new());

pub struct JankSampler {
    prev: HashMap<i32, (u64, u64)>,
    last: Instant,
}

impl Default for JankSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl JankSampler {
    pub fn new() -> Self {
        Self {
            prev: HashMap::new(),
            last: Instant::now(),
        }
    }

    /// 读取 Critical 线程的 `schedstat` 增量。返回本轮最差的几个，
    /// 同时把超过阈值的写进日志（30 秒最多一条，避免刷屏）
    pub fn sample(&mut self, cache: &ProcCache) -> Vec<JankSample> {
        let dt = self.last.elapsed();
        // 窗口太短时 ds 只有个位数，均值会被单次抖动带偏，宁可不报
        if dt < Duration::from_millis(800) {
            return lock_ignore_poison(&JANK).clone();
        }
        self.last = Instant::now();

        let mut out = Vec::new();
        for (&tid, e) in &cache.tasks {
            if role_of(&e.comm) != Role::Critical {
                continue;
            }
            let Some((runtime, wait, slices)) = read_schedstat(tid) else {
                continue;
            };
            let _ = runtime;
            if let Some((pw, ps)) = self.prev.insert(tid, (wait, slices)) {
                let dw = wait.saturating_sub(pw);
                let ds = slices.saturating_sub(ps);
                // 窗口内调度不到 8 次时，「平均等待」等于拿一两次偶发当结论
                if ds < 8 || dw == 0 {
                    continue;
                }
                let wait_ms = dw as f64 / ds as f64 / 1_000_000.0;
                out.push(JankSample {
                    tid,
                    comm: e.comm.clone(),
                    wait_ms,
                    switches: ds,
                    total_wait_ms: dw as f64 / 1_000_000.0,
                    affinity: CpuSet::get_affinity(tid)
                        .map(|c| c.to_range_string())
                        .unwrap_or_else(|| "-".to_string()),
                    cpu: thread_cpu(tid),
                });
            }
        }
        self.prev.retain(|tid, _| cache.tasks.contains_key(tid));
        out.sort_by(|a, b| b.wait_ms.total_cmp(&a.wait_ms));
        out.truncate(4);

        if let Some(worst) = out.first()
            && worst.wait_ms >= JANK_WARN_MS
        {
            let mut guard = sink();
            if let Some(s) = guard.as_mut()
                && s.last_jank_log.elapsed() >= JANK_LOG_GAP
            {
                s.last_jank_log = Instant::now();
                let line = format!(
                    "卡顿信号: {}({}) 就绪等待均值 {:.1} ms（{} 次调度，累计 {:.0} ms），affinity={}，最后运行 cpu={}",
                    worst.comm,
                    worst.tid,
                    worst.wait_ms,
                    worst.switches,
                    worst.total_wait_ms,
                    worst.affinity,
                    worst.cpu
                );
                emit(&line);
                push_event(s, line);
            }
        }

        *lock_ignore_poison(&JANK) = out.clone();
        out
    }
}

/// 线程最后一次运行的 CPU：`/proc/<tid>/stat` 第 39 字段。
/// comm 里可能有空格和括号，必须从最后一个 `)` 之后再切
fn thread_cpu(tid: i32) -> String {
    let Ok(s) = fs::read_to_string(format!("/proc/{}/stat", tid)) else {
        return "-".to_string();
    };
    let Some(pos) = s.rfind(')') else {
        return "-".to_string();
    };
    s[pos + 1..]
        .split_whitespace()
        .nth(36)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// `/proc/<tid>/schedstat` 三个字段：累计运行 ns、累计就绪等待 ns、调度次数
fn read_schedstat(tid: i32) -> Option<(u64, u64, u64)> {
    let s = fs::read_to_string(format!("/proc/{}/schedstat", tid)).ok()?;
    let mut it = s.split_whitespace();
    let runtime = it.next()?.parse().ok()?;
    let wait = it.next()?.parse().ok()?;
    let slices = it.next()?.parse().ok()?;
    Some((runtime, wait, slices))
}

/// 读一次系统级 CPU 争用，作为卡顿的旁证
pub fn cpu_pressure() -> Option<f64> {
    let s = fs::read_to_string("/proc/pressure/cpu").ok()?;
    let line = s.lines().find(|l| l.starts_with("some"))?;
    let avg = line
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix("avg10="))?;
    avg.parse().ok()
}

#[derive(Clone, Default)]
pub struct Snapshot {
    pub aff: AffinityStats,
    pub events: Vec<String>,
    pub threads: Vec<ThreadDiag>,
    pub jank: Vec<JankSample>,
    pub pressure: Option<f64>,
}

pub fn snapshot() -> Snapshot {
    let mut guard = sink();
    let (aff, events) = match guard.as_mut() {
        Some(s) => (s.stats.clone(), s.events.iter().cloned().collect()),
        None => (AffinityStats::default(), Vec::new()),
    };
    Snapshot {
        aff,
        events,
        threads: lock_ignore_poison(&THREADS).clone(),
        jank: lock_ignore_poison(&JANK).clone(),
        pressure: cpu_pressure(),
    }
}

/// 摘要行给 Web 用，避免前端自己拼 errno
pub fn affinity_line(st: &AffinityStats) -> String {
    format!(
        "调用 {} · 真写 {} · 短路 {} · 失败 {}（{}） · 已退出 {}",
        st.calls,
        st.writes,
        st.noop,
        st.failed,
        st.errno_line(),
        st.gone
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply_affinity::AffinityOutcome;

    #[test]
    fn counters_split_by_outcome() {
        let before = snapshot().aff;
        note(ApplyReason::Rule, &AffinityOutcome::Set, true);
        note(ApplyReason::Sync, &AffinityOutcome::Set, false);
        note(ApplyReason::Sched, &AffinityOutcome::Gone, false);
        let after = snapshot().aff;
        assert_eq!(after.calls - before.calls, 3);
        assert_eq!(after.writes - before.writes, 1);
        assert_eq!(after.noop - before.noop, 1);
        assert_eq!(after.gone - before.gone, 1);
    }

    #[test]
    fn failure_buckets_by_errno() {
        let before = snapshot().aff;
        let mut set = CpuSet::new();
        set.set(1);
        note_failure(2_000_000_000, "T", &set, libc::EINVAL);
        note_failure(2_000_000_000, "T", &set, libc::EPERM);
        let after = snapshot().aff;
        assert_eq!(after.failed - before.failed, 2);
        assert_eq!(after.einval - before.einval, 1);
        assert_eq!(after.eperm - before.eperm, 1);
    }

    #[test]
    fn events_are_bounded() {
        for i in 0..(EVENT_CAP * 3) {
            note_sched(format!("e{}", i));
        }
        let ev = snapshot().events;
        assert_eq!(ev.len(), EVENT_CAP);
        assert!(ev.last().unwrap().starts_with("e"));
    }

    fn set_of(cpus: &[usize]) -> CpuSet {
        let mut s = CpuSet::new();
        for &c in cpus {
            s.set(c);
        }
        s
    }

    /// 漂移必须按「裁剪/重置/挪簇」分开计数：三种故障的处理方式完全不同
    #[test]
    fn drift_kinds_are_distinguished() {
        let expect = set_of(&[4, 5, 6]);
        let before = snapshot().aff;
        note_drift(2_000_000_000, "T", &expect, &set_of(&[4, 5]));
        note_drift(
            2_000_000_000,
            "T",
            &expect,
            &set_of(&[0, 1, 2, 3, 4, 5, 6, 7]),
        );
        note_drift(2_000_000_000, "T", &expect, &set_of(&[0, 1]));
        let after = snapshot().aff;
        assert!(after.clip > before.clip, "子集应计为裁剪");
        assert!(after.reset > before.reset, "超集应计为重置");
        assert!(after.shifted > before.shifted, "互不包含应计为挪簇");
    }

    /// S7 开着却不动时，摘要必须说清「跑了几轮、为什么跳过」
    #[test]
    fn sched_summary_explains_idle_policy() {
        let prev = SchedSnapshot {
            mode: 2,
            state: "运行中",
            ticks: 10,
            probed: 640,
            ..Default::default()
        };
        let mut cur = prev.clone();
        cur.ticks = 22;
        cur.probed = 1408;
        cur.skip[0] = 40;
        cur.skip[1] = 7;
        cur.load = [100, 500, 200];
        let mut hint = false;
        let line = sched_period_line(Some(&prev), &cur, &mut hint).expect("开着 S7 必须有摘要");
        assert!(line.contains("迁移 0 次"), "{}", line);
        assert!(line.contains("跳过"), "{}", line);
        assert!(line.contains("100/500/200"), "{}", line);

        // 关闭时不产出 S7 日志，保持安静
        let mut off = cur.clone();
        off.mode = 0;
        let mut hint2 = false;
        assert!(sched_period_line(Some(&prev), &off, &mut hint2).is_none());
    }

    /// cpuset 失败时给出的现场必须包含目标/父/根三层与线程所在 cpuset，
    /// 缺一层就无法判断是「目录没建成」还是「与父级没有交集」
    #[test]
    fn cpuset_detail_reports_three_layers() {
        let lines = cpuset_detail("0-3", 1);
        assert_eq!(lines.len(), 3);
        assert!(
            lines[0].contains("目标") && lines[0].contains("0-3"),
            "{:?}",
            lines
        );
        assert!(lines[1].contains("父"), "{:?}", lines);
        assert!(
            lines[2].contains("根") && lines[2].contains("线程 1"),
            "{:?}",
            lines
        );
    }

    /// schedstat 在当前内核不存在时要安静跳过，不能 panic 也不能误报
    #[test]
    fn jank_sampler_tolerates_missing_proc() {
        let mut c = ProcCache::new();
        c.tasks.insert(
            2_000_000_000,
            crate::cache::TaskEntry {
                pid: 1,
                pkg: "com.x".into(),
                cpus: CpuSet::new(),
                cpuset_dir: String::new(),
                is_thread_rule: false,
                comm: "RenderThread".into(),
                applied: true,
                group: crate::cpuset::SysGroup::Unknown,
                blocked: false,
            },
        );
        let mut s = JankSampler::new();
        // 第一次只建基准
        assert!(s.sample(&c).is_empty() || s.sample(&c).is_empty());
    }
}
