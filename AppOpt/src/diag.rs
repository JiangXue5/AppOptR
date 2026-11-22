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

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::apply_affinity::ApplyReason;
use crate::cache::ProcCache;
use crate::cpuset::CpuSet;
use crate::lock_ignore_poison;
use crate::roles::{Role, role_of};

/// 事件环上限。比 S7 的 8 条更宽一点，够看清一次抖动的前后因果
const EVENT_CAP: usize = 12;
/// 失败日志最小间隔，避免一个必然失败的线程每秒刷屏
const FAIL_LOG_GAP: Duration = Duration::from_secs(5);
/// 周期摘要间隔
pub const SUMMARY_GAP: Duration = Duration::from_secs(60);
/// 卡顿信号阈值：Critical 线程单次就绪等待均值超过它才上报
const JANK_WARN_MS: f64 = 4.0;
/// 卡顿日志最小间隔
const JANK_LOG_GAP: Duration = Duration::from_secs(30);
/// 线程表最多保留的条目，避免 Web 一次拉太多
const THREAD_CAP: usize = 160;

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
    last_summary: Instant,
    last_jank_log: Instant,
    /// 本轮摘要周期内新增的失败数，用于决定要不要打摘要
    fail_since_summary: u64,
    rewrite_since_summary: u64,
    cpuset_since_summary: u64,
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
        last_summary: now,
        last_jank_log: now,
        fail_since_summary: 0,
        rewrite_since_summary: 0,
        cpuset_since_summary: 0,
    });
    guard
}

/// 启动时打一次，让用户知道这些日志在哪、怎么看
pub fn announce() {
    if INIT.swap(true, Ordering::AcqRel) {
        return;
    }
    println!(
        "诊断: 绑核失败会写明 errno，S7 每次迁移/回弹/冻结都会记录，卡顿信号见「设置 → 诊断」"
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

    // 同一 errno 每 5 秒最多一条；换了 errno 立即打，方便一次看清不同原因
    let should_log = match s.last_fail_log {
        Some((last_errno, at)) => last_errno != errno || at.elapsed() >= FAIL_LOG_GAP,
        None => true,
    };
    if should_log {
        eprintln!("{}", line);
        s.last_fail_log = Some((errno, Instant::now()));
    }
}

/// cpuset 目录写入失败。真相是「绑核还有 sched_setaffinity 兜底」，
/// 但如果设备上 cpuset 只读又叠加应用自己改亲和性，就会表现为绑不住
pub fn note_cpuset_failure(dir: &str, err: Option<i32>) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.cpuset_fail += 1;
    s.cpuset_since_summary += 1;
    let line = match err {
        Some(e) => format!(
            "cpuset: 写入 {}/tasks 失败（{}），本次只靠绑核",
            dir,
            errno_hint(e)
        ),
        None => format!("cpuset: 写入 {}/tasks 失败，本次只靠绑核", dir),
    };
    push_event(s, line.clone());
    // 这类失败通常是持续性的，只在首次与每 60 秒摘要里出现
    if s.stats.cpuset_fail == 1 {
        eprintln!("{}", line);
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
    eprintln!("{}", line);
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

/// 主循环低频调用：只在有事发生时打一行摘要，无事保持安静
pub fn periodic_summary() {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    if s.last_summary.elapsed() < SUMMARY_GAP {
        return;
    }
    s.last_summary = Instant::now();
    let fails = std::mem::take(&mut s.fail_since_summary);
    let rewrites = std::mem::take(&mut s.rewrite_since_summary);
    let cpuset = std::mem::take(&mut s.cpuset_since_summary);
    if fails == 0 && rewrites < 8 && cpuset == 0 {
        return;
    }
    let st = &s.stats;
    if fails > 0 {
        eprintln!(
            "绑核: 近 {} 秒失败 {} 次（累计 {}，EPERM/EACCES {}、EINVAL {}、ENOSYS {}、其他 {}）",
            SUMMARY_GAP.as_secs(),
            fails,
            st.failed,
            st.eperm,
            st.einval,
            st.enosys,
            st.other
        );
    }
    if rewrites >= 8 {
        eprintln!(
            "绑核: 校验时发现 {} 个线程的亲和性被外部改写并已重新绑定；若持续出现，说明有别的组件在抢着改",
            rewrites
        );
    }
    if cpuset > 0 {
        eprintln!(
            "cpuset: 近 {} 秒 {} 次目录写入失败（累计 {}），当前绑核由 sched_setaffinity 单独维持",
            SUMMARY_GAP.as_secs(),
            cpuset,
            st.cpuset_fail
        );
    }
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
        if dt < Duration::from_secs(2) {
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
                if ds < 2 || dw == 0 {
                    continue;
                }
                let wait_ms = dw as f64 / ds as f64 / 1_000_000.0;
                out.push(JankSample {
                    tid,
                    comm: e.comm.clone(),
                    wait_ms,
                    switches: ds,
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
                    "卡顿信号: {}({}) 就绪等待均值 {:.1} ms（{} 次调度）",
                    worst.comm, worst.tid, worst.wait_ms, worst.switches
                );
                eprintln!("{}", line);
                push_event(s, line);
            }
        }

        *lock_ignore_poison(&JANK) = out.clone();
        out
    }
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
            },
        );
        let mut s = JankSampler::new();
        // 第一次只建基准
        assert!(s.sample(&c).is_empty() || s.sample(&c).is_empty());
    }
}
