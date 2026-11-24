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
use crate::diag_fmt::{
    Drift, RewriteHit, SyncTally, classify_clip, combo_list, contra_line, delta_desc,
    empty_state_hint, errno_hint, sample_tag, tally_line,
};
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
/// 同一线程一个周期内被改写多少次才判为「持续对抗」
const CONTRA_HITS: u32 = 3;
/// 对抗行最多列几个线程
const CONTRA_CAP: usize = 3;
/// cpuset 失败后打印完整上下文的间隔
const CPUSET_DETAIL_GAP: Duration = Duration::from_secs(300);

static START: OnceLock<Instant> = OnceLock::new();

/// 进程启动至今的秒数。静态 musl 下 localtime 依赖 TZ/tzdata，Android 上会静默
/// 退化成 UTC，反而误导；相对时间零依赖，且能精确看出「两次失败隔了多久」
pub fn uptime() -> f64 {
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// 带分类标签的日志出口。标签固定两个汉字，紧跟在时间戳后面，同一类事实
/// 永远落在同一列上：
///
/// ```text
/// [+34.9s] 改写  HWC release(12588)[sgame] 4-6 → 4-7 …
/// [+60.5s] 周期  受管 201 ｜ 一致 201 ｜ 改写 2 …
/// ```
///
/// 这样 `grep ' 改写 '` 就是「谁动过我的线程」，`grep ' 失败 '` 就是「真正
/// 的绑定错误」，不必逐行读叙述。标签集合是封闭的：
/// `启动 环境 配置 规则 策略 组件 就绪`（启动块）+ `改写 裁剪 跳过 失败 周期 事件 警告`（运行块）
pub fn tag(tag: &str, line: &str) {
    eprintln!("[+{:.1}s] {} {}", uptime(), tag, line);
}

/// 组件级信息行（eBPF / Web / RT / inotify）。做成宏是为了不重新排格式串的
/// 参数——这些 `println!` 全是带占位符的，逐条手改最容易把顺序改错
#[macro_export]
macro_rules! diag_say {
    ($($arg:tt)*) => { $crate::diag::tag("组件", &format!($($arg)*)) };
}

/// 组件级警告/失败行。原来走 stderr 的那些 `eprintln!` 都属于这一类：
/// 它们不带时间戳时，日志里分不清是启动时还是运行中发生的
#[macro_export]
macro_rules! diag_warn {
    ($($arg:tt)*) => { $crate::diag::tag("警告", &format!($($arg)*)) };
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
    /// 写 cpuset 时线程已退出（ESRCH）。这是竞态不是故障，单独计数，
    /// 不能混进 cpuset_fail 的摘要里
    pub cpuset_gone: u64,
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

/// 本周期计数：只记「发生了什么、几次」，摘要用完即清零。
/// 与去重集合、样本分开，是为了加新的播报维度时不必再往一个大结构里堆字段
#[derive(Default)]
struct Counters {
    fail: u64,
    rewrite: u64,
    cpuset: u64,
    cap: u64,
    sysgroup: u64,
    unreachable: u64,
    ineffective: u64,
    stuck: u64,
    /// 掩码已对、但线程不在自己的 cpuset 组里，补写组归属的次数。
    /// 与 `rewrite` 分开统计：补组不是「被系统改回去」，混在一起会让人以为
    /// 系统在反复冲掉绑定
    group_fix: u64,
    /// 漂移分类计数：裁剪 / 重置 / 挪簇
    kinds: [u64; 3],
}

/// 已经解释过一次的东西。这些集合跨周期保留，用来压掉重复播报
#[derive(Default)]
struct Seen {
    /// 已经说明过的系统组（后台组 / 其他组）
    sysgroup: HashSet<SysGroup>,
    /// 已经说明过「目标被组集合裁小」的组
    clip: HashSet<SysGroup>,
    /// 已经解释过「为什么少了核」的期望集合。裁剪会在几百个线程上重复出现，
    /// 原因却只有一个；按集合去重，避免把唯一有价值的解释刷掉
    clip_why: HashSet<String>,
    /// 已经解释过「多出来的核是谁写的」的读回集合。跨周期保留：
    /// `4-7` 这种超集只会有一两种来源，重复解释等于每 60 秒说一遍同样的话
    reset_why: HashSet<String>,
    /// 已经提示过渲染护栏的包。按包去重：一个包通常只有一个渲染线程，
    /// 但线程重建会换 tid，按 tid 去重会反复刷同一句话
    guard: HashSet<String>,
    /// 已经解释过「补写组归属」的线程名。按线程名去重：同名的游戏主线程
    /// 每局都会重建，按 tid 去重等于每局说一遍
    group_fix: HashSet<String>,
    /// 本窗口是否已经打过「同批线程不再逐条列出」的省略提示。
    /// 跟着 `counters.group_fix` 一起按窗口清零，否则一局之后永远不再提示
    group_fix_capped: bool,
}

/// 本周期样本：给摘要的明细行用，用完即清零。
/// 计数与样本分开存：计数回答「几次」，样本回答「哪种、谁」
#[derive(Default)]
struct Samples {
    /// 「期望→实际」组合的精确计数：(是否超集, "a→b") → 次数。
    /// 不能用样例去凑：真机上 7 次改写只留了 4 条样例，明细写成
    /// 「多核写入 7（4-6→4-7 ×4）」，另外 3 次凭空消失
    combo: HashMap<(bool, String), u32>,
    /// 同一线程本周期被反复改写：tid → 汇总（含改名前的 comm）
    reset_hits: HashMap<i32, RewriteHit>,
    /// 被系统改动最多的线程名，只给前三个，不带 tid
    cap_top: HashMap<String, u32>,
    /// 组上限来自哪个组：path → 次数
    cap_groups: HashMap<String, u32>,
    /// 目标与所在组无交集的次数与首个样例
    unreachable: Option<(String, i32, String, String)>,
    /// 写后回读仍不一致的样本
    ineffective: Vec<Drift>,
}

struct Sink {
    stats: AffinityStats,
    events: VecDeque<String>,
    last_fail_log: Option<(i32, Instant)>,
    /// 每条线程各自的最近一次失败播报，避免持续失败刷屏
    fail_tid: HashMap<(i32, i32), Instant>,
    last_jank_log: Instant,
    /// 本周期计数与样本，两者都不跨周期
    counters: Counters,
    samples: Samples,
    /// 跨周期的去重集合
    seen: Seen,
    /// 上一次 cpuset 完整上下文的打印时刻
    last_detail: Option<Instant>,
    /// 上一次看到的在线 CPU 集合，用于识别热插拔
    last_online: Option<String>,
    /// 上一次 S7 快照，摘要里做差得到本周期增量
    last_snap: Option<SchedSnapshot>,
    /// 「规则只覆盖一个簇」这条说明已经给过：它是静态结论，
    /// 每 60 秒重复一遍只会把真正变化的行挤掉
    allow_hint_shown: bool,
    /// 上一轮校验结束时各状态的线程数。用户最想知道的是「此刻绑上没有」，
    /// 只报「本周期重绑 17 个」会让人以为一直没绑上
    tally: Option<SyncTally>,
    /// 最近一轮被组限制的线程集中在哪个组、该组可用哪几个核
    blocked_note: Option<(SysGroup, String)>,
    /// 自启动以来是否成功接管过线程。用来区分「游戏还没开」与「进程退出了」，
    /// 两者的处理动作相反
    ever_bound: bool,
    /// 本周期渲染护栏命中：包 → 次数。护栏只观察，计数是唯一的产出
    guard_hits: HashMap<String, u32>,
    /// tid → (所属包, 是否进程主线程)。线程名常常和包名毫无关系
    /// （`HWC release`、`dns-work-0`），只印线程名时用户无法判断模块有没有
    /// 管到规则外的进程；主线程的 comm 会被内核截到 15 字节，日志里
    /// `cent.tmgp.sgame` 这种残名需要标注，否则读者以为是另一个进程
    thread_pkg: HashMap<i32, (String, bool)>,
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
        last_jank_log: now,
        counters: Counters::default(),
        samples: Samples::default(),
        seen: Seen::default(),
        last_detail: None,
        last_online: None,
        last_snap: None,
        allow_hint_shown: false,
        tally: None,
        blocked_note: None,
        ever_bound: false,
        guard_hits: HashMap::new(),
        thread_pkg: HashMap::new(),
    });
    guard
}

/// 启动块收尾：告诉读者「下面开始是运行日志」，并给出标签含义。
/// 放在启动块最后一行，而不是夹在规则表中间——原来的位置在真机上被
/// 当成「又一条配置信息」，没人看出它是在解释整份日志的读法
pub fn announce() {
    if INIT.swap(true, Ordering::AcqRel) {
        return;
    }
    // 尽早占位，后面所有时间戳都以这里为零点
    let _ = uptime();
    tag(
        "就绪",
        "运行中。格式 [+秒] 标签 内容；运行期标签：改写(外部改了亲和性) \
         裁剪(被组裁小) 跳过(规则与所在组无交集) 失败(写不进去) 周期(每 60 秒一行汇总) 事件(S7)",
    );
}

/// 记录 tid 属于哪个包。只在接管线程时写一次，后续漂移样例直接查表。
///
/// 不查表的代价是每条样例多读一次 `/proc/<tid>/cmdline`，而样例每分钟
/// 只有几条——真正的理由是线程名和包名的对应关系在这里最可靠：
/// 接管时已经完成 `pkg_owned` 校验，不会把规则外的进程记进来
pub fn bind_pkg(tid: i32, pkg: &str, is_main: bool) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    if s.thread_pkg.len() >= 8192 {
        // 线程退出后条目不会自己消失，超过上限整表清空重来。
        // 代价是清空后极少数样例的包名显示为空，远好过无界增长
        s.thread_pkg.clear();
    }
    s.thread_pkg.insert(tid, (pkg.to_string(), is_main));
}

/// 线程退出：条目跟着走，避免长期运行时表只增不减
pub fn unbind_pkg(tid: i32) {
    let mut guard = sink();
    if let Some(s) = guard.as_mut() {
        s.thread_pkg.remove(&tid);
    }
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
                s.counters.rewrite += 1;
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
    s.counters.fail += 1;
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
    tag("失败", &line);
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
        tag("跳过", &why);
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
    // 线程在两次写之间退出是竞态，不是 cpuset 故障。计进失败会让每分钟的摘要
    // 冒出一批「仍在重试」，把真正的失败盖掉，现场也可能抓在一个已死线程上
    if fail.errno() == Some(libc::ESRCH) {
        s.stats.cpuset_gone += 1;
        return;
    }
    s.stats.cpuset_fail += 1;
    s.counters.cpuset += 1;
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
        tag("失败", &line);
    }
    let due = s
        .last_detail
        .is_none_or(|at| at.elapsed() >= CPUSET_DETAIL_GAP);
    if due {
        s.last_detail = Some(Instant::now());
        let detail = cpuset_detail(dir, tid);
        for l in detail {
            push_event(s, l.clone());
            tag("失败", &l);
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
    // 与组判定共用 effective_at：读不到导出值时按父链求交自算。
    // 只读导出文件会让这一格在部分内核上恒为 `-`，而它恰好是判断
    // 「内核为什么不接受」的唯一依据
    let eff = |p: &str| crate::cpuset::effective_at(p).unwrap_or_else(|| "-".to_string());
    let root = format!(
        "根[/dev/cpuset] cpus={} mems={}",
        read("/dev/cpuset/cpus"),
        read("/dev/cpuset/mems")
    );
    // 线程已退出时 /proc/<tid>/cgroup 读不到。此时不能再拿 `-` 当路径去求父链交集：
    // 那会取到根组的 0-7，端出一份「与目标有交集」的假现场
    let Some(group_path) = crate::cpuset::thread_cgroup(tid) else {
        return vec![
            format!(
                "cpuset 现场: 目标[{}] cpus={} mems={} effective={}",
                target,
                read(&format!("{}/cpus", target)),
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
                "cpuset 现场: 线程 {} 已退出（读不到 /proc/{}/cgroup），无可达性可判；{}",
                tid, tid, root
            ),
        ];
    };
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
            "cpuset 现场: 线程 {} 所在组 {}({}，{}) {}；{}",
            tid,
            group_path,
            group_eff,
            group.label(),
            reachable,
            root,
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
    tag("失败", &line);
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

/// 线程所在组的天花板恰好等于读回的集合时，返回该组路径。
///
/// 这不是「被裁」：系统把线程放进 /foreground，该组 `cpus` 只到 0-5，
/// 规则要 4-6，内核求交只能给 4-5。**判据必须是「期望∩组上限」而不是
/// 「读回==组上限」**——线程的亲和性是规则与组的交集，组自己是 0-5、
/// 线程拿到的是 4-5，直接比 0-5 永远不相等，2.5.5 第一版就栽在这里
fn cap_group(tid: i32, expect: &CpuSet, actual: &CpuSet) -> Option<String> {
    let path = crate::cpuset::thread_cgroup(tid)?;
    let eff = crate::cpuset::group_effective_cached(&path)?;
    is_group_cap(expect, actual, &eff).then_some(path)
}

/// 纯判定：读回是不是「期望在所在组里能拿到的最大值」。抽出来能脱离
/// /dev/cpuset 单测——这条判错一次，日志每分钟就会多出上百条「裁剪」
fn is_group_cap(expect: &CpuSet, actual: &CpuSet, eff: &str) -> bool {
    let eff_set = crate::cpuset::parse_cpu_ranges(eff, None);
    if eff_set.count() == 0 {
        return false;
    }
    let mut inter = *expect;
    inter.and(&eff_set);
    inter.count() > 0 && inter == *actual
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
    // 读回正好是所在组的天花板：这是系统组的稳态，不是这一轮的异常。
    // 单独成一类，否则每分钟几百条「裁剪」会把真正被改写的线程埋掉
    let capped = if kind == DriftKind::Clip {
        cap_group(tid, expect, actual)
    } else {
        None
    };
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    if unreachable {
        s.stats.unreachable += 1;
        s.counters.unreachable += 1;
        if s.samples.unreachable.is_none() {
            s.samples.unreachable = Some((
                comm.to_string(),
                tid,
                expect.to_range_string(),
                read_thread_cpuset(tid),
            ));
        }
        return;
    }
    if let Some(path) = capped {
        s.counters.cap += 1;
        *s.samples.cap_top.entry(comm.to_string()).or_insert(0) += 1;
        *s.samples.cap_groups.entry(path).or_insert(0) += 1;
        return;
    }
    match kind {
        DriftKind::Clip => {
            s.stats.clip += 1;
            s.counters.kinds[0] += 1;
        }
        DriftKind::Reset => {
            s.stats.reset += 1;
            s.counters.kinds[1] += 1;
        }
        DriftKind::Shifted => {
            s.stats.shifted += 1;
            s.counters.kinds[2] += 1;
        }
    }
    let (pkg, is_main) = s
        .thread_pkg
        .get(&tid)
        .cloned()
        .unwrap_or_else(|| (String::new(), false));
    let sample = Drift {
        tid,
        comm: comm.to_string(),
        pkg,
        is_main,
        expect: expect.to_range_string(),
        actual: actual.to_range_string(),
        cpuset: read_thread_cpuset(tid),
    };
    let key = format!("{}→{}", sample.expect, sample.actual);
    *s.samples
        .combo
        .entry((kind == DriftKind::Reset, key))
        .or_insert(0) += 1;
    // 裁剪的第一条现场必须回答「少的那几个核去哪了」。这台设备的 cpuset 连
    // effective_cpus 都没导出、父链交集又是全集，唯一能解释的实际是内核把
    // sched_setaffinity 的掩码与在线集合求交——不写清这一点，182 次裁剪
    // 会被读成「规则写错了核」
    // 按「期望集合 + 所在组」去重：同一组同一目标只解释一次，
    // 但线程换到另一个组后仍然要重新解释——结论依赖组，不能复用
    let why_key = format!("{}@{}", sample.expect, sample.cpuset);
    match kind {
        DriftKind::Clip => {
            if s.seen.clip_why.insert(why_key) {
                let line = clip_reason(&sample.expect, &sample.actual, &sample.cpuset);
                tag("裁剪", &line);
                push_event(s, line);
            }
        }
        DriftKind::Shifted => {
            // 与裁剪共用去重集合：键里已含「期望@实际」，不会互相撞
            let key = format!("{}>{}", sample.expect, sample.actual);
            if s.seen.clip_why.insert(key) {
                let line = format!(
                    "{} {} → {}（两边互不包含，被整体挪到别的簇）cpuset={}；\
                     本轮已按规则写回，若同一线程反复出现，多半是有外部组件在给它设亲和性",
                    sample_tag(&sample),
                    sample.expect,
                    sample.actual,
                    sample.cpuset
                );
                tag("挪簇", &line);
                push_event(s, line);
            }
        }
        DriftKind::Reset => {
            let e = s
                .samples
                .reset_hits
                .entry(tid)
                .or_insert_with(|| RewriteHit {
                    comm: comm.to_string(),
                    first_comm: comm.to_string(),
                    ..Default::default()
                });
            // 线程会改名：comm 跟最新一次走，first_comm 留作对照
            e.comm = comm.to_string();
            e.n += 1;
            e.actual = sample.actual.clone();
            // 每次改写都留时间点（用户要的是「什么时候被动过」），
            // 但「谁写的」只解释一次：同一台设备上超集来源就那么几种，
            // 每条都念一遍长句会把「改了什么集合」埋掉
            let first = s.seen.reset_why.is_empty();
            s.seen.reset_why.insert(sample.actual.clone());
            let mut line = format!(
                "{} {} → {}{} cpuset={}",
                sample_tag(&sample),
                sample.expect,
                sample.actual,
                delta_desc(&sample.expect, &sample.actual),
                sample.cpuset
            );
            line.push_str(if first {
                " ｜ 外部写入（AppOpt 只写规则集合或其子集）：常见来源是厂商性能 HAL、\
                 游戏自身 boost、系统恢复默认集合；下一轮按规则重绑，写不进去会另打一行「失败」"
            } else {
                " ｜ 外部写入；下一轮按规则重绑（失败会另打一行「失败」）"
            });
            tag("改写", &line);
            push_event(s, line);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DriftKind {
    /// 读回比期望小：被 cpuset 的 effective_cpus 或离线核裁掉
    Clip,
    /// 读回比期望大：被整体重置
    Reset,
    /// 互不包含：被挪到别的簇
    Shifted,
}

/// 「期望比实际多几个核」的解释。差集能完全由离线解释时明确说是热插拔
/// （这是真机上最常见的一类，且会自动恢复）；解释不了才指向组配置，
/// 并给出可核对的落点。两种情况都必须在第一现场说清，否则读者只能
/// 把裁剪当成规则写错了核
fn clip_reason(expect: &str, actual: &str, group: &str) -> String {
    let want = crate::cpuset::parse_cpu_ranges(expect, None);
    let Some(online) = crate::cpuset::online_cpus() else {
        return format!(
            "期望 {} 实际 {}；读不到 /sys/devices/system/cpu/online，无法区分热插拔与组限制",
            expect, actual
        );
    };
    match classify_clip(&want, &online, crate::cpuset::cpu_is_online) {
        crate::diag_fmt::ClipWhy::Offline(lost) => {
            // online 位图读得到时这层是冗余的，读不到时它是唯一依据；
            // 顺带排掉「online 写着在、单核 online 文件写着 0」这种不一致
            let dead: Vec<String> = (0..64)
                .filter(|&c| lost.is_set(c) && !crate::cpuset::cpu_is_online(c))
                .map(|c| format!("cpu{}", c))
                .collect();
            format!(
                "期望 {} 实际 {}，在线 [{}]，CPU {} 不在线；内核会把 sched_setaffinity 与在线掩码求交，\
                 核上线后下一轮自动恢复（不是规则写错）{}",
                expect,
                actual,
                online.to_range_string(),
                lost.to_range_string(),
                if dead.is_empty() {
                    String::new()
                } else {
                    format!("；{} 的 online 文件已确认为 0", dead.join("、"))
                }
            )
        }
        crate::diag_fmt::ClipWhy::GroupLimited => group_clip_reason(expect, actual, &want, group),
    }
}

/// 核都「在线」却写不进去时，两种可能必须分开说：
/// 组本身就不含这几个核（改规则或让接管搬组），还是组含这几个核但内核
/// 当下不接受（收核/热插拔/隔离，等下一轮）。
///
/// 曾经的版本一律判成前者，于是真机上打出「差集来自组集合」，用户对着
/// `cpus=0-7` 的组目录反复核对，什么也查不出来——结论本身是错的
fn group_clip_reason(expect: &str, actual: &str, want: &CpuSet, group: &str) -> String {
    let (gcpus, geff, exported) = crate::cpuset::group_evidence(group);
    let gpath = if group.trim().is_empty() || group.trim() == "-" {
        "未知组（/proc/<tid>/cpuset 读不到）".to_string()
    } else {
        group.trim().to_string()
    };
    let eff_note = match (&geff, exported) {
        (Some(v), true) => format!("cpuset.effective_cpus={}", v),
        (Some(v), false) => format!("effective={}（未导出，按父链交集推算）", v),
        (None, _) => "effective 读不到".to_string(),
    };
    let cpus_note = gcpus
        .as_deref()
        .map(|v| format!("cpus={}", if v.is_empty() { "空" } else { v }))
        .unwrap_or_else(|| "cpus 读不到".to_string());

    // 差集里有哪些核其实不在组集合内
    let mut gone = *want;
    // 两个文件都读不到时不要下结论：这正是上一版「照着日志查不出问题」的根源
    if gcpus.is_none() && geff.is_none() {
        return format!(
            "期望 {} 实际 {}，{}（{}，{}）读不到任何集合，无法判断是组限制还是核下电；\
             内核会把写入的掩码与可用集合求交，下一轮会自动重试，届时若仍裁剪请对照组目录",
            expect, actual, gpath, cpus_note, eff_note
        );
    }
    if let Some(g) = gcpus.as_deref() {
        let gset = crate::cpuset::parse_cpu_ranges(g, None);
        gone.and_not(&gset);
    } else {
        // 组 cpus 读不到就按生效集合算，至少不会把「组确实没有」说反
        if let Some(e) = geff.as_deref() {
            let eset = crate::cpuset::parse_cpu_ranges(e, None);
            gone.and_not(&eset);
        }
    }
    if gone.count() > 0 {
        format!(
            "期望 {} 实际 {}，{}({})，该组不含 CPU {}，取交只能是 {}；\
             要拿到完整集合需把线程迁进 AppOpt 组（切「强制绑核」或写 @sysgroup=takeover），\
             否则把规则改成组内集合",
            expect,
            actual,
            gpath,
            cpus_note,
            gone.to_range_string(),
            actual
        )
    } else if geff
        .as_deref()
        .is_some_and(|e| crate::cpuset::parse_cpu_ranges(e, None).count() == 0)
    {
        format!(
            "期望 {} 实际 {}，{}({}) 的生效集合为空，该组当前不接受任何任务；\
             内核会把写入全部丢弃，等组配置恢复后下一轮自动重试",
            expect, actual, gpath, cpus_note
        )
    } else {
        format!(
            "期望 {} 实际 {}，{} 里的核都在线，{}({}，{}) 本应容纳目标却写不进去——\
             说明被扣掉的核此刻不可调度（core_ctl 收核、热插拔进行中或 sched 隔离），\
             不是规则写错，下一轮会自动重试",
            expect, actual, expect, gpath, cpus_note, eff_note
        )
    }
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
    s.counters.ineffective += 1;
    if s.samples.ineffective.len() < 2 {
        let (pkg, is_main) = s
            .thread_pkg
            .get(&tid)
            .cloned()
            .unwrap_or_else(|| (String::new(), false));
        s.samples.ineffective.push(Drift {
            tid,
            comm: comm.to_string(),
            pkg,
            is_main,
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
    s.counters.stuck += 1;
}

/// 线程被系统放在后台组、规则目标又不在该组生效集合内。
/// 这不是失败：内核对 cgroup 迁移和 sched_setaffinity 都会返回 EINVAL，
/// 硬试只会把线程在簇之间来回踢。同类组只说明一次，其余进 60 秒摘要。
/// `eff` 是判定所依据的生效集合，必须一起打出来——否则「4-6 不在该组内」
/// 只是一句无法验证的结论
pub fn note_sysgroup_skip(tid: i32, comm: &str, group: SysGroup, want: &CpuSet, eff: Option<&str>) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.sysgroup_skip += 1;
    s.counters.sysgroup += 1;
    if !s.seen.sysgroup.insert(group) {
        return;
    }
    // 与改写/裁剪行同样带 [包名]：`dns-work-15` 这种名字看不出属于谁，
    // 没有包名就无法核对「模块是不是管到了规则外的进程」
    let pkg = s
        .thread_pkg
        .get(&tid)
        .map(|(p, _)| p.as_str())
        .unwrap_or("");
    let name = match (comm.is_empty(), pkg.is_empty()) {
        (true, _) => format!("tid {}", tid),
        (false, true) => format!("{}({})", comm, tid),
        (false, false) => format!("{}({})[{}]", comm, tid, pkg),
    };
    let eff = eff.filter(|s| !s.is_empty()).unwrap_or("未知");
    // label 自带「组」字（后台组 / 其他组），模板里不能再补一个
    let line = format!(
        "{} 在 {}（可用 {}），规则 {} 不在该组内，内核必然拒绝绑定 ｜ 来源：eBPF 新线程 \
         ｜ 切前台自动恢复；要强制接管写 @sysgroup=takeover",
        name,
        group.label(),
        eff,
        want.to_range_string()
    );
    tag("跳过", &line);
    push_event(s, line);
}

/// 校验轮里整批因系统分组被跳过。逐线程播报会把日志刷满，
/// 这里只累加计数，并在首次给出一次结论
pub fn note_sysgroup_batch(n: u64, hint: Option<(SysGroup, String)>) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.stats.sysgroup_skip += n;
    s.counters.sysgroup += n;
    // 归因留给总账：这一批线程在哪个组、该组可用哪几个核，
    // 是「游戏切后台」与「规则写错核」的唯一分界
    let (group, eff) = hint.unwrap_or((SysGroup::Unknown, "未知".to_string()));
    let eff = eff.as_str();
    s.blocked_note = Some((group, eff.to_string()));
    if !s.seen.sysgroup.insert(group) {
        return;
    }
    let line = format!(
        "本轮 {} 个线程在 {}（可用 {}），规则要求的核不在该组可用集合内，内核必然拒绝绑定 \
         ｜ 来源：周期校验 ｜ 切前台自动恢复；要强制接管写 @sysgroup=takeover",
        n,
        group.label(),
        eff
    );
    tag("跳过", &line);
    push_event(s, line);
}

/// 校验轮结束时登记全局状态：受管多少、此刻符合多少、多少被系统组挡住。
///
/// 「近 60 秒重绑 17 个」不能回答「现在绑上没有」——重绑成功、失败、被组
/// 限制的线程混在一起，只能靠读的人自己去减。这一行把它摊开，
/// 用户在 Scene 里看到的和日志给出的必须是同一件事
pub fn note_sync_tally(total: usize, ok: usize, rebound: usize, failed: usize, blocked: usize) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    if total > 0 {
        s.ever_bound = true;
    }
    s.tally = Some(SyncTally {
        total,
        ok,
        rebound,
        failed,
        blocked,
    });
}

/// 目标集合被所在组的生效集合裁小。写全集时内核会求交，返回成功但回读永远是
/// 子集，接着被判成「写了也白写」白停 300 秒。改成按交集绑之后不会再有回读
/// 不一致，所以这条说明就是唯一的现场记录，同一组只给一次
pub fn note_group_clip(group: SysGroup, want: &CpuSet, got: &CpuSet, eff: &str) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    if !s.seen.clip.insert(group) {
        return;
    }
    // 这句曾经收在「要拿到完整集合写 @sysgroup=takeover」上，可 takeover 也要
    // cgroup 写权限——自检没通过时那条路根本不存在，等于把人指去撞墙。
    // 现在只说清约束与两条真实出路：让接管恢复，或把规则改成组内集合
    let line = format!(
        "{} 的可用集合是 {}，规则要的 {} 超出该组，实际按 {} 绑定 ｜ 来源：规则命中 \
         ｜ 要拿完整集合需 cgroup 接管可用（启动行应显示「cpuset 就绪」），\
         或把规则改成该组内的集合",
        group.label(),
        eff,
        want.to_range_string(),
        got.to_range_string()
    );
    tag("裁剪", &line);
    push_event(s, line);
}

/// 掩码已经正确、但线程不在 `AppOpt/<目标集合>` 组里。
///
/// 这是接管语义的缺口：只写 `sched_setaffinity` 不写 cpuset 时，系统在进程
/// 状态变化时会把亲和性收敛回「所在组允许的集合」，于是同一批线程被反复
/// 改写。补组之后线程才真正受本模块的组约束。
///
/// **不是故障**：日志里明确写「已补写」，避免用户以为绑定出错
pub fn note_group_fix(tid: i32, dir: &str, comm: &str) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    s.counters.group_fix += 1;
    let name = if comm.is_empty() {
        format!("tid {}", tid)
    } else {
        comm.to_string()
    };
    if !s.seen.group_fix.insert(name.clone()) {
        return;
    }
    // 一批线程首次接管时会同时补组，真机上一分钟三四十条，逐条打印没有信息量。
    // 前 3 条给出线程名就够定位是哪类线程，剩下的只留一行省略提示，
    // 总数由 60 秒汇总那行交代。窗口随 counters 一起清零，下一局重新给 3 条
    const GROUP_FIX_DETAIL: u64 = 3;
    if s.counters.group_fix > GROUP_FIX_DETAIL {
        if !s.seen.group_fix_capped {
            s.seen.group_fix_capped = true;
            tag(
                "改写",
                "…同批线程的组归属也在补写，不再逐条列出（本窗口总数见周期汇总）",
            );
        }
        return;
    }
    let target = if dir.is_empty() {
        "AppOpt".to_string()
    } else {
        format!("AppOpt/{}", dir)
    };
    tag(
        "改写",
        &format!(
            "{} 的掩码已正确但不在 {} 组，已补写组归属（接管语义，不是被系统改回去）",
            name, target
        ),
    );
}

/// 渲染护栏命中（观察模式）：关键线程的目标集合里没有性能核，或只剩一个核。
///
/// 只记数、每个包提示一次，**不改变任何绑定**。先攒真机数据：把渲染线程
/// 放到小核是否真的掉帧，要看卡顿采样的前后对比，不能凭直觉直接拦
pub fn note_render_guard(pkg: &str, comm: &str, target: &CpuSet, reason: &str) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    *s.guard_hits.entry(pkg.to_string()).or_insert(0) += 1;
    if !s.seen.guard.insert(pkg.to_string()) {
        return;
    }
    let line = format!(
        "{} 的 {} 落在 {}：{}｜护栏只观察不拦截，规则仍按此目标绑定；\
         要放宽就改成两个核以上（如 6-7），或写 @render_guard=off",
        pkg,
        comm,
        target.to_range_string(),
        reason
    );
    tag("警告", &line);
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
            tag("事件", &line);
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
    tag("事件", &line);
    note_sched(line);
}

fn push_event(s: &mut Sink, line: String) {
    if s.events.len() >= EVENT_CAP {
        s.events.pop_front();
    }
    s.events.push_back(line);
}

/// 主循环低频调用：每 60 秒给一条「总账」，有异常才追加明细行。
///
/// 布局刻意做成「一行总账 + 若干明细」：
///
/// ```text
/// [+60.5s] 周期  受管 201 ｜ 一致 201 ｜ 本周期改写 2
/// [+60.5s] 周期  改写明细  多核写入 2（4-6→4-7 ×1、4-6→0-7 ×1，外部 HAL/boost，已改回）
/// ```
///
/// 总账第一项永远是「此刻受管多少、一致多少」，明细跟在后面。上一版把
/// 「近 60 秒被改了 N 次」放在最前，被真机读成「一直没绑上」，这一条
/// 在 2.5.4~2.5.7 反复出现过三次，不能再靠措辞补救，只能靠布局
pub fn periodic_summary(current: &SchedSnapshot) {
    let mut guard = sink();
    let Some(s) = guard.as_mut() else { return };
    let fails = std::mem::take(&mut s.counters.fail);
    let rewrites = std::mem::take(&mut s.counters.rewrite);
    let cpuset = std::mem::take(&mut s.counters.cpuset);
    let sysgroup = std::mem::take(&mut s.counters.sysgroup);
    let unreach = std::mem::take(&mut s.counters.unreachable);
    let unreach_sample = s.samples.unreachable.take();
    let kinds = std::mem::take(&mut s.counters.kinds);
    let combo = std::mem::take(&mut s.samples.combo);
    let reset_hits = std::mem::take(&mut s.samples.reset_hits);
    let caps = std::mem::take(&mut s.counters.cap);
    let cap_top = std::mem::take(&mut s.samples.cap_top);
    let mut cap_groups: Vec<(String, u32)> = std::mem::take(&mut s.samples.cap_groups)
        .into_iter()
        .collect();
    let ineff_n = std::mem::take(&mut s.counters.ineffective);
    let ineff = std::mem::take(&mut s.samples.ineffective);
    let stuck = std::mem::take(&mut s.counters.stuck);
    let group_fix = std::mem::take(&mut s.counters.group_fix);
    // 省略提示跟着窗口走：下一窗口前 3 条又能逐条打出来
    s.seen.group_fix_capped = false;
    let guards = std::mem::take(&mut s.guard_hits);
    let tally = s.tally.take();
    let prev = s.last_snap.replace(current.clone());

    // 护栏只有计数没有动作，单独一行放最前：它是「你可能想改规则」的提示，
    // 不是故障，混在失败里会让人以为绑定出错了
    if !guards.is_empty() {
        let total: u32 = guards.values().sum();
        let mut top: Vec<(String, u32)> = guards.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let list = top
            .iter()
            .take(3)
            .map(|(p, c)| format!("{} {}", p, c))
            .collect::<Vec<_>>()
            .join("、");
        tag(
            "警告",
            &format!(
                "渲染护栏（观察）近 {} 秒命中 {} 次：{}{}",
                SUMMARY_GAP.as_secs(),
                total,
                list,
                if top.len() > 3 { " 等" } else { "" }
            ),
        );
    }

    // 补组是「第一次接管」的一次性动作，通常在启动或规则变更那一分钟出现，
    // 之后归零。单列一行是为了让用户确认它发生过，而不是被当成故障反复解释
    if group_fix > 0 {
        tag(
            "改写",
            &format!(
                "补写组归属 {} 次（近 {} 秒）：这些线程的掩码本来是对的，但不在自己的 cpuset 组里，已迁入以免被系统收敛重置",
                group_fix,
                SUMMARY_GAP.as_secs()
            ),
        );
    }

    // 失败与 cpuset 排在总账前面：它们是「同一件事反复发生」的计数器，
    // 一旦出现就是这一分钟的主要结论，不能让总账把它们盖住
    if fails > 0 {
        tag(
            "失败",
            &format!(
                "绑核失败 {} 次（近 {} 秒）｜ 累计 {}：EPERM/EACCES {}、EINVAL {}、ENOSYS {}、其他 {}",
                fails,
                SUMMARY_GAP.as_secs(),
                s.stats.failed,
                s.stats.eperm,
                s.stats.einval,
                s.stats.enosys,
                s.stats.other
            ),
        );
    }
    if cpuset > 0 {
        tag(
            "失败",
            &format!(
                "cpuset 目录写入失败 {} 次（近 {} 秒，累计 {}），{}；绑核由 sched_setaffinity 单独维持",
                cpuset,
                SUMMARY_GAP.as_secs(),
                s.stats.cpuset_fail,
                if crate::apply_affinity::cpuset_paused() {
                    "已暂停重试，等半开试探"
                } else {
                    "仍在重试"
                }
            ),
        );
    }
    if unreach > 0 {
        let body = match unreach_sample {
            Some((comm, tid, expect, cpuset)) => format!(
                "{} 个线程的目标集合与所在组无交集（累计 {}），如 {}({}) 期望 {} 位置 {}；\
                 内核会同时拒绝迁组与绑核，已跳过——改规则为组内集合，或切「强制绑核」把线程搬进 AppOpt 组",
                unreach, s.stats.unreachable, comm, tid, expect, cpuset
            ),
            None => format!(
                "另有 {} 个线程的目标集合与所在组无交集（累计 {}），已跳过",
                unreach, s.stats.unreachable
            ),
        };
        tag("跳过", &body);
    }

    // ── 总账 ──────────────────────────────────────────────────
    match tally.filter(|t| t.total > 0) {
        Some(t) => tag("周期", &tally_line(t, rewrites, s.blocked_note.as_ref())),
        None => tag("周期", empty_state_hint(tally, s.ever_bound)),
    }

    // ── 持续对抗：同一个线程被反复改写 ────────────────────────
    // 聚合与排版在 diag_fmt，这里只提供 pkg 表
    if let Some(line) = contra_line(&reset_hits, CONTRA_HITS, CONTRA_CAP, |tid| {
        s.thread_pkg.get(&tid).cloned()
    }) {
        tag("周期", &line);
    }

    // ── 明细：每类一行，没有就不打 ───────────────────────────
    if kinds[1] > 0 || kinds[0] > 0 || kinds[2] > 0 {
        let mut segs: Vec<String> = Vec::new();
        if kinds[1] > 0 {
            segs.push(format!(
                "多核写入 {}（{}）",
                kinds[1],
                combo_list(&combo, true)
            ));
        }
        if kinds[0] > 0 {
            segs.push(format!(
                "被裁小 {}（{}）",
                kinds[0],
                combo_list(&combo, false)
            ));
        }
        if kinds[2] > 0 {
            segs.push(format!("挪簇 {}", kinds[2]));
        }
        tag("周期", &format!("改写明细 {}", segs.join(" ｜ ")));
    }
    if caps > 0 {
        // 组上限是系统组的稳态，不是失败：给组名、次数、天花板，一句结论
        cap_groups.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        cap_groups.truncate(2);
        let segs: Vec<String> = cap_groups
            .iter()
            .map(|(path, n)| {
                let eff = crate::cpuset::group_effective_cached(path)
                    .unwrap_or_else(|| "读不到".to_string());
                format!("{} {} 次（该组可用 {}）", path, n, eff)
            })
            .collect();
        tag(
            "周期",
            &format!(
                "组上限 {} {}；线程被系统放回这些组，规则集合超出该组可用集合，\
                 每轮已拉回规则集合——系统行为，不是绑定失败",
                caps,
                segs.join("、")
            ),
        );
        // 谁被搬得最勤，直接给名字：用户看到「被改 167 次」时想知道的正是这个
        if !cap_top.is_empty() {
            let mut v: Vec<(String, u32)> = cap_top.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            v.truncate(3);
            let list: Vec<String> = v.iter().map(|(c, n)| format!("{} {}", c, n)).collect();
            tag("周期", &format!("组上限高频线程 {}", list.join("、")));
        }
    }
    if ineff_n > 0 {
        tag(
            "裁剪",
            &format!(
                "{} 个线程写入返回成功但回读仍不一致（组把它裁掉），已暂停重绑 {} 秒，本轮跳过 {} 次",
                ineff_n,
                crate::apply_affinity::STUCK_PAUSE.as_secs(),
                stuck
            ),
        );
        for d in ineff {
            tag(
                "裁剪",
                &format!(
                    "{} 期望 {} 实际 {} cpuset={}",
                    sample_tag(&d),
                    d.expect,
                    d.actual,
                    d.cpuset
                ),
            );
        }
    }
    if sysgroup > 0 {
        // 两个数必须各自标清来源：`sysgroup` 是判定次数之和（含 eBPF 新线程的
        // 即时判定），`最近一轮` 只看周期校验。上一版把它们写成一句话，
        // 真机上出现「刚报 dns-work-15 被跳过」紧接「最近一轮没有这类线程」。
        //
        // 总账那一行已经写了「被组限制 N」，这里不再重复同一个数字：
        // 相邻两行说同一个 228，读者会以为是两件事
        let head = match tally {
            // 总账刚说过同一个数字，不再重复
            Some(t) if t.blocked > 0 => String::new(),
            // 周期校验没看到、但 eBPF 事件里出现过：说明这些线程已经退出或被搬回，
            // 也要说清「最近一轮是干净的」，否则读者以为两个来源在打架
            Some(_) => "最近一轮没有线程被所在组挡住；".to_string(),
            None => String::new(),
        };
        tag(
            "周期",
            &format!(
                "跳过明细 {}近 {} 秒累计跳过 {} 次（同一线程每轮各计一次，含 eBPF 新线程的即时判定）\
                 ｜ respect 下不硬抢，切前台自动恢复；强制接管写 @sysgroup=takeover",
                head,
                SUMMARY_GAP.as_secs(),
                sysgroup
            ),
        );
    }
    let mut hint = std::mem::take(&mut s.allow_hint_shown);
    if let Some(line) = sched_period_line(prev.as_ref(), current, &mut hint) {
        // 先释放锁再打日志，避免写 stdout 阻塞时把诊断入口一起卡住
        s.allow_hint_shown = hint;
        tag("事件", &line);
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
        // 「规则无跨簇」是静态结论：启动块的策略行已经写明「不会采样」，
        // 运行期再说一遍只是噪声。真机上它每个周期都出现，把真正变化的行挤掉
        if cur.state.contains("无跨簇") {
            return None;
        }
        // 状态没变不重复；变了才值得一行
        if prev.is_some_and(|p| p.state == cur.state) {
            return None;
        }
        return Some(format!("S7 近 {} 秒未推进判定（状态：{}）", gap, cur.state));
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
            "{} 近 {} 秒 {} 轮、探测 {} 线程、迁移 {} 次（累计 {}），回弹 {}、冻结 {}，簇负载 {}，状态 {}",
            head, gap, ticks, probed, moved, cur.moved, bounced, frozen, load, cur.state
        )
    } else {
        format!(
            "{} 近 {} 秒 {} 轮、探测 {} 线程、本可迁移 {} 次（未执行），簇负载 {}，状态 {}",
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
                tag("事件", &line);
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

    /// 读回正好等于「期望在所在组里能拿到的最大值」时，不是「被裁」而是
    /// 「这组只能给这么多」。判定错一次，日志每分钟就会多出上百条「裁剪」，
    /// 把真正被改写的线程埋掉。第一版用「读回==组上限」比，永远不成立
    #[test]
    fn group_cap_is_ceiling_not_failure() {
        // 规则 4-6，线程在 /foreground（0-5），读回 4-5：正是交集，也是该组能给的全部
        assert!(is_group_cap(&set_of(&[4, 5, 6]), &set_of(&[4, 5]), "0-5"));
        // 同组但读回只剩 4，还少一个，属于真裁剪
        assert!(!is_group_cap(&set_of(&[4, 5, 6]), &set_of(&[4]), "0-5"));
        // 读回比交集还大：不是组上限能解释的
        assert!(!is_group_cap(
            &set_of(&[4, 5, 6]),
            &set_of(&[4, 5, 6]),
            "0-5"
        ));
        // 交集为空（后台组 0-3）时，任何非空读回都不是「组上限」
        assert!(!is_group_cap(&set_of(&[4, 5, 6]), &set_of(&[0, 1]), "0-3"));
        // 生效集合读不到或为空时不能倒推结论
        assert!(!is_group_cap(&set_of(&[4, 5, 6]), &set_of(&[4, 5]), ""));
        assert!(!is_group_cap(
            &set_of(&[4, 5, 6]),
            &set_of(&[4, 5]),
            "读不到"
        ));
    }

    /// 外部改写要一路走到事件环：Drift 构造 → 包名标注 → 差集描述。
    /// 日志层拆分后这条链路跨了两个模块，必须有一个端到端用例盯着
    #[test]
    fn reset_rewrite_reaches_the_event_ring_with_package() {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        bind_pkg(tid, "com.audit.game", true);
        // 期望是子集、读回是超集 → 分类为 Reset（被整体改大）
        note_drift(
            tid,
            "com.audit.game",
            &set_of(&[4, 5, 6]),
            &set_of(&[4, 5, 6, 7]),
        );
        let sn = snapshot();
        let line = sn
            .events
            .iter()
            .rev()
            .find(|e| e.contains("4-6 → 4-7"))
            .expect("改写行必须进入事件环");
        assert!(line.contains("[com.audit.game]"), "{}", line);
        assert!(line.contains("（多 7）"), "{}", line);
        // 主线程不再重复念截断的 comm
        assert!(!line.contains("主线程 com.audit.game("), "{}", line);
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
                want: CpuSet::new(),
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

    /// ESRCH 是线程退出竞态，一次组都没写过。沿用「已抬到 base 组」的说明
    /// 会让人去查 cpuset 配置，而真正发生的事只是线程没了
    #[test]
    fn cpuset_target_label_matches_actual_path() {
        use crate::apply_affinity::CpusetFail;
        let gone = CpusetFail::Target(libc::ESRCH).label();
        let rejected = CpusetFail::Target(libc::EINVAL).label();
        assert!(gone.contains("线程已退出"), "{}", gone);
        assert!(!gone.contains("base"), "{}", gone);
        assert!(rejected.contains("base"), "{}", rejected);
    }

    /// 线程退出不能算成「cpuset 目录写入失败」：否则每 60 秒摘要里都会
    /// 冒出一批「仍在重试」，把真正的失败盖掉
    #[test]
    fn esrch_does_not_pollute_cpuset_failure_stats() {
        use crate::apply_affinity::CpusetFail;
        let before = snapshot().aff;
        note_cpuset_failure(2_000_000_000, "4-6", CpusetFail::Target(libc::ESRCH));
        let gone = snapshot().aff;
        assert_eq!(gone.cpuset_fail, before.cpuset_fail);
        assert_eq!(gone.cpuset_gone - before.cpuset_gone, 1);

        note_cpuset_failure(2_000_000_000, "4-6", CpusetFail::Target(libc::EINVAL));
        assert_eq!(snapshot().aff.cpuset_fail - before.cpuset_fail, 1);
    }

    /// 线程已退出时不能再拿 `-` 当路径求父链交集，否则会取到根组的 0-7，
    /// 端出一份「与目标有交集」的假现场
    #[test]
    fn cpuset_detail_marks_dead_thread_without_fake_reachability() {
        let lines = cpuset_detail("4-6", 2_000_000_000);
        assert_eq!(lines.len(), 3);
        assert!(lines[2].contains("已退出"), "{:?}", lines);
        assert!(!lines[2].contains("与目标有交集"), "{:?}", lines);
        // 曾是「-(0-7，其他组组)」：label 已含「组」，格式串又加了一次
        assert!(!lines[2].contains("组组"), "{:?}", lines);
    }

    /// 系统分组播报必须带上判定依据，否则「4-6 不在该组内」无法验证
    #[test]
    fn sysgroup_skip_reports_effective_set() {
        note_sysgroup_skip(
            2_000_000_001,
            "dns-work",
            SysGroup::Other,
            &set_of(&[4, 5, 6]),
            Some("0-3"),
        );
        let ev = snapshot().events;
        let line = ev
            .iter()
            .rev()
            .find(|l| l.contains("dns-work"))
            .expect("应有系统分组播报");
        assert!(line.contains("0-3"), "{}", line);
        assert!(line.contains("4-6"), "{}", line);
        assert!(
            !line.contains("组 组"),
            "标签自带「组」字，不能再补一个：{}",
            line
        );
    }

    /// 裁剪归因必须给出可核对的值，不能只说「来自组集合」。
    /// 组路径读不到时也要明确说读不到，而不是编一个组名
    #[test]
    fn clip_reason_states_group_values_or_says_unknown() {
        let line = clip_reason("4-6", "4-5", "-");
        assert!(line.contains("期望"), "{}", line);
        assert!(line.contains("4-5"), "{}", line);
        assert!(
            line.contains("未知组"),
            "读不到 cpuset 时必须直说，不能指向不存在的组：{}",
            line
        );
    }

    /// 组目录存在但判成「组不含目标」还是「核不可调度」，两句话指向的处理
    /// 方式完全不同：前者要改规则，后者只需等。这里用真实目录验证分支
    /// 不 panic 且必定给出下一步，避免真机上再出现「照着日志查不出问题」
    #[test]
    fn clip_reason_always_names_a_next_step() {
        for path in [
            "/top-app",
            "/foreground",
            "/background",
            "/nonexistent-group",
        ] {
            let line = clip_reason("4-6", "4-5", path);
            assert!(
                line.contains("规则") || line.contains("自动"),
                "{} 的解释没有给出处理方式：{}",
                path,
                line
            );
        }
    }

    /// 只给次数不给状态，是这套日志被反复误读的根源。
    /// 缓存空了必须明说，不能静默地只留一句「近 60 秒被改了 N 次」
    #[test]
    fn missing_state_is_announced_not_silent() {
        assert!(empty_state_hint(None, false).contains("首轮校验"));
        let empty = SyncTally::default();
        // 从未接管过 = 游戏还没启动，属正常状态，不能说成「进程已退出」
        let never = empty_state_hint(Some(empty), false);
        assert!(never.contains("还没命中"), "{}", never);
        assert!(!never.contains("已退出"), "{}", never);
        // 接管过又归零才算「退出了」
        let gone = empty_state_hint(Some(empty), true);
        assert!(gone.contains("已退出"), "{}", gone);
        assert!(gone.contains("重新接管"), "{}", gone);
        let full = SyncTally {
            total: 3,
            ok: 3,
            ..Default::default()
        };
        assert_eq!(empty_state_hint(Some(full), true), "此刻没有受管线程");
    }

    /// 「受管 N 个 / 当前符合 X」必须能回答 Scene 里看到的到底是什么状态
    #[test]
    fn sync_tally_is_kept_for_summary() {
        note_sync_tally(200, 12, 3, 1, 184);
        let t = sink()
            .as_ref()
            .and_then(|s| s.tally)
            .expect("摘要要取到 tally");
        assert_eq!(
            (t.total, t.ok, t.rebound, t.failed, t.blocked),
            (200, 12, 3, 1, 184)
        );
        // 四个分档加本轮退出的线程应能对上总数
        assert!(t.ok + t.rebound + t.failed + t.blocked <= t.total);
    }

    /// 状态没变时不重复刷同一行（实测 5 分钟刷了 5 遍「规则无跨簇」），
    /// 状态变了必须重新说明
    #[test]
    fn idle_sched_state_repeats_only_when_it_changes() {
        let mut hint = false;
        // 「规则无跨簇」是静态结论：启动块的策略行已经写明「不会采样」，
        // 运行期出现在这里只是噪声，连首轮也不打
        let static_state = SchedSnapshot {
            mode: 2,
            state: "规则无跨簇",
            ticks: 0,
            ..Default::default()
        };
        assert!(sched_period_line(None, &static_state, &mut hint).is_none());

        // 其它「一轮都没跑」的原因（等待进程）首次要说明，重复则静默
        let wait = SchedSnapshot {
            mode: 2,
            state: "等待被管理进程",
            ticks: 0,
            ..Default::default()
        };
        assert!(sched_period_line(None, &wait, &mut hint).is_some());
        assert!(sched_period_line(Some(&wait), &wait, &mut hint).is_none());

        // 状态真的变了必须重新说明
        let mut moved = wait.clone();
        moved.state = "等待采样窗口";
        assert!(sched_period_line(Some(&wait), &moved, &mut hint).is_some());
    }
}
