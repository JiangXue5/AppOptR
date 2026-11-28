use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::io::Write as _;

use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const CPU_SETSIZE: usize = 1024;
pub const CPU_WORD_BITS: usize = 64;
pub const CPU_WORDS: usize = CPU_SETSIZE / CPU_WORD_BITS;

/// BASE_CPUSET 运行时路径，web 端可热更新，未设置时默认 /dev/cpuset/AppOpt
static BASE_CPUSET_PATH: RwLock<Option<String>> = RwLock::new(None);

pub const DEFAULT_CPUSET_NAME: &str = "AppOpt";

/// 校验 cpuset 目录名。名字直接拼进 `/dev/cpuset/<name>`，`/` 之外
/// `.` 与 `..` 同样危险：`.` 退化成根组（线程被迁进去就不再受系统分组约束），
/// `..` 让 base 变成 `/dev`，随后会在 `/dev` 下建 cpus/mems 与集合目录。
///
/// 命令行、配置文件、Web 接口、`set_base_cpuset` 共用这一个判据：以前各处
/// 各写一套，`-b .` 能过命令行的检查却在设置时被静默拒绝，结果单实例锁
/// 按 `.` 命名、实际操作的却是默认目录，两个进程可以同时管一个 cpuset
pub fn validate_cpuset_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("目录名不能为空");
    }
    if name.len() >= 64 {
        return Err("目录名过长");
    }
    if name == "." || name == ".." {
        return Err("不能用 . 或 .. 作为目录名");
    }
    if name.contains('/') || name.contains("..") {
        return Err("目录名不能包含路径分隔符或 ..");
    }
    if name.bytes().any(|b| b <= b' ') {
        return Err("目录名不能包含空白或控制字符");
    }
    Ok(())
}

/// 设置 BASE_CPUSET 目录名。失败时返回原因，调用方必须停下来——
/// 静默回落到默认目录会让「锁名」和「实际路径」对不上
pub fn set_base_cpuset(name: &str) -> Result<(), &'static str> {
    validate_cpuset_name(name)?;
    *BASE_CPUSET_PATH.write().unwrap() = Some(format!("/dev/cpuset/{}", name));
    Ok(())
}

pub fn base_cpuset() -> String {
    BASE_CPUSET_PATH
        .read()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "/dev/cpuset/AppOpt".to_string())
}

/// base 目录的最后一段，用来把「自己的组」和系统组分开
fn base_name() -> String {
    base_cpuset()
        .rsplit('/')
        .next()
        .unwrap_or("AppOpt")
        .to_string()
}

/// 线程所在的 cpuset 组。Android 在组配置变化时会把组内线程的亲和性
/// 强制收敛到组生效集合，这是「刚绑上又变回去」最主要的来源：
/// 不接管组，任何 sched_setaffinity 都会被下一次收敛覆盖
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum SysGroup {
    #[default]
    Unknown,
    /// AppOpt 自己建的组，系统不会碰
    Own,
    TopApp,
    Foreground,
    /// background / system-background / restricted：系统有意压在小核
    Background,
    Other,
}

impl SysGroup {
    pub fn label(self) -> &'static str {
        match self {
            SysGroup::Own => "AppOpt",
            SysGroup::TopApp => "top-app",
            SysGroup::Foreground => "foreground",
            SysGroup::Background => "后台组",
            SysGroup::Other => "其他组",
            SysGroup::Unknown => "未知",
        }
    }
}

/// 读线程所在 cpuset 组路径。cgroup v1 形如 `3:cpuset:/top-app`，
/// v2 形如 `0::/top-app`，两种都要认
pub fn thread_cgroup(tid: i32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{}/cgroup", tid)).ok()?;
    for line in raw.lines() {
        let mut it = line.splitn(3, ':');
        let _id = it.next()?;
        let ctrl = it.next()?;
        let path = it.next()?;
        // v2 的控制器列为空；v1 只有 cpuset 那一行才是我们要的
        if ctrl.is_empty() || ctrl.split(',').any(|c| c == "cpuset") {
            return Some(path.trim().to_string());
        }
    }
    None
}

/// 按组路径归类。只看第一段，子组（如 /foreground/bg）跟随父组语义
/// 读线程在 schedtune（挂载点 `/dev/stune`，控制器名 `schedtune`）层级里的组。
///
/// 这是判断前后台时唯一不会被我们夺走的信号：cpuset 组一旦被
/// `@group=own` 接管，名字就变成 `AppOpt/<集合>`，之后系统把应用切进切出
/// 都不会再改它；而 AMS 每次改前后台都会同步写 stune 组。
///
/// cgroup v2 把 cpuset 与 stune 合并成一个层级（控制器列为空），那时没有
/// 独立信号，返回 `None` 交给 `oom_score_adj` 兜底。
pub fn stune_group(tid: i32) -> Option<SysGroup> {
    let raw = fs::read_to_string(format!("/proc/{}/cgroup", tid)).ok()?;
    for line in raw.lines() {
        let mut it = line.splitn(3, ':');
        let _id = it.next()?;
        let ctrl = it.next()?;
        let path = it.next()?;
        if !ctrl.split(',').any(|c| c == "schedtune" || c == "stune") {
            continue;
        }
        return Some(classify_group(path.trim()));
    }
    None
}

pub fn classify_group(path: &str) -> SysGroup {
    let p = path.trim_matches('/');
    let base = base_name();
    if !base.is_empty() && (p == base || p.starts_with(&format!("{}/", base))) {
        return SysGroup::Own;
    }
    match p.split('/').next().unwrap_or("") {
        "top-app" => SysGroup::TopApp,
        "foreground" => SysGroup::Foreground,
        "background" | "system-background" | "restricted" => SysGroup::Background,
        "" => SysGroup::Unknown,
        _ => SysGroup::Other,
    }
}

/// 生效集合是从哪种途径拿到的。
///
/// 「读不到导出值」和「导出值为空」是两件事：前者靠父链求交兜底，后者是
/// 内核明确说「这组没有可运行核」。把来源写进启动行，排查时不用再猜这台
/// 机器走的是哪条路——真机上两种布局的差异会让同一份配置表现完全不同
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EffectiveCpuSource {
    /// cgroup v1 导出：`cpuset.effective_cpus`
    CpusetEffectiveCpus,
    /// cgroup v2 导出：`cpuset.cpus.effective`
    CpusetCpusEffective,
    /// 少数厂商内核只导出不带前缀的 `effective_cpus`
    EffectiveCpus,
    /// 没有任何导出值，按父链 `cpus` 求交算出来
    FallbackCpus,
    /// 导出值读不到、父链也求不出来
    Unavailable,
}

impl EffectiveCpuSource {
    /// 日志里显示的名字。写成文件名而不是枚举名，读者能直接去目录里核对
    pub fn label(self) -> &'static str {
        match self {
            Self::CpusetEffectiveCpus => "cpuset.effective_cpus",
            Self::CpusetCpusEffective => "cpuset.cpus.effective",
            Self::EffectiveCpus => "effective_cpus",
            Self::FallbackCpus => "父链 cpus 求交",
            Self::Unavailable => "不可用",
        }
    }

    /// 是否来自内核导出。父链求交在「子组 cpus 超出父组」时结果一致，
    /// 但父组文件缺失或只读时可能算偏，日志里要能区分
    pub fn exported(self) -> bool {
        matches!(
            self,
            Self::CpusetEffectiveCpus | Self::CpusetCpusEffective | Self::EffectiveCpus
        )
    }
}

/// 探测顺序。`effective_cpus` 放最后：v2 没有这个文件，v1 也不会同时导出
/// 两个，放在后面只是多一次失败的 open，不会读错
const EFFECTIVE_FILES: [(&str, EffectiveCpuSource); 3] = [
    (
        "cpuset.effective_cpus",
        EffectiveCpuSource::CpusetEffectiveCpus,
    ),
    (
        "cpuset.cpus.effective",
        EffectiveCpuSource::CpusetCpusEffective,
    ),
    ("effective_cpus", EffectiveCpuSource::EffectiveCpus),
];

/// 读导出值并说明来源。空文件按「没导出」处理：v1 的空 effective 表示
/// 该组没有可运行核，让父链求交去给出同样的空结果，归因更准
pub fn read_effective_with_source(dir: &str) -> Option<(String, EffectiveCpuSource)> {
    for (name, src) in EFFECTIVE_FILES {
        if let Ok(s) = fs::read_to_string(format!("{}/{}", dir, name)) {
            let t = s.trim();
            if !t.is_empty() {
                return Some((t.to_string(), src));
            }
        }
    }
    None
}

/// 生效集合的文件名：v1 是 `cpuset.effective_cpus`，v2 是 `cpuset.cpus.effective`。
/// 只读其中一个会让现场信息永远是 `-`，而这一格恰好是判断「不可达」的关键
pub fn read_effective(dir: &str) -> Option<String> {
    read_effective_with_source(dir).map(|(v, _)| v)
}

/// 读一层的 CPU 集合，返回（内容，是否 v2 布局）。
/// 内容为空是有意义的：v2 的空 `cpuset.cpus` 表示「继承父级」，
/// v1 的空 `cpus` 表示「本组没有 CPU」，两者语义相反，不能混
fn read_cpus_file(dir: &str) -> Option<(String, bool)> {
    for (name, v2) in [("cpus", false), ("cpuset.cpus", true)] {
        if let Ok(s) = fs::read_to_string(format!("{}/{}", dir, name)) {
            return Some((s.trim().to_string(), v2));
        }
    }
    None
}

/// 按内核定义自己算生效集合：自身 `cpus` 与所有祖先 `cpus` 的交集。
///
/// 真机 2.3.7 的日志里 `effective` 恒为 `-`——部分 Android 内核不导出
/// `cpuset.effective_cpus`。于是「可达性」永远未知，「尊重系统分组」这条
/// 逻辑一次都没生效，`/background`(0-3) 的线程照样被硬写 4-6，
/// `+2599s` 之后每分钟 495 次 EINVAL 就是这么来的。
///
/// 交集是内核的定义本身，读不到导出值时按定义算，结果一致，也不依赖
/// 内核导出了哪些文件。
pub fn effective_by_walk(root: &str, path: &str) -> Option<String> {
    let mut levels: Vec<String> = vec![root.to_string()];
    let mut cur = root.to_string();
    for seg in path.trim_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        cur.push('/');
        cur.push_str(seg);
        levels.push(cur.clone());
    }
    let mut acc: Option<CpuSet> = None;
    let mut saw_any = false;
    for lv in &levels {
        // 这一层没有 cpus 文件（尚未建的组）就跳过，不当作空集
        let Some((raw, is_v2)) = read_cpus_file(lv) else {
            continue;
        };
        saw_any = true;
        if raw.is_empty() {
            if is_v2 {
                // v2 空值 = 继承父级
                continue;
            }
            // v1 空值 = 本组不可运行任何任务
            return Some(String::new());
        }
        let set = parse_cpu_ranges(&raw, None);
        acc = Some(match acc {
            Some(mut a) => {
                a.and(&set);
                a
            }
            None => set,
        });
    }
    if !saw_any {
        return None;
    }
    acc.map(|s| s.to_range_string())
}

/// `thread_cgroup` 的计数版，供绑核主路径使用。
///
/// 只为周期总账统计「一轮到底读了几次组归属」——这是判断要不要做 PID 级
/// 缓存的唯一依据。诊断路径仍走裸函数：那些读取由限流控制，按需触发，
/// 混进来会让读数失去意义
pub fn thread_cgroup_counted(tid: i32) -> Option<String> {
    crate::diag::note_group_read();
    thread_cgroup(tid)
}

/// 组路径（`/top-app` 这类）对应的生效集合。优先用内核导出值，
/// 读不到再按父链交集自己算
pub fn group_effective(path: &str) -> Option<String> {
    let dir = format!("/dev/cpuset{}", path.trim_end_matches('/'));
    effective_at(&dir)
}

/// 任意 cpuset 目录（挂载点绝对路径）的生效集合。
///
/// 现场打印与组判定必须走同一个口子：一边只读导出文件、另一边按父链求交，
/// 同一个「现场」里就会出现「目标 effective=-，线程组却是 0-7」这种对不上的画面
pub fn effective_at(dir: &str) -> Option<String> {
    effective_at_with_source(dir).map(|(v, _)| v)
}

/// 同 `effective_at`，额外带回来源。父链求交成功但导出值缺失时，
/// 调用方需要知道这个结果不是内核给的，诊断里要写清
pub fn effective_at_with_source(dir: &str) -> Option<(String, EffectiveCpuSource)> {
    let d = dir.trim_end_matches('/');
    if let Some(v) = read_effective_with_source(d) {
        return Some(v);
    }
    effective_by_walk("/dev/cpuset", &cgroup_rel(d))
        .filter(|s| !s.is_empty())
        .map(|s| (s, EffectiveCpuSource::FallbackCpus))
}

/// 组目录自己的 `cpus` 原文，不做父链求交。
///
/// 生效集合是「所有祖先的交集」，用它无法区分「这一层就没写进去」和
/// 「祖先把它卡住了」。裁剪归因要把两个数都摆出来：用户看到
/// 「组 cpus=4-5、effective=4-5」就知道是组本身只有 4-5，而不是核坏了
pub fn group_cpus(dir: &str) -> Option<String> {
    read_cpus_file(dir.trim_end_matches('/')).map(|(s, _)| s)
}

/// 线程所在组的现场：组自己的 cpus、生效集合，以及生效集合是否来自内核导出。
///
/// 裁剪归因不能只给结论，必须给可核对的数字。真机上出现过日志说
/// 「差集来自组集合」，用户去翻组目录却发现 `cpus=0-7` 的情况——
/// 那时结论是错的，真正原因是 CPU 在 online 里却不可调度
pub fn group_evidence(path: &str) -> (Option<String>, Option<String>, bool) {
    let p = path.trim();
    if p.is_empty() || p == "-" {
        return (None, None, false);
    }
    let dir = format!("/dev/cpuset{}", p.trim_end_matches('/'));
    let exported = read_effective(&dir).is_some();
    (group_cpus(&dir), effective_at(&dir), exported)
}

/// 当前在线的 CPU 集合（`/sys/devices/system/cpu/online`）。
///
/// 真机上「规则写 4-6、回读 4-5」不能只归因于 cpuset：这批设备连
/// `cpuset.effective_cpus` 都没导出，父链交集又是 0-7。真正的减法发生在
/// 内核把 `sched_setaffinity` 的掩码与 `cpu_active_mask` 求交——核被
/// hotplug 或 core_ctl 下电时，写进去的 bit 会静默消失。打印裁剪现场时
/// 必须带上这个值，否则读者只能把它当成配置错误
pub fn online_cpus() -> Option<CpuSet> {
    let s = fs::read_to_string("/sys/devices/system/cpu/online").ok()?;
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    Some(parse_cpu_ranges(t, None))
}

/// 生效集合的短时缓存。校验一轮要遍历几百个线程，同一组会被反复求交
/// （`/foreground` 上 172 个线程就是 344 次 open + 按父链求交）。
/// 组配置以秒级稳定，5 秒缓存既跟得上真实变更，也不会把这份开销摊到每个线程
const EFF_TTL: Duration = Duration::from_secs(5);
/// 硬容量上限。TTL 只保证「旧的不被读」，不保证表不会长：
/// 短时间内遍历到大量不同组路径时，过期项还没被清掉就会继续插入。
/// Android 的 cpuset 目录数量有限，128 条足够覆盖，超了就淘汰最早的一条
const EFF_CACHE_CAP: usize = 128;
/// 组路径 → (读取时刻, 生效集合)。`None` 表示读不到，同样缓存：
/// 读不到时按父链求交会连撞几次失败，没必要每个线程重来一遍
type EffCache = HashMap<String, (Instant, Option<String>)>;
static EFF_CACHE: RwLock<Option<EffCache>> = RwLock::new(None);
/// 命中/未命中计数。唯一用途是回答「5 秒 TTL 够不够」：命中率高说明
/// 大多数求交在窗口内复用，未命中率高就得怀疑线程在多个组之间被搬来搬去
static EFF_HIT: AtomicU64 = AtomicU64::new(0);
static EFF_MISS: AtomicU64 = AtomicU64::new(0);

/// 缓存运行数据。只在 `/api/diag` 里出现，不参与任何判定
pub struct EffCacheStat {
    pub hit: u64,
    pub miss: u64,
    pub size: usize,
}

pub fn eff_cache_stat() -> EffCacheStat {
    EffCacheStat {
        hit: EFF_HIT.load(Ordering::Relaxed),
        miss: EFF_MISS.load(Ordering::Relaxed),
        size: EFF_CACHE
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(HashMap::len))
            .unwrap_or(0),
    }
}

/// 插入前的容量整理：先清过期，仍然满就淘汰最早写入的一条。
/// 这里不引入 LRU：缓存只有一百多条，线性扫一遍比维护链表便宜，
/// 也不会因为顺序字段写错而误淘汰刚写进去的热点
fn eff_make_room(m: &mut EffCache, now: Instant) {
    if m.len() < EFF_CACHE_CAP {
        return;
    }
    m.retain(|_, (at, _)| now.duration_since(*at) < EFF_TTL);
    // 过期项清完仍然满，就逐条淘汰最早写入的，直到留出一个空位。
    // 一次只淘汰一条是不够的：表可能已经超了很多，插入后仍然超限
    while m.len() >= EFF_CACHE_CAP {
        let Some(oldest) = m
            .iter()
            .min_by_key(|(_, (at, _))| *at)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        m.remove(&oldest);
    }
}

pub fn group_effective_cached(path: &str) -> Option<String> {
    let now = Instant::now();
    if let Ok(g) = EFF_CACHE.read()
        && let Some(m) = g.as_ref()
        && let Some((at, v)) = m.get(path)
        && now.duration_since(*at) < EFF_TTL
    {
        EFF_HIT.fetch_add(1, Ordering::Relaxed);
        return v.clone();
    }
    EFF_MISS.fetch_add(1, Ordering::Relaxed);
    let v = group_effective(path);
    if let Ok(mut g) = EFF_CACHE.write() {
        let m = g.get_or_insert_with(HashMap::new);
        eff_make_room(m, now);
        m.insert(path.to_string(), (now, v.clone()));
    }
    v
}

/// 作废某个组的生效集合缓存。热插拔、组收紧、EINVAL 之后必须重读：
/// 缓存里的旧值会让同一轮判定反复落在「规则可达」上，写入却一直被拒
pub fn invalidate_effective(path: &str) {
    if let Ok(mut g) = EFF_CACHE.write()
        && let Some(m) = g.as_mut()
    {
        m.remove(path);
    }
}

/// 作废某线程**所在组**的缓存。写入失败时连组路径都要重读：
/// 线程可能刚被系统搬进另一个组，缓存的还是搬家前那个组的生效集合
pub fn invalidate_effective_of(tid: i32) {
    if let Some(path) = thread_cgroup(tid) {
        invalidate_effective(&path);
    }
}

const _: () = assert!(std::mem::size_of::<CpuSet>() == std::mem::size_of::<libc::cpu_set_t>());

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuSet {
    pub bits: [u64; CPU_WORDS],
}

impl std::fmt::Debug for CpuSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CpuSet({})", self.to_range_string())
    }
}

impl CpuSet {
    pub fn new() -> Self {
        CpuSet::default()
    }

    pub fn set(&mut self, cpu: usize) {
        if cpu < CPU_SETSIZE {
            self.bits[cpu / CPU_WORD_BITS] |= 1u64 << (cpu % CPU_WORD_BITS);
        }
    }

    pub fn is_set(&self, cpu: usize) -> bool {
        cpu < CPU_SETSIZE && self.bits[cpu / CPU_WORD_BITS] & (1u64 << (cpu % CPU_WORD_BITS)) != 0
    }

    pub fn count(&self) -> usize {
        self.bits.iter().map(|&b| b.count_ones() as usize).sum()
    }

    pub fn or(&mut self, other: &CpuSet) {
        for (d, &s) in self.bits.iter_mut().zip(other.bits.iter()) {
            *d |= s;
        }
    }

    /// 交集。S7 把目标簇限制在规则允许集合内时用，避免把线程放到规则之外
    pub fn and(&mut self, other: &CpuSet) {
        for (d, &s) in self.bits.iter_mut().zip(other.bits.iter()) {
            *d &= s;
        }
    }

    /// 差集：留在自己里、但不在 `other` 里的核。
    /// 诊断用它回答「规则要的核里有几个此刻不在线」
    pub fn and_not(&mut self, other: &CpuSet) {
        for (d, &s) in self.bits.iter_mut().zip(other.bits.iter()) {
            *d &= !s;
        }
    }

    /// 是否为另一集合的子集。诊断用它区分「被 cpuset 裁小」与「被整体重置」：
    /// 前者是写进去又被内核求交，后者是写进去之后被别的东西改回了全核
    pub fn subset_of(&self, other: &CpuSet) -> bool {
        self.bits
            .iter()
            .zip(other.bits.iter())
            .all(|(a, b)| a & !b == 0)
    }

    pub fn to_range_string(self) -> String {
        let mut result = String::new();
        let mut start: Option<usize> = None;
        let mut end: Option<usize> = None;
        let mut first = true;

        for (word_idx, &word) in self.bits.iter().enumerate() {
            if word == 0 {
                if start.is_some() {
                    push_range(&mut result, start, end, &mut first);
                    start = None;
                    end = None;
                }
                continue;
            }
            let base = word_idx * CPU_WORD_BITS;
            for bit in 0..CPU_WORD_BITS {
                if word & (1u64 << bit) != 0 {
                    let cpu = base + bit;
                    if start.is_none() {
                        start = Some(cpu);
                        end = Some(cpu);
                    } else if end.is_some_and(|e| cpu == e + 1) {
                        end = Some(cpu);
                    } else {
                        push_range(&mut result, start, end, &mut first);
                        start = Some(cpu);
                        end = Some(cpu);
                    }
                }
            }
        }
        push_range(&mut result, start, end, &mut first);
        result
    }

    pub fn get_affinity(tid: i32) -> Option<CpuSet> {
        let mut curr = CpuSet::new();
        let ret = unsafe {
            libc::sched_getaffinity(
                tid,
                std::mem::size_of::<CpuSet>(),
                &mut curr as *mut CpuSet as *mut libc::cpu_set_t,
            )
        };
        if ret == -1 { None } else { Some(curr) }
    }

    pub fn set_affinity(&self, tid: i32) -> io::Result<()> {
        let ret = unsafe {
            libc::sched_setaffinity(
                tid,
                std::mem::size_of::<CpuSet>(),
                self as *const CpuSet as *const libc::cpu_set_t,
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn push_range(s: &mut String, start: Option<usize>, end: Option<usize>, first: &mut bool) {
    if let (Some(lo), Some(hi)) = (start, end) {
        if !*first {
            s.push(',');
        }
        if lo == hi {
            let _ = write!(s, "{}", lo);
        } else {
            let _ = write!(s, "{}-{}", lo, hi);
        }
        *first = false;
    }
}

pub fn parse_cpu_ranges(spec: &str, present: Option<&CpuSet>) -> CpuSet {
    let mut set = CpuSet::new();
    if spec.is_empty() {
        return set;
    }
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = if let Some(pos) = part.find('-') {
            let a: usize = part[..pos].parse().ok().unwrap_or(usize::MAX);
            let b: usize = part[pos + 1..].parse().ok().unwrap_or(a);
            if a == usize::MAX {
                continue;
            }
            if a > b { (b, a) } else { (a, b) }
        } else {
            let a: usize = part.parse().ok().unwrap_or(usize::MAX);
            if a == usize::MAX {
                continue;
            }
            (a, a)
        };
        for i in lo..=hi.min(CPU_SETSIZE - 1) {
            if let Some(present) = present
                && !present.is_set(i)
            {
                continue;
            }
            set.set(i);
        }
    }
    set
}

/// 语义核心名 → 规范名。同时接受 `e-core` 与 `{e_core}`：
/// 花括号形式与「按拓扑展开的占位符」写法一致，旧写法永久兼容。
///
/// 校验（`spec_like`）与解析（`parse_cpu_spec`）必须共用这一个判据，
/// 否则会出现「配置校验通过、解析出空集合」这种只在一侧报错的裂口
fn core_alias(name: &str) -> Option<&'static str> {
    let bare = name
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(name);
    Some(match bare {
        "e-core" | "e_core" => "e-core",
        "p-core" | "p_core" => "p-core",
        "hp-core" | "hp_core" => "hp-core",
        "all-core" | "all_core" => "all-core",
        _ => return None,
    })
}

/// 该段是否是语义核心名（含花括号写法）
pub fn is_semantic_core(name: &str) -> bool {
    core_alias(name).is_some()
}

/// 语义核心名对应的集合。展开发生在配置解析阶段（Present 拓扑），
/// 执行时再被目标组的生效集合裁剪
pub fn semantic_core<'a>(name: &str, topo: &'a CpuTopology) -> Option<&'a CpuSet> {
    match core_alias(name)? {
        "e-core" => Some(&topo.e_core),
        "p-core" => Some(&topo.p_core),
        "hp-core" => Some(&topo.hp_core),
        "all-core" => Some(&topo.present_cpus),
        _ => None,
    }
}

/// 解析 CPU 规格，支持语义核心名(e-core/p-core/hp-core/all-core，
/// 也接受 `{e_core}` 写法)与数字范围混合
pub fn parse_cpu_spec(spec: &str, topo: &CpuTopology) -> CpuSet {
    let mut set = CpuSet::new();
    if spec.is_empty() {
        return set;
    }
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // 语义名展开为对应核心层，其余按数字范围解析
        match semantic_core(part, topo) {
            Some(seg) => set.or(seg),
            None => set.or(&parse_cpu_ranges(part, Some(&topo.present_cpus))),
        }
    }
    set
}

/// 创建 cpuset 子目录并写入 cpus 与 mems
pub(crate) fn create_cpuset_dir(path: &str, cpus: &str, mems: &str) -> bool {
    let c_path = CString::new(path).expect("cpuset path 受控输入，无 NUL");
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), 0o755) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return false;
        }
    }
    if unsafe { libc::chmod(c_path.as_ptr(), 0o755) } != 0 {
        return false;
    }
    if unsafe { libc::chown(c_path.as_ptr(), 0, 0) } != 0 {
        return false;
    }
    let cpus_path = format!("{}/cpus", path);
    if fs::write(&cpus_path, cpus).is_err() {
        return false;
    }
    let mems_path = format!("{}/mems", path);
    fs::write(&mems_path, mems).is_ok()
}

/// 回收 `AppOpt/` 下不再被规则引用、且没有线程驻留的空子目录。
///
/// 只读 + `rmdir`，不做递归：`tasks` 非空一律跳过，`referenced` 里的名字跳过。
/// `rmdir` 失败（非空 / 权限 / 已被删除）全部忽略——清目录是尽力而为，
/// 一个删不掉不该让整轮 GC 报错。返回实际删除的数量。
///
/// 调用方必须在删除后让 `READY_DIRS` 失效（本函数内部已做），否则缓存仍认为
/// 目录就绪，下一次写入会得到 ENOENT，白白触发一轮重建。
pub fn gc_empty_dirs(referenced: &HashSet<String>) -> usize {
    let removed = gc_empty_dirs_at(&base_cpuset(), referenced);
    if removed > 0 {
        crate::apply_affinity::reset_cpuset_dir_cache();
        // 生效集合缓存也按组路径存：被删目录的旧值（很可能是「读不到」甚至
        // 是删除瞬间的 None）会在同名目录重建后继续命中 5 秒。命中 None 会
        // 让判定退回「组不限制」，按全集写进去又被新目录裁小，随后被判成
        // 「写了也白写」停 300 秒。整表清空比逐条删便宜，且只在真删了目录时发生
        if let Ok(mut g) = EFF_CACHE.write() {
            *g = None;
        }
    }
    removed
}

/// `gc_empty_dirs` 的实现，base 可注入以便测试
fn gc_empty_dirs_at(base: &str, referenced: &HashSet<String>) -> usize {
    let entries = match fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        // file_type 不跟随符号链接：cgroupfs 里不该有，但别的一旦有就跳过
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = match entry.file_name().to_str() {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };
        if !gc_reclaimable(base, &name, referenced) {
            continue;
        }
        let path = format!("{}/{}", base, name);
        let Ok(c_path) = CString::new(path) else {
            continue;
        };
        // 直接 rmdir 由内核判定是否为空，避免 stat 与删除之间的竞态
        if unsafe { libc::rmdir(c_path.as_ptr()) } == 0 {
            removed += 1;
        }
    }
    removed
}

/// 单个目录是否满足回收条件：无引用、且 `tasks` 可读且为空。
/// 读不到 `tasks` 就当成「可能有线程」，宁可留一个空目录。
fn gc_reclaimable(base: &str, name: &str, referenced: &HashSet<String>) -> bool {
    if referenced.contains(name) {
        return false;
    }
    match fs::read_to_string(format!("{}/{}/tasks", base, name)) {
        Ok(s) => s.trim().is_empty(),
        Err(_) => false,
    }
}

/// 把一个线程号写进 cgroup 的 `tasks`。
///
/// **必须一次 write 写完，且不带换行。** `writeln!` 会被展开成两次 write
/// （先写数字，再写 `"\n"`）；内核 `__cgroup_procs_write` 收到的第二段是空内容，
/// `kstrtoint(strstrip(buf))` 失败，直接返回 `EINVAL`。于是「线程其实已经迁进
/// 目标组」被读成「EINVAL 迁移失败」：2.3.8 的自检就是被这一行判成
/// 「本机不接受 cgroup 接管」，把整条 cgroup 路关掉了；两步迁组里的 base
/// 回退也一并被误判成「连 base 都写不进去」。
pub fn attach_task(path: &str, tid: i32) -> io::Result<()> {
    let mut buf = [0u8; 12];
    let n = {
        let mut cur = std::io::Cursor::new(&mut buf[..]);
        write!(cur, "{}", tid)?;
        cur.position() as usize
    };
    let mut f = fs::OpenOptions::new().append(true).open(path)?;
    f.write_all(&buf[..n])
}

/// 把挂载路径换成 cgroup 内的相对路径。
///
/// `/proc/<tid>/cgroup` 里的路径永远相对层级根（`/AppOpt`），而 base 是挂载点
/// 下的完整路径（`/dev/cpuset/AppOpt`）。两者直接比较**在任何设备上都不相等**——
/// 2.3.9 的自检就因此把「已经迁进去了」读成「线程仍在原组」，判成
/// 「本机不接受 cgroup 接管」，把整条 cgroup 路永久关掉。日志里那句
/// 「写入返回成功但线程仍在 /AppOpt」正是这个断言失败的产物：
/// `/AppOpt` 就是 base 目录，它其实成功了
fn cgroup_rel(path: &str) -> String {
    let p = path.trim_end_matches('/');
    match p.strip_prefix("/dev/cpuset") {
        Some("") => "/".to_string(),
        Some(rest) if rest.starts_with('/') => rest.to_string(),
        _ => p.to_string(),
    }
}

/// 建组自检：把自己写进 base 的 tasks 一次，写进去之后**回读组归属**，
/// 两件事都对才算真的能用。写返回 0 不代表迁进去了（只读挂载、内核裁剪都可能），
/// 不看回读就下结论，等于用「没报错」冒充「成功了」。
///
/// 真机上出现过「mkdir、写 cpus/mems 全部成功，但写 tasks 一直 EINVAL、
/// `cpuset.effective_cpus` 也读不到」的情况——文件都在，cgroup 却不接受
/// 任何任务。不试一次就无从判断，只能每分钟撞一次失败。
///
/// 失败时立刻把 cpuset 关掉：剩下唯一的绑核手段是 sched_setaffinity，
/// 而它会被系统改组配置时重置，这个结论必须一次说清，而不是反复重试。
fn probe_cpuset(base: &str) -> Result<(), String> {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
    // 写文件用挂载路径，比较用 cgroup 相对路径，两者不能混
    let base_dir = base.trim_end_matches('/');
    let base_norm = cgroup_rel(base);
    // 自检会短暂改变自己的组与亲和性，先备份再恢复，不能留下副作用
    let orig = thread_cgroup(tid);
    let backup = CpuSet::get_affinity(tid);
    let res = (|| {
        attach_task(&format!("{}/tasks", base_dir), tid)
            .map_err(|e| format!("写入失败（{}）", e))?;
        match thread_cgroup(tid) {
            Some(p) if p.trim_end_matches('/') == base_norm => Ok(()),
            Some(p) => Err(format!("写入返回成功但线程仍在 {}（组被禁用或只读）", p)),
            None => Err("写入后读不到线程组归属".to_string()),
        }
    })();
    // 恢复现场：先写回原组，再恢复亲和性。顺序反了会被迁组再裁一次
    if let Some(p) = orig.as_deref()
        && p.trim_end_matches('/') != base_norm
    {
        let _ = attach_task(
            &format!("/dev/cpuset{}/tasks", p.trim_end_matches('/')),
            tid,
        );
    }
    if let Some(b) = backup {
        let _ = b.set_affinity(tid);
    }
    res
}

#[derive(Clone)]
pub struct CpuTopology {
    /// 可调度的 CPU 集合（present ∩ online）。
    ///
    /// 名字沿用历史的 `present`，实际语义是「能写进亲和性掩码的核」。
    /// 离线核刻意不进来：执行层不做 `Rule ∩ online` 的求交，把离线位写进
    /// 掩码只会换来「内核接受但回读不一致」，随后被判成「写了也白写」
    /// 停 300 秒。真机热插拔时这比少绑一个核贵得多
    pub present_cpus: CpuSet,
    pub present_str: String,
    pub mems_str: String,
    pub cpuset_enabled: bool,
    pub e_core: CpuSet,
    pub p_core: CpuSet,
    pub hp_core: CpuSet,
    /// 按 capacity/max_freq 升序排列的**每一层**原始分组，只含在线 CPU。
    ///
    /// `e_core` / `p_core` / `hp_core` 是它的三档视图：≥3 层时首层为 e、
    /// 末层为 hp、中间层并集为 p。保留原始层是为了让「1+2+2+3」这类四簇
    /// 机器不被压成三档后丢失信息——S7 选簇、跨簇判定都需要知道真实簇数。
    /// 无分层信息时为空，读取方必须回退到 e/p/hp
    pub all_tiers: Vec<CpuSet>,
    /// 分层依据：capacity / max_freq / fallback
    pub topo_source: &'static str,
    /// 簇数不足 3 时语义名做了降级映射，规则生效范围与原意不同
    pub topo_degraded: bool,
}

#[cfg(test)]
impl CpuTopology {
    /// 空拓扑，仅供单元测试与空配置使用，不能参与真实决策
    pub fn empty() -> Self {
        Self {
            present_cpus: CpuSet::new(),
            present_str: String::new(),
            mems_str: String::new(),
            cpuset_enabled: false,
            e_core: CpuSet::new(),
            p_core: CpuSet::new(),
            hp_core: CpuSet::new(),
            all_tiers: Vec::new(),
            topo_source: "fallback",
            topo_degraded: true,
        }
    }
}

/// 读取 cpuN/online，节点缺失（如 CPU0）视为在线
pub(crate) fn cpu_is_online(cpu: usize) -> bool {
    match fs::read_to_string(format!("/sys/devices/system/cpu/cpu{}/online", cpu)) {
        Ok(s) => s.trim() != "0",
        Err(_) => true,
    }
}

/// 读取单核 capacity，部分内核不提供该节点时返回 0
pub(crate) fn cpu_capacity(cpu: usize) -> u64 {
    fs::read_to_string(format!("/sys/devices/system/cpu/cpu{}/cpu_capacity", cpu))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// cpufreq policy 或单核 capacity 归并出的候选核组
struct CoreGroup {
    cpus: Vec<usize>,
    capacity: u64,
    max_freq: u64,
}

/// 排序指标：capacity 优先，缺失时整体回退 max_freq。
/// 一次只用一种指标，避免部分簇的缺失值以 0 参与比较被误判成 e-core。
#[derive(Clone, Copy)]
enum RankMetric {
    Capacity,
    MaxFreq,
}

impl RankMetric {
    /// 只有参与分组的簇全部具备同一指标时才可用，否则返回 None 交由调用方降级
    fn pick(groups: &[&CoreGroup]) -> Option<Self> {
        if groups.is_empty() {
            return None;
        }
        if groups.iter().all(|g| g.capacity > 0) {
            Some(RankMetric::Capacity)
        } else if groups.iter().all(|g| g.max_freq > 0) {
            Some(RankMetric::MaxFreq)
        } else {
            None
        }
    }

    fn key(self, g: &CoreGroup) -> u64 {
        match self {
            RankMetric::Capacity => g.capacity,
            RankMetric::MaxFreq => g.max_freq,
        }
    }

    fn source(self) -> &'static str {
        match self {
            RankMetric::Capacity => "capacity",
            RankMetric::MaxFreq => "max_freq",
        }
    }
}

/// 按单一指标排序并合并同指标的簇，结果升序。
///
/// 返回 `None` 表示两种指标都不完整——此时不能猜分层，只能整体降级。
/// 排序与合并是 e/p/hp 三档视图和四层原始视图的共同前提，抽出来是为了
/// 两者不会因为一处改口径而出现「三档说 3 层、原始层说 4 层」的矛盾
fn rank_groups(
    entries: &[CoreGroup],
    online: &CpuSet,
) -> Option<(Vec<(u64, CpuSet)>, &'static str)> {
    // 全部离线的簇不参与分组，其指标缺失也不应牵连整体判定
    let active: Vec<&CoreGroup> = entries
        .iter()
        .filter(|g| g.cpus.iter().any(|&c| online.is_set(c)))
        .collect();
    let metric = RankMetric::pick(&active)?;

    let mut groups: Vec<(u64, CpuSet)> = Vec::new();
    for g in active {
        let key = metric.key(g);
        let mut set = CpuSet::new();
        for &c in &g.cpus {
            if online.is_set(c) {
                set.set(c);
            }
        }
        if set.count() == 0 {
            continue;
        }
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, exist)) => exist.or(&set),
            None => groups.push((key, set)),
        }
    }
    groups.sort_by_key(|(k, _)| *k);
    Some((groups, metric.source()))
}

/// 由候选簇推导语义核心集合：指标完整时按单一指标排序分组，
/// 两种指标都不完整时不猜测分层，直接降级到全部在线 CPU。
///
/// 生产路径走 `classify_tiers` + `derive_cores`（要先拿到原始层再派生三档）；
/// 这里保留单步入口，只给单元测试对照用——两者一旦分叉，测试会立刻发现
#[cfg(test)]
fn classify_cores(
    entries: &[CoreGroup],
    online: &CpuSet,
) -> (CpuSet, CpuSet, CpuSet, &'static str, bool) {
    match rank_groups(entries, online) {
        Some((groups, source)) => map_cores(groups, online, source),
        None => (*online, *online, *online, "fallback", true),
    }
}

/// 保留每一层的原始分组（升序），供 `CpuTopology::all_tiers` 使用。
///
/// 与 `classify_cores` 共用 `rank_groups`：三档视图是这一份数据的派生结果，
/// 不是另算一遍。无分层信息时返回空 Vec，调用方回退到 e/p/hp
fn classify_tiers(entries: &[CoreGroup], online: &CpuSet) -> (Vec<CpuSet>, &'static str) {
    match rank_groups(entries, online) {
        Some((groups, source)) => (groups.into_iter().map(|(_, set)| set).collect(), source),
        None => (Vec::new(), "fallback"),
    }
}

/// 无 cpufreq policy 时按每核 capacity 归并候选簇。
/// 只有全部在线 CPU 都读得到容量才分组：部分 CPU 缺失时分组会漏掉这些 CPU，
/// 排名也随之失真，此时返回空由调用方降级到全部在线 CPU。
fn group_by_cpu_capacity(online: &CpuSet, capacity_of: impl Fn(usize) -> u64) -> Vec<CoreGroup> {
    let mut by_cap: Vec<(u64, Vec<usize>)> = Vec::new();
    let mut missing = false;
    for cpu in 0..CPU_SETSIZE {
        if !online.is_set(cpu) {
            continue;
        }
        let cap = capacity_of(cpu);
        if cap == 0 {
            missing = true;
            continue;
        }
        match by_cap.iter_mut().find(|(c, _)| *c == cap) {
            Some(g) => g.1.push(cpu),
            None => by_cap.push((cap, vec![cpu])),
        }
    }
    if missing {
        return Vec::new();
    }
    by_cap
        .into_iter()
        .map(|(capacity, cpus)| CoreGroup {
            cpus,
            capacity,
            max_freq: 0,
        })
        .collect()
}

/// CPU 分层检测：优先按 capacity 分组，缺失时回退 cpuinfo_max_freq。
/// 只纳入在线 CPU。返回升序的每一层与分层依据；层数不足时由 `derive_cores`
/// 决定语义名怎么降级
fn detect_tiers(online: &CpuSet) -> (Vec<CpuSet>, &'static str) {
    let mut entries: Vec<CoreGroup> = Vec::new();

    if let Ok(dirs) = fs::read_dir("/sys/devices/system/cpu/cpufreq") {
        for entry in dirs.flatten() {
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("policy"))
            {
                continue;
            }
            let cpus: Vec<usize> = ["related_cpus", "cpus"]
                .iter()
                .find_map(|f| fs::read_to_string(path.join(f)).ok())
                .map(|s| {
                    s.split_whitespace()
                        .filter_map(|c| c.parse().ok())
                        .collect()
                })
                .unwrap_or_default();
            if cpus.is_empty() {
                continue;
            }
            let max_freq: u64 = fs::read_to_string(path.join("cpuinfo_max_freq"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let capacity = cpus.iter().map(|&c| cpu_capacity(c)).max().unwrap_or(0);
            // 指标全缺的簇也要保留：它确实存在，只是无法参与排序，
            // 由 classify_cores 判定是否整体降级，不能在此静默丢弃
            entries.push(CoreGroup {
                cpus,
                capacity,
                max_freq,
            });
        }
    }

    // 无 cpufreq（部分内核裁剪）时仍可按每核 capacity 分层
    if entries.is_empty() {
        entries = group_by_cpu_capacity(online, cpu_capacity);
    }

    classify_tiers(&entries, online)
}

/// 由升序的原始层派生三档语义集合。
///
/// 1 层：三者同集合；2 层：p-core 跟随末层（避免 p-core 规则被静默丢弃）；
/// 3 层及以上：首层 e-core、末层 hp-core、中间层并集 p-core。
/// 直接复用 `map_cores`，保证「三档」与「原始层」永远出自同一次排序
fn derive_cores(
    tiers: &[CpuSet],
    online: &CpuSet,
    source: &'static str,
) -> (CpuSet, CpuSet, CpuSet, bool) {
    let groups: Vec<(u64, CpuSet)> = tiers
        .iter()
        .enumerate()
        .map(|(i, set)| (i as u64, *set))
        .collect();
    let (e, p, h, _, degraded) = map_cores(groups, online, source);
    (e, p, h, degraded)
}

/// 核组按 key 升序映射到语义核心名。
/// 1 组：三者同集合；2 组：p-core 跟随末组（避免 p-core 规则被静默丢弃）；
/// 3 组及以上：首组 e-core、末组 hp-core、中间并集为 p-core。
fn map_cores(
    groups: Vec<(u64, CpuSet)>,
    online: &CpuSet,
    source: &'static str,
) -> (CpuSet, CpuSet, CpuSet, &'static str, bool) {
    let n = groups.len();
    match n {
        0 => (*online, *online, *online, "fallback", true),
        1 => (groups[0].1, groups[0].1, groups[0].1, source, true),
        2 => (groups[0].1, groups[1].1, groups[1].1, source, true),
        _ => {
            let mut p = CpuSet::new();
            for (_, set) in &groups[1..n - 1] {
                p.or(set);
            }
            let h = groups[n - 1].1;
            if p.count() == 0 {
                p = h;
            }
            (groups[0].1, p, h, source, false)
        }
    }
}

/// 启动行的分层说明。抽成纯函数只为能单测文案——这是用户唯一能看到的
/// 拓扑结论，层数口径改过一次（三档去重 → 原始层数），必须钉住。
///
/// 层数按原始层算：四簇机器（1+2+2+3）的 p-core 是中间两层并集，
/// 按三档去重会写成「核心层 3」，与实际簇数不符
fn topo_line(t: &CpuTopology) -> String {
    if t.topo_degraded {
        return format!(
            "未能分层（{}，三档同为 {}，语义核心名不生效）",
            t.topo_source, t.present_str
        );
    }
    let layers = t.all_tiers.len().max(1);
    let mut s = format!(
        "e-core {} ｜ p-core {} ｜ hp-core {} ｜ 分层依据 {} ｜ 核心层 {}",
        t.e_core.to_range_string(),
        t.p_core.to_range_string(),
        t.hp_core.to_range_string(),
        t.topo_source,
        layers
    );
    if layers > 3 {
        // 只说「4 层」而不说 p-core 是并集，读者会以为少了一档
        s.push_str(&format!("（p-core 为中间 {} 层并集）", layers - 2));
    }
    s
}

/// 初始化 CPU 拓扑，检测 cpuset 可用性并创建 BASE_CPUSET 目录
pub fn init_cpu_topo() -> CpuTopology {
    let raw = fs::read_to_string("/sys/devices/system/cpu/present")
        .ok()
        .or_else(|| fs::read_to_string("/sys/devices/system/cpu/possible").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut present = parse_cpu_ranges(raw.as_deref().unwrap_or(""), None);
    if present.count() == 0 {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        present = parse_cpu_ranges(&format!("0-{}", n.saturating_sub(1)), None);
    }

    // 离线 CPU 不进入规则集合与 cpuset 写入集合
    let mut online = CpuSet::new();
    for cpu in 0..CPU_SETSIZE {
        if present.is_set(cpu) && cpu_is_online(cpu) {
            online.set(cpu);
        }
    }
    if online.count() == 0 {
        online = present;
    }

    let (tiers, topo_source) = detect_tiers(&online);
    let (e, p, h, topo_degraded) = derive_cores(&tiers, &online, topo_source);

    let mut topo = CpuTopology {
        present_cpus: online,
        present_str: online.to_range_string(),
        mems_str: String::new(),
        cpuset_enabled: false,
        e_core: e,
        p_core: p,
        hp_core: h,
        all_tiers: tiers,
        topo_source,
        topo_degraded,
    };

    crate::diag::tag(
        "环境",
        &format!("CPU 在线 {} ｜ {}", topo.present_str, topo_line(&topo)),
    );

    let cpuset_path = CString::new("/dev/cpuset").expect("常量字符串无 NUL");
    if unsafe { libc::access(cpuset_path.as_ptr(), libc::F_OK) } != 0 {
        return topo;
    }

    let mems = fs::read_to_string("/dev/cpuset/mems")
        .ok()
        .and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() { None } else { Some(t) }
        })
        .unwrap_or_else(|| "0".to_string());
    topo.mems_str = mems;

    if !create_cpuset_dir(&base_cpuset(), &topo.present_str, &topo.mems_str) {
        return topo;
    }
    match probe_cpuset(&base_cpuset()) {
        Ok(()) => {
            topo.cpuset_enabled = true;
            // 生效集合来自导出文件还是父链求交，决定了后面所有「组上限」
            // 判断的可信度。真机上两种布局的解释完全不同，启动时就说清
            let eff_src = ["/dev/cpuset/top-app", "/dev/cpuset"]
                .iter()
                .find_map(|d| effective_at_with_source(d).map(|(_, s)| s))
                .unwrap_or(EffectiveCpuSource::Unavailable);
            // 来源决定「组上限」判断的可信度：导出值是内核当面给的，
            // 父链求交是我们按定义算的，读不到就只能退化直写
            let eff_note = match eff_src {
                EffectiveCpuSource::Unavailable => "（读不到，组可达性判定退化为直写）",
                s if !s.exported() => "（按父链求交，非内核导出）",
                _ => "",
            };
            // 成功也要留一行：真机上「有没有接管成功」直接决定后面所有
            // 绑核行为的解释，不打印就只能靠猜
            crate::diag::tag(
                "环境",
                &format!(
                    "cpuset 可用 {} ｜ 自检通过（tasks 可写）｜ 生效集合来源 {}{} ｜ respect 下只迁「组内能凑出规则核」的线程，后台组不硬抢",
                    base_cpuset(),
                    eff_src.label(),
                    eff_note
                ),
            );
        }
        Err(e) => {
            // 目录建得出、文件写得进，但内核不接受任务：这台设备上
            // cgroup 接管这条路是死的，早说清楚好过每分钟失败一次
            crate::diag::tag(
                "警告",
                &format!(
                    "cpuset 自检失败：{}。本机不接受 cgroup 接管线程，绑核只靠 sched_setaffinity，\
                     系统改动组配置时会被重置",
                    e
                ),
            );
        }
    }

    topo
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

    /// 临时目录。三种 effective 布局靠它挨个搭出来，
    /// 真机上不可能为了跑测试去改 /dev/cpuset
    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("appopt-eff-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("建临时目录");
        p
    }

    fn write(p: &std::path::Path, v: &str) {
        fs::write(p, v).expect("写测试文件");
    }

    /// 三种导出布局都要认，顺序不能反：v1 与 v2 同时存在时以 v1 为准，
    /// 因为 v1 的 `cpuset.effective_cpus` 是内核算好的最终值
    #[test]
    fn effective_reads_all_three_layouts() {
        let d = tmp("layouts");
        write(&d.join("cpuset.effective_cpus"), "0-3\n");
        let (v, src) = read_effective_with_source(d.to_str().unwrap()).expect("v1");
        assert_eq!(
            (v.as_str(), src),
            ("0-3", EffectiveCpuSource::CpusetEffectiveCpus)
        );

        let d2 = tmp("layouts-v2");
        write(&d2.join("cpuset.cpus.effective"), "4-7\n");
        let (v, src) = read_effective_with_source(d2.to_str().unwrap()).expect("v2");
        assert_eq!(
            (v.as_str(), src),
            ("4-7", EffectiveCpuSource::CpusetCpusEffective)
        );

        let d3 = tmp("layouts-bare");
        write(&d3.join("effective_cpus"), "0-7\n");
        let (v, src) = read_effective_with_source(d3.to_str().unwrap()).expect("裸名");
        assert_eq!(
            (v.as_str(), src),
            ("0-7", EffectiveCpuSource::EffectiveCpus)
        );

        for d in [d, d2, d3] {
            let _ = fs::remove_dir_all(&d);
        }
    }

    /// 三种文件都不存在：必须返回 None 交给父链求交，
    /// 而不是编一个空集合出去（空集合会被当成「这组没有可运行核」）
    #[test]
    fn effective_all_missing_is_none() {
        let d = tmp("missing");
        assert!(read_effective_with_source(d.to_str().unwrap()).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    /// 空文件 = 没导出。v1 的空 effective 语义是「无可运行核」，
    /// 但那时父链求交也会得到空结果，让后者给归因（能说清是哪一层卡的）
    #[test]
    fn effective_empty_file_falls_through() {
        let d = tmp("empty");
        write(&d.join("cpuset.effective_cpus"), "  \n");
        write(&d.join("cpuset.cpus.effective"), "2-5\n");
        let (v, src) = read_effective_with_source(d.to_str().unwrap()).expect("应落到 v2");
        assert_eq!(
            (v.as_str(), src),
            ("2-5", EffectiveCpuSource::CpusetCpusEffective)
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// 文件位置被建成了目录（读到 EISDIR）：按不可用跳过，落到下一级。
    /// 真机上出现过厂商把节点做成目录、`read_to_string` 一直失败的情况
    #[test]
    fn effective_unreadable_falls_through() {
        let d = tmp("isdir");
        fs::create_dir_all(d.join("cpuset.effective_cpus")).expect("建同名目录");
        write(&d.join("effective_cpus"), "6,7\n");
        let (v, src) = read_effective_with_source(d.to_str().unwrap()).expect("应落到裸名");
        assert_eq!(
            (v.as_str(), src),
            ("6,7", EffectiveCpuSource::EffectiveCpus)
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// 差集只留「自己要了、对方没有」的核：裁剪归因靠它区分
    /// 「核下线」与「组集合限制」，多算或少算一个核就会给出相反的结论
    #[test]
    fn and_not_leaves_only_missing_cpus() {
        let mut s = set(&[4, 5, 6]);
        s.and_not(&set(&[0, 1, 2, 3, 5, 7]));
        assert_eq!(s.to_range_string(), "4,6");
        // 完全包含时结果为空
        let mut t = set(&[4, 5]);
        t.and_not(&set(&[0, 1, 2, 3, 4, 5, 6, 7]));
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn three_clusters_map_by_key_order() {
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let groups = vec![
            (400, set(&[0, 1, 2, 3])),
            (700, set(&[4, 5])),
            (1024, set(&[6, 7])),
        ];
        let (e, p, h, src, degraded) = map_cores(groups, &online, "capacity");
        assert_eq!(e, set(&[0, 1, 2, 3]));
        assert_eq!(p, set(&[4, 5]));
        assert_eq!(h, set(&[6, 7]));
        assert_eq!(src, "capacity");
        assert!(!degraded);
    }

    #[test]
    fn two_clusters_keep_pcore_rules_alive() {
        // 两簇设备 p-core 必须落到末簇，否则规则会被 parse 阶段丢弃
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let groups = vec![(400, set(&[0, 1, 2, 3])), (1024, set(&[4, 5, 6, 7]))];
        let (e, p, h, _, degraded) = map_cores(groups, &online, "capacity");
        assert_eq!(e, set(&[0, 1, 2, 3]));
        assert_eq!(p, set(&[4, 5, 6, 7]));
        assert_eq!(h, set(&[4, 5, 6, 7]));
        assert!(degraded);
    }

    #[test]
    fn single_cluster_aliases_every_semantic_name() {
        let online = set(&[0, 1, 2, 3]);
        let (e, p, h, src, degraded) = map_cores(vec![(1, online)], &online, "fallback");
        assert_eq!(e, online);
        assert_eq!(p, online);
        assert_eq!(h, online);
        assert_eq!(src, "fallback");
        assert!(degraded);
    }

    #[test]
    fn no_groups_falls_back_to_all_online() {
        let online = set(&[0, 1]);
        let (e, p, h, src, degraded) = map_cores(Vec::new(), &online, "max_freq");
        assert_eq!((e, p, h), (online, online, online));
        assert_eq!(src, "fallback");
        assert!(degraded);
    }

    #[test]
    fn four_clusters_merge_middle_into_pcore() {
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let groups = vec![
            (100, set(&[0, 1])),
            (200, set(&[2, 3])),
            (300, set(&[4, 5])),
            (400, set(&[6, 7])),
        ];
        let (e, p, h, _, degraded) = map_cores(groups, &online, "max_freq");
        assert_eq!(e, set(&[0, 1]));
        assert_eq!(p, set(&[2, 3, 4, 5]));
        assert_eq!(h, set(&[6, 7]));
        assert!(!degraded);
    }

    /// 四层机器（1+2+2+3）必须保住原始层：三档视图里 p-core 是中间两层
    /// 的并集，但 S7 选簇要知道真实层数与每层边界
    #[test]
    fn all_tiers_keep_every_cluster_of_four_layer_soc() {
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let entries = vec![
            grp(&[0], 200, 0),
            grp(&[1, 2], 500, 0),
            grp(&[3, 4], 800, 0),
            grp(&[5, 6, 7], 1024, 0),
        ];
        let (tiers, src) = classify_tiers(&entries, &online);
        assert_eq!(src, "capacity");
        assert_eq!(tiers.len(), 4, "四簇不能被压成三档：{:?}", tiers);
        assert_eq!(tiers[0], set(&[0]));
        assert_eq!(tiers[1], set(&[1, 2]));
        assert_eq!(tiers[2], set(&[3, 4]));
        assert_eq!(tiers[3], set(&[5, 6, 7]));

        let (e, p, h, degraded) = derive_cores(&tiers, &online, src);
        assert_eq!(e, set(&[0]));
        assert_eq!(p, set(&[1, 2, 3, 4]));
        assert_eq!(h, set(&[5, 6, 7]));
        assert!(!degraded);
    }

    /// 2+2+4：三档与三层一一对应
    #[test]
    fn all_tiers_two_plus_two_plus_four() {
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let entries = vec![
            grp(&[0, 1], 300, 0),
            grp(&[2, 3], 600, 0),
            grp(&[4, 5, 6, 7], 1024, 0),
        ];
        let (tiers, src) = classify_tiers(&entries, &online);
        assert_eq!(tiers, vec![set(&[0, 1]), set(&[2, 3]), set(&[4, 5, 6, 7])]);
        let (e, p, h, degraded) = derive_cores(&tiers, &online, src);
        assert_eq!((e, p, h), (set(&[0, 1]), set(&[2, 3]), set(&[4, 5, 6, 7])));
        assert!(!degraded);
    }

    /// 1+3+4：层数够三档，但与「小核 4 个」的常见布局一样要求层边界准确
    #[test]
    fn all_tiers_one_plus_three_plus_four() {
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let entries = vec![
            grp(&[0], 200, 0),
            grp(&[1, 2, 3], 700, 0),
            grp(&[4, 5, 6, 7], 1024, 0),
        ];
        let (tiers, src) = classify_tiers(&entries, &online);
        assert_eq!(tiers, vec![set(&[0]), set(&[1, 2, 3]), set(&[4, 5, 6, 7])]);
        let (e, p, h, _) = derive_cores(&tiers, &online, src);
        assert_eq!((e, p, h), (set(&[0]), set(&[1, 2, 3]), set(&[4, 5, 6, 7])));
    }

    /// 单层 / 两层：三档全部降级，all_tiers 仍如实反映层数
    #[test]
    fn all_tiers_single_and_two_layer_degrade() {
        let online = set(&[0, 1, 2, 3]);

        let one = vec![grp(&[0, 1, 2, 3], 1024, 0)];
        let (tiers, src) = classify_tiers(&one, &online);
        assert_eq!(tiers.len(), 1);
        let (e, p, h, degraded) = derive_cores(&tiers, &online, src);
        assert_eq!((e, p, h), (online, online, online));
        assert!(degraded);

        let two = vec![grp(&[0, 1], 512, 0), grp(&[2, 3], 1024, 0)];
        let (tiers, src) = classify_tiers(&two, &online);
        assert_eq!(tiers.len(), 2);
        let (e, p, h, degraded) = derive_cores(&tiers, &online, src);
        // 两档时 p-core 跟随末层，避免 p-core 规则被静默丢成小核
        assert_eq!((e, p, h), (set(&[0, 1]), set(&[2, 3]), set(&[2, 3])));
        assert!(degraded);
    }

    /// 全离线的簇整层消失：不能留一个空层去占 hp-core 的位置
    #[test]
    fn all_tiers_drop_fully_offline_cluster() {
        let online = set(&[0, 1, 2, 3]);
        let entries = vec![
            grp(&[0, 1], 300, 0),
            grp(&[2, 3], 700, 0),
            grp(&[4, 5], 1024, 0), // 整簇离线
        ];
        let (tiers, src) = classify_tiers(&entries, &online);
        assert_eq!(tiers.len(), 2, "离线簇不该占层：{:?}", tiers);
        let (e, p, h, degraded) = derive_cores(&tiers, &online, src);
        assert_eq!(e, set(&[0, 1]));
        assert_eq!(p, set(&[2, 3]), "hp 落回最后仍在线的那层");
        assert_eq!(h, set(&[2, 3]));
        assert!(degraded);
    }

    #[test]
    fn numeric_ranges_respect_present_mask() {
        let present = set(&[0, 2, 4]);
        assert_eq!(parse_cpu_ranges("0-7", Some(&present)), present);
        assert_eq!(parse_cpu_ranges("1-5", Some(&present)), set(&[2, 4]));
    }

    fn topo3() -> CpuTopology {
        CpuTopology {
            present_cpus: set(&[0, 1, 2, 3, 4, 5, 6, 7]),
            present_str: "0-7".into(),
            mems_str: "0".into(),
            cpuset_enabled: true,
            e_core: set(&[0, 1, 2, 3]),
            p_core: set(&[4, 5]),
            hp_core: set(&[6, 7]),
            all_tiers: vec![set(&[0, 1, 2, 3]), set(&[4, 5]), set(&[6, 7])],
            topo_source: "capacity",
            topo_degraded: false,
        }
    }

    /// 占位符与旧语义名必须展开成同一集合：新增写法是为了「配置里一眼看出
    /// 这是按拓扑展开的」，不是为了引入第二套语义
    /// 启动行的层数按原始层，不按三档去重
    #[test]
    fn topo_line_reports_real_cluster_count() {
        let mut t = topo3();
        let line = topo_line(&t);
        assert!(line.contains("核心层 3"), "{}", line);
        assert!(!line.contains("并集"), "三簇不该提并集：{}", line);

        // 四簇：p-core 是中间两层并集，必须写出来
        t.all_tiers = vec![set(&[0]), set(&[1, 2]), set(&[3, 4]), set(&[5, 6, 7])];
        t.p_core = set(&[1, 2, 3, 4]);
        t.hp_core = set(&[5, 6, 7]);
        let line = topo_line(&t);
        assert!(line.contains("核心层 4"), "{}", line);
        assert!(line.contains("p-core 为中间 2 层并集"), "{}", line);

        // 降级：不能说「核心层 N」，否则会被读成分层成功
        t.topo_degraded = true;
        let line = topo_line(&t);
        assert!(line.contains("未能分层"), "{}", line);
        assert!(!line.contains("核心层"), "{}", line);
    }

    #[test]
    fn brace_placeholders_expand_like_legacy_names() {
        let t = topo3();
        assert_eq!(parse_cpu_spec("{e_core}", &t), set(&[0, 1, 2, 3]));
        assert_eq!(parse_cpu_spec("{p_core}", &t), set(&[4, 5]));
        assert_eq!(parse_cpu_spec("{hp_core}", &t), set(&[6, 7]));
        assert_eq!(parse_cpu_spec("{all_core}", &t), t.present_cpus);

        // 旧写法永久兼容，两者结果必须一致
        assert_eq!(parse_cpu_spec("e-core", &t), parse_cpu_spec("{e_core}", &t));
        assert_eq!(
            parse_cpu_spec("hp-core", &t),
            parse_cpu_spec("{hp_core}", &t)
        );

        // 与数字混合、花括号里写连字符都要认
        assert_eq!(parse_cpu_spec("{hp_core},0", &t), set(&[0, 6, 7]));
        assert_eq!(parse_cpu_spec("{hp-core}", &t), set(&[6, 7]));

        // 未知占位符不能悄悄展开成全集——那会把「写错了」变成「绑了所有核」
        assert_eq!(parse_cpu_spec("{x_core}", &t).count(), 0);
        assert!(!is_semantic_core("{x_core}"));
        assert!(is_semantic_core("{e_core}"));
        assert!(is_semantic_core("all-core"));
    }
    fn grp(cpus: &[usize], capacity: u64, max_freq: u64) -> CoreGroup {
        CoreGroup {
            cpus: cpus.to_vec(),
            capacity,
            max_freq,
        }
    }

    #[test]
    fn capacity_complete_ranks_by_capacity_only() {
        // max_freq 顺序与 capacity 相反：混用指标会把首簇排错
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let entries = vec![
            grp(&[0, 1, 2, 3], 400, 3_000_000),
            grp(&[4, 5], 700, 2_000_000),
            grp(&[6, 7], 1024, 1_000_000),
        ];
        let (e, p, h, src, degraded) = classify_cores(&entries, &online);
        assert_eq!(e, set(&[0, 1, 2, 3]));
        assert_eq!(p, set(&[4, 5]));
        assert_eq!(h, set(&[6, 7]));
        assert_eq!(src, "capacity");
        assert!(!degraded);
    }

    #[test]
    fn capacity_partial_switches_whole_ranking_to_max_freq() {
        // 缺 capacity 的簇不能以 0 参与排序，整体改用 max_freq
        let online = set(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let entries = vec![
            grp(&[0, 1, 2, 3], 0, 1_000_000),
            grp(&[4, 5], 700, 2_000_000),
            grp(&[6, 7], 1024, 3_000_000),
        ];
        let (e, p, h, src, degraded) = classify_cores(&entries, &online);
        assert_eq!(e, set(&[0, 1, 2, 3]));
        assert_eq!(p, set(&[4, 5]));
        assert_eq!(h, set(&[6, 7]));
        assert_eq!(src, "max_freq");
        assert!(!degraded);
    }

    #[test]
    fn both_metrics_partial_degrades_to_all_online() {
        let online = set(&[0, 1, 2, 3]);
        let entries = vec![grp(&[0, 1], 0, 1_000_000), grp(&[2, 3], 512, 0)];
        let (e, p, h, src, degraded) = classify_cores(&entries, &online);
        assert_eq!((e, p, h), (online, online, online));
        assert_eq!(src, "fallback");
        assert!(degraded);
    }

    #[test]
    fn cluster_without_metrics_is_not_ranked_as_ecore() {
        // 旧逻辑缺 capacity 时改用 max_freq，该簇 key 落成 0 被排到最前，
        // 与小核簇合并成 e-core；现在两种指标都不完整，整体降级
        let online = set(&[0, 1, 2, 3, 4, 5]);
        let entries = vec![
            grp(&[0, 1], 512, 0),
            grp(&[2, 3], 0, 0),
            grp(&[4, 5], 1024, 0),
        ];
        let (e, p, h, src, degraded) = classify_cores(&entries, &online);
        assert_eq!((e, p, h), (online, online, online));
        assert_eq!(src, "fallback");
        assert!(degraded);
    }

    #[test]
    fn per_cpu_capacity_groups_when_cpufreq_missing() {
        let online = set(&[0, 1, 2, 3, 4, 5]);
        let caps = [400u64, 400, 700, 700, 1024, 1024];
        let entries = group_by_cpu_capacity(&online, |c| caps[c]);
        assert_eq!(entries.len(), 3);
        let (e, p, h, src, degraded) = classify_cores(&entries, &online);
        assert_eq!(e, set(&[0, 1]));
        assert_eq!(p, set(&[2, 3]));
        assert_eq!(h, set(&[4, 5]));
        assert_eq!(src, "capacity");
        assert!(!degraded);
    }

    #[test]
    fn partial_cpu_capacity_without_cpufreq_degrades() {
        // 只有一个 CPU 缺容量时不能只给其余 CPU 分组
        let online = set(&[0, 1, 2, 3]);
        let caps = [512u64, 512, 512, 0];
        let entries = group_by_cpu_capacity(&online, |c| caps[c]);
        assert!(entries.is_empty());
        let (e, p, h, src, degraded) = classify_cores(&entries, &online);
        assert_eq!((e, p, h), (online, online, online));
        assert_eq!(src, "fallback");
        assert!(degraded);
    }

    #[test]
    fn no_metric_degrades_every_semantic_name() {
        let online = set(&[0, 1]);
        let (e, p, h, src, degraded) = classify_cores(&[], &online);
        assert_eq!((e, p, h), (online, online, online));
        assert_eq!(src, "fallback");
        assert!(degraded);
    }

    #[test]
    fn offline_cluster_metrics_do_not_force_degrade() {
        // cpu4-7 离线，该簇指标全缺只影响它自己，不应牵连在线簇的分层
        let online = set(&[0, 1, 2, 3]);
        let entries = vec![
            grp(&[0, 1], 512, 0),
            grp(&[2, 3], 1024, 0),
            grp(&[4, 5, 6, 7], 0, 0),
        ];
        let (e, p, h, src, degraded) = classify_cores(&entries, &online);
        assert_eq!(e, set(&[0, 1]));
        assert_eq!(p, set(&[2, 3]));
        assert_eq!(h, set(&[2, 3]));
        assert_eq!(src, "capacity");
        assert!(degraded);
    }

    /// 写入必须一次完成且不带换行。`writeln!` 会被拆成「数字」+「\n」两次
    /// write，内核收到只有换行的第二段直接返回 EINVAL——线程其实已经迁进去了，
    /// 却被记成失败。2.3.8 的自检就是被这一行判成「本机不接受 cgroup 接管」
    #[test]
    fn attach_task_writes_digits_only_in_one_shot() {
        let dir = std::env::temp_dir().join(format!("ao_attach_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("tasks");
        fs::write(&p, "").unwrap();

        attach_task(p.to_str().unwrap(), 13552).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"13552", "不得带换行符");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 自检回读的路径口径：/proc/<tid>/cgroup 给的是 `/AppOpt`，
    /// base 给的是 `/dev/cpuset/AppOpt`。修复前两者直接比较，永远不等，
    /// 于是「迁移成功」被读成「线程仍在原组」，cgroup 路被永久关掉
    #[test]
    fn probe_compares_paths_in_same_units() {
        assert_eq!(cgroup_rel("/dev/cpuset/AppOpt"), "/AppOpt");
        assert_eq!(cgroup_rel("/dev/cpuset/AppOpt/"), "/AppOpt");
        assert_eq!(cgroup_rel("/AppOpt"), "/AppOpt");
        assert_eq!(cgroup_rel("/dev/cpuset"), "/");
        assert_eq!(cgroup_rel("/dev/cpuset/"), "/");
        // 真正的失败必须仍然判得出来：线程在别的组
        assert_ne!(cgroup_rel("/dev/cpuset/AppOpt"), "/top-app");
        assert_ne!(cgroup_rel("/dev/cpuset/AppOpt"), "/AppOpt2");
    }

    /// Android 的 cpuset 组名决定线程能不能上大核，分类错一个，
    /// 「尊重系统分组」就会误伤前台线程或白放过后台线程
    #[test]
    fn group_classification_covers_android_sets() {
        assert_eq!(classify_group("/top-app"), SysGroup::TopApp);
        assert_eq!(classify_group("/foreground"), SysGroup::Foreground);
        assert_eq!(classify_group("/foreground/bg"), SysGroup::Foreground);
        assert_eq!(classify_group("/background"), SysGroup::Background);
        assert_eq!(classify_group("/system-background"), SysGroup::Background);
        assert_eq!(classify_group("/restricted"), SysGroup::Background);
        assert_eq!(classify_group("/AppOpt"), SysGroup::Own);
        assert_eq!(classify_group("/AppOpt/4-6"), SysGroup::Own);
        assert_eq!(classify_group("/"), SysGroup::Unknown);
        assert_eq!(classify_group("/camera-daemon"), SysGroup::Other);
    }

    /// 生效集合必须自己按父链求交集：真机 2.3.7 的日志里
    /// `cpuset.effective_cpus` 读不到，导致「可达性」永远未知，
    /// background(0-3) 的线程被硬写 4-6，每分钟几百次 EINVAL
    #[test]
    fn effective_walks_ancestors_and_intersects() {
        let root = std::env::temp_dir().join(format!("ao_walk_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let r = root.to_str().unwrap();
        fs::create_dir_all(root.join("AppOpt/4-6")).unwrap();
        fs::create_dir_all(root.join("background")).unwrap();
        fs::write(root.join("cpus"), "0-7\n").unwrap();
        fs::write(root.join("AppOpt/cpus"), "0-7\n").unwrap();
        fs::write(root.join("AppOpt/4-6/cpus"), "4-6\n").unwrap();
        fs::write(root.join("background/cpus"), "0-3\n").unwrap();

        assert_eq!(
            effective_by_walk(r, "/AppOpt/4-6").as_deref(),
            Some("4-6"),
            "三层交集应等于最内层"
        );
        assert_eq!(effective_by_walk(r, "/background").as_deref(), Some("0-3"));
        assert_eq!(effective_by_walk(r, "/").as_deref(), Some("0-7"));

        // 子组超出父组时必须被裁掉，这正是「内核为什么拒绝」的依据
        fs::write(root.join("AppOpt/4-6/cpus"), "4-9\n").unwrap();
        assert_eq!(effective_by_walk(r, "/AppOpt/4-6").as_deref(), Some("4-7"));

        let _ = fs::remove_dir_all(&root);
    }

    /// v2 的空 `cpuset.cpus` 表示继承父级，v1 的空 `cpus` 表示本组
    /// 没有 CPU。两种语义相反，判错会把「继承全核」当成「无核可用」
    #[test]
    fn effective_handles_v2_inheritance_and_v1_empty() {
        let root = std::env::temp_dir().join(format!("ao_walk2_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let r = root.to_str().unwrap();
        fs::create_dir_all(root.join("top-app")).unwrap();
        fs::create_dir_all(root.join("empty_v1")).unwrap();
        fs::write(root.join("cpuset.cpus"), "0-7\n").unwrap();
        fs::write(root.join("cpuset.mems"), "0\n").unwrap();
        fs::write(root.join("top-app/cpuset.cpus"), "\n").unwrap();
        fs::write(root.join("empty_v1/cpus"), "\n").unwrap();

        assert_eq!(
            effective_by_walk(r, "/top-app").as_deref(),
            Some("0-7"),
            "v2 空值继承父级"
        );
        assert_eq!(
            effective_by_walk(r, "/empty_v1").as_deref(),
            Some(""),
            "v1 空值表示该组不能运行任务"
        );

        // 显式值时 v2 同样要参与交集
        fs::write(root.join("top-app/cpuset.cpus"), "4-7\n").unwrap();
        assert_eq!(effective_by_walk(r, "/top-app").as_deref(), Some("4-7"));

        let _ = fs::remove_dir_all(&root);
    }

    /// 生效集合的文件名 v1/v2 不同，只认一种就会把所有组都判成「未知」
    #[test]
    fn effective_reads_both_cgroup_layouts() {
        let dir = std::env::temp_dir().join(format!("ao_eff_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("cpuset.effective_cpus"), "0-3\n").unwrap();
        assert_eq!(
            read_effective(dir.to_str().unwrap()).as_deref(),
            Some("0-3")
        );

        fs::remove_file(dir.join("cpuset.effective_cpus")).unwrap();
        fs::write(dir.join("cpuset.cpus.effective"), "4-7\n").unwrap();
        assert_eq!(
            read_effective(dir.to_str().unwrap()).as_deref(),
            Some("4-7")
        );

        fs::remove_file(dir.join("cpuset.cpus.effective")).unwrap();
        assert_eq!(read_effective(dir.to_str().unwrap()), None);
        let _ = fs::remove_dir_all(&dir);
    }

    /// 三种布局各自能被认出来，且顺序是 v1 → v2 → 裸名。
    ///
    /// 顺序不是随便定的：同一个目录里同时存在两种文件只可能是内核在过渡期
    /// 双写，此时 v1 的值才是内核真正用来计算的那个。裸名 `effective_cpus`
    /// 放最后，避免某些 ROM 的无关文件被当成效生集合
    #[test]
    fn effective_source_names_three_layouts_in_order() {
        let dir = std::env::temp_dir().join(format!("ao_effsrc_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let d = dir.to_str().unwrap();

        // 只有 v1
        fs::write(dir.join("cpuset.effective_cpus"), "0-3\n").unwrap();
        assert_eq!(
            read_effective_with_source(d),
            Some(("0-3".to_string(), EffectiveCpuSource::CpusetEffectiveCpus))
        );

        // v1 + v2 同时存在：v1 优先
        fs::write(dir.join("cpuset.cpus.effective"), "4-7\n").unwrap();
        assert_eq!(
            read_effective_with_source(d).map(|(_, s)| s),
            Some(EffectiveCpuSource::CpusetEffectiveCpus)
        );

        // 只剩 v2
        fs::remove_file(dir.join("cpuset.effective_cpus")).unwrap();
        assert_eq!(
            read_effective_with_source(d),
            Some(("4-7".to_string(), EffectiveCpuSource::CpusetCpusEffective))
        );

        // 只剩裸名
        fs::remove_file(dir.join("cpuset.cpus.effective")).unwrap();
        fs::write(dir.join("effective_cpus"), "6-7\n").unwrap();
        assert_eq!(
            read_effective_with_source(d),
            Some(("6-7".to_string(), EffectiveCpuSource::EffectiveCpus))
        );

        // 空文件算「没导出」，不能返回空串——空串会被当成「该组无核」，
        // 与「读不到」的处理方向相反
        fs::write(dir.join("effective_cpus"), "  \n").unwrap();
        assert_eq!(read_effective_with_source(d), None);

        let _ = fs::remove_dir_all(&dir);
    }

    /// 来源的可读名与「是否内核导出」两件事都要对：父链求交的结果
    /// 与导出值在子组越界时可能不同，日志里必须能区分
    #[test]
    fn effective_source_labels_are_distinguishable() {
        assert_eq!(
            EffectiveCpuSource::CpusetEffectiveCpus.label(),
            "cpuset.effective_cpus"
        );
        assert!(EffectiveCpuSource::CpusetCpusEffective.exported());
        assert!(EffectiveCpuSource::EffectiveCpus.exported());
        assert!(!EffectiveCpuSource::FallbackCpus.exported());
        assert!(!EffectiveCpuSource::Unavailable.exported());
    }

    /// 回收判定只放行「无引用 + tasks 为空」的目录：有线程驻留的目录一旦被删，
    /// 线程会瞬间落回 root cpuset，等于把系统分组限制整个绕开
    #[test]
    fn gc_only_reclaims_unreferenced_empty_dirs() {
        let base = std::env::temp_dir().join(format!("ao_gc_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        // 空、无引用 → 可回收
        fs::create_dir_all(base.join("0-3")).unwrap();
        fs::write(base.join("0-3/tasks"), "").unwrap();

        // 空、但被规则引用 → 不可回收
        fs::create_dir_all(base.join("4-7")).unwrap();
        fs::write(base.join("4-7/tasks"), "\n").unwrap();

        // 有线程 → 不可回收
        fs::create_dir_all(base.join("0-7")).unwrap();
        fs::write(base.join("0-7/tasks"), "1234\n").unwrap();

        // 没有 tasks（不是 cgroup 目录 / 读失败）→ 不可回收
        fs::create_dir_all(base.join("6-7")).unwrap();

        let b = base.to_str().unwrap();
        let mut referenced = HashSet::new();
        referenced.insert("4-7".to_string());
        assert!(gc_reclaimable(b, "0-3", &referenced), "空且无引用应回收");
        assert!(!gc_reclaimable(b, "4-7", &referenced), "被引用不能回收");
        assert!(!gc_reclaimable(b, "0-7", &referenced), "有线程不能回收");
        assert!(
            !gc_reclaimable(b, "6-7", &referenced),
            "读不到 tasks 不能回收"
        );

        let _ = fs::remove_dir_all(&base);
        // base 不存在时整体返回 0，不 panic
        assert_eq!(gc_empty_dirs_at(b, &referenced), 0);
    }

    /// 命令行、配置文件、Web 接口、set_base_cpuset 必须共用同一套判据。
    /// 以前命令行只拦 `/`，`-b .` 能过；设置阶段静默拒掉后回落到默认目录，
    /// 于是锁名按 `.` 建、实际却操作 `/dev/cpuset/AppOpt`，两个实例能同时管
    /// 命令行、配置文件、Web 接口、set_base_cpuset 必须共用同一套判据。
    /// 以前命令行只拦 `/`，`-b .` 能过；设置阶段静默拒掉后回落到默认目录，
    /// 于是锁名按 `.` 建、实际却操作 `/dev/cpuset/AppOpt`，两个实例能同时管
    #[test]
    fn cpuset_name_is_validated_consistently() {
        for bad in ["", ".", "..", "a/b", "a..b", "a b", "a\tb"] {
            assert!(validate_cpuset_name(bad).is_err(), "{:?} 应当被拒绝", bad);
        }
        let long = "x".repeat(64);
        assert!(validate_cpuset_name(&long).is_err(), "64 字符应被拒绝");
        for ok in ["AppOpt", "AppOpt-8", "sched_2", &"x".repeat(63)] {
            assert!(validate_cpuset_name(ok).is_ok(), "{:?} 应当通过", ok);
        }
    }

    /// 生效集合缓存的容量上限是硬的：TTL 只保证过期项不被读，
    /// 不能阻止短时间内插入大量未过期路径把表撑大
    #[test]
    fn eff_cache_capacity_is_hard_capped() {
        let now = Instant::now();
        let mut m: EffCache = HashMap::new();
        // 全部在 TTL 内，retain 清不掉，只能靠淘汰最早的一条
        for i in 0..EFF_CACHE_CAP + 32 {
            m.insert(
                format!("/g{i}"),
                (now - Duration::from_millis(i as u64), None),
            );
        }
        eff_make_room(&mut m, now);
        assert!(m.len() < EFF_CACHE_CAP, "容量必须落到上限以下");
        // 写入最早的那条被淘汰，最新插入的保留
        assert!(!m.contains_key(&format!("/g{}", EFF_CACHE_CAP + 31)));
        assert!(m.contains_key("/g0"));
    }
}
