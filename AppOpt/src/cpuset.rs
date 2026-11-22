use std::ffi::CString;
use std::fmt::Write as _;
use std::fs;
use std::io;

use std::sync::RwLock;

pub const CPU_SETSIZE: usize = 1024;
pub const CPU_WORD_BITS: usize = 64;
pub const CPU_WORDS: usize = CPU_SETSIZE / CPU_WORD_BITS;

/// BASE_CPUSET 运行时路径，web 端可热更新，未设置时默认 /dev/cpuset/AppOpt
static BASE_CPUSET_PATH: RwLock<Option<String>> = RwLock::new(None);

pub const DEFAULT_CPUSET_NAME: &str = "AppOpt";

/// 设置 BASE_CPUSET 目录名，name 为空或含 / 时忽略
pub fn set_base_cpuset(name: &str) {
    if name.is_empty() || name.contains('/') {
        return;
    }
    *BASE_CPUSET_PATH.write().unwrap() = Some(format!("/dev/cpuset/{}", name));
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
    pub fn is_background(self) -> bool {
        self == SysGroup::Background
    }

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

pub fn thread_group(tid: i32) -> SysGroup {
    thread_cgroup(tid)
        .map(|p| classify_group(&p))
        .unwrap_or(SysGroup::Unknown)
}

/// 生效集合的文件名：v1 是 `cpuset.effective_cpus`，v2 是 `cpuset.cpus.effective`。
/// 只读其中一个会让现场信息永远是 `-`，而这一格恰好是判断「不可达」的关键
pub fn read_effective(dir: &str) -> Option<String> {
    for name in ["cpuset.effective_cpus", "cpuset.cpus.effective"] {
        if let Ok(s) = fs::read_to_string(format!("{}/{}", dir, name)) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// 组路径（`/top-app` 这类）对应的生效集合
pub fn group_effective(path: &str) -> Option<String> {
    read_effective(&format!("/dev/cpuset{}", path.trim_end_matches('/')))
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

/// 解析 CPU 规格，支持语义核心名(e-core/p-core/hp-core)与数字范围混合
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
        let seg = match part {
            "e-core" => &topo.e_core,
            "p-core" => &topo.p_core,
            "hp-core" => &topo.hp_core,
            "all-core" => &topo.present_cpus,
            _ => {
                set.or(&parse_cpu_ranges(part, Some(&topo.present_cpus)));
                continue;
            }
        };
        set.or(seg);
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

#[derive(Clone)]
pub struct CpuTopology {
    pub present_cpus: CpuSet,
    pub present_str: String,
    pub mems_str: String,
    pub cpuset_enabled: bool,
    pub e_core: CpuSet,
    pub p_core: CpuSet,
    pub hp_core: CpuSet,
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
            topo_source: "fallback",
            topo_degraded: true,
        }
    }
}

/// 读取 cpuN/online，节点缺失（如 CPU0）视为在线
fn cpu_online(cpu: usize) -> bool {
    match fs::read_to_string(format!("/sys/devices/system/cpu/cpu{}/online", cpu)) {
        Ok(s) => s.trim() != "0",
        Err(_) => true,
    }
}

/// 读取单核 capacity，部分内核不提供该节点时返回 0
fn cpu_capacity(cpu: usize) -> u64 {
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

/// 由候选簇推导语义核心集合：指标完整时按单一指标排序分组，
/// 两种指标都不完整时不猜测分层，直接降级到全部在线 CPU。
fn classify_cores(
    entries: &[CoreGroup],
    online: &CpuSet,
) -> (CpuSet, CpuSet, CpuSet, &'static str, bool) {
    // 全部离线的簇不参与分组，其指标缺失也不应牵连整体判定
    let active: Vec<&CoreGroup> = entries
        .iter()
        .filter(|g| g.cpus.iter().any(|&c| online.is_set(c)))
        .collect();
    let Some(metric) = RankMetric::pick(&active) else {
        return (*online, *online, *online, "fallback", true);
    };

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

    map_cores(groups, online, metric.source())
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
/// 只纳入在线 CPU；簇数不足 3 时按 e-core → 首簇、hp-core → 末簇、p-core 跟随末簇降级，
/// 无任何分层信息时三个语义名全部映射到在线 CPU 集合，避免语义规则整体失效。
fn detect_core_types(online: &CpuSet) -> (CpuSet, CpuSet, CpuSet, &'static str, bool) {
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

    classify_cores(&entries, online)
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
        if present.is_set(cpu) && cpu_online(cpu) {
            online.set(cpu);
        }
    }
    if online.count() == 0 {
        online = present;
    }

    let (e, p, h, topo_source, topo_degraded) = detect_core_types(&online);

    let mut topo = CpuTopology {
        present_cpus: online,
        present_str: online.to_range_string(),
        mems_str: String::new(),
        cpuset_enabled: false,
        e_core: e,
        p_core: p,
        hp_core: h,
        topo_source,
        topo_degraded,
    };

    crate::diag::emit(&format!(
        "CPU 拓扑: 在线[{}] e-core[{}] p-core[{}] hp-core[{}] 依据={}{}",
        topo.present_str,
        topo.e_core.to_range_string(),
        topo.p_core.to_range_string(),
        topo.hp_core.to_range_string(),
        topo.topo_source,
        if topo.topo_degraded {
            "（簇数不足，语义核心已降级映射）"
        } else {
            ""
        }
    ));

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

    if create_cpuset_dir(&base_cpuset(), &topo.present_str, &topo.mems_str) {
        topo.cpuset_enabled = true;
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

    #[test]
    fn numeric_ranges_respect_present_mask() {
        let present = set(&[0, 2, 4]);
        assert_eq!(parse_cpu_ranges("0-7", Some(&present)), present);
        assert_eq!(parse_cpu_ranges("1-5", Some(&present)), set(&[2, 4]));
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
}
