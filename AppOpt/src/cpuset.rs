use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::io::Write as _;

use std::sync::RwLock;
use std::time::{Duration, Instant};

pub const CPU_SETSIZE: usize = 1024;
pub const CPU_WORD_BITS: usize = 64;
pub const CPU_WORDS: usize = CPU_SETSIZE / CPU_WORD_BITS;

/// BASE_CPUSET 运行时路径，web 端可热更新，未设置时默认 /dev/cpuset/AppOpt
static BASE_CPUSET_PATH: RwLock<Option<String>> = RwLock::new(None);

pub const DEFAULT_CPUSET_NAME: &str = "AppOpt";

/// 设置 BASE_CPUSET 目录名。名字直接拼进 `/dev/cpuset/<name>`，`/` 之外
/// `.` 与 `..` 同样危险：`.` 退化成根组（线程被迁进去就不再受系统分组约束），
/// `..` 让 base 变成 `/dev`，随后会在 `/dev` 下建 cpus/mems 与集合目录
pub fn set_base_cpuset(name: &str) {
    if name.is_empty() || name.len() >= 64 || name.contains('/') || name.contains("..") {
        return;
    }
    if name == "." || name == ".." || name.bytes().any(|b| b <= b' ') {
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
    let d = dir.trim_end_matches('/');
    if let Some(eff) = read_effective(d) {
        return Some(eff);
    }
    effective_by_walk("/dev/cpuset", &cgroup_rel(d)).filter(|s| !s.is_empty())
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
/// 组路径 → (读取时刻, 生效集合)。`None` 表示读不到，同样缓存：
/// 读不到时按父链求交会连撞几次失败，没必要每个线程重来一遍
type EffCache = HashMap<String, (Instant, Option<String>)>;
static EFF_CACHE: RwLock<Option<EffCache>> = RwLock::new(None);

pub fn group_effective_cached(path: &str) -> Option<String> {
    let now = Instant::now();
    if let Ok(g) = EFF_CACHE.read()
        && let Some(m) = g.as_ref()
        && let Some((at, v)) = m.get(path)
        && now.duration_since(*at) < EFF_TTL
    {
        return v.clone();
    }
    let v = group_effective(path);
    if let Ok(mut g) = EFF_CACHE.write() {
        let m = g.get_or_insert_with(HashMap::new);
        if m.len() > 64 {
            m.retain(|_, (at, _)| now.duration_since(*at) < EFF_TTL);
        }
        m.insert(path.to_string(), (now, v.clone()));
    }
    v
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
pub(crate) fn cpu_is_online(cpu: usize) -> bool {
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
        if present.is_set(cpu) && cpu_is_online(cpu) {
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

    // 分层结果直接给「哪几个核是哪一档」+ 依据，规则行随后引用这些档名
    // 三档取不同集合的个数。降级映射时三档是同一个集合，按「非空集合数」
    // 会算成 3 层——这正是把「本机没分层」写成「核心层 3」的原因
    let mut uniq: Vec<String> = Vec::new();
    for c in [topo.e_core, topo.p_core, topo.hp_core] {
        if c.count() > 0 {
            let s = c.to_range_string();
            if !uniq.contains(&s) {
                uniq.push(s);
            }
        }
    }
    let layers = uniq.len();
    let cores = if topo.topo_degraded {
        format!(
            "未能分层（{}，三档同为 {}，语义核心名不生效）",
            topo.topo_source, topo.present_str
        )
    } else {
        format!(
            "e-core {} ｜ p-core {} ｜ hp-core {} ｜ 分层依据 {} ｜ 核心层 {}",
            topo.e_core.to_range_string(),
            topo.p_core.to_range_string(),
            topo.hp_core.to_range_string(),
            topo.topo_source,
            layers
        )
    };
    crate::diag::tag(
        "环境",
        &format!("CPU 在线 {} ｜ {}", topo.present_str, cores),
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
            // 成功也要留一行：真机上「有没有接管成功」直接决定后面所有
            // 绑核行为的解释，不打印就只能靠猜
            crate::diag::tag(
                "环境",
                &format!(
                    "cpuset 就绪 {}（受管线程可迁入，规则集合不再被系统组裁剪）",
                    base_cpuset()
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
}
