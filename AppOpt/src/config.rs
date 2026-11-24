use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use crate::cpuset::{CpuSet, CpuTopology, base_cpuset, create_cpuset_dir, parse_cpu_spec};
use crate::{CONFIG_UPDATED, MAX_PKG_LEN, MAX_THREAD_LEN, lock_ignore_poison};

pub static INOTIFY_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static INOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
pub static INOTIFY_WD: AtomicI32 = AtomicI32::new(-1);

/// 运行时可调参数，web 端热更新
pub static CHECK_INTERVAL: AtomicU64 = AtomicU64::new(2);
pub static FORCE_RELOAD: AtomicBool = AtomicBool::new(false);
pub static CONFIG_FILE: Mutex<String> = Mutex::new(String::new());
/// 上一次真正生效的「内容 + 拓扑」指纹。一次保存往往触发两三个 CLOSE_WRITE
/// （编辑器先写临时文件再改名、WebUI 分两次落盘），mtime 每次都变，
/// 只靠 mtime 去重挡不住——真机上出现过 396 次写触发 99 次重解析、
/// 以及一次保存 2 秒内解析两遍的情况
static RELOAD_SIG: AtomicU64 = AtomicU64::new(0);
static RELOAD_SIG_SET: AtomicBool = AtomicBool::new(false);

/// 线程规则的匹配具体度。只由 pattern 形态决定、与线程名无关，
/// 因此可以在解析阶段预计算一次，匹配时不必比较字符串。
///
/// 顺序即优先级：精确 > 区间/字符类 > `?` 通配 > `*` 通配 > 包级兜底。
/// 同档仍按原有 OR 合并——档内多条规则写的是同一类线程，取并集是用户
/// 已经依赖的语义；跨档则只取最高档，否则「精确规则 + 通配规则」会被
/// 并成一个谁都没写的集合
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum MatchSpecificity {
    /// 包级规则（无线程名），永远最后一档
    #[default]
    PackageFallback = 0,
    StarWildcard = 1,
    QuestionWildcard = 2,
    /// 含 `[`：`Thread-[0-9]?` 的意图是「Thread- 加两位数字」，
    /// 比 `Thread-?` 更具体，所以 `[` 优先于 `?`
    Range = 3,
    Exact = 4,
}

impl MatchSpecificity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Exact => "精确",
            Self::Range => "区间",
            Self::QuestionWildcard => "? 通配",
            Self::StarWildcard => "* 通配",
            Self::PackageFallback => "包级兜底",
        }
    }
}

/// 按 pattern 形态定档。判定顺序有讲究：先看 `[`，再看 `*`，最后 `?`。
/// `[0-9]*` 只算 `*` 通配（`*` 可以吞掉任意长度，具体度不再由字符类决定）
pub fn spec_of_pattern(pattern: &str) -> MatchSpecificity {
    if pattern.contains('*') {
        MatchSpecificity::StarWildcard
    } else if pattern.contains('[') {
        MatchSpecificity::Range
    } else if pattern.contains('?') {
        MatchSpecificity::QuestionWildcard
    } else {
        MatchSpecificity::Exact
    }
}

pub struct AffinityRule {
    pub pkg: String,
    pub thread: String,
    pub thread_pattern: CString,
    /// 解析期算好的匹配档位，匹配时只做枚举比较
    pub spec: MatchSpecificity,
    pub cpuset_dir: String,
    pub cpus: CpuSet,
}

/// 同一包的规则下标，决策时不再遍历全部规则
#[derive(Default)]
pub struct PkgRules {
    pub pkg_rules: Vec<usize>,
    pub thread_rules: Vec<usize>,
}

/// S7 三档模式。默认 off：不采样、不产生系统调用，与纯静态规则行为一致
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum SchedMode {
    #[default]
    Off = 0,
    /// 采样与判定，只记录不迁移
    Shadow = 1,
    /// 全部约束满足时提交 sched_setaffinity
    On = 2,
}

/// RT 全局模式。默认 off：升级后不改变任何现有设备的调度行为
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RtScope {
    #[default]
    Off,
    /// 全部已管理应用按同一套规则启用
    Global,
    /// 只对显式启用的应用生效
    PerApp,
}

/// 单个应用（或 global 模式）的线程匹配方式
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum RtMatch {
    /// 角色为 Critical 且允许集合不超过 2 核
    #[default]
    Auto,
    /// 显式线程名，支持 fnmatch
    Names(Vec<String>),
}

impl RtMatch {
    fn label(&self) -> String {
        match self {
            RtMatch::Auto => "auto（仅 Critical，允许集合 ≤2 核）".to_string(),
            RtMatch::Names(v) => format!("{} 条线程名", v.len()),
        }
    }
}

/// 分应用配置。缺省即关闭，`@rt.app` 未出现的包不会获得 RT
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AppRt {
    pub enabled: bool,
    pub mode: RtMatch,
    pub max_threads: u8,
}

/// 每进程 RT 线程上限的缺省值。2 个是经验值：再多就拿不到 CFS 的公平性
pub const RT_DEFAULT_MAX: u8 = 2;
/// 缺省 RR 时间片。内核默认 100 ms 对渲染线程过长
pub const RT_DEFAULT_TIMESLICE: u32 = 3;
/// 单进程 RT 线程上限的允许范围。超过 8 个等于放弃 CFS 公平性
pub const RT_MAX_LIMIT: u8 = 8;
/// 时间片允许范围（毫秒）
pub const RT_TIMESLICE_LIMIT: u32 = 100;

/// RT 总配置。`timeslice_ms` 是全局内核参数，不支持按应用设置，
/// 因此在任何应用启用时统一生效，全部关闭时还原
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RtConfig {
    pub scope: RtScope,
    /// global 模式下使用的线程匹配方式
    pub global: RtMatch,
    /// global 与分应用条目的缺省上限
    pub max_per_app: u8,
    pub timeslice_ms: u32,
    pub apps: HashMap<String, AppRt>,
}

impl Default for RtConfig {
    fn default() -> Self {
        Self {
            scope: RtScope::Off,
            global: RtMatch::Auto,
            max_per_app: RT_DEFAULT_MAX,
            timeslice_ms: RT_DEFAULT_TIMESLICE,
            apps: HashMap::new(),
        }
    }
}

impl RtConfig {
    pub fn is_off(&self) -> bool {
        self.scope == RtScope::Off
    }

    /// 该包是否有资格获得 RT，返回匹配方式与线程上限。
    /// 这只回答「配置允许」，实际能否提升还要看规则允许集合与当前调度策略
    pub fn policy(&self, pkg: &str) -> Option<(&RtMatch, u8)> {
        match self.scope {
            RtScope::Off => None,
            RtScope::Global => Some((&self.global, self.max_per_app)),
            RtScope::PerApp => self
                .apps
                .get(pkg)
                .filter(|a| a.enabled)
                .map(|a| (&a.mode, a.max_threads)),
        }
    }

    pub fn label(&self) -> String {
        match self.scope {
            RtScope::Off => "off".to_string(),
            RtScope::Global => format!("global（{}）", self.global.label()),
            RtScope::PerApp => {
                let n = self.apps.values().filter(|a| a.enabled).count();
                format!("per_app（{} 个应用启用）", n)
            }
        }
    }
}

pub struct AppConfig {
    pub rules: Vec<AffinityRule>,
    pub pkgs: HashSet<String>,
    pub has_thread_rules: HashSet<String>,
    /// 内核 comm 最多 15 字节，长包名只能按前/后 15 字节比较；
    /// 预建键表把 O(包数) 的线性前缀/后缀扫描降到 O(1)
    pub trunc_keys: HashSet<[u8; 15]>,
    /// 按包索引的规则下标表
    pub rule_index: HashMap<String, PkgRules>,
    /// 每个包当前规则的指纹，配置热更新时用于判断哪些包真正发生变化
    pub pkg_sig: HashMap<String, u64>,
    /// 影响所有包的全局策略指纹（当前为 @unmatched），单独比对才能发现这类变更
    pub policy_sig: u64,
    /// 线程未命中任何线程规则、且包无包级规则时的行为：
    /// false（默认 keep）保持原亲和性，true（all）沿用旧行为设为全部核心
    pub unmatched_all: bool,
    /// 是否尊重系统 cpuset 分组。为 true 时，线程被 Android 放在
    /// background / system-background / restricted 组且目标核不在该组
    /// 生效集合内，就不去硬绑——内核本来就会拒绝，硬试只会造成无效迁移。
    /// `@sysgroup=takeover` 关闭该行为，把线程从系统组里强行拉出来
    pub sysgroup_respect: bool,
    /// 跨簇规则统计，仅用于展示 S7 的潜在作用面
    pub sched_scope: SchedScope,
    /// 允许集合横跨多个核心层的包。S7 靠线程名判角色，这些包即使没有线程规则
    /// 也必须采集 comm，否则 S7 对「只有包级规则」的应用完全失效
    pub sched_pkgs: HashSet<String>,
    /// S7 模式，off 时运行期零开销
    pub sched: SchedMode,
    /// 息屏时放松周期复核：`@screen=relax` 打开。只降低「复查频率」，
    /// 不影响新线程的首次绑定；息屏判定本身不依赖该开关
    pub screen_relax: bool,
    /// 接管组归属：掩码已正确、但线程还在系统组里时补写一次 cpuset。
    /// `@group=mask` 可退回 2.6.1 的行为（只写 sched_setaffinity）。
    ///
    /// 与 `@sysgroup` 的区别：那个管「交集为空时要不要硬抬」，这个管
    /// 「交集够、但线程还没进自己的组」——后者才是「每分钟被系统重置」的根因
    pub group_own: bool,
    /// RT 配置。off 时运行期不查询任何线程的调度策略
    pub rt: RtConfig,
    pub topo: CpuTopology,
}

impl AppConfig {
    /// 配置变更后可以被 GC 复用的「目录引用集」。
    ///
    /// 包级规则的目录在解析时就写进 `rule.cpuset_dir`；线程规则的目录是
    /// 命中时才按合并后的集合派生（见 `thread_affinity`），配置里没有任何
    /// 字段存它。只收集前者，会把「线程规则正在用、但此刻恰好没有线程
    /// 驻留」的目录判成无主而回收——下次命中有一次 ENOENT 抖动。
    ///
    /// 这里补两类近似：每条线程规则自己的集合（单条命中的结果）与该包
    /// 全部线程规则的并集（全命中的结果）。中间组合枚举不出来，但漏掉的
    /// 目录里只要还有线程，`rmdir` 本身就会失败，不会真的删掉
    pub fn referenced_cpuset_dirs(&self) -> HashSet<String> {
        let mut out: HashSet<String> = self
            .rules
            .iter()
            .filter(|r| !r.cpuset_dir.is_empty())
            .map(|r| r.cpuset_dir.clone())
            .collect();
        for pr in self.rule_index.values() {
            if pr.thread_rules.is_empty() {
                continue;
            }
            let mut all = CpuSet::new();
            for &i in &pr.thread_rules {
                let r = &self.rules[i];
                out.insert(r.cpus.to_range_string());
                all.or(&r.cpus);
            }
            if all.count() > 0 {
                out.insert(all.to_range_string());
            }
        }
        out
    }

    /// 该包是否需要读取线程名。三个消费方：线程规则匹配、S7 角色判定、RT 匹配。
    /// 只在任一成立时才读 `/proc/<tid>/comm`，不给无关应用增加开销；
    /// S7 关闭时跨簇包也不再采集，避免留下无意义的读取
    pub fn needs_comm(&self, pkg: &str) -> bool {
        self.has_thread_rules.contains(pkg)
            || (self.sched != SchedMode::Off && self.sched_pkgs.contains(pkg))
            || self.rt.policy(pkg).is_some()
    }

    /// 是否存在真正会被管理的 RT 应用。全局时间片是否改写以此为闸门：
    /// 光有 `@rt=global` 但列表里没有任何受管包时，一个线程都不会被提升，
    /// 这时改 `sched_rr_timeslice_ms` 只会影响别人的 RR 线程
    pub fn rt_active(&self) -> bool {
        match self.rt.scope {
            RtScope::Off => false,
            RtScope::Global => !self.pkgs.is_empty(),
            RtScope::PerApp => self
                .rt
                .apps
                .iter()
                .any(|(pkg, a)| a.enabled && self.pkgs.contains(pkg)),
        }
    }
}

#[cfg(test)]
impl AppConfig {
    /// 空配置。单元测试与 RT 退出路径使用，不代表任何真实规则
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            pkgs: HashSet::new(),
            has_thread_rules: HashSet::new(),
            trunc_keys: HashSet::new(),
            rule_index: HashMap::new(),
            pkg_sig: HashMap::new(),
            policy_sig: 0,
            unmatched_all: false,
            sysgroup_respect: true,
            sched_scope: SchedScope::default(),
            sched_pkgs: HashSet::new(),
            sched: SchedMode::Off,
            screen_relax: false,
            group_own: true,
            rt: RtConfig::default(),
            topo: CpuTopology::empty(),
        }
    }
}

/// 构建按包索引，保持规则原有顺序即保持原有并集语义
fn build_rule_index(rules: &[AffinityRule]) -> HashMap<String, PkgRules> {
    let mut index: HashMap<String, PkgRules> = HashMap::new();
    for (i, rule) in rules.iter().enumerate() {
        let entry = index.entry(rule.pkg.clone()).or_default();
        if rule.thread.is_empty() {
            entry.pkg_rules.push(i);
        } else {
            entry.thread_rules.push(i);
        }
    }
    index
}

fn rule_hash(rule: &AffinityRule) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    rule.thread.hash(&mut h);
    rule.cpus.to_range_string().hash(&mut h);
    h.finish()
}

/// 逐包指纹：同包规则哈希排序后再哈希，保证与书写顺序无关、重复规则可区分
fn build_pkg_sig(rules: &[AffinityRule]) -> HashMap<String, u64> {
    let mut per: HashMap<String, Vec<u64>> = HashMap::new();
    for rule in rules {
        per.entry(rule.pkg.clone())
            .or_default()
            .push(rule_hash(rule));
    }
    per.into_iter()
        .map(|(pkg, mut hashes)| {
            hashes.sort_unstable();
            let mut h = std::collections::hash_map::DefaultHasher::new();
            hashes.hash(&mut h);
            (pkg, h.finish())
        })
        .collect()
}

/// 全局策略指纹：逐包指纹只覆盖规则本身，@unmatched / @sched / @rt 这类
/// 影响所有包的开关变化不会体现在 pkg_sig 里，必须单独比对，
/// 否则已缓存线程不会重新应用，`on → off` 也回滚不了。
/// RT 的每一项都要进来：分应用开关、匹配方式、上限、时间片变化都要触发全量重扫
fn build_policy_sig(
    unmatched_all: bool,
    sysgroup_respect: bool,
    sched: SchedMode,
    screen_relax: bool,
    group_own: bool,
    rt: &RtConfig,
) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    unmatched_all.hash(&mut h);
    sysgroup_respect.hash(&mut h);
    (sched as u8).hash(&mut h);
    // 息屏放松只影响复查节奏，但切换时要让主循环立即按新策略排下一次复查，
    // 所以也进指纹；否则改了这一行要等下一次规则变化才生效
    screen_relax.hash(&mut h);
    // 接管开关决定要不要补组，切换时必须整轮重扫，否则已绑的线程还留在
    // 系统组里，用户看不到任何变化
    group_own.hash(&mut h);
    (rt.scope as u8).hash(&mut h);
    match &rt.global {
        RtMatch::Auto => 0u8.hash(&mut h),
        RtMatch::Names(v) => {
            1u8.hash(&mut h);
            // 名字列表是 OR 语义，顺序无关，排序后再哈希避免误判变更
            let mut sorted: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
            sorted.sort_unstable();
            sorted.hash(&mut h);
        }
    }
    rt.max_per_app.hash(&mut h);
    rt.timeslice_ms.hash(&mut h);
    // 分应用表按包名排序后逐项哈希，保证与书写顺序无关
    let mut apps: Vec<(&String, &AppRt)> = rt.apps.iter().collect();
    apps.sort_by(|a, b| a.0.cmp(b.0));
    for (pkg, a) in apps {
        pkg.hash(&mut h);
        a.enabled.hash(&mut h);
        a.max_threads.hash(&mut h);
        match &a.mode {
            RtMatch::Auto => 0u8.hash(&mut h),
            RtMatch::Names(v) => {
                1u8.hash(&mut h);
                let mut sorted: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
                sorted.sort_unstable();
                sorted.hash(&mut h);
            }
        }
    }
    h.finish()
}

/// S7 收益面统计：动态分配只在「一条规则的允许集合横跨多个核心层」时才有作用面。
/// 解析期一次性计算，不参与运行期决策，也不产生系统调用。
#[derive(Clone, Copy, Default)]
pub struct SchedScope {
    /// 去重后的实际核心层数：降级拓扑下 e/p/hp 会指向同一集合，按语义名数会虚高
    pub levels: usize,
    /// 允许集合横跨两层及以上的规则数
    pub rules: usize,
    /// 上述规则涉及的包数，比规则条数更接近实际收益面
    pub pkgs: usize,
}

/// 两个 CPU 集合是否有交集
fn intersects(a: &CpuSet, b: &CpuSet) -> bool {
    a.bits.iter().zip(b.bits.iter()).any(|(x, y)| x & y != 0)
}

/// 统计跨簇规则。等于在线全集的规则视为「不限制」，不计入：
/// 写 0-7 的用户本来就没打算指定核心层，动态分配对他没有信息可加。
/// 同时返回涉及的包集合，供线程名采集判定使用（S7 判角色必须有 comm）
fn sched_scope(rules: &[AffinityRule], topo: &CpuTopology) -> (SchedScope, HashSet<String>) {
    let mut levels: Vec<CpuSet> = Vec::new();
    for s in [topo.e_core, topo.p_core, topo.hp_core] {
        if s.count() > 0 && !levels.contains(&s) {
            levels.push(s);
        }
    }
    let mut scope = SchedScope {
        levels: levels.len(),
        ..SchedScope::default()
    };
    let mut pkgs: HashSet<String> = HashSet::new();
    if levels.len() < 2 {
        return (scope, pkgs);
    }

    // 与 rule_match::thread_affinity 同口径：同一包内「相同线程模式」的多行
    // 规则会 OR 合并成一个集合。逐条统计会把
    //   com.a { Worker-*=p-core
    //           Worker-*=hp-core }
    // 判成「两条各占一个簇」，scope.rules 归零，S7 直接把采样关掉，
    // 而线程实际拿到的是 p-core ∪ hp-core —— 用户配的正是跨簇规则
    let mut merged: HashMap<(String, String), (CpuSet, usize)> = HashMap::new();
    for r in rules {
        if r.cpus.count() == 0 {
            continue;
        }
        let e = merged
            .entry((r.pkg.clone(), r.thread.clone()))
            .or_insert_with(|| (CpuSet::new(), 0));
        e.0.or(&r.cpus);
        e.1 += 1;
    }
    for ((pkg, _), (cpus, n)) in merged {
        // 合并后等于在线全集才视为「不限制」：单条写 0-7 与两条各写一半
        // 都要区分开，后者合起来仍可能是全集
        if cpus == topo.present_cpus {
            continue;
        }
        let hit = levels.iter().filter(|l| intersects(&cpus, l)).count();
        if hit > 1 {
            // 计的是原始规则条数，日志里的「跨簇 N/总条数」才对得上
            scope.rules += n;
            pkgs.insert(pkg);
        }
    }
    scope.pkgs = pkgs.len();
    (scope, pkgs)
}

/// 包名被截断到 15 字节时可能命中的键（前缀 + 后缀），与内核白名单同构
fn build_trunc_keys(pkgs: &HashSet<String>) -> HashSet<[u8; 15]> {
    let mut keys = HashSet::with_capacity(pkgs.len() * 2);
    for pkg in pkgs {
        let b = pkg.as_bytes();
        if b.len() < 15 {
            continue;
        }
        keys.insert(b[..15].try_into().expect("切片长度固定 15"));
        keys.insert(b[b.len() - 15..].try_into().expect("切片长度固定 15"));
    }
    keys
}

pub static CURRENT_CONFIG: Mutex<Option<Arc<AppConfig>>> = Mutex::new(None);

pub static PARSE_FAILS: AtomicUsize = AtomicUsize::new(0);

/// 校验 CPU 规格形态
pub fn spec_like(s: &str) -> bool {
    let mut any = false;
    for part in s.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        any = true;
        // 语义核心名与解析共用同一判据（含 `{e_core}` 写法）
        let ok = crate::cpuset::is_semantic_core(t)
            || t.bytes().all(|b| b.is_ascii_digit())
            || t.split_once('-').is_some_and(|(a, b)| {
                !a.is_empty()
                    && !b.is_empty()
                    && a.bytes().all(|b| b.is_ascii_digit())
                    && b.bytes().all(|b| b.is_ascii_digit())
            });
        if !ok {
            return false;
        }
    }
    any
}

pub fn comment_at(s: &str) -> Option<usize> {
    let mut prev_ws = false;
    for (i, c) in s.char_indices() {
        if prev_ws && (c == '#' || (c == '/' && s[i..].starts_with("//"))) {
            return Some(s[..i].trim_end().len());
        }
        prev_ws = c.is_whitespace();
    }
    None
}

pub fn strip_comment(s: &str) -> &str {
    &s[..comment_at(s).unwrap_or(s.len())]
}

pub fn split_rule_line(p: &str) -> Option<(&str, &str, bool)> {
    let p = strip_comment(p);
    fn kv(s: &str) -> Option<(&str, &str)> {
        s.rfind('=')
            .map(|eq| (s[..eq].trim(), s[eq + 1..].trim()))
            .filter(|(k, _)| !k.is_empty())
    }
    p.match_indices('}')
        .find_map(|(cb, _)| kv(&p[..cb]).map(|(k, v)| (k, v, true)))
        .or_else(|| kv(p).map(|(k, v)| (k, v, false)))
}

pub fn close_like(p: &str) -> bool {
    p.strip_prefix('}').is_some_and(|r| {
        r.is_empty()
            || r.starts_with(char::is_whitespace)
            || r.starts_with('#')
            || r.starts_with("//")
    })
}

pub fn split_single_line(body: &str) -> Option<(&str, &str, &str)> {
    let eq = body.rfind('=')?;
    let cpus = body[eq + 1..].trim();
    let left = body[..eq].trim_end().strip_suffix('}')?.trim_end();
    let ob = left.find('{')?;
    let (pkg, thread) = (left[..ob].trim(), left[ob + 1..].trim());
    (!pkg.is_empty() && !thread.is_empty()).then_some((pkg, thread, cpus))
}

pub enum OuterLine<'a> {
    Rule {
        pkg: &'a str,
        cpus: &'a str,
        open: bool,
    },
    BareOpen {
        pkg: &'a str,
    },
    Pending {
        pkg: &'a str,
    },
    Single {
        pkg: &'a str,
        thread: &'a str,
        cpus: &'a str,
        open: bool,
    },
    Junk,
}

pub fn parse_outer(p: &str) -> OuterLine<'_> {
    let p = strip_comment(p);
    let (open, body) = match p.strip_suffix('{') {
        Some(b) => (true, b.trim_end()),
        None => (false, p),
    };
    if let Some((pkg, thread, cpus)) = split_single_line(body) {
        return OuterLine::Single {
            pkg,
            thread,
            cpus,
            open,
        };
    }
    if !open && close_like(body) {
        return OuterLine::Junk;
    }
    match body.rfind('=') {
        Some(eq) => {
            let (pkg, cpus) = (body[..eq].trim(), body[eq + 1..].trim());
            if cpus.is_empty() {
                return if open {
                    OuterLine::BareOpen { pkg }
                } else {
                    OuterLine::Pending { pkg }
                };
            }
            OuterLine::Rule { pkg, cpus, open }
        }
        None => {
            if open {
                OuterLine::BareOpen { pkg: body }
            } else {
                OuterLine::Pending { pkg: body }
            }
        }
    }
}

fn add_rule(
    rules: &mut Vec<AffinityRule>,
    topo: &CpuTopology,
    pkg: &str,
    thread: &str,
    cpus_spec: &str,
) -> bool {
    if pkg.is_empty() || pkg.len() >= MAX_PKG_LEN || thread.len() >= MAX_THREAD_LEN {
        return false;
    }
    if pkg
        .bytes()
        .chain(thread.bytes())
        .any(|b| b < 0x20 || b == 0x7f)
    {
        return false;
    }
    if !spec_like(cpus_spec) {
        return false;
    }
    let set = parse_cpu_spec(cpus_spec, topo);
    if set.count() == 0 {
        return false;
    }
    let cpuset_dir = if thread.is_empty() {
        let dir_name = set.to_range_string();
        if topo.cpuset_enabled {
            let path = format!("{}/{}", base_cpuset(), dir_name);
            if create_cpuset_dir(&path, &dir_name, &topo.mems_str) {
                dir_name
            } else {
                Default::default()
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    rules.push(AffinityRule {
        pkg: pkg.to_string(),
        thread: thread.to_string(),
        thread_pattern: CString::new(thread).unwrap_or_default(),
        spec: spec_of_pattern(thread),
        cpuset_dir,
        cpus: set,
    });
    true
}

/// 逗号分隔的线程名模式，供 `@rt` 与 `@rt.app` 共用
fn split_names(s: &str) -> Option<Vec<String>> {
    let names: Vec<String> = s
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty() && x.len() < MAX_THREAD_LEN)
        .map(str::to_string)
        .collect();
    if names.is_empty() { None } else { Some(names) }
}

/// 解析 `@rt.app=<包名> <模式> [上限]`。
/// 模式为 `auto` / `names:RenderThread,RHI*` / `off`，省略时按 auto 处理；
/// 上限省略时用 `@rt.max`，与配置行顺序无关
fn parse_rt_app(arg: &str, default_max: u8) -> Option<(String, AppRt)> {
    let toks: Vec<&str> = arg.split_whitespace().collect();
    let pkg = *toks.first()?;
    if pkg.is_empty() || pkg.len() >= MAX_PKG_LEN {
        return None;
    }
    let mut app = AppRt {
        enabled: true,
        mode: RtMatch::Auto,
        max_threads: default_max,
    };
    let mut rest = &toks[1..];

    // 可选的状态段。写 off 时保留后面的模式，用户再打开不必重填
    if let Some(&first) = rest.first() {
        match first {
            "on" | "true" | "1" => rest = &rest[1..],
            "off" | "false" | "0" => {
                app.enabled = false;
                rest = &rest[1..];
            }
            _ => {}
        }
    }

    // 模式段，省略时按 auto
    if let Some(&m) = rest.first() {
        if let Ok(n) = m.parse::<u8>() {
            if !(1..=RT_MAX_LIMIT).contains(&n) {
                return None;
            }
            app.max_threads = n;
            rest = &rest[1..];
        } else {
            match m {
                "auto" => {
                    app.mode = RtMatch::Auto;
                    rest = &rest[1..];
                }
                "names" => {
                    app.mode = RtMatch::Names(split_names(rest.get(1)?)?);
                    rest = &rest[2..];
                }
                _ => {
                    app.mode = RtMatch::Names(split_names(m.strip_prefix("names:")?)?);
                    rest = &rest[1..];
                }
            }
        }
    }

    // 剩下的唯一一个 token 是上限
    if let Some(&n) = rest.first() {
        let n = n.parse::<u8>().ok()?;
        if !(1..=RT_MAX_LIMIT).contains(&n) {
            return None;
        }
        app.max_threads = n;
        rest = &rest[1..];
    }
    if !rest.is_empty() {
        return None;
    }
    Some((pkg.to_string(), app))
}

/// 启动（或热重载）时检查规则里的核是否都在线。
///
/// 真机上「规则写 4-6、日志一直记裁剪 4-5」最常见的成因是中核簇被 core_ctl
/// 或 hotplug 下电：`sched_setaffinity` 的掩码会与在线集合求交，写进去的 bit
/// 静默消失，随后被校验判成「被裁剪」。启动行先说清楚，省得用户以为规则错了
/// 启动时把规则原文逐条摊开。
///
/// 日志后面每一句「期望 4-6」都是从这张表推出来的。不打印它，用户拿着
/// 自己写的配置去核对时只能靠记忆——真机上出现过「我写的是 4-7」与
/// 「日志说期望 4-6」对不上的争执，实际是规则里另有更窄的一条线程规则
fn report_rule_list(rules: &[AffinityRule], topo: &CpuTopology) {
    const CAP: usize = 12;
    for r in rules.iter().take(CAP) {
        // 包名与线程名都是 ASCII，定宽填充能对齐成表格；核集合后面跟一档
        // 语义名（p-core 大核），不必每次回看「环境」那行去查数字
        let thread = if r.thread.is_empty() {
            "all"
        } else {
            r.thread.as_str()
        };
        let mut line = format!(
            "{:<26} {:<14} → {:<5}",
            r.pkg,
            thread,
            r.cpus.to_range_string()
        );
        if !r.cpuset_dir.is_empty() {
            line.push_str(&format!(" 组 {}", r.cpuset_dir));
        }
        let kind = core_class(&r.cpus, topo);
        if !kind.is_empty() {
            line.push_str(&format!("  {}", kind));
        }
        crate::diag::tag("规则", line.trim_end());
        // 包名只能由字母、数字、下划线、点组成。含冒号几乎一定是想写
        // `pkg:thread=cpus`——这种写法会被整串当成包名，规则永远匹配不到进程，
        // 而且日志里看起来「规则已加载」，不警告就只能靠用户自己发现绑没上
        if r.thread.is_empty() && r.pkg.contains(':') {
            crate::diag::tag(
                "警告",
                &format!(
                    "「{}」不是合法包名，线程规则请写成 pkg{{thread}}=cpus；\
                     按现在这条写，它会被当成一个叫这个名字的包，永远匹配不到任何进程",
                    r.pkg
                ),
            );
        }
    }
    if rules.len() > CAP {
        crate::diag::tag("规则", &format!("另有 {} 条未列出", rules.len() - CAP));
    }
}

/// 规则集合落在哪一档核心上。启动块已给出 e/p/hp 各是哪几个核，
/// 这里只负责回答「4-6 到底是大核还是小核」——这是读规则表时第一个问题
fn core_class(cpus: &CpuSet, topo: &CpuTopology) -> &'static str {
    if cpus.count() == 0 {
        return "空集合";
    }
    // 没分层时三档是同一个集合，任何「p-core/大核」的标注都是编的
    if topo.topo_degraded {
        return "";
    }
    if topo.hp_core.count() > 0 && *cpus == topo.hp_core {
        return "hp-core 超大核";
    }
    if topo.p_core.count() > 0 && *cpus == topo.p_core {
        return "p-core 大核";
    }
    if topo.e_core.count() > 0 && *cpus == topo.e_core {
        return "e-core 小核";
    }
    if cpus.subset_of(&topo.hp_core) || cpus.subset_of(&topo.p_core) || cpus.subset_of(&topo.e_core)
    {
        // 只取了某一档的一部分：贴档名但标明「部分」，避免被当成整档
        return "某档部分核";
    }
    "跨簇"
}

fn report_offline_rules(rules: &[AffinityRule], topo: &CpuTopology) {
    // 优先现读：热重载时 topo 是启动快照，中间可能发生过热插拔
    let online = crate::cpuset::online_cpus().unwrap_or(topo.present_cpus);
    let mut reported: Vec<String> = Vec::new();
    for r in rules {
        let mut off = r.cpus;
        off.and_not(&online);
        if off.count() == 0 {
            continue;
        }
        let want = r.cpus.to_range_string();
        if reported.contains(&want) {
            continue;
        }
        reported.push(want.clone());
        crate::diag::tag(
            "警告",
            &format!(
                "规则要的 {} 里 CPU {} 当前不在线（在线 {}）；这些核会被内核静默扣掉、回读变小，\
             日志随后记成「裁剪」。核上线后下一轮自动恢复，不是规则写错",
                want,
                off.to_range_string(),
                online.to_range_string()
            ),
        );
    }
}

/// 加载配置文件，返回 None 表示未变化或解析失败
pub fn load_config(
    config_file: &str,
    topo: &CpuTopology,
    last_mtime: &mut i64,
) -> Option<AppConfig> {
    let metadata = fs::metadata(config_file).ok()?;
    let mtime = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as i64;

    if *last_mtime == mtime && *last_mtime != -1 {
        return None;
    }

    let content = fs::read_to_string(config_file).ok()?;

    let mut rules: Vec<AffinityRule> = Vec::new();
    let mut fail_cnt: usize = 0;
    let mut cur_pkg = String::new();
    let mut pending_pkg = String::new();
    let mut in_block = false;
    // 保守默认：未匹配线程保持原有亲和性，不再主动设为全部核心
    let mut unmatched_all = false;
    // 默认尊重系统分组：后面的应用在后台组时本来就不许上大核
    let mut sysgroup_respect = true;
    // 动态调度默认全关，配置里不写就与 2.3.0 行为一致
    let mut sched = SchedMode::Off;
    // 息屏放松默认关：默认行为必须与 2.6.1 完全一致
    let mut screen_relax = false;
    // 补组默认开：这是修接管语义的缺口，不是可选增强。出问题时用
    // `@group=mask` 退回「只写掩码」的 2.6.1 行为
    let mut group_own = true;
    // `@render_guard` 在 2.7.0-beta5 移除（判据长期无有效命中）。用户是通过
    // WebUI 打开的，配置文件里还留着这一行；直接判「格式无效」等于把一个
    // 官方功能的下线变成他的错误，所以这里只吞掉并提示一次
    let mut legacy_render_guard = false;
    let mut rt = RtConfig::default();
    // 分应用条目先收集原文，等 @rt.max 解析完再统一构造，避免配置行顺序影响缺省上限
    let mut rt_apps: Vec<String> = Vec::new();

    for line in content.lines() {
        let p = line.trim();
        if p.is_empty() || p.starts_with('#') || p.starts_with("//") {
            continue;
        }

        // 指令行：@unmatched=keep|all，与规则行互不影响
        if let Some(rest) = p.strip_prefix('@') {
            if in_block {
                fail_cnt += 1;
                continue;
            }
            let (key, val) = match rest.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => {
                    let mut it = rest.split_whitespace();
                    (it.next().unwrap_or(""), it.next().unwrap_or(""))
                }
            };
            match (key, val) {
                ("unmatched", "keep") => unmatched_all = false,
                ("unmatched", "all") => unmatched_all = true,
                ("sysgroup", "respect" | "keep") => sysgroup_respect = true,
                ("sysgroup", "takeover" | "ignore" | "force") => sysgroup_respect = false,
                ("sched", "off") => sched = SchedMode::Off,
                ("sched", "shadow") => sched = SchedMode::Shadow,
                ("sched", "on") => sched = SchedMode::On,
                ("screen", "off") => screen_relax = false,
                ("screen", "relax") => screen_relax = true,
                // 已下线的开关：不报格式错误，只置位等构建完统一提示
                ("render_guard", _) => legacy_render_guard = true,
                ("group", "own") => group_own = true,
                ("group", "mask") => group_own = false,
                ("rt", "off") => rt.scope = RtScope::Off,
                ("rt", "global") => rt.scope = RtScope::Global,
                ("rt", "per_app" | "per-app" | "perapp") => rt.scope = RtScope::PerApp,
                // 兼容旧写法：@rt=auto / @rt=Name1,Name2 等价于 global 模式
                ("rt", "auto") => {
                    rt.scope = RtScope::Global;
                    rt.global = RtMatch::Auto;
                }
                ("rt.max", v) => match v.parse::<u8>() {
                    Ok(n) if (1..=RT_MAX_LIMIT).contains(&n) => rt.max_per_app = n,
                    _ => fail_cnt += 1,
                },
                ("rt.timeslice", v) => match v.parse::<u32>() {
                    Ok(n) if (1..=RT_TIMESLICE_LIMIT).contains(&n) => rt.timeslice_ms = n,
                    _ => fail_cnt += 1,
                },
                // 分应用条目：@rt.app=com.x auto 2 / names:RenderThread,RHI* / off
                ("rt.app", v) if !v.is_empty() => rt_apps.push(v.to_string()),
                ("rt", v) if !v.is_empty() => match split_names(v) {
                    Some(names) => {
                        rt.scope = RtScope::Global;
                        rt.global = RtMatch::Names(names);
                    }
                    None => fail_cnt += 1,
                },
                _ => fail_cnt += 1,
            }
            continue;
        }

        if in_block {
            if close_like(p) {
                in_block = false;
                cur_pkg.clear();
                continue;
            }
            match split_rule_line(p) {
                Some((thread, cpus, closed)) => {
                    if !add_rule(&mut rules, topo, &cur_pkg, thread, cpus) {
                        fail_cnt += 1;
                    }
                    if closed {
                        in_block = false;
                        cur_pkg.clear();
                    }
                }
                None => {
                    fail_cnt += 1;
                    if p.contains('}') {
                        in_block = false;
                        cur_pkg.clear();
                    }
                }
            }
            continue;
        }

        match parse_outer(p) {
            OuterLine::Single {
                pkg,
                thread,
                cpus,
                open,
            } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pending_pkg.clear();
                if !add_rule(&mut rules, topo, pkg, thread, cpus) {
                    fail_cnt += 1;
                }
                if open {
                    cur_pkg = pkg.to_string();
                    in_block = true;
                }
            }
            OuterLine::Rule { pkg, cpus, open } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                if !add_rule(&mut rules, topo, pkg, "", cpus) {
                    fail_cnt += 1;
                }
                if open {
                    cur_pkg = pkg.to_string();
                    in_block = true;
                }
                pending_pkg.clear();
            }
            OuterLine::BareOpen { pkg } => {
                let owner = if !pkg.is_empty() {
                    if !pending_pkg.is_empty() {
                        fail_cnt += 1;
                    }
                    pkg.to_string()
                } else {
                    pending_pkg.clone()
                };
                if owner.is_empty() {
                    fail_cnt += 1;
                    continue;
                }
                cur_pkg = owner;
                pending_pkg.clear();
                in_block = true;
            }
            OuterLine::Pending { pkg } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pending_pkg = pkg.to_string();
            }
            OuterLine::Junk => {
                fail_cnt += 1;
                pending_pkg.clear();
            }
        }
    }

    if in_block || !pending_pkg.is_empty() {
        fail_cnt += 1;
    }

    // 分应用条目此时构造：@rt.max 已解析完，缺省上限与书写顺序无关
    for arg in &rt_apps {
        match parse_rt_app(arg, rt.max_per_app) {
            Some((pkg, app)) => {
                rt.apps.insert(pkg, app);
            }
            None => fail_cnt += 1,
        }
    }

    *last_mtime = mtime;
    PARSE_FAILS.store(fail_cnt, Ordering::Relaxed);

    // 不静默吞掉：用户得知道这行已经不起作用，否则会以为护栏还开着
    if legacy_render_guard {
        crate::diag::tag(
            "配置",
            "@render_guard 已在 2.7.0 移除（判据长期无有效命中），本行忽略，可以从配置里删掉",
        );
    }

    let pkgs: HashSet<String> = rules.iter().map(|r| r.pkg.clone()).collect();
    let has_thread_rules: HashSet<String> = rules
        .iter()
        .filter(|r| !r.thread.is_empty())
        .map(|r| r.pkg.clone())
        .collect();
    let num_rules = rules.len();
    let trunc_keys = build_trunc_keys(&pkgs);
    let rule_index = build_rule_index(&rules);
    let pkg_sig = build_pkg_sig(&rules);
    let policy_sig = build_policy_sig(
        unmatched_all,
        sysgroup_respect,
        sched,
        screen_relax,
        group_own,
        &rt,
    );

    // 同一包多条包级规则按并集生效，顺序无关；只提示不改变语义
    let mut multi: Vec<&str> = rule_index
        .iter()
        .filter(|(_, v)| v.pkg_rules.len() > 1)
        .map(|(k, _)| k.as_str())
        .collect();
    if !multi.is_empty() {
        multi.sort_unstable();
        let sample = multi.iter().take(3).copied().collect::<Vec<_>>().join(", ");
        crate::diag::tag(
            "警告",
            &format!(
                "{} 个应用存在多条包级规则，CPU 集合按并集生效（与书写顺序无关）：{}{}",
                multi.len(),
                sample,
                if multi.len() > 3 { " 等" } else { "" }
            ),
        );
    }

    // 启动块第一行就是「读的是哪个文件」。真机上「改了没生效」十次有九次
    // 是改的不是这个路径，日志里不给路径就只能靠猜
    let mut pkg_list: Vec<&str> = pkgs.iter().map(|s| s.as_str()).collect();
    pkg_list.sort_unstable();
    let shown = if pkg_list.len() > 6 {
        format!("{} 等", pkg_list[..6].join("、"))
    } else {
        pkg_list.join("、")
    };
    crate::diag::tag(
        "配置",
        &format!(
            "{} ｜ {} 条规则 ｜ {} 个包：{} ｜ 只处理这些包的线程（cmdline+属主双校验），其余进程不读不写",
            config_file,
            num_rules,
            pkg_list.len(),
            shown
        ),
    );
    report_rule_list(&rules, topo);
    report_offline_rules(&rules, topo);
    if fail_cnt > 0 {
        // 指令写错也走这条路（`@screen=dim` 之类），只说「规则」会让人回头
        // 去翻规则行，实际该看的是指令拼写
        crate::diag::tag(
            "警告",
            &format!(
                "{} 行因格式无效被跳过（规则或指令，写法见 README）",
                fail_cnt
            ),
        );
    }
    let (scope, sched_pkgs) = sched_scope(&rules, topo);
    // 策略压成一行：这几项都是静态开关，逐项一行会把启动块拉长到看不清
    // 主线。哪一项与默认值不同，就多给一句为什么
    // 未分层时三档是同一个集合，「跨簇 0/4」会被读成「规则都没跨簇」，
    // 实际是根本没有簇可分——两种结论指向的下一步完全不同
    let scope_desc = if topo.topo_degraded {
        "跨簇 不适用（未分层）".to_string()
    } else if scope.levels < 2 {
        format!("跨簇 0（只识别到 {} 个核心层）", scope.levels)
    } else {
        format!(
            "跨簇 {}/{} 条（{} 个包）",
            scope.rules, num_rules, scope.pkgs
        )
    };
    let sched_desc = match sched {
        SchedMode::Off => "S7 off（不采样）".to_string(),
        SchedMode::Shadow => "S7 shadow（只采样不改）".to_string(),
        SchedMode::On if topo.topo_degraded => "S7 on 但未分层，不会生效".to_string(),
        SchedMode::On if scope.levels < 2 => {
            format!("S7 on 但只有 {} 个核心层，不会生效", scope.levels)
        }
        SchedMode::On if scope.rules == 0 => {
            "S7 on 但规则无跨簇，没有可让位目标，不会采样".to_string()
        }
        SchedMode::On => "S7 on（Worker/Background 让位，每秒最多迁 1 个）".to_string(),
    };
    // 非默认开关必须自证：开了 `@screen=relax` 却在启动块里看不到任何变化，
    // 用户只能靠「息屏后日志变安静」去推断，等于让他猜。默认值不出现，
    // 因此默认配置下的启动块与 2.6.1 逐字一致
    let mut extra: Vec<String> = Vec::new();
    if screen_relax {
        extra.push("息屏=relax（复核降到 60 秒）".to_string());
    }
    if !group_own {
        extra.push("接管组=mask（只写掩码，退回 2.6.1）".to_string());
    }
    let extra_desc = if extra.is_empty() {
        String::new()
    } else {
        format!(" ｜ {}", extra.join(" ｜ "))
    };
    crate::diag::tag(
        "策略",
        &format!(
            "未匹配={} ｜ 系统分组={} ｜ {} ｜ {}{}",
            if unmatched_all {
                "all（设为全核）"
            } else {
                "keep（保持原样）"
            },
            if sysgroup_respect {
                "respect（后台组不硬抢）"
            } else {
                "takeover（拉进 AppOpt 组，费电）"
            },
            scope_desc,
            sched_desc,
            extra_desc
        ),
    );
    if !rt.is_off() {
        crate::diag::tag(
            "策略",
            &format!(
                "RT {} ｜ 每应用上限 {} ｜ RR 时间片 {} ms",
                rt.label(),
                rt.max_per_app,
                rt.timeslice_ms
            ),
        );
        // per_app 里配了但没有任何亲和性规则的包不会进入决策路径，提前说明比事后排查省事
        if rt.scope == RtScope::PerApp {
            let mut orphan: Vec<&str> = rt
                .apps
                .iter()
                .filter(|(p, a)| a.enabled && !pkgs.contains(*p))
                .map(|(p, _)| p.as_str())
                .collect();
            if !orphan.is_empty() {
                orphan.sort_unstable();
                let sample = orphan
                    .iter()
                    .take(3)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ");
                crate::diag::tag(
                    "警告",
                    &format!(
                        "{} 个应用配置了 RT 但没有亲和性规则，不会生效：{}{}",
                        orphan.len(),
                        sample,
                        if orphan.len() > 3 { " 等" } else { "" }
                    ),
                );
            }
        }
    }

    Some(AppConfig {
        rules,
        pkgs,
        has_thread_rules,
        trunc_keys,
        rule_index,
        pkg_sig,
        policy_sig,
        unmatched_all,
        sysgroup_respect,
        sched_scope: scope,
        sched_pkgs,
        sched,
        screen_relax,
        group_own,
        rt,
        topo: topo.clone(),
    })
}

pub fn config_loader() {
    let name = CString::new("ConfigLoader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    let mut last_mtime: i64 = -1;

    loop {
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        if FORCE_RELOAD.swap(false, Ordering::AcqRel) {
            last_mtime = -1;
            if INOTIFY_SUPPORTED.load(Ordering::Acquire) {
                let fd = INOTIFY_FD.load(Ordering::Acquire);
                inotify_rewatch(fd);
            }
            config_reload(&mut last_mtime);
        }
        if INOTIFY_SUPPORTED.load(Ordering::Acquire) {
            inotify_handle(interval, &mut last_mtime);
        } else {
            config_reload(&mut last_mtime);
            thread::sleep(Duration::from_secs(interval));
        }
    }
}

pub fn init_inotify(config_file: &str) {
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if inotify_fd < 0 {
        crate::diag::tag("组件", "inotify 初始化失败，改用轮询监听配置");
        return;
    }
    let cfg_cstr = match CString::new(config_file) {
        Ok(c) => c,
        Err(_) => {
            crate::diag::tag("警告", "配置文件路径含非法字符，inotify 不可用，改用轮询");
            unsafe {
                libc::close(inotify_fd);
            }
            return;
        }
    };
    let wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };
    if wd >= 0 {
        INOTIFY_SUPPORTED.store(true, Ordering::Release);
        INOTIFY_FD.store(inotify_fd, Ordering::Release);
        INOTIFY_WD.store(wd, Ordering::Release);
        crate::diag::tag("组件", "inotify 监听配置文件变更");
    } else {
        unsafe {
            libc::close(inotify_fd);
        }
        crate::diag::tag("组件", "inotify 初始化失败，改用轮询监听配置");
    }
}

fn disable_inotify(inotify_fd: i32) {
    INOTIFY_SUPPORTED.store(false, Ordering::Release);
    unsafe {
        libc::close(inotify_fd);
    }
    INOTIFY_FD.store(-1, Ordering::Release);
    INOTIFY_WD.store(-1, Ordering::Release);
}

/// 文件内容 + 拓扑的指纹。拓扑变了必须重解析（热插拔会改变核心层映射），
/// 内容没变则不解析：重解析除了刷出十几行日志、让 S7 与 RT 各重建一遍状态，
/// 不会带来任何变化
fn content_sig(file: &str, topo: &CpuTopology) -> Option<u64> {
    let content = fs::read_to_string(file).ok()?;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in content
        .as_bytes()
        .iter()
        .copied()
        .chain(topo.present_str.bytes())
        .chain(topo.mems_str.bytes())
    {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Some(h)
}

fn config_reload(last_mtime: &mut i64) {
    let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
        return;
    };
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    if let Some(sig) = content_sig(&file, &cfg.topo) {
        // 内容与拓扑都没变：这次事件只是同一次保存的余波，重解析毫无收益
        if RELOAD_SIG_SET.load(Ordering::Acquire) && RELOAD_SIG.load(Ordering::Relaxed) == sig {
            return;
        }
        // 内容确实变了：绕过 mtime 门。两次写入落在同一时间戳精度内时，
        // mtime 会相等，光靠它会把真实修改挡在门外
        *last_mtime = -1;
        let Some(new_cfg) = load_config(&file, &cfg.topo, last_mtime) else {
            return;
        };
        RELOAD_SIG.store(sig, Ordering::Relaxed);
        RELOAD_SIG_SET.store(true, Ordering::Release);
        {
            let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
            *guard = Some(Arc::new(new_cfg));
        }
        CONFIG_UPDATED.store(true, Ordering::Release);
        return;
    }
    // 读不到内容（正在被写、被删）：按老路走一次，失败就等下一次事件
    let Some(new_cfg) = load_config(&file, &cfg.topo, last_mtime) else {
        return;
    };
    {
        let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(new_cfg));
    }
    CONFIG_UPDATED.store(true, Ordering::Release);
}

pub fn config_reload_now() {
    let mut mtime: i64 = -1;
    config_reload(&mut mtime);
}

fn inotify_handle(interval: u64, last_mtime: &mut i64) {
    let inotify_fd = INOTIFY_FD.load(Ordering::Acquire);

    let mut pfd = libc::pollfd {
        fd: inotify_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, (interval as libc::c_int) * 1000) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            return;
        }
        disable_inotify(inotify_fd);
        return;
    } else if ret == 0 {
        return;
    }

    #[repr(align(8))]
    struct InotifyBuf([u8; 4096]);
    let mut buf = InotifyBuf([0u8; 4096]);
    let mut reload_needed = false;
    let mut needs_rewatch = false;
    let hdr = std::mem::size_of::<libc::inotify_event>();

    loop {
        let len = unsafe {
            libc::read(
                inotify_fd,
                buf.0.as_mut_ptr() as *mut libc::c_void,
                buf.0.len(),
            )
        };
        if len <= 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error();
            if errno == Some(libc::EAGAIN)
                || errno == Some(libc::EWOULDBLOCK)
                || errno == Some(libc::EINTR)
            {
                break;
            }
            disable_inotify(inotify_fd);
            return;
        }

        let mut offset = 0;
        while offset + hdr <= len as usize {
            let event = unsafe { &*(buf.0.as_ptr().add(offset) as *const libc::inotify_event) };
            if event.mask & (libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0
            {
                reload_needed = true;
                // 只对「换了 inode」的事件作废 mtime：改名/删除后路径指向的已不是
                // 原文件，mtime 不可比。普通 CLOSE_WRITE 交给 config_reload 的
                // 内容指纹判断——这里无脑置 -1，等于每次保存都强制重解析，
                // 而一次保存往往触发两三个事件
                if event.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                    *last_mtime = -1;
                    needs_rewatch = true;
                }
            }
            offset += hdr + event.len as usize;
        }
    }

    if needs_rewatch {
        thread::sleep(Duration::from_secs(interval));
        if !inotify_rewatch(inotify_fd) {
            return;
        }
    }

    if reload_needed {
        config_reload(last_mtime);
    }
}

fn inotify_rewatch(inotify_fd: i32) -> bool {
    let inotify_wd = INOTIFY_WD.load(Ordering::Acquire);
    unsafe {
        libc::inotify_rm_watch(inotify_fd, inotify_wd);
    }
    let cfg_cstr = match CString::new(lock_ignore_poison(&CONFIG_FILE).clone()) {
        Ok(c) => c,
        Err(_) => {
            crate::diag::tag("警告", "配置文件路径含非法字符，降级为轮询");
            disable_inotify(inotify_fd);
            return false;
        }
    };
    let new_wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };

    if new_wd < 0 {
        disable_inotify(inotify_fd);
        return false;
    }
    INOTIFY_WD.store(new_wd, Ordering::Release);
    true
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

    fn topo_of(e: &[usize], p: &[usize], h: &[usize]) -> CpuTopology {
        let mut present = CpuSet::new();
        for group in [e, p, h] {
            present.or(&set(group));
        }
        // 测试拓扑：三档就是三层，空层不进 all_tiers（真实检测也不会产出空层）
        let mut tiers = Vec::new();
        for group in [e, p, h] {
            if !group.is_empty() {
                tiers.push(set(group));
            }
        }
        CpuTopology {
            present_cpus: present,
            present_str: present.to_range_string(),
            mems_str: "0".to_string(),
            cpuset_enabled: false,
            e_core: set(e),
            p_core: set(p),
            hp_core: set(h),
            all_tiers: tiers,
            topo_source: "capacity",
            topo_degraded: false,
        }
    }

    fn scope_of(name: &str, conf: &str, topo: &CpuTopology) -> SchedScope {
        let path = format!("/tmp/appopt_scope_{}.conf", name);
        fs::write(&path, conf).unwrap();
        let mut mtime = -1i64;
        let cfg = load_config(&path, topo, &mut mtime).expect("配置应能加载");
        let _ = fs::remove_file(&path);
        cfg.sched_scope
    }

    /// 内容指纹：同一次保存的多个事件必须同值（否则每次都重解析），
    /// 内容或拓扑一变必须不同值（否则真实修改被挡在门外）
    #[test]
    fn content_sig_dedupes_only_identical_reloads() {
        let t = topo_of(&[0, 1, 2, 3], &[4, 5, 6], &[7]);
        let p = "/tmp/appopt_sig_a.conf";
        fs::write(p, "com.a=4-6\n").unwrap();
        let a = content_sig(p, &t).unwrap();
        // 同样的内容 + 同样的拓扑：命中，跳过重解析
        assert_eq!(a, content_sig(p, &t).unwrap());

        // 只改一个字符也必须重新解析
        fs::write(p, "com.a=4-6\ncom.b=7\n").unwrap();
        assert_ne!(a, content_sig(p, &t).unwrap());

        // 内容没变但拓扑变了（热插拔换掉了一个簇）：必须重新解析
        fs::write(p, "com.a=4-6\n").unwrap();
        let t2 = topo_of(&[0, 1, 2, 3], &[4, 5], &[6]);
        assert_ne!(a, content_sig(p, &t2).unwrap());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn full_set_rule_is_not_cross_cluster() {
        // 写 0-7 表示不限制，不代表跨簇意图
        let topo = topo_of(&[0, 1, 2, 3], &[4, 5], &[6, 7]);
        let s = scope_of("full", "com.a=0-7\n", &topo);
        assert_eq!((s.levels, s.rules, s.pkgs), (3, 0, 0));
    }

    /// 线程规则的 cpuset 目录是命中时按合并集合派生的，配置里没有字段存它。
    /// GC 的引用集必须把它算进去，否则「线程规则正在用、此刻恰好空闲」的
    /// 目录会被当成无主回收，下次命中要重建一次
    #[test]
    fn gc_references_cover_thread_rule_dirs() {
        let topo = topo_of(&[0, 1, 2, 3], &[4, 5, 6], &[7]);
        let p = "/tmp/appopt_gc_ref.conf";
        fs::write(p, "com.a {\n  RenderThread=2-5\n  Worker*=4-6\n}\n").unwrap();
        let mut mtime = -1i64;
        let cfg = load_config(p, &topo, &mut mtime).expect("配置应能加载");
        let _ = fs::remove_file(p);

        let r = cfg.referenced_cpuset_dirs();
        assert!(r.contains("2-5"), "单条命中派生目录：{:?}", r);
        assert!(r.contains("4-6"), "单条命中派生目录：{:?}", r);
        assert!(r.contains("2-6"), "两条都命中时的合并目录：{:?}", r);
    }

    #[test]
    fn rule_spanning_two_layers_is_counted() {
        let topo = topo_of(&[0, 1, 2, 3], &[4, 5], &[6, 7]);
        let conf = "com.a {\n  RenderThread=2-5\n}\ncom.b=6-7\n";
        let s = scope_of("span", conf, &topo);
        // 2-5 同时命中 e-core 与 p-core；6-7 只在 hp-core
        assert_eq!((s.levels, s.rules, s.pkgs), (3, 1, 1));
    }

    #[test]
    fn cross_pkgs_dedups_rules_in_same_package() {
        let topo = topo_of(&[0, 1, 2, 3], &[4, 5], &[6, 7]);
        let conf = "com.a {\n  A=2-5\n  B=3-6\n}\n";
        let s = scope_of("dedup", conf, &topo);
        assert_eq!((s.levels, s.rules, s.pkgs), (3, 2, 1));
    }

    /// 同一条线程规则拆成两行时，线程拿到的是并集；逐条统计会把 S7 关掉
    #[test]
    fn same_thread_pattern_rules_merge_before_scope_check() {
        let topo = topo_of(&[0, 1, 2, 3], &[4, 5], &[6, 7]);
        let conf = "com.a {\n  Worker-*=p-core\n  Worker-*=hp-core\n}\n";
        let s = scope_of("merge", conf, &topo);
        // 合并后 4-7 跨 p/hp 两层；rules 仍按原始两条计，便于与总条数对齐
        assert_eq!((s.levels, s.rules, s.pkgs), (3, 2, 1));

        // 不同线程名各自单簇：没有任何线程会同时命中，仍不算跨簇
        let conf = "com.a {\n  Worker-1=p-core\n  Worker-2=hp-core\n}\n";
        let s = scope_of("merge2", conf, &topo);
        assert_eq!((s.levels, s.rules, s.pkgs), (3, 0, 0));
    }

    #[test]
    fn two_cluster_topo_merges_pcore_and_hpcore() {
        // 两簇设备 p-core 与 hp-core 是同一批核，跨它俩没有收益面
        let topo = topo_of(&[0, 1, 2, 3], &[4, 5, 6, 7], &[4, 5, 6, 7]);
        let s = scope_of("two", "com.a {\n  A=p-core,hp-core\n}\n", &topo);
        assert_eq!((s.levels, s.rules, s.pkgs), (2, 0, 0));
    }

    #[test]
    fn degraded_topo_reports_no_scope() {
        // 单簇/降级拓扑下三个语义名同集合，动态分配无意义
        let topo = topo_of(&[0, 1, 2, 3], &[0, 1, 2, 3], &[0, 1, 2, 3]);
        let s = scope_of("degraded", "com.a=0-1\n", &topo);
        assert_eq!((s.levels, s.rules, s.pkgs), (1, 0, 0));
    }

    fn cfg_of(name: &str, conf: &str) -> AppConfig {
        let path = format!("/tmp/appopt_cfg_{}.conf", name);
        fs::write(&path, conf).unwrap();
        let topo = topo_of(&[0, 1, 2, 3], &[4, 5], &[6, 7]);
        let mut mtime = -1i64;
        load_config(&path, &topo, &mut mtime).expect("配置应能加载")
    }

    #[test]
    fn sched_directive_parses_all_levels() {
        assert_eq!(
            cfg_of("s_off", "@sched=off\ncom.a=0-1\n").sched,
            SchedMode::Off
        );
        assert_eq!(
            cfg_of("s_sh", "@sched=shadow\ncom.a=0-1\n").sched,
            SchedMode::Shadow
        );
        assert_eq!(
            cfg_of("s_on", "@sched=on\ncom.a=0-1\n").sched,
            SchedMode::On
        );
        // 非法值回退 off，但不能牵连规则
        let bad = cfg_of("s_bad", "@sched=turbo\ncom.a=0-1\n");
        assert_eq!(bad.sched, SchedMode::Off);
        assert_eq!(bad.rules.len(), 1);
    }

    /// `@render_guard` 已下线，但用户的配置里可能还留着（当初是从 WebUI 开的）。
    /// 必须吞掉而不是判格式错误，否则功能下线会变成用户配置里的红字
    #[test]
    fn removed_render_guard_directive_is_ignored() {
        let c = cfg_of(
            "rg_legacy",
            "@render_guard=observe\ncom.a {\n  UnityMain=7\n}\n",
        );
        assert_eq!(c.rules.len(), 1, "块里那条线程规则照常解析");
        assert!(c.pkgs.contains("com.a"));
        // 不断言 PARSE_FAILS：它是进程级全局量，测试并行跑时会被其他用例
        // 改写。这里要证明的是「该行没有吃掉后面的规则」，规则数已经足够
    }

    /// 补组默认开（修接管语义），`@group=mask` 是逃生口。
    /// 三种情况都要明确：默认、显式关、非法值
    #[test]
    fn group_own_defaults_on_and_can_fall_back() {
        let base = cfg_of("gt_def", "com.a=0-1\n");
        assert!(base.group_own, "不写 @group 必须默认补组");
        let mask = cfg_of("gt_mask", "@group=mask\ncom.a=0-1\n");
        assert!(!mask.group_own, "@group=mask 必须退回只写掩码");
        assert_eq!(mask.rules.len(), 1, "指令不能吞掉规则");
        assert_ne!(base.policy_sig, mask.policy_sig, "开关变化要触发重扫");

        // 非法值按默认处理，不牵连规则
        let bad = cfg_of("gt_bad", "@group=maybe\ncom.a=0-1\n");
        assert!(bad.group_own);
        assert_eq!(bad.rules.len(), 1);
    }

    #[test]
    fn screen_directive_defaults_off_and_tracks_sig() {
        let base = cfg_of("sc_off", "com.a=0-1\n");
        assert!(!base.screen_relax, "不写 @screen 必须保持关");
        let relax = cfg_of("sc_relax", "@screen=relax\ncom.a=0-1\n");
        assert!(relax.screen_relax);
        assert_eq!(relax.rules.len(), 1, "指令不能吞掉规则");
        // 只改这一行也必须换指纹，否则主循环不会立即按新节奏排复查
        assert_ne!(base.policy_sig, relax.policy_sig);

        // 非法值不生效、不牵连规则
        let bad = cfg_of("sc_bad", "@screen=dim\ncom.a=0-1\n");
        assert!(!bad.screen_relax);
        assert_eq!(bad.rules.len(), 1);
    }

    #[test]
    fn rt_directive_parses_auto_and_names() {
        assert!(cfg_of("r_off", "@rt=off\ncom.a=0-1\n").rt.is_off());
        let auto = cfg_of("r_auto", "@rt=auto\ncom.a=0-1\n");
        assert_eq!(auto.rt.scope, RtScope::Global);
        assert_eq!(auto.rt.global, RtMatch::Auto);
        // 旧写法 @rt=名字列表 等价于 global + names
        let named = cfg_of("r_names", "@rt=RenderThread,RHI*\ncom.a=0-1\n");
        assert_eq!(named.rt.scope, RtScope::Global);
        match named.rt.global {
            RtMatch::Names(v) => {
                assert_eq!(v, vec!["RenderThread".to_string(), "RHI*".to_string()])
            }
            other => panic!("期望名字列表，得到 {:?}", other),
        }
    }

    #[test]
    fn rt_per_app_parses_entries() {
        let cfg = cfg_of(
            "r_perapp",
            "@rt=per_app\n@rt.max=1\n@rt.app=com.a auto 2\n@rt.app=com.b names:RenderThread,RHI* 1\n@rt.app=com.c off\n@rt.app=com.d\ncom.a=0-1\n",
        );
        assert_eq!(cfg.rt.scope, RtScope::PerApp);
        assert_eq!(cfg.rt.apps.len(), 4);
        let a = &cfg.rt.apps["com.a"];
        assert!(a.enabled);
        assert_eq!(a.mode, RtMatch::Auto);
        assert_eq!(a.max_threads, 2);
        let b = &cfg.rt.apps["com.b"];
        assert_eq!(
            b.mode,
            RtMatch::Names(vec!["RenderThread".to_string(), "RHI*".to_string()])
        );
        assert_eq!(b.max_threads, 1);
        assert!(!cfg.rt.apps["com.c"].enabled);
        // 省略模式按 auto，省略上限取 @rt.max
        let d = &cfg.rt.apps["com.d"];
        assert!(d.enabled);
        assert_eq!(d.mode, RtMatch::Auto);
        assert_eq!(d.max_threads, 1);
    }

    #[test]
    fn rt_app_entry_is_order_independent_of_max() {
        // @rt.max 写在条目之后，缺省上限仍应取 4
        let cfg = cfg_of(
            "r_order",
            "@rt=per_app\n@rt.app=com.a\n@rt.max=4\ncom.a=0-1\n",
        );
        assert_eq!(cfg.rt.apps["com.a"].max_threads, 4);
    }

    #[test]
    fn rt_disabled_entry_keeps_mode() {
        // 关闭时保留模式，再打开不必重填
        let cfg = cfg_of(
            "r_keep",
            "@rt=per_app\n@rt.app=com.a off names:RenderThread,RHI* 3\ncom.a=0-1\n",
        );
        let a = &cfg.rt.apps["com.a"];
        assert!(!a.enabled);
        assert_eq!(
            a.mode,
            RtMatch::Names(vec!["RenderThread".to_string(), "RHI*".to_string()])
        );
        assert_eq!(a.max_threads, 3);
        assert!(cfg.rt.policy("com.a").is_none());
    }

    #[test]
    fn rt_bad_entry_counts_as_failure() {
        let cfg = cfg_of("r_bad", "@rt=per_app\n@rt.app=com.a turbo\ncom.a=0-1\n");
        assert!(cfg.rt.apps.is_empty());
    }

    #[test]
    fn needs_comm_follows_consumers() {
        // 测试拓扑：e=0-3、p=4-5、hp=6-7。3-4 横跨 e 与 p
        let plain = cfg_of("comm_plain", "com.a=0-1\n");
        assert!(!plain.needs_comm("com.a"));

        // 线程规则：必须读
        let thread = cfg_of("comm_thread", "com.a {\n  RenderThread=0-1\n}\n");
        assert!(thread.needs_comm("com.a"));

        // S7 开启且规则跨簇：必须读，否则判不出角色
        let sched = cfg_of("comm_sched", "@sched=on\ncom.a=3-4\n");
        assert!(sched.needs_comm("com.a"));
        // 关掉 S7 后不再有理由读
        let off = cfg_of("comm_sched_off", "@sched=off\ncom.a=3-4\n");
        assert!(!off.needs_comm("com.a"));
        // 单簇规则即使开了 S7 也不需要线程名
        let single = cfg_of("comm_single", "@sched=on\ncom.a=0-1\n");
        assert!(!single.needs_comm("com.a"));

        // RT 需要线程名做角色/名字匹配
        let rt = cfg_of("comm_rt", "@rt=auto\ncom.a=0-1\n");
        assert!(rt.needs_comm("com.a"));
        // per_app 只影响列表里的包
        let per = cfg_of(
            "comm_rt_per",
            "@rt=per_app\n@rt.app=com.b\ncom.a=0-1\ncom.b=0-1\n",
        );
        assert!(!per.needs_comm("com.a"));
        assert!(per.needs_comm("com.b"));
    }

    #[test]
    fn policy_sig_covers_sched_and_rt() {
        let base = cfg_of("sig_base", "com.a=0-1\n");
        let s = cfg_of("sig_sched", "@sched=shadow\ncom.a=0-1\n");
        let r = cfg_of("sig_rt", "@rt=auto\ncom.a=0-1\n");
        // 不纳入 policy_sig 的话，改配置不会触发重建，on -> off 无法回滚
        assert_ne!(base.policy_sig, s.policy_sig);
        assert_ne!(base.policy_sig, r.policy_sig);
        // 名字列表是 OR 语义，顺序不影响
        let n1 = cfg_of("sig_n1", "@rt=A,B\ncom.a=0-1\n");
        let n2 = cfg_of("sig_n2", "@rt=B,A\ncom.a=0-1\n");
        assert_eq!(n1.policy_sig, n2.policy_sig);
        // 分应用开关、上限、时间片都要触发重建
        let p1 = cfg_of("sig_p1", "@rt=per_app\n@rt.app=com.a on\ncom.a=0-1\n");
        let p2 = cfg_of("sig_p2", "@rt=per_app\n@rt.app=com.a off\ncom.a=0-1\n");
        let p3 = cfg_of("sig_p3", "@rt=per_app\n@rt.app=com.a on 3\ncom.a=0-1\n");
        let t = cfg_of("sig_t", "@rt=global\n@rt.timeslice=5\ncom.a=0-1\n");
        let g = cfg_of("sig_g", "@rt=global\ncom.a=0-1\n");
        assert_ne!(p1.policy_sig, p2.policy_sig);
        assert_ne!(p1.policy_sig, p3.policy_sig);
        assert_ne!(g.policy_sig, t.policy_sig);
    }
}
