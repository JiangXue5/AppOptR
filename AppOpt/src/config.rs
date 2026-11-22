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

pub struct AffinityRule {
    pub pkg: String,
    pub thread: String,
    pub thread_pattern: CString,
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
    /// 跨簇规则统计，仅用于展示 S7 的潜在作用面
    pub sched_scope: SchedScope,
    /// 允许集合横跨多个核心层的包。S7 靠线程名判角色，这些包即使没有线程规则
    /// 也必须采集 comm，否则 S7 对「只有包级规则」的应用完全失效
    pub sched_pkgs: HashSet<String>,
    /// S7 模式，off 时运行期零开销
    pub sched: SchedMode,
    /// RT 配置。off 时运行期不查询任何线程的调度策略
    pub rt: RtConfig,
    pub topo: CpuTopology,
}

impl AppConfig {
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
            sched_scope: SchedScope::default(),
            sched_pkgs: HashSet::new(),
            sched: SchedMode::Off,
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
fn build_policy_sig(unmatched_all: bool, sched: SchedMode, rt: &RtConfig) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    unmatched_all.hash(&mut h);
    (sched as u8).hash(&mut h);
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

    for r in rules {
        if r.cpus.count() == 0 || r.cpus == topo.present_cpus {
            continue;
        }
        let hit = levels.iter().filter(|l| intersects(&r.cpus, l)).count();
        if hit > 1 {
            scope.rules += 1;
            pkgs.insert(r.pkg.clone());
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
        let ok = matches!(t, "e-core" | "p-core" | "hp-core" | "all-core")
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
    // 动态调度默认全关，配置里不写就与 2.3.0 行为一致
    let mut sched = SchedMode::Off;
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
                ("sched", "off") => sched = SchedMode::Off,
                ("sched", "shadow") => sched = SchedMode::Shadow,
                ("sched", "on") => sched = SchedMode::On,
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
    let policy_sig = build_policy_sig(unmatched_all, sched, &rt);

    // 同一包多条包级规则按并集生效，顺序无关；只提示不改变语义
    let mut multi: Vec<&str> = rule_index
        .iter()
        .filter(|(_, v)| v.pkg_rules.len() > 1)
        .map(|(k, _)| k.as_str())
        .collect();
    if !multi.is_empty() {
        multi.sort_unstable();
        let sample = multi.iter().take(3).copied().collect::<Vec<_>>().join(", ");
        eprintln!(
            "提示: {} 个应用存在多条包级规则，CPU 集合按并集生效（与书写顺序无关）：{}{}",
            multi.len(),
            sample,
            if multi.len() > 3 { " 等" } else { "" }
        );
    }

    crate::diag::emit(&format!("配置文件解析完成，共加载 {} 条规则", num_rules));
    if fail_cnt > 0 {
        eprintln!("警告: {} 条规则因格式无效被跳过", fail_cnt);
    }
    if unmatched_all {
        crate::diag::emit("未匹配线程: all（沿用旧行为，设为全部核心）");
    } else {
        crate::diag::emit("未匹配线程: keep（保持原有亲和性）");
    }
    let (scope, sched_pkgs) = sched_scope(&rules, topo);
    if scope.levels < 2 {
        crate::diag::emit(&format!(
            "跨簇规则: 不适用（当前识别为 {} 个核心层）",
            scope.levels
        ));
    } else {
        crate::diag::emit(&format!(
            "跨簇规则: {} / {} 条，涉及 {} 个包（核心层级 {}）",
            scope.rules, num_rules, scope.pkgs, scope.levels
        ));
    }
    match sched {
        SchedMode::Off => crate::diag::emit("S7 动态分配: off（不采样，行为与静态规则一致）"),
        SchedMode::Shadow => crate::diag::emit("S7 动态分配: shadow（采样与记录，不修改亲和性）"),
        // 拓扑不满足时照常记录意图，但明确不会生效，避免误以为已经在优化
        SchedMode::On if scope.levels < 2 => crate::diag::emit(&format!(
            "S7 动态分配: on（核心层仅 {} 个，不会生效）",
            scope.levels
        )),
        SchedMode::On => {
            crate::diag::emit("S7 动态分配: on（仅 Worker/Background 让位，每秒最多迁移 1 个线程）")
        }
    }
    if !rt.is_off() {
        crate::diag::emit(&format!(
            "RT 调度: {}，每应用上限 {}，RR 时间片 {} ms",
            rt.label(),
            rt.max_per_app,
            rt.timeslice_ms
        ));
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
                eprintln!(
                    "提示: {} 个应用配置了 RT 但没有亲和性规则，不会生效：{}{}",
                    orphan.len(),
                    sample,
                    if orphan.len() > 3 { " 等" } else { "" }
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
        sched_scope: scope,
        sched_pkgs,
        sched,
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
        println!("inotify初始化失败，使用轮询模式");
        return;
    }
    let cfg_cstr = match CString::new(config_file) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("错误: 配置文件路径包含非法字符，使用轮询模式");
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
        println!("启用inotify监控配置文件变更");
    } else {
        unsafe {
            libc::close(inotify_fd);
        }
        println!("inotify初始化失败，使用轮询模式");
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

fn config_reload(last_mtime: &mut i64) {
    let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
        return;
    };
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
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
                *last_mtime = -1;
                if event.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
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
            eprintln!("错误: 配置文件路径包含非法字符，降级为轮询模式");
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
        CpuTopology {
            present_cpus: present,
            present_str: present.to_range_string(),
            mems_str: "0".to_string(),
            cpuset_enabled: false,
            e_core: set(e),
            p_core: set(p),
            hp_core: set(h),
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

    #[test]
    fn full_set_rule_is_not_cross_cluster() {
        // 写 0-7 表示不限制，不代表跨簇意图
        let topo = topo_of(&[0, 1, 2, 3], &[4, 5], &[6, 7]);
        let s = scope_of("full", "com.a=0-7\n", &topo);
        assert_eq!((s.levels, s.rules, s.pkgs), (3, 0, 0));
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
