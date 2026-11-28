//! Auto Assign 候选（融合方案第十三节）。
//!
//! 只做「观察 + 建议」，不写主配置。用户确认后由 `web.rs` 转交
//! `rule_edit::rule_upsert` 写入——配置写入器只能有一个，这条边界不能破。
//!
//! 候选落在与主配置同目录的 `AppOpt.autocache.conf`，30 天过期。
//! 第一版不做负载采样与 ML：按线程角色给建议，判错方向的代价不对称，
//! 角色表本身已经是保守口径（见 `roles.rs`）。

use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{AppConfig, CONFIG_FILE};
use crate::lock_ignore_poison;
use crate::roles::{Role, role_of};

/// 候选有效期。超过这个时间的候选自动从列表里消失——三个月前的线程名
/// 对现在的版本未必成立，留着只会误导
const TTL_SECS: u64 = 30 * 24 * 3600;
/// 线程至少在前台存活这么久才建议：只闪一下的多是临时线程，给它们写规则
/// 只会让配置膨胀而没有任何收益
const MIN_ALIVE_SECS: u64 = 60;
/// 前台存活超过这么久算高置信度
const HIGH_ALIVE_SECS: u64 = 300;
/// 两次观察的最大合理间隔。超过它说明中间根本没看住这条线程（包被移出配置
/// 一段时间后又加回来、进程被冻住），这段空档不能算成前台时长，否则一个
/// 刚被重新纳入管理的进程能凭「挂了一小时」直接跳到高置信度
const MAX_GAP_SECS: u64 = 120;

/// 一条候选。字段与 `AppOpt.autocache.conf` 的列一一对应
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub pkg: String,
    /// 空表示包级规则
    pub thread: String,
    /// 建议集合，语义名或数字范围
    pub cpus: String,
    pub role: &'static str,
    /// high / medium
    pub confidence: &'static str,
    pub reason: &'static str,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Candidate {
    pub fn expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// 观察记录。只在 `@auto_assign=on` 时累积
struct Seen {
    role: Role,
    first: u64,
    /// 最近一次被观察到的时刻，用来把两轮之间的间隔计入前台时长
    last: u64,
    /// 累计在前台被观察到的秒数。后台挂着的时间一律不算
    fg_secs: u64,
    /// 是否至少在前台出现过。从没在前台跑过的线程不给建议
    seen_fg: bool,
    /// 最近一次看到的 tid。线程重建后编号会变，用它做存活校验
    tid: i32,
}

static SEEN: Mutex<Option<HashMap<(String, String), Seen>>> = Mutex::new(None);

/// 候选文件路径：与主配置同目录，避免用户在 `/data/adb` 下找不到
pub fn candidate_path() -> String {
    let main = lock_ignore_poison(&CONFIG_FILE).clone();
    match main.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => format!("{dir}/AppOpt.autocache.conf"),
        _ => "AppOpt.autocache.conf".to_string(),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 角色 → 建议集合。Unknown 不生成候选：不知道就不写。
fn suggest_cpus(role: Role) -> Option<&'static str> {
    match role {
        Role::Critical => Some("hp-core"),
        Role::Latency => Some("p-core"),
        Role::Worker | Role::Background => Some("e-core"),
        Role::Unknown => None,
    }
}

/// 线程是否还活着：tid 对不上（已退出或被复用）即为否。
/// 读不到 `/proc/<tid>/comm` 时不建议——候选列表里不该出现已经消失的线程
fn alive(s: &Seen, thread: &str) -> bool {
    fs::read_to_string(format!("/proc/{}/comm", s.tid)).is_ok_and(|c| c.trim() == thread)
}

/// 采样窗口里的一档负载。只用来校正置信度，**不改变建议集合**：
/// 集合由角色决定，实测负载回答的是「值不值得现在就去问用户」，
/// 不是「该绑哪个核」——后者需要对照实验，不是一次采样能定的
enum Load {
    Busy,
    Light,
    Idle,
}

fn load_class(s: &crate::pmu::Sample) -> Load {
    let pct = s
        .cpu_ns
        .map(|ns| ns as f64 / (s.window_ms.max(1) as f64 * 1e6));
    match pct {
        // 软件计时给的是「占满一个核的比例」，5% 已经能说明这条线程在干活
        Some(p) if p >= 0.05 => Load::Busy,
        Some(p) if p < 0.005 => Load::Idle,
        Some(_) => Load::Light,
        // 硬件计数只有 M/s。不同 SoC 每 M/s 对应的核占比差一倍以上，
        // 用它算占比会得出不可比的数，只按量级分忙闲
        None if s.mips() >= 100.0 => Load::Busy,
        None if s.mips() < 5.0 => Load::Idle,
        None => Load::Light,
    }
}

/// 置信度与理由。`pmu` 为 `None` 表示这条线程没被测过（PMU 关着、
/// 或本窗口不够忙没进采样），**不能当成「测了是 0」**——把「没测」
/// 当「闲」会把正常线程的建议压成低置信度
fn grade(fg_secs: u64, pmu: Option<&crate::pmu::Sample>) -> (&'static str, &'static str) {
    let by_time = if fg_secs >= HIGH_ALIVE_SECS {
        "high"
    } else {
        "medium"
    };
    match pmu.map(load_class) {
        Some(Load::Busy) => ("high", "负载采样确认：观察窗口内持续占用 CPU"),
        Some(Load::Idle) => ("medium", "负载采样：窗口内几乎不占 CPU，仅按角色推断"),
        Some(Load::Light) => (by_time, "负载采样：窗口内负载较轻"),
        None => (by_time, "按线程角色推断，未经负载采样验证"),
    }
}

fn role_label(role: Role) -> &'static str {
    match role {
        Role::Critical => "Critical",
        Role::Latency => "Latency",
        Role::Worker => "Worker",
        Role::Background => "Background",
        Role::Unknown => "Unknown",
    }
}

/// 把一次观察写进记录。抽成纯函数：`note` 依赖墙钟与全局表，
/// 只有它自己能脱离真机单测，而「空档不算前台」「重建从头计」这两条
/// 恰好是最容易写错的地方
fn observe(s: &mut Seen, thread: &str, tid: i32, now: u64, fg: bool) {
    // tid 变了 = 同名的旧线程已退出、编号被新线程拿走（线程重建）。
    // 计时必须从头算：沿用旧 `first` 会把上一个实例的前台时长算到新实例头上，
    // 一个刚起来 2 秒的线程能直接显示「高置信度」，采纳后写进配置的却是
    // 一个还没被观察过的对象
    if s.tid != tid {
        *s = Seen {
            role: role_of(thread),
            first: now,
            last: now,
            fg_secs: 0,
            seen_fg: fg,
            tid,
        };
        return;
    }
    if fg {
        // 只把「确实看住的那段」算成前台：两轮之间隔了两分钟以上，说明这段
        // 时间没有观察（包被移出配置、进程被冻住），按 0 计，不虚增置信度
        let gap = now.saturating_sub(s.last);
        if gap <= MAX_GAP_SECS {
            s.fg_secs = s.fg_secs.saturating_add(gap);
        }
        s.seen_fg = true;
    }
    s.last = now;
}

/// 观察一条线程。`cache::task_apply` 每次评估都会调一次，判重靠 `(包, 线程名)`，
/// 重复调用不累加计数——否则「每轮都看到」会被算成「活得久」，置信度虚高。
///
/// `fg` 是这条线程所在应用此刻是否在前台。后台样本只记录角色、不累计时长：
/// 后台进程常常整夜挂着，按存活时长算出来的「高置信度」毫无意义，而且
/// 会让建议与前后台降档互相矛盾
pub fn note(pkg: &str, thread: &str, tid: i32, fg: bool) {
    if thread.is_empty() {
        return;
    }
    let now = now_secs();
    let mut guard = lock_ignore_poison(&SEEN);
    let map = guard.get_or_insert_with(HashMap::new);
    let e = map
        .entry((pkg.to_string(), thread.to_string()))
        .or_insert(Seen {
            role: role_of(thread),
            first: now,
            last: now,
            fg_secs: 0,
            seen_fg: fg,
            tid,
        });
    observe(e, thread, tid, now, fg);
}

/// 这条线程是否已被用户显式配置覆盖（含通配与包级兜底）。
/// 抽成纯函数：`collect` 依赖 `/proc` 存活探测，只有它能脱离真机单测
fn covered(cfg: &AppConfig, pkg: &str, thread: &str) -> bool {
    cfg.rules.iter().any(|r| {
        r.pkg == pkg && (r.thread.is_empty() || crate::rule_match::pattern_hits(&r.thread, thread))
    })
}

/// 生成当前候选。已存在于正式规则里的跳过：用户已经表态过，不必再问
pub fn collect(cfg: &AppConfig) -> Vec<Candidate> {
    let now = now_secs();
    let guard = lock_ignore_poison(&SEEN);
    let Some(map) = guard.as_ref() else {
        return Vec::new();
    };
    // 门槛看「前台观察时长」而不是「存活时长」：后台挂着的线程活得再久，
    // 也没有一条能说明它需要绑核的证据
    // 采样表只在 PMU 开着时有内容。空表意味着「没有实测」，不是「负载为零」
    let loads = crate::pmu::loads();
    let mut out: Vec<Candidate> = map
        .iter()
        .filter(|((_, thread), s)| alive(s, thread) && s.seen_fg && s.fg_secs >= MIN_ALIVE_SECS)
        .filter_map(|((pkg, thread), s)| {
            // 已有同包同名（含通配）的线程规则就不再建议
            if covered(cfg, pkg, thread) {
                return None;
            }
            let cpus = suggest_cpus(s.role)?;
            let (confidence, reason) = grade(s.fg_secs, loads.get(&(pkg.clone(), thread.clone())));
            Some(Candidate {
                pkg: pkg.clone(),
                thread: thread.clone(),
                cpus: cpus.to_string(),
                role: role_label(s.role),
                confidence,
                reason,
                created_at: s.first,
                expires_at: s.first + TTL_SECS,
            })
        })
        .filter(|c| !c.expired(now))
        .collect();

    // 包级兜底：某个包有线程规则、但没有包级规则，且未识别线程已经多到
    // 说明「线程规则覆盖不全」。这时给一条包级 other 建议到小核，
    // 比让这些线程按继承的掩码到处跑更可控。
    // 阈值取 8：三五个临时线程不足以说明覆盖不全
    let mut unknown: HashMap<&str, (u32, u64)> = HashMap::new();
    for ((pkg, thread), s) in map.iter() {
        // 与候选同一条口径：后台观察到的未识别线程不算「覆盖不全」的证据，
        // 否则一个只在后台跑过的包也会被建议加包级兜底规则
        if s.role == Role::Unknown && alive(s, thread) && s.seen_fg && s.fg_secs >= MIN_ALIVE_SECS {
            let e = unknown.entry(pkg.as_str()).or_insert((0, s.first));
            e.0 += 1;
            e.1 = e.1.min(s.first);
        }
    }
    for (pkg, (n, first)) in unknown {
        if n < 8 {
            continue;
        }
        let has_thread = cfg
            .rules
            .iter()
            .any(|r| r.pkg == pkg && !r.thread.is_empty());
        let has_pkg = cfg
            .rules
            .iter()
            .any(|r| r.pkg == pkg && r.thread.is_empty());
        if !has_thread || has_pkg {
            continue;
        }
        out.push(Candidate {
            pkg: pkg.to_string(),
            thread: String::new(),
            cpus: "e-core".to_string(),
            role: "Unknown",
            confidence: "medium",
            reason: "包内未识别线程占多数，建议包级兜底到小核",
            created_at: first,
            expires_at: first + TTL_SECS,
        });
    }
    out.sort_by(|a, b| a.pkg.cmp(&b.pkg).then(a.thread.cmp(&b.thread)));
    out
}

/// 从候选文件读，丢弃过期行。格式损坏的行直接跳过：这是可再生的派生文件，
/// 不该让一行写坏导致整个列表打不开
pub fn load_file() -> Vec<Candidate> {
    let now = now_secs();
    read_all().into_iter().filter(|c| !c.expired(now)).collect()
}

/// 文件里的全部可解析行，含已过期。`flush` 要靠它统计「这次清掉了几条」——
/// 只读未过期的列表，过期行会永远留在文件里，越攒越多
fn read_all() -> Vec<Candidate> {
    let Ok(text) = fs::read_to_string(candidate_path()) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(parse_line)
        .collect()
}

fn parse_line(line: &str) -> Option<Candidate> {
    let f: Vec<&str> = line.split('|').collect();
    if f.len() != 8 {
        return None;
    }
    Some(Candidate {
        pkg: f[0].trim().to_string(),
        thread: f[1].trim().to_string(),
        cpus: f[2].trim().to_string(),
        // 角色与原因是 `&'static str`，读回来的任意文本只能归一化，
        // 认不出的归为 Unknown：宁可在界面上少一个标签，也不泄漏任意串
        role: match f[3].trim() {
            "Critical" => "Critical",
            "Latency" => "Latency",
            "Worker" => "Worker",
            "Background" => "Background",
            _ => "Unknown",
        },
        confidence: if f[4].trim() == "high" {
            "high"
        } else {
            "medium"
        },
        reason: "按线程角色推断，未经负载采样验证",
        created_at: f[6].trim().parse().ok()?,
        expires_at: f[7].trim().parse().ok()?,
    })
}

/// 合并「文件里已有」与「本轮新采集」：同键保留旧记录（创建时间不能被
/// 刷新，否则永远不过期），过期的直接丢弃。
///
/// 返回 `(合并结果, 新增条数, 清掉的过期条数)`。纯函数，`flush` 只管读写
fn merge_into(
    existing: Vec<Candidate>,
    fresh: Vec<Candidate>,
    now: u64,
) -> (Vec<Candidate>, usize, usize) {
    let total = existing.len();
    let mut merged: HashMap<(String, String), Candidate> = existing
        .into_iter()
        .filter(|c| !c.expired(now))
        .map(|c| ((c.pkg.clone(), c.thread.clone()), c))
        .collect();
    let dropped = total - merged.len();
    let mut added = 0;
    for c in fresh {
        let key = (c.pkg.clone(), c.thread.clone());
        if !merged.contains_key(&key) {
            added += 1;
        }
        merged.entry(key).or_insert(c);
    }
    let mut list: Vec<Candidate> = merged.into_values().collect();
    list.sort_by(|a, b| a.pkg.cmp(&b.pkg).then(a.thread.cmp(&b.thread)));
    (list, added, dropped)
}

/// 把内存候选合并进文件。
///
/// 本函数同时负责**清理过期行**：`load_file` 已经把它们过滤掉了，若只按
/// 「有没有新增」决定写不写，过期记录会一直躺在文件里。用户打开
/// `AppOpt.autocache.conf` 看到的是一堆早就失效的建议，与界面上的列表不符
pub fn flush(cfg: &AppConfig) -> usize {
    if !cfg.auto_assign {
        return 0;
    }
    let (list, added, dropped) = merge_into(read_all(), collect(cfg), now_secs());
    if added == 0 && dropped == 0 {
        return 0;
    }
    if write_file(&list).is_ok() { added } else { 0 }
}

fn write_file(list: &[Candidate]) -> std::io::Result<()> {
    let mut s = String::from(
        "# AppOpt Auto Assign 候选（自动生成，可直接删除）\n\
         # 格式：包|线程|建议集合|角色|置信度|原因|创建时间|过期时间\n\
         # 确认请在 WebUI 规则页操作；确认后本行会自动移除\n",
    );
    for c in list {
        s.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}|{}\n",
            c.pkg, c.thread, c.cpus, c.role, c.confidence, c.reason, c.created_at, c.expires_at
        ));
    }
    fs::write(candidate_path(), s)
}

/// 用户确认或忽略后移除一条。确认路径由 `web.rs` 先写正式规则再调这里
pub fn remove(pkg: &str, thread: &str) -> bool {
    let mut list = load_file();
    let before = list.len();
    list.retain(|c| !(c.pkg == pkg && c.thread == thread));
    if list.len() == before {
        return false;
    }
    write_file(&list).is_ok()
}

/// 退出或关掉开关时清空内存观察，避免下次打开时把旧计数当新数据
pub fn reset() {
    *lock_ignore_poison(&SEEN) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_empty_produce_no_candidate() {
        assert_eq!(suggest_cpus(Role::Unknown), None);
        assert_eq!(suggest_cpus(Role::Critical), Some("hp-core"));
        assert_eq!(suggest_cpus(Role::Worker), Some("e-core"));
        assert_eq!(suggest_cpus(Role::Latency), Some("p-core"));
    }

    fn sample(cpu_ns: Option<u64>, inst: u64) -> crate::pmu::Sample {
        crate::pmu::Sample {
            tid: 100,
            pkg: "com.a".into(),
            comm: "RenderThread".into(),
            inst,
            cycles: inst * 2,
            misses: None,
            cpu_ns,
            window_ms: 5000,
        }
    }

    /// 实测持续占用 CPU 的线程直接给高置信度：它自己证明了自己值不值得问
    #[test]
    fn busy_sample_raises_to_high() {
        // 5 秒窗口里跑了 1 秒 = 20% 一个核
        let s = sample(Some(1_000_000_000), 0);
        assert_eq!(grade(0, Some(&s)).0, "high");
        // 硬件计数模式：200 M/s 属于在干活
        let s2 = sample(None, 1_000_000_000);
        assert_eq!(grade(0, Some(&s2)).0, "high");
    }

    /// 采到但几乎不跑：降回 medium 并写明原因。
    /// 「挂着但不干活」的线程占了 hp-core 只会让真正要跑的线程抢不到
    #[test]
    fn idle_sample_downgrades() {
        let s = sample(Some(1_000_000), 0); // 0.02% 一个核
        let (c, r) = grade(HIGH_ALIVE_SECS + 10, Some(&s));
        assert_eq!(c, "medium");
        assert!(r.contains("几乎不占 CPU"), "{r}");
    }

    /// 没测到 ≠ 测出来是 0。PMU 关着时不能把全部候选降成低置信度，
    /// 否则默认配置下 Auto Assign 的建议会整体变差
    #[test]
    fn no_sample_keeps_time_grade() {
        assert_eq!(grade(0, None).0, "medium");
        assert_eq!(grade(HIGH_ALIVE_SECS, None).0, "high");
        assert!(grade(0, None).1.contains("未经负载采样"));
    }

    #[test]
    fn line_roundtrip() {
        let c = Candidate {
            pkg: "com.a".into(),
            thread: "RenderThread".into(),
            cpus: "hp-core".into(),
            role: "Critical",
            confidence: "high",
            reason: "r",
            created_at: 100,
            expires_at: 200,
        };
        let line = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            c.pkg, c.thread, c.cpus, c.role, c.confidence, c.reason, c.created_at, c.expires_at
        );
        let back = parse_line(&line).expect("应能解析");
        assert_eq!(back.pkg, c.pkg);
        assert_eq!(back.thread, c.thread);
        assert_eq!(back.cpus, c.cpus);
        assert_eq!(back.created_at, 100);
    }

    /// 未知角色名归一化成 Unknown，不把任意文本带进界面
    #[test]
    fn unknown_role_is_normalised() {
        let c = parse_line("a|b|e-core|<script>|x|r|1|2").unwrap();
        assert_eq!(c.role, "Unknown");
    }

    #[test]
    fn malformed_line_is_skipped() {
        assert!(parse_line("a|b|c").is_none());
        assert!(parse_line("a|b|c|Worker|high|r|x|2").is_none());
    }

    fn rule(pkg: &str, thread: &str) -> crate::config::AffinityRule {
        crate::config::AffinityRule {
            pkg: pkg.to_string(),
            thread: thread.to_string(),
            thread_pattern: std::ffi::CString::new(thread).unwrap_or_default(),
            spec: crate::config::spec_of_pattern(thread),
            cpuset_dir: String::new(),
            cpus: crate::cpuset::CpuSet::new(),
        }
    }

    fn cand(pkg: &str, thread: &str, created: u64, expires: u64) -> Candidate {
        Candidate {
            pkg: pkg.into(),
            thread: thread.into(),
            cpus: "e-core".into(),
            role: "Worker",
            confidence: "medium",
            reason: "r",
            created_at: created,
            expires_at: expires,
        }
    }

    /// 过期行必须被丢掉：只在「有新增」时才写文件的话，一条早就失效的
    /// 建议会永远留在 `AppOpt.autocache.conf` 里，与界面列表对不上
    #[test]
    fn merge_drops_expired_and_counts_it() {
        let old = vec![
            cand("com.a", "Old", 100, 200),
            cand("com.a", "Live", 100, 900),
        ];
        let (list, added, dropped) = merge_into(old, Vec::new(), 500);
        assert_eq!(dropped, 1);
        assert_eq!(added, 0);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].thread, "Live");
    }

    /// 同键保留旧的创建时间：每轮刷新会让 created_at 永远是「现在」，
    /// 30 天过期永远不会触发
    #[test]
    fn merge_keeps_original_created_at() {
        let old = vec![cand("com.a", "RenderThread", 100, 900)];
        let (list, added, dropped) =
            merge_into(old, vec![cand("com.a", "RenderThread", 800, 900)], 500);
        assert_eq!((added, dropped), (0, 0));
        assert_eq!(list[0].created_at, 100);
    }

    /// 通配规则已经覆盖的线程不再给建议：`Render*` 配过之后再提示
    /// 「建议给 RenderThread 加规则」属于重复劳动
    #[test]
    fn wildcard_rule_covers_candidate() {
        let mut cfg = AppConfig::empty();
        cfg.rules.push(rule("com.a", "Render*"));
        assert!(covered(&cfg, "com.a", "RenderThread"));
        assert!(!covered(&cfg, "com.a", "AudioTrack"));
        // 别的包的通配不构成覆盖
        assert!(!covered(&cfg, "com.b", "RenderThread"));
    }

    /// 包级规则覆盖包内全部线程，不必逐条建议
    #[test]
    fn package_rule_covers_every_thread() {
        let mut cfg = AppConfig::empty();
        cfg.rules.push(rule("com.a", ""));
        assert!(covered(&cfg, "com.a", "Anything"));
    }

    /// 同名线程重建（tid 变了）时计时从头算：否则旧实例在前台跑了一小时，
    /// 新实例刚起来就被标成「高置信度」
    #[test]
    fn reused_tid_resets_alive_window() {
        reset();
        let pkg = "com.test.reuse";
        let thread = "RenderThread";
        note(pkg, thread, 12345, true);
        {
            let mut g = lock_ignore_poison(&SEEN);
            let m = g.as_mut().expect("已登记");
            let e = m
                .get_mut(&(pkg.to_string(), thread.to_string()))
                .expect("键存在");
            e.first = 0;
            e.fg_secs = 600;
        }
        note(pkg, thread, 54321, true);
        let g = lock_ignore_poison(&SEEN);
        let s = g
            .as_ref()
            .unwrap()
            .get(&(pkg.to_string(), thread.to_string()))
            .unwrap();
        assert_ne!(s.first, 0, "tid 变化后 first 必须重置");
        assert_eq!(s.tid, 54321);
        assert_eq!(s.fg_secs, 0, "上一个实例的前台时长不能算到新实例头上");
        drop(g);
        reset();
    }

    fn seen(tid: i32) -> Seen {
        Seen {
            role: Role::Worker,
            first: 0,
            last: 0,
            fg_secs: 0,
            seen_fg: false,
            tid,
        }
    }

    /// 后台挂着的时间不能算成前台时长：否则一个整夜挂在后台的进程，
    /// 第二天会被建议绑大核
    #[test]
    fn background_time_is_not_counted() {
        let mut s = seen(7);
        observe(&mut s, "Worker", 7, 10, false);
        observe(&mut s, "Worker", 7, 120, false);
        assert_eq!(s.fg_secs, 0);
        assert!(!s.seen_fg);
    }

    /// 前台按轮次间隔累加，且只在真实观察到的那段里累加
    #[test]
    fn foreground_time_accumulates_by_gap() {
        let mut s = seen(7);
        // 新建记录时 last 与 now 相同，首轮间隔为 0
        s.last = 10;
        observe(&mut s, "Worker", 7, 10, true);
        observe(&mut s, "Worker", 7, 70, true);
        observe(&mut s, "Worker", 7, 130, true);
        assert!(s.seen_fg);
        assert_eq!(s.fg_secs, 120);
    }

    /// 两轮之间隔太久说明中间没看住（包被移出配置、进程被冻住），
    /// 这段空档按 0 计，不能虚增置信度
    #[test]
    fn long_gap_is_not_counted() {
        let mut s = seen(7);
        observe(&mut s, "Worker", 7, 0, true);
        observe(&mut s, "Worker", 7, MAX_GAP_SECS + 1, true);
        assert_eq!(s.fg_secs, 0);
        // 下一次间隔正常，照常累加
        observe(&mut s, "Worker", 7, MAX_GAP_SECS + 31, true);
        assert_eq!(s.fg_secs, 30);
    }
}
