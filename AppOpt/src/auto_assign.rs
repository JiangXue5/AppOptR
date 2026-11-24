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
/// 线程至少存活这么久才建议：只闪一下的多是临时线程，给它们写规则
/// 只会让配置膨胀而没有任何收益
const MIN_ALIVE_SECS: u64 = 60;
/// 存活超过这么久算高置信度
const HIGH_ALIVE_SECS: u64 = 300;

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

/// 线程已存活多少秒；tid 对不上（线程已退出或被复用）返回 0，视为不可用。
/// 读不到 `/proc/<tid>/comm` 时不建议：候选列表里不该出现已经消失的线程
fn alive_for(s: &Seen, thread: &str, now: u64) -> u64 {
    let alive = fs::read_to_string(format!("/proc/{}/comm", s.tid))
        .is_ok_and(|c| c.trim() == thread);
    if !alive {
        return 0;
    }
    now.saturating_sub(s.first)
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

/// 观察一条线程。由 `cache::task_apply` 在「首次登记」时调用一次，
/// 不在稳态路径上重复计数——那会把「线程活得久」算成「置信度高」。
/// 未知角色的线程也记：它们不进候选列表，但要让包级兜底建议有依据
pub fn note(pkg: &str, thread: &str, tid: i32) {
    if thread.is_empty() {
        return;
    }
    let mut guard = lock_ignore_poison(&SEEN);
    let map = guard.get_or_insert_with(HashMap::new);
    let e = map
        .entry((pkg.to_string(), thread.to_string()))
        .or_insert(Seen {
            role: role_of(thread),
            first: now_secs(),
            tid,
        });
    // 线程重建（tid 变了）时把指针指向新线程，存活校验才不会一直看旧号
    e.tid = tid;
}

/// 生成当前候选。已存在于正式规则里的跳过：用户已经表态过，不必再问
pub fn collect(cfg: &AppConfig) -> Vec<Candidate> {
    let now = now_secs();
    let guard = lock_ignore_poison(&SEEN);
    let Some(map) = guard.as_ref() else {
        return Vec::new();
    };
    let mut out: Vec<Candidate> = map
        .iter()
        .filter(|((_, thread), s)| alive_for(s, thread, now) >= MIN_ALIVE_SECS)
        .filter_map(|((pkg, thread), s)| {
            // 已有同包同名的线程规则就不再建议
            let exists = cfg.rules.iter().any(|r| {
                r.pkg == *pkg && (r.thread == *thread || r.thread.is_empty())
            });
            if exists {
                return None;
            }
            let cpus = suggest_cpus(s.role)?;
            Some(Candidate {
                pkg: pkg.clone(),
                thread: thread.clone(),
                cpus: cpus.to_string(),
                role: role_label(s.role),
                confidence: if alive_for(s, thread, now) >= HIGH_ALIVE_SECS {
                    "high"
                } else {
                    "medium"
                },
                reason: "按线程角色推断，未经负载采样验证",
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
    for ((pkg, _thread), s) in map.iter() {
        if s.role == Role::Unknown && alive_for(s, _thread, now) >= MIN_ALIVE_SECS {
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

/// 从候选文件读。格式损坏的行直接跳过：这是可再生的派生文件，
/// 不该让一行写坏导致整个列表打不开
pub fn load_file() -> Vec<Candidate> {
    let Ok(text) = fs::read_to_string(candidate_path()) else {
        return Vec::new();
    };
    let now = now_secs();
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(parse_line)
        .filter(|c| !c.expired(now))
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
        confidence: if f[4].trim() == "high" { "high" } else { "medium" },
        reason: "按线程角色推断，未经负载采样验证",
        created_at: f[6].trim().parse().ok()?,
        expires_at: f[7].trim().parse().ok()?,
    })
}

/// 把内存候选合并进文件。已有的同键候选保留原创建时间——
/// 每轮都刷新 created_at 会让它永远不过期
pub fn flush(cfg: &AppConfig) -> usize {
    if !cfg.auto_assign {
        return 0;
    }
    let fresh = collect(cfg);
    if fresh.is_empty() {
        return 0;
    }
    let now = now_secs();
    let mut merged: HashMap<(String, String), Candidate> = load_file()
        .into_iter()
        .filter(|c| !c.expired(now))
        .map(|c| ((c.pkg.clone(), c.thread.clone()), c))
        .collect();
    let mut added = 0;
    for c in fresh {
        let key = (c.pkg.clone(), c.thread.clone());
        if !merged.contains_key(&key) {
            added += 1;
        }
        merged.entry(key).or_insert(c);
    }
    if added == 0 {
        return 0;
    }
    let mut list: Vec<Candidate> = merged.into_values().collect();
    list.sort_by(|a, b| a.pkg.cmp(&b.pkg).then(a.thread.cmp(&b.thread)));
    if write_file(&list).is_ok() {
        added
    } else {
        0
    }
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
}
