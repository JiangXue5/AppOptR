use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::apply_affinity::{read_cmdline, reset_cpuset_dir_cache, task_tids};
use crate::cache::ProcCache;
use crate::config::{
    config_reload_now, spec_like,
    CHECK_INTERVAL, CONFIG_FILE, CURRENT_CONFIG, FORCE_RELOAD, PARSE_FAILS, RT_MAX_LIMIT,
    RT_TIMESLICE_LIMIT,
};
use crate::cpuset::{base_cpuset, create_cpuset_dir, parse_cpu_spec, CpuSet, CpuTopology, DEFAULT_CPUSET_NAME};
use crate::diag;
use crate::ebpf_mode::ebpf_probe;
use crate::config::{RtMatch, RtScope};
use crate::rt;
use crate::rule_edit::{
    adv_configure, rt_app_set, rt_configure, rt_toggle, rule_delete, rule_delete_pkg, rule_rename,
    rule_upsert, sched_set, RuleEdit,
};
use crate::sched::SCHED_SNAPSHOT;
use crate::{lock_ignore_poison, EBPF_GAVE_UP, MAX_PKG_LEN, MAX_THREAD_LEN};

pub const WEB_PORT: u16 = 8889;
const INDEX_HTML: &str = include_str!("../../web/index.html");

pub static MODE_FORCE: AtomicU8 = AtomicU8::new(0);
pub static WEB_ENABLED: AtomicBool = AtomicBool::new(false);

pub static WEB_STATS: Mutex<Option<WebStats>> = Mutex::new(None);

#[derive(Clone)]
pub struct WebStats {
    pub rules: usize,
    pub pkgs: usize,
    pub hit_pkgs: usize,
    pub threads: usize,
    pub ebpf: bool,
    pub uptime: u64,
    /// 运行期累计的 RingBuf 丢弃事件数
    pub dropped: u64,
}

/// 缓存统计
pub fn cache_stats(cache: &ProcCache) -> (usize, usize) {
    let pkgs: HashSet<&str> = cache.tasks.values().map(|e| e.pkg.as_str()).collect();
    (cache.tasks.len(), pkgs.len())
}

/// 启动 web 前端，监听成功返回 true
pub fn web_start() -> bool {
    let listener = match TcpListener::bind(("127.0.0.1", WEB_PORT)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Web: 监听 127.0.0.1:{} 失败 ({})", WEB_PORT, e);
            return false;
        }
    };
    WEB_ENABLED.store(true, Ordering::Release);
    println!("Web: 前端已启用 http://127.0.0.1:{}/", WEB_PORT);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || conn_handle(stream));
        }
    });
    true
}

struct Request {
    method: String,
    path: String,
    host: String,
    origin: String,
    fetch_site: String,
    content_type: String,
    body: Vec<u8>,
    keep_alive: bool,
}

fn conn_handle(stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_nodelay(true);
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    while let Some(req) = request_read(&mut reader) {
        dispatch(&mut writer, &req);
        if !req.keep_alive {
            return;
        }
    }
}

fn request_read(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut head = Vec::with_capacity(512);
    let mut line = Vec::with_capacity(128);
    loop {
        line.clear();
        reader.read_until(b'\n', &mut line).ok()?;
        if line.is_empty() {
            return None;
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head.extend_from_slice(&line);
        if head.len() > 8192 {
            return None;
        }
    }

    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.split('?').next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let (mut host, mut origin, mut site, mut ctype, mut len) =
        (String::new(), String::new(), String::new(), String::new(), 0usize);
    let mut conn = String::new();
    for h in lines {
        let Some((k, v)) = h.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "host" => host = v.to_ascii_lowercase(),
            "origin" => origin = v.to_ascii_lowercase(),
            "sec-fetch-site" => site = v.to_ascii_lowercase(),
            "content-type" => ctype = v.to_ascii_lowercase(),
            "content-length" => len = v.parse().unwrap_or(usize::MAX),
            "connection" => conn = v.to_ascii_lowercase(),
            "transfer-encoding" => return None, // 拒绝 chunked
            _ => {}
        }
    }
    if len > 16384 {
        return None;
    }

    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    let keep_alive = if version == "HTTP/1.0" {
        conn.contains("keep-alive")
    } else {
        !conn.contains("close")
    };
    Some(Request {
        method,
        path,
        host,
        origin,
        fetch_site: site,
        content_type: ctype,
        body,
        keep_alive,
    })
}

/// WebUI 容器（KernelSU 的 WebViewAssetLoader）页面源的固定域名。
/// 该域名下的页面由模块自己的 webroot 提供，属于本机受信容器；
/// 回环来源同理，能起本地服务的进程本来就能直连 8889，不构成新增攻击面。
/// 其余跨站 Origin 仍然拒绝，避免任意网页驱动本地 API。
fn origin_allowed(origin: &str) -> bool {
    if origin == "https://mui.kernelsu.org" {
        return true;
    }
    // 回环来源允许任意端口，但 host 之后必须是结尾或 ":端口"，避免 127.0.0.1.evil 这类前缀伪装
    for prefix in ["http://127.0.0.1", "http://localhost"] {
        if let Some(rest) = origin.strip_prefix(prefix)
            && (rest.is_empty()
                || (rest.starts_with(':') && rest[1..].bytes().all(|b| b.is_ascii_digit())))
        {
            return true;
        }
    }
    false
}

fn resp_send(
    out: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
    close: bool,
    cors: Option<&str>,
) {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: {}\r\n",
        status,
        reason,
        ctype,
        body.len(),
        if close { "close" } else { "keep-alive" }
    );
    if let Some(o) = cors {
        // 回显具体来源而非 *，保留将来加凭据的可能；PNA 头供 https 页面访问回环地址时通过预检
        head.push_str(&format!(
            "Access-Control-Allow-Origin: {}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Allow-Private-Network: true\r\n",
            o
        ));
    }
    head.push_str("\r\n");
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(body);
    let _ = out.flush();
}

fn dispatch(out: &mut TcpStream, req: &Request) {
    let port_str = format!(":{}", WEB_PORT);
    let host = req.host.strip_suffix(&port_str).unwrap_or(req.host.as_str());
    let host_ok = matches!(host, "127.0.0.1" | "localhost");
    // 同源请求不带 Origin 或为 null；WebUI 容器来源的 Sec-Fetch-Site 必然是 cross-site
    let same_site = req.origin.is_empty()
        || req.origin == "null"
        || matches!(req.fetch_site.as_str(), "" | "none" | "same-origin");
    let cross_webui = origin_allowed(&req.origin);
    let cors = cross_webui.then_some(req.origin.as_str());
    let origin_ok = host_ok
        && (same_site || cross_webui)
        && (req.method != "POST" || req.content_type.starts_with("application/json"));

    // 预检不携带业务语义，只回放行头；来源不在白名单时直接拒绝
    if req.method == "OPTIONS" {
        let ok = host_ok && cross_webui;
        resp_send(
            out,
            if ok { 204 } else { 403 },
            "text/plain",
            b"",
            true,
            if ok { cors } else { None },
        );
        return;
    }

    if !origin_ok {
        resp_send(
            out,
            403,
            "application/json",
            b"{\"ok\":false,\"err\":\"forbidden\"}",
            true,
            None,
        );
        return;
    }

    if req.method == "GET" && matches!(req.path.as_str(), "/" | "/index.html") {
        resp_send(
            out,
            200,
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes(),
            !req.keep_alive,
            cors,
        );
        return;
    }

    let (status, body) = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/status") => (200, status_json()),
        ("GET", "/api/rules") => (200, rules_json()),
        ("GET", "/api/config") => (200, config_json()),
        ("GET", "/api/diag") => (200, diag_json()),
        ("GET", "/api/rt") => (200, rt_json()),
        ("POST", "/api/rule") => rule_api(req),
        ("POST", "/api/rule/del") => rule_del_api(req),
        ("POST", "/api/rule/rename") => rule_rename_api(req),
        ("POST", "/api/config") => config_set_api(req),
        ("POST", "/api/rt") => rt_api(req),
        ("POST", "/api/rt/app") => rt_app_api(req),
        ("POST", "/api/rt/toggle") => rt_toggle_api(req),
        ("POST", "/api/sched") => sched_api(req),
        ("POST", "/api/adv") => adv_api(req),
        ("POST", "/api/suggest") => suggest_api(req),
        _ => err_json(404, "not found"),
    };
    resp_send(out, status, "application/json", body.as_bytes(), !req.keep_alive, cors);
}

fn err_json(code: u16, msg: &str) -> (u16, String) {
    (code, json!({ "ok": false, "err": msg }).to_string())
}

fn current_cfg() -> Option<std::sync::Arc<crate::config::AppConfig>> {
    lock_ignore_poison(&CURRENT_CONFIG).clone()
}

fn sys_procs() -> u16 {
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        info.procs
    } else {
        0
    }
}

/// CPU 集合转语义名
fn spec_name(cpus: &CpuSet, topo: &CpuTopology) -> String {
    if cpus.count() > 0 {
        // 降级拓扑下多个语义名可能指向同一集合，先判全集再判单簇，展示才不误导
        if *cpus == topo.present_cpus {
            return "all-core".into();
        }
        if *cpus == topo.e_core {
            return "e-core".into();
        }
        if *cpus == topo.p_core {
            return "p-core".into();
        }
        if *cpus == topo.hp_core {
            return "hp-core".into();
        }
    }
    cpus.to_range_string()
}

fn status_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    let topo = cfg.as_ref().map(|c| &c.topo);
    let s = stats.unwrap_or(WebStats {
        rules: 0,
        pkgs: 0,
        hit_pkgs: 0,
        threads: 0,
        ebpf: false,
        uptime: 0,
        dropped: 0,
    });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if s.ebpf { "ebpf" } else { "proc" },
        "uptime": s.uptime,
        "rules": s.rules,
        "pkgs": s.pkgs,
        "parse_fail": PARSE_FAILS.load(Ordering::Relaxed),
        "hit_pkgs": s.hit_pkgs,
        "threads": s.threads,
        "dropped": s.dropped,
        "total_procs": sys_procs(),
        "interval": CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        "e_core": topo.map(|t| t.e_core.to_range_string()).unwrap_or_default(),
        "p_core": topo.map(|t| t.p_core.to_range_string()).unwrap_or_default(),
        "hp_core": topo.map(|t| t.hp_core.to_range_string()).unwrap_or_default(),
        "all_core": topo.map(|t| t.present_str.clone()).unwrap_or_default(),
        "cores": topo.map(|t| t.present_cpus.count()).unwrap_or(0),
        "cpuset_enabled": topo.is_some_and(|t| t.cpuset_enabled),
        "topo_source": topo.map(|t| t.topo_source).unwrap_or(""),
        "topo_degraded": topo.is_some_and(|t| t.topo_degraded),
    })
    .to_string()
}

fn rules_json() -> String {
    let Some(cfg) = current_cfg() else {
        return json!({ "rules": [] }).to_string();
    };
    // 规则页每行一个 RT 按钮，状态必须跟规则一起下发，否则要多一次往返
    let per_app = cfg.rt.scope == RtScope::PerApp;
    let mut groups: Vec<serde_json::Value> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for r in &cfg.rules {
        let gi = *index.entry(r.pkg.as_str()).or_insert_with(|| {
            let rt = per_app && cfg.rt.apps.get(&r.pkg).is_some_and(|a| a.enabled);
            groups.push(json!({ "pkg": r.pkg, "items": [], "rt": rt }));
            groups.len() - 1
        });
        groups[gi]["items"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "thread": r.thread, "spec": spec_name(&r.cpus, &cfg.topo) }));
    }
    json!({ "rules": groups, "rt_scope": rt_scope_str(cfg.rt.scope) }).to_string()
}

/// 名称校验
fn token_ok(s: &str, max: usize) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() < max
        && !t.bytes().any(|b| b < 0x20 || b == 0x7f)
        && !t.contains('#')
        && !t.contains("//")
}

fn pkg_shape_ok(pkg: &str) -> bool {
    !(pkg.contains('{') && pkg.ends_with('}'))
}

fn rule_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(pkg), Some(cpus)) = (
        v["pkg"].as_str().map(str::trim),
        v["cpus"].as_str().map(str::trim),
    ) else {
        return err_json(400, "缺少 pkg 或 cpus 字段");
    };
    let thread = v["thread"].as_str().map(str::trim).unwrap_or("");
    let Some(cfg) = current_cfg() else {
        return err_json(500, "配置未就绪");
    };
    if !token_ok(pkg, MAX_PKG_LEN) || (!thread.is_empty() && !token_ok(thread, MAX_THREAD_LEN)) {
        return err_json(400, "名称含有非法字符");
    }
    if thread.is_empty() && !pkg_shape_ok(pkg) {
        return err_json(400, "包名含 { 且以 } 结尾时不支持包级规则，可改用线程规则");
    }
    if cpus.is_empty() || cpus.len() >= 64 || !spec_like(cpus)
        || parse_cpu_spec(cpus, &cfg.topo).count() == 0
    {
        return err_json(400, "无效的 CPU 规格");
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_upsert(&file, pkg, thread, cpus) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

fn rule_del_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(pkg) = v["pkg"].as_str().map(str::trim) else {
        return err_json(400, "缺少 pkg 字段");
    };
    let thread = v["thread"].as_str().map(str::trim).unwrap_or("");

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    let result = if v["all"].as_bool().unwrap_or(false) {
        rule_delete_pkg(&file, pkg)
    } else {
        rule_delete(&file, pkg, thread)
    };
    match result {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "规则不存在"),
        RuleEdit::Conflict => err_json(409, "状态冲突"),
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        RuleEdit::IoErr => err_json(500, "配置文件写入失败"),
    }
}

fn rule_rename_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(old), Some(new)) =
        (v["old"].as_str().map(str::trim), v["new"].as_str().map(str::trim))
    else {
        return err_json(400, "缺少 old 或 new 字段");
    };
    if !token_ok(old, MAX_PKG_LEN) || !token_ok(new, MAX_PKG_LEN) {
        return err_json(400, "名称含有非法字符");
    }
    if !pkg_shape_ok(new) {
        return err_json(400, "包名含 { 且以 } 结尾时不可作为重命名目标");
    }
    if old == new {
        return (200, json!({ "ok": true }).to_string());
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_rename(&file, old, new) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "原包名不存在"),
        RuleEdit::Conflict => err_json(409, "目标包名已存在规则"),
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        RuleEdit::IoErr => err_json(500, "配置文件写入失败"),
    }
}

/// 输入建议
fn suggest_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let q = v["q"].as_str().map(str::trim).unwrap_or("");
    if q.len() > 64 {
        return err_json(400, "q 过长");
    }
    let list: Vec<String> = match v["pkg"].as_str().map(str::trim).filter(|p| !p.is_empty()) {
        None => suggest_pkgs(q).into_iter().map(|(n, _)| n).collect(),
        Some(pkg) => {
            if !token_ok(pkg, MAX_PKG_LEN) {
                return err_json(400, "名称含有非法字符");
            }
            suggest_threads(pkg, q).into_iter().map(|(n, _)| n).collect()
        }
    };
    (200, json!({ "ok": true, "list": list }).to_string())
}

/// 枚举包名
fn installed_pkgs() -> Vec<String> {
    fs::read_dir("/data/data")
        .map(|dirs| {
            dirs.flatten()
                .map(|d| d.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains('.') && !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default()
}

fn for_each_pid(mut f: impl FnMut(i32)) {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                f(pid);
            }
        }
    }
}

/// 排序键
fn rank_top(counts: BTreeMap<String, usize>, lq: &str) -> Vec<(String, usize)> {
    let mut ranked: Vec<(u8, Reverse<usize>, String)> = counts
        .into_iter()
        .filter_map(|(n, c)| {
            let ln = n.to_ascii_lowercase();
            let r = if ln.starts_with(lq) { 0 } else if ln.contains(lq) { 1 } else { 2 };
            (r < 2).then_some((r, Reverse(c), n))
        })
        .collect();
    ranked.sort_unstable();
    ranked.truncate(20);
    ranked.into_iter().map(|(_, Reverse(c), n)| (n, c)).collect()
}

fn suggest_pkgs(q: &str) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> =
        installed_pkgs().into_iter().map(|p| (p, 0)).collect();
    for_each_pid(|pid| {
        if let Some(name) = read_cmdline(pid).filter(|n| n.contains('.')) {
            *counts.entry(name).or_insert(0) += 1;
        }
    });
    rank_top(counts, &q.to_ascii_lowercase())
}

fn thread_comm(pid: i32, tid: i32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid)).ok()?;
    let name = s.trim_end_matches(['\0', '\n']).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn suggest_threads(pkg: &str, q: &str) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for_each_pid(|pid| {
        if read_cmdline(pid).as_deref() == Some(pkg) {
            for tid in task_tids(pid).unwrap_or_default() {
                if let Some(comm) = thread_comm(pid, tid) {
                    *counts.entry(comm).or_insert(0) += 1;
                }
            }
        }
    });
    rank_top(counts, &q.to_ascii_lowercase())
}

fn config_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    let cpuset_enabled = cfg.as_ref().is_some_and(|c| c.topo.cpuset_enabled);
    let unmatched = if cfg.as_ref().is_some_and(|c| c.unmatched_all) { "all" } else { "keep" };
    let scope = cfg.as_ref().map(|c| c.sched_scope).unwrap_or_default();
    // 档位取配置真值而不是运行快照：快照由主循环低频刷新，
    // 刚切档时读到的还是旧值，界面高亮会慢一拍
    let sched_mode = cfg.as_ref().map(|c| c.sched as u8).unwrap_or(0);
    let rules_total = cfg.as_ref().map(|c| c.rules.len()).unwrap_or(0);
    let rt = cfg
        .as_ref()
        .map(|c| c.rt.label())
        .unwrap_or_else(|| "off".to_string());
    let (rt_max, rt_ts) = cfg
        .as_ref()
        .map(|c| (c.rt.max_per_app, c.rt.timeslice_ms))
        .unwrap_or((crate::config::RT_DEFAULT_MAX, crate::config::RT_DEFAULT_TIMESLICE));
    let snap = lock_ignore_poison(&SCHED_SNAPSHOT).clone().unwrap_or_default();
    let s_state = snap.state;
    let s_ticks = snap.ticks;
    let s_would = snap.would;
    let s_moved = snap.moved;
    let s_failed = snap.failed;
    let s_blocked = snap.blocked;
    let s_load = snap.load.to_vec();
    let s_last = snap.last.clone();
    json!({
        "mode": MODE_FORCE.load(Ordering::Relaxed),
        "mode_active": if stats.is_some_and(|s| s.ebpf) { "ebpf" } else { "proc" },
        "ebpf_available": ebpf_probe(),
        "interval": CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        "cpuset_name": base_cpuset().rsplit('/').next().unwrap_or_default(),
        "config_file": lock_ignore_poison(&CONFIG_FILE).clone(),
        "cpuset_enabled": cpuset_enabled,
        "unmatched": unmatched,
        "cluster_levels": scope.levels,
        "cross_rules": scope.rules,
        "cross_pkgs": scope.pkgs,
        "rules_total": rules_total,
        "rt": rt,
        "rt_max": rt_max,
        "rt_timeslice": rt_ts,
        "sched_mode": sched_mode,
        "sched_state": s_state,
        "sched_ticks": s_ticks,
        "sched_would": s_would,
        "sched_moved": s_moved,
        "sched_failed": s_failed,
        "sched_blocked": s_blocked,
        "sched_load": s_load,
        "sched_last": s_last,
        "sched_skip": snap.skip.to_vec(),
        "sched_skip_labels": crate::sched::SKIP_LABELS.to_vec(),
        "sched_bounced": snap.bounced,
        "sched_frozen": snap.frozen,
    })
    .to_string()
}

/// 诊断面板数据。线程表取自主循环每 5 秒发布一次的快照，
/// 因此这里的 `actual` 最多滞后 5 秒，够用来发现「一直没绑上」
fn diag_json() -> String {
    let d = diag::snapshot();
    let snap = lock_ignore_poison(&SCHED_SNAPSHOT).clone().unwrap_or_default();
    let threads: Vec<Value> = d
        .threads
        .iter()
        .map(|t| {
            json!({
                "tid": t.tid,
                "pkg": t.pkg,
                "comm": t.comm,
                "expect": t.expect,
                "actual": t.actual,
                "ok": t.ok,
                "role": t.role,
            })
        })
        .collect();
    let jank: Vec<Value> = d
        .jank
        .iter()
        .map(|j| {
            json!({
                "tid": j.tid,
                "comm": j.comm,
                "wait_ms": (j.wait_ms * 10.0).round() / 10.0,
                "switches": j.switches,
            })
        })
        .collect();
    json!({
        "affinity": {
            "calls": d.aff.calls,
            "writes": d.aff.writes,
            "noop": d.aff.noop,
            "gone": d.aff.gone,
            "failed": d.aff.failed,
            "eperm": d.aff.eperm,
            "einval": d.aff.einval,
            "enosys": d.aff.enosys,
            "other": d.aff.other,
            "cpuset_fail": d.aff.cpuset_fail,
            "rule": d.aff.rule,
            "sync": d.aff.sync,
            "sched": d.aff.sched,
            "line": diag::affinity_line(&d.aff),
            "errno_line": d.aff.errno_line(),
        },
        "s7": {
            "mode": snap.mode,
            "state": snap.state,
            "skip": snap.skip.to_vec(),
            "skip_labels": crate::sched::SKIP_LABELS.to_vec(),
            "bounced": snap.bounced,
            "frozen": snap.frozen,
            "moved": snap.moved,
            "failed": snap.failed,
            "blocked": snap.blocked,
        },
        "jank": jank,
        "pressure": d.pressure,
        "threads": threads,
        "events": d.events,
    })
    .to_string()
}

fn rt_scope_str(s: RtScope) -> &'static str {
    match s {
        RtScope::Off => "off",
        RtScope::Global => "global",
        RtScope::PerApp => "per_app",
    }
}

fn rt_match_parts(m: &RtMatch) -> (&'static str, Vec<String>) {
    match m {
        RtMatch::Auto => ("auto", Vec::new()),
        RtMatch::Names(v) => ("names", v.clone()),
    }
}

/// RT 配置 + 运行期状态。配置回答「谁有资格」，threads 回答「当前实际提升了谁」，
/// 两者分开才能看出配置了但没生效的情况
fn rt_json() -> String {
    let cfg = current_cfg();
    let snap = rt::snapshot();
    let mut mode = "off";
    let mut max = crate::config::RT_DEFAULT_MAX;
    let mut ts = crate::config::RT_DEFAULT_TIMESLICE;
    let mut apps: Vec<Value> = Vec::new();

    if let Some(c) = &cfg {
        mode = rt_scope_str(c.rt.scope);
        max = c.rt.max_per_app;
        ts = c.rt.timeslice_ms;
        let mut pkgs: Vec<&String> = c.rt.apps.keys().collect();
        pkgs.sort();
        for p in pkgs {
            let a = &c.rt.apps[p];
            let (m, pat) = rt_match_parts(&a.mode);
            apps.push(json!({
                "pkg": p,
                "enabled": a.enabled,
                "mode": m,
                "patterns": pat,
                "max": a.max_threads,
            }));
        }
    }

    let threads: Vec<Value> = snap
        .threads
        .iter()
        .map(|(pkg, tid, comm)| json!({ "pkg": pkg, "tid": tid, "comm": comm }))
        .collect();

    json!({
        "mode": mode,
        "max": max,
        "timeslice": ts,
        "timeslice_current": snap.timeslice_current,
        "timeslice_applied": snap.timeslice_applied,
        "gate_open": snap.enabled,
        "demoted": snap.demoted,
        "apps": apps,
        "threads": threads,
        "default_max": crate::config::RT_DEFAULT_MAX,
        "default_timeslice": crate::config::RT_DEFAULT_TIMESLICE,
    })
    .to_string()
}

/// 切换全局 RT 模式，可同时改每应用上限与时间片
fn rt_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(mode) = v["mode"].as_str() else {
        return err_json(400, "缺少 mode 字段");
    };
    if !matches!(mode, "off" | "global" | "per_app") {
        return err_json(400, "无效的 RT 模式");
    }
    let max = match v["max"].as_u64() {
        Some(n) if (1..=8).contains(&n) => Some(n as u8),
        Some(_) => return err_json(400, "每应用上限需在 1-8 之间"),
        None => None,
    };
    let ts = match v["timeslice"].as_u64() {
        Some(n) if (1..=100).contains(&n) => Some(n as u32),
        Some(_) => return err_json(400, "时间片需在 1-100 ms 之间"),
        None => None,
    };

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rt_configure(&file, mode, max, ts) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

/// 单个应用的 RT 开关与规则。关闭等同于删除该条目，保持配置文件干净
fn rt_app_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(pkg) = v["pkg"].as_str().map(str::trim) else {
        return err_json(400, "缺少 pkg 字段");
    };
    // 空白会破坏 `@rt.app=<包名> <模式>` 的分词
    if !token_ok(pkg, MAX_PKG_LEN) || pkg.chars().any(char::is_whitespace) {
        return err_json(400, "包名含有非法字符");
    }

    // 整条替换语义：未提供的字段取默认值。前端始终回传当前行，
    // 因此「关闭」会写成 `off <原模式> <原上限>`，再打开不必重填
    let enabled = v["enabled"].as_bool().unwrap_or(true);
    let has_mode = v["mode"].is_string();
    let spec = if v["delete"].as_bool().unwrap_or(false) {
        // 空 spec 即删除条目，与 rt_app_set 的约定一致
        String::new()
    } else if !enabled && !has_mode {
        "off".to_string()
    } else {
        let part = match v["mode"].as_str().unwrap_or("auto") {
            "auto" => "auto".to_string(),
            "names" => {
                let pats: Vec<String> = v["patterns"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                if pats.is_empty() {
                    return err_json(400, "names 模式需要至少一个线程名");
                }
                // 逗号是条目内的分隔符，单个模式里出现会破坏语法
                if pats.iter().any(|p| {
                    !token_ok(p, MAX_THREAD_LEN)
                        || p.contains(',')
                        || p.chars().any(char::is_whitespace)
                }) {
                    return err_json(400, "线程名含有非法字符");
                }
                format!("names:{}", pats.join(","))
            }
            _ => return err_json(400, "无效的匹配方式"),
        };
        let max = match v["max"].as_u64() {
            Some(n) if (1..=8).contains(&n) => n,
            Some(_) => return err_json(400, "每应用上限需在 1-8 之间"),
            None => 0,
        };
        let state = if enabled { "on" } else { "off" };
        if max == 0 {
            format!("{} {}", state, part)
        } else {
            format!("{} {} {}", state, part, max)
        }
    };

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rt_app_set(&file, pkg, &spec) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

/// 规则页的「一键 RT」：只传包名与开关，参数取缺省（auto / 2 线程 / 3 ms）。
/// 设置页不再暴露细项，需要手工调参时直接改配置文件
fn rt_toggle_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(pkg) = v["pkg"].as_str().map(str::trim) else {
        return err_json(400, "缺少 pkg 字段");
    };
    if !token_ok(pkg, MAX_PKG_LEN) || pkg.chars().any(char::is_whitespace) {
        return err_json(400, "包名含有非法字符");
    }
    let enabled = v["enabled"].as_bool().unwrap_or(true);

    // global 模式下所有应用都在 RT，单个包的开关没有意义，
    // 直接改写成 per_app 会静默改变其它应用的行为，因此要求先显式切模式
    if current_cfg().is_some_and(|c| c.rt.scope == RtScope::Global) {
        return err_json(
            409,
            "当前为「全部应用」模式，请先在设置中切到「按规则开启」",
        );
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rt_toggle(&file, pkg, enabled) {
        RuleEdit::Ok => {
            config_reload_now();
            (
                200,
                json!({ "ok": true, "pkg": pkg, "enabled": enabled }).to_string(),
            )
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

/// S7 三档开关，只写 `@sched=`，不牵动其它键
fn sched_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(mode) = v["mode"].as_str() else {
        return err_json(400, "缺少 mode 字段");
    };
    if !matches!(mode, "off" | "shadow" | "on") {
        return err_json(400, "无效的 S7 模式");
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match sched_set(&file, mode) {
        RuleEdit::Ok => {
            config_reload_now();
            // 单核心层机型开 on 不会生效。写盘照做，但把结论回传，
            // 免得用户以为已经在优化，实际一直在走「不适用」分支
            let levels = current_cfg().map(|c| c.sched_scope.levels).unwrap_or(0);
            let inactive = mode == "on" && levels < 2;
            (
                200,
                json!({ "ok": true, "levels": levels, "inactive": inactive }).to_string(),
            )
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

/// 进阶参数：`@unmatched`、`@rt.max`、`@rt.timeslice`。三项都可选，
/// 但不带的项保持原值不动，一项都不带直接拒绝，避免空写一次文件
fn adv_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let unmatched = match v["unmatched"].as_str() {
        Some("keep") => Some("keep"),
        Some("all") => Some("all"),
        Some(_) => return err_json(400, "unmatched 只能是 keep 或 all"),
        None => None,
    };
    let rt_max = match v["rt_max"].as_u64() {
        Some(n) if (1..=RT_MAX_LIMIT as u64).contains(&n) => Some(n as u8),
        Some(_) => {
            return err_json(400, &format!("每应用上限需在 1-{} 之间", RT_MAX_LIMIT));
        }
        None => None,
    };
    let rt_ts = match v["rt_timeslice"].as_u64() {
        Some(n) if (1..=RT_TIMESLICE_LIMIT as u64).contains(&n) => Some(n as u32),
        Some(_) => {
            return err_json(
                400,
                &format!("RR 时间片需在 1-{} ms 之间", RT_TIMESLICE_LIMIT),
            );
        }
        None => None,
    };
    if unmatched.is_none() && rt_max.is_none() && rt_ts.is_none() {
        return err_json(400, "没有要修改的项");
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match adv_configure(&file, unmatched, rt_max, rt_ts) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

fn config_set_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let mode = v["mode"].as_u64();
    let interval = v["interval"].as_u64();
    let name = v["cpuset_name"].as_str();
    let path = v["config_file"].as_str();

    if mode.is_some_and(|m| m > 2) {
        return err_json(400, "无效的工作模式");
    }
    if interval.is_some_and(|n| !(1..=3600).contains(&n)) {
        return err_json(400, "间隔需在 1-3600 秒之间");
    }
    if name.is_some_and(|n| !valid_name(n)) {
        return err_json(400, "无效的 cpuset 目录名");
    }
    if path.is_some_and(|p| !valid_path(p) || !path_allowed(p)) {
        return err_json(400, "无效的配置文件路径");
    }

    if let Some(m) = mode {
        MODE_FORCE.store(m as u8, Ordering::Relaxed);
        // 用户主动切回 eBPF 方向时清除放弃标记允许重试
        if m != 2 {
            EBPF_GAVE_UP.store(false, Ordering::Relaxed);
        }
    }
    if let Some(n) = interval {
        CHECK_INTERVAL.store(n, Ordering::Relaxed);
    }
    if let Some(n) = name {
        crate::cpuset::set_base_cpuset(n);
        // 目录全部换到新 base 下，旧的“已建”记录必须作废
        reset_cpuset_dir_cache();
        if let Some(cfg) = current_cfg()
            && cfg.topo.cpuset_enabled {
                create_cpuset_dir(&base_cpuset(), &cfg.topo.present_str, &cfg.topo.mems_str);
            }
        FORCE_RELOAD.store(true, Ordering::Release);
    }
    if let Some(p) = path {
        if std::fs::metadata(p).is_err()
            && let Err(e) = create_config_file(p)
        {
            eprintln!("Web: 创建配置文件 {} 失败: {}", p, e);
            return err_json(400, "配置文件无法创建");
        }
        *lock_ignore_poison(&CONFIG_FILE) = p.to_string();
        FORCE_RELOAD.store(true, Ordering::Release);
    }

    settings_save();
    (200, json!({ "ok": true }).to_string())
}

pub const SETTINGS_FILE: &str = "./AppOpt.json";

static SAVE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub struct Settings {
    pub web_enable: bool,
    pub mode: u8,
    pub check_interval: u64,
    pub cpuset_name: String,
    pub config_file: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            web_enable: false,
            mode: 0,
            check_interval: 2,
            cpuset_name: DEFAULT_CPUSET_NAME.to_string(),
            config_file: "./applist.conf".to_string(),
        }
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() < 64 && !s.contains('/') && !s.bytes().any(|b| b <= b' ')
}

fn valid_path(s: &str) -> bool {
    !s.is_empty() && s.len() < 256 && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// 新建配置文件时写入的初始内容
const CONFIG_HEADER: &str = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";

/// Web 端只能把配置文件指到固定白名单目录内，避免 root 权限下被诱导写入任意路径。
/// 目录白名单：模块（可执行文件）目录、当前配置所在目录、/data/adb、/data/local/tmp、/sdcard。
/// 路径先拒绝 `..` 组件，再规范化父目录后比较前缀；最终目标本身是符号链接时直接拒绝，
/// 否则按路径打开会跟随链接落到白名单之外。真正的写入由 create_config_file 用 openat 兜底。
fn path_allowed(p: &str) -> bool {
    use std::path::{Component, Path, PathBuf};

    let path = Path::new(p);
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(dir) = fs::canonicalize(parent) else {
        return false;
    };
    // 已存在的路径：符号链接（含指向白名单内部的）一律不接，避免被换链绕过；
    // 普通文件再规范化一次，确认它确实落在白名单目录下
    if let Ok(md) = fs::symlink_metadata(path)
        && (md.file_type().is_symlink() || fs::canonicalize(path).is_err())
    {
        return false;
    }

    let mut roots: Vec<PathBuf> = vec![
        PathBuf::from("/data/adb"),
        PathBuf::from("/data/local/tmp"),
        PathBuf::from("/sdcard"),
    ];
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    {
        roots.push(exe_dir);
    }
    // 当前配置可能写成相对路径（如 ./applist.conf），此时以工作目录为准
    let cur = lock_ignore_poison(&CONFIG_FILE).clone();
    if let Some(dir) = Path::new(&cur)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::current_dir().ok())
    {
        roots.push(dir);
    }

    roots.iter().any(|root| {
        fs::canonicalize(root)
            .map(|root| dir.starts_with(&root))
            .unwrap_or(false)
    })
}

/// 在白名单目录内新建配置文件。
/// 字符串校验与实际创建之间存在窗口，因此这里用父目录句柄 + openat 打开：
/// O_NOFOLLOW 拒绝最终名是符号链接，O_EXCL 拒绝覆盖已存在文件，两者都不跟随链接。
fn create_config_file(path: &str) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let p = std::path::Path::new(path);
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let parent = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let dir = fs::File::open(parent)?;
    let cname = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    f.write_all(CONFIG_HEADER.as_bytes())?;
    f.sync_all()
}

impl Settings {
    fn from_json(v: &Value) -> Self {
        let d = Settings::default();
        Self {
            web_enable: v["web_enable"].as_bool().unwrap_or(d.web_enable),
            mode: v["mode"].as_u64().unwrap_or(d.mode as u64).min(2) as u8,
            check_interval: v["check_interval"]
                .as_u64()
                .unwrap_or(d.check_interval)
                .clamp(1, 3600),
            cpuset_name: v["cpuset_name"]
                .as_str()
                .filter(|s| valid_name(s))
                .unwrap_or(&d.cpuset_name)
                .to_string(),
            config_file: v["config_file"]
                .as_str()
                .filter(|s| valid_path(s))
                .unwrap_or(&d.config_file)
                .to_string(),
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "web_enable": self.web_enable,
            "mode": self.mode,
            "check_interval": self.check_interval,
            "cpuset_name": self.cpuset_name,
            "config_file": self.config_file,
        })
    }

    fn save(&self, path: &str) {
        let _guard = lock_ignore_poison(&SAVE_LOCK);
        let json = serde_json::to_string_pretty(&self.to_value()).unwrap_or_default();
        let tmp = format!("{}.tmp", path);
        let res = fs::File::create(&tmp)
            .and_then(|mut f| {
                f.write_all(format!("{}\n", json).as_bytes())?;
                f.sync_all()
            })
            .and_then(|_| fs::rename(&tmp, path));
        if let Err(e) = res {
            eprintln!("警告: 设置写入 {} 失败: {}", path, e);
        }
    }
}

pub fn settings_load(path: &str) -> Settings {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => Settings::from_json(&v),
            Err(e) => {
                eprintln!("警告: {} 已损坏({})，使用默认设置", path, e);
                Settings::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let d = Settings::default();
            d.save(path);
            println!("设置文件不存在，已写入默认设置: {}", path);
            d
        }
        Err(e) => {
            eprintln!("警告: 读取 {} 失败({})，使用默认设置", path, e);
            Settings::default()
        }
    }
}

pub fn settings_save() {
    Settings {
        web_enable: WEB_ENABLED.load(Ordering::Relaxed),
        mode: MODE_FORCE.load(Ordering::Relaxed),
        check_interval: CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        cpuset_name: base_cpuset().rsplit('/').next().unwrap_or_default().to_string(),
        config_file: lock_ignore_poison(&CONFIG_FILE).clone(),
    }
    .save(SETTINGS_FILE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webui_origin_is_accepted() {
        assert!(origin_allowed("https://mui.kernelsu.org"));
        assert!(origin_allowed("http://localhost:8080"));
        assert!(origin_allowed("http://127.0.0.1:5000"));
    }

    #[test]
    fn foreign_origin_is_rejected() {
        assert!(!origin_allowed("https://evil.example"));
        // 前缀相似但域名不同，不能被 starts_with 放行
        assert!(!origin_allowed("https://mui.kernelsu.org.evil.example"));
        assert!(!origin_allowed("http://127.0.0.1.evil.example"));
        assert!(!origin_allowed(""));
    }

    fn exe_dir() -> std::path::PathBuf {
        std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    #[test]
    fn path_inside_module_dir_is_allowed() {
        let p = exe_dir().join("rules.conf");
        assert!(path_allowed(p.to_str().unwrap()));
    }

    #[test]
    fn path_outside_whitelist_is_rejected() {
        assert!(!path_allowed("/etc/passwd"));
        assert!(!path_allowed("/proc/sys/kernel/core_pattern"));
        assert!(!path_allowed("/root/.ssh/authorized_keys"));
    }

    #[test]
    fn parent_dir_component_is_rejected() {
        let p = format!("{}/../escape.conf", exe_dir().display());
        assert!(!path_allowed(&p));
        assert!(!path_allowed("../applist.conf"));
    }

    #[test]
    fn symlink_escape_is_rejected() {
        let link = exe_dir().join("escape_link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        let p = link.join("evil.conf");
        assert!(!path_allowed(p.to_str().unwrap()));
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn nonexistent_parent_is_rejected() {
        assert!(!path_allowed("/data/adb/not_exist_dir/x.conf"));
    }

    /// 测试专用文件名，带进程号避免并行用例互相删除
    fn tmp_name(tag: &str) -> String {
        format!(
            "{}/appopt_test_{}_{}.conf",
            exe_dir().display(),
            tag,
            std::process::id()
        )
    }

    #[test]
    fn target_file_symlink_is_rejected() {
        let link = tmp_name("link_out");
        let victim = format!("/tmp/appopt_victim_{}", std::process::id());
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&victim);
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        // 父目录在白名单内，但最终目标是外部文件的符号链接
        assert!(!path_allowed(&link));
        // 即使直接调用创建逻辑也必须拒绝，且不能动到链接指向的文件
        assert!(create_config_file(&link).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&victim);
    }

    #[test]
    fn dangling_symlink_is_rejected() {
        let link = tmp_name("link_dangling");
        let victim = format!("/tmp/appopt_missing_{}", std::process::id());
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&victim);
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(!path_allowed(&link));
        assert!(create_config_file(&link).is_err());
        assert!(!std::path::Path::new(&victim).exists());
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn parent_symlink_inside_whitelist_is_accepted() {
        let dir = format!("{}/appopt_dir_{}", exe_dir().display(), std::process::id());
        let link = format!("{}/appopt_dir_link_{}", exe_dir().display(), std::process::id());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let p = format!("{}/rules.conf", link);
        assert!(path_allowed(&p));
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_config_file_is_exclusive() {
        let p = tmp_name("create");
        let _ = std::fs::remove_file(&p);
        create_config_file(&p).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), CONFIG_HEADER);
        // 已存在时不得截断
        assert!(create_config_file(&p).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), CONFIG_HEADER);
        let _ = std::fs::remove_file(&p);
    }
}
