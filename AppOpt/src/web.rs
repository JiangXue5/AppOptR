use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::apply_affinity::{read_cmdline, reset_cpuset_dir_cache, task_tids};
use crate::cache::ProcCache;
use crate::config::{
    CHECK_INTERVAL, CONFIG_FILE, CURRENT_CONFIG, FORCE_RELOAD, PARSE_FAILS, RT_MAX_LIMIT,
    RT_TIMESLICE_LIMIT, config_reload_now, parse_fail_lines, spec_like,
};
use crate::config::{RtMatch, RtScope};
use crate::cpuset::{
    CpuSet, CpuTopology, DEFAULT_CPUSET_NAME, base_cpuset, create_cpuset_dir, parse_cpu_spec,
};
use crate::diag;
use crate::ebpf_mode::ebpf_probe;
use crate::rt;
use crate::rule_edit::{
    BehaviorKey, RuleEdit, adv_configure, behavior_set, rt_app_set, rt_configure, rt_toggle,
    rule_delete, rule_delete_pkg, rule_rename, rule_upsert, sched_set,
};
use crate::sched::SCHED_SNAPSHOT;
use crate::{EBPF_GAVE_UP, MAX_PKG_LEN, MAX_THREAD_LEN, lock_ignore_poison};

pub const WEB_PORT: u16 = 8889;
const INDEX_HTML: &str = include_str!("../../web/index.html");

/// 令牌文件名，与可执行文件同目录（service.sh 会把工作目录切到模块目录）
pub const TOKEN_NAME: &str = "web.token";

/// 单连接并发上限。每个连接一个线程，慢速连接不设上限时可以耗光线程。
/// 浏览器对同一源最多 6 条长连接，留出余量即可
const MAX_CONNS: usize = 32;
/// 请求头单行上限。必须在读入过程中就截断，读完再查等于没查
const MAX_HEAD_LINE: usize = 8192;
/// 整个请求头上限
const MAX_HEAD_TOTAL: usize = 16384;

static ACTIVE_CONNS: AtomicUsize = AtomicUsize::new(0);

/// Web API 的访问令牌。8889 只监听回环，但「能连回环」不等于「是用户本人」：
/// 任何带 INTERNET 权限的本地应用都能直连，Host/Origin 校验对它们完全无效，
/// 而守护进程是 root，替它办事就是提权。令牌由守护进程生成、以 0600 写入
/// 模块目录，普通应用读不到；前端从 fragment 或 KernelSU WebUI 的 root shell 取得
static WEB_TOKEN: Mutex<String> = Mutex::new(String::new());

pub static MODE_FORCE: AtomicU8 = AtomicU8::new(0);
pub static WEB_ENABLED: AtomicBool = AtomicBool::new(false);

pub static WEB_STATS: Mutex<Option<WebStats>> = Mutex::new(None);

/// 本次启动是首次运行（设置文件不存在、刚写入默认值）。由 main 在启动行
/// 之后打一行说明——放在 settings_load 里会跑到启动行前面
pub static SETTINGS_FRESH: AtomicBool = AtomicBool::new(false);

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
    /// 三簇（e/p/hp）实时占用百分比，-1 = 尚未建立基线
    pub load: [i8; 3],
}

/// 缓存统计
pub fn cache_stats(cache: &ProcCache) -> (usize, usize) {
    let pkgs: HashSet<&str> = cache.tasks.values().map(|e| e.pkg.as_str()).collect();
    (cache.tasks.len(), pkgs.len())
}

fn token_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(TOKEN_NAME)))
        .unwrap_or_else(|| std::path::PathBuf::from(TOKEN_NAME))
}

fn random_token() -> String {
    let mut buf = [0u8; 16];
    match fs::File::open("/dev/urandom") {
        Ok(mut f) => {
            if f.read_exact(&mut buf).is_err() {
                return String::new();
            }
        }
        Err(_) => return String::new(),
    }
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn token_shape_ok(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn token_js(tok: &str) -> String {
    format!("window.__APPOPT_TOKEN=\"{}\";\n", tok)
}

/// 把令牌发布成模块 `webroot/token.js`，供 KernelSU / APatch 的 WebUI 同源读取。
///
/// WebUI 用 WebViewAssetLoader 把页面映射到模块的 webroot 目录，页面里的
/// `fetch('token.js')` 走的是加载器而不是 8889，因此能拿到这份文件；浏览器直连
/// 8889 时没有这条路由，仍走日志里的链接或手动粘贴。文件落在 /data/adb 下，
/// 普通应用读不到，不削弱认证。
///
/// 写不进去只是少一条自动路径，不阻止启动——ksu.exec 与手动输入仍然可用
fn publish_webroot_token(tok: &str) {
    use std::io::Write as _;
    use std::os::fd::{AsRawFd, FromRawFd};

    let Some(webroot) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("webroot")))
        .filter(|d| d.is_dir())
    else {
        return;
    };
    let path = webroot.join("token.js");
    let Ok(name) = std::ffi::CString::new(path.as_os_str().to_string_lossy().as_bytes()) else {
        return;
    };
    // O_NOFOLLOW：预先放一个同名链接不能把令牌写到模块目录之外
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return;
    }
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    let _ = f.write_all(token_js(tok).as_bytes());
    let _ = f.sync_all();
    unsafe { libc::fchmod(f.as_raw_fd(), 0o600) };
}

/// 读取或生成令牌。已存在且格式正确时沿用，重启后前端不必重输。
/// 写不进去（只读挂载、权限损坏）返回空串，调用方必须据此拒绝启动 Web——
/// 没有令牌就等于没有认证，宁可不开也不留一个 root 的后门
fn token_load_or_create() -> String {
    use std::io::Write as _;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    let path = token_path();
    if let Ok(s) = fs::read_to_string(&path) {
        let t = s.trim().to_ascii_lowercase();
        // 属主不是 root 或同组/其他可读时，这份令牌可能早被别人看过，重新生成
        let trusted = fs::metadata(&path)
            .map(|m| m.uid() == 0 && m.mode() & 0o077 == 0)
            .unwrap_or(false);
        if token_shape_ok(&t) && trusted {
            return t;
        }
    }
    let tok = random_token();
    if !token_shape_ok(&tok) {
        crate::diag::tag("失败", "Web 无法生成随机令牌，拒绝启动");
        return String::new();
    }
    let name = match std::ffi::CString::new(path.as_os_str().to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    // O_NOFOLLOW：预先放一个指向别处的同名链接不能把令牌写到白名单外
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        crate::diag::tag(
            "失败",
            &format!(
                "Web 创建令牌文件 {} 失败（{}）",
                path.display(),
                std::io::Error::last_os_error()
            ),
        );
        return String::new();
    }
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    let ok = f.write_all(format!("{}\n", tok).as_bytes()).is_ok() && f.sync_all().is_ok();
    // 已存在文件的权限位不受 open 的 mode 影响，这里显式收紧
    unsafe {
        libc::fchmod(f.as_raw_fd(), 0o600);
    }
    if !ok {
        crate::diag::tag("失败", "Web 写入令牌文件失败");
        return String::new();
    }
    crate::diag::tag(
        "组件",
        &format!("Web 令牌已写入 {}（0600）", path.display()),
    );
    tok
}

/// 常量时间比较，避免按字节提前返回泄露前缀
fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn token_match(got: &str) -> bool {
    let want = lock_ignore_poison(&WEB_TOKEN);
    !want.is_empty() && token_eq(got, &want)
}

/// 启动 web 前端，监听成功返回 true
pub fn web_start() -> bool {
    let listener = match TcpListener::bind(("127.0.0.1", WEB_PORT)) {
        Ok(l) => l,
        Err(e) => {
            crate::diag::tag(
                "失败",
                &format!(
                    "Web 监听 127.0.0.1:{} 失败（{}），端口可能被占用",
                    WEB_PORT, e
                ),
            );
            return false;
        }
    };
    let tok = token_load_or_create();
    if tok.is_empty() {
        crate::diag::tag(
            "失败",
            "Web 没有可用令牌，拒绝启动（避免出现无认证的 root 接口）",
        );
        return false;
    }
    publish_webroot_token(&tok);
    *lock_ignore_poison(&WEB_TOKEN) = tok;
    WEB_ENABLED.store(true, Ordering::Release);
    // 令牌绝不进日志。日志会被整段贴出去求助，一次泄露就等于把 root 接口的
    // 永久通行证公开（令牌只有删掉 web.token 才会更换）。前端本来就能从
    // 同源 token.js 与 KSU 的 ksu.exec 自动取到，不需要用户手抄
    crate::diag::tag(
        "组件",
        &format!(
            "Web 就绪 http://127.0.0.1:{}/ ｜ 令牌文件 {}（0600，前端自动读取；日志不打印令牌）",
            WEB_PORT,
            token_path().display()
        ),
    );
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if ACTIVE_CONNS.fetch_add(1, Ordering::AcqRel) >= MAX_CONNS {
                ACTIVE_CONNS.fetch_sub(1, Ordering::AcqRel);
                // 不排队也不回响应，直接断：慢速连接宁可被拒也不吃线程
                drop(stream);
                continue;
            }
            thread::spawn(move || {
                conn_handle(stream);
                ACTIVE_CONNS.fetch_sub(1, Ordering::AcqRel);
            });
        }
    });
    true
}

struct Request {
    method: String,
    path: String,
    host: String,
    origin: String,
    content_type: String,
    token: String,
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

/// 有界读一行。`read_until` 会先把整行读进内存再返回，8192 的上限放在
/// 读完之后等于没有——5 秒窗口内往连接里灌数据就能把 root 进程撑爆。
/// 这里逐块取缓冲，超过上限立即失败，内存占用与对端行为无关
fn read_head_line(
    reader: &mut BufReader<TcpStream>,
    out: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<bool> {
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(false);
        }
        let (chunk, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (&buf[..=i], true),
            None => (buf, false),
        };
        if out.len() + chunk.len() > max {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        out.extend_from_slice(chunk);
        let n = chunk.len();
        reader.consume(n);
        if done {
            return Ok(true);
        }
    }
}

fn request_read(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut head = Vec::with_capacity(512);
    let mut line = Vec::with_capacity(128);
    loop {
        line.clear();
        if !read_head_line(reader, &mut line, MAX_HEAD_LINE).ok()? {
            return None;
        }
        if line.is_empty() {
            return None;
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if head.len() + line.len() > MAX_HEAD_TOTAL {
            return None;
        }
        head.extend_from_slice(&line);
    }

    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.split('?').next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let (mut host, mut origin, mut ctype, mut token, mut len) = (
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        0usize,
    );
    let mut conn = String::new();
    for h in lines {
        let Some((k, v)) = h.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "host" => host = v.to_ascii_lowercase(),
            "origin" => origin = v.to_ascii_lowercase(),
            "content-type" => ctype = v.to_ascii_lowercase(),
            "x-appopt-token" => token = v.to_ascii_lowercase(),
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
        content_type: ctype,
        token,
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
        401 => "Unauthorized",
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
            "Access-Control-Allow-Origin: {}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-AppOpt-Token\r\nAccess-Control-Allow-Private-Network: true\r\n",
            o
        ));
    }
    head.push_str("\r\n");
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(body);
    let _ = out.flush();
}

/// 请求来源判定。抽成纯函数，便于覆盖「不带 Sec-Fetch-Site 的客户端」这类边界。
///
/// 曾经用 `Sec-Fetch-Site` 作为同源依据：不带该头就算同源。这个头是客户端自己
/// 填的，curl 只要不填、再带一个恶意 Origin 就能写配置，比浏览器更容易通过。
/// 现在只认两件事——Origin 为空（本机工具），或命中白名单（回环与 KernelSU
/// WebUI 容器）。`Origin: null` 来自沙箱 iframe 与 file:// 页面，任何网页都能
/// 造出这个值，不再放行。其余一律 403。
///
/// 这一层只挡浏览器跨站与 DNS 重绑定；本地应用的直连由 API 令牌负责，
/// 两者缺一不可
fn origin_ok(host: &str, origin: &str, method: &str, ctype: &str) -> bool {
    let host_ok = matches!(host, "127.0.0.1" | "localhost");
    host_ok
        && (origin.is_empty() || origin_allowed(origin))
        && (method != "POST" || ctype.starts_with("application/json"))
}

fn dispatch(out: &mut TcpStream, req: &Request) {
    let port_str = format!(":{}", WEB_PORT);
    let host = req
        .host
        .strip_suffix(&port_str)
        .unwrap_or(req.host.as_str());
    let host_ok = matches!(host, "127.0.0.1" | "localhost");
    let cross_webui = origin_allowed(&req.origin);
    let cors = cross_webui.then_some(req.origin.as_str());
    let allowed = origin_ok(host, &req.origin, req.method.as_str(), &req.content_type);

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

    if !allowed {
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

    // 页面本身放行：前端要靠它把令牌输入框和提示渲染出来。
    // 所有 /api/* 一律要求令牌——读接口能枚举已装包名与线程名，
    // 同样属于隐私泄露，不能只保护写接口
    if req.path.starts_with("/api/") && !token_match(&req.token) {
        resp_send(
            out,
            401,
            "application/json",
            b"{\"ok\":false,\"err\":\"\\u9700\\u8981\\u8bbf\\u95ee\\u4ee4\\u724c\",\"need_token\":true}",
            true,
            cors,
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
        ("GET", "/api/candidates") => (200, candidates_json()),
        ("POST", "/api/rule") => rule_api(req),
        ("POST", "/api/rule/del") => rule_del_api(req),
        ("POST", "/api/rule/rename") => rule_rename_api(req),
        ("POST", "/api/config") => config_set_api(req),
        ("POST", "/api/rt") => rt_api(req),
        ("POST", "/api/rt/app") => rt_app_api(req),
        ("POST", "/api/rt/toggle") => rt_toggle_api(req),
        ("POST", "/api/sched") => sched_api(req),
        ("POST", "/api/behavior") => behavior_api(req),
        ("POST", "/api/adv") => adv_api(req),
        ("POST", "/api/suggest") => suggest_api(req),
        ("POST", "/api/candidate/accept") => candidate_accept_api(req),
        ("POST", "/api/candidate/del") => candidate_del_api(req),
        _ => err_json(404, "not found"),
    };
    resp_send(
        out,
        status,
        "application/json",
        body.as_bytes(),
        !req.keep_alive,
        cors,
    );
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
        load: [-1; 3],
    });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if s.ebpf { "ebpf" } else { "proc" },
        "uptime": s.uptime,
        "rules": s.rules,
        "pkgs": s.pkgs,
        "parse_fail": PARSE_FAILS.load(Ordering::Relaxed),
        // 只给前三条：状态页是一行横幅，再多也读不完，完整信息在诊断面板
        "parse_fail_lines": parse_fail_lines()
            .into_iter()
            .take(3)
            .map(|(no, text)| json!({ "line": no, "text": text }))
            .collect::<Vec<_>>(),
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
        // 三簇实时占用，前端拿它画核带；-1 表示还没测出来
        "load": s.load,
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
            groups.push(json!({
                "pkg": r.pkg,
                "items": [],
                "rt": rt,
                // 名单标记随规则一起下发，用户不用去配置文件里核对
                // 这个包为什么「有规则但没生效」
                "bl": cfg.is_blacklisted(&r.pkg),
                "ex": cfg.is_exempt(&r.pkg),
            }));
            groups.len() - 1
        });
        groups[gi]["items"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "thread": r.thread, "spec": spec_name(&r.cpus, &cfg.topo) }));
    }
    json!({ "rules": groups, "rt_scope": rt_scope_str(cfg.rt.scope) }).to_string()
}

/// 名称校验。这里写进的是配置文件，正常包名只有字母数字与点，线程名多几个
/// `-_.:@+*`；shell 元字符一个都不需要，全部拒绝。
///
/// 之前只拦 `#`、`//` 与控制字符，`x;sh a.sh;y` 这种包名能原样落进配置。
/// 配置文件本身不被 shell 执行，但曾经的 config_file 白名单允许把它指到
/// `post-fs-data.sh`，注入串就成了 root 持久化路径。两道一起收紧才安全
fn token_ok(s: &str, max: usize) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() < max
        && !t.bytes().any(|b| b < 0x20 || b == 0x7f)
        && !t.contains('#')
        && !t.contains("//")
        && !t.contains("..")
        && !t.bytes().any(|b| {
            matches!(
                b,
                b';' | b'$' | b'`' | b'\\' | b'|' | b'&' | b'>' | b'<' | b'(' | b')' | b'"' | b'\''
            )
        })
}

fn pkg_shape_ok(pkg: &str) -> bool {
    !(pkg.contains('{') && pkg.ends_with('}'))
}

/// 线程名最终写成 `\t名字=集合`。`{` `}` `=` 会改变配置结构：
/// `a{b` 会被读成包 a 的线程 b（幽灵规则，解析器不报错），`}` 会提前闭合规则块，
/// `=` 会让集合解析从错误的位置开始。包名不能一起拉黑——`pkg {` 是块语法的开头
fn thread_token_ok(s: &str, max: usize) -> bool {
    token_ok(s, max) && !s.bytes().any(|b| matches!(b, b'{' | b'}' | b'='))
}

/// Auto Assign 候选列表。时间同时给 unix 秒与本地日期：前端不想为了
/// 一个时间戳再写一遍时区换算，日志里也要能直接对上
fn candidates_json() -> String {
    let list: Vec<Value> = crate::auto_assign::load_file()
        .into_iter()
        .map(|c| {
            json!({
                "pkg": c.pkg,
                "thread": c.thread,
                "cpus": c.cpus,
                "role": c.role,
                "confidence": c.confidence,
                "reason": c.reason,
                "created_at": c.created_at,
                "expires_at": c.expires_at,
            })
        })
        .collect();
    json!({ "items": list }).to_string()
}

/// 确认候选：先用 `rule_upsert` 写正式规则，成功后才把候选行删掉。
/// 顺序不能反——先删候选再写规则失败，用户会同时失去建议和规则
fn candidate_accept_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(pkg), Some(thread)) = (v["pkg"].as_str(), v["thread"].as_str()) else {
        return err_json(400, "缺少 pkg 或 thread 字段");
    };
    // 只接受候选文件里确实存在的条目：集合与包名都从文件读，
    // 不让客户端用这个接口绕过 `/api/rule` 的校验
    let Some(cand) = crate::auto_assign::load_file()
        .into_iter()
        .find(|c| c.pkg == pkg && c.thread == thread)
    else {
        return err_json(404, "候选不存在或已过期");
    };
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_upsert(&file, &cand.pkg, &cand.thread, &cand.cpus) {
        RuleEdit::Ok => {
            crate::auto_assign::remove(&cand.pkg, &cand.thread);
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

/// 忽略一条候选：只删候选行，不动正式规则
fn candidate_del_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(pkg), Some(thread)) = (v["pkg"].as_str(), v["thread"].as_str()) else {
        return err_json(400, "缺少 pkg 或 thread 字段");
    };
    if crate::auto_assign::remove(pkg, thread) {
        (200, json!({ "ok": true }).to_string())
    } else {
        err_json(404, "候选不存在")
    }
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
    if !token_ok(pkg, MAX_PKG_LEN)
        || (!thread.is_empty() && !thread_token_ok(thread, MAX_THREAD_LEN))
    {
        return err_json(400, "名称含有非法字符");
    }
    if thread.is_empty() && !pkg_shape_ok(pkg) {
        return err_json(400, "包名含 { 且以 } 结尾时不支持包级规则，可改用线程规则");
    }
    if cpus.is_empty()
        || cpus.len() >= 64
        || !spec_like(cpus)
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
    let (Some(old), Some(new)) = (
        v["old"].as_str().map(str::trim),
        v["new"].as_str().map(str::trim),
    ) else {
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
            suggest_threads(pkg, q)
                .into_iter()
                .map(|(n, _)| n)
                .collect()
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
            let r = if ln.starts_with(lq) {
                0
            } else if ln.contains(lq) {
                1
            } else {
                2
            };
            (r < 2).then_some((r, Reverse(c), n))
        })
        .collect();
    ranked.sort_unstable();
    ranked.truncate(20);
    ranked
        .into_iter()
        .map(|(_, Reverse(c), n)| (n, c))
        .collect()
}

/// 联想结果的缓存时长。`/api/suggest` 由输入触发，每次都要全量遍历
/// `/proc` 与 `/data/data`；前端虽然有 250ms 防抖，连续输入仍会打出
/// 多次全量扫描。扫描结果只随安装/启动变化，5 秒足够，且排序在 q 上做，
/// 缓存全量列表不影响过滤
const SUGGEST_TTL: Duration = Duration::from_secs(5);

/// (扫描时刻, 全量结果)
type ScanCache = (Instant, Vec<(String, usize)>);
/// (扫描时刻, 包名, 该包的线程名结果)
type ThreadScanCache = (Instant, String, Vec<(String, usize)>);

static PKG_SCAN: Mutex<Option<ScanCache>> = Mutex::new(None);
static THREAD_SCAN: Mutex<Option<ThreadScanCache>> = Mutex::new(None);

/// 全量包名与同名进程数，命中缓存直接返回
fn pkg_counts() -> Vec<(String, usize)> {
    let cached = {
        let g = lock_ignore_poison(&PKG_SCAN);
        g.as_ref()
            .filter(|(t, _)| t.elapsed() < SUGGEST_TTL)
            .map(|(_, v)| v.clone())
    };
    if let Some(v) = cached {
        return v;
    }
    let mut counts: BTreeMap<String, usize> =
        installed_pkgs().into_iter().map(|p| (p, 0)).collect();
    for_each_pid(|pid| {
        if let Some(name) = read_cmdline(pid).filter(|n| n.contains('.')) {
            *counts.entry(name).or_insert(0) += 1;
        }
    });
    let v: Vec<(String, usize)> = counts.into_iter().collect();
    *lock_ignore_poison(&PKG_SCAN) = Some((Instant::now(), v.clone()));
    v
}

fn suggest_pkgs(q: &str) -> Vec<(String, usize)> {
    let counts: BTreeMap<String, usize> = pkg_counts().into_iter().collect();
    rank_top(counts, &q.to_ascii_lowercase())
}

fn thread_comm(pid: i32, tid: i32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid)).ok()?;
    let name = s.trim_end_matches(['\0', '\n']).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn suggest_threads(pkg: &str, q: &str) -> Vec<(String, usize)> {
    // 线程名变化比包名快，缓存短一些，且按包名分开存：
    // 用户先看 A 包再看 B 包时不能拿 A 的列表顶上去
    let cached = {
        let g = lock_ignore_poison(&THREAD_SCAN);
        g.as_ref()
            .filter(|(t, p, _)| p == pkg && t.elapsed() < SUGGEST_TTL)
            .map(|(_, _, v)| v.clone())
    };
    let list = match cached {
        Some(v) => v,
        None => {
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
            let v: Vec<(String, usize)> = counts.into_iter().collect();
            *lock_ignore_poison(&THREAD_SCAN) = Some((Instant::now(), pkg.to_string(), v.clone()));
            v
        }
    };
    rank_top(list.into_iter().collect(), &q.to_ascii_lowercase())
}

fn config_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    let cpuset_enabled = cfg.as_ref().is_some_and(|c| c.topo.cpuset_enabled);
    let unmatched = if cfg.as_ref().is_some_and(|c| c.unmatched_all) {
        "all"
    } else {
        "keep"
    };
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
        .unwrap_or((
            crate::config::RT_DEFAULT_MAX,
            crate::config::RT_DEFAULT_TIMESLICE,
        ));
    // 系统分组策略取配置真值：界面上的「强制接管」是一个开关，
    // 切换后要立刻反映，不能等主循环刷新快照
    let sysgroup = match cfg.as_ref() {
        Some(c) if !c.sysgroup_respect => "takeover",
        _ => "respect",
    };
    // 三个行为开关同样取配置真值：切换后要立刻反映，不能等主循环刷新。
    // 配置尚未加载时按默认值回，避免界面显示成「未知」再跳变
    let screen = if cfg.as_ref().is_some_and(|c| c.screen_relax) {
        "relax"
    } else {
        "off"
    };
    let group = match cfg.as_ref() {
        Some(c) if !c.group_own => "mask",
        _ => "own",
    };
    // 新增的三个开关同样取配置真值，界面切换后立即反映
    let demote = cfg.as_ref().is_some_and(|c| c.foreground_demote);
    let auto_assign = cfg.as_ref().is_some_and(|c| c.auto_assign);
    let pmu = cfg.as_ref().is_some_and(|c| c.pmu_observe);
    let pmu_alloc = cfg.as_ref().is_some_and(|c| c.pmu_alloc && c.pmu_observe);
    let snap = lock_ignore_poison(&SCHED_SNAPSHOT)
        .clone()
        .unwrap_or_default();
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
        "sysgroup": sysgroup,
        "screen": screen,
        "group": group,
        "demote": demote,
        "auto_assign": auto_assign,
        "pmu": pmu,
        "pmu_alloc": pmu_alloc,
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
    let gc = crate::cpuset::eff_cache_stat();
    let pmu_snap = crate::pmu::snapshot();
    let scan = crate::proc_mode::metrics();
    let snap = lock_ignore_poison(&SCHED_SNAPSHOT)
        .clone()
        .unwrap_or_default();
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
                "bg": t.bg,
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
                "total_wait_ms": (j.total_wait_ms * 10.0).round() / 10.0,
                "switches": j.switches,
                "affinity": j.affinity,
                "cpu": j.cpu,
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
            "cpuset_paused": crate::apply_affinity::cpuset_paused(),
            "clip": d.aff.clip,
            "reset": d.aff.reset,
            "shifted": d.aff.shifted,
            "ineffective": d.aff.ineffective,
            "stuck_skip": d.aff.stuck_skip,
            "sysgroup_skip": d.aff.sysgroup_skip,
            "unreachable": d.aff.unreachable,
            "stuck": crate::apply_affinity::stuck_count(),
            "rule": d.aff.rule,
            "sync": d.aff.sync,
            "sched": d.aff.sched,
            "line": diag::affinity_line(&d.aff),
            "errno_line": d.aff.errno_line(),
            // 0 未尝试（/proc 模式）、1 已挂 kprobe、2 不可用
            "affinity_probe": crate::ebpf_mode::AFFINITY_PROBE.load(std::sync::atomic::Ordering::Relaxed),
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
        // /proc 扫描成本：回答「定时对账到底贵不贵、贵在哪一段」
        "scan": {
            "full_scans": scan.full_scans,
            "incremental": scan.incremental,
            "worst_ms": (scan.worst_full_us / 1000) as u64,
            "last": {
                "procs": scan.last_full.procs,
                "threads": scan.last_full.threads,
                "walk_ms": (scan.last_full.walk_us / 1000) as u64,
                "tasks_ms": (scan.last_full.tasks_us / 1000) as u64,
                "total_ms": (scan.last_full.total_us / 1000) as u64,
            },
        },
        // 组生效集合缓存：命中率回答「5 秒 TTL 够不够」，容量回答「会不会
        // 一直在淘汰」。两项都只观察，不参与判定
        "group_cache": {
            "hit": gc.hit,
            "miss": gc.miss,
            "size": gc.size,
            "cap": 128,
            "ttl_s": 5,
        },
        // 账本条数 vs 缓存受管数。两者应当接近：账本少说明登记漏了，
        // 退出时这些线程的亲和性不会被还原；账本多说明有记录没清掉
        "ledger": {
            "records": crate::lifecycle::managed_count(),
            "recovery": crate::lifecycle::recovery_required(),
            "managed": d.tally.map_or(0, |t| t.total),
            "consistent": d.tally.map_or(0, |t| t.ok + t.rebound),
            "blocked": d.tally.map_or(0, |t| t.blocked),
            "known": d.tally.is_some(),
        },
        "jank": jank,
        "pressure": d.pressure,
        "threads": threads,
        "pmu": {
            "state": pmu_snap.state,
            "fds": pmu_snap.fds,
            "budget": pmu_snap.budget,
            "threads": pmu_snap.threads,
            "active": pmu_snap.active,
            "windows": pmu_snap.windows,
            "miss_ok": pmu_snap.miss_ok,
            "mode": pmu_snap.mode,
            "samples": pmu_snap.samples.iter().map(|s| json!({
                "tid": s.tid,
                "pkg": s.pkg,
                "comm": s.comm,
                "inst": s.inst,
                "cycles": s.cycles,
                "misses": s.misses,
                "cpi": (s.cpi() * 100.0).round() / 100.0,
                "mips": (s.mips() * 10.0).round() / 10.0,
                // 部分设备只放出 cycles：面板要能退到这一项，不能显示 0
                "gcyc": (s.gcyc() * 100.0).round() / 100.0,
                "cpu_ms": (s.cpu_ms() * 10.0).round() / 10.0,
                "cpu_pct": (s.cpu_pct() * 10.0).round() / 10.0,
                "window_ms": s.window_ms,
            })).collect::<Vec<_>>(),
            // Shadow 配额：只算不执行，字段命名与日志保持同一套口径
            "alloc": crate::pmu_allocator::snapshot().map(|a| json!({
                "heavy": a.heavy,
                "medium": a.medium,
                "light": a.light,
                "heavy_share": (a.heavy_share * 1000.0).round() / 10.0,
                "want": a.want.iter().map(|x| (x * 1000.0).round() / 10.0).collect::<Vec<_>>(),
                "got": a.got.map(|g| g.iter().map(|x| (x * 1000.0).round() / 10.0).collect::<Vec<_>>()),
                "gap": a.gap.iter().map(|x| (x * 1000.0).round() / 10.0).collect::<Vec<_>>(),
                "fit": (a.fit * 1000.0).round() / 10.0,
                "starved": a.starved_name,
                "source": a.source,
                "hints": a.hints,
                "samples": a.samples,
            })),
            // λmod：每层的影子价格与落层建议。同样只算不执行，
            // `share` 与 `rho` 都按「线程数占比」计，`cap_share` 才是算力加权
            "lambda": crate::pmu_lambda::snapshot().map(|l| json!({
                "state": l.state,
                "tiers": l.tiers.iter().map(|t| json!({
                    "cpus": t.cpus.to_range_string(),
                    "rho": (t.rho * 1000.0).round() / 10.0,
                    "l2_kb": t.l2_kb.round(),
                })).collect::<Vec<_>>(),
                "lambda": l.lambda.iter().map(|x| (x * 100.0).round() / 100.0).collect::<Vec<_>>(),
                "share": l.share.iter().map(|x| (x * 1000.0).round() / 10.0).collect::<Vec<_>>(),
                "cap_share": l.cap_share.iter().map(|x| (x * 1000.0).round() / 10.0).collect::<Vec<_>>(),
                "err": (l.err * 1000.0).round() / 10.0,
                "rounds": l.rounds,
                "threads": l.threads,
                "picks": l.picks.iter().map(|(comm, tid, tier, p)| json!({
                    "comm": comm,
                    "tid": tid,
                    "tier": tier,
                    "p": (p * 1000.0).round() / 10.0,
                })).collect::<Vec<_>>(),
                "line": l.log_text(),
            })),
        },
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

/// 行为开关：`@screen`、`@group`。一次只改一个键，
/// 与 `@sched` 走同一条路径（写盘 → 立即重载），改完日志里的策略行会自证
fn behavior_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let key = match v["key"].as_str() {
        Some("screen") => BehaviorKey::Screen,
        Some("group") => BehaviorKey::Group,
        Some("foreground_demote") => BehaviorKey::Demote,
        Some("auto_assign") => BehaviorKey::AutoAssign,
        Some("pmu") => BehaviorKey::Pmu,
        Some("pmu_alloc") => BehaviorKey::PmuAlloc,
        Some(_) => return err_json(400, "未知的开关名"),
        None => return err_json(400, "缺少 key 字段"),
    };
    let Some(on) = v["on"].as_bool() else {
        return err_json(400, "缺少 on 字段（true / false）");
    };

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match behavior_set(&file, key, on) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
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
    // `respect` 保留系统分组（后台线程不上大核），`takeover` 强行拉进 AppOpt 组。
    // 别名与配置解析器保持一致，避免两个入口对同一策略给出不同拼写
    let sysgroup = match v["sysgroup"].as_str() {
        Some("respect") | Some("keep") => Some("respect"),
        Some("takeover") | Some("force") => Some("takeover"),
        Some(_) => return err_json(400, "sysgroup 只能是 respect 或 takeover"),
        None => None,
    };
    if unmatched.is_none() && rt_max.is_none() && rt_ts.is_none() && sysgroup.is_none() {
        return err_json(400, "没有要修改的项");
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match adv_configure(&file, unmatched, rt_max, rt_ts, sysgroup) {
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
        // 非法名字不能静默回落到默认目录：Web 上看着改成功了，
        // 实际 base 没变，后面的所有组都建在旧路径下
        if crate::cpuset::set_base_cpuset(n).is_err() {
            return err_json(400, "无效的 cpuset 目录名");
        }
        // 目录全部换到新 base 下，旧的“已建”记录必须作废
        reset_cpuset_dir_cache();
        if let Some(cfg) = current_cfg()
            && cfg.topo.cpuset_enabled
        {
            create_cpuset_dir(&base_cpuset(), &cfg.topo.present_str, &cfg.topo.mems_str);
        }
        FORCE_RELOAD.store(true, Ordering::Release);
    }
    if let Some(p) = path {
        if std::fs::metadata(p).is_err()
            && let Err(e) = create_config_file(p)
        {
            crate::diag::tag("失败", &format!("Web 创建配置文件 {} 失败：{}", p, e));
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

/// cpuset 目录名。`.` 会让 base 变成 `/dev/cpuset/.`（等于根组，
/// 线程被迁进去就退出了系统分组）；`..` 会让 base 变成 `/dev`，
/// 守护进程随后在 `/dev` 下建 cpus/mems 与 `4-6` 目录。两者都必须拒绝，
/// 而且值会落进 AppOpt.json，重启后依然有效
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 64
        && s != "."
        && s != ".."
        && !s.contains('/')
        && !s.contains("..")
        && !s.bytes().any(|b| b <= b' ')
}

fn valid_path(s: &str) -> bool {
    !s.is_empty() && s.len() < 256 && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// 新建配置文件时写入的初始内容
const CONFIG_HEADER: &str = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";

/// Web 端只能把配置文件指到模块自身目录内（当前配置所在目录或可执行文件目录），
/// 且必须是 `.conf` 结尾的普通文件。
///
/// 之前还放行 `/data/adb`、`/data/local/tmp`、`/sdcard`：`/data/adb` 覆盖了
/// `modules/AppOpt/post-fs-data.sh` 与 `service.d/*.sh`，模块框架开机以 root 执行，
/// 指向它等于把 root 持久化的写权限交给任何能连 8889 的应用。共享存储同理，
/// 很多应用都能写 /sdcard。这两类目录整体移出白名单。
///
/// 路径先拒绝 `..` 组件，再规范化父目录后比较前缀；最终目标是符号链接时直接拒绝，
/// 否则按路径打开会跟随链接落到白名单之外。真正的写入由 create_config_file 用 openat 兜底
fn path_allowed(p: &str) -> bool {
    use std::path::{Component, Path, PathBuf};

    let path = Path::new(p);
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return false;
    }
    // 只收 .conf：脚本、JSON、二进制都不是规则文件，没必要留后门
    if path.extension().and_then(|e| e.to_str()) != Some("conf") {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(dir) = fs::canonicalize(parent) else {
        return false;
    };
    // 已存在的路径：符号链接一律不接，避免被换链绕过；必须是普通文件，
    // 否则 FIFO、设备节点会让读取阻塞或读不完
    if let Ok(md) = fs::symlink_metadata(path)
        && (md.file_type().is_symlink() || !md.file_type().is_file())
    {
        return false;
    }

    let mut roots: Vec<PathBuf> = Vec::new();
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
        use std::os::unix::fs::OpenOptionsExt;

        let _guard = lock_ignore_poison(&SAVE_LOCK);
        let json = serde_json::to_string_pretty(&self.to_value()).unwrap_or_default();
        let tmp = format!("{}.tmp", path);
        // 显式 0644，别让 umask 决定设置文件是 0600 还是 0666
        let res = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&tmp)
            .and_then(|mut f| {
                f.write_all(format!("{}\n", json).as_bytes())?;
                f.sync_all()
            })
            .and_then(|_| fs::rename(&tmp, path));
        if let Err(e) = res {
            crate::diag::tag("警告", &format!("设置写入 {} 失败：{}", path, e));
        }
    }
}

pub fn settings_load(path: &str) -> Settings {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => Settings::from_json(&v),
            Err(e) => {
                crate::diag::tag("警告", &format!("{} 已损坏（{}），使用默认设置", path, e));
                Settings::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let d = Settings::default();
            d.save(path);
            // 首次运行的提示要排在「启动」行之后，否则启动块的第一行就不是启动行
            SETTINGS_FRESH.store(true, Ordering::Release);
            d
        }
        Err(e) => {
            crate::diag::tag(
                "警告",
                &format!("读取 {} 失败（{}），使用默认设置", path, e),
            );
            Settings::default()
        }
    }
}

pub fn settings_save() {
    Settings {
        web_enable: WEB_ENABLED.load(Ordering::Relaxed),
        mode: MODE_FORCE.load(Ordering::Relaxed),
        check_interval: CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        cpuset_name: base_cpuset()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string(),
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

    /// 不带 Sec-Fetch-Site 的客户端不能因为「缺头」被当成同源。
    /// 修复前 curl 带 `Origin: https://evil.example` 能直接写规则
    #[test]
    fn origin_requires_whitelist_even_without_fetch_site() {
        assert!(origin_ok("127.0.0.1", "", "GET", ""));
        assert!(origin_ok(
            "127.0.0.1",
            "https://mui.kernelsu.org",
            "POST",
            "application/json"
        ));
        assert!(origin_ok(
            "127.0.0.1",
            "http://127.0.0.1:8889",
            "POST",
            "application/json"
        ));
        // `Origin: null` 任何网页都能构造，不再当作本机来源
        assert!(!origin_ok("localhost", "null", "POST", "application/json"));
        // 恶意 Origin：不再因为没带 Sec-Fetch-Site 而放行
        assert!(!origin_ok("127.0.0.1", "https://evil.example", "GET", ""));
        assert!(!origin_ok(
            "127.0.0.1",
            "https://evil.example",
            "POST",
            "application/json"
        ));
        // Host 不是回环、POST 不是 JSON，仍然拒绝
        assert!(!origin_ok("10.0.0.2", "", "GET", ""));
        assert!(!origin_ok("127.0.0.1", "", "POST", "text/plain"));
    }

    /// 令牌必须是 32 位十六进制，比较走常量时间实现
    #[test]
    fn token_shape_and_compare() {
        let a = "0123456789abcdef0123456789abcdef";
        assert!(token_shape_ok(a));
        assert!(token_eq(a, a));
        assert!(!token_eq(a, "0123456789abcdef0123456789abcdee"));
        assert!(!token_eq(a, &a[..31]));
        for bad in ["", "0123", "zz23456789abcdef0123456789abcdef"] {
            assert!(!token_shape_ok(bad), "{bad}");
        }
    }

    /// 规则名会原样写进配置文件。虽然配置不被 shell 执行，但曾经的白名单能把
    /// config_file 指到 post-fs-data.sh，`x;sh a.sh;y` 就是 root 持久化路径
    #[test]
    fn rule_name_rejects_shell_metachars() {
        for bad in [
            "x;sh /sdcard/a.sh;y",
            "$(id)",
            "a`id`b",
            "a|b",
            "a&&b",
            "a>b",
            "a$(b)",
            "a'b",
            "a\"b",
        ] {
            assert!(!token_ok(bad, MAX_PKG_LEN), "{bad}");
        }
        assert!(token_ok("com.example.game", MAX_PKG_LEN));
        assert!(token_ok("RenderThread", MAX_THREAD_LEN));
        assert!(token_ok("HwBinder:1234_1", MAX_THREAD_LEN));
        assert!(token_ok("mali-rX", MAX_THREAD_LEN));
    }

    /// cpuset 目录名直接拼进 /dev/cpuset/<name>，`.` 会退回根组、`..` 会落到 /dev
    #[test]
    fn cpuset_name_rejects_dots() {
        assert!(valid_name("AppOpt"));
        assert!(valid_name("AppOpt-1"));
        for bad in [".", "..", "a..b", "a/b", "", "a b"] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(valid_name(&"a".repeat(63)));
        assert!(!valid_name(&"a".repeat(64)));
    }

    /// 配置文件只能是模块目录下的 .conf：脚本与共享存储都不再放行
    #[test]
    fn only_conf_inside_module_is_allowed() {
        let exe = exe_dir();
        assert!(path_allowed(exe.join("rules.conf").to_str().unwrap()));
        for bad in [
            exe.join("post-fs-data.sh"),
            exe.join("service.d"),
            exe.join("AppOpt.json"),
            std::path::PathBuf::from("/sdcard/applist.conf"),
            std::path::PathBuf::from("/data/adb/modules/AppOpt/post-fs-data.sh"),
            std::path::PathBuf::from("/data/local/tmp/x.conf"),
        ] {
            assert!(!path_allowed(bad.to_str().unwrap()), "{}", bad.display());
        }
    }

    /// `a{b` 会被写成包 a 的线程 b，`}` 会提前闭合块，`=` 会让集合错位
    #[test]
    fn thread_name_rejects_block_syntax() {
        assert!(thread_token_ok("RenderThread", MAX_THREAD_LEN));
        assert!(thread_token_ok("Thread-1", MAX_THREAD_LEN));
        for bad in ["a{b", "a}b", "a=b", "{", "}", "="] {
            assert!(!thread_token_ok(bad, MAX_THREAD_LEN), "{bad}");
        }
        // 包名不受影响：`pkg {` 是块语法
        assert!(token_ok("com.example.game", MAX_PKG_LEN));
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
        let link = format!(
            "{}/appopt_dir_link_{}",
            exe_dir().display(),
            std::process::id()
        );
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

    /// WebUI 读的是模块 webroot 里的 token.js，格式必须能直接被页面正则识别
    /// 联想结果必须命中缓存：每次请求都全量扫 /proc，连续输入会把
    /// 读放大成每秒几十次（审计报告里点名的那处）
    #[test]
    fn suggest_scan_is_cached() {
        let a = pkg_counts();
        let t1 = lock_ignore_poison(&PKG_SCAN).as_ref().map(|(t, _)| *t);
        let b = pkg_counts();
        let t2 = lock_ignore_poison(&PKG_SCAN).as_ref().map(|(t, _)| *t);
        assert_eq!(a, b);
        assert_eq!(t1, t2, "TTL 内不得重新扫描");

        // 线程名缓存按包分开：换一个包必须重新扫，不能拿上一个包的结果
        let _ = suggest_threads("com.appopt.none_a", "");
        let _ = suggest_threads("com.appopt.none_b", "");
        let owner = lock_ignore_poison(&THREAD_SCAN)
            .as_ref()
            .map(|(_, p, _)| p.clone());
        assert_eq!(owner.as_deref(), Some("com.appopt.none_b"));
    }

    #[test]
    fn token_js_is_a_parseable_assignment() {
        let js = token_js("0123456789abcdef0123456789abcdef");
        assert_eq!(
            js,
            "window.__APPOPT_TOKEN=\"0123456789abcdef0123456789abcdef\";\n"
        );
        // 只有十六进制才会写进这个文件，不存在引号逃逸
        assert!(token_shape_ok("0123456789abcdef0123456789abcdef"));
        assert!(!token_shape_ok("0123456789abcdef0123456789abcde\""));
        assert!(!token_shape_ok("0123456789abcdef0123456789abcde\n"));
    }
}
