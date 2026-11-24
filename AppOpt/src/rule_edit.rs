use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::sync::Mutex;

use crate::config::{
    OuterLine, close_like, comment_at, parse_outer, split_rule_line, split_single_line,
    strip_comment,
};

pub enum RuleEdit {
    Ok,
    NotFound,
    Conflict,
    Malformed,
    IoErr,
}

static WRITE_LOCK: Mutex<()> = Mutex::new(());

enum PkgLine {
    Standalone(usize),
    OpenInline(usize),
    BareOpen(usize),
    BarePending(usize),
}

#[derive(Clone, Copy)]
struct ThreadLoc {
    idx: usize,
    single: bool,
    closed: bool,
    open: bool,
}

struct Target {
    pkg_line: Option<PkgLine>,
    block_open: Option<usize>,
    block_close: Option<usize>,
    threads: HashMap<String, Vec<ThreadLoc>>,
    unterminated: bool,
}

fn target_scan(lines: &[String], pkg: &str) -> Target {
    let mut t = Target {
        pkg_line: None,
        block_open: None,
        block_close: None,
        threads: HashMap::new(),
        unterminated: false,
    };
    let mut pending: Option<usize> = None;
    let mut in_block = false;
    let mut target_block = false;

    let block_close = |t: &mut Target, target_block: &mut bool, i: usize| {
        if *target_block && t.block_close.is_none() {
            t.block_close = Some(i);
        }
        *target_block = false;
    };
    let block_open = |t: &mut Target, i: usize| {
        if t.block_close.is_none() {
            t.block_open = Some(i);
        }
    };

    for (i, raw) in lines.iter().enumerate() {
        let p = raw.trim();
        if p.is_empty() || p.starts_with('#') || p.starts_with("//") {
            continue;
        }

        if in_block {
            if close_like(p) {
                in_block = false;
                block_close(&mut t, &mut target_block, i);
                continue;
            }
            match split_rule_line(p) {
                Some((name, _, closed)) => {
                    if target_block && !name.is_empty() {
                        t.threads
                            .entry(name.to_string())
                            .or_default()
                            .push(ThreadLoc {
                                idx: i,
                                single: false,
                                closed,
                                open: false,
                            });
                    }
                    if closed {
                        in_block = false;
                        block_close(&mut t, &mut target_block, i);
                    }
                }
                None => {
                    if p.contains('}') {
                        in_block = false;
                        block_close(&mut t, &mut target_block, i);
                    }
                }
            }
            continue;
        }

        match parse_outer(p) {
            OuterLine::Single {
                pkg: pg,
                thread: th,
                open,
                ..
            } => {
                pending = None;
                if pg == pkg && !th.is_empty() {
                    t.threads
                        .entry(th.to_string())
                        .or_default()
                        .push(ThreadLoc {
                            idx: i,
                            single: true,
                            closed: false,
                            open,
                        });
                }
                if open {
                    in_block = true;
                    if pg == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                    }
                }
            }
            OuterLine::Rule { pkg: pg, open, .. } => {
                if open {
                    in_block = true;
                    pending = None;
                    if pg == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::OpenInline(i));
                        }
                    }
                } else {
                    pending = None;
                    if pg == pkg && t.pkg_line.is_none() {
                        t.pkg_line = Some(PkgLine::Standalone(i));
                    }
                }
            }
            OuterLine::BareOpen { pkg: owner } => {
                if !owner.is_empty() {
                    pending = None;
                    in_block = true;
                    if owner == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::BareOpen(i));
                        }
                    }
                } else if let Some(pi) = pending.take() {
                    in_block = true;
                    if let OuterLine::Pending { pkg: pp } = parse_outer(lines[pi].trim())
                        && pp == pkg
                    {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::BarePending(pi));
                        }
                    }
                }
            }
            OuterLine::Pending { .. } => {
                pending = Some(i);
            }
            OuterLine::Junk => {
                pending = None;
            }
        }
    }

    t.unterminated = in_block;
    t
}

impl Target {
    fn singles(&self) -> impl Iterator<Item = &ThreadLoc> {
        self.threads.values().flatten().filter(|l| l.single)
    }
    fn any_line(&self) -> bool {
        self.pkg_line.is_some() || self.singles().next().is_some()
    }
}

fn normalize_singles(lines: &mut Vec<String>, pkg: &str) {
    let t = target_scan(lines, pkg);
    let mut items: Vec<(ThreadLoc, String)> = Vec::new();
    for loc in t.singles() {
        let raw_line = lines[loc.idx].trim();
        let raw = strip_comment(raw_line);
        let body = raw.strip_suffix('{').map(str::trim_end).unwrap_or(raw);
        if let Some((_, th, cp)) = split_single_line(body) {
            let line = with_comment(&format!("\t{}={}", th, cp), raw_line);
            items.push((*loc, line));
        }
    }
    if items.is_empty() {
        return;
    }
    items.sort_unstable_by_key(|(l, _)| l.idx);
    if t.block_close.is_none()
        && (items.iter().any(|(l, _)| l.open)
            || !matches!(t.pkg_line, None | Some(PkgLine::Standalone(_))))
    {
        return;
    }

    let at = items[0].0.idx;
    for (loc, _) in items.iter().rev() {
        line_remove(lines, pkg, loc);
    }
    let items: Vec<String> = items.into_iter().map(|(_, line)| line).collect();

    let t2 = target_scan(lines, pkg);
    if let Some(close) = t2.block_close {
        for (off, line) in items.into_iter().enumerate() {
            lines.insert(close + off, line);
        }
    } else if let Some(PkgLine::Standalone(i)) = t2.pkg_line {
        lines[i] = format!("{} {{", lines[i].trim_end());
        let chunk: Vec<String> = items
            .into_iter()
            .chain(std::iter::once("}".to_string()))
            .collect();
        lines.splice(i + 1..i + 1, chunk);
    } else {
        let chunk: Vec<String> = std::iter::once(bare_open_line(pkg))
            .chain(items)
            .chain(std::iter::once("}".to_string()))
            .collect();
        let at = at.min(lines.len());
        lines.splice(at..at, chunk);
    }
}

fn bare_open_line(pkg: &str) -> String {
    if pkg.contains('=') {
        format!("{pkg}= {{")
    } else {
        format!("{pkg} {{")
    }
}

fn with_comment(new_line: &str, old: &str) -> String {
    match comment_at(old) {
        Some(at) => format!("{}{}", new_line, &old[at..]),
        None => new_line.to_string(),
    }
}

fn spec_swap(raw: &str, cpus: &str) -> String {
    let cut = comment_at(raw).unwrap_or(raw.len());
    let Some(eq) = raw[..cut].rfind('=') else {
        return raw.into();
    };
    let rhs = &raw[eq + 1..cut];
    let val = rhs.trim_start();
    let lead = rhs.len() - val.len();
    let v_end = val
        .find(|c: char| c.is_whitespace() || c == '{' || c == '}')
        .unwrap_or(val.len());
    let tail: String = val[v_end..]
        .chars()
        .filter(|c| c.is_whitespace() || *c == '{' || *c == '}')
        .collect();
    format!("{}{}{}{}", &raw[..eq + 1 + lead], cpus, tail, &raw[cut..])
}

fn line_remove(lines: &mut Vec<String>, pkg: &str, loc: &ThreadLoc) {
    if loc.open {
        lines[loc.idx] = with_comment(&bare_open_line(pkg), &lines[loc.idx]);
    } else if loc.closed {
        lines[loc.idx] = with_comment("}", &lines[loc.idx]);
    } else {
        lines.remove(loc.idx);
    }
}

/// 复制一个扩展属性（SELinux 标签）。rename 之后新文件的标签是当前进程的，
/// 在强制模式下可能让原本能读配置的进程被拒
fn copy_xattr(dst_fd: i32, src: &str, name: &str) {
    use std::ffi::CString;
    let (Ok(csrc), Ok(cname)) = (CString::new(src), CString::new(name)) else {
        return;
    };
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::getxattr(
            csrc.as_ptr(),
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            buf.len(),
        )
    };
    if n > 0 {
        unsafe {
            libc::fsetxattr(
                dst_fd,
                cname.as_ptr(),
                buf.as_ptr() as *const _,
                n as usize,
                0,
            );
        }
    }
}

fn file_write(path: &str, lines: &[String]) -> RuleEdit {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut out = lines.join("\n");
    out.push('\n');
    let tmp = format!("{}.tmp", path);
    // 新文件默认受 umask 影响，可能是 0600 也可能是 0666；直接指定按原文件权限，
    // 原文件不存在时用 0644，与 create_config_file 一致
    let orig = fs::symlink_metadata(path).ok();
    let mode = orig
        .as_ref()
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o644);
    // 配置目录可能位于共享存储，临时文件用 O_NOFOLLOW 打开，
    // 防止预先放置的同名符号链接把这次写入引到白名单之外
    let res = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .and_then(|mut f| {
            if let Some(m) = &orig {
                // rename 会把属主换成当前进程，这里先对齐原文件
                unsafe {
                    libc::fchown(f.as_raw_fd(), m.uid(), m.gid());
                }
                copy_xattr(f.as_raw_fd(), path, "security.selinux");
            }
            f.write_all(out.as_bytes())?;
            f.sync_all()
        })
        .and_then(|_| fs::rename(&tmp, path));
    if res.is_ok() {
        RuleEdit::Ok
    } else {
        RuleEdit::IoErr
    }
}

pub fn rule_upsert(path: &str, pkg: &str, thread: &str, cpus: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    normalize_singles(&mut lines, pkg);
    let t = target_scan(&lines, pkg);

    if thread.is_empty() {
        match t.pkg_line {
            Some(PkgLine::Standalone(i)) => {
                lines[i] = spec_swap(&lines[i], cpus);
            }
            Some(PkgLine::BarePending(i)) => {
                lines[i] = with_comment(&format!("{}={} {{", pkg, cpus), &lines[i]);
                if let Some(open) = t.block_open
                    && matches!(
                        parse_outer(lines[open].trim()),
                        OuterLine::BareOpen { pkg: "" }
                    )
                {
                    lines.remove(open);
                }
            }
            Some(PkgLine::OpenInline(i)) => {
                lines[i] = spec_swap(&lines[i], cpus);
            }
            Some(PkgLine::BareOpen(i)) => {
                lines[i] = with_comment(&format!("{}={} {{", pkg, cpus), &lines[i]);
            }
            None if t.unterminated => return RuleEdit::Malformed,
            None => lines.push(format!("{}={}", pkg, cpus)),
        }
    } else if let Some(locs) = t.threads.get(thread) {
        let last = locs.last().copied().unwrap();
        lines[last.idx] = spec_swap(&lines[last.idx], cpus);
        for loc in locs[..locs.len() - 1].iter().rev() {
            line_remove(&mut lines, pkg, loc);
        }
    } else if let Some(close) = t.block_close {
        lines.insert(close, format!("\t{}={}", thread, cpus));
    } else if let Some(PkgLine::Standalone(i)) = t.pkg_line {
        lines[i] = format!("{} {{", lines[i].trim_end());
        lines.splice(
            i + 1..i + 1,
            [format!("\t{}={}", thread, cpus), "}".to_string()],
        );
    } else if t.unterminated {
        return RuleEdit::Malformed;
    } else {
        lines.push(bare_open_line(pkg));
        lines.push(format!("\t{}={}", thread, cpus));
        lines.push("}".to_string());
    }

    file_write(path, &lines)
}

pub fn rule_delete(path: &str, pkg: &str, thread: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    normalize_singles(&mut lines, pkg);
    let t = target_scan(&lines, pkg);

    if thread.is_empty() {
        match t.pkg_line {
            Some(PkgLine::Standalone(i)) => {
                lines.remove(i);
            }
            Some(PkgLine::OpenInline(i)) => {
                lines[i] = bare_open_line(pkg);
            }
            _ => return RuleEdit::NotFound,
        }
    } else if let Some(locs) = t.threads.get(thread) {
        for loc in locs.iter().rev() {
            line_remove(&mut lines, pkg, loc);
        }
    } else {
        return RuleEdit::NotFound;
    }

    file_write(path, &lines)
}

pub fn rule_delete_pkg(path: &str, pkg: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    normalize_singles(&mut lines, pkg);

    let mut removed = false;
    loop {
        let t = target_scan(&lines, pkg);
        let mut del: Vec<usize> = Vec::new();
        match t.pkg_line {
            Some(PkgLine::Standalone(i))
            | Some(PkgLine::OpenInline(i))
            | Some(PkgLine::BareOpen(i))
            | Some(PkgLine::BarePending(i)) => del.push(i),
            None => {
                if !t.any_line() {
                    break;
                }
            }
        }
        if let Some(open) = t.block_open {
            let end = t
                .block_close
                .or_else(|| {
                    t.threads
                        .values()
                        .flatten()
                        .filter(|l| !l.single)
                        .map(|l| l.idx)
                        .max()
                })
                .unwrap_or(open);
            del.extend(open..=end);
        }
        del.extend(t.singles().map(|l| l.idx));

        del.sort_unstable();
        del.dedup();
        for i in del.into_iter().rev() {
            lines.remove(i);
        }
        removed = true;
    }

    if !removed {
        return RuleEdit::NotFound;
    }
    file_write(path, &lines)
}

pub fn rule_rename(path: &str, old: &str, new: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    normalize_singles(&mut lines, old);
    if !target_scan(&lines, old).any_line() {
        return RuleEdit::NotFound;
    }
    if target_scan(&lines, new).any_line() {
        return RuleEdit::Conflict;
    }

    loop {
        let t = target_scan(&lines, old);
        let mut idxs: Vec<usize> = t.singles().map(|l| l.idx).collect();
        if let Some(
            PkgLine::Standalone(i)
            | PkgLine::OpenInline(i)
            | PkgLine::BareOpen(i)
            | PkgLine::BarePending(i),
        ) = t.pkg_line
        {
            idxs.push(i);
        }
        if idxs.is_empty() {
            break;
        }
        for i in idxs {
            if let Some(rest) = lines[i].trim().strip_prefix(old) {
                let tail = match (new.contains('='), rest.trim()) {
                    (true, "" | "=") => "=",
                    (true, "{") => "= {",
                    _ => rest,
                };
                lines[i] = format!("{}{}", new, tail);
            }
        }
    }
    file_write(path, &lines)
}

/// 指令行的键与值：`@rt=off` 与 `@rt off` 两种写法都认
fn directive_parts(line: &str) -> Option<(&str, &str)> {
    let t = line.trim();
    let rest = t.strip_prefix('@')?;
    match rest.split_once('=') {
        Some((k, v)) => Some((k.trim(), v.trim())),
        None => {
            let mut it = rest.splitn(2, char::is_whitespace);
            Some((it.next()?.trim(), it.next().unwrap_or("").trim()))
        }
    }
}

/// `@rt.app=<包名> ...` 的包名
fn rt_app_pkg(line: &str) -> Option<&str> {
    match directive_parts(line) {
        Some(("rt.app", v)) => v.split_whitespace().next(),
        _ => None,
    }
}

/// 在最后一条指令行之后插入，保持指令区聚集在文件头部
fn insert_directive(lines: &mut Vec<String>, line: String) {
    let pos = lines
        .iter()
        .rposition(|l| l.trim_start().starts_with('@'))
        .map(|i| i + 1)
        .unwrap_or(0);
    lines.insert(pos, line);
}

/// 替换或删除指定键的指令行。`value` 为 None 表示删除。
/// 重复行只保留第一条，其余删除；返回是否命中过
fn directive_put(lines: &mut Vec<String>, key: &str, value: Option<&str>) -> bool {
    let mut hit = false;
    let mut i = 0;
    while i < lines.len() {
        if matches!(directive_parts(&lines[i]), Some((k, _)) if k == key) {
            match value {
                Some(v) if !hit => {
                    lines[i] = with_comment(&format!("@{}={}", key, v), &lines[i]);
                    hit = true;
                }
                _ => {
                    lines.remove(i);
                    continue;
                }
            }
        }
        i += 1;
    }
    if !hit && let Some(v) = value {
        insert_directive(lines, format!("@{}={}", key, v));
    }
    hit
}

/// 一次性写入 RT 的全局指令。分三次写会产生三个中间状态，
/// 配置线程可能读到只改了一半的文件
pub fn rt_configure(path: &str, mode: &str, max: Option<u8>, timeslice: Option<u32>) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    directive_put(&mut lines, "rt", Some(mode));
    if let Some(m) = max {
        directive_put(&mut lines, "rt.max", Some(&m.to_string()));
    }
    if let Some(t) = timeslice {
        directive_put(&mut lines, "rt.timeslice", Some(&t.to_string()));
    }
    file_write(path, &lines)
}

/// 写 `@sched=off|shadow|on`。S7 的三档开关，不写时保持 off。
/// 与 `@rt` 不同，这里没有分应用条目，切换即整机生效
pub fn sched_set(path: &str, mode: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    directive_put(&mut lines, "sched", Some(mode));
    file_write(path, &lines)
}

/// 行为开关的目标键。用枚举而不是裸字符串：Web 端直接把 JSON 里的名字
/// 传进来，拼错一个字母就会在配置里留一行 `@scren=relax`，而配置解析只会
/// 报「格式无效」，用户看不出是自己拼错了
#[derive(Clone, Copy)]
pub enum BehaviorKey {
    /// 息屏时放松周期复核
    Screen,
    /// 渲染护栏（观察模式）
    RenderGuard,
    /// 首次绑定是否接管 cpuset 组
    Group,
}

impl BehaviorKey {
    fn name(self) -> &'static str {
        match self {
            BehaviorKey::Screen => "screen",
            BehaviorKey::RenderGuard => "render_guard",
            BehaviorKey::Group => "group",
        }
    }

    /// 布尔值映射到配置里的取值。每个键的两个取值都显式写出，
    /// 不写成「真 = 第一个」的隐式约定：`group` 的默认值是 `own`，
    /// 顺序一反过来就会把默认行为翻过去
    fn value(self, on: bool) -> &'static str {
        match (self, on) {
            (BehaviorKey::Screen, true) => "relax",
            (BehaviorKey::Screen, false) => "off",
            (BehaviorKey::RenderGuard, true) => "observe",
            (BehaviorKey::RenderGuard, false) => "off",
            (BehaviorKey::Group, true) => "own",
            (BehaviorKey::Group, false) => "mask",
        }
    }
}

/// 写一个全局开关指令。只动这一个键，规则行与其它 `@` 指令原样保留
pub fn behavior_set(path: &str, key: BehaviorKey, on: bool) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    directive_put(&mut lines, key.name(), Some(key.value(on)));
    file_write(path, &lines)
}

/// 进阶参数一次写盘：`@unmatched`、`@rt.max`、`@rt.timeslice`。
/// `None` 表示该键不动。三者互不依赖，但分三次写会留下中间态，
/// 配置线程可能读到只改了一半的文件
pub fn adv_configure(
    path: &str,
    unmatched: Option<&str>,
    rt_max: Option<u8>,
    rt_timeslice: Option<u32>,
    sysgroup: Option<&str>,
) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    if let Some(u) = unmatched {
        directive_put(&mut lines, "unmatched", Some(u));
    }
    if let Some(m) = rt_max {
        directive_put(&mut lines, "rt.max", Some(&m.to_string()));
    }
    if let Some(t) = rt_timeslice {
        directive_put(&mut lines, "rt.timeslice", Some(&t.to_string()));
    }
    // 系统分组策略是全局指令，与规则行、其它 @ 指令互不影响；
    // 写 respect 而不是删行，是为了让用户能在配置文件里直接看到当前策略
    if let Some(g) = sysgroup {
        directive_put(&mut lines, "sysgroup", Some(g));
    }
    file_write(path, &lines)
}

/// 读配置并切成行。只有 `NotFound` 才当成空文件——
/// 其余错误（权限、IO、编解码）必须原样报出去。
///
/// 旧实现把所有 `Err` 都当空串：配置文件里只要有一个非 UTF-8 字节（GBK 注释很常见），
/// `read_to_string` 就失败，随后写入会把整个文件替换成只含本次修改的那一条，
/// 用户攒的几十条规则一次全丢
fn read_conf(path: &str) -> Result<Vec<String>, RuleEdit> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s.lines().map(String::from).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(RuleEdit::IoErr),
    }
}

/// 写或删除 `@rt.app=<包名> ...`。`spec` 为空表示删除该条目
pub fn rt_app_set(path: &str, pkg: &str, spec: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };
    let new_line = if spec.is_empty() {
        None
    } else {
        Some(format!("@rt.app={} {}", pkg, spec))
    };

    let mut found = false;
    let mut i = 0;
    while i < lines.len() {
        if rt_app_pkg(&lines[i]) == Some(pkg) {
            match &new_line {
                Some(l) if !found => {
                    lines[i] = with_comment(l, &lines[i]);
                    found = true;
                }
                _ => {
                    lines.remove(i);
                    continue;
                }
            }
        }
        i += 1;
    }
    if !found && let Some(l) = new_line {
        insert_directive(&mut lines, l);
    }
    // 删掉最后一个启用条目后把 @rt 收回 off，与 rt_toggle 的收尾一致。
    // global 不动：那是显式声明的全局策略，不因删条目降级
    if spec.is_empty() && !any_rt_enabled(&lines) {
        let scope = lines.iter().find_map(|l| match directive_parts(l) {
            Some(("rt", v)) => Some(v.trim().to_string()),
            _ => None,
        });
        if scope.as_deref() == Some("per_app") {
            directive_put(&mut lines, "rt", Some("off"));
        }
    }
    file_write(path, &lines)
}

/// 是否还存在启用的 `@rt.app=` 条目。省略状态时与解析一致按 on 处理
fn any_rt_enabled(lines: &[String]) -> bool {
    lines
        .iter()
        .any(|l| matches!(directive_parts(l), Some(("rt.app", _))) && rt_app_state(l) == Some(true))
}

/// `@rt.app=<包名> on|off ...` 的开关状态。省略状态时按 on 处理，
/// 与 `parse_rt_app` 的缺省一致
fn rt_app_state(line: &str) -> Option<bool> {
    let (_, v) = directive_parts(line)?;
    let mut it = v.split_whitespace();
    it.next()?;
    match it.next() {
        Some("off") => Some(false),
        Some("on") => Some(true),
        // 只有包名或直接跟模式，都算开启
        _ => Some(true),
    }
}

/// 规则页「一键 RT」：一次加锁、一次写盘完成范围切换与条目写入。
///
/// 不写 `@rt.max` / `@rt.timeslice`，沿用配置缺省（每应用 2 线程、3 ms），
/// 与 AsoulOpt 的 `rt=1` 等价。关闭最后一个启用条目时把 `@rt` 收回 off，
/// 否则 `rt_active()` 仍为真，内核时间片会一直被改写。
pub fn rt_toggle(path: &str, pkg: &str, enabled: bool) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let Ok(mut lines) = read_conf(path) else {
        return RuleEdit::IoErr;
    };

    // 保留手工调过的模式与上限：`off` 只是状态位，重新打开时恢复原参数
    let keep = lines.iter().find_map(|l| {
        if rt_app_pkg(l) != Some(pkg) {
            return None;
        }
        let (_, v) = directive_parts(l)?;
        let mut it = v.split_whitespace();
        it.next()?;
        it.next()?;
        let rest = it.collect::<Vec<_>>().join(" ");
        (!rest.is_empty()).then_some(rest)
    });
    let part = keep.unwrap_or_else(|| "auto".to_string());
    let spec = format!("{} {}", if enabled { "on" } else { "off" }, part);

    let new_line = format!("@rt.app={} {}", pkg, spec);
    let mut found = false;
    let mut i = 0;
    while i < lines.len() {
        if rt_app_pkg(&lines[i]) == Some(pkg) {
            if !found {
                lines[i] = with_comment(&new_line, &lines[i]);
                found = true;
            } else {
                lines.remove(i);
                continue;
            }
        }
        i += 1;
    }
    if !found {
        insert_directive(&mut lines, new_line);
    }

    if enabled {
        directive_put(&mut lines, "rt", Some("per_app"));
    } else {
        let any_on = lines
            .iter()
            .any(|l| rt_app_pkg(l).is_some() && rt_app_state(l) == Some(true));
        if !any_on {
            directive_put(&mut lines, "rt", Some("off"));
        }
    }
    file_write(path, &lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 行为开关只改自己那一个键：规则、注释、其它指令都要原样留着。
    /// 另外 `group` 的 on/off 映射到 `own`/`mask` 是反直觉的（on=own），
    /// 写错了会把默认行为翻过去，所以逐个断言
    #[test]
    fn behavior_set_touches_only_target_directive() {
        let dir = format!("/tmp/appopt_behavior_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);
        fs::write(
            &conf,
            "# 顶部注释\n@sched=on\ncom.a=0-3\ncom.b=4-7  # 尾部注释\n",
        )
        .unwrap();

        assert!(matches!(
            behavior_set(&conf, BehaviorKey::Screen, true),
            RuleEdit::Ok
        ));
        assert!(matches!(
            behavior_set(&conf, BehaviorKey::Group, false),
            RuleEdit::Ok
        ));
        let out = fs::read_to_string(&conf).unwrap();
        assert!(out.contains("@screen=relax"), "{out}");
        assert!(out.contains("@group=mask"), "{out}");
        assert!(out.contains("@sched=on"), "不能动其它指令: {out}");
        assert!(out.contains("com.a=0-3"), "不能动规则: {out}");
        assert!(
            out.contains("com.b=4-7  # 尾部注释"),
            "行尾注释要保留: {out}"
        );

        // 再打开一次：同一个键只能有一行，不能越写越多
        behavior_set(&conf, BehaviorKey::Screen, false);
        behavior_set(&conf, BehaviorKey::Screen, true);
        let out = fs::read_to_string(&conf).unwrap();
        assert_eq!(out.matches("@screen=").count(), 1, "同键只能留一行: {out}");
        assert!(out.contains("@screen=relax"));

        // 三个键的取值映射
        assert_eq!(BehaviorKey::Screen.value(true), "relax");
        assert_eq!(BehaviorKey::RenderGuard.value(true), "observe");
        assert_eq!(BehaviorKey::Group.value(true), "own");
        assert_eq!(BehaviorKey::Group.value(false), "mask");

        let _ = fs::remove_dir_all(&dir);
    }

    /// 非 UTF-8 文件必须报错而不是当成空文件：旧实现会把整个配置替换成一条规则
    #[test]
    fn undecodable_config_is_not_truncated() {
        let dir = format!("/tmp/appopt_edit_gbk_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);
        // GBK 编码的「# 你好」注释，第二个字节起不是合法 UTF-8
        let raw = [0x23, 0x20, 0xc4, 0xe3, 0xba, 0xc3, 0x0a];
        fs::write(&conf, raw).unwrap();

        assert!(matches!(
            rule_upsert(&conf, "com.test.app", "", "0-1"),
            RuleEdit::IoErr
        ));
        assert!(matches!(
            rule_delete(&conf, "com.test.app", ""),
            RuleEdit::IoErr
        ));
        assert_eq!(fs::read(&conf).unwrap(), raw, "读失败时不得改写原文件");

        // 不存在的文件仍然按空配置新建，保持首次使用的行为
        let fresh = format!("{}/fresh.conf", dir);
        assert!(matches!(
            rule_upsert(&fresh, "com.test.app", "", "0-1"),
            RuleEdit::Ok
        ));
        assert!(
            fs::read_to_string(&fresh)
                .unwrap()
                .contains("com.test.app=0-1")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tmp_symlink_does_not_redirect_write() {
        let dir = format!("/tmp/appopt_edit_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);
        let victim = format!("{}/victim.conf", dir);
        fs::write(&victim, "original\n").unwrap();
        std::os::unix::fs::symlink(&victim, format!("{}.tmp", conf)).unwrap();

        // 临时文件被换成指向外部文件的符号链接时，写入必须失败且不碰目标
        assert!(matches!(
            rule_upsert(&conf, "com.test.app", "", "0-1"),
            RuleEdit::IoErr
        ));
        assert_eq!(fs::read_to_string(&victim).unwrap(), "original\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rt_directives_write_update_and_delete() {
        let dir = format!("/tmp/appopt_rt_edit_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);
        fs::write(&conf, "@unmatched=keep\ncom.a=0-1\n").unwrap();

        assert!(matches!(
            rt_configure(&conf, "per_app", Some(2), Some(3)),
            RuleEdit::Ok
        ));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@rt=per_app"));
        assert!(s.contains("@rt.max=2"));
        assert!(s.contains("@rt.timeslice=3"));
        assert!(s.contains("com.a=0-1"));

        // 条目追加后重复写入应就地更新，而不是堆积多行
        assert!(matches!(rt_app_set(&conf, "com.a", "auto 2"), RuleEdit::Ok));
        assert!(matches!(
            rt_app_set(&conf, "com.a", "names:RenderThread 1"),
            RuleEdit::Ok
        ));
        let s = fs::read_to_string(&conf).unwrap();
        assert_eq!(s.matches("@rt.app=com.a").count(), 1);
        assert!(s.contains("@rt.app=com.a names:RenderThread 1"));

        // 模式切换时旧值被替换，全局指令不重复
        assert!(matches!(
            rt_configure(&conf, "global", None, None),
            RuleEdit::Ok
        ));
        let s = fs::read_to_string(&conf).unwrap();
        assert_eq!(s.matches("@rt=").count(), 1);
        assert!(s.contains("@rt=global"));
        assert!(s.contains("@rt.max=2"));

        // 空 spec 表示删除条目
        assert!(matches!(rt_app_set(&conf, "com.a", ""), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(!s.contains("@rt.app=com.a"));

        let _ = fs::remove_dir_all(&dir);
    }

    /// 删掉最后一个启用条目后 @rt 收回 off，避免空转改写内核时间片；
    /// global 是显式策略，不能因为删条目被降级
    #[test]
    fn deleting_last_rt_app_retracts_scope() {
        let dir = format!("/tmp/appopt_rt_del_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);

        fs::write(&conf, "@rt=per_app\n@rt.app=com.a on auto\ncom.a=0-1\n").unwrap();
        assert!(matches!(rt_app_set(&conf, "com.a", ""), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(!s.contains("@rt.app="));
        assert!(s.contains("@rt=off"), "最后一个条目删除后应收敛为 off");

        // 还有别的启用条目时不动 @rt
        fs::write(
            &conf,
            "@rt=per_app\n@rt.app=com.a on auto\n@rt.app=com.b on auto\n",
        )
        .unwrap();
        assert!(matches!(rt_app_set(&conf, "com.a", ""), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@rt=per_app"));

        // global 不降级
        fs::write(&conf, "@rt=global\n@rt.app=com.a on auto\n").unwrap();
        assert!(matches!(rt_app_set(&conf, "com.a", ""), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@rt=global"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rt_toggle_opens_with_defaults_and_restores_scope() {
        let dir = format!("/tmp/appopt_rt_toggle_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);
        fs::write(&conf, "com.a=0-1\ncom.b=0-1\n").unwrap();

        // 首次开启：写 per_app + on auto，不写 max/timeslice，沿用缺省 2/3
        assert!(matches!(rt_toggle(&conf, "com.a", true), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@rt=per_app"));
        assert!(s.contains("@rt.app=com.a on auto"));
        assert!(!s.contains("@rt.max"));
        assert!(!s.contains("@rt.timeslice"));

        // 第二个应用：不重复写 @rt，各自一条
        assert!(matches!(rt_toggle(&conf, "com.b", true), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert_eq!(s.matches("@rt=").count(), 1);
        assert_eq!(s.matches("@rt.app=").count(), 2);

        // 关掉一个：条目变 off，仍留 per_app（com.b 还在开）
        assert!(matches!(rt_toggle(&conf, "com.a", false), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@rt.app=com.a off auto"));
        assert!(s.contains("@rt=per_app"));

        // 关掉最后一个：@rt 收回 off，避免空转改写内核时间片
        assert!(matches!(rt_toggle(&conf, "com.b", false), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@rt=off"));
        assert_eq!(s.matches("@rt=").count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rt_toggle_keeps_custom_mode_and_dedups() {
        let dir = format!("/tmp/appopt_rt_toggle2_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);
        // 手工调过的模式与上限，按钮开关不应覆盖
        fs::write(
            &conf,
            "@rt=per_app\n@rt.app=com.a off names:RenderThread,RHI* 5\ncom.a=0-1\n",
        )
        .unwrap();

        assert!(matches!(rt_toggle(&conf, "com.a", true), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@rt.app=com.a on names:RenderThread,RHI* 5"));
        assert_eq!(s.matches("@rt.app=com.a").count(), 1);

        // 重复开启不堆行
        assert!(matches!(rt_toggle(&conf, "com.a", true), RuleEdit::Ok));
        assert_eq!(
            fs::read_to_string(&conf)
                .unwrap()
                .matches("@rt.app=com.a")
                .count(),
            1
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// @sched 是单值指令：重复写只留一条，已有注释要跟着走
    #[test]
    fn sched_set_rewrites_single_line() {
        let dir = format!("/tmp/appopt_sched_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);
        fs::write(&conf, "@unmatched=keep\ncom.a=0-1\n").unwrap();

        assert!(matches!(sched_set(&conf, "shadow"), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@sched=shadow"));
        // 新键插在指令区，不跑到规则后面
        assert!(s.find("@sched=shadow").unwrap() < s.find("com.a=0-1").unwrap());

        // 改档不新增第二行
        assert!(matches!(sched_set(&conf, "on"), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert_eq!(s.matches("@sched=").count(), 1);
        assert!(s.contains("@sched=on"));

        // 行尾注释保留
        fs::write(&conf, "@sched=on  # 手写备注\ncom.a=0-1\n").unwrap();
        assert!(matches!(sched_set(&conf, "off"), RuleEdit::Ok));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@sched=off  # 手写备注"));

        let _ = fs::remove_dir_all(&dir);
    }

    /// 进阶三项一次写盘：只动传入的键，其余保持不变
    #[test]
    fn adv_configure_only_touches_given_keys() {
        let dir = format!("/tmp/appopt_adv_{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = format!("{}/applist.conf", dir);
        fs::write(&conf, "@rt=per_app\ncom.a=0-1\n").unwrap();

        // 只改 unmatched：不应凭空写出 rt.max / rt.timeslice
        assert!(matches!(
            adv_configure(&conf, Some("all"), None, None, None),
            RuleEdit::Ok
        ));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@unmatched=all"));
        assert!(!s.contains("@rt.max"));
        assert!(!s.contains("@rt.timeslice"));
        assert!(s.contains("@rt=per_app"));

        // 三项同写：一次落盘，各一条
        assert!(matches!(
            adv_configure(&conf, Some("keep"), Some(4), Some(6), None),
            RuleEdit::Ok
        ));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@unmatched=keep"));
        assert!(s.contains("@rt.max=4"));
        assert!(s.contains("@rt.timeslice=6"));
        assert_eq!(s.matches("@rt.max=").count(), 1);

        // 空参数不动文件
        let before = fs::read_to_string(&conf).unwrap();
        assert!(matches!(
            adv_configure(&conf, None, None, None, None),
            RuleEdit::Ok
        ));
        assert_eq!(before, fs::read_to_string(&conf).unwrap());

        // sysgroup 独立写入：切换策略要替换原行而不是追加，
        // 否则配置里会留下两条互相矛盾的 @sysgroup，解析取最后一条
        assert!(matches!(
            adv_configure(&conf, None, None, None, Some("takeover")),
            RuleEdit::Ok
        ));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@sysgroup=takeover"));
        assert!(matches!(
            adv_configure(&conf, None, None, None, Some("respect")),
            RuleEdit::Ok
        ));
        let s = fs::read_to_string(&conf).unwrap();
        assert!(s.contains("@sysgroup=respect"));
        assert!(!s.contains("@sysgroup=takeover"));
        assert_eq!(s.matches("@sysgroup=").count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
