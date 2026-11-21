use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::sync::Mutex;

use crate::config::{close_like, comment_at, parse_outer, split_rule_line, split_single_line, strip_comment, OuterLine};

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
                        t.threads.entry(name.to_string()).or_default().push(ThreadLoc {
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
            OuterLine::Single { pkg: pg, thread: th, open, .. } => {
                pending = None;
                if pg == pkg && !th.is_empty() {
                    t.threads.entry(th.to_string()).or_default().push(ThreadLoc {
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
        && (items.iter().any(|(l, _)| l.open) || !matches!(t.pkg_line, None | Some(PkgLine::Standalone(_))))
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
    if pkg.contains('=') { format!("{pkg}= {{") } else { format!("{pkg} {{") }
}

fn with_comment(new_line: &str, old: &str) -> String {
    match comment_at(old) {
        Some(at) => format!("{}{}", new_line, &old[at..]),
        None => new_line.to_string(),
    }
}

fn spec_swap(raw: &str, cpus: &str) -> String {
    let cut = comment_at(raw).unwrap_or(raw.len());
    let Some(eq) = raw[..cut].rfind('=') else { return raw.into() };
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

fn file_write(path: &str, lines: &[String]) -> RuleEdit {
    use std::os::unix::fs::OpenOptionsExt;

    let mut out = lines.join("\n");
    out.push('\n');
    let tmp = format!("{}.tmp", path);
    // 配置目录可能位于共享存储，临时文件用 O_NOFOLLOW 打开，
    // 防止预先放置的同名符号链接把这次写入引到白名单之外
    let res = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .and_then(|mut f| {
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
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
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
                    && matches!(parse_outer(lines[open].trim()), OuterLine::BareOpen { pkg: "" })
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
        lines.splice(i + 1..i + 1, [format!("\t{}={}", thread, cpus), "}".to_string()]);
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
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
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
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
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
                .or_else(|| t.threads.values().flatten().filter(|l| !l.single).map(|l| l.idx).max())
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
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
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
    let mut lines = read_lines(path);
    directive_put(&mut lines, "rt", Some(mode));
    if let Some(m) = max {
        directive_put(&mut lines, "rt.max", Some(&m.to_string()));
    }
    if let Some(t) = timeslice {
        directive_put(&mut lines, "rt.timeslice", Some(&t.to_string()));
    }
    file_write(path, &lines)
}

fn read_lines(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

/// 写或删除 `@rt.app=<包名> ...`。`spec` 为空表示删除该条目
pub fn rt_app_set(path: &str, pkg: &str, spec: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines = read_lines(path);
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
    file_write(path, &lines)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
