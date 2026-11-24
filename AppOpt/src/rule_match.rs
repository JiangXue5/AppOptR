use std::ffi::CString;

use crate::MAX_THREAD_LEN;
use crate::apply_affinity::{pkg_owned, read_cmdline};
use crate::config::{AppConfig, MatchSpecificity};
use crate::cpuset::CpuSet;

/// 线程亲和性计算结果
pub struct AffinityResult<'a> {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
    /// 命中的最高档位。无命中、或只命中包级规则时为 `PackageFallback`
    pub spec: MatchSpecificity,
    /// 该档位命中了几条规则。>1 说明发生了同档 OR 合并，日志要写明
    pub hits: usize,
    /// 命中的最高档里第一条规则的原 pattern，仅用于日志。
    /// 指向 `cfg.rules`，不额外分配
    pub hit_pattern: Option<&'a str>,
}

/// 线程规则匹配：先取最高具体度，再在**同档内**取并集。
///
/// 旧实现把所有命中规则无条件 OR。冲突配置下（`RenderThread=6-7` 与
/// `Render*=0-3`）会得到 0-7——谁都没写过的集合，而且还把用户明确指定
/// 的 6-7 稀释掉了。分档之后：
/// - 精确命中就只认精确规则；
/// - 只有同档多条规则才合并，这是用户已经依赖的语义，不能动；
/// - 全部不命中才落到包级兜底。
pub fn thread_affinity<'a>(
    pkg: &str,
    thread: &str,
    cfg: &'a AppConfig,
) -> Option<AffinityResult<'a>> {
    let pkg_rules = cfg.rule_index.get(pkg)?;

    let mut cpus = CpuSet::new();
    let mut cpuset_dir = String::new();
    let mut best: Option<MatchSpecificity> = None;
    let mut hits = 0usize;
    let mut hit_pattern: Option<&str> = None;

    if !thread.is_empty() {
        // 只遍历该包的线程规则，不再线性扫描全部规则
        for &i in &pkg_rules.thread_rules {
            let rule = &cfg.rules[i];
            if !fnmatch_c(&rule.thread_pattern, thread) {
                continue;
            }
            match best {
                // 更具体的档位出现：丢掉低档已经累积的集合，重新开始
                Some(b) if rule.spec > b => {
                    cpus = rule.cpus;
                    best = Some(rule.spec);
                    hits = 1;
                    hit_pattern = Some(&rule.thread);
                }
                Some(b) if rule.spec == b => {
                    cpus.or(&rule.cpus);
                    hits += 1;
                }
                Some(_) => {}
                None => {
                    cpus = rule.cpus;
                    best = Some(rule.spec);
                    hits = 1;
                    hit_pattern = Some(&rule.thread);
                }
            }
        }
        // 目录名按合并后的 CPU 集合派生，保证与亲和性一致；
        // 真正建目录由执行层负责，决策路径不产生文件系统副作用
        if best.is_some() && cfg.topo.cpuset_enabled {
            cpuset_dir = cpus.to_range_string();
        }
    }

    let matched = best.is_some();
    if !matched {
        let mut fallback_seen = false;
        for &i in &pkg_rules.pkg_rules {
            let rule = &cfg.rules[i];
            cpus.or(&rule.cpus);
            hits += 1;
            if !fallback_seen {
                cpuset_dir = rule.cpuset_dir.clone();
                fallback_seen = true;
            } else {
                cpuset_dir.clear();
            }
        }
    }
    let spec = best.unwrap_or(MatchSpecificity::PackageFallback);

    if cpus.count() == 0 {
        // 包内存在线程规则但本线程未命中，且无包级规则：
        // keep 保持原亲和性不干预，all 沿用旧行为设为全部核心
        if cfg.has_thread_rules.contains(pkg) && cfg.unmatched_all {
            return Some(AffinityResult {
                cpus: cfg.topo.present_cpus,
                cpuset_dir: String::new(),
                is_thread_rule: false,
                spec: MatchSpecificity::PackageFallback,
                hits: 0,
                hit_pattern: None,
            });
        }
        None
    } else {
        Some(AffinityResult {
            cpus,
            cpuset_dir,
            is_thread_rule: matched,
            spec,
            hits,
            hit_pattern,
        })
    }
}

/// POSIX fnmatch 封装，需预转换为 CString
fn fnmatch_c(pattern: &CString, string: &str) -> bool {
    if string.len() >= MAX_THREAD_LEN {
        return false;
    }
    let mut buf = [0u8; MAX_THREAD_LEN];
    buf[..string.len()].copy_from_slice(string.as_bytes());
    unsafe {
        libc::fnmatch(
            pattern.as_ptr(),
            buf.as_ptr() as *const _,
            libc::FNM_NOESCAPE,
        ) == 0
    }
}

/// 通过内核 comm 匹配配置包名
pub fn comm_to_pkg(pid: i32, comm: &str, cfg: &AppConfig) -> Option<String> {
    if cfg.pkgs.contains(comm) {
        return Some(comm.to_string());
    }
    // comm 不到 15 字节说明未被截断，精确匹配未命中即无候选
    if comm.len() < 15 {
        return None;
    }
    let key: [u8; 15] = comm.as_bytes()[..15].try_into().ok()?;
    if !cfg.trunc_keys.contains(&key) {
        return None;
    }
    // 键只表示“某包名的前/后 15 字节与之相同”，仍需 cmdline 确认是本进程，
    // 再用目录属主确认这个包名不是自己改出来的
    read_cmdline(pid).filter(|name| cfg.pkgs.contains(name) && pkg_owned(pid, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpuset::init_cpu_topo;

    /// 每个用例独占配置文件，避免并行测试互相覆盖
    fn cfg_with(name: &str, conf: &str) -> AppConfig {
        let p = format!("/tmp/appopt_test_{}.conf", name);
        std::fs::write(&p, conf).unwrap();
        let topo = init_cpu_topo();
        let mut m = -1i64;
        crate::config::load_config(&p, &topo, &mut m).unwrap()
    }

    #[test]
    fn exact_match_wins() {
        let cfg = cfg_with("exact", "com.test.applications=0-1\n");
        assert_eq!(
            comm_to_pkg(1, "com.test.applications", &cfg).as_deref(),
            Some("com.test.applications")
        );
    }

    #[test]
    fn short_comm_without_truncation_returns_none() {
        let cfg = cfg_with("short", "com.test.applications=0-1\n");
        // 不到 15 字节说明 comm 未被截断，精确未命中即无候选，不读 cmdline
        assert_eq!(comm_to_pkg(1, "workerthread-01", &cfg), None);
    }

    #[test]
    fn truncated_key_miss_returns_none() {
        let cfg = cfg_with("miss", "com.test.applications=0-1\n");
        let cfg2 = cfg_with("miss2", "com.tencent.tmgp.sgame=0-1\n");
        // 21 字节包名：前缀 15 与后缀 15 各一键
        assert_eq!(cfg.trunc_keys.len(), 2);
        // 15 字节但既非任何包名前缀也非后缀
        assert_eq!(comm_to_pkg(1, "com.other.applic", &cfg), None);
        // 前缀键与后缀键都要建
        assert!(cfg2.trunc_keys.contains(b"cent.tmgp.sgame"));
        assert!(cfg2.trunc_keys.contains(b"com.tencent.tmg"));
    }

    #[test]
    fn truncated_key_hit_still_verified_by_cmdline() {
        let cfg = cfg_with("verify", "com.test.applications=0-1\n");
        // 键命中，但 pid 1 的 cmdline 不是目标包，必须被否决
        assert_eq!(comm_to_pkg(1, "com.test.applic", &cfg), None);
    }

    #[test]
    fn truncated_key_hit_real_process() {
        let cfg = cfg_with("real", "com.test.applications=0-1\n");
        let bin = "/tmp/com.test.applications";
        std::fs::copy("/bin/sleep", bin).expect("复制测试进程失败");
        let mut child = std::process::Command::new(bin)
            .arg("30")
            .spawn()
            .expect("启动测试进程失败");
        std::thread::sleep(std::time::Duration::from_millis(300));
        // comm 为首 15 字节，cmdline 可确认真实包名
        let got = comm_to_pkg(child.id() as i32, "com.test.applic", &cfg);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(got.as_deref(), Some("com.test.applications"));
    }

    #[test]
    fn unmatched_thread_keeps_affinity_by_default() {
        let cfg = cfg_with("keep", "com.test.game {\n  RenderThread=0-1\n}\n");
        // 未命中任何线程规则，包内也没有包级规则：默认 keep 不返回任何目标
        assert!(thread_affinity("com.test.game", "Worker-9", &cfg).is_none());
        assert!(!cfg.unmatched_all);
    }

    #[test]
    fn unmatched_all_directive_restores_old_behavior() {
        let cfg = cfg_with(
            "all",
            "@unmatched=all\ncom.test.game {\n  RenderThread=0-1\n}\n",
        );
        let got = thread_affinity("com.test.game", "Worker-9", &cfg).expect("all 应返回全部核心");
        assert!(cfg.unmatched_all);
        assert_eq!(got.cpus, cfg.topo.present_cpus);
        assert!(!got.is_thread_rule);
    }

    #[test]
    fn unknown_directive_does_not_drop_rules() {
        // PARSE_FAILS 是进程级全局量，并行测试下不可断言，这里只校验规则仍能加载
        let cfg = cfg_with("baddir", "@unknown=1\ncom.test.game=0-1\n");
        assert_eq!(cfg.rules.len(), 1);
        assert!(!cfg.unmatched_all);
    }

    #[test]
    fn rule_index_limits_rules_to_same_pkg() {
        let cfg = cfg_with(
            "index",
            "com.a {\n  RenderThread=0-1\n}\ncom.b {\n  RenderThread=2-3\n}\n",
        );
        let a = thread_affinity("com.a", "RenderThread", &cfg).unwrap();
        assert_eq!(a.cpus.to_range_string(), "0-1");
        let b = thread_affinity("com.b", "RenderThread", &cfg).unwrap();
        assert_eq!(b.cpus.to_range_string(), "2-3");
        assert_eq!(cfg.rule_index["com.a"].thread_rules.len(), 1);
        assert_eq!(cfg.rule_index["com.a"].pkg_rules.len(), 0);
    }

    #[test]
    fn pkg_signature_ignores_rule_order_but_detects_changes() {
        let cfg1 = cfg_with("sig1", "com.a {\n  A=0-1\n  B=2-3\n}\n");
        let cfg2 = cfg_with("sig2", "com.a {\n  B=2-3\n  A=0-1\n}\n");
        let cfg3 = cfg_with("sig3", "com.a {\n  A=0-1\n  B=2-4\n}\n");
        assert_eq!(cfg1.pkg_sig["com.a"], cfg2.pkg_sig["com.a"]);
        assert_ne!(cfg1.pkg_sig["com.a"], cfg3.pkg_sig["com.a"]);
    }

    /// 旧实现：所有命中规则无条件 OR。对照测试的基准
    fn legacy_cpus(pkg: &str, thread: &str, cfg: &AppConfig) -> Option<CpuSet> {
        let pr = cfg.rule_index.get(pkg)?;
        let mut cpus = CpuSet::new();
        if !thread.is_empty() {
            for &i in &pr.thread_rules {
                let r = &cfg.rules[i];
                if fnmatch_c(&r.thread_pattern, thread) {
                    cpus.or(&r.cpus);
                }
            }
        }
        if cpus.count() == 0 {
            for &i in &pr.pkg_rules {
                cpus.or(&cfg.rules[i].cpus);
            }
        }
        (cpus.count() > 0).then_some(cpus)
    }

    /// 把 glob 变成一个能命中它的具体线程名：`*`→`1`、`?`→`7`、
    /// `[0-9]`→`1`。用于给样本配置生成「真实会出现的线程名」
    fn sample_of(pattern: &str) -> String {
        let bytes: Vec<char> = pattern.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                '*' => out.push('1'),
                '?' => out.push('7'),
                '[' => {
                    // 找到字符类结尾，取第一个可用字符。`[!a]`/`[^a]`
                    // 这类否定类不能取被排除的字符，取 'z' 避开常见排除集
                    let mut j = i + 1;
                    while j < bytes.len() && bytes[j] != ']' {
                        j += 1;
                    }
                    if j >= bytes.len() {
                        out.push('['); // 未闭合，原样保留
                        i += 1;
                        continue;
                    }
                    let body: String = bytes[i + 1..j].iter().collect();
                    let negated = body.starts_with('!') || body.starts_with('^');
                    if negated {
                        out.push('z');
                    } else if let Some(c) = body.chars().next() {
                        // `a-z` 取 'a'；单字符类取它自己
                        out.push(c);
                    }
                    i = j + 1;
                    continue;
                }
                c => out.push(c),
            }
            i += 1;
        }
        out
    }

    /// 方案 9.3 的硬要求：用现有配置样本对照，无跨档冲突时结果必须完全一致。
///
    /// 两个样本都来自仓库实际分发的配置（`module/`），覆盖「包级 + 线程规则」、
    /// `Thread-[0-9]?` / `Thread-?` / `RenderThread*` 这些真实写法
    #[test]
    fn shipped_samples_match_legacy_affinity() {
        let topo = init_cpu_topo();
        for path in [
            "../module/applist.conf",
            "../module/applist.asoulopt.conf",
        ] {
            let mut mtime = -1i64;
            let Some(cfg) = crate::config::load_config(path, &topo, &mut mtime) else {
                panic!("{} 应能解析", path);
            };

            let mut checked = 0usize;
            let mut diffs: Vec<String> = Vec::new();
            for (pkg, pr) in &cfg.rule_index {
                let mut names: Vec<String> = pr
                    .thread_rules
                    .iter()
                    .map(|&i| sample_of(&cfg.rules[i].thread))
                    .collect();
                names.push("main".to_string());
                names.push("Worker-1".to_string());
                for name in names {
                    checked += 1;
                    let old = legacy_cpus(pkg, &name, &cfg);
                    let new = thread_affinity(pkg, &name, &cfg).map(|r| r.cpus);
                    if old != new {
                        diffs.push(format!(
                            "{}:{} 旧 {:?} 新 {:?}",
                            pkg,
                            name,
                            old.map(|s| s.to_range_string()),
                            new.map(|s| s.to_range_string())
                        ));
                    }
                }
            }
            assert!(checked > 50, "{} 样本太小：{}", path, checked);
            assert!(
                diffs.is_empty(),
                "{}：{} 处结果改变，前 5 条 {:?}",
                path,
                diffs.len(),
                &diffs[..diffs.len().min(5)]
            );
        }
    }

    /// 跨档冲突时的预期行为：精确规则胜出，不再被通配规则稀释
    #[test]
    fn exact_rule_beats_star_rule_instead_of_union() {
        let cfg = cfg_with(
            "spec_conflict",
            "com.x {\n  RenderThread=6-7\n  Render*=0-3\n}\n",
        );
        let r = thread_affinity("com.x", "RenderThread", &cfg).unwrap();
        assert_eq!(r.cpus.to_range_string(), "6-7", "精确规则必须独占");
        assert_eq!(r.spec, crate::config::MatchSpecificity::Exact);
        assert_eq!(r.hits, 1);
        assert_eq!(r.hit_pattern, Some("RenderThread"));

        // 只命中通配的线程仍按通配走
        let r = thread_affinity("com.x", "RenderFoo", &cfg).unwrap();
        assert_eq!(r.cpus.to_range_string(), "0-3");
        assert_eq!(r.spec, crate::config::MatchSpecificity::StarWildcard);
    }

    /// 同档多条规则继续 OR：这是用户已经依赖的语义，不能被优先级改掉
    #[test]
    fn same_tier_rules_still_union() {
        let cfg = cfg_with(
            "spec_same",
            "com.x {\n  Unity*=4-5\n  Unity*=6-7\n}\n",
        );
        let r = thread_affinity("com.x", "UnityMain", &cfg).unwrap();
        assert_eq!(r.cpus.to_range_string(), "4-7");
        assert_eq!(r.hits, 2, "两条同档规则都应参与");
        assert_eq!(r.spec, crate::config::MatchSpecificity::StarWildcard);
    }

    /// 分档判定的边界：`[...]` 比 `?` 具体，`*` 一出现就压到最低档
    #[test]
    fn spec_of_pattern_orders_by_shape() {
        use crate::config::MatchSpecificity as S;
        assert_eq!(crate::config::spec_of_pattern("RenderThread"), S::Exact);
        assert_eq!(crate::config::spec_of_pattern("Thread-[0-9]?"), S::Range);
        assert_eq!(crate::config::spec_of_pattern("Thread-?"), S::QuestionWildcard);
        assert_eq!(crate::config::spec_of_pattern("Thread-*"), S::StarWildcard);
        // `*` 能吞掉任意长度，字符类具体度不再成立
        assert_eq!(crate::config::spec_of_pattern("[0-9]*"), S::StarWildcard);

        assert!(S::Exact > S::Range);
        assert!(S::Range > S::QuestionWildcard);
        assert!(S::QuestionWildcard > S::StarWildcard);
        assert!(S::StarWildcard > S::PackageFallback);
    }

    #[test]
    #[ignore = "性能测量，手动运行：cargo test bench_rule_decision -- --ignored --nocapture"]
    fn bench_rule_decision_200_rules() {
        // 20 个包 × 11 条线程规则 = 220 条
        let mut conf = String::new();
        for p in 0..20 {
            conf.push_str(&format!("com.bench.p{:02} {{\n", p));
            for t in 0..10 {
                conf.push_str(&format!("  Thread-{}=0-7\n", t));
            }
            conf.push_str("}\n");
        }
        let cfg = cfg_with("bench", &conf);
        assert!(cfg.rules.len() >= 200);
        const N: u32 = 200_000;

        let t0 = std::time::Instant::now();
        for _ in 0..N {
            std::hint::black_box(thread_affinity("com.bench.p10", "Thread-3", &cfg));
        }
        let hit = t0.elapsed().as_nanos() as f64 / N as f64;

        let t1 = std::time::Instant::now();
        for _ in 0..N {
            std::hint::black_box(thread_affinity("com.bench.p10", "Worker-9", &cfg));
        }
        let miss = t1.elapsed().as_nanos() as f64 / N as f64;

        println!(
            "{} 条规则：命中线程 {:.0} ns/次，未命中线程 {:.0} ns/次",
            cfg.rules.len(),
            hit,
            miss
        );
    }
}
