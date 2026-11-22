use std::ffi::CString;

use crate::MAX_THREAD_LEN;
use crate::apply_affinity::{pkg_owned, read_cmdline};
use crate::config::AppConfig;
use crate::cpuset::CpuSet;

/// 线程亲和性计算结果
pub struct AffinityResult {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 线程规则 CPU 累加，无线程匹配走包级 fallback，仍无则按 keep/all 语义处理
pub fn thread_affinity(pkg: &str, thread: &str, cfg: &AppConfig) -> Option<AffinityResult> {
    let pkg_rules = cfg.rule_index.get(pkg)?;

    let mut cpus = CpuSet::new();
    let mut cpuset_dir = String::new();
    let mut matched = false;

    if !thread.is_empty() {
        // 只遍历该包的线程规则，不再线性扫描全部规则
        for &i in &pkg_rules.thread_rules {
            let rule = &cfg.rules[i];
            if fnmatch_c(&rule.thread_pattern, thread) {
                cpus.or(&rule.cpus);
                matched = true;
            }
        }
        // 目录名按合并后的 CPU 集合派生，保证与亲和性一致；
        // 真正建目录由执行层负责，决策路径不产生文件系统副作用
        if matched && cfg.topo.cpuset_enabled {
            cpuset_dir = cpus.to_range_string();
        }
    }

    if !matched {
        let mut fallback_seen = false;
        for &i in &pkg_rules.pkg_rules {
            let rule = &cfg.rules[i];
            cpus.or(&rule.cpus);
            if !fallback_seen {
                cpuset_dir = rule.cpuset_dir.clone();
                fallback_seen = true;
            } else {
                cpuset_dir.clear();
            }
        }
    }

    if cpus.count() == 0 {
        // 包内存在线程规则但本线程未命中，且无包级规则：
        // keep 保持原亲和性不干预，all 沿用旧行为设为全部核心
        if cfg.has_thread_rules.contains(pkg) && cfg.unmatched_all {
            return Some(AffinityResult {
                cpus: cfg.topo.present_cpus,
                cpuset_dir: String::new(),
                is_thread_rule: false,
            });
        }
        None
    } else {
        Some(AffinityResult {
            cpus,
            cpuset_dir,
            is_thread_rule: matched,
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
