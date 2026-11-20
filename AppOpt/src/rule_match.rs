use std::ffi::CString;

use crate::MAX_THREAD_LEN;
use crate::apply_affinity::read_cmdline;
use crate::config::AppConfig;
use crate::cpuset::CpuSet;

/// 线程亲和性计算结果
pub struct AffinityResult {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 线程规则 CPU 累加，无线程匹配走包级 fallback，仍无则返回 None
pub fn thread_affinity(
    pkg: &str,
    thread: &str,
    cfg: &AppConfig,
) -> Option<AffinityResult> {
    let mut cpus = CpuSet::new();
    let mut cpuset_dir = String::new();
    let mut matched = false;

    if !thread.is_empty() {
        for rule in &cfg.rules {
            if rule.pkg != pkg || rule.thread.is_empty() {
                continue;
            }
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
        for rule in &cfg.rules {
            if rule.pkg != pkg || !rule.thread.is_empty() {
                continue;
            }
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
        if cfg.has_thread_rules.contains(pkg) {
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
    unsafe { libc::fnmatch(pattern.as_ptr(), buf.as_ptr() as *const _, libc::FNM_NOESCAPE) == 0 }
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
    // 键只表示“某包名的前/后 15 字节与之相同”，仍需 cmdline 确认是本进程
    read_cmdline(pid).filter(|name| cfg.pkgs.contains(name))
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
}
