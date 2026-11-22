use std::collections::HashMap;

use crate::apply_affinity::{AffinityOutcome, ApplyReason, affinity_apply};
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology, SysGroup};
use crate::rule_match::{comm_to_pkg, thread_affinity};

pub struct TaskEntry {
    pub pid: i32,
    pub pkg: String,
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
    /// 线程名。S7 判定角色、RT 匹配模式都要用，不再回读 /proc
    pub comm: String,
    /// 本进程是否成功把该线程写到过目标集合。为 false 时读回不一致是
    /// 「还没绑上」而不是「被外部改写」，不能记成漂移
    pub applied: bool,
    /// 线程所在的系统 cpuset 组。系统改组配置时会重置组内所有线程的亲和性，
    /// 只有接管到自己组里才不受影响
    pub group: SysGroup,
    /// 目标集合与所在组的生效集合没有交集：写 cpuset 与 sched_setaffinity
    /// 都会被内核拒绝，继续尝试只会产生无效迁移
    pub blocked: bool,
}

/// 系统把线程压在小核是有意的：省电，也不让后台抢前台的核。强行抬到大核
/// 会与 cgroup 生效集合冲突，表现为持续 EINVAL 与无效重绑。只有目标集合
/// 与该组仍有交集时才值得绑（例如规则本来就写 0-3）
fn background_blocked(tid: i32, cpus: &CpuSet, group: SysGroup) -> bool {
    if !group.is_background() {
        return false;
    }
    let Some(path) = crate::cpuset::thread_cgroup(tid) else {
        return false;
    };
    let eff = crate::cpuset::group_effective(&path);
    blocked_by_group(group, cpus, eff.as_deref())
}

/// 判定逻辑单独抽出来：只有「后台组 + 读得到生效集合 + 交集为空」三者同时成立，
/// 才认定内核必然拒绝。读不到生效集合时不能猜，否则会把前台线程误判成不可绑
fn blocked_by_group(group: SysGroup, want: &CpuSet, eff: Option<&str>) -> bool {
    if !group.is_background() {
        return false;
    }
    let Some(eff) = eff else {
        return false;
    };
    let eff_set = crate::cpuset::parse_cpu_ranges(eff, None);
    if eff_set.count() == 0 {
        return false;
    }
    let mut inter = *want;
    inter.and(&eff_set);
    inter.count() == 0
}

/// 双模式共用进程缓存，eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub tasks: HashMap<i32, TaskEntry>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.tasks.clear();
    }

    pub fn task_del(&mut self, tid: i32) {
        self.tasks.remove(&tid);
    }

    /// 进程退出时清理其全部线程
    pub fn purge_pid(&mut self, pid: i32) {
        self.tasks.retain(|_, e| e.pid != pid);
    }

    /// 包规则变更时清理该包全部线程，返回被清理的 tid 供调用方同步内核表
    pub fn purge_pkg(&mut self, pkg: &str) -> Vec<i32> {
        let stale: Vec<i32> = self
            .tasks
            .iter()
            .filter(|(_, e)| e.pkg == pkg)
            .map(|(&tid, _)| tid)
            .collect();
        for tid in &stale {
            self.tasks.remove(tid);
        }
        stale
    }

    /// comm 匹配包名，线程名时回退主线程条目
    pub fn pkg_lookup_comm(&self, pid: i32, comm: &str, cfg: &AppConfig) -> Option<String> {
        comm_to_pkg(pid, comm, cfg).or_else(|| self.tasks.get(&pid).map(|e| e.pkg.clone()))
    }

    /// 计算并应用线程亲和性，保护已有线程规则绑定防止降级
    pub fn task_apply<F>(
        &mut self,
        tid: i32,
        pid: i32,
        pkg: &str,
        comm: &str,
        cfg: &AppConfig,
        apply_fn: F,
    ) -> bool
    where
        F: FnOnce(i32, &CpuSet, &str, bool) -> AffinityOutcome,
    {
        let thread_name = if cfg.has_thread_rules.contains(pkg) {
            comm
        } else {
            ""
        };
        let Some(result) = thread_affinity(pkg, thread_name, cfg) else {
            return false;
        };

        if !result.is_thread_rule && self.tasks.get(&tid).is_some_and(|old| old.is_thread_rule) {
            return true;
        }

        // 规则没变、且确实写过：这次不是「首次绑定」而是「复核」。
        // 复核必须走校验语义，才能把「被外部改写」记成漂移而不是正常写入
        let prev = self.tasks.get(&tid);
        let recheck = prev.is_some_and(|old| old.applied && old.cpus == result.cpus);
        let prev_applied = prev.is_some_and(|old| old.applied);
        // 组归属只在首次接管时读一次：/proc/<tid>/cgroup 一次 open，
        // 之后跟着缓存走，不会变成每轮开销
        let (group, blocked) = match prev {
            Some(old) => (old.group, old.blocked),
            None => {
                let g = crate::cpuset::thread_group(tid);
                (g, background_blocked(tid, &result.cpus, g))
            }
        };
        if cfg.sysgroup_respect && blocked {
            crate::diag::note_sysgroup_skip(tid, comm, group, &result.cpus);
            self.tasks.insert(
                tid,
                TaskEntry {
                    pid,
                    pkg: pkg.to_string(),
                    cpus: result.cpus,
                    cpuset_dir: result.cpuset_dir,
                    is_thread_rule: result.is_thread_rule,
                    comm: comm.to_string(),
                    applied: false,
                    group,
                    blocked: true,
                },
            );
            return true;
        }
        let outcome = apply_fn(tid, &result.cpus, &result.cpuset_dir, recheck);
        if outcome == AffinityOutcome::Gone {
            self.tasks.remove(&tid);
            return false;
        }
        // 失败时不能把「之前绑上了」改成「没绑上」，否则下一轮又按首次绑定处理
        let applied = if outcome == AffinityOutcome::Set {
            true
        } else {
            prev_applied
        };

        self.tasks.insert(
            tid,
            TaskEntry {
                pid,
                pkg: pkg.to_string(),
                cpus: result.cpus,
                cpuset_dir: result.cpuset_dir,
                is_thread_rule: result.is_thread_rule,
                comm: comm.to_string(),
                applied,
                group,
                blocked,
            },
        );
        true
    }

    /// 遍历 tasks 应用亲和性，返回 dead_tids 供 eBPF 调用方清理 APPLIED_MAP。
    /// 只有 ESRCH 才算退出，设置失败（EPERM/EINVAL）的线程保留在缓存里等下一轮
    pub fn affinity_sync(&mut self, topo: &CpuTopology) -> Vec<i32> {
        let mut dead_tids: Vec<i32> = Vec::new();
        for (tid, e) in self.tasks.iter_mut() {
            // 系统分组硬限制：目标与所在组生效集合无交集，写多少次都不会生效。
            // 但应用切前台时系统会把它移出 background，必须重新评估，
            // 否则这个线程会被永久放弃
            if e.blocked {
                let group = crate::cpuset::thread_group(*tid);
                if group == e.group {
                    continue;
                }
                e.group = group;
                e.blocked = background_blocked(*tid, &e.cpus, group);
                if e.blocked {
                    continue;
                }
                e.applied = false;
            }
            // 还没绑上过的线程走首次绑定语义，只有绑定过的才做「被改写」判定
            let reason = if e.applied {
                ApplyReason::Sync
            } else {
                ApplyReason::Rule
            };
            // 只有「读回与期望不一致」才会真写，写入次数就是被外部改写的线程数
            let (outcome, wrote) =
                affinity_apply(*tid, &e.cpus, Some(&e.cpuset_dir), topo, reason, &e.comm);
            if wrote {
                e.applied = true;
            }
            // 线程已退出与设置失败要分开：前者清缓存，后者保留等下一轮
            if outcome == AffinityOutcome::Gone {
                e.applied = false;
                dead_tids.push(*tid);
            }
        }
        for tid in &dead_tids {
            self.task_del(*tid);
        }
        dead_tids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_of(spec: &str) -> CpuSet {
        crate::cpuset::parse_cpu_ranges(spec, None)
    }

    /// 后台组 + 目标在大核 + 交集为空，是「写多少遍都 EINVAL」的那一类
    #[test]
    fn background_group_blocks_out_of_range_targets() {
        assert!(blocked_by_group(
            SysGroup::Background,
            &set_of("4-6"),
            Some("0-3")
        ));
        // 目标本来就在该组范围内，没有理由拦
        assert!(!blocked_by_group(
            SysGroup::Background,
            &set_of("0-2"),
            Some("0-3")
        ));
        // 前台组不受这条限制：系统允许它上大核
        assert!(!blocked_by_group(
            SysGroup::Foreground,
            &set_of("4-6"),
            Some("0-3")
        ));
        // 读不到生效集合时不猜，交给内核返回真实 errno
        assert!(!blocked_by_group(
            SysGroup::Background,
            &set_of("4-6"),
            None
        ));
        // 文件为空同样不猜
        assert!(!blocked_by_group(
            SysGroup::Background,
            &set_of("4-6"),
            Some("")
        ));
    }
}
