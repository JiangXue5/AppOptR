use std::collections::HashMap;

use crate::apply_affinity::{AffinityOutcome, ApplyReason, affinity_apply};
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, SysGroup};
use crate::rule_match::{comm_to_pkg, thread_affinity};

pub struct TaskEntry {
    pub pid: i32,
    pub pkg: String,
    /// 规则算出来的集合，原样保留。它可能被系统组裁小（见 `cpus`），
    /// 但恢复接管后要能回到这个值，所以不能只存裁剪后的结果
    pub want: CpuSet,
    /// 本轮实际写入的集合。正常情况下等于 `want`；cpuset 不可用时是
    /// `want ∩ 组生效集合`
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
    /// 当前目标由谁定：规则 / S7 落点 / 后台降档。
    /// 只在来源变化时打一行日志，用于回答「这个线程什么时候被降档了」
    pub source: PolicySource,
}

/// Own 组短路的定期复核周期（按周期同步轮次计）。
///
/// 32 轮 × 3-5 秒 ≈ 1.5-2.5 分钟：足够短，系统把线程挪出组后能在一两分钟内
/// 发现；也足够长，稳态下省掉绝大部分 `/proc/<tid>/cgroup` 打开。
/// Own 组由本模块自建，系统不会主动改组内线程，这是能短路的前提
const GROUP_RECHECK_ROUNDS: u64 = 32;

/// 是否需要补写组归属：只在「首次绑定 / 目标变更」、且线程确实不在
/// 目标组时做。稳态（`changed` 为假）与短路复用都不做，否则每轮一次
/// `/proc/<tid>/cgroup` 等于把 C08 省下的读取又还回去
fn need_verify_group(
    migrate: bool,
    dir: &str,
    changed: bool,
    reuse: bool,
    path: Option<&str>,
) -> bool {
    migrate && !dir.is_empty() && changed && !reuse && path.is_some_and(|p| !in_own_dir(p, dir))
}

/// 规则目录对应的绝对组路径。`dir` 为空表示 base 组本身
fn own_dir_path(dir: &str) -> String {
    let base = crate::cpuset::base_cpuset();
    if dir.is_empty() {
        base
    } else {
        format!("{}/{}", base, dir)
    }
}

/// 线程当前路径是否就在 `AppOpt/<dir>`。
///
/// `thread_cgroup` 返回的是层级相对路径（形如 `/AppOpt/6-7`），
/// `base_cpuset` 是绝对路径（形如 `/dev/cpuset/AppOpt`），只比最后一段
fn in_own_dir(path: &str, dir: &str) -> bool {
    let base = crate::cpuset::base_cpuset();
    let base = base.rsplit('/').next().unwrap_or("AppOpt");
    let p = path.trim_matches('/');
    if dir.is_empty() {
        p == base
    } else {
        p == format!("{}/{}", base, dir)
    }
}

/// 组名以本轮读到的 path 为准，读不到才退回缓存。
/// 反过来会在「系统刚把线程挪到另一个组」的那一轮里播报旧组名，
/// 与判定用的生效集合并列，读日志的人无法验证结论
fn resolve_group(path: Option<&str>, prev: Option<&TaskEntry>) -> SysGroup {
    path.map(crate::cpuset::classify_group)
        .or_else(|| prev.map(|old| old.group))
        .unwrap_or(SysGroup::Unknown)
}

/// 单条线程本轮的目标：能维持 S7 落点就维持，否则回到规则值。
///
/// 具体判据在 `policy::plan_entry`——那里是纯函数，这套判断错一次，
/// 日志里就会多出几百行 EINVAL 或几百次无效重绑，必须能脱离真机单测
use crate::policy::{PolicySource, plan_entry};

/// 双模式共用进程缓存，eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub tasks: HashMap<i32, TaskEntry>,
    /// S7 接管落点：tid → 上次迁移成功写入的集合。
    ///
    /// 必须单独存放，不能只记在 `TaskEntry` 里：proc 模式每 60 秒全量重建缓存，
    /// eBPF 模式配置变更也会 `clear()`，落点存在条目上会连同条目一起丢掉，
    /// 定期校验随后按规则原值重写，S7 的迁移活不过一个周期。
    /// 规则改小、组不再可达、线程退出时由 `landing_for` 与 `purge_*` 清掉。
    sched: HashMap<i32, CpuSet>,
    /// 周期同步轮次，只用于 Own 组短路的定期复核。由 `affinity_sync` 推进：
    /// 事件驱动路径不推进它，否则事件密集时复核周期会被压到几秒
    round: u64,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            sched: HashMap::new(),
            round: 0,
        }
    }

    /// 只清线程条目，保留 S7 落点：全量重建后定期校验仍要按落点维持，
    /// 否则每 60 秒就会把动态迁移拉回规则值一次
    pub fn clear(&mut self) {
        self.tasks.clear();
    }

    pub fn task_del(&mut self, tid: i32) {
        self.tasks.remove(&tid);
        self.sched.remove(&tid);
        crate::diag::unbind_pkg(tid);
    }

    /// 线程确实退出了：缓存与账本一起清。
    ///
    /// 账本不能放进 `task_del`：「不再匹配规则」也走那条路，而那种线程还活着，
    /// 账必须留着，否则规则一删就没有依据把它还回原组
    pub fn task_gone(&mut self, tid: i32) {
        self.task_del(tid);
        crate::lifecycle::forget(tid);
    }

    /// S7 迁移成功。落点单独存，重建缓存后仍能维持
    pub fn note_sched(&mut self, tid: i32, cpus: CpuSet) {
        self.sched.insert(tid, cpus);
    }

    /// 关掉 S7 时清空全部落点，让线程按规则重新落地
    pub fn clear_sched(&mut self) {
        self.sched.clear();
    }

    /// 进程退出时清理其全部线程
    pub fn purge_pid(&mut self, pid: i32) {
        self.tasks.retain(|_, e| e.pid != pid);
        self.sched.retain(|tid, _| self.tasks.contains_key(tid));
        // 进程没了，账本里属于它的记录也一并作废：没有线程可还
        crate::lifecycle::forget_pid(pid);
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
            // 规则变了，按旧规则迁出来的落点不再有效
            self.sched.remove(tid);
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
        F: FnOnce(i32, &CpuSet, Option<&str>, bool, bool) -> AffinityOutcome,
    {
        // 需要线程名的消费方都在 `needs_comm` 里：线程规则、S7、RT、Auto Assign。
        // 只按 has_thread_rules 传，会让「只有包级规则但开了 Auto Assign」的包
        // 永远拿不到 comm，候选也就永远生成不出来
        let thread_name = if cfg.needs_comm(pkg) { comm } else { "" };
        // 只登记已经通过 pkg_owned 校验、且确实命中规则的包：日志里的每条
        // 样例都要能回答「这是谁的线程」，否则 `HWC release` 这种名字
        // 说它是游戏进程还是 surfaceflinger 的，全凭读者猜
        crate::diag::bind_pkg(tid, pkg, tid == pid);
        // 必须在规则匹配之前观察：Auto Assign 要看到「当前没命中任何线程规则」
        // 的线程，否则只能建议已配过的线程，等于没有建议
        if cfg.auto_assign {
            crate::auto_assign::note(pkg, thread_name, tid);
        }
        let Some(result) = thread_affinity(pkg, thread_name, cfg) else {
            return false;
        };
        // 只在新线程登记时说明「按哪条规则绑的」：稳态每轮都打等于刷屏
        if !self.tasks.contains_key(&tid) {
            crate::diag::note_rule_hit(
                pkg,
                thread_name,
                result.spec,
                result.hits,
                &result.cpus,
                result.hit_pattern,
            );
        }

        if !result.is_thread_rule && self.tasks.get(&tid).is_some_and(|old| old.is_thread_rule) {
            return true;
        }

        // 组归属：系统随时可能把线程在 top-app / background 之间挪，沿用上
        // 一轮的缓存在「刚挪组」的那一轮会算出错误的有效集合。但线程已经在
        // 自己的 AppOpt 组里、规则也没变时，系统不会去动它（这正是接管组的
        // 意义），此时不必每轮再 open `/proc/<tid>/cgroup`。
        //
        // 定期复核兜住「组被外部删除、手动改过」这类意外：每
        // GROUP_RECHECK_ROUNDS 轮强制回读一次，其余轮次只对已接管线程短路
        let prev = self.tasks.get(&tid);
        // 短路必须带一个哨兵：`sched_getaffinity` 比 open `/proc/<tid>/cgroup`
        // 便宜一个数量级，但能发现「系统把线程挪去 background 并把亲和性
        // 收敛成 0-3」这种最危险的变化。少了它，reuse 期间会把后台线程
        // 当成还留在自己组里，走两步迁组硬拽回大核——等于绕过系统对后台的限制
        let reuse = prev.is_some_and(|p| {
            p.applied
                && p.group == SysGroup::Own
                && p.want == result.cpus
                && CpuSet::get_affinity(tid).is_some_and(|cur| cur == p.cpus)
        }) && !self.round.is_multiple_of(GROUP_RECHECK_ROUNDS);
        let path = if reuse {
            None
        } else {
            crate::cpuset::thread_cgroup_counted(tid)
        };
        // 组名必须跟这一轮的 path 走。沿用上一轮的缓存，会在「系统刚把线程
        // 从前台组挪到后台组」的那一轮里播报「在 top-app 组，4-6 不在该组内」，
        // 与实际生效集合自相矛盾，用户没法验证这句话
        let group = if reuse {
            SysGroup::Own
        } else {
            resolve_group(path.as_deref(), prev)
        };
        // 豁免包只写亲和性，不迁组：与其他管 cpuset 的模块共存
        let exempt = cfg.is_exempt(pkg);
        let migrate = cfg.topo.cpuset_enabled
            && !crate::apply_affinity::cpuset_paused()
            && !exempt;        // 短路时组已知是 Own，生效集合按规则目录自己算，不再走 /proc
        let eff = if reuse {
            crate::cpuset::group_effective_cached(&own_dir_path(&result.cpuset_dir))
        } else {
            path.as_deref()
                .and_then(crate::cpuset::group_effective_cached)
        };
        // 规则变了（同一条目却算出不同集合）就丢掉旧的 S7 落点：
        // 事件重放或重扫可能在 purge 之前撞上同一个 tid
        if prev.is_some_and(|old| old.want != result.cpus) {
            self.sched.remove(&tid);
        }
        // 前后台降档：只作用于没有显式线程规则的线程。用户写明的绑定优先于
        // 任何自动策略，这一点与 S7 让位同源
        let floor = if crate::background::should_demote(
            cfg.foreground_demote,
            result.is_thread_rule,
            tid,
            group,
        ) {
            crate::background::floor_of(&cfg.topo)
        } else {
            None
        };
        let (target, keep) = plan_entry(
            &result.cpus,
            self.sched.get(&tid).copied(),
            group,
            eff.as_deref(),
            cfg.sysgroup_respect,
            migrate,
            floor.as_ref(),
        );
        if keep.is_none() {
            self.sched.remove(&tid);
        }
        if let Some(eff) = &target.clipped {
            crate::diag::note_group_clip(group, &result.cpus, &target.cpus, eff);
        }
        // 规则没变、且确实写过：这次不是「首次绑定」而是「复核」。
        // 复核必须走校验语义，才能把「被外部改写」记成漂移而不是正常写入
        let recheck = prev.is_some_and(|old| old.applied && old.cpus == target.cpus);
        // 组归属校验只在「首次绑定 / 目标变更」做：稳态每轮校验等于把
        // C08 省下的 open 又还回去。掩码对但组不对时，写一次组才不会
        // 在系统下一次状态变化时被收敛掉
        let changed =
            !prev.is_some_and(|old| old.applied) || prev.is_some_and(|old| old.cpus != target.cpus);
        let verify_group = need_verify_group(
            migrate && cfg.group_own,
            &result.cpuset_dir,
            changed,
            reuse,
            path.as_deref(),
        );
        let prev_applied = prev.is_some_and(|old| old.applied);
        // 首次接管前先记住「原来在哪一组、什么亲和性」——写完就再也读不回来了。
        // 只在首次绑定读一次，稳态复核不付这个开销
        let original = if prev_applied {
            (None, CpuSet::default())
        } else {
            (path.clone(), CpuSet::get_affinity(tid).unwrap_or_default())
        };
        if target.blocked {
            crate::diag::note_sysgroup_skip(tid, comm, group, &result.cpus, eff.as_deref());
            self.tasks.insert(
                tid,
                TaskEntry {
                    pid,
                    pkg: pkg.to_string(),
                    want: result.cpus,
                    cpus: target.cpus,
                    cpuset_dir: result.cpuset_dir,
                    is_thread_rule: result.is_thread_rule,
                    comm: comm.to_string(),
                    applied: false,
                    group,
                    blocked: true,
                    source: target.source,
                },
            );
            return true;
        }
        // 豁免包传 None：affinity_apply 见到 None 就只写掩码、不碰 cpuset。
        // 传空字符串不行——空字符串表示「迁到 AppOpt 基组」，那仍然是在抢组
        let dir_arg = if exempt {
            None
        } else {
            Some(result.cpuset_dir.as_str())
        };
        let outcome = apply_fn(tid, &target.cpus, dir_arg, recheck, verify_group);
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
        // 账本只在真的接管成功时记：匹配到规则但没写进去不算，否则规则一删
        // 就会去释放一个我们从没动过的线程
        if outcome == AffinityOutcome::Set {
            if prev_applied {
                crate::lifecycle::note_applied(tid, &target.cpus, &result.cpuset_dir);
            } else {
                crate::lifecycle::note_managed(
                    tid,
                    pkg,
                    comm,
                    original,
                    &target.cpus,
                    &result.cpuset_dir,
                );
            }
        }

        self.tasks.insert(
            tid,
            TaskEntry {
                pid,
                pkg: pkg.to_string(),
                want: result.cpus,
                cpus: target.cpus,
                cpuset_dir: result.cpuset_dir,
                is_thread_rule: result.is_thread_rule,
                comm: comm.to_string(),
                applied,
                group,
                blocked: false,
                source: target.source,
            },
        );
        true
    }

    /// 遍历 tasks 应用亲和性，返回 dead_tids 供 eBPF 调用方清理 APPLIED_MAP。
    /// 只有 ESRCH 才算退出，设置失败（EPERM/EINVAL）的线程保留在缓存里等下一轮
    ///
    /// 传入整个配置而不是几个散装布尔：豁免名单、降档开关都是按包/按线程
    /// 生效的，散装参数会让调用方各自组装一遍，迟早出现口径不一致
    pub fn affinity_sync(&mut self, cfg: &AppConfig) -> Vec<i32> {
        let topo = &cfg.topo;
        let respect = cfg.sysgroup_respect;
        let mut dead_tids: Vec<i32> = Vec::new();
        let mut blocked_now = 0usize;
        // 被挡线程集中在哪个组、该组可用哪几个核：交给总账解释「为什么一致 0」
        let mut blocked_hint: Option<(SysGroup, String)> = None;
        // 本轮结束时的状态分布，摘要要直接回答「此刻绑上没有」。
        // `ok` 是读回就一致、一次都没写的线程，`rebound` 是写过且内核接受的
        let total = self.tasks.len();
        let mut ok_now = 0usize;
        let mut rebind_now = 0usize;
        let mut fail_now = 0usize;
        let can_migrate = topo.cpuset_enabled && !crate::apply_affinity::cpuset_paused();
        // 轮次只在周期同步里推进：事件驱动路径每来一个事件都推进的话，
        // 「每 32 轮复核一次」会退化成每秒复核
        self.round = self.round.wrapping_add(1);
        let round = self.round;
        // 已退出的线程不会再有事件，落点留在这里只会慢慢堆积。
        // 每轮按在线条目裁剪一次，成本是一次哈希遍历
        self.sched.retain(|tid, _| self.tasks.contains_key(tid));
        let sched = &mut self.sched;
        for (tid, e) in self.tasks.iter_mut() {
            // 组归属每轮都重看，不只在「已被拦住」时看。应用切后台时系统会把
            // 线程从 top-app 搬进 background(0-3)，规则却仍要 4-6，交集为空。
            // 只在首次评估的话，线程一旦被判成「可绑」就再也不会重看，
            // 于是切后台后每轮都硬写一次——真机日志里 `+2599s` 之后
            // 每分钟 495 次 EINVAL、`挪簇 495` 就是这么来的。
            // 代价是每 60 秒每个受管线程读一次 /proc/<tid>/cgroup，
            // 相比几百次注定失败的 sched_setaffinity 便宜得多
            //
            // 目标集合也跟着重算：组把目标裁小时按交集绑，组放宽或接管恢复后
            // 再回到规则原值。只算一次的话，线程会在「裁剪值」上永久停住
            // 已接管、规则未变时不必回读 /proc：Own 组是模块自建的，
            // 系统不会改组内线程。每 GROUP_RECHECK_ROUNDS 轮强制回读一次，
            // 兜住组被外部删除或手动修改的情况
            // 与 task_apply 同一条判据：亲和性读回仍是上一轮的落点，才认为
            // 线程还在自己的组里。系统把它挪去别的组时一定会重置亲和性，
            // 这个哨兵能在同一轮发现，不必等 32 轮复核
            let reuse = e.applied
                && e.group == SysGroup::Own
                && !round.is_multiple_of(GROUP_RECHECK_ROUNDS)
                && CpuSet::get_affinity(*tid).is_some_and(|cur| cur == e.cpus);
            let path = if reuse {
                None
            } else {
                crate::cpuset::thread_cgroup_counted(*tid)
            };
            let group = if reuse {
                SysGroup::Own
            } else {
                path.as_deref()
                    .map(crate::cpuset::classify_group)
                    .unwrap_or(SysGroup::Unknown)
            };
            let eff = if reuse {
                crate::cpuset::group_effective_cached(&own_dir_path(&e.cpuset_dir))
            } else {
                path.as_deref()
                    .and_then(crate::cpuset::group_effective_cached)
            };
            // 豁免包只写亲和性：迁组会跟 LKT/Uperf 这类同样管 cpuset 的模块
            // 抢归属，两边互相覆盖比谁都不管更糟
            let exempt = cfg.is_exempt(&e.pkg);
            let migrate = can_migrate && !exempt;
            // 降档只在用户显式打开时才算——`floor_of` 与 `is_background` 都在
            // 闸门里面调用，默认配置下这条路径零系统调用
            let floor = if crate::background::should_demote(
                cfg.foreground_demote,
                e.is_thread_rule,
                *tid,
                group,
            ) {
                crate::background::floor_of(topo)
            } else {
                None
            };
            // S7 接管过的线程按落点维持，不按规则原值重算：`want` 是规则集，
            // 直接拿它算会把刚迁到 4-7 的线程拉回 0-7，迁移白做
            let (target, keep) = plan_entry(
                &e.want,
                sched.get(tid).copied(),
                group,
                eff.as_deref(),
                respect,
                migrate,
                floor.as_ref(),
            );
            if keep.is_none() && sched.contains_key(tid) {
                // 落点已不可达（切后台、组收紧、规则改小）：接管作废
                sched.remove(tid);
            }
            // 「首次绑定 / 目标变更」才需要校验组归属；稳态校验等于白读一次
            let changed = !e.applied || e.cpus != target.cpus;
            // 来源变化单独播报：这是回答「这个线程什么时候被降档了、
            // 什么时候恢复的」的唯一线索，写入次数本身看不出来
            let proposal = target.proposal();
            if e.applied && e.source != proposal.source {
                let label = if e.comm.is_empty() {
                    e.pkg.as_str()
                } else {
                    e.comm.as_str()
                };
                crate::diag::note_target_shift(
                    label,
                    e.source.label(),
                    proposal.source.label(),
                    &proposal.cpus.to_range_string(),
                    proposal.reason,
                );
            }
            e.source = proposal.source;
            e.group = group;
            e.cpus = target.cpus;
            e.blocked = target.blocked;
            if e.blocked {
                blocked_now += 1;
                if blocked_hint.is_none() {
                    blocked_hint = Some((group, eff.clone().unwrap_or_default()));
                }
                continue;
            }
            // 还没绑上过的线程走首次绑定语义，只有绑定过的才做「被改写」判定
            let reason = if e.applied {
                ApplyReason::Sync
            } else {
                ApplyReason::Rule
            };
            // 首次绑定前留一份原始状态。`reuse` 要求 `applied` 为真，
            // 与这里互斥，所以 !applied 时 `path` 是这一轮真实读到的组
            let original = if e.applied {
                (None, CpuSet::default())
            } else {
                (path.clone(), CpuSet::get_affinity(*tid).unwrap_or_default())
            };
            // 掩码对但组不对时补写一次组归属。短路复用组时不必校验：
            // 那一轮的组本来就记着 Own
            let verify_group = need_verify_group(
                migrate && cfg.group_own,
                &e.cpuset_dir,
                changed,
                reuse,
                path.as_deref(),
            );
            // 只有「读回与期望不一致」才会真写，写入次数就是被外部改写的线程数
            let was_applied = e.applied;
            let (outcome, wrote) = affinity_apply(
                *tid,
                &e.cpus,
                Some(&e.cpuset_dir),
                topo,
                reason,
                &e.comm,
                verify_group,
            );
            if wrote {
                e.applied = true;
                rebind_now += 1;
            }
            // 接管成功才记账。失败时保留旧账：线程还在我们组里，只是这一轮
            // 没写成，规则一删仍然要能还回去。
            // 只有写成功（或首次登记）才动账本：稳态每轮都加锁是白费
            if outcome == AffinityOutcome::Set && (wrote || !was_applied) {
                if was_applied {
                    crate::lifecycle::note_applied(*tid, &e.cpus, &e.cpuset_dir);
                } else {
                    crate::lifecycle::note_managed(
                        *tid,
                        &e.pkg,
                        &e.comm,
                        original,
                        &e.cpus,
                        &e.cpuset_dir,
                    );
                }
            }
            match outcome {
                AffinityOutcome::Set => {
                    if !wrote {
                        ok_now += 1;
                    }
                }
                AffinityOutcome::Failed(_) => fail_now += 1,
                // Gone 的线程本轮退出，不计入任何一档，总数里也已经被移除
                AffinityOutcome::Gone => {}
            }
            // 线程已退出与设置失败要分开：前者清缓存，后者保留等下一轮
            if outcome == AffinityOutcome::Gone {
                e.applied = false;
                dead_tids.push(*tid);
            }
        }
        for tid in &dead_tids {
            self.task_gone(*tid);
        }
        if blocked_now > 0 {
            crate::diag::note_sysgroup_batch(blocked_now as u64, blocked_hint);
        }
        crate::diag::note_sync_tally(total, ok_now, rebind_now, fail_now, blocked_now);
        dead_tids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_of(spec: &str) -> CpuSet {
        crate::cpuset::parse_cpu_ranges(spec, None)
    }

    /// 组归属校验只在「首次 / 目标变更且真的不在目标组」时发生：
    /// 稳态每轮校验会把 C08 省下的 open 还回去，漏判则接管不彻底
    #[test]
    fn verify_group_only_on_first_or_target_change() {
        // 已在目标组：不需要补
        assert!(!need_verify_group(
            true,
            "6-7",
            true,
            false,
            Some("/AppOpt/6-7")
        ));
        // 掩码对、但在系统组：要补
        assert!(need_verify_group(
            true,
            "6-7",
            true,
            false,
            Some("/top-app")
        ));
        // 在自己的组但目录不对（规则改了集合）：要补
        assert!(need_verify_group(
            true,
            "6-7",
            true,
            false,
            Some("/AppOpt/0-3")
        ));
        // 稳态 / 短路复用 / cpuset 暂停 / 无目录 / 读不到 cgroup：一律不补
        assert!(!need_verify_group(
            true,
            "6-7",
            false,
            false,
            Some("/top-app")
        ));
        assert!(!need_verify_group(
            true,
            "6-7",
            true,
            true,
            Some("/top-app")
        ));
        assert!(!need_verify_group(
            false,
            "6-7",
            true,
            false,
            Some("/top-app")
        ));
        assert!(!need_verify_group(true, "", true, false, Some("/top-app")));
        assert!(!need_verify_group(true, "6-7", true, false, None));
    }

    /// 已接管且规则未变时不该再读 `/proc/<tid>/cgroup`：沙箱里当前线程
    /// 不在 AppOpt 组，一旦回读，group 就会从 Own 变成 Unknown，断言能抓住
    #[test]
    fn own_group_is_reused_between_recheck_rounds() {
        let tid = std::process::id() as i32;
        let cur = CpuSet::get_affinity(tid).expect("读当前线程亲和性");
        let mut cache = ProcCache::new();
        cache.tasks.insert(
            tid,
            TaskEntry {
                pid: tid,
                pkg: "com.test.own".into(),
                want: cur,
                cpus: cur,
                cpuset_dir: "own-test".into(),
                is_thread_rule: false,
                comm: "own-test".into(),
                applied: true,
                group: SysGroup::Own,
                blocked: false,
                source: PolicySource::UserRule,
            },
        );
        // 目标就是当前亲和性：affinity_apply 会短路，不会真的改测试线程
        cache.affinity_sync(&crate::config::AppConfig::empty());
        assert_eq!(
            cache.tasks.get(&tid).map(|e| e.group),
            Some(SysGroup::Own),
            "未到复核轮次必须复用组归属，不回读 cgroup"
        );

        // 推到复核轮次：32 % 32 == 0，必须回读。沙箱里当前线程在
        // `/user.slice/...`（Other），不会再被认成 Own
        cache.round = GROUP_RECHECK_ROUNDS - 1;
        cache.affinity_sync(&crate::config::AppConfig::empty());
        assert_ne!(
            cache.tasks.get(&tid).map(|e| e.group),
            Some(SysGroup::Own),
            "到复核轮次必须回读真实组归属"
        );
    }

    /// base 组名取自 `-b` 参数最后一段，`/dev/cpuset/AppOpt` 与 `/AppOpt`
    /// 必须认成同一个组，否则每次都会误判成「不在自己的组里」
    #[test]
    fn own_dir_matches_relative_cgroup_path() {
        assert!(in_own_dir("/AppOpt/6-7", "6-7"));
        assert!(!in_own_dir("/AppOpt/0-7", "6-7"));
        assert!(!in_own_dir("/top-app", "6-7"));
        assert!(in_own_dir("/AppOpt", ""));
        assert!(in_own_dir("AppOpt/6-7", "6-7"));
    }

    /// proc 模式每 60 秒全量重建缓存，eBPF 模式配置变更也会 `clear()`。
    /// 落点若只记在条目里，重建一次就被规则值覆盖，S7 的迁移活不过一个周期
    #[test]
    fn sched_landing_survives_cache_rebuild() {
        let mut cache = ProcCache::new();
        cache.note_sched(4321, set_of("4-7"));
        cache.clear();
        assert_eq!(cache.sched.get(&4321).copied(), Some(set_of("4-7")));
        // 线程退出后不再保留
        cache.task_del(4321);
        assert!(!cache.sched.contains_key(&4321));
    }

    /// 组名必须跟本轮读到的 path 走。沿用上一轮缓存会在「系统刚把线程从
    /// 前台挪到后台」的那一轮里报出「在 top-app 组，4-6 不在该组内」，
    /// 而判定其实用的是后台组的 0-3——日志自相矛盾，用户无从验证
    #[test]
    fn group_name_follows_current_path() {
        let old = TaskEntry {
            pid: 1,
            pkg: "com.x".into(),
            want: set_of("4-6"),
            cpus: set_of("4-6"),
            cpuset_dir: "4-6".into(),
            is_thread_rule: false,
            comm: "T".into(),
            applied: true,
            group: SysGroup::TopApp,
            blocked: false,
            source: PolicySource::UserRule,
        };
        assert_eq!(
            resolve_group(Some("/background"), Some(&old)),
            SysGroup::Background
        );
        assert_eq!(
            resolve_group(Some("/top-app"), Some(&old)),
            SysGroup::TopApp
        );
        // 读不到 path 才退回缓存
        assert_eq!(resolve_group(None, Some(&old)), SysGroup::TopApp);
        assert_eq!(resolve_group(None, None), SysGroup::Unknown);
    }
}
