#![no_std]
#![no_main]
#![allow(linker_messages)]
#![allow(dead_code)]

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read},
    macros::{kprobe, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, TracePointContext},
};

/// 事件类型与用户态 EbpfProcEvent.event_type 一致
/// FORK 已不再下发事件（子线程继承父线程亲和性，用户态无事可做），编号保留以固定 ABI
const EVENT_FORK: u32 = 1;
const EVENT_EXEC: u32 = 2;
const EVENT_RENAME: u32 = 3;
const EVENT_EXIT: u32 = 4;
/// 受管线程的亲和性被别人改写，用户态需要立刻按规则改回
const EVENT_AFFINITY: u32 = 5;

/// `sched_setaffinity` 的参数在 `pt_regs` 里的偏移，随架构不同：
/// arm64 的 `__arm64_sys_*` 把 `regs` 指针放在 `regs[0]`（0），
/// x86_64 的 `__x64_sys_*` 放在 `di`（112）。
///
/// 一份 bpfel 字节码同时给两个架构用，编译期选不了，只能由用户态注入。
/// 偏移不对时读出来的是垃圾，`APPLIED_MAP` 查不到就自然不出事件——
/// 错得很安静，所以 `ready` 必须由用户态显式置 1。
#[repr(C)]
#[derive(Clone, Copy)]
struct RegsOff {
    ready: u32,
    /// 从 `pt_regs` 里取「参数块指针」（`regs` 实参）的位置
    regs: u32,
    /// 参数块里 `pid` 的位置
    pid: u32,
    /// 参数块里 `user_mask_ptr` 的位置
    mask: u32,
}

/// 4 类 tracepoint 字段布局：fork 读 child_pid/child_comm，exec/exit 用 bpf_get_current_pid_tgid，rename 读 newcomm
/// 用户态解析 format 文件注入的字段偏移，因内核版本设备而异禁止硬编码
#[repr(C)]
#[derive(Clone, Copy)]
struct TracepointOffsets {
    fork_child_pid: u32,
    fork_child_comm: u32,
    rename_newcomm: u32,
}

/// 进程事件，布局需与用户态 EbpfProcEvent 一致
#[repr(C)]
struct ProcEvent {
    pid: i32,
    tid: i32,
    comm: [u8; 16],
    event_type: u32,
}

const MAP_CAPACITY: u32 = 16 << 5;
const APPLIED_CAPACITY: u32 = 8192;

/// 白名单键为包名前 15 字节或末 15 字节，与 comm 截断上限一致
#[map]
static TARGET_COMM_MAP: HashMap<[u8; 15], u32> = HashMap::with_max_entries(MAP_CAPACITY, 0);

/// 已应用亲和性表 tid 到 CPU mask，LruHashMap 配合 ESRCH 兜底
#[map]
static APPLIED_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(APPLIED_CAPACITY, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// 用户态注入的 tracepoint 字段偏移单条 Array 索引 0
#[map]
static OFFSETS_MAP: Array<TracepointOffsets> = Array::with_max_entries(1, 0);

/// 用户态注入的 pt_regs 偏移，索引 0；`ready=0` 表示探针参数还不认识，程序直接返回
#[map]
static REGS_OFF: Array<RegsOff> = Array::with_max_entries(1, 0);

/// RingBuf 满导致的事件丢弃计数。per-CPU 槽位：每个 CPU 只写自己的槽位，
/// 不需要原子指令，也不会因为多核并发更新丢计数；用户态读取时按 CPU 求和并做差分
#[map]
static DROP_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// 读取偏移，fork_child_pid 为 0 视为未注入返回 None
#[inline(always)]
fn offsets_load() -> Option<TracepointOffsets> {
    OFFSETS_MAP.get(0).and_then(|o| {
        if o.fork_child_pid != 0 {
            Some(*o)
        } else {
            None
        }
    })
}

/// 事件元信息
struct EventMeta {
    pid: i32,
    tid: i32,
    comm: [u8; 16],
    parent_tid: u32,
    parent_tgid: u32,
}

#[inline(always)]
fn applied_lookup(key: u32) -> bool {
    unsafe { APPLIED_MAP.get(key) }.is_some()
}

/// 在 comm 16 字节上以 15 字节窗口滑动匹配白名单
#[inline(always)]
fn whitelist_matched(comm: &[u8; 16]) -> bool {
    for pos in 0..=1usize {
        let key: [u8; 15] = comm[pos..pos + 15].try_into().unwrap_or([0u8; 15]);
        if unsafe { TARGET_COMM_MAP.get(key) }.is_some() {
            return true;
        }
    }
    false
}

#[inline(always)]
fn submit_event(event: ProcEvent) {
    if let Some(mut entry) = EVENTS.reserve(0) {
        entry.write(event);
        entry.submit(0);
    } else if let Some(ptr) = DROP_COUNT.get_ptr_mut(0) {
        // 指向本 CPU 的槽位，同一 CPU 不会并发执行本程序，直接自增即可
        unsafe { *ptr = (*ptr).wrapping_add(1) };
    }
}

/// 解析 fork 字段，统一用 parent_tgid 作为 pid 确保 clone 共享 TGID，tid 为 child_pid
#[inline(always)]
fn fork_parse(ctx: &TracePointContext, offsets: &TracepointOffsets) -> EventMeta {
    let pid_tgid = bpf_get_current_pid_tgid();
    let parent_tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let parent_tgid = (pid_tgid >> 32) as u32;
    let child_pid = unsafe {
        ctx.read_at::<i32>(offsets.fork_child_pid as usize)
            .unwrap_or(0)
    };
    let child_comm = unsafe {
        ctx.read_at::<[u8; 16]>(offsets.fork_child_comm as usize)
            .unwrap_or([0u8; 16])
    };
    EventMeta {
        pid: parent_tgid as i32,
        tid: child_pid,
        comm: child_comm,
        parent_tid,
        parent_tgid,
    }
}

#[inline(always)]
fn exec_parse() -> EventMeta {
    let pid_tgid = bpf_get_current_pid_tgid();
    EventMeta {
        pid: (pid_tgid >> 32) as i32,
        tid: pid_tgid as i32,
        comm: bpf_get_current_comm().unwrap_or_default(),
        parent_tid: 0,
        parent_tgid: 0,
    }
}

/// FORK 不提交事件：子线程创建时继承父线程的 affinity 与 cpuset 归属，用户态没有可做的事。
/// 这里只在内核侧占位 APPLIED_MAP[child_tid]=0，保留两点原有语义：
/// 1) RENAME 时该 tid 视为已管理，不依赖新线程名命中白名单；
/// 2) EXIT 时该 tid 能被上报，用户态缓存得以清理。
#[inline(always)]
fn fork_track(ctx: &TracePointContext) -> u32 {
    let Some(offsets) = offsets_load() else {
        return 0;
    };
    let meta = fork_parse(ctx, &offsets);
    let is_tracked = applied_lookup(meta.parent_tid);
    if !is_tracked && !whitelist_matched(&meta.comm) {
        return 0;
    }
    let _ = APPLIED_MAP.insert(meta.tid as u32, 0, 0);
    0
}

/// EXEC 检查自身是否已管理，否则以白名单兜底
#[inline(always)]
fn report_exec() -> u32 {
    let meta = exec_parse();
    if !applied_lookup(meta.tid as u32) && !whitelist_matched(&meta.comm) {
        return 0;
    }
    submit_event(ProcEvent {
        pid: meta.pid,
        tid: meta.tid,
        comm: meta.comm,
        event_type: EVENT_EXEC,
    });
    0
}

#[tracepoint(name = "sched_process_fork", category = "sched")]
fn sched_process_fork(ctx: TracePointContext) -> u32 {
    fork_track(&ctx)
}

#[tracepoint(name = "sched_process_exec", category = "sched")]
fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    report_exec()
}

/// 捕获线程改名，已管理线程直接放行否则白名单匹配
#[tracepoint(name = "task_rename", category = "task")]
fn task_rename(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    if tid == 0 {
        return 0;
    }
    let tgid = (pid_tgid >> 32) as u32;

    let tracked = applied_lookup(tid);

    let Some(offsets) = offsets_load() else {
        return 0;
    };
    let new_comm = unsafe {
        ctx.read_at::<[u8; 16]>(offsets.rename_newcomm as usize)
            .unwrap_or([0u8; 16])
    };

    if !tracked && !whitelist_matched(&new_comm) {
        return 0;
    }

    submit_event(ProcEvent {
        pid: tgid as i32,
        tid: tid as i32,
        comm: new_comm,
        event_type: EVENT_RENAME,
    });
    0
}

/// 捕获线程退出，已管理线程清理 APPLIED_MAP
#[tracepoint(name = "sched_process_exit", category = "sched")]
fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;

    if !applied_lookup(tid) {
        return 0;
    }

    let _ = APPLIED_MAP.remove(tid);

    submit_event(ProcEvent {
        pid: tgid as i32,
        tid: tid as i32,
        comm: [0u8; 16],
        event_type: EVENT_EXIT,
    });
    0
}

/// 本模块自己的进程名。自己改自己不算「被别人改写」，否则每次绑核都会
/// 回环成一条事件，全量扫描时几百条一起涌进来
const SELF_COMM: &[u8; 6] = b"AppOpt";

#[inline(always)]
fn is_self(comm: &[u8; 16]) -> bool {
    &comm[..6] == SELF_COMM
}

/// 读取并校验注入偏移；未注入（ready=0）时返回 None
#[inline(always)]
fn regs_off() -> Option<RegsOff> {
    REGS_OFF.get(0).copied().filter(|o| o.ready != 0)
}

/// `sched_setaffinity` 探针：别人把受管线程的掩码改掉时立刻通知用户态。
///
/// 判定完全在内核侧做完，用户态只负责重绑：
/// 1. 跳过本模块自己的写入（comm 为 AppOpt）；
/// 2. 线程不在 `APPLIED_MAP` 里 → 不是我们管的，不管；
/// 3. 新掩码与 `APPLIED_MAP` 里记的期望值相同 → 没有变化，不报。
///
/// 第 3 条同时挡住「用户态写成功、内核侧事件后到」的顺序问题：事件到达时
/// map 里已经是新值，比较相等，自然安静。
#[kprobe(function = "sched_setaffinity")]
fn setaffinity(ctx: ProbeContext) -> u32 {
    let Some(off) = regs_off() else {
        return 0;
    };
    let caller = bpf_get_current_comm().unwrap_or_default();
    if is_self(&caller) {
        return 0;
    }

    // 参数块指针：kprobe 的 ctx 是 pt_regs，syscall wrapper 的第一个参数
    // 就存在 pt_regs 的固定位置上
    let base = ctx.as_ptr() as usize;
    let Ok(regs) = (unsafe { bpf_probe_read::<u64>((base + off.regs as usize) as *const u64) })
    else {
        return 0;
    };
    // 参数块本身还是 pt_regs，pid 与 mask 指针各在固定偏移
    let Ok(tid_arg) =
        (unsafe { bpf_probe_read::<i32>((regs as usize + off.pid as usize) as *const i32) })
    else {
        return 0;
    };
    let Ok(mask_ptr) =
        (unsafe { bpf_probe_read::<u64>((regs as usize + off.mask as usize) as *const u64) })
    else {
        return 0;
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    // pid=0 表示「改自己」，目标就是调用者线程
    let tid = if tid_arg > 0 {
        tid_arg as u32
    } else {
        (pid_tgid & 0xFFFF_FFFF) as u32
    };
    if tid == 0 {
        return 0;
    }

    let Some(want) = (unsafe { APPLIED_MAP.get(tid) }).copied() else {
        return 0;
    };
    // 用户缓冲区至少 cpumask_size（64 位上是 8 字节），手机核数远小于 64，
    // 读一个 u64 足够；长度参数小于 8 时可能读到相邻栈数据，最多多报一次，
    // 用户态发现掩码已一致就短路了
    let Ok(new_mask) = (unsafe { bpf_probe_read::<u64>(mask_ptr as *const u64) }) else {
        return 0;
    };
    if new_mask == want {
        return 0;
    }

    submit_event(ProcEvent {
        pid: (pid_tgid >> 32) as i32,
        tid: tid as i32,
        comm: caller,
        event_type: EVENT_AFFINITY,
    });
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
