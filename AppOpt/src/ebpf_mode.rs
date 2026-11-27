use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, Map, PerCpuArray as AyaPerCpuArray};
use aya::programs::{KProbe as AyaKProbe, TracePoint as AyaTracePoint};
use aya::{Ebpf, EbpfLoader, Pod};

use crate::apply_affinity::{
    AffinityOutcome, ApplyReason, affinity_apply, proc_walk, task_tids, tid_comm,
};
use crate::cache::ProcCache;
use crate::config::{AppConfig, CURRENT_CONFIG};
use crate::cpuset::CpuSet;
use crate::rt;

/// eBPF 进程事件，布局需与内核态 ProcEvent 一致
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfProcEvent {
    pub pid: i32,
    pub tid: i32,
    pub comm: [u8; 16],
    pub event_type: u32,
}

pub const EBPF_EVENT_FORK: u32 = 1;
pub const EBPF_EVENT_EXEC: u32 = 2;
pub const EBPF_EVENT_RENAME: u32 = 3;
pub const EBPF_EVENT_EXIT: u32 = 4;
/// 受管线程的亲和性被外部改写，用户态立刻重绑
pub const EBPF_EVENT_AFFINITY: u32 = 5;

/// 运行期累计的 RingBuf 丢弃事件数，供 Web 状态展示
pub static DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// kprobe 改写监听的状态，供 Web 诊断展示：0 未尝试、1 已挂上、2 不可用
pub static AFFINITY_PROBE: AtomicU8 = AtomicU8::new(0);

/// 上次写进 TARGET_COMM_MAP 的键数。热重载时包名没变也会重写一遍 map，
/// 但这行「白名单已配置」只在键数真的变了时才有信息量
static COMM_KEYS_SEEN: AtomicU32 = AtomicU32::new(u32::MAX);

/// 用户态注入内核的 tracepoint 字段偏移，布局需与内核态 TracepointOffsets 一致
#[repr(C)]
#[derive(Clone, Copy)]
struct EbpfOffsets {
    fork_child_pid: u32,
    fork_child_comm: u32,
    rename_newcomm: u32,
}

unsafe impl Pod for EbpfOffsets {}

/// 与内核态 `RegsOff` 对应：`sched_setaffinity` 的参数在 `pt_regs` 里的偏移。
/// 一份 bpfel 字节码同时给 arm64 与 x86_64 用，只能在运行时注入。
#[repr(C)]
#[derive(Clone, Copy)]
struct RegsOff {
    ready: u32,
    regs: u32,
    pid: u32,
    mask: u32,
}

unsafe impl Pod for RegsOff {}

/// 同一线程被连续改写时的最小重绑间隔。HAL 有的会几十毫秒写一次，
/// 每条事件都跟着重绑会把一个核打满；跳过的那些由周期校验兜底。
const FIX_MIN_GAP: Duration = Duration::from_millis(100);

/// 距上次重绑是否已经超过节流窗口
fn fix_allowed(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|t| now.duration_since(t) >= FIX_MIN_GAP)
}

/// 将内核 comm 截断于首个 NUL 并 trim 尾部空白
fn comm_str(comm: &[u8; 16]) -> &str {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&comm[..end]).unwrap_or("").trim()
}

pub struct EbpfState {
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub reader_thread: Option<thread::JoinHandle<()>>,
    pub bpf: Ebpf,
    pub cache: ProcCache,
    pub wakeup_fd: RawFd,
    pub comm_capacity: u32,
    /// 本轮生效的逐包规则指纹，用于配置热更新时定位变化的包
    pub cfg_sig: HashMap<String, u64>,
    /// 本轮生效的全局策略指纹，变化时无法按包增量处理
    pub cfg_policy_sig: u64,
    /// 上一轮读到的内核累计丢弃数，用于差分求新增丢弃
    pub drop_seen: u64,
    /// 每个受管线程最近一次「被改写后重绑」的时间，用于节流
    pub last_fix: HashMap<i32, Instant>,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // 写 eventfd 唤醒 reader 线程的 epoll_wait 后 join 等待退出
        if self.wakeup_fd >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(self.wakeup_fd, &val as *const u64 as *const _, 8);
            }
        }
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
        if self.wakeup_fd >= 0 {
            unsafe {
                libc::close(self.wakeup_fd);
            }
        }
    }
}

pub fn ebpf_probe() -> bool {
    fs::metadata("/sys/kernel/btf/vmlinux").is_ok()
}

fn attach_tracepoint(bpf: &mut Ebpf, category: &str, name: &str, required: bool) -> bool {
    let Some(prog) = bpf.program_mut(name) else {
        if required {
            crate::diag_warn!("eBPF 未找到 {} 程序", name);
        }
        return false;
    };
    let Ok(tp): Result<&mut AyaTracePoint, _> = prog.try_into() else {
        if required {
            crate::diag_warn!("eBPF {} 类型转换失败", name);
        }
        return false;
    };
    if let Err(e) = tp.load() {
        if required {
            crate::diag_warn!("eBPF {} 加载失败 ({})", name, e);
        }
        return false;
    }
    if let Err(e) = tp.attach(category, name) {
        if required {
            crate::diag_warn!("eBPF {} 附加失败 ({})", name, e);
        }
        return false;
    }
    true
}

/// 构建白名单键，每个包名生成前 15 字节与末 15 字节键
fn comm_keys_build<'a, I: IntoIterator<Item = &'a String>>(pkgs: I) -> Vec<[u8; 15]> {
    let mut entries: Vec<[u8; 15]> = Vec::new();
    for pkg in pkgs {
        let bytes = pkg.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        let mut prefix = [0u8; 15];
        let end = bytes.len().min(15);
        prefix[..end].copy_from_slice(&bytes[..end]);
        entries.push(prefix);
        if bytes.len() > 15 {
            let mut suffix = [0u8; 15];
            suffix.copy_from_slice(&bytes[bytes.len() - 15..]);
            entries.push(suffix);
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

/// 初始化 TARGET_COMM_MAP，返回 true 表示需重载
pub fn comm_map_init(bpf: &mut Ebpf, pkgs: &HashSet<String>, comm_capacity: u32) -> bool {
    let entries = comm_keys_build(pkgs.iter());

    if entries.len() > comm_capacity as usize {
        crate::diag_warn!(
            "eBPF 白名单容量不足（需 {} > 现 {}），触发内核端重载",
            entries.len(),
            comm_capacity
        );
        return true;
    }

    let Some(map) = bpf.map_mut("TARGET_COMM_MAP") else {
        crate::diag_warn!("eBPF 未找到 TARGET_COMM_MAP");
        return false;
    };
    let mut target_map = match AyaHashMap::<_, [u8; 15], u32>::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            crate::diag_warn!("eBPF TARGET_COMM_MAP 类型转换失败 ({})", e);
            return false;
        }
    };

    let old_keys: Vec<[u8; 15]> = target_map.keys().filter_map(|r| r.ok()).collect();
    for key in &old_keys {
        let _ = target_map.remove(key);
    }

    let mut count = 0;
    for key in &entries {
        if target_map.insert(key, 1, 0).is_ok() {
            count += 1;
        }
    }

    if count < entries.len() {
        crate::diag_warn!(
            "eBPF 白名单插入部分失败（{}/{}），触发重载",
            count,
            entries.len()
        );
        return true;
    }

    if COMM_KEYS_SEEN.swap(count as u32, Ordering::Relaxed) != count as u32 {
        crate::diag_say!(
            "eBPF 白名单已配置，{} 个包名 → {} 个 comm 键（各取包名前 15/末 15 字节，重复的合并）",
            pkgs.len(),
            count
        );
    }
    false
}

/// 检测 tracefs 根路径，现代内核优先 tracing 旧内核回退 debug/tracing
fn tracefs_root() -> Option<&'static str> {
    if fs::metadata("/sys/kernel/tracing").is_ok() {
        return Some("/sys/kernel/tracing");
    }
    if fs::metadata("/sys/kernel/debug/tracing").is_ok() {
        return Some("/sys/kernel/debug/tracing");
    }
    None
}

/// 解析 tracepoint format 文件提取字段名到偏移映射，字段名剥离数组下标
fn tracepoint_parse(root: &str, category: &str, name: &str) -> Option<HashMap<String, u32>> {
    let path = format!("{}/events/{}/{}/format", root, category, name);
    let content = fs::read_to_string(&path).ok()?;
    let mut offsets = HashMap::new();
    for line in content.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let parts: Vec<&str> = rest.split(';').map(|s| s.trim()).collect();
        if parts.len() < 2 {
            continue;
        }
        let field_name = parts[0]
            .split_whitespace()
            .last()
            .unwrap_or("")
            .split('[')
            .next()
            .unwrap_or("");
        if field_name.is_empty() {
            continue;
        }
        for part in &parts[1..] {
            if let Some(off_str) = part.strip_prefix("offset:")
                && let Ok(off) = off_str.trim().parse::<u32>()
            {
                offsets.insert(field_name.to_string(), off);
                break;
            }
        }
    }
    Some(offsets)
}

/// 解析本机 format 文件并注入 OFFSETS_MAP 索引 0，失败返回 false 由调用方回退 /proc
fn offsets_inject(bpf: &mut Ebpf) -> bool {
    let Some(root) = tracefs_root() else {
        crate::diag_warn!("eBPF tracefs 不可用，回退到 /proc 轮询");
        return false;
    };

    let offsets = (|| {
        let fork_fields = tracepoint_parse(root, "sched", "sched_process_fork")?;
        let rename_fields = tracepoint_parse(root, "task", "task_rename")?;
        Some(EbpfOffsets {
            fork_child_pid: *fork_fields.get("child_pid")?,
            fork_child_comm: *fork_fields.get("child_comm")?,
            rename_newcomm: *rename_fields.get("newcomm")?,
        })
    })();
    let Some(offsets) = offsets else {
        crate::diag_warn!(
            "eBPF tracepoint format 解析失败 [{}]，回退到 /proc 轮询",
            root
        );
        return false;
    };

    let Some(map) = bpf.map_mut("OFFSETS_MAP") else {
        crate::diag_warn!("eBPF 未找到 OFFSETS_MAP，回退到 /proc 轮询");
        return false;
    };
    let Ok(mut offsets_map) = AyaArray::<_, EbpfOffsets>::try_from(map) else {
        crate::diag_warn!("eBPF OFFSETS_MAP 类型转换失败，回退到 /proc 轮询");
        return false;
    };
    if offsets_map.set(0, offsets, 0).is_err() {
        crate::diag_warn!("eBPF OFFSETS_MAP 注入失败，回退到 /proc 轮询");
        return false;
    }

    // 这三个数都是结构体字节偏移，不是字段值。写成 `child_comm=28` 会被
    // 读成「comm 是 28」，真机上已经有人问过这是不是异常
    crate::diag_say!(
        "eBPF tracepoint 字段偏移注入 [{}] fork(child_pid@{}B, child_comm@{}B) rename(newcomm@{}B)",
        root,
        offsets.fork_child_pid,
        offsets.fork_child_comm,
        offsets.rename_newcomm
    );
    true
}

/// 挂 `sched_setaffinity` 探针。
///
/// 参数的寄存器位置随架构不同，同一份字节码要在两种架构上跑，只能在运行时
/// 注入偏移。挂不上不算失败：内核没开 kprobe、syscall wrapper 符号被裁掉、
/// 或 SELinux 拦下 perf_event_open，都会走到这里返回 false，
/// 退回到原来的周期校验。
/// `sched_setaffinity` 的入口符号，按架构排尝试顺序。
///
/// Android 导出的都是 syscall 包装 `__arm64_sys_*` / `__x64_sys_*`，
/// 更老的内核直接导出 `sys_sched_setaffinity`。混着试只会在日志里
/// 多两条「符号不存在」，看着像两个都坏了。
fn probe_symbols(arch: &str) -> &'static [&'static str] {
    match arch {
        "aarch64" => &["__arm64_sys_sched_setaffinity", "sys_sched_setaffinity"],
        _ => &["__x64_sys_sched_setaffinity", "sys_sched_setaffinity"],
    }
}

fn attach_affinity_probe(bpf: &mut Ebpf) -> bool {
    // arm64: pt_regs.regs[0] 存参数块指针，参数块里 regs[0]=pid、regs[2]=mask
    // x86_64: pt_regs.di(112) 存参数块指针，参数块里 di(112)=pid、dx(96)=mask
    let (regs, pid, mask) = match std::env::consts::ARCH {
        "aarch64" => (0u32, 0u32, 16u32),
        "x86_64" => (112u32, 112u32, 96u32),
        other => {
            crate::diag_warn!("kprobe 改写监听不支持 {} 架构，改写仍按周期校验回改", other);
            return false;
        }
    };
    {
        let Some(map) = bpf.map_mut("REGS_OFF") else {
            crate::diag_warn!("eBPF 未找到 REGS_OFF map，跳过改写监听");
            return false;
        };
        let Ok(mut arr) = AyaArray::<_, RegsOff>::try_from(map) else {
            crate::diag_warn!("eBPF REGS_OFF map 类型不符，跳过改写监听");
            return false;
        };
        if let Err(e) = arr.set(
            0,
            RegsOff {
                ready: 1,
                regs,
                pid,
                mask,
            },
            0,
        ) {
            crate::diag_warn!("eBPF 注入 pt_regs 偏移失败 ({})，跳过改写监听", e);
            return false;
        }
    }

    let Some(prog) = bpf.program_mut("setaffinity") else {
        crate::diag_warn!("eBPF 未找到 setaffinity 程序，跳过改写监听");
        return false;
    };
    let Ok(kp): Result<&mut AyaKProbe, _> = prog.try_into() else {
        crate::diag_warn!("eBPF setaffinity 程序类型不符，跳过改写监听");
        return false;
    };
    // aya 0.14 不在 load 对象时加载程序，attach 前必须自己 load 一次。
    // 少了这一步，attach 会报 "the program is not loaded"（beta25 就是这样）。
    if let Err(e) = kp.load() {
        AFFINITY_PROBE.store(2, Ordering::Relaxed);
        crate::diag_warn!(
            "kprobe 程序未通过内核校验 ({})，改写监听关闭，仍按周期校验回改",
            e
        );
        return false;
    }

    for sym in probe_symbols(std::env::consts::ARCH) {
        match kp.attach(*sym, 0) {
            Ok(_) => {
                AFFINITY_PROBE.store(1, Ordering::Relaxed);
                crate::diag_say!("eBPF 已监听 {}，外部改写立刻改回", sym);
                return true;
            }
            Err(e) => crate::diag_warn!("kprobe {} 挂载失败 ({})", sym, e),
        }
    }
    AFFINITY_PROBE.store(2, Ordering::Relaxed);
    crate::diag_warn!("kprobe 改写监听不可用（符号缺失或被策略拦截），仍按周期校验回改");
    false
}

/// 初始化 eBPF，加载程序 attach tracepoint 创建 RingBuf 线程，失败回退 /proc
pub fn ebpf_init() -> Option<EbpfState> {
    if !ebpf_probe() {
        crate::diag_warn!("eBPF 内核不支持（缺少 BTF），回退到 /proc 轮询");
        return None;
    }

    let ebpf_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("AppOpt-ebpf")))?;

    if !ebpf_path.exists() {
        crate::diag_warn!("eBPF 未找到 {}，回退到 /proc 轮询", ebpf_path.display());
        return None;
    }

    // 这份字节码会以 root 身份加载进内核，被替换就是持久的 rootkit，
    // 比改配置文件更隐蔽（下次重启自动生效）。只接受属主 root、
    // 组/其他不可写的普通文件；符号链接一律不接，避免被换链
    {
        use std::os::unix::fs::MetadataExt;

        let md = match fs::symlink_metadata(&ebpf_path) {
            Ok(m) => m,
            Err(e) => {
                crate::diag_warn!(
                    "eBPF 无法检查 {} ({})，回退到 /proc 轮询",
                    ebpf_path.display(),
                    e
                );
                return None;
            }
        };
        let mode = md.mode() & 0o777;
        if !md.file_type().is_file() || md.uid() != 0 || mode & 0o022 != 0 {
            crate::diag_warn!(
                "eBPF {} 不安全（需 root 所有、组与其他不可写，当前 uid={} mode={:o}），拒绝加载",
                ebpf_path.display(),
                md.uid(),
                mode
            );
            return None;
        }
    }

    let ebpf_data = match fs::read(&ebpf_path) {
        Ok(d) => d,
        Err(e) => {
            crate::diag_warn!(
                "eBPF 读取 {} 失败 ({})，回退到 /proc 轮询",
                ebpf_path.display(),
                e
            );
            return None;
        }
    };

    if ebpf_data.is_empty() {
        crate::diag_warn!("eBPF {} 文件为空，回退到 /proc 轮询", ebpf_path.display());
        return None;
    }
    // 加载器只认 ELF，这里先挡掉明显不是字节码的内容
    if !ebpf_data.starts_with(b"\x7fELF") {
        crate::diag_warn!(
            "eBPF {} 不是 ELF 文件，回退到 /proc 轮询",
            ebpf_path.display()
        );
        return None;
    }

    crate::diag_say!(
        "eBPF 从 {} 加载程序 ({} bytes)",
        ebpf_path.display(),
        ebpf_data.len()
    );

    let pkgs_len = crate::lock_ignore_poison(&CURRENT_CONFIG)
        .as_ref()
        .map(|cfg| cfg.pkgs.len())
        .unwrap_or(0);
    let capacity = (pkgs_len * 2).max(512).next_power_of_two() as u32;

    let mut loader = EbpfLoader::new();
    loader.map_max_entries("TARGET_COMM_MAP", capacity);
    let mut bpf = match loader.load(&ebpf_data) {
        Ok(b) => b,
        Err(e) => {
            crate::diag_warn!("eBPF 加载失败 ({})，回退到 /proc 轮询", e);
            return None;
        }
    };

    // attach 前注入偏移避免首批事件读到空 map
    if !offsets_inject(&mut bpf) {
        return None;
    }

    if !attach_tracepoint(&mut bpf, "sched", "sched_process_fork", true) {
        return None;
    }
    if !attach_tracepoint(&mut bpf, "sched", "sched_process_exec", true) {
        return None;
    }
    if !attach_tracepoint(&mut bpf, "sched", "sched_process_exit", true) {
        return None;
    }
    if !attach_tracepoint(&mut bpf, "task", "task_rename", true) {
        return None;
    }

    let ring_buf = match bpf.take_map("EVENTS") {
        Some(map) => match aya::maps::RingBuf::try_from(map) {
            Ok(rb) => rb,
            Err(e) => {
                crate::diag_warn!("eBPF EVENTS map 类型转换失败 ({})，回退到 /proc 轮询", e);
                return None;
            }
        },
        None => {
            crate::diag_warn!("eBPF 未找到 EVENTS map，回退到 /proc 轮询");
            return None;
        }
    };

    // 可选能力：挂不上只影响「被改写后多久改回」，绑核本身照常
    attach_affinity_probe(&mut bpf);

    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        crate::diag_warn!("eBPF eventfd 创建失败，回退到 /proc 轮询");
        return None;
    }
    let reader_thread = thread::spawn(move || {
        ebpf_reader(ring_buf, tx, wakeup_fd);
    });

    crate::diag_say!("eBPF 初始化成功");

    Some(EbpfState {
        event_rx: rx,
        reader_thread: Some(reader_thread),
        bpf,
        cache: ProcCache::new(),
        wakeup_fd,
        comm_capacity: capacity,
        cfg_sig: HashMap::new(),
        cfg_policy_sig: 0,
        drop_seen: 0,
        last_fix: HashMap::new(),
    })
}

/// RingBuf 读取线程，epoll 阻塞等待事件 wakeup_fd 用于 Drop 唤醒退出
fn ebpf_reader(
    mut ring_buf: aya::maps::RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<EbpfProcEvent>,
    wakeup_fd: RawFd,
) {
    let name = CString::new("EbpfReader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        crate::diag_warn!("eBPF epoll_create1 失败");
        return;
    }

    let ring_fd = ring_buf.as_raw_fd();
    let mut ring_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ring_ev.events = libc::EPOLLIN as u32;
    ring_ev.u64 = 0;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ring_fd, &mut ring_ev) } < 0 {
        crate::diag_warn!("eBPF epoll_ctl ADD ring_fd 失败");
        unsafe { libc::close(epfd) };
        return;
    }

    let mut wake_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    wake_ev.events = libc::EPOLLIN as u32;
    wake_ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut wake_ev) } < 0 {
        crate::diag_warn!("eBPF epoll_ctl ADD wakeup_fd 失败");
        unsafe { libc::close(epfd) };
        return;
    }

    let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, -1) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        // wakeup 事件优先退出
        if events.iter().take(n as usize).any(|e| e.u64 == 1) {
            break;
        }

        while let Some(item) = ring_buf.next() {
            let bytes: &[u8] = &item;
            if bytes.len() >= std::mem::size_of::<EbpfProcEvent>() {
                let event: EbpfProcEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfProcEvent) };
                if tx.send(event).is_err() {
                    unsafe { libc::close(epfd) };
                    return;
                }
            }
        }
    }
    unsafe { libc::close(epfd) };
}

fn applied_get(bpf: &mut Ebpf) -> Option<AyaHashMap<&mut aya::maps::MapData, u32, u64>> {
    AyaHashMap::<_, u32, u64>::try_from(bpf.map_mut("APPLIED_MAP")?).ok()
}

fn applied_set(bpf: &mut Ebpf, tid: i32, cpus: &CpuSet) {
    let Some(mut applied) = applied_get(bpf) else {
        return;
    };
    if let Err(e) = applied.insert(tid as u32, cpus.bits[0], 0) {
        crate::diag_warn!(
            "eBPF APPLIED_MAP 插入失败 tid={} ({})，map 可能已满",
            tid,
            e
        );
    }
}

fn applied_del(bpf: &mut Ebpf, tid: i32) {
    let Some(mut applied) = applied_get(bpf) else {
        return;
    };
    let _ = applied.remove(&(tid as u32));
}

fn applied_clear(bpf: &mut Ebpf) {
    let Some(mut m) = applied_get(bpf) else {
        return;
    };
    let keys: Vec<u32> = m.keys().filter_map(|r| r.ok()).collect();
    for k in &keys {
        let _ = m.remove(k);
    }
}

/// 读取内核侧累计丢弃数：per-CPU 槽位求和。旧版对象文件是普通 Array，同样返回累计值
fn drop_count_read(bpf: &mut Ebpf) -> Option<u64> {
    let map = bpf.map_mut("DROP_COUNT")?;
    if matches!(map, Map::PerCpuArray(_)) {
        let arr = AyaPerCpuArray::<_, u64>::try_from(map).ok()?;
        let values = arr.get(&0, 0).ok()?;
        return Some(values.iter().fold(0u64, |acc, v| acc.saturating_add(*v)));
    }
    // 旧版 AppOpt-ebpf 用普通 Array；按累计值差分，不依赖清零也不会丢增量
    if matches!(map, Map::Array(_)) {
        let arr = AyaArray::<_, u64>::try_from(map).ok()?;
        return arr.get(&0, 0).ok();
    }
    None
}

/// 累计计数差分：只统计新增丢弃量，读取期间继续递增的计数留到下一轮。
/// current 小于基准说明计数器被重建（重新加载 eBPF），此时只更新基准，不重复对账
fn drop_delta(seen: &mut u64, current: u64) -> u64 {
    if current < *seen {
        *seen = current;
        return 0;
    }
    let delta = current - *seen;
    *seen = current;
    delta
}

/// RingBuf 丢事件对账：低频对比内核累计计数，有新增丢弃则全量重扫一次
/// 缓存状态由 full_scan 重建，不额外引入心跳或高频 /proc 扫描
pub fn reconcile(state: &mut EbpfState, cfg: &AppConfig) {
    let Some(current) = drop_count_read(&mut state.bpf) else {
        return;
    };
    let delta = drop_delta(&mut state.drop_seen, current);
    if delta == 0 {
        return;
    }
    DROPPED_TOTAL.fetch_add(delta, Ordering::Relaxed);
    crate::diag_warn!("eBPF RingBuf 丢弃 {} 条事件，执行全量对账扫描", delta);
    full_scan(cfg, state);
}

/// 应用亲和性并写 APPLIED_MAP，返回 true 表示 tid 已退出。
///
/// 参数多是因为它要转交 `affinity_apply` 的全部上下文（含两种布尔语义：
/// `recheck` 决定漂移判定、`verify` 决定要不要补组），拆结构体反而多一层
#[allow(clippy::too_many_arguments)]
/// APPLIED_MAP 的语义是「已被本模块接管」，设置失败也保持接管关系，
/// 否则该线程的 EXIT 事件不再上报，缓存会一直留到下次 reconcile
fn affinity_apply_task(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: Option<&str>,
    cfg: &AppConfig,
    bpf: &mut Ebpf,
    comm: &str,
    recheck: bool,
    verify_group: bool,
) -> AffinityOutcome {
    // 复核走 Sync 语义：只有它能区分「首次绑定」与「读回被改写」
    let reason = if recheck {
        ApplyReason::Sync
    } else {
        ApplyReason::Rule
    };
    let outcome = affinity_apply(tid, cpus, cpuset_dir, &cfg.topo, reason, comm, verify_group).0;
    if outcome != AffinityOutcome::Gone {
        applied_set(bpf, tid, cpus);
    }
    outcome
}

/// 事件派发，按 event_type 增量处理 FORK/RENAME/EXEC/EXIT
pub fn event_dispatch(event: &EbpfProcEvent, cfg: &AppConfig, state: &mut EbpfState) {
    let tid = event.tid;
    let pid = event.pid;
    let comm = comm_str(&event.comm);

    match event.event_type {
        EBPF_EVENT_EXIT => {
            // 内核态已在 sched_process_exit 里删除 APPLIED_MAP[tid]，此处不再重复删除
            // task_gone 内部已经把账本记录（含 RT 所有权）一并删掉
            state.cache.task_gone(tid);
            state.last_fix.remove(&tid);
        }

        EBPF_EVENT_EXEC if !event_apply(&mut state.cache, &mut state.bpf, tid, pid, comm, cfg) => {
            state.cache.task_del(tid);
            applied_del(&mut state.bpf, tid);
        }

        EBPF_EVENT_FORK => {
            // 内核已不再下发 FORK 事件：子线程创建即继承父线程 affinity 与 cpuset，
            // 用户态无需动作；APPLIED_MAP 占位由内核侧完成，EXIT 仍会上报。
            // 此分支仅用于兼容旧版 AppOpt-ebpf 二进制，收到事件同样不做处理。
        }

        EBPF_EVENT_RENAME => {
            event_apply(&mut state.cache, &mut state.bpf, tid, pid, comm, cfg);
        }

        EBPF_EVENT_AFFINITY => {
            // 内核侧已比较过掩码，这里只做节流：同一个线程被连续改写时，
            // 100ms 内只重绑一次，剩下的由周期校验收尾
            let now = Instant::now();
            if fix_allowed(state.last_fix.get(&tid).copied(), now) {
                state.last_fix.insert(tid, now);
                rebind_known(state, tid, cfg);
            }
        }

        _ => {}
    }
}

/// 统一事件处理 pkg_lookup_comm 到 task_apply
fn event_apply(
    cache: &mut ProcCache,
    bpf: &mut Ebpf,
    tid: i32,
    pid: i32,
    comm: &str,
    cfg: &AppConfig,
) -> bool {
    let Some(pkg) = cache.pkg_lookup_comm(pid, comm, cfg) else {
        return false;
    };

    let ok = cache.task_apply(tid, pid, &pkg, comm, cfg, |t, c, d, recheck, verify| {
        affinity_apply_task(t, c, d, cfg, bpf, comm, recheck, verify)
    });
    // 规则命中且亲和性写入成功后再考虑 RT，避免把没被管理的线程提升
    if ok && let Some(e) = cache.tasks.get(&tid) {
        rt::note(tid, pid, &e.pkg, &e.comm, &e.cpus, cfg);
    }
    ok
}

/// 探针报来的外部改写：按缓存里已有的包名重绑。
///
/// 不能用 `event_apply`：那里的 comm 是改写方（HAL 线程）的名字，
/// 拿它去查包名必然查不到，只能靠 `cache.tasks` 里记着的那条。
fn rebind_known(state: &mut EbpfState, tid: i32, cfg: &AppConfig) {
    let Some((pkg, comm, pid)) = state
        .cache
        .tasks
        .get(&tid)
        .map(|e| (e.pkg.clone(), e.comm.clone(), e.pid))
    else {
        return;
    };
    let bpf = &mut state.bpf;
    state
        .cache
        .task_apply(tid, pid, &pkg, &comm, cfg, |t, c, d, r, v| {
            affinity_apply_task(t, c, d, cfg, bpf, &comm, r, v)
        });
}

/// 定期纠正 affinity_sync 清死亡 tid
pub fn affinity_check(state: &mut EbpfState, cfg: &AppConfig) {
    let dead_tids = state.cache.affinity_sync(cfg);
    for tid in dead_tids {
        // 这里的 tid 已经 ESRCH。`affinity_sync` 对每个死号都调了 `task_gone`，
        // 账本记录（含 RT 所有权）已经收回，只剩 eBPF 表要清
        applied_del(&mut state.bpf, tid);
    }
}

/// 启动或配置更新时全量扫描 /proc
pub fn full_scan(cfg: &AppConfig, state: &mut EbpfState) {
    state.cache.clear();
    state.last_fix.clear();
    applied_clear(&mut state.bpf);

    proc_walk(
        cfg,
        |_| true,
        |pid, pkg| {
            let Some(tids) = task_tids(pid) else { return };
            // 线程名按需读取：线程规则、S7 角色、RT 匹配任一需要才读
            let need_comm = cfg.needs_comm(pkg);
            for tid in tids {
                let t_name = if need_comm {
                    tid_comm(tid).unwrap_or_default()
                } else {
                    String::new()
                };
                let ok = state.cache.task_apply(
                    tid,
                    pid,
                    pkg,
                    &t_name,
                    cfg,
                    |tid, cpus, cpuset_dir, recheck, verify| {
                        affinity_apply_task(
                            tid,
                            cpus,
                            cpuset_dir,
                            cfg,
                            &mut state.bpf,
                            &t_name,
                            recheck,
                            verify,
                        )
                    },
                );
                if ok && let Some(e) = state.cache.tasks.get(&tid) {
                    rt::note(tid, pid, &e.pkg, &e.comm, &e.cpus, cfg);
                }
            }
        },
    );
    state.cfg_sig = cfg.pkg_sig.clone();
    state.cfg_policy_sig = cfg.policy_sig;
    // 缓存重建后再对账 RT：扫描期间退出的进程、被移出配置的包不能再留着 RT 记录
    rt::reconcile(cfg, &state.cache);
}

/// 比对两轮逐包指纹，返回（新增或变更、已删除）的包名
fn cfg_diff(old: &HashMap<String, u64>, new: &HashMap<String, u64>) -> (Vec<String>, Vec<String>) {
    let mut changed: Vec<String> = Vec::new();
    for (pkg, sig) in new {
        match old.get(pkg) {
            Some(prev) if prev == sig => {}
            _ => changed.push(pkg.clone()),
        }
    }
    let removed: Vec<String> = old
        .keys()
        .filter(|p| !new.contains_key(*p))
        .cloned()
        .collect();
    (changed, removed)
}

/// 配置变更后的增量重建：只清理并重扫规则发生变化的包，其余包的缓存与亲和性保持不变。
/// 影响面过大（超过 4 个包）或删除了包时仍走全量，避免漏判导致残留绑定。
pub fn config_rescan(new: &AppConfig, state: &mut EbpfState) {
    // 全局策略变化影响所有已缓存线程，逐包增量覆盖不到，直接全量重建
    if state.cfg_policy_sig != new.policy_sig {
        full_scan(new, state);
        return;
    }
    let (targets, removed) = cfg_diff(&state.cfg_sig, &new.pkg_sig);

    if targets.is_empty() && removed.is_empty() {
        state.cfg_sig = new.pkg_sig.clone();
        return;
    }
    if targets.len() + removed.len() > 4 {
        full_scan(new, state);
        return;
    }

    for pkg in targets.iter().chain(removed.iter()) {
        for tid in state.cache.purge_pkg(pkg) {
            applied_del(&mut state.bpf, tid);
        }
    }

    if !targets.is_empty() {
        let target_set: HashSet<&str> = targets.iter().map(|s| s.as_str()).collect();
        proc_walk(
            new,
            |_| true,
            |pid, pkg| {
                if !target_set.contains(pkg) {
                    return;
                }
                let Some(tids) = task_tids(pid) else { return };
                let need_comm = new.needs_comm(pkg);
                for tid in tids {
                    let t_name = if need_comm {
                        tid_comm(tid).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    let ok = state.cache.task_apply(
                        tid,
                        pid,
                        pkg,
                        &t_name,
                        new,
                        |tid, cpus, dir, recheck, verify| {
                            affinity_apply_task(
                                tid,
                                cpus,
                                dir,
                                new,
                                &mut state.bpf,
                                &t_name,
                                recheck,
                                verify,
                            )
                        },
                    );
                    if ok && let Some(e) = state.cache.tasks.get(&tid) {
                        rt::note(tid, pid, &e.pkg, &e.comm, &e.cpus, new);
                    }
                }
            },
        );
    }

    state.cfg_sig = new.pkg_sig.clone();
    // 被移除的包已从缓存清掉，这里收回它们的 RT 记录
    rt::reconcile(new, &state.cache);
    crate::diag_say!(
        "eBPF 规则增量重建 {} 个应用，移除 {} 个应用的绑定记录",
        targets.len(),
        removed.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig_of(items: &[(&str, u64)]) -> HashMap<String, u64> {
        items.iter().map(|(p, s)| (p.to_string(), *s)).collect()
    }

    #[test]
    fn unchanged_config_has_no_targets() {
        let old = sig_of(&[("com.a", 1), ("com.b", 2)]);
        let (changed, removed) = cfg_diff(&old, &old);
        assert!(changed.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn only_modified_pkg_is_rebuilt() {
        let old = sig_of(&[("com.a", 1), ("com.b", 2)]);
        let new = sig_of(&[("com.a", 9), ("com.b", 2)]);
        let (changed, removed) = cfg_diff(&old, &new);
        assert_eq!(changed, vec!["com.a".to_string()]);
        assert!(removed.is_empty());
    }

    #[test]
    fn added_and_removed_pkgs_are_reported() {
        let old = sig_of(&[("com.a", 1)]);
        let new = sig_of(&[("com.b", 2)]);
        let (mut changed, mut removed) = cfg_diff(&old, &new);
        changed.sort();
        removed.sort();
        assert_eq!(changed, vec!["com.b".to_string()]);
        assert_eq!(removed, vec!["com.a".to_string()]);
    }

    /// 必须与 AppOpt-ebpf/src/main.rs 的 ProcEvent 完全一致，否则事件解析错位
    #[test]
    fn event_layout_matches_kernel_definition() {
        assert_eq!(std::mem::size_of::<EbpfProcEvent>(), 28);
        assert_eq!(std::mem::align_of::<EbpfProcEvent>(), 4);
        assert_eq!(EBPF_EVENT_FORK, 1);
        assert_eq!(EBPF_EVENT_EXEC, 2);
        assert_eq!(EBPF_EVENT_RENAME, 3);
        assert_eq!(EBPF_EVENT_EXIT, 4);
        // 偏移注入结构同样是三个 u32
        assert_eq!(std::mem::size_of::<EbpfOffsets>(), 12);
    }

    #[test]
    fn drop_delta_counts_only_new_drops() {
        let mut seen = 0u64;
        assert_eq!(drop_delta(&mut seen, 3), 3);
        assert_eq!(drop_delta(&mut seen, 7), 4);
        // 计数没有增长时不重复触发对账
        assert_eq!(drop_delta(&mut seen, 7), 0);
        assert_eq!(seen, 7);
    }

    #[test]
    fn drop_delta_keeps_increments_during_read() {
        // 读取后、下一轮之前内核继续累加的部分留到下一轮，不会丢
        let mut seen = 0u64;
        assert_eq!(drop_delta(&mut seen, 2), 2);
        assert_eq!(drop_delta(&mut seen, 5), 3);
    }

    #[test]
    fn drop_delta_treats_reset_as_new_baseline() {
        let mut seen = 10u64;
        // eBPF 重新加载后计数从头开始，只更新基准，不应把旧值当成一次大丢弃
        assert_eq!(drop_delta(&mut seen, 1), 0);
        assert_eq!(seen, 1);
        assert_eq!(drop_delta(&mut seen, 3), 2);
    }

    fn cfg_of(name: &str, conf: &str) -> AppConfig {
        let p = format!("/tmp/appopt_ebpf_test_{}.conf", name);
        std::fs::write(&p, conf).unwrap();
        let topo = crate::cpuset::init_cpu_topo();
        let mut m = -1i64;
        crate::config::load_config(&p, &topo, &mut m).unwrap()
    }

    #[test]
    fn global_policy_change_requires_full_scan() {
        let keep = cfg_of("policy_keep", "@unmatched=keep\ncom.a=0-1\ncom.b=2-3\n");
        let all = cfg_of("policy_all", "@unmatched=all\ncom.a=0-1\ncom.b=2-3\n");
        assert_ne!(keep.policy_sig, all.policy_sig);
        // 逐包指纹完全一致，说明只靠 cfg_diff 发现不了这次变更
        let (changed, removed) = cfg_diff(&keep.pkg_sig, &all.pkg_sig);
        assert!(changed.is_empty(), "逐包指纹不应变化：{:?}", changed);
        assert!(removed.is_empty());
    }

    #[test]
    fn identical_global_policy_keeps_signature() {
        let a = cfg_of("policy_same_a", "com.a=0-1\n");
        let b = cfg_of("policy_same_b", "@unmatched=keep\ncom.a=0-1\n");
        // 缺省值与显式 keep 等价，不应触发全量重建
        assert_eq!(a.policy_sig, b.policy_sig);
        assert_eq!(a.pkg_sig, b.pkg_sig);
    }

    #[test]
    fn affinity_event_number_stays_stable() {
        // 与 AppOpt-ebpf 的 EVENT_AFFINITY 必须一致，改一处就是 ABI 变更
        assert_eq!(EBPF_EVENT_AFFINITY, 5);
        assert_eq!(std::mem::size_of::<RegsOff>(), 16);
    }

    #[test]
    fn probe_symbols_follow_arch() {
        assert_eq!(probe_symbols("aarch64")[0], "__arm64_sys_sched_setaffinity");
        assert_eq!(probe_symbols("x86_64")[0], "__x64_sys_sched_setaffinity");
        // 每个架构都要留老内核的兜底名
        assert_eq!(
            probe_symbols("aarch64").last(),
            Some(&"sys_sched_setaffinity")
        );
        assert_eq!(
            probe_symbols("x86_64").last(),
            Some(&"sys_sched_setaffinity")
        );
    }

    #[test]
    fn throttle_lets_one_fix_per_window() {
        let t0 = Instant::now();
        assert!(fix_allowed(None, t0));
        assert!(!fix_allowed(Some(t0), t0 + Duration::from_millis(99)));
        assert!(fix_allowed(Some(t0), t0 + Duration::from_millis(100)));
    }

    #[test]
    fn policy_and_rule_change_together() {
        let old = cfg_of("policy_mix_old", "@unmatched=keep\ncom.a=0-1\n");
        let new = cfg_of("policy_mix_new", "@unmatched=all\ncom.a=0-2\n");
        assert_ne!(old.policy_sig, new.policy_sig);
        let (changed, _) = cfg_diff(&old.pkg_sig, &new.pkg_sig);
        assert_eq!(changed, vec!["com.a".to_string()]);
    }
}
