use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;

use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, Map, PerCpuArray as AyaPerCpuArray};
use aya::{programs::TracePoint as AyaTracePoint, Ebpf, EbpfLoader, Pod};

use crate::apply_affinity::{affinity_set, proc_walk, task_tids, tid_comm};
use crate::cache::ProcCache;
use crate::config::{AppConfig, CURRENT_CONFIG};
use crate::cpuset::CpuSet;

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

/// 运行期累计的 RingBuf 丢弃事件数，供 Web 状态展示
pub static DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// 用户态注入内核的 tracepoint 字段偏移，布局需与内核态 TracepointOffsets 一致
#[repr(C)]
#[derive(Clone, Copy)]
struct EbpfOffsets {
    fork_child_pid: u32,
    fork_child_comm: u32,
    rename_newcomm: u32,
}

unsafe impl Pod for EbpfOffsets {}

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
    /// 上一轮读到的内核累计丢弃数，用于差分求新增丢弃
    pub drop_seen: u64,
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
            unsafe { libc::close(self.wakeup_fd); }
        }
    }
}

pub fn ebpf_probe() -> bool {
    fs::metadata("/sys/kernel/btf/vmlinux").is_ok()
}

fn attach_tracepoint(bpf: &mut Ebpf, category: &str, name: &str, required: bool) -> bool {
    let Some(prog) = bpf.program_mut(name) else {
        if required {
            eprintln!("eBPF: 未找到 {} 程序", name);
        }
        return false;
    };
    let Ok(tp): Result<&mut AyaTracePoint, _> = prog.try_into() else {
        if required {
            eprintln!("eBPF: {} 类型转换失败", name);
        }
        return false;
    };
    if let Err(e) = tp.load() {
        if required {
            eprintln!("eBPF: {} 加载失败 ({})", name, e);
        }
        return false;
    }
    if let Err(e) = tp.attach(category, name) {
        if required {
            eprintln!("eBPF: {} 附加失败 ({})", name, e);
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
        eprintln!(
            "eBPF: 白名单容量不足（需 {} > 现 {}），触发内核端重载",
            entries.len(),
            comm_capacity
        );
        return true;
    }

    let Some(map) = bpf.map_mut("TARGET_COMM_MAP") else {
        eprintln!("eBPF: 未找到 TARGET_COMM_MAP");
        return false;
    };
    let mut target_map = match AyaHashMap::<_, [u8; 15], u32>::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("eBPF: TARGET_COMM_MAP 类型转换失败 ({})", e);
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
        eprintln!(
            "eBPF: 白名单插入部分失败（{}/{}），触发重载",
            count,
            entries.len()
        );
        return true;
    }

    println!(
        "eBPF: 白名单已配置，{} 个包名 > {} 条匹配规则",
        pkgs.len(),
        count
    );
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
        let field_name = parts[0].split_whitespace().last().unwrap_or("").split('[').next().unwrap_or("");
        if field_name.is_empty() {
            continue;
        }
        for part in &parts[1..] {
            if let Some(off_str) = part.strip_prefix("offset:")
                && let Ok(off) = off_str.trim().parse::<u32>() {
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
        eprintln!("eBPF: tracefs 不可用，回退到 /proc 轮询");
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
        eprintln!(
            "eBPF: tracepoint format 解析失败 [{}]，回退到 /proc 轮询",
            root
        );
        return false;
    };

    let Some(map) = bpf.map_mut("OFFSETS_MAP") else {
        eprintln!("eBPF: 未找到 OFFSETS_MAP，回退到 /proc 轮询");
        return false;
    };
    let Ok(mut offsets_map) = AyaArray::<_, EbpfOffsets>::try_from(map) else {
        eprintln!("eBPF: OFFSETS_MAP 类型转换失败，回退到 /proc 轮询");
        return false;
    };
    if offsets_map.set(0, offsets, 0).is_err() {
        eprintln!("eBPF: OFFSETS_MAP 注入失败，回退到 /proc 轮询");
        return false;
    }

    println!(
        "eBPF: tracepoint 偏移注入 [{}] fork[child_pid={}, child_comm={}] rename[newcomm={}]",
        root, offsets.fork_child_pid, offsets.fork_child_comm, offsets.rename_newcomm
    );
    true
}

/// 初始化 eBPF，加载程序 attach tracepoint 创建 RingBuf 线程，失败回退 /proc
pub fn ebpf_init() -> Option<EbpfState> {
    if !ebpf_probe() {
        eprintln!("eBPF: 内核不支持（缺少 BTF），回退到 /proc 轮询");
        return None;
    }

    let ebpf_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("AppOpt-ebpf")))?;

    if !ebpf_path.exists() {
        eprintln!("eBPF: 未找到 {}，回退到 /proc 轮询", ebpf_path.display());
        return None;
    }

    let ebpf_data = match fs::read(&ebpf_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "eBPF: 读取 {} 失败 ({})，回退到 /proc 轮询",
                ebpf_path.display(),
                e
            );
            return None;
        }
    };

    if ebpf_data.is_empty() {
        eprintln!("eBPF: {} 文件为空，回退到 /proc 轮询", ebpf_path.display());
        return None;
    }

    println!(
        "eBPF: 从 {} 加载程序 ({} bytes)",
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
            eprintln!("eBPF: 加载失败 ({})，回退到 /proc 轮询", e);
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
                eprintln!("eBPF: EVENTS map 类型转换失败 ({})，回退到 /proc 轮询", e);
                return None;
            }
        },
        None => {
            eprintln!("eBPF: 未找到 EVENTS map，回退到 /proc 轮询");
            return None;
        }
    };

    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        eprintln!("eBPF: eventfd 创建失败，回退到 /proc 轮询");
        return None;
    }
    let reader_thread = thread::spawn(move || {
        ebpf_reader(ring_buf, tx, wakeup_fd);
    });

    println!("eBPF: 初始化成功");

    Some(EbpfState {
        event_rx: rx,
        reader_thread: Some(reader_thread),
        bpf,
        cache: ProcCache::new(),
        wakeup_fd,
        comm_capacity: capacity,
        cfg_sig: HashMap::new(),
        drop_seen: 0,
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
        eprintln!("eBPF: epoll_create1 失败");
        return;
    }

    let ring_fd = ring_buf.as_raw_fd();
    let mut ring_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ring_ev.events = libc::EPOLLIN as u32;
    ring_ev.u64 = 0;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ring_fd, &mut ring_ev) } < 0 {
        eprintln!("eBPF: epoll_ctl ADD ring_fd 失败");
        unsafe { libc::close(epfd) };
        return;
    }

    let mut wake_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    wake_ev.events = libc::EPOLLIN as u32;
    wake_ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut wake_ev) } < 0 {
        eprintln!("eBPF: epoll_ctl ADD wakeup_fd 失败");
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
    let Some(mut applied) = applied_get(bpf) else { return };
    if let Err(e) = applied.insert(tid as u32, cpus.bits[0], 0) {
        eprintln!("eBPF: APPLIED_MAP 插入失败 tid={} ({})，map 可能已满", tid, e);
    }
}

fn applied_del(bpf: &mut Ebpf, tid: i32) {
    let Some(mut applied) = applied_get(bpf) else { return };
    let _ = applied.remove(&(tid as u32));
}

fn applied_clear(bpf: &mut Ebpf) {
    let Some(mut m) = applied_get(bpf) else { return };
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
    eprintln!("eBPF: RingBuf 丢弃 {} 条事件，执行全量对账扫描", delta);
    full_scan(cfg, state);
}

/// 应用亲和性并写 APPLIED_MAP，返回 true 表示 tid 已退出
fn affinity_apply(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    cfg: &AppConfig,
    bpf: &mut Ebpf,
) -> bool {
    let dead = affinity_set(tid, cpus, cpuset_dir, &cfg.topo);
    if !dead {
        applied_set(bpf, tid, cpus);
    }
    dead
}

/// 事件派发，按 event_type 增量处理 FORK/RENAME/EXEC/EXIT
pub fn event_dispatch(event: &EbpfProcEvent, cfg: &AppConfig, state: &mut EbpfState) {
    let tid = event.tid;
    let pid = event.pid;
    let comm = comm_str(&event.comm);

    match event.event_type {
        EBPF_EVENT_EXIT => {
            // 内核态已在 sched_process_exit 里删除 APPLIED_MAP[tid]，此处不再重复删除
            state.cache.task_del(tid);
        }

        EBPF_EVENT_EXEC
            if !event_apply(&mut state.cache, &mut state.bpf, tid, pid, comm, cfg) => {
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

    cache.task_apply(tid, pid, &pkg, comm, cfg, |t, c, d| {
        affinity_apply(t, c, d, cfg, bpf)
    })
}

/// 定期纠正 affinity_sync 清死亡 tid
pub fn affinity_check(state: &mut EbpfState, cfg: &AppConfig) {
    let dead_tids = state.cache.affinity_sync(&cfg.topo);
    for tid in dead_tids {
        applied_del(&mut state.bpf, tid);
    }
}

/// 启动或配置更新时全量扫描 /proc
pub fn full_scan(cfg: &AppConfig, state: &mut EbpfState) {
    state.cache.clear();
    applied_clear(&mut state.bpf);

    proc_walk(cfg, |_| true, |pid, pkg, has_thread_rules| {
        let Some(tids) = task_tids(pid) else { return };
        for tid in tids {
            let t_name = if has_thread_rules {
                tid_comm(tid).unwrap_or_default()
            } else {
                String::new()
            };
            state.cache.task_apply(tid, pid, pkg, &t_name, cfg, |tid, cpus, cpuset_dir| {
                affinity_apply(tid, cpus, cpuset_dir, cfg, &mut state.bpf)
            });
        }
    });
    state.cfg_sig = cfg.pkg_sig.clone();
}

/// 比对两轮逐包指纹，返回（新增或变更、已删除）的包名
fn cfg_diff(
    old: &HashMap<String, u64>,
    new: &HashMap<String, u64>,
) -> (Vec<String>, Vec<String>) {
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
        proc_walk(new, |_| true, |pid, pkg, has_thread_rules| {
            if !target_set.contains(pkg) {
                return;
            }
            let Some(tids) = task_tids(pid) else { return };
            for tid in tids {
                let t_name = if has_thread_rules {
                    tid_comm(tid).unwrap_or_default()
                } else {
                    String::new()
                };
                state.cache.task_apply(tid, pid, pkg, &t_name, new, |tid, cpus, dir| {
                    affinity_apply(tid, cpus, dir, new, &mut state.bpf)
                });
            }
        });
    }

    state.cfg_sig = new.pkg_sig.clone();
    println!(
        "eBPF: 规则增量重建 {} 个应用，移除 {} 个应用的绑定记录",
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

}
