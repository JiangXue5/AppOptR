#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod cache;
mod config;
mod cpuset;
mod diag;
mod ebpf_mode;
mod proc_mode;
mod roles;
mod rt;
mod rule_edit;
mod rule_match;
mod sched;
mod web;

use std::env;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::apply_affinity::{AffinityOutcome, ApplyReason, affinity_apply};
use crate::config::{
    AppConfig, CHECK_INTERVAL, CONFIG_FILE, CURRENT_CONFIG, SchedMode, config_loader, init_inotify,
    load_config,
};
use crate::cpuset::{CpuSet, init_cpu_topo, set_base_cpuset};
use crate::ebpf_mode::{
    DROPPED_TOTAL, EbpfState, affinity_check, comm_map_init, config_rescan, ebpf_init,
    event_dispatch, full_scan, reconcile,
};
use crate::proc_mode::{ProcScanState, cache_sync};
use crate::sched::SchedState;
use crate::web::{
    MODE_FORCE, SETTINGS_FILE, WEB_ENABLED, WEB_STATS, WebStats, cache_stats, settings_load,
    settings_save, web_start,
};

pub const MAX_PKG_LEN: usize = 128;
pub const MAX_THREAD_LEN: usize = 32;

pub static CONFIG_UPDATED: AtomicBool = AtomicBool::new(false);

/// 自动模式下 eBPF 初始化失败后的放弃标记，用户强制切换时清除
pub static EBPF_GAVE_UP: AtomicBool = AtomicBool::new(false);

pub(crate) fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| {
        eprintln!("警告: 互斥锁中毒，尝试恢复...");
        e.into_inner()
    })
}

fn print_help(prog_name: &str) {
    println!("Usage: {} [OPTIONS]", prog_name);
    println!("Options:");
    println!("  -c <config_file>   指定配置文件 (默认: ./applist.conf)");
    println!("  -s <interval>      设置检查间隔(秒) (必须>=1, 默认: 2)");
    println!("  -b <cpuset_name>   指定 BASE_CPUSET 目录名 (默认: AppOpt)");
    println!("  -w                 启用网页前端 (仅本机 127.0.0.1:8889)");
    println!("  -v                 显示程序版本");
    println!("  -h                 显示帮助信息");
    println!();
    println!("示例:");
    println!("  {} -c /data/applist.conf -s 3", prog_name);
    println!("  {} -b MyAppOpt", prog_name);
    println!();
    println!("应用设置保存于 ./AppOpt.json，首次运行自动创建；");
    println!("命令行参数优先于设置文件，web 端修改会写回该文件。");
    println!();
    println!("规则格式:");
    println!("  # 注释以 # 或 // 开头");
    println!("  com.example=0-3           包级规则，绑定到 CPU 0-3");
    println!("  com.example=e-core        语义核心，绑定到全部小核");
    println!("  com.example=p-core        语义核心，绑定到全部中核");
    println!("  com.example=hp-core       语义核心，绑定到全部大核");
    println!();
    println!("  块语法，包级规则 + 线程规则");
    println!("  com.example {{");
    println!("    RenderThread=6-7");
    println!("    Thread-1=0-5");
    println!("  }}");
    println!("  线程 RenderThread 绑定到 CPU 6-7");
    println!("  线程 Thread-1 绑定到 CPU 0-5");
}

/// 单实例锁的持有者，进程退出（含被 kill）时由内核自动释放
struct InstanceLock {
    // 句柄存活即持锁，无需手动解锁
    _file: fs::File,
}

/// 退出标志。信号处理函数里只做原子写，真正的清理放回主循环
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_exit_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Release);
}

/// 注册 SIGTERM / SIGINT。模块停止一般靠 pkill，不接这个信号
/// RT 时间片就只能等下次启动恢复
fn install_exit_handler() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            on_exit_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            on_exit_signal as *const () as libc::sighandler_t,
        );
    }
}

/// 同一 cpuset 目录只允许一个进程管理，不同 -b 名称各自成锁、仍可并行。
///
/// 锁文件与可执行文件同目录（模块安装后即模块目录），文件内的 PID 仅用于冲突提示。
/// 目录不可写、SELinux 受限等情况一律视为“锁不可用”并放行，避免模块整体失效。
fn instance_lock(cpuset_name: &str) -> Option<InstanceLock> {
    let dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| ".".into());
    let path = dir.join(format!(".AppOpt.{}.lock", cpuset_name));
    let file = match fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            crate::diag::tag(
                "警告",
                &format!("无法创建锁文件 {}（{}），跳过单实例检查", path.display(), e),
            );
            return None;
        }
    };
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            let holder = fs::read_to_string(&path).unwrap_or_default();
            let holder = holder.trim();
            if holder.is_empty() {
                crate::diag::tag(
                    "失败",
                    &format!("已有实例在管理 cpuset 目录 {}，本进程退出", cpuset_name),
                );
            } else {
                crate::diag::tag(
                    "失败",
                    &format!(
                        "已有实例（pid {}）在管理 cpuset 目录 {}，本进程退出",
                        holder, cpuset_name
                    ),
                );
            }
            crate::diag::tag("警告", "如需并行，请用 -b 指定不同的 cpuset 目录名");
            process::exit(0);
        }
        crate::diag::tag(
            "警告",
            &format!(
                "锁文件 {} 加锁失败（{}），跳过单实例检查",
                path.display(),
                err
            ),
        );
        return None;
    }
    // 仅作冲突提示用途，不参与运行判定
    let _ = fs::write(&path, format!("{}\n", process::id()));
    Some(InstanceLock { _file: file })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog_name = &args[0];

    // 参数解析先行，-v/-h/错误用法在设置加载前退出，不产生文件副作用
    let (mut cli_cfg, mut cli_interval, mut cli_cpuset, mut cli_web) = (None, None, None, false);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                if i < args.len() {
                    cli_cfg = Some(args[i].clone());
                } else {
                    eprintln!("错误: -c 需要指定配置文件路径");
                    process::exit(1);
                }
            }
            "-s" => {
                i += 1;
                if i < args.len() {
                    let val: u64 = match args[i].parse() {
                        Ok(v) if v >= 1 => v,
                        _ => {
                            eprintln!("无效的时间间隔: {}", args[i]);
                            eprintln!("间隔必须是 >=1 的整数");
                            process::exit(1);
                        }
                    };
                    cli_interval = Some(val);
                } else {
                    eprintln!("错误: -s 需要指定时间间隔");
                    process::exit(1);
                }
            }
            "-w" => {
                cli_web = true;
            }
            "-b" => {
                i += 1;
                if i < args.len() {
                    cli_cpuset = Some(args[i].clone());
                    if args[i].is_empty() || args[i].contains('/') {
                        eprintln!("无效的 cpuset 目录名: {}", args[i]);
                        eprintln!("目录名不能为空或包含路径分隔符");
                        process::exit(1);
                    }
                } else {
                    eprintln!("错误: -b 需要指定 cpuset 目录名");
                    process::exit(1);
                }
            }
            "-v" => {
                if crate::ebpf_mode::ebpf_probe() {
                    println!("AppOpt 版本 {} eBPF", env!("CARGO_PKG_VERSION"));
                } else {
                    println!("AppOpt 版本 {}", env!("CARGO_PKG_VERSION"));
                }
                process::exit(0);
            }
            "-h" => {
                print_help(prog_name);
                process::exit(0);
            }
            other => {
                eprintln!("未知选项: {}", other);
                print_help(prog_name);
                process::exit(1);
            }
        }
        i += 1;
    }

    // 应用设置持久化于 AppOpt.json，命令行参数优先覆盖
    let st = settings_load(SETTINGS_FILE);
    let config_file = cli_cfg.unwrap_or(st.config_file);
    let sleep_interval = cli_interval.unwrap_or(st.check_interval);
    let cpuset_name = cli_cpuset.unwrap_or(st.cpuset_name);
    let web_enable = cli_web || st.web_enable;

    // 单实例锁贯穿整个运行生命周期，先于 cpuset 初始化，避免重复建目录与双份绑核
    let _instance = instance_lock(&cpuset_name);

    // 启动块第一行：版本 + pid + 墙钟 + 本次真正生效的参数。
    // 日志是追加写的，模块重启后同一文件里会有多段 [+0.0s]，只有这行能划出
    // 「这段属于哪一次启动、用的是哪套参数」
    crate::diag::tag(
        "启动",
        &format!(
            "AppOpt v{} ｜ pid {} ｜ {} ｜ 检查间隔 {}s ｜ cpuset 组 {}",
            env!("CARGO_PKG_VERSION"),
            std::process::id(),
            wall_clock(),
            sleep_interval,
            cpuset_name
        ),
    );
    if crate::web::SETTINGS_FRESH.load(Ordering::Relaxed) {
        crate::diag::tag("配置", "首次运行，已写入默认设置 AppOpt.json");
    }

    // 锁内先恢复上次异常退出留下的 RT 时间片，避免多实例互相覆盖备份
    rt::init();
    // 正常退出（SIGTERM/SIGINT）也要还原时间片，否则只能等下次启动兜底
    install_exit_handler();

    // 先设置 cpuset 路径再初始化拓扑，init_cpu_topo 会创建 BASE_CPUSET 目录
    set_base_cpuset(&cpuset_name);
    let topo = init_cpu_topo();

    if fs::metadata(&config_file).is_err() {
        let initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";
        if fs::write(&config_file, initial_content).is_ok() {
            crate::diag::tag(
                "警告",
                &format!("配置文件不存在，已重建空文件：{}", config_file),
            );
        }
    }

    {
        let mut guard = lock_ignore_poison(&CONFIG_FILE);
        *guard = config_file.clone();
    }
    CHECK_INTERVAL.store(sleep_interval, Ordering::Release);
    MODE_FORCE.store(st.mode, Ordering::Release);

    let mut tmp_mtime: i64 = -1;
    let initial_config = match load_config(&config_file, &topo, &mut tmp_mtime) {
        Some(cfg) => cfg,
        None => {
            crate::diag::tag("失败", "初始配置加载失败，退出");
            process::exit(1);
        }
    };

    {
        let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(initial_config));
    }
    CONFIG_UPDATED.store(true, Ordering::Release);

    // RT 全局参数只在这里改一次，配置热更新走循环里的 prepare
    if let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() {
        rt::prepare(&cfg);
    }

    init_inotify(&config_file);

    if web_enable {
        // 绑定失败时不落盘，否则会把 web_enable 写成 false，一次端口冲突永久关闭 Web
        if web_start() {
            // -w 或设置恢复启用后落盘，重启保持开启
            settings_save();
        } else {
            crate::diag::tag("失败", "Web 启动失败，保留原有 web_enable 设置");
        }
    }

    // 守护进程模式，保存 JoinHandle 用于 panic 恢复检测
    let mut config_handle = thread::spawn(config_loader);

    let mut proc_state: Option<ProcScanState> = None;
    let mut affinity_deadline = Instant::now();
    let prog_start = Instant::now();
    let mut web_stats_deadline = Instant::now();
    // 事件丢弃对账周期，只读一次内核计数器，不产生额外轮询
    let mut reconcile_deadline = Instant::now();
    // 预支 60 秒使首次重试立即到期
    let mut ebpf_retry_at = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);

    // S7 状态。模式由配置驱动，off 时 tick 立即返回，不读 /proc/stat
    let mut sched_state = SchedState::new();
    let mut sched_deadline = Instant::now();
    // 诊断：卡顿信号 1 秒采样（样本够多才可信），线程表 5 秒刷新一次
    let mut jank = diag::JankSampler::new();
    let mut jank_deadline = Instant::now();
    let mut diag_deadline = Instant::now();
    let mut summary_deadline = Instant::now();

    // 恢复的强制 proc 模式无需 eBPF 初始化
    let mut ebpf_state: Option<EbpfState> = if MODE_FORCE.load(Ordering::Relaxed) == 2 {
        None
    } else {
        ebpf_init()
    };
    // 启动块收尾：所有组件就绪后才说「开始运行」，否则这条会排在 eBPF/Web
    // 之前，读者以为它们没起来
    diag::announce();
    // 仅自动模式失败一次即放弃；强制 eBPF 需持续重试，强制 proc 无需 eBPF
    if ebpf_state.is_none() && MODE_FORCE.load(Ordering::Relaxed) == 0 {
        EBPF_GAVE_UP.store(true, Ordering::Relaxed);
    }

    loop {
        if SHUTDOWN.load(Ordering::Acquire) {
            crate::diag::tag("事件", "收到退出信号，正在还原 RT 状态");
            rt::shutdown();
            break;
        }
        // 先 swap CONFIG_UPDATED 再获取 cfg 防止漏更新
        let config_changed = CONFIG_UPDATED.swap(false, Ordering::AcqRel);
        let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
            thread::sleep(Duration::from_millis(100));
            continue;
        };
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        let mode = MODE_FORCE.load(Ordering::Relaxed);

        // 热插拔会让 cpuset 重算 effective_cpus 并重置组内线程亲和性，
        // 是「刚才绑住了、过一会儿又散了」最常见的成因，必须留下时间点
        diag::watch_cpu_online();

        // 模式切换必须立即生效：`on -> off` 依赖 policy_sig 变化触发全量重扫，
        // 这里同时清空 S7 状态，让已迁移线程按规则重新落地
        if config_changed {
            // 只改规则时模式不变，set_mode 会直接返回；不单独唤醒，
            // 新规则最坏要等一个休眠间隔（30 秒）才参与判定
            sched_state.note_config_change();
            // 离开 on（含 on -> shadow）必须丢掉缓存里的 S7 落点，
            // 否则定期校验会一直按旧落点维持，等于模式没关掉
            let switched = sched_state.set_mode(cfg.sched);
            if switched && cfg.sched != SchedMode::On {
                if let Some(es) = ebpf_state.as_mut() {
                    es.cache.clear_sched();
                }
                if let Some(ps) = proc_state.as_mut() {
                    ps.cache.clear_sched();
                }
            }
            // 先按新配置复核 RT 所有权，再决定时间片是否需要改写或还原
            rt::prune(&cfg);
            rt::prepare(&cfg);
        }

        // 配置加载线程 panic 恢复
        if config_handle.is_finished() {
            crate::diag::tag("警告", "配置加载线程异常退出，尝试重启");
            config_handle = thread::spawn(config_loader);
        }

        // 强制 /proc 时卸载 eBPF 并触发全量扫描
        if mode == 2 && ebpf_state.is_some() {
            crate::diag::tag("事件", "工作模式切换：/proc 轮询");
            ebpf_state = None;
            let cache = proc_state.get_or_insert_with(ProcScanState::new);
            cache.request_full_scan();
            affinity_deadline = Instant::now();
        }

        // eBPF 缺失时周期重试，自动模式失败一次后放弃，强制模式持续重试
        if mode != 2
            && ebpf_state.is_none()
            && (mode == 1 || !EBPF_GAVE_UP.load(Ordering::Relaxed))
            && ebpf_retry_at.elapsed() >= Duration::from_secs(30)
        {
            ebpf_retry_at = Instant::now();
            if let Some(mut new_es) = ebpf_init() {
                if comm_map_init(&mut new_es.bpf, &cfg.pkgs, new_es.comm_capacity) {
                    crate::diag::tag("警告", "eBPF 白名单容量不足，保持 /proc 轮询");
                    if mode == 0 {
                        EBPF_GAVE_UP.store(true, Ordering::Relaxed);
                    }
                } else {
                    crate::diag::tag("事件", "工作模式切换：eBPF 事件驱动");
                    full_scan(&cfg, &mut new_es);
                    ebpf_state = Some(new_es);
                    affinity_deadline = Instant::now();
                }
            } else if mode == 0 {
                EBPF_GAVE_UP.store(true, Ordering::Relaxed);
            }
        }

        let mut ebpf_dead = false;

        let need_reload = if let Some(es) = ebpf_state.as_mut() {
            if config_changed {
                let r = comm_map_init(&mut es.bpf, &cfg.pkgs, es.comm_capacity);
                if !r {
                    // 只重建规则变化的包，未变化的包不重新绑定
                    config_rescan(&cfg, es);
                }
                r
            } else {
                false
            }
        } else {
            false
        };

        if need_reload {
            ebpf_state = None;
            if let Some(mut new_es) = ebpf_init() {
                if comm_map_init(&mut new_es.bpf, &cfg.pkgs, new_es.comm_capacity) {
                    crate::diag::tag("警告", "eBPF 重载后白名单容量仍不足，回退到 /proc 轮询");
                    continue;
                }
                full_scan(&cfg, &mut new_es);
                ebpf_state = Some(new_es);
            }
            continue;
        }

        if let Some(es) = ebpf_state.as_mut() {
            match es.event_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(event) => {
                    event_dispatch(&event, &cfg, es);
                    while let Ok(event) = es.event_rx.try_recv() {
                        event_dispatch(&event, &cfg, es);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    ebpf_dead = true;
                }
            }

            if affinity_deadline.elapsed() >= Duration::from_secs(3 * interval) {
                affinity_check(es, &cfg);
                affinity_deadline = Instant::now();
            }

            // RingBuf 满时事件会静默丢失，60 秒对账一次，命中丢失即全量重扫
            if reconcile_deadline.elapsed() >= Duration::from_secs(60) {
                reconcile_deadline = Instant::now();
                reconcile(es, &cfg);
            }
        } else {
            let cache = proc_state.get_or_insert_with(ProcScanState::new);
            if config_changed {
                cache.request_full_scan();
            }
            cache_sync(&cfg, cache);
            if affinity_deadline.elapsed() >= Duration::from_secs(5 * interval)
                || cache.force_affinity
            {
                // ESRCH 的线程同时收回 RT 记录，避免事件漏报时配额一直被占
                for tid in cache.cache.affinity_sync(&cfg.topo, cfg.sysgroup_respect) {
                    rt::forget(tid);
                }
                affinity_deadline = Instant::now();
                cache.force_affinity = false;
            }
            thread::sleep(Duration::from_secs(interval));
        }

        if ebpf_dead {
            crate::diag::tag("警告", "eBPF 事件通道断开，回退到 /proc 轮询");
            ebpf_state = None;
            let cache = proc_state.get_or_insert_with(ProcScanState::new);
            cache.request_full_scan();
            affinity_deadline = Instant::now();
        }

        // S7 采样与迁移。off 时 tick 立即返回，只刷新一次快照供 Web 显示
        if sched_deadline.elapsed() >= sched::sample_period() {
            sched_deadline = Instant::now();
            let _ = sched_state.set_mode(cfg.sched);
            let moves = if cfg.sched == SchedMode::On {
                match (&ebpf_state, &proc_state) {
                    (Some(es), _) => sched_state.tick(&cfg, &es.cache),
                    (None, Some(ps)) => sched_state.tick(&cfg, &ps.cache),
                    _ => Vec::new(),
                }
            } else {
                // off / shadow：只推进采样与 would 统计，候选迁移直接丢弃。
                // 主循环只有这一条通往亲和性写入的路径，shadow 不可能执行迁移
                match (&ebpf_state, &proc_state) {
                    (Some(es), _) => {
                        sched_state.tick(&cfg, &es.cache);
                    }
                    (None, Some(ps)) => {
                        sched_state.tick(&cfg, &ps.cache);
                    }
                    _ => {}
                }
                Vec::new()
            };
            for m in &moves {
                let outcome = match (&mut ebpf_state, &mut proc_state) {
                    (Some(es), _) => apply_move_ebpf(es, &cfg, m),
                    (None, Some(ps)) => apply_move_proc(ps, &cfg, m),
                    _ => AffinityOutcome::Failed,
                };
                // 只有内核确认写入成功，settle 才会提交落点与 moved
                sched_state.settle(m, outcome);
            }
            sched_state.publish();
        }

        // 诊断快照：线程表回答「谁没绑住」，卡顿采样回答「绑了之后渲染线程还等不等 CPU」。
        // 两件事都只在被管理线程上做，enumerate 上限由 diag 内部兜住
        if jank_deadline.elapsed() >= Duration::from_secs(1) {
            jank_deadline = Instant::now();
            match (&ebpf_state, &proc_state) {
                (Some(es), _) => {
                    jank.sample(&es.cache);
                }
                (None, Some(ps)) => {
                    jank.sample(&ps.cache);
                }
                _ => {}
            }
        }
        if diag_deadline.elapsed() >= Duration::from_secs(5) {
            diag_deadline = Instant::now();
            match (&ebpf_state, &proc_state) {
                (Some(es), _) => diag::publish_threads(&es.cache),
                (None, Some(ps)) => diag::publish_threads(&ps.cache),
                _ => {}
            }
        }
        if summary_deadline.elapsed() >= diag::SUMMARY_GAP {
            summary_deadline = Instant::now();
            diag::periodic_summary(&sched_state.snapshot());
        }

        // web 状态统计，低频更新避免高频事件循环下的额外开销
        if WEB_ENABLED.load(Ordering::Relaxed)
            && web_stats_deadline.elapsed() >= Duration::from_secs(2)
        {
            web_stats_deadline = Instant::now();
            let (threads, hit_pkgs) = match (&ebpf_state, &proc_state) {
                (Some(es), _) => cache_stats(&es.cache),
                (None, Some(ps)) => cache_stats(&ps.cache),
                _ => (0, 0),
            };
            *lock_ignore_poison(&WEB_STATS) = Some(WebStats {
                rules: cfg.rules.len(),
                pkgs: cfg.pkgs.len(),
                hit_pkgs,
                threads,
                ebpf: ebpf_state.is_some(),
                uptime: prog_start.elapsed().as_secs(),
                dropped: DROPPED_TOTAL.load(Ordering::Relaxed),
            });
        }
    }
}

/// S7 迁移执行（eBPF 模式）：只改亲和性，不写 cpuset 目录，保持原有归属。
/// 只有 `Set` 才同步缓存里的集合，失败保持旧值等下一轮
fn apply_move_ebpf(es: &mut EbpfState, cfg: &AppConfig, m: &sched::Move) -> AffinityOutcome {
    // S7 只改绑核，不写 cpuset：cgroup 迁移会带来额外抖动，
    // 失败时还会把线程留在一个比目标更宽的集合里
    match affinity_apply(m.tid, &m.cpus, None, &cfg.topo, ApplyReason::Sched, &m.comm).0 {
        AffinityOutcome::Set => {
            // S7 只写 sched_setaffinity，cgroup 会把集合求交：返回 0 也可能被裁小。
            // 读回不一致就不能记落点——定期校验会按一个内核根本不接受的集合维持，
            // S7 又把「回读不一致」当成被规则拉回，每轮重置状态再迁一次
            if CpuSet::get_affinity(m.tid).is_some_and(|a| a != m.cpus) {
                return AffinityOutcome::Failed;
            }
            // 同步缓存：affinity_sync 每 3*interval 秒会按 entry.cpus 重设，
            // 不改这里，迁移结果几秒后就被拉回规则值
            if let Some(e) = es.cache.tasks.get_mut(&m.tid) {
                e.cpus = m.cpus;
            }
            // 落点另存一份：缓存随时可能被全量重建，条目里的值活不过一次重扫
            es.cache.note_sched(m.tid, m.cpus);
            AffinityOutcome::Set
        }
        AffinityOutcome::Gone => {
            es.cache.task_del(m.tid);
            AffinityOutcome::Gone
        }
        AffinityOutcome::Failed => AffinityOutcome::Failed,
    }
}

fn apply_move_proc(ps: &mut ProcScanState, cfg: &AppConfig, m: &sched::Move) -> AffinityOutcome {
    match affinity_apply(m.tid, &m.cpus, None, &cfg.topo, ApplyReason::Sched, &m.comm).0 {
        AffinityOutcome::Set => {
            if CpuSet::get_affinity(m.tid).is_some_and(|a| a != m.cpus) {
                return AffinityOutcome::Failed;
            }
            if let Some(e) = ps.cache.tasks.get_mut(&m.tid) {
                e.cpus = m.cpus;
            }
            ps.cache.note_sched(m.tid, m.cpus);
            AffinityOutcome::Set
        }
        AffinityOutcome::Gone => {
            ps.cache.task_del(m.tid);
            AffinityOutcome::Gone
        }
        AffinityOutcome::Failed => AffinityOutcome::Failed,
    }
}

/// 墙钟时间，只用在启动行。日志按追加写，同一文件里会有多段 `[+0.0s]`，
/// 没有一个绝对时间就无法判断哪一段是本次开机
fn wall_clock() -> String {
    // SAFETY: `time` 与 `localtime_r` 都只写调用方提供的结构体；
    // 返回的空指针在下面判掉，不会解引用
    unsafe {
        let mut t: libc::time_t = 0;
        if libc::time(&mut t) == -1 {
            return "时间未知".to_string();
        }
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return "时间未知".to_string();
        }
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}
