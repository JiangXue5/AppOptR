//! 线程角色判定。S7 让位与 RT 提升共用一张表，避免两处口径漂移。
//!
//! 判错方向的代价不对称：把关键线程判成 Worker，会被迁到小核或降频；
//! 把 Worker 判成 Critical，只是少优化一个线程。所以表只收录确认过的名字，
//! 任何拿不准的命名一律 `Unknown`，不参与 S7，也不参与 RT。

/// 线程角色。只用于筛选，不参与允许集合计算。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// 渲染主线程、音频、引擎主循环：既不让位，也不因 S7 被迁移
    Critical,
    /// 延迟敏感但允许在簇内浮动（GL/Vulkan 提交、推理）
    Latency,
    /// 可被调度的工作线程，S7 的主要对象
    Worker,
    /// 后台任务，S7 优先迁出高负载簇
    Background,
    /// 未知命名，保守不动
    Unknown,
}

/// 精确名表，按字符串比较。游戏引擎与主流渲染栈的固定线程名。
const CRITICAL: &[&str] = &[
    "RenderThread",
    "RHIThread",
    "UnityMain",
    "WZ_Main",
    "_DummyMain",
    "__DoubleMain",
    "GPU Submission",
    "AudioTrack",
    "AudioFlinger",
];

const LATENCY: &[&str] = &[
    "GLThread",
    "VkThread",
    "DAVA::RhiThread",
    "TfLite",
    "VulkanThread",
];

/// 延迟敏感但名字带序号/子名，精确比较覆盖不到。
///
/// `hwuiTask*` 是 RenderThread 拉起来的并行绘制任务：迁走会让一帧的绘制
/// 跨簇分叉，比不动更慢，所以归 Latency（`movable()` 为 false）而不是 Worker
const LATENCY_PREFIX: &[&str] = &["hwuiTask", "MediaCodec", "Chrome_"];

/// 前缀表：这类名字带序号，精确比较覆盖不到
const WORKER_PREFIX: &[&str] = &[
    "Thread-",
    "Worker",
    "worker",
    "PoolThread",
    "Job.Thread",
    "AsyncTask",
    "Task-",
    "Loading-",
    "ForkJoinPool",
];

const BACKGROUND_PREFIX: &[&str] = &["bg", "Bg", "BG", "Background", "background"];

/// 线程池的**模式**命名。非游戏应用（IM、电商、浏览器壳）的线程几乎全是
/// 这一类，光靠前缀表一条都命中不了，真机上 60% 的线程因此落到 Unknown。
///
/// 只收「确定是工作线程」的命名：宁可漏掉（少优化一条线程），也不能把
/// 渲染/音频线程判成 Worker（会被迁到小核）。系统线程（`Signal Catcher`、
/// `Binder:*`、`FinalizerDaemon`）不匹配任何一条，仍然落到 Unknown
fn is_worker_pool(name: &str) -> bool {
    // ThreadPoolExecutor 默认命名：pool-3-thread-1
    if let Some(rest) = name.strip_prefix("pool-")
        && rest.starts_with(|c: char| c.is_ascii_digit())
    {
        return true;
    }
    // RxJava：RxCachedThreadScheduler-1 / RxIoScheduler-2 /
    // RxComputationThreadPool-3，微商/淘宝系 SDK 大量使用
    if name.starts_with("Rx") && (name.contains("Scheduler") || name.contains("ThreadPool")) {
        return true;
    }
    // 网络、图片、下载：都是「可让位」的后台工作线程，迁走不伤主线程
    [
        "OkHttp",
        "cronet",
        "Glide",
        "Fresco",
        "ImageLoader",
        "Download",
        "Upload",
    ]
    .iter()
    .any(|p| name.starts_with(p))
}

/// 判定线程角色。空名（包内无线程规则时用户态不读 comm）视为未知。
pub fn role_of(comm: &str) -> Role {
    if comm.is_empty() {
        return Role::Unknown;
    }
    if CRITICAL.contains(&comm) {
        return Role::Critical;
    }
    if LATENCY.contains(&comm) {
        return Role::Latency;
    }
    if LATENCY_PREFIX.iter().any(|p| comm.starts_with(p)) {
        return Role::Latency;
    }
    // 后台判定先于 Worker：`bgWorker` 这类命名应归为后台
    if BACKGROUND_PREFIX.iter().any(|p| comm.starts_with(p)) {
        return Role::Background;
    }
    if WORKER_PREFIX.iter().any(|p| comm.starts_with(p)) || is_worker_pool(comm) {
        return Role::Worker;
    }
    Role::Unknown
}

impl Role {
    /// S7 只对这两类让位；Critical/Latency/Unknown 一律不动
    pub fn movable(self) -> bool {
        matches!(self, Role::Worker | Role::Background)
    }

    /// RT 只提升 Critical：RT 的意义是不能被抢占，Worker 变 RT 会挤掉整个 CFS
    pub fn rt_candidate(self) -> bool {
        matches!(self, Role::Critical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_names_are_exact() {
        for n in ["RenderThread", "RHIThread", "UnityMain", "GPU Submission"] {
            assert_eq!(role_of(n), Role::Critical, "{n}");
        }
        // 大小写与前缀都不放宽，避免误判
        assert_eq!(role_of("renderthread"), Role::Unknown);
        assert_eq!(role_of("RenderThread2"), Role::Unknown);
    }

    #[test]
    fn latency_names_are_exact() {
        assert_eq!(role_of("GLThread"), Role::Latency);
        assert_eq!(role_of("VkThread"), Role::Latency);
        assert_eq!(role_of("TfLite"), Role::Latency);
    }

    #[test]
    fn worker_prefix_matches_numbered_threads() {
        assert_eq!(role_of("Thread-12"), Role::Worker);
        assert_eq!(role_of("PoolThread"), Role::Worker);
        assert_eq!(role_of("AsyncTask#3"), Role::Worker);
    }

    #[test]
    fn background_wins_over_worker() {
        // `bgWorker` 同时命中 bg 前缀与 Worker 前缀，必须归为后台
        assert_eq!(role_of("bgWorker"), Role::Background);
        assert_eq!(role_of("BackgroundLoad"), Role::Background);
    }

    #[test]
    fn empty_and_unknown_are_unknown() {
        assert_eq!(role_of(""), Role::Unknown);
        assert_eq!(role_of("some.random.name"), Role::Unknown);
    }

    #[test]
    fn only_worker_and_background_are_movable() {
        assert!(Role::Worker.movable());
        assert!(Role::Background.movable());
        assert!(!Role::Critical.movable());
        assert!(!Role::Latency.movable());
        assert!(!Role::Unknown.movable());
    }

    /// 非游戏应用的线程池命名。真机上这类线程占了探测总数的一半以上，
    /// 不收进来 S7 的候选池就一直是空的
    #[test]
    fn java_thread_pools_are_workers() {
        for n in [
            "pool-3-thread-1",
            "pool-12-thread-4",
            "RxCachedThreadScheduler-1",
            "RxIoScheduler-2",
            "RxComputationThreadPool-3",
            "ForkJoinPool-1-worker-2",
            "OkHttp Dispatcher",
            "OkHttp ConnectionPool",
            "cronet-impl-thread",
            "Glide-source-th-0",
            "ImageLoader-1",
            "Download-2",
        ] {
            assert_eq!(role_of(n), Role::Worker, "{n}");
        }
    }

    /// 只有「pool- + 数字」才算线程池。`pool-worker` 这类自定义名不该被误判，
    /// 否则一个前缀就能把所有 `pool` 开头的线程卷进迁移
    #[test]
    fn worker_pool_needs_a_number() {
        assert_eq!(role_of("pool-worker"), Role::Unknown);
        assert_eq!(role_of("pooled"), Role::Unknown);
        assert_eq!(role_of("RxBus"), Role::Unknown);
    }

    /// 运行时与渲染线程必须留在 Unknown/Latency：它们一旦被当成 Worker，
    /// 迁到小核的代价远大于「少优化一条线程」
    #[test]
    fn runtime_threads_stay_unknown() {
        for n in [
            "Signal Catcher",
            "Binder:1234_1",
            "FinalizerDaemon",
            "ReferenceQueueDaemon",
            "HeapTaskDaemon",
            "Jit thread pool",
            "Profile Saver",
        ] {
            assert_eq!(role_of(n), Role::Unknown, "{n}");
        }
        // hwui 并行绘制任务归 Latency：不可迁，但也不再算「未知」
        assert_eq!(role_of("hwuiTask0"), Role::Latency);
        assert_eq!(role_of("hwuiTask12"), Role::Latency);
    }

    #[test]
    fn only_critical_is_rt_candidate() {
        assert!(Role::Critical.rt_candidate());
        for r in [Role::Latency, Role::Worker, Role::Background, Role::Unknown] {
            assert!(!r.rt_candidate(), "{:?}", r);
        }
    }
}
