//! 息屏判定与确认。
//!
//! 只有 `@screen=relax` 会用到它：息屏期间把「周期复核」从每 3/5 个 interval
//! 降到 60 秒一次，S7 采样与卡顿采样暂停。**新线程的首次绑定不走这条路**——
//! eBPF 事件与 proc 的 `cache_sync` 照常工作，息屏时新建的线程仍会立刻被发现并绑定。
//!
//! 判据分四级，按可靠性从高到低：
//! 1. `/sys/class/thermal/thermal_message/screen_state`（厂商节点，0/1）
//! 2. `/sys/class/backlight/*/actual_brightness`（内核实际亮度，>0 为亮）
//! 3. `/sys/class/backlight/*/brightness`（用户设定亮度，>0 为亮）
//! 4. `/sys/class/drm/card*-*/dpms`（输出电源状态）
//!
//! 四级全部不可用时按「亮屏」处理：宁可多复核，不可漏绑。

use std::fs;
use std::time::{Duration, Instant};

/// 状态翻转需要持续多久才确认。AOD、亮度调节、锁屏动画都会让判据短暂抖动，
/// 不确认就会在「息屏”和“亮屏」之间反复横跳
const CONFIRM: Duration = Duration::from_millis(250);
/// 两次探测的最小间隔。eBPF 事件密集时主循环每秒能转很多圈，
/// 每次探测是 1~3 次文件读取，必须自己节流
const MIN_GAP: Duration = Duration::from_millis(500);

const SCREEN_STATE: &str = "/sys/class/thermal/thermal_message/screen_state";
const BACKLIGHT_DIR: &str = "/sys/class/backlight";
const DRM_DIR: &str = "/sys/class/drm";

/// 三个判据的根路径。抽出来只为单测能把它们指向临时目录：
/// 「某一级缺失」「四级全不可用」在真机上很难凑齐，而这两种分支恰恰
/// 决定了会不会把息屏误判成亮屏（多复核 vs 漏绑的取舍）
struct Paths {
    screen_state: String,
    backlight: String,
    drm: String,
}

fn default_paths() -> Paths {
    Paths {
        screen_state: SCREEN_STATE.to_string(),
        backlight: BACKLIGHT_DIR.to_string(),
        drm: DRM_DIR.to_string(),
    }
}

/// `screen_state` 节点的取值：0/off/false 为灭，1/on/true 为亮。
/// 未识别的值返回 `None`，让下一级判据接手，而不是猜
fn parse_screen_state(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "0" | "off" | "false" => Some(false),
        "1" | "on" | "true" => Some(true),
        _ => None,
    }
}

/// 亮度是 0 表示背光关闭。负数不存在，解析失败按不可用
fn parse_brightness(s: &str) -> Option<bool> {
    s.trim().parse::<u64>().ok().map(|v| v > 0)
}

/// dpms 的常见取值是 `On` / `Off` / `On (unknown)`，
/// 也可能是 `Unknown`（驱动没实现），后者不可用
fn parse_dpms(s: &str) -> Option<bool> {
    let v = s.trim().to_ascii_lowercase();
    if v.starts_with("on") {
        Some(true)
    } else if v.starts_with("off") {
        Some(false)
    } else {
        None
    }
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// 遍历一个 class 目录，按名字排序后返回子目录的完整路径。
/// 排序只为让多设备机器上的结果稳定，不参与判定
fn class_entries(dir: &str) -> Vec<String> {
    let mut out: Vec<String> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter_map(|e| e.file_name().to_str().map(|n| n.to_string()))
            .map(|n| format!("{}/{}", dir, n))
            .collect(),
        Err(_) => return Vec::new(),
    };
    out.sort_unstable();
    out
}

fn probe_backlight(dir: &str) -> Option<bool> {
    for base in class_entries(dir) {
        if let Some(v) =
            read_trim(&format!("{}/actual_brightness", base)).and_then(|s| parse_brightness(&s))
        {
            return Some(v);
        }
        if let Some(v) =
            read_trim(&format!("{}/brightness", base)).and_then(|s| parse_brightness(&s))
        {
            return Some(v);
        }
    }
    None
}

fn probe_dpms(dir: &str) -> Option<bool> {
    for card in class_entries(dir) {
        // 只认连接器目录（`card0-DSI-1`），`card0` 本身没有 dpms
        if !card.rsplit('/').next().is_some_and(|n| n.contains('-')) {
            continue;
        }
        if let Some(v) = read_trim(&format!("{}/dpms", card)).and_then(|s| parse_dpms(&s)) {
            return Some(v);
        }
    }
    None
}

/// 探测一次，返回「是否亮屏」与命中的判据名（用于日志解释）。
/// 判据顺序即可靠性顺序，前一级给出结论就不再往下看
pub fn probe() -> (bool, &'static str) {
    probe_with(&default_paths())
}

fn probe_with(p: &Paths) -> (bool, &'static str) {
    if let Some(v) = read_trim(&p.screen_state).and_then(|s| parse_screen_state(&s)) {
        return (v, "screen_state");
    }
    if let Some(v) = probe_backlight(&p.backlight) {
        return (v, "backlight");
    }
    if let Some(v) = probe_dpms(&p.drm) {
        return (v, "dpms");
    }
    // 四级全不可用时按亮屏：宁可多复核，不可漏绑
    (true, "none")
}

pub struct ScreenState {
    on: bool,
    /// 尚未确认的翻转：`(目标状态, 首次观察时间)`
    pending: Option<(bool, Instant)>,
    last_probe: Option<Instant>,
    source: &'static str,
}

impl Default for ScreenState {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenState {
    /// 初始按亮屏：第一次探测到灭屏也要走一次确认，不会在启动瞬间降频
    pub fn new() -> Self {
        Self {
            on: true,
            pending: None,
            last_probe: None,
            source: "none",
        }
    }

    /// 当前命中的判据名，仅用于日志解释「凭什么判定息屏」
    pub fn source(&self) -> &'static str {
        self.source
    }

    /// 主循环每轮调用，返回确认后的屏态（true = 亮屏）。
    /// 距上次探测不足 `MIN_GAP` 时直接返回缓存结论，不读任何文件
    pub fn observe(&mut self) -> bool {
        let now = Instant::now();
        if let Some(last) = self.last_probe
            && now.duration_since(last) < MIN_GAP
        {
            return self.on;
        }
        self.last_probe = Some(now);
        let (raw, source) = probe();
        self.source = source;
        self.step(raw, now)
    }

    /// 确认逻辑，与文件读取解耦以便单测
    fn step(&mut self, raw: bool, now: Instant) -> bool {
        if raw == self.on {
            // 抖动回来了：取消待确认
            self.pending = None;
            return self.on;
        }
        match self.pending {
            // 目标一致但还没等够：保留最初的观察时间戳。
            // 每次都重置会永远等不到确认窗口（探测间隔可能远小于 CONFIRM）
            Some((target, since)) if target == raw => {
                if now.duration_since(since) >= CONFIRM {
                    self.pending = None;
                    self.on = raw;
                }
            }
            _ => self.pending = Some((raw, now)),
        }
        self.on
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_state_values() {
        assert_eq!(parse_screen_state("1"), Some(true));
        assert_eq!(parse_screen_state("0\n"), Some(false));
        assert_eq!(parse_screen_state("ON"), Some(true));
        assert_eq!(parse_screen_state(" off "), Some(false));
        // 未知值必须交下一级，不能猜成亮屏
        assert_eq!(parse_screen_state("2"), None);
        assert_eq!(parse_screen_state(""), None);
    }

    #[test]
    fn brightness_and_dpms_values() {
        assert_eq!(parse_brightness("255\n"), Some(true));
        assert_eq!(parse_brightness("0"), Some(false));
        assert_eq!(parse_brightness("abc"), None);
        assert_eq!(parse_dpms("On\n"), Some(true));
        assert_eq!(parse_dpms("Off"), Some(false));
        assert_eq!(parse_dpms("On (unknown)"), Some(true));
        assert_eq!(parse_dpms("Unknown"), None);
    }

    /// 亮→灭必须连续两次观察才生效；中间抖回亮屏则取消
    #[test]
    fn flip_needs_confirmation() {
        let mut s = ScreenState::new();
        let t0 = Instant::now();
        assert!(s.step(false, t0), "第一次看到灭屏只记待确认");
        assert!(!s.step(false, t0 + CONFIRM), "持续够确认窗口才提交");
        assert!(!s.on, "确认后应处于息屏");

        // 灭→亮同样要确认
        assert!(!s.step(true, t0 + Duration::from_secs(1)));
        assert!(s.step(true, t0 + Duration::from_secs(1) + CONFIRM));
        assert!(s.on, "确认后应处于亮屏");
    }

    /// 临时目录。测试之间用 tag 隔离，跑完随手清掉
    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("appopt-screen-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("建临时目录");
        p
    }

    fn write(path: &std::path::Path, v: &str) {
        if let Some(d) = path.parent() {
            fs::create_dir_all(d).expect("建父目录");
        }
        fs::write(path, v).expect("写测试文件");
    }

    /// 厂商节点缺失时必须落到背光，而不是直接判亮屏
    #[test]
    fn missing_screen_state_falls_to_backlight() {
        let root = tmp("no-state");
        write(&root.join("backlight/panel0/actual_brightness"), "0\n");
        let p = Paths {
            screen_state: root.join("screen_state").to_string_lossy().to_string(),
            backlight: root.join("backlight").to_string_lossy().to_string(),
            drm: root.join("drm").to_string_lossy().to_string(),
        };
        assert_eq!(probe_with(&p), (false, "backlight"));
        let _ = fs::remove_dir_all(&root);
    }

    /// actual_brightness 缺失时用 brightness；它为 0 同样是息屏。
    /// 「调节亮度到 0」在多数机型上就等于关背光
    #[test]
    fn zero_brightness_without_actual_is_off() {
        let root = tmp("bright-only");
        write(&root.join("backlight/panel0/brightness"), "0\n");
        let p = Paths {
            screen_state: root.join("screen_state").to_string_lossy().to_string(),
            backlight: root.join("backlight").to_string_lossy().to_string(),
            drm: root.join("drm").to_string_lossy().to_string(),
        };
        assert_eq!(probe_with(&p), (false, "backlight"));
        let _ = fs::remove_dir_all(&root);
    }

    /// 驱动返回 `Unknown` 时不能当成「灭」：那会把常亮设备判成息屏，
    /// 整晚按 60 秒间隔复核
    #[test]
    fn dpms_unknown_is_unavailable() {
        let root = tmp("dpms-unknown");
        write(&root.join("drm/card0-DSI-1/dpms"), "Unknown\n");
        let p = Paths {
            screen_state: root.join("screen_state").to_string_lossy().to_string(),
            backlight: root.join("backlight").to_string_lossy().to_string(),
            drm: root.join("drm").to_string_lossy().to_string(),
        };
        assert_eq!(probe_with(&p), (true, "none"));
        let _ = fs::remove_dir_all(&root);
    }

    /// 四级全不可用：按亮屏处理。这是「宁可多复核」的兜底，
    /// 反过来会把一整类无节点设备永久锁在降频路径上
    #[test]
    fn all_sources_missing_is_on() {
        let root = tmp("all-missing");
        let p = Paths {
            screen_state: root.join("screen_state").to_string_lossy().to_string(),
            backlight: root.join("backlight").to_string_lossy().to_string(),
            drm: root.join("drm").to_string_lossy().to_string(),
        };
        assert_eq!(probe_with(&p), (true, "none"));
        let _ = fs::remove_dir_all(&root);
    }

    /// dpms 只有在连接器目录里才有意义：`card0` 本身读不到就该跳过，
    /// 不能因为路径存在就当成有效判据
    #[test]
    fn dpms_only_read_from_connector() {
        let root = tmp("dpms-card");
        write(&root.join("drm/card0/dpms"), "Off\n");
        write(&root.join("drm/card1-HDMI-A-1/dpms"), "On\n");
        let p = Paths {
            screen_state: root.join("screen_state").to_string_lossy().to_string(),
            backlight: root.join("backlight").to_string_lossy().to_string(),
            drm: root.join("drm").to_string_lossy().to_string(),
        };
        assert_eq!(probe_with(&p), (true, "dpms"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn jitter_cancels_pending() {
        let mut s = ScreenState::new();
        let t0 = Instant::now();
        assert!(s.step(false, t0), "待确认灭屏");
        assert!(s.step(true, t0 + Duration::from_millis(100)), "抖回亮屏");
        // 再灭一次要重新计时，不能沿用第一次的时间戳
        assert!(s.step(false, t0 + Duration::from_millis(200)));
        assert!(
            s.step(false, t0 + Duration::from_millis(300)),
            "距重新计时只有 100ms，不足以确认"
        );
        assert!(
            !s.step(false, t0 + Duration::from_millis(200) + CONFIRM),
            "确认后这一轮就应返回灭屏"
        );
        assert!(!s.on, "确认后应处于息屏");
    }
}
