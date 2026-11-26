//! 三簇占用率：读 `/proc/stat` 的逐核忙时增量，按 `CpuTopology` 归簇。
//!
//! 与 S7、PMU 都无关——不需要跨簇规则、不需要 `perf_event_open`、不需要
//! root，任何配置下都能给出数字。状态页顶部的「核带」就是拿它画的：
//! 用户最想知道的「现在活压在哪个簇」有了答案，S7 才有存在的意义。
//!
//! 口径：各簇**自己**的利用率（busy / total），三簇不归一化，所以三段可以
//! 同时接近 100%。这和 `pmu_allocator` 里的「份额」是两件事——那边把三簇
//! 化成一个饼看错位，这边看各自还剩多少余量。

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cpuset::{CPU_SETSIZE, CpuSet, CpuTopology};
use crate::lock_ignore_poison;

/// 一簇的（忙 jiffies, 总 jiffies）。核全部不可读时为 None
pub(crate) type ClusterTicks = Option<(u64, u64)>;

/// 低于这个间隔直接回上次的结果。主循环 2 秒问一次，这里多留一层保护：
/// 别处顺手调用也不会变成高频采样
const MIN_GAP: Duration = Duration::from_millis(800);

struct State {
    at: Instant,
    ticks: [ClusterTicks; 3],
    last: [i8; 3],
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// 三簇利用率百分比 0–100；`-1` 表示还没建立基线（刚启动的第一秒）
pub fn util(topo: &CpuTopology) -> [i8; 3] {
    let mut guard = lock_ignore_poison(&STATE);
    if let Some(s) = guard.as_ref()
        && s.at.elapsed() < MIN_GAP
    {
        return s.last;
    }

    let Some(times) = read_cpu_times() else {
        return [-1; 3];
    };
    let cur = [
        cluster_busy(&times, &topo.e_core),
        cluster_busy(&times, &topo.p_core),
        cluster_busy(&times, &topo.hp_core),
    ];

    // 首轮只建基线
    let Some(prev) = guard.as_ref().map(|s| s.ticks) else {
        *guard = Some(State {
            at: Instant::now(),
            ticks: cur,
            last: [-1; 3],
        });
        return [-1; 3];
    };

    let mut out = [-1i8; 3];
    for i in 0..3 {
        let (Some((b0, t0)), Some((b1, t1))) = (prev[i], cur[i]) else {
            continue;
        };
        if t1 <= t0 {
            // 该簇核全部离线，或 tick 未推进
            continue;
        }
        let busy = (b1 - b0) as f64;
        let span = (t1 - t0) as f64;
        out[i] = (busy / span * 100.0).round().clamp(0.0, 100.0) as i8;
    }
    *guard = Some(State {
        at: Instant::now(),
        ticks: cur,
        last: out,
    });
    out
}

/// 汇总各簇核的忙时。簇内没有任何可读核时返回 None
pub(crate) fn cluster_busy(times: &[(u64, u64)], set: &CpuSet) -> ClusterTicks {
    let mut busy = 0u64;
    let mut total = 0u64;
    let mut any = false;
    for cpu in 0..CPU_SETSIZE {
        if !set.is_set(cpu) {
            continue;
        }
        if let Some(&(b, t)) = times.get(cpu) {
            busy += b;
            total += t;
            any = true;
        }
    }
    any.then_some((busy, total))
}

pub(crate) fn read_cpu_times() -> Option<Vec<(u64, u64)>> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    parse_cpu_times(&text)
}

/// 解析成「按 cpu 编号索引」的数组，元素是（忙, 总）jiffies。
///
/// 只取前 8 个字段：`/proc/stat` 的第 9、10 位是 guest / guest_nice，
/// 它们已经算在 user / nice 里，再加一遍会把总量抬高、占用率压低
pub(crate) fn parse_cpu_times(text: &str) -> Option<Vec<(u64, u64)>> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        // 汇总行是 `cpu `（cpu 后直接空格），逐核行是 `cpu0`/`cpu10`
        if rest.starts_with(' ') || rest.starts_with('\t') {
            continue;
        }
        let mut it = rest.split_whitespace();
        let Some(num) = it.next() else { continue };
        let Ok(idx) = num.parse::<usize>() else {
            continue;
        };
        let vals: Vec<u64> = it.filter_map(|x| x.parse().ok()).collect();
        if vals.len() < 5 {
            continue;
        }
        let idle = vals[3] + vals[4];
        let total: u64 = vals.iter().take(8).sum();
        if idx >= out.len() {
            out.resize(idx + 1, (0, 0));
        }
        out[idx] = (total.saturating_sub(idle), total);
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_summary_row_and_guest() {
        let text = "\
cpu  100 0 50 1000 10 0 0 0 0 0
cpu0 50 0 25 500 5 0 0 0 0 0
cpu1 50 0 25 500 5 0 0 0 0 0
intr 12345
";
        let v = parse_cpu_times(text).unwrap();
        assert_eq!(v.len(), 2, "汇总行不能进数组");
        // busy = 50+25 = 75；total = 50+25+500+5 = 580（不含 guest）
        assert_eq!(v[0], (75, 580));
    }

    /// 首次调用只有基线，必须返回「未知」而不是 0——
    /// 面板把 0 画成空簇，等于把「还没测」说成「没人用」
    #[test]
    fn first_call_is_unknown() {
        *lock_ignore_poison(&STATE) = None;
        let topo = CpuTopology::empty();
        assert_eq!(util(&topo), [-1; 3]);
    }

    /// 真机形态：两次采样之间烧 CPU，util 必须落在合理区间且不超过 100
    #[test]
    fn util_tracks_real_activity() {
        *lock_ignore_poison(&STATE) = None;
        let mut topo = CpuTopology::empty();
        topo.e_core = CpuSet::new();
        topo.e_core.set(0);
        topo.p_core = CpuSet::new();
        topo.p_core.set(1);

        let _ = util(&topo);

        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let f = stop.clone();
                std::thread::spawn(move || {
                    let mut n = 0u64;
                    while !f.load(Ordering::Relaxed) {
                        n = n.wrapping_add(1);
                        std::hint::black_box(n);
                    }
                })
            })
            .collect();
        // 要跨过 MIN_GAP 才会重新采样
        std::thread::sleep(MIN_GAP + Duration::from_millis(150));
        let got = util(&topo);
        stop.store(true, Ordering::Relaxed);
        for w in workers {
            w.join().unwrap();
        }

        assert!((0..=100).contains(&got[0]), "实得 {got:?}");
        assert_eq!(got[2], -1, "空的 hp 簇没有基线，不能报 0");
    }
}
