# λmod 与上游 Aether_OptExt 的对应关系

上游：`https://github.com/NetizenNemo/Aether_OptExt`
基线提交：`31a23c4a3f0eb9ee45bc337dba3597ca707ca47b`（2026-11-27，1127 发布）
对应文件：`src/lagrange.rs`（767 行）

本仓库实现：`AppOpt/src/pmu_lambda.rs`（模型内核）+ `AppOpt/src/arbiter.rs`（裁决）

## 一、逐函数对应

| 上游 | 本仓库 | 是否等价 |
|:---|:---|:---|
| `TierInfo { cpus, l2_kb, rho }` | 同名同字段 | 是 |
| `Lambda::new(topo)` | `build_tiers(topo)` + `update()` 内的重建 | 是（多了层集合变化检测） |
| `capacity()` / `eta()` | 同名 | 是 |
| `thread_w()` | 同名 | 逐行一致（含 `w = exp(-pi_lse)` 的负号） |
| `step_lambdas()` | 同名 | 是（`λ = max(0, λ + γ·η·err)`，无单步限幅） |
| `solve()` | 同名，入参由 `nodes` 换成 `&[Feat]` | 是（软累加 `s`、按线程数归一、Monte Carlo 采样） |
| `advance()` | 同名 | 是（误差、`v_fr`/`dz`/`cone` 三组 EWMA、boost、钳位） |
| `pick_tier()` | 同名 | 逐行一致（splitmix + salt） |
| `tier_target()` | 同名 | 是（在线裁剪 + min_cpus 只向高层并入） |
| `Handles` / `sample_tids()` / `perf_available()` | 不移植，用 `pmu.rs` | 见差异 1 |
| `GLOBAL` / `tick()` / `target_for()` | 不移植 | 见差异 2 |

## 二、四处差异（都是本仓库架构决定，不是「还没做」）

1. **采样不自己开 fd**。上游每线程 4 个 perf fd，配免 fd 预筛选、`RLIMIT_NOFILE`
   预算、空闲回收。`pmu.rs` 已经有同一套（`fd_budget()`、`slots`、任务时钟回退），
   再搬一套就是每线程双份 fd。上游自己实测 2541 线程吃掉 11520 个 fd，这个坑
   不能踩第二次。
2. **不执行**。`tier_target` / `pick_tier` 原样保留但 `#[allow(dead_code)]`，
   `policy` / `sched` / `apply_affinity` 不读。执行要等方案 16.4 的验收
   （3 游戏 × 2 拓扑 × 重复测试 × 帧时间 / 1% low / 迁移次数 / 大核驻留 / 功耗）。
   执行闸门已就位：`@lambda=apply`，默认 `shadow`（裁决照跑、结论不采纳）。
3. **`REF_MISS = 0.01`（上游 0.05）**。上游 `c_llc` 是 LLC miss **率**
   （`miss/llc_ref`）；本仓库只有 `PERF_COUNT_HW_CACHE_MISSES / 指令数`，
   典型值低一个数量级。公式一字未改，只换常数——照抄 0.05 会让 `pressure/ref`
   小十倍，`sens` 恒 ≈1，大 L2 偏好整个消失。
4. **层集合变化即重建 λ，同核集档位合并**。上游在 `init` 时建一次；本仓库
   每窗口按在线核重建（thermal 下线会改层），层集合变了就丢掉旧 λ——旧 λ
   对应的是另一套约束。单层设备的 e/p/hp 三档全等，留三份会让 λ 在三个同集
   层上互打。

另外三处细节：L2 沿用上游的两档估值（顶层 1024、其余 512），但按**裁剪合并
之后**的下标判顶层（上游用原始下标，顶层整层下线时没人拿到大 L2）；`c_llc`
下限取 0.001、CPI 下限 0.1，与上游一致；整轮无指令增量也无 CPU 时间的线程
不参与分配（上游用 `/proc/{tid}/stat` 的 tick 增量做同样的事），否则空闲线程
会占一份配额，把重线程挤到小核。

## 三、上游踩过的坑（已继承，勿回退）

| 坑 | 现象 | 本仓库处置 |
|:---|:---|:---|
| π 里保留常数项（`λ[0]+λ[1]·c_llc+λ[2]·m_mem`） | softmax 平移不变，常数额外漂移，实测 λ[1] 1h23min 从 0.002 涨到 0.663 不回落 | π 只留 `λ_k·sens_k` |
| `s` 按指令量加权 | `cap` 是核数比例，量纲不匹配，误差恒为正、λ 单调上升 | 按线程数占比软累加 |
| `s` 不归一 | 随线程数线性增长，同上 | 除以线程数 |
| 无 γ 阻尼 | 误差 26 时单步 Δλ≈21，两小时不收敛 | 拥塞 EWMA，钳 0.05–2.0 |
| `w = exp(+pi_lse)` 漏负号 | π 大时指数爆炸，`inf`/`NaN` | 保留负号（即使当前不消费 `w`） |
| 硬编码层号 | 2+2+4 被压成三档 | 取实测 `all_tiers` |
| 不裁在线核 | thermal 下线后 `EINVAL` | 每轮与 `online_cpus()` 求交 |
| 最高层强扩 `min_cpus` | 2 核性能簇并成全核，等于放弃绑定 | 只向更高层并入，顶层不动 |
| 单线程每轮重采样 | 每轮 `setaffinity` | 本仓库不执行，未触发；接执行时必须补 |

## 四、跟进上游的步骤

```bash
git clone --depth 50 https://github.com/NetizenNemo/Aether_OptExt.git /tmp/aether
cd /tmp/aether && git log --oneline -5         # 记录新基线
diff -u <(git show 31a23c4:src/lagrange.rs) src/lagrange.rs   # 看上游改了什么
```

只读三个区段，其余不用跟：

- **模型区**（`thread_w` / `step_lambdas` / `advance` / `solve` / `pick_tier`）：
  上游一改就同步，逐行照抄，只把 `CpuSet::intersection` 换成 `and`（原地版）。
- **拓扑区**（`Lambda::new` / `tier_target`）：同步，但保留本仓库的在线裁剪与合并。
- **采集区**（`Handles` / `sample_tids` / `perf_*`）：不同步，`pmu.rs` 已有等价物。

同步完跑 `cargo test pmu_lambda arbiter`，再更新本文的「基线提交」。
