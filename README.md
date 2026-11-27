# AppOptR

#### 介绍
Android 应用 CPU 亲和性管理工具

 **使用说明请参考** 

http://appopt.suto.top

### 模块说明

| 模块 | 功能 |
|------|------|
| `main.rs` | 程序入口，CLI 解析与双模式主循环编排 |
| `config.rs` | 配置解析、inotify 热加载与降级轮询 |
| `cpuset.rs` | CPU 拓扑检测与 cpuset 管理 |
| `rule_match.rs` | 规则匹配与决策（按包索引，不遍历全部规则） |
| `rule_edit.rs` | 规则增删改与归一化 |
| `apply_affinity.rs` | 亲和性应用（cpuset 目录就绪缓存 + 写 tasks + sched_setaffinity） |
| `cache.rs` | 统一缓存 |
| `roles.rs` | 线程名角色分类（渲染 / 延迟敏感 / 工作线程 / 后台前缀） |
| `sched.rs` | S7 负载感知调度（`off` / `shadow` / `on` 三档，按 `/proc/stat` 判定迁移） |
| `policy.rs` | 目标解析纯函数（规则 → S7 落点 → 降档 → 组裁剪 → 最终集合） |
| `background.rs` | 前后台判定（按应用：系统组 → stune 组 → `oom_score_adj`） |
| `auto_assign.rs` | Auto Assign 候选采集（只写 `AppOpt.autocache.conf`） |
| `load.rs` | 三簇实时占用（`/proc/stat` 逐核忙时按拓扑归簇；不需要 S7 / PMU / root） |
| `pmu.rs` | PMU 观察（Instructions / Cycles / CPI；硬件计数不可用时退到 CPU 时间，只采样不迁移） |
| `pmu_allocator.rs` | PMU Shadow 配额（重/中/轻分档 + 按 capacity 算各簇建议承载，只算不执行） |
| `rt.rs` | RT 实时调度（`SCHED_RR` + `RESET_ON_FORK`，含时间片备份与恢复） |
| `diag.rs` | 诊断采集与计数（分层标签、失败节流、周期摘要） |
| `diag_fmt.rs` | 诊断文本排版（纯函数，便于单测） |
| `ebpf_mode.rs` | eBPF 事件驱动 |
| `proc_mode.rs` | Proc 轮询模式 |
| `web.rs` | 轻量 HTTP 管理面板服务 |
| `appopt-ebpf` | eBPF 内核态 |


### 构建

```sh
./build.sh                 # 当前主机架构
./build.sh -a arm64        # 需要 aarch64 交叉链接器（NDK clang）
./build.sh -a x64          # 需要 x86_64 交叉链接器
./build.sh -a all          # 两个架构
```

- 模块脚本源码在 `module/`，产物打包到 `dist/AppOpt-<版本>-<ABI>.zip`，不覆盖 `modules_update/` 下的发布包。
- 用户态仅需稳定版 Rust；eBPF 需要 `nightly` + `rust-src` + `bpf-linker`，缺失时脚本会直接报错并给出安装命令。
- 交叉编译目标可用 `APPOPT_ARM64_TRIPLE` / `APPOPT_X64_TRIPLE` 覆盖，链接器用 `CARGO_TARGET_<TRIPLE>_LINKER` 指定。

本地不装工具链也能构建：把提交推上去，用 CI 出的包。工具链安装、eBPF 编译、双架构打包都在
`.github/workflows/ci.yml` 里做完了。


### CI

`.github/workflows/ci.yml`，三种触发：

| 触发 | 做什么 | 产物 |
|------|--------|------|
| push 到 `experimental` | 格式、clippy、单测，再构建两个架构 | Actions 页面 → 该次运行 → Artifacts，保留 14 天 |
| 测试版 tag（`v*-beta*`） | 同上，不发 Release | Artifacts |
| 正式版 tag（如 `v2.7.0`） | 同上，再发版到 GitHub / Gitee | Release 附件 |
| PR / 手动触发 | 只做检查与构建，不发版 | Artifacts |

Release 列表只留正式版；测试版的包都在 Actions 的 Artifacts 里，14 天后自动清理。

`master` 是 2.6.x 稳定线，暂未带这套工作流；2.7 的改动都在 `experimental` 上。

日常小改动只需要推代码，不用本地构建：

```sh
git commit -am "fix: ..." && git push github HEAD
# 等 CI 绿了，去 Actions 页面下载 AppOpt-<sha> 里的 zip 装机验证
```

要发正式版才打 tag：

```sh
# 1. 改三处版本号（AppOpt/Cargo.toml、AppOpt/Cargo.lock、module/module.prop）
#    再在 CHANGELOG.md 写一节 ## <版本>（日期），CI 会拿它当 Release 正文
# 2. 打不带 -beta 的 tag，剩下交给 CI
git tag -a v2.8.0 -m "2.8.0: ..." && git push github v2.8.0
```

CI 在发版前会核对三件事，不一致就直接失败，不会发出一个版本号对不上的包：
tag 与 `module.prop` 的 version 一致、`CHANGELOG.md` 里有这一节、两个 zip 里都带着
对应 ABI 的 `AppOpt-ebpf`。

需要的 secret 只有一个：

| secret | 用途 | 不配的后果 |
|--------|------|------------|
| `GITEE_TOKEN` | 把 tag 推到 Gitee、建 Gitee Release、传包 | 只发 GitHub，Gitee 仍需本地跑 `release.py` |

`GITHUB_TOKEN` 由 Actions 自动提供，不用配。仓库 Settings → Secrets and variables →
Actions → New repository secret，名字必须叫 `GITEE_TOKEN`，值是 Gitee 私人令牌（勾 `projects`
权限）。


### 发版（本地，CI 不可用时）

推送 tag 不等于发版——tag 只是个 git 对象，Release 和安装包要在两个平台各建一次。
beta8~beta23 就是这么漏的：代码和 tag 都在，Gitee 上一片空白。CI 已接管这一段，
下面只在 CI 挂了或要补发旧版本时用：

```sh
./build.sh -a all
git push origin HEAD && git push origin v<版本>
git push github HEAD && git push github v<版本>
python3 tools/release.py <版本>            # GitHub + Gitee 一起建 Release 并传包
python3 tools/release.py <版本> --dry-run  # 先看要做什么
```

脚本幂等：Release 已存在就复用，附件已存在就跳过，缺哪个补哪个；也支持
`--only github` / `--only gitee`。令牌优先读 `GITHUB_TOKEN` / `GITEE_TOKEN` 环境变量，
读不到再回落到 `~/.git-credentials`。


### 规则文件指令

规则文件与规则行同级的指令行以 `@` 开头，目前支持：

| 指令 | 取值 | 默认 | 说明 |
|------|------|------|------|
| `@unmatched` | `keep` / `all` | `keep` | 包内有线程规则但某线程未命中、且包无包级规则时的行为。`keep` 保持该线程原有亲和性；`all` 沿用 2.2.x 行为设为全部核心。 |
| `@sched` | `off` / `shadow` / `on` | `off` | S7 负载感知：`shadow` 只判定不迁移，`on` 才真正改亲和性。 |
| `@screen` | `off` / `relax` | `off` | 息屏时放松周期复核。`relax` 把已绑定线程的复查从每 3/5 个 interval 降到 60 秒，并暂停 S7 与卡顿采样；新线程的首次绑定不受影响。 |
| `@rt` | `off` / `global` / `per_app` | `off` | RT 调度范围。`global` 对全部受管应用生效，`per_app` 只对 `@rt.app` 里显式开启的包生效。 |
| `@rt.max` | 1–8 | `2` | 每应用最多提升多少个线程。 |
| `@rt.timeslice` | 1–100 | `3` | RR 时间片（毫秒），全局内核参数，仅在至少一个应用启用时写入。 |
| `@rt.app` | `<包名> on\|off [auto\|names:名1,名2] [上限]` | — | 单个应用的 RT 条目。参数省略时按 `auto` 与 `@rt.max`。 |
| `@sysgroup` | `respect` / `takeover` | `respect` | 线程被 Android 放进 `background`/`system-background`/`restricted` 组时，该组的生效集合只有小核。`respect` 尊重系统安排，规则要的大核绑不上就跳过并说明；`takeover` 强行把线程拉进 AppOpt 组再绑（大核跑后台，耗电上升）。 |
| `@group` | `own` / `mask` | `own` | 首次绑定或目标变更时，把线程迁进 `AppOpt/<集合>` 组。只在掩码上绑、不接管组时，系统会在进程状态变化时把亲和性收敛回组允许集合——这是「绑上又被冲掉」的主因。`mask` 退回 2.6.1 的「只写掩码」行为。 |
| `@foreground_demote` | `on` / `off` | `off` | 前后台降档。`on` 时，判为后台（系统后台组，或已被接管但 stune 组在 `background`、或 `oom_score_adj ≥ 700`）且**没有显式线程规则**的线程，目标缩到 `e-core`。判据按应用而不是按线程，同进程的线程不会一半降一半不降。应用切回前台后按规则原值重算，不会停在降档值上。降档的优先级高于 S7 落点：这类线程不参与 S7 迁簇，避免「降档—迁回大核—再降档」两轮一抖。 |
| `@blacklist` | `<包名>[ ,<包名>…]`（逗号或空格分隔） | — | 完全不管理：不读 cmdline/comm、不匹配规则、不进 S7/RT。可写多行累加。新增后热加载会立即把已在 `AppOpt` 组里的线程还回去。 |
| `@exempt` | `<包名>[ ,<包名>…]`（逗号或空格分隔） | — | 半管理：只写 `sched_setaffinity`，不迁组、不补组、不参与 S7。给 LKT / Uperf 这类同样管 cpuset 的模块让路，避免两边互相覆盖。 |
| `@auto_assign` | `on` / `off` | `off` | 采集 Auto Assign 候选，写入同目录的 `AppOpt.autocache.conf`（30 天过期）。只观察、不改规则；在 WebUI 规则页逐条采纳或忽略，采纳才会经 `rule_edit` 写进主配置。只累计应用在前台时的观察时长：后台挂着的线程活得再久也不成候选，避免「后台样本」把建议带偏。 |
| `@pmu_alloc` | `shadow` / `off` | `shadow` | PMU 配额 Shadow。拿 PMU 本窗口的全量采样，按活动量把线程分成重 / 中 / 轻三档，再按各簇 capacity 算出「应该承载多少」，与该时间段的实际簇占用对照（有跨簇规则时用 S7 的统计，否则自己读 `/proc/stat` 逐核忙时），输出匹配度与偏空的簇。分档按活动量份额切：累计到 50% 算重、85% 算中，其余算轻。**只算不执行**：不发任何写操作，绑核结果不受影响。只在 `@pmu=observe` 打开时生效。 |
| `@pmu` | `observe` / `off` | `off` | PMU 观察。`observe` 时读取硬件计数器（Instructions / Cycles / cache-misses），在诊断页显示每个受管线程的 CPI 与指令速率，用于评估 S7 迁移是否真的划算。硬件计数器能打开但读数恒为 0（部分厂商锁了 PMU）时自动退到 `TASK_CLOCK`，按 CPU 时间显示占用；两种都读不到才关闭。**只采样、不迁移**：执行路径不会因为本开关改变一个核。上限 128 线程，FD 按 `RLIMIT_NOFILE` 预算自动收缩。只放出 cycles 的内核上按周期速率显示（`Gcyc/s`），不会显示成 0。权限不足、计数器不支持、读数为 0（厂商独占 PMU）时自动关闭并写明原因，绑核结果不受影响。 |

包名可以直接写子进程名，比如 `com.tencent.mobileqq:MSF=0-3`：只作用于这个子进程，
主进程 `com.tencent.mobileqq` 不受影响，两条规则各管各的，不会合并。

保存配置后只打印改动的规则，前缀 `+` 新增、`~` 修改、`-` 删除；规则没动就只回一句
「规则未变」。策略项（`@sched`、`@rt`、`@pmu` 等）变了才会重打那一行。

### CPU 规格怎么写

规则右边可以写数字范围，也可以写语义核心名：

| 写法 | 含义 |
|------|------|
| `0-3`、`4,5,7` | 直接写核号，可用逗号与区间 |
| `e-core` / `{e_core}` | 能效核（最低一档） |
| `p-core` / `{p_core}` | 大核（中间层；四簇机器上是中间两层的并集） |
| `hp-core` / `{hp_core}` | 超大核（最高一档） |
| `all-core` / `{all_core}` | 当前在线的全部核 |

语义名按 `cpu_capacity` 分层，缺这个节点时回退 `cpuinfo_max_freq`。两者都读不到时启动行会写「未能分层」，此时三个语义名都指向全集——规则不会失效，但也不再区分核心层。启动行会如实报层数，四簇机器写「核心层 4（p-core 为中间 2 层并集）」。

```
@unmatched=all
@sched=on
@rt=per_app
@rt.app=com.example.game on auto 2
com.example.game {
  MainThread=6-7
  RenderThread=6-7
}
```

**RT 的推荐用法**：不用手写 `@rt.app`。设置页「RT 实时调度」选「按规则开启」，
再在规则页点每个应用右侧的 `RT` 按钮即可，参数固定为 AsoulOpt 的缺省值
（`auto` / 2 线程 / 3 ms）。全部应用的 RT 都关掉后 `@rt` 自动回到 `off`。

依赖 2.2.x「未匹配线程设为全部核心」行为的配置，升级后请显式加上 `@unmatched=all`。

### AsoulOpt 配置迁移

`tools/asopt2appopt.py` 把 AsoulOpt 的 `asopt.conf` 转成 AppOpt 规则，详见
[docs/AsoulOpt_配置迁移.md](docs/AsoulOpt_配置迁移.md)。

模块已附带 `applist.asoulopt.conf`（AsoulOpt 内置 **333** 个游戏、29 组线程规则，
共 926 条），**不自动启用**；需要时在设置页把「规则配置文件」指向它，或复制覆盖
`applist.conf`。包名与规则从 AsoulOpt Kana 的二进制逐组还原，核对方法见迁移文档第九节。
加载与决策细节见 [CHANGELOG.md](CHANGELOG.md)；负载感知调度（S7）已实现三档
`off` / `shadow` / `on`，设计与判定细节见
[docs/S7_负载感知调度策略设计.md](docs/S7_负载感知调度策略设计.md)。

**关于「每分钟被改写几十次」**：日志里出现 `改写` 计数时，先看有没有
`补写组归属 N 次`。有就说明线程原先只绑了掩码、没进 `AppOpt` 组，系统每次
进程状态变化都会把它重置；补组后这个数字应在一个周期内归零。若持续不为零，
检查 `@group` 是否被设成 `mask`。


### 内核调参（可选）

`core_ctl` 会在空闲时把整个 CPU 簇下电。部分机型上，绑到该簇的线程会被系统挤回小核，
表现为「规则写了大核、实际落点却在小核」。模块**默认不改动**内核参数，需要时手动开启：

```sh
touch /data/adb/modules/AppOpt/keep_cores    # 启用：把每个簇的 min_cpus 拉到 max_cpus
rm /data/adb/modules/AppOpt/keep_cores       # 关闭：下次启动按 core_ctl.bak 恢复原值
```

代价是核心常在线，待机功耗与发热会上升。原值记录在模块目录的 `core_ctl.bak`；
升级模块时该文件可能被覆盖，重新 `touch keep_cores` 即可。

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c <file>` | 指定配置文件路径 | `./applist.conf` |
| `-s <seconds>` | 检查间隔（秒，≥1） | `2` |
| `-b <name>` | 指定 BASE_CPUSET 目录名（不可含 `/`） | `AppOpt` |
| `-w` | 启动 Web 管理面板（仅监听 `127.0.0.1:8889`） | 关闭 |
| `-v` | 显示版本信息 | — |
| `-h` | 显示帮助 | — |


### 请作者喝咖啡

![请作者喝奶茶](%E8%AF%B7%E4%BD%9C%E8%80%85%E6%9D%AF%E5%A5%B6%E8%8C%B6.png)

