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

