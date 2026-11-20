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

```
@unmatched=all
com.example.game {
  RenderThread=6-7
}
```

依赖 2.2.x「未匹配线程设为全部核心」行为的配置，升级后请显式加上 `@unmatched=all`。
加载与决策细节见 [CHANGELOG.md](CHANGELOG.md)；负载感知调度仅完成设计，见
[docs/S7_负载感知调度策略设计.md](docs/S7_负载感知调度策略设计.md)。


### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c <file>` | 指定配置文件路径 | `./applist.conf` |
| `-s <seconds>` | 检查间隔（秒，≥1） | `2` |
| `-b <name>` | 指定 BASE_CPUSET 目录名（不可含 `/`） | `AppOpt` |
| `-v` | 显示版本信息 | — |
| `-h` | 显示帮助 | — |


### 请作者喝咖啡

![请作者喝奶茶](%E8%AF%B7%E4%BD%9C%E8%80%85%E6%9D%AF%E5%A5%B6%E8%8C%B6.png)

