# AppOptR 变更记录

## 2.3.0（未发布）

本版本按审计路线 S0–S7 完成构建、生命周期、事件路径、Proc 发现、CPU 拓扑与规则引擎修复。
涉及行为变化的条目已单独标注，升级前请阅读。

### 构建与模块

- 修复 `AppOpt/src/web.rs` 中 `include_str!` 指向不存在文件导致的编译失败。
- 修复 `libc::inotify_rm_watch` 参数类型（libc 0.2.189 起为 `c_int`）。
- 修复 Web 端口被占用时把 `web_enable=false` 写回设置文件、导致下次启动永久关闭 Web 的问题。
- 修复模块安装脚本 x86_64 分支的复制错误，补充 `AppOpt-ebpf` 拷贝。
- `service.sh` 日志改为写入模块目录 `appopt.log` 并做启动前轮转，不再丢弃到 `/dev/null`。
- 新增 `build.sh`：工具链检查 → eBPF → 用户态 → 按 ABI 组包，产物落 `dist/`。
- **修复**：`sched_param` 改为零初始化后赋值。`aarch64-unknown-linux-musl` 的该结构带
  `sched_ss_*` 字段，结构体字面量无法编译，arm64 包因此构建不出来。

### 生命周期

- 新增 `flock` 单实例锁，锁文件为可执行文件同目录的 `.AppOpt.<cpuset名>.lock`。
  相同 `-b` 名称只允许一个实例；不同 `-b` 名称仍可并行；加锁失败一律放行（fail-open）。

### eBPF 事件路径

- cpuset 子目录创建从规则决策层移到执行层并加就绪缓存，线程命名风暴下 mkdir/chmod/chown 由 609 次降到 2 次。
- 新增 15 字节 comm 键表，长包名匹配不再逐包做前缀/后缀比较。
- 删除 EXIT 事件在用户态的重复 `APPLIED_MAP` 删除。
- **FORK 事件不再提交 RingBuf**：子线程创建即继承父线程 affinity 与 cpuset，用户态无事可做；
  内核侧仍保留 `APPLIED_MAP` 占位，RENAME 放行与 EXIT 上报语义不变。
- 新增 `DROP_COUNT` Map：per-CPU 槽位累计 RingBuf 满时的丢弃数，主循环每 60 秒按累计值差分对账一次，
  发现新增丢弃即全量重扫；不再用「读取后清零」，并发更新不会丢计数。Web 状态页展示累计丢弃数。

### Proc 模式

- **不再用 `sysinfo.procs`（实为系统线程总数）增加 11 判断新进程**，改为 `/proc` PID 集合差分：
  只对新增 PID 读取 `cmdline`，只对新线程读取 `comm`。
- 进程退出即清理其缓存与跟踪状态；每 60 秒做一次全量校验兜底 PID/tid 复用。

### CPU 拓扑

- 分层依据改为 capacity 优先、`cpuinfo_max_freq` 兜底；两者都缺失时全部语义核心名映射到在线 CPU，
  不再让语义规则整体失效。
- 支持 1/2/3 簇设备：两簇设备 `p-core` 跟随末簇，不再被静默丢弃；单簇设备三个语义名指向同一集合。
- 离线 CPU 不进入规则集合与 cpuset 写入；`present` 缺失时回退 `possible`，再回退在线 CPU 数。
- **排序指标不再混用**：capacity 或 `cpuinfo_max_freq` 必须在一批候选簇上同时完整才用于排序；
  两者都不完整时三个语义名统一降级到全部在线 CPU，不再让缺失值以 0 参与比较被排成 e-core。
  无 cpufreq 的每核 capacity 回退同样要求全部在线 CPU 都有容量。
- **行为变化**：指标不完整的设备不再做部分分层，e/p/hp 规则在这些设备上退化为整个在线 CPU 集合；
  全部离线的簇不参与判定，其指标缺失不会牵连在线簇。
- Web 状态页展示分层依据与实际映射，并在降级时给出提示。
- **行为变化**：原本因拓扑识别失败而被丢弃的 `p-core`/`hp-core` 规则，现在会实际生效。

### 规则引擎

- **行为变化**：新增配置指令 `@unmatched=keep|all`，默认 `keep`。
  包内存在线程规则但某线程未命中、且包无包级规则时，`keep` 保持该线程原有亲和性，`all` 沿用旧行为设为全部核心。
  依赖旧行为的配置请在规则文件首行加 `@unmatched=all`。
- 规则按包建索引，决策只遍历同包规则，并集语义与优先级不变。
- 配置热更新改为按包增量重建：只重扫指纹变化的包，影响超过 4 个包时回退全量。
- 全局策略单独计算指纹：`@unmatched` 这类影响所有包的开关变化时走全量重建，
  已缓存线程与新线程采用同一策略；普通规则修改仍按包增量。
- 加载阶段提示同包多条包级规则（并集生效，与顺序无关），不改语义。

### 动态调度（S7）

- 新增配置指令 `@sched=off|shadow|on`，默认 `off`。默认配置下不读 `/proc/stat`、不产生任何系统调用，
  行为与纯静态规则一致。
- `shadow` 只采样与判定，把「本可迁移」计入 `sched_would` 并保留最近 8 条决策文本，不改亲和性；
  `on` 在全部约束满足时才提交 `sched_setaffinity`。
- 搬迁范围严格限制在规则给出的允许集合内部：目标簇与允许集合取交集，绝不扩大集合。
  只对 `Worker` / `Background` 角色生效，`Critical` / `Latency` / 未知角色一律不动。
- 五个防抖参数固定为常量：1 s 采样、连续 3 次确认、15 个百分点负载差、10 s 同线程冷却、
  单轮最多 2 次迁移；单轮最多检查 64 个线程，游标轮转保证公平。
- 簇负载取 `/proc/stat` 按核差分后的千分比；`Δtotal == 0`、计数回绕、离核一律记 -1（不可用），
  不参与排序，不把缺失值当 0。
- 无活跃进程（pid 的 utime+stime 未增长）时不决策：后台挂起的游戏没有迁移收益。
- 核心层少于 2 时状态固定为「不适用」，不做采样也不做决策。
- `@sched` 纳入 `policy_sig`：改配置会触发全量重建，`on → off` 能真正回滚已迁移线程，
  不会停在「半 S7」状态。
- 迁移后同步更新缓存里的 CPU 集合，否则 `affinity_sync` 会在数秒后把线程拉回规则值。
- **修复**：`shadow` 不再产出 `Move`。旧实现在两种模式下都返回迁移候选，由主循环统一执行，
  等于 `shadow` 也会真的改亲和性。现在决策层直接截断、主循环只在 `@sched=on` 时接收候选，
  两道独立闸门；`shadow` 全程不建 cpuset、不调任何亲和性接口。
- **修复**：迁移结果改为三态 `AffinityOutcome { Set, Gone, Failed }`。旧实现把
  「线程是否退出」当成「亲和性是否设置成功」，EPERM/EINVAL 会被记成一次成功迁移并把
  目标集合写进状态。现在只有 `Set` 才提交 `cur` / `own` / `applied` / `moved`，
  失败只增加 `sched_failed` 并进入冷却；`Gone` 清掉线程状态。
- **修复**：活跃 PID 判定超过 8 个进程时按窗口轮转，`MAX_ACTIVE_PIDS` 的低开销设计保留，
  高位 pid 不再永远轮不到；增删进程只改变取模基数，不会把游标重置回 0。
- **修复**：线程名按 `cfg.needs_comm(pkg)` 采集——线程规则、S7 角色判定、RT 匹配任一需要才读。
  旧实现只在线程规则存在时读 `comm`，导致「只有包级规则」的应用在 S7 里角色恒为 Unknown、
  RT Auto 永不命中；proc 模式也不再因此漏掉这类应用的新线程。

### RT 调度

- 新增三种模式 `@rt=off|global|per_app`，默认 `off`。`global` 只作用于**已管理**应用
  （在亲和性规则中出现过的包），不是对系统全部应用提权；`per_app` 只认 `@rt.app` 里显式启用的条目。
- 新增分应用配置 `@rt.app=<包名> [on|off] [auto|names:<列表>] [上限]`，省略的字段按 `auto`
  与 `@rt.max` 补齐；写 `off` 时保留模式，再次打开不必重填。
- 新增 `@rt.max`（每应用线程上限，1–8，默认 2）与 `@rt.timeslice`（RR 时间片，1–100 ms，默认 3）。
  时间片是全局内核参数，只在至少一个应用启用时写入，全部关闭后还原，不伪装成按应用独立生效。
- 兼容旧写法：`@rt=auto` 与 `@rt=RenderThread,RHI*` 等价于 global 模式的 auto / names。
- **修复**：外部模块或系统设置的 RR/FIFO 线程不再进入自有集合。旧实现把它们加入 `applied`
  以避免重复查询，代价是关闭 RT 时会把别人的实时线程降级。
- **修复**：线程退出立即释放配额。配额改为从自有线程表派生，不再维护独立计数器，
  杜绝「线程已退出但计数不减」；进程退出清空该 PID 的全部记录。`Owned` 持久化 TID→PID 对应关系。
- **修复**：`global ↔ per_app`、`auto ↔ names`、应用级开关互不影响都能热切换。配置变更时遍历
  自有线程按新规则复核，符合的保留 RT，不符合的降为 `SCHED_OTHER`，不做降级再提升的无谓往返。
- **修复**：时间片原值只在第一次改写时备份，后续热更新与多应用启停不再覆盖它；
  SIGTERM/SIGINT 正常退出时还原，异常退出仍靠下次启动的备份还原。
- **修复**：`note` 会用一次 `sched_getscheduler` 复核记录是否仍有效。线程退出后 tid 被复用、
  或外部把线程改回 CFS 时，旧记录会被当成「已提升」，新线程既不提升也不释放配额；
  现在发现内核不是 RR 就丢弃记录并重新判定。
- **修复**：全量重扫后对账（`rt::reconcile`）。缓存里已不存在的 tid、被移出配置的包、
  规则变化后不再符合的线程一律收回；仍符合条件的保持 RT 不动。proc 模式的全量校验、
  eBPF 的规则重建与丢弃对账都会走这一步。
- **修复**：`affinity_check` 与 proc 模式的 `affinity_sync` 发现 ESRCH 时同时 `rt::forget`，
  EXIT 事件丢失时配额也不会被永久占用。
- **修复**：`sched_setscheduler` 返回 ESRCH（线程刚好退出）不再关闭全局闸门，只有 EPERM 这类
  环境问题才整体停用 RT。
- **修复**：时间片只还原自己写入的值。外部在运行期改过 `sched_rr_timeslice_ms` 时，
  以现值为新的原值记录；关闭时若发现当前值已不是自己写的，只清记录不覆盖。
- **修复**：时间片闸门从 `RtConfig::any_enabled()` 改为 `AppConfig::rt_active()`。
  旧实现在 `@rt=global` 下无条件返回 true，规则文件里一个包都没有时也会改写整机
  `sched_rr_timeslice_ms`。现在 global 要求至少有一个受管包，per_app 要求启用的
  应用确实在规则文件里。
- **整理**：资格判定收敛为单个 `eligible(mode, comm, allowed)`。`note` 之前直接用
  `matches()`，与 `prune` / `reconcile` 走的 `eligible()` 是两条路径，文档却写着
  「共用」。现在三处都取一次 `cfg.rt.policy(pkg)` 再调同一个函数。
- `SCHED_RR | SCHED_RESET_ON_FORK`、优先级 1 保持不变；只改 `sched_rr_timeslice_ms`，
  不动 `sched_rt_runtime_us` / `sched_rt_period_us`——改 RT 预算是整机行为。

### Web

- **行为变化**：`/api/config` 的 `config_file` 只允许指向模块目录、当前配置目录、`/data/adb`、
  `/data/local/tmp`、`/sdcard` 之内；拒绝 `..` 组件与指向外部的符号链接。命令行 `-c` 不受限制。
- 配置文件路径的最终目标是符号链接时一律拒绝；新建文件改用父目录句柄 + `openat`
  （`O_CREAT|O_EXCL|O_NOFOLLOW`），校验与创建之间不再有换链窗口。
- 规则写入的临时文件改用 `O_NOFOLLOW`：配置目录位于共享存储时，预置的 `<config>.tmp`
  符号链接无法再把 root 写入引到白名单外。
- 设置页新增「可跨簇调度的规则」统计：解析期按去重后的核心层判定哪些规则的允许集合横跨多层，
  同时写一行启动日志。该数字仅用于评估动态调度的作用面，不参与任何决策。
- 设置页新增「S7 动态分配」与「RT 调度」两行：展示模式、当前状态、本可迁移/已迁移次数与三簇负载；
  `/api/config` 增加 `sched_mode` / `sched_state` / `sched_ticks` / `sched_would` / `sched_moved` /
  `sched_failed` / `sched_blocked` / `sched_load` / `sched_last` / `rt` 十个字段，便于写 A/B 记录脚本。
  `sched_failed` 是亲和性设置失败次数，与 `sched_moved` 严格互斥。
- 设置页新增「RT 实时调度」卡片：全局模式分段选择、每应用上限与时间片、应用列表
  （开关 / auto 或 names / 上限 / 当前 RT 线程数 / 内核时间片当前值），支持直接添加应用。
  新增 `GET /api/rt`、`POST /api/rt`、`POST /api/rt/app`，写入落到配置文件的 `@rt*` 指令行并触发热加载。
- 适配 KernelSU 的 WebUI 入口：页面由 `https://mui.kernelsu.org` 加载，相对路径会被解析到该域，
  前端在非 8889 端口时改用绝对地址 `http://127.0.0.1:8889`；后端补 OPTIONS 预检与
  `Access-Control-Allow-Private-Network`。来源白名单只放行该域与回环地址，其他跨站 Origin 仍返回 403，
  POST 仍要求 `application/json`。

### 已知限制

- eBPF 加载、RingBuf 压力对账、Android cgroupfs/cpuset 行为未在真机验证，仅完成编译、Map 布局校验与
  x86_64 沙箱内的 Proc 路径实测。
- S7 与 RT 同样未在真机验证。沙箱拓扑降级为单簇，端到端只覆盖了「不适用」路径与 Web 字段；
  采样、判定与迁移由单元测试用注入的簇负载覆盖，`sched_setaffinity` 与 `sched_setscheduler` 的
  实际成功率、厂商调度器是否拉回、SELinux 是否放行均需真机确认。
- RT 的**成功路径**在沙箱内完全走不到：容器内 `/proc/sys/kernel/sched_rr_timeslice_ms` 只读、
  `sched_setscheduler(SCHED_RR)` 返回 `EPERM`。已验证的是配置解析、状态所有权、配额释放、
  热切换判定与 Web 读写，以及「时间片写入失败即全局关闭」这一失败路径。
- RT 异常退出（`kill -9`、断电）只能还原时间片，被提升的线程会保持 RR 直到进程退出——
  跨进程无法记录状态，属固有限制。
- `-Os`→`-O2` 为 bpf-linker 0.13 的强制要求，eBPF 目标文件体积略有增加。
