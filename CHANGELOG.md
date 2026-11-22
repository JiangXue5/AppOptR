# AppOptR 变更记录

## 2.3.9（2026-11-22）

2.3.8 的日志第一行就把自己否定了：

```
[+0.0s] cpuset: 自检失败，写入失败（Invalid argument (os error 22)），本机不接受 cgroup 接管线程
```

同一份日志里，`mkdir` 之后的 `cpus=0-7`、`mems=0` 全部写成功（否则根本走不到自检），
紧接着唯一失败的动作是「把一个 tid 写进 `tasks`」。这不是设备的问题，是这一行的写法。

### 根因：`writeln!` 把一次写入拆成了两次

`std::io::Write::write_fmt` 会按格式串的字面量分段调用 `write`。`writeln!(f, "{}", tid)`
展开成 `"{}"` + `"\n"` 两段，于是每次挂线程都是两个系统调用：

```
write(3, "13552", 5) = 5      ← 迁移在这一步就已经成功
write(3, "\n",    1) = 1      ← 内核 strstrip 后是空串，kstrtoint 失败 → EINVAL
```

内核的 `__cgroup_procs_write` 对空内容返回 `EINVAL`。于是：

- **迁移成功** → 第二段 EINVAL → 记成「cpuset 写入失败」；
- **迁移被拒** → 第一段就 EINVAL → 也记成「cpuset 写入失败」。

两种情况在日志里长得一模一样，这正是「绑核时灵时不灵」却始终查不出来的原因。
影响面覆盖 2.3.6 起的每一次 cpuset 写入：2.3.7 的两步迁组里「连 base 都写不进去」
是误判（base 其实写进去了），2.3.8 的自检更是因此把整条 cgroup 路永久关掉，
只留下 `sched_setaffinity` 一条腿——而它一定会被系统的组配置重置。

### 修复

- **一次写完，不带换行**：新增 `cpuset::attach_task()`，数字用栈上缓冲格式化后
  单次 `write_all`。这是本版所有改动的根。
- **自检看结果不看返回值**：写完再读一次 `/proc/<tid>/cgroup`，线程真的进了 base 组
  才算通过；顺手把自己写回原组、恢复亲和性，不留副作用。失败信息区分
  「打不开 / 写不进 / 写了没迁进去」。
- **目标按组生效集合裁剪**：cpuset 迁不进自己的组时（不可用或熔断中），按
  `规则 ∩ 组生效集合` 绑。真机上 `/foreground` 只有 `0-5`，规则要 `4-6`，
  硬写的结果是「返回成功、回读 4-5」，被判成写了也白写并停 300 秒——
  每 60 秒 182 个线程全撞在这上面。现在一次绑到 4-5，回读立刻一致。
- **裁剪不粘住**：`TaskEntry` 单独保留规则原值 `want`，组放开或接管恢复后
  自动回到 `4-6`，不会永久停在被裁小的集合上。
- **生效集合按组缓存 5 秒**：一轮校验里 172 个线程同属 `/foreground`，
  以前每个线程都把父链读一遍，现在一组一次。
- **S7 空转再降一档**：连续 30 轮「探到线程、零迁移、跳过全是允许集合不足」后
  判定间隔从 8 秒拉到 30 秒，状态显示「规则单簇，判定已休眠」。
- **摘要数字不再被轮次放大**：`系统分组: 当前 172 个线程被系统限定在小核
  （近 60 秒跳过 860 次）`——860 是 172 × 5 轮，只有「当前多少个线程」能对照。

### 预期

真机装 2.3.9 后第一行应该是 `cpuset 自检通过`（不再有「自检失败」），
随后 `/foreground` 的渲染线程会被迁进 `AppOpt/4-6`，`4-6` 不再被裁成 `4-5`。
若仍出现自检失败，说明这台设备的 `/dev/cpuset` 确实不接受任务，日志会直接给出
「写入返回成功但线程仍在 …」或具体 errno，不再需要靠猜。

## 2.3.8（2026-11-22）

2.3.7 的日志证明「尊重系统分组」这项能力**在真机上一次都没生效**，而它本该解决
每分钟几百次的 EINVAL。

### 日志里的证据

1. `cpuset 现场: 目标[...] cpus=4-6 mems=0 effective=-`、`父[...] cpus=0-7 effective=-`、
   `线程 6405 所在组 /AppOpt(-，AppOpt组) 可达性未知（读不到生效集合）` ——
   这台设备的内核不导出 `cpuset.effective_cpus`。2.3.7 用「读不到就不猜」处理，
   于是 `background` 的线程永远判不出「不可达」，照样硬写大核。
2. `+2599s`：`绑核: 近 60 秒失败 495 次（EINVAL 495）`、`校验: ... 挪簇 495`。
   495 不是「线程被挪了 495 次」，是 495 次失败被同时记成了一次漂移。
3. `+2582s` 起爆发，同一时刻 `簇负载 243/33/10‰`、`漂移: BatchDeleteObje 期望 4-6
   实际 0-3 cpuset=/background` —— 应用切后台，系统把线程搬进 `/background`(0-3)，
   规则仍要 4-6，交集为空。而 `blocked` 只在**首次**见到线程时算过一次，
   之后线程被搬组也不会重算。
4. `S7: 近 60 秒 56 轮、探测 3584 线程、迁移 0 次…跳过：允许集合不足两层 3584`，
   连续 40 分钟一字不变。S7 每秒扫 64 个线程，结论永远是「无事可做」。

### 修复

- **生效集合改为父链交集**：`/dev/cpuset` 到目标组逐级 `cpus` 求交，与内核定义一致，
  不再依赖内核是否导出 `effective_cpus`。v2 的空 `cpuset.cpus` 表示继承父级、
  v1 的空 `cpus` 表示本组无核，两种语义分开处理。这是让「尊重系统分组」
  真正生效的前提。
- **组归属每轮重算**：不再只在「已被拦住」时看组。应用切后台后第一轮校验就会
  发现 `/background` 并跳过，而不是每分钟硬写 495 次。
- **失败不再计入漂移**：目标与所在组无交集时归入「不可达」，与「被裁剪 / 被重置 /
  被挪簇」分开计数。以前 `挪簇 495` 会让人以为线程被搬了 495 次。
- **cpuset 失败分三类**：`目录未建成`、`连 base 全核都写不进去`、`已抬到 base 组
  但目标组仍拒绝`。第三类说明该组生效集合为空，改规则才有出路；第一类要去查
  权限与 SELinux。混成一句「写入失败」等于没说。
- **建组自检**：启动时把自己写进 base 的 tasks 一次。成功才启用 cpuset；
  失败立刻关闭并说明「本机不接受 cgroup 接管，绑核只靠 sched_setaffinity，
  系统改动组配置时会被重置」，不再每分钟撞同一个失败。
- **熔断暂停指数退避**：120 s → 240 → 480 → 600 封顶。真机上「组不可用」是
  静态事实，每分钟试探一次没有意义。
- **S7 单簇规则降频**：连续 5 轮「探到线程、零迁移、跳过全是允许集合不足」后，
  判定间隔 1 s → 8 s，`/proc` 读取量降到 1/8；出现真实迁移立刻恢复。
  这是「开 S7 就掉帧」的一部分——S7 什么都没做，却每秒读 64 个线程的
  `/proc/stat`、`schedstat`、`comm`。
- **S7 单簇说明只报一次**：静态结论每 60 秒重复一遍只会挤掉真正变化的行。

### 验证

- `cargo test`：145 passed / 0 failed / 1 ignored（新增父链交集、v1/v2 语义、
  S7 降频共 3 条）。
- clippy 零告警，`cargo fmt --check` 通过。
- 真机待验证：装 2.3.8 后启动 5 秒内应出现 `cpuset: 自检失败…` 或正常启用；
  `grep 不可达` 应能看到后台组线程被明确跳过，`EINVAL` 从每分钟几百次降到 0；
  S7 摘要里的探测线程数应从 3584/60s 降到约 448/60s。

## 2.3.7（2026-11-22）

2.3.6 的日志把「绑不住」的答案摆到了台面上：**不是 AppOpt 的绑定逻辑写错了，
是线程所在的系统 cpuset 组不允许它上那些核**。

### 日志里的证据链

1. `cpuset 现场` 第一次给出完整三层。目标 `/dev/cpuset/AppOpt/4-6` 的 `cpus=4-6`，
   线程 19946 也确实在 `/AppOpt/4-6`；但同一批出问题的线程，`cpuset=` 分别是
   `/foreground`、`/top-app`、`/background`——它们根本不在 AppOpt 的组里。
2. 漂移样例的实际值，全部等于所在组的生效集合：
   `process reaper 期望 4-6 实际 0-3 cpuset=/background`、
   `Thread-232 期望 4-6 实际 4-5 cpuset=/foreground`、
   `ent.tmgp.osgame 期望 4-6 实际 0-7 cpuset=/top-app`。
   这不是随机改写，是内核在组配置变化时把组内线程的亲和性收敛回 `effective_cpus`。
3. `+1938.5s` 一轮 170 个线程被裁剪，`+1998s` 累计 33 次 EINVAL，全是同一类：
   目标集合与线程所在组的生效集合没有交集。内核 `cpuset_can_attach` 与
   `sched_setaffinity` 都会直接拒绝，两条路同时堵死。
4. S7 一次都没迁，跳过原因 3520/3520 都是「允许集合不足两层」——规则全是单簇，
   S7 的让位前提根本不成立。

### 新增

- **两步迁组**：写目标组返回 EINVAL 时，先把线程写进 base（全核，与任何线程都有交集，
  必然成功），抬出原组后再写目标组。这是解开「background(0-3) → 4-6 交集为空」死锁的唯一办法。
- **尊重系统分组**：线程在 `background` / `system-background` / `restricted` 组、
  且规则目标不在该组生效集合内时，跳过并说明一次，不再每秒硬试。
  `@sysgroup=takeover` 可关闭该行为，把线程强行拉进 AppOpt 组（代价是耗电上升）。
  应用切前台被系统移出后台组时，会重新评估并恢复绑定。
- **失败按线程节流**：同一线程同一 errno 60 秒一条。`process reaper` 这类持续失败
  不再每 5 秒刷一行，把位置让给真正有变化的日志。
- **EINVAL 附带归因**：直接写出「线程在 /background(0-3)，与目标 4-6 无交集，
  属系统分组限制；要绑到大核必须先把线程迁出该组」。
- **生效集合兼容 cgroup v1/v2 文件名**（`cpuset.effective_cpus` / `cpuset.cpus.effective`），
  现场信息不再出现 `-`；并新增「与目标有无交集」的结论。
- **S7 全跳过时给结论**：当跳过几乎全是「允许集合不足两层」，直接说明
  「规则只覆盖一个簇，S7 没有可让位的目标，规则写成跨簇（如 all-core）才会生效」。
- 启动日志与 Web 诊断抽屉显示当前分组策略与因系统分组跳过的线程数。

### 验证

- `cargo test`：142 passed / 0 failed / 1 ignored（新增组分类、v1/v2 生效集合读取、
  后台组拦截判定共 3 条）。
- clippy 零告警，`cargo fmt --check` 通过。
- 真机待验证：装 2.3.7 后 `grep -E "系统分组|两步|漂移"` 应能看到后台组被明确跳过，
  EINVAL 从每分钟几十次降到 0；若仍出现，说明该设备的 `/dev/cpuset` 连 base 都写不进去，
  那就只能用 `@sysgroup=takeover` 或改规则。

## 2.3.6（2026-11-22）

拿到真机 2.3.5 日志后，把「绑不住 / 掉帧 / S7 开了没动静」从"猜"变成"日志里能直接读出来"。

### 日志里读到的三件事

1. **cpuset 从头到尾没写进去过**：`cpuset: 写入 0-7/tasks 失败（EINVAL）` 从启动第一秒出现，
   60 秒摘要累计到 3821 次。也就是说绑定实际只剩 `sched_setaffinity` 一条腿，
   cgroup 层完全没兜住——任何一次亲和性重置都留不下来，这正是「有时绑得住、有时绑不住」的一半。
2. **每 60 秒有 236～941 个线程被判定「被外部改写」并重绑**，数量与 cpuset 失败次数同一量级。
   这是「写进去被裁掉 → 下一轮读回又不一致 → 再写」的死循环，每分钟几百次跨核迁移，
   本身就会不停打断正在出帧的核。日志里 RenderThread 就绪等待 7.5～17 ms 与它同时出现。
3. **S7 全程 `on`，却没有任何一条迁移记录**。旧日志只记"动了什么"，不记"为什么没动"，
   用户只能看到"开了 S7 掉帧"，无从下手。

### 新增

- **时间戳**：所有运行期日志行首加 `[+123.4s]`（进程启动后耗时）。静态 musl 下 `localtime`
  依赖 TZ/tzdata，Android 上会静默退化成 UTC，相对时间零依赖且能精确看出间隔。
- **漂移归因**：校验发现读回不一致时按三类计数并给样例——
  `裁剪`（实际 ⊂ 期望，被 cpuset 的 effective_cpus 限制）、`重置`（实际 ⊃ 期望，被热插拔或
  别的组件写回全核）、`挪簇`（互不包含）。样例带线程所在 cpuset：
  `漂移: RenderThread(4035) 期望 4-6 实际 0-7 cpuset=/top-app`。
- **写入回读确认 + 无效绑定退避**：`sched_setaffinity` 返回 0 后再读一次，仍不一致就记
  `无效绑定`，并对该线程暂停重绑 300 秒。这类线程再写一万次也不会生效，只会反复迁移。
- **cpuset 失败现场**：失败时打印目标/父/根三层 `cpus/cpuset.effective_cpus` 与线程的
  `/proc/<tid>/cpuset`，直接回答"是目录没建成、父级没交集，还是线程原本在别的组里"。
- **cpuset 熔断**：连续 3 次失败暂停 120 秒（半开试探一次），不再每秒往失败路径上撞。
- **热插拔监测**：`/sys/devices/system/cpu/online` 变化时记录
  `CPU 在线集合变化: [0-7] → [0-3]（热插拔会重置 cpuset 组内线程的亲和性）`。
- **S7 周期摘要**：开关开着就每 60 秒给一行，含轮数、探测线程次、迁移次数、回弹/冻结、
  三簇负载，以及逐项跳过原因（目标簇不足/角色/负载/驻留/冷却/配额）。`shadow` 档报「本可迁移」。
- **卡顿信号改进**：采样窗口 5 秒 → 1 秒，窗口内调度不足 8 次不报（避免拿一两次偶发当结论），
  日志补 `affinity=` 与 `最后运行 cpu=`，能直接看出是不是被挤到小核。
- Web 诊断抽屉同步展示裁剪/重置/挪簇、无效绑定与暂停数、cpuset 熔断状态、卡顿线程的亲和性。

### 修复

- **首次绑定不再误报「被外部改写」**：`TaskEntry` 增加 `applied` 标记，只有确实写成功过的
  线程才参与漂移判定。此前 /proc 模式每次启动、每个新线程都会被算成一次改写。
- **复核走校验语义**：规则未变且已绑定过的线程，重扫时按 `Sync` 计数，才能与首次绑定区分开。

### 验证

- `cargo test`：139 passed / 0 failed / 1 ignored（新增熔断状态机、漂移三分类、S7 摘要、
  cpuset 现场共 4 条）。
- clippy 零告警，`cargo fmt --check` 通过。
- 沙箱端到端：人为把受管线程从 `0-3` 改成 `0-31`，下一轮校验立即输出
  `漂移: AppOpt(31474) 期望 0-3 实际 0-31 cpuset=/init.scope`，并计入「重置」；
  首次绑定阶段不再产生漂移计数。

## 2.3.5（2026-11-22）

解决「S7 开了掉帧」与「线程有时绑得到、有时绑不到」，并把这三类问题变成日志能定位的内容。

### 诊断

- 新增 `diag` 模块：绑核调用按「真写 / 短路 / 已退出 / 失败」计数，失败按 errno 分桶
  （EPERM/EACCES、EINVAL、ENOSYS、其他），60 秒摘要一次；同一 errno 的明细 5 秒最多一条，
  形如 `绑核失败: Thread-7(1234) → 4-6（EINVAL：目标集合非法，或与 cgroup cpuset 没有交集）`。
- S7 迁移日志补上来源簇与前后负载：`S7: Thread-7(1234) p-core → hp-core（620‰ → 180‰）`；
  迁移失败上屏；回弹被拦与预算冻结分别计数并记录一次。
- 新增卡顿信号：对 Critical 线程读 `/proc/<tid>/schedstat`，计算两次采样间「就绪等待 / 调度次数」，
  超过 4 ms 输出 `卡顿信号: UnityMain(1234) 就绪等待均值 6.2 ms（12 次调度）`。
- Web 设置页新增「诊断」抽屉：绑核计数、S7 跳过原因、卡顿信号、线程绑定表（期望 vs 实际）、
  最近事件；新接口 `GET /api/diag`。

### 修复

- **S7 不再写 cpuset**。此前每次迁移都会往规则目录的 `tasks` 追加 tid，等于多做一次 cgroup 迁移；
  写失败时线程还会停留在比目标更宽的集合里，表现为「绑了一半」。现在 S7 只调 `sched_setaffinity`，
  与设计文档一致。
- **反抖动**：单轮迁移由 2 个降为 1 个；新增 90 秒反向冷却（刚迁出的簇不得马上迁回）、
  目标簇配额（单核簇 1 个、多核簇 2×核数）、180 秒 3 次预算（超限冻结该线程）。
  这三道闸针对的是 `hp(1 核) ↔ p` 每 10 秒来回跳：单核目标被一个线程打满后立刻又变成「更忙」，
  旧逻辑没有反悔冷却，会持续乒乓。
- **目标选择**：`pick_target` 只在 p/hp 两层里挑。旧实现先按全表取最低负载，若最低是 e-core
  再被 `target_ok` 否决，整个线程这一轮就白跑了，S7 看起来「开了不动」。
- **/proc 模式线程改名漏绑**：引擎在创建线程后才 `pthread_setname_np`，而 /proc 模式没有 rename
  事件，`known_tids` 一旦记下就不会重读 comm。新增每轮 32 个 tid 的轮转重读，改名后重新匹配规则；
  未命中规则的也更新名字，保证 S7 角色判定不用旧名。
- 最小驻留由 2 s 提到 5 s，避开新线程的冷启动。

### 验证

- `cargo test`：135 passed / 0 failed / 1 ignored（新增反悔冷却、预算冻结、单核配额、诊断计数、
  事件环上限、schedstat 缺失容错共 5 条）。
- clippy 零告警；`diag.rs`、`sched.rs`、`cache.rs`、`proc_mode.rs` 的 rustfmt 差异为 0。
- 沙箱端到端：`/api/diag` 返回绑核计数与线程表，浏览器展开「诊断」抽屉无脚本错误；
  当前沙箱为单核心层，S7 按设计显示「不适用」。

## 2.3.4（2026-11-22）

修复 RT 在真机上完全无法生效。

### 根因

Rust 自带的 musl 静态库（`rustlib/<target>/lib/self-contained/libc.a`）把
`sched_setscheduler`、`sched_setparam`、`sched_getscheduler` 编成了「直接返回
`-ENOSYS`」的桩，反汇编即 `mov x0, #-0x26; ret`。静态链接后桩顶替了真正的实现，
每次提升都失败；桩又不设置 `errno`，日志里只能看到
`Function not implemented (os error 38)`，看起来像内核或 ROM 不支持实时调度。
aarch64 与 x86_64 的 `libc.a` 都有这个问题，因此 2.3.0 以来 RT 在所有设备上都没生效过。

### 修复

- 三个调用点改为直接 `syscall(SYS_sched_setscheduler / SYS_sched_getscheduler)`，
  绕开这两个符号。产物反汇编已确认走真实 `svc`：aarch64 用 119 / 120，
  x86_64 用 144 / 145
- `ENOSYS` 归入环境级失败：熔断一次并写明原因，不再每个线程、每轮扫描重复刷日志
- 新增 `raw_sched_syscall_matches_libc`：syscall 包装与 libc 的 `sched_getscheduler`
  对拍，调用号写错会直接测试失败，不会静默退回桩

### 验证

- `cargo test`：128 passed / 0 failed / 1 ignored
- 两个架构的 release 产物反汇编确认无 ENOSYS 桩调用；亲和性仍走 `svc` 122 / 123，未受影响
- 真机 RT 是否实际提升仍需装上后看日志里是否出现 `RT: 已提升`，并用
  `cat /proc/<tid>/stat` 第 41 个字段或 `chrt -p <tid>` 复核

## 2.3.3（2026-11-21）

修正 AsoulOpt 内置表的迁移结果。

### 包名

- 旧清单 324 条漏了 9 个真实条目：`ahf.dummynation`、`com.albiononline`、
  `com.heavenburnsred`、`com.pubg`、`minitech.miniworld`、`Nekootan.kfkj`、
  `supercell.brawlstars`、`supercell.clashofclans`、`supercell.squad`。
- 其中 4 个曾被误判为「死字符串」的（`com.netease.wotb`、`net.wargaming.wot.blitz`、
  `com.supercell.clashroyale`、`com.tencent.tmgp.supercell.clash`）实际在栈上临时
  数组里被引用，属真实成员，予以保留。
- 现在 333 个包位：数据区指针 316 + 栈表 4 + 代码内联 13，与「全部形似包名的
  字符串 337 个减 4 个非包名」互相验证。

### 规则

- `--full` 不再对所有应用套同一份 30 条名单，改为按二进制里的 29 个分组逐组还原。
  每个应用只写它所在组实际列出的线程名（1–4 条），规则数 9870 → 926。
- 组内 `count=0` 的条目视为「不处理」，跳过。
- `com.digitalextremes.warframemobile` 那组第 2 条指向 `/data/adb/naki/asopt.conf`
  自身路径，不可能是线程名，按无效项丢弃。

### Web 面板

此前 `@sched`、`@rt.max`、`@rt.timeslice`、`@unmatched` 只能在配置文件里手写，
`@rt=global` 有后端但没有按钮，`@rt.app` 的 `names:` 与逐应用上限也没有界面。

- 设置页新增「S7 动态分配」卡片：关闭 / 观察 / 开启三档，实时显示采样轮数、
  本可迁移、已迁移、失败、受限与三簇负载。单核心层机型选「开启」会明确提示
  「不会生效」，不再让人误以为已经在优化。
- RT 卡片补「全部应用」档，与「关闭 / 按规则开启」并列。
- 新增可折叠的「进阶配置」抽屉：
  - 每应用 RT 线程上限（`@rt.max`，1–8）
  - RR 时间片（`@rt.timeslice`，1–100 ms）
  - 未匹配线程行为（`@unmatched=keep|all`）
  - 逐应用 RT 条目列表：显示包名、匹配方式（`auto` 或完整的 `names:...`）、
    该应用上限，可直接开关或删除
- 新增接口 `POST /api/sched`（`{"mode":"off|shadow|on"}`）与
  `POST /api/adv`（`rt_max` / `rt_timeslice` / `unmatched`，三项均可选）。
  进阶三项一次写盘，不产生「只改了一半」的中间状态。
- `POST /api/rt/app` 支持 `{"delete":true}` 删除条目；删掉最后一个启用条目时
  `@rt` 自动收回 `off`，与规则页一键开关的收尾一致。`global` 不因删条目降级。
- `/api/config` 的 `sched_mode` 改为读配置真值而非运行快照，切档后按钮高亮
  不再慢一拍。

### 已知差异

- 线程名集合与分组逐字节还原；分配策略仍是静态近似——AsoulOpt 按 schedstat
  挑最闲线程上大核，AppOpt 只做固定簇映射。

### 验证

- `cargo test`：127 passed / 0 failed / 1 ignored。
- 配置实测加载 926 条规则，333 个规则块与清单完全对应。
- `--full` 在缺少分组数据时退回旧清单路径，输出仍为 333 个应用。

## 2.3.2（2026-11-21）

RT 所有权收尾：修正 TID 复用时的误降级。

### 修复

- `RtState::note()` 的执行顺序调整。此前顺序是「查 `cfg.rt.policy` → 无策略直接
  `drop_threads` → 核对 `Owned.pid`」，TID 被复用后新线程所属包若没有 RT 策略，
  会在身份核对之前被降级，等于替别的进程改调度策略。
- 现在 `Owned.pid` 核对提到最前：pid 不符只 `own.remove`，不调用 `demote()`、
  不调用 `sched_setscheduler(SCHED_OTHER)`；随后按新线程当前所属包的策略走——
  有策略且符合条件正常提升，已是 RR/FIFO 走 `Foreign` 分支不接管不记录，
  无策略直接跳过。
- `note()` 四条退出路径（闸门关闭 / pid 不符 / 无策略 / `action` 各分支）全部核对过，
  所有 `drop_threads` 调用点现在都在 pid 核对之后。

### 测试

- 新增 `rt::tests::note_drops_stale_record_before_policy_check`：真实线程 + 假 pid
  （旧记录 pid=100，新线程 pid=200，新包无 RT 策略）。断言旧记录被清除、不残留
  pid=100 的记录、`demoted == 0`、内核策略仍为 `SCHED_OTHER`。
  用例不依赖 `CAP_SYS_NICE`（CFS→CFS 的 `sched_setscheduler` 无需特权），
  且有红→绿证据：改代码前 `demoted == 1`。
- `cargo test`：124 passed / 0 failed / 1 ignored；clippy 零告警；双架构 musl 静态构建通过。

### 已知边界

- 同一 pid 内 tid 被复用时，`Owned.pid` 无法区分新旧线程，仍可能按旧记录降级。
  这是 pid 核对机制本身的天花板，需要 TID 代际或线程启动时间才能解决，未在本版处理。

## 2.3.1（2026-11-21）

RT 从「设置页手填包名」改为「规则页一键开关」，参数不再暴露。

### RT 交互

- `POST /api/rt/toggle`：只收 `pkg` 与 `enabled`，一次写盘完成 `@rt=per_app` 与
  `@rt.app=<包> on auto`。原子替换避免配置线程读到只改一半的文件。
- 不写 `@rt.max` / `@rt.timeslice`，沿用缺省 2 线程 / 3 ms，等价于 AsoulOpt 的 `rt=1`。
- 关闭最后一个启用条目时把 `@rt` 收回 `off`。此前只关条目会让 `rt_active()` 仍为真，
  内核时间片一直被改写，等于给别人的 RR 线程也换了时间片。
- 重新打开时保留手工调过的模式与上限（`off names:RenderThread 5` → `on names:RenderThread 5`）。
- `@rt=global` 下拒绝按包开关（409）。global 表示所有应用都在 RT，单个包的 off 没有意义，
  自动改写成 per_app 会静默改变其它应用的行为。
- `/api/rules` 增加每包 `rt` 状态与顶层 `rt_scope`，规则页不再额外请求 `/api/rt`。
- 设置页移除上限、时间片输入与「＋ 应用」入口，只留「关闭 / 按规则开启」。

### 配置迁移

- `module/applist.asoulopt.conf`：`tools/asopt2appopt.py --full` 的产物，
  324 个应用 / 9720 条线程规则，随模块安装但不自动启用。
- README 补齐 `@sched`、`@rt`、`@rt.max`、`@rt.timeslice`、`@rt.app` 指令表。

### 验证

- `cargo test`：123 passed / 0 failed / 1 ignored（新增 `rt_toggle_*` 两个用例）。
- clippy 零告警；双架构 musl 静态构建通过。
- 沙箱实测：debug 与 release 静态二进制均能加载 9720 条迁移规则；
  Web 面板点击 RT 按钮后按钮转橙、`applist.conf` 写入 `@rt.app=... on auto` 与 `@rt=per_app`；
  global 模式返回 409 及中文提示；关闭最后一个条目后 `@rt=off`。

## 2.3.0（2026-11-21）

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
- **修复**：tid 被别的进程复用时，所有权记录不会交接给新线程。`note` 发现记录里的
  pid 与当前 pid 不一致就丢弃；`reconcile` 把这类记录归为「只丢记录、不降级」
  （`Plan::Forget`），不会对现承租人调 `sched_setscheduler` 把别人的 RR 线程降掉。
- **修复**：熔断时清理残留。旧实现只在 `apply()` 里置 `enabled = false`，已提升的
  线程还是 RR、整机时间片还是配置值，后续 `prepare()` 又因为 `enabled` 为 false
  直接返回。现在统一走 `fuse()`：先降级自有线程、再按所有权检查恢复时间片、最后
  关闸门；时间片写入/备份失败同样走这条路。
- **修复**：`sched_setscheduler` 的错误分类。ESRCH 只跳过该线程；EPERM / EACCES
  触发熔断；其余 errno 记录后跳过当前线程，不再不加区分地永久关闭整个 RT。
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
