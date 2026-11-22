### v2.3.5更新日志
- 补诊断：绑核失败会写明 errno（EPERM / EINVAL / ENOSYS），S7 的迁移、回弹、冻结与跳过原因
  都会记录；设置页新增「诊断」抽屉，可直接看每个线程的期望集合与内核实际集合
- 修 S7 掉帧：迁移不再写 cpuset（避免每次迁移额外做一次 cgroup 迁移）；单轮只迁 1 个线程；
  新增 90 秒反向冷却、目标簇配额与 180 秒 3 次预算，掐掉 p ↔ hp 来回跳
- 修「有时绑不到」：/proc 模式轮转重读线程名，补上线程创建后才改名导致的漏绑；
  绑核失败不再静默，卡顿信号会在 Critical 线程就绪等待超过 4 ms 时上报

### v2.3.4更新日志
- 修复 RT 在真机上完全没生效：静态链接的 musl 把 `sched_setscheduler` /
  `sched_getscheduler` 编成了直接返回 -ENOSYS 的桩，日志里因此一直报
  `Function not implemented (os error 38)`。改为直接走系统调用，两个架构都验证到真实 svc
- `ENOSYS` 不再当普通错误处理：熔断一次并写明原因，不会每个线程每轮重复刷日志

### v2.3.3更新日志
- 修正内置的 AsoulOpt 游戏表：包名由 324 补到 333，补上 PUBG、Albion Online、
  Heaven Burns Red、Mini World、Dumb Nation 以及 Supercell 的荒野乱斗 / 部落冲突 / squad 等 9 个
- 线程规则改为按 AsoulOpt 二进制里的 29 个分组逐组还原，每个应用只写它所在组实际列出的
  线程名，规则数由 9870 降到 926；warframe 那条指向配置路径的无效规则已丢弃
- 该配置仍不随安装自动启用，需在设置页把「规则配置文件」指向 applist.asoulopt.conf
- Web 面板补齐此前只能手写配置的选项：
  - 设置页新增「S7 动态分配」卡片，关闭 / 观察 / 开启三档可直接切换，并显示采样轮数、
    本可迁移、已迁移、失败、受限与三簇负载；单核心层机型选「开启」会明确提示不会生效
  - RT 卡片补「全部应用」档，与「关闭 / 按规则开启」并列
  - 新增可折叠的「进阶配置」抽屉：每应用 RT 线程上限（`@rt.max` 1-8）、
    RR 时间片（`@rt.timeslice` 1-100 ms）、未匹配线程行为（`@unmatched=keep|all`），
    以及逐应用 RT 条目列表，可直接开关或删除
- 新增接口 `POST /api/sched`、`POST /api/adv`，进阶三项一次写盘，不会出现只改了一半的中间状态；
  `POST /api/rt/app` 支持 `{"delete":true}` 删除条目，删掉最后一个启用条目时 `@rt` 自动收回 `off`
- 修复 `/api/config` 的 `sched_mode` 读的是运行快照，切档后按钮高亮慢一拍

### v2.3.2更新日志
- 修复 TID 复用导致的误降级：`note()` 原先先查 RT 策略、无策略时直接降级，之后才核对记录里的 pid。
  旧线程退出、tid 被新线程复用且新线程所属包没有 RT 策略时，新线程会被当成旧记录降级。
  现在 pid 核对提到最前，不符只丢弃旧记录，不调用 `sched_setscheduler`，之后按新线程自己的策略处理
- 已是 RR/FIFO 的外部线程仍不接管、不记录、不降级；无策略的线程直接跳过

### v2.3.1更新日志
- 规则页每个应用新增 `RT` 按钮，点一下即开启该应用的实时调度，参数固定为 AsoulOpt 缺省：
  自动挑选 Critical 线程、每应用最多 2 个、RR 时间片 3 ms
- 设置页 RT 卡片精简为「关闭 / 按规则开启」，移除线程上限、时间片与加包输入
- 关闭最后一个应用的 RT 后 `@rt` 自动回到 `off`，内核时间片随即还原
- 当前为 `@rt=global` 时按包开关会返回 409 并提示先切到「按规则开启」，避免静默改变其它应用
- 模块附带 `applist.asoulopt.conf`（AsoulOpt 内置 324 个游戏、9720 条规则），不自动启用，
  可在设置页把「规则配置文件」指向它
- README 补齐 `@sched` / `@rt` / `@rt.app` 指令说明

### v2.3.0更新日志
- 新增 S7 负载感知调度（`@sched=off|shadow|on`）：按簇级负载在规则允许集合内迁移 Worker/Background 线程，
  默认关闭；`shadow` 只统计不迁移，`on` 才真正生效
- 新增 RT 实时调度（`@rt=off|global|per_app`）：`SCHED_RR|SCHED_RESET_ON_FORK`、优先级 1，
  只管理自己提升的线程，线程退出即释放配额
- 新增配置指令：`@sched`、`@rt`、`@rt.max`、`@rt.timeslice`、`@rt.app=<包> on|off [auto|names:] [上限]`
- 修复：`shadow` 模式会真实修改线程亲和性
- 修复：亲和性设置失败被当成成功迁移（EPERM/EINVAL 会计入 `sched_failed`）
- 修复：RT 会接管系统或厂商已设置的 RR/FIFO 线程
- 修复：线程退出后 RT 配额不释放、tid 复用后所有权被新线程继承
- 修复：RT 熔断后已提升的线程与整机时间片残留
- 修复：只有包级规则的应用无法使用 S7 / RT（线程名采集条件过窄）
- 修复：活跃进程超过 8 个时后面的进程永远轮不到检查
- 修复：arm64 交叉编译因 `sched_param` 结构体字面量失败
- 设置页新增 S7 / RT 状态展示与 RT 配置卡片；`/api/config` 增加 `sched_*` 与 `rt` 字段
- 新增 `tools/asopt2appopt.py`：把 AsoulOpt 的 asopt.conf 转成 AppOpt 配置

### v2.2.6更新日志
- 修复已知问题

### v2.2.1更新日志
- 完善 Web 管理面板：
- http://127.0.0.1:8889


### v2.1.3更新日志
- 主程序：修复已知问题
- 主程序：性能优化

### v2.1.2更新日志
- 主程序：支持在applist.conf中使用"语义核心"，可与范围核心随意混用
```
- e-core 表示能效小核
- p-core 表示性能中核
- hp-core 为高性能大核
- all-core 表示所有核心
 也可以组合一起用（英文逗号）：
- e-core,p-core  为小核与中核
- p-core,hp-core 为中核与大核
```
- 主程序：支持使用-b参数自定义/dev/cpuset目录，防止被某些程序检测
```
- 使用方法：例如AppOpt -b MyAppOpt则目录会变成/dev/cpuset/MyAppOpt
```
- 主程序：修复了已知问题
- 主程序：完善 eBPF 支持
- 主程序：性能优化，内存与CPU占用更低

