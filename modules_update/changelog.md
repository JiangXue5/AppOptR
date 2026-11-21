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

