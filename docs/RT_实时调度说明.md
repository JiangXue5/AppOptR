# RT（实时调度）实现说明

状态：2.3.0 已实现，默认关闭。`@rt=off` 时本模块不读 `/proc/sys`、不调用 `sched_setscheduler`。

## 1. 配置

```
@rt=off                       # 默认
@rt=auto                      # 角色 Critical 且允许集合 ≤2 核
@rt=RenderThread,RHIThread    # 显式名字，支持 fnmatch
```

与 `@sched` 同级、独立开关。非法值 `fail_cnt += 1` 并保持 `off`，不影响静态规则。
`@rt` 计入 `policy_sig`，改配置触发全量重建，切回 `off` 时把已提升线程放回 `SCHED_OTHER`。

## 2. 做了什么

```
sched_rr_timeslice_ms = 3           # 100 → 3，缩短单次霸占
sched_setscheduler(tid, RR|RESET_ON_FORK, prio=1)
```

就这两步。与 AsoulOpt 的差异如下。

| 项 | AsoulOpt | AppOpt | 原因 |
|---|---|---|---|
| `rr_timeslice_ms` | 3 | 3 | 必须改：RR 默认 100 ms 才让位一次，比 CFS 更糟 |
| `rt_runtime_us` | 95% → 98.3% | **不改** | 整机行为，音频/显示合成 RT 线程一起受影响 |
| `rt_period_us` | 950000 → 30000 | **不改** | 同上 |
| 原值恢复 | 无 | 落盘，下次启动恢复 | `kill -9` 后不会永久停在 3 ms |
| 失败处理 | 不检查 | 首次失败即全局关闭 | `EPERM`/SELinux 重试无意义，只会刷日志 |
| 数量限制 | 1–2 个（硬编码位置） | 每 pid ≤2，按角色/名字选 | 语义清晰，可配置 |

`SCHED_RESET_ON_FORK`（`0x40000000`）不能省：没有它，游戏每 fork 一个线程都继承 RT，
几百个不可抢占线程会直接拖死系统。

## 3. 执行路径

```
task_apply 成功（规则命中、亲和性写入）
  → rt::note(tid, pid, comm, allowed, cfg)
  → 已 applied / 已是 RR|FIFO → 跳过
  → per_pid >= 2 → 跳过
  → mode_matches：auto 看角色与允许集合核数，names 走 fnmatch
  → sched_setscheduler
  → 失败：enabled=false，打印一行，本次进程内不再尝试
```

只对**规则命中**的线程设置，不做全量扫描、不继承。`auto` 只选 `Critical`：
RT 的意义是不能被抢占，`Worker` 变 RT 会把 CFS 的时间挤掉。

## 4. 时间片备份与恢复

路径：可执行文件同目录的 `.AppOpt.rt.bak`，内容为原始毫秒数。

```
启动 → restore_stale()：文件存在则写回内核并删除（上次异常退出）
     → prepare()：读原值 → 写盘 → 写内核 3
关闭 → demote_all()：线程回 SCHED_OTHER → 写回原值 → 删除备份
```

先写盘再改内核，是为了不留「内核已改、备份没写」的窗口。若备份目录不可写，
RT 直接不启用——宁可没有这个功能，也不能留下无法恢复的全局状态。

## 5. 风险

1. **SELinux**：部分 ROM 拒绝非系统域对游戏线程 `sched_setscheduler`，会触发全局关闭。
   这是预期行为，不是 bug；日志里能看到具体 errno。
2. **厂商调度器**：MTK fpsgo / 高通 boost 可能把线程拉回 CFS，RT 失效但不报错。
   真机上需要 `sched_getscheduler` 复查。
3. **优先级反转**：优先级固定为 1（RR 最低），只影响同为 RR 的线程之间的排序，
   不会压过系统 RT 线程（通常 50+）。
4. **与 S7 的交互**：RT 线程不参与 S7 迁移。迁移会改变 CPU 集合，但保留调度策略，
   两者互不干扰。

## 6. 真机验证清单（未执行）

- `sched_setscheduler` 成功率，失败时的 errno。
- `cat /proc/sys/kernel/sched_rr_timeslice_ms` 在启用/退出后是否分别回到 3 / 原值。
- 强制 `kill -9` 后重启，时间片是否被恢复。
- `sched_getscheduler <tid>` 在 10 分钟后是否仍为 RR（厂商是否拉回）。
- 帧时间 1% Low / P99，对照 `@rt=off`。
