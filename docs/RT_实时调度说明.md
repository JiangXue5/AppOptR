# RT（实时调度）实现说明

状态：3.0 已实现分应用启用，默认 `off`。`@rt=off` 时本模块不读 `/proc/sys`、
不调用 `sched_setscheduler`，也不会为 RT 做任何 /proc 扫描。

## 1. 三种模式

| 模式 | 含义 | 是否改写时间片 |
|---|---|---|
| `off`（默认） | 任何应用都不获得 RT | 否 |
| `global` | 全部**已管理**应用按同一套规则启用 RT | 有任一启用即改写 |
| `per_app` | 只有 `@rt.app` 里显式 `enabled` 的应用获得 RT | 至少一个应用启用时改写 |

「已管理」指该包在亲和性规则里出现过。`global` 不是对系统全部应用无差别提权：
RT 决策只在规则命中路径上执行，没有亲和性规则的进程永远走不到这里。

优先级是互斥而非叠加：

```
off      → policy() 恒为 None，即使写了 @rt.app 也不生效
global   → 只读全局规则，@rt.app 条目被忽略（配置保留，切回 per_app 时恢复）
per_app  → 只读 @rt.app，未列出的包、列出但 enabled=false 的包都拿不到 RT
```

## 2. 配置

```
@rt=off                       # 默认
@rt=global                    # 全部已管理应用，auto 规则
@rt=per_app                   # 按应用配置

@rt.max=2                     # 每应用 RT 线程上限，默认 2，范围 1-8
@rt.timeslice=3               # RR 时间片，默认 3 ms，范围 1-100

@rt.app=com.tencent.tmgp.sgame on auto 2
@rt.app=com.example.other       on names:RenderThread,RHI* 1
@rt.app=com.example.third       off names:GLThread 2
```

单条 `@rt.app` 的语法是 `<包名> [on|off] [auto|names:<列表>] [上限]`，三段都可省略：

| 写法 | 结果 |
|---|---|
| `com.a` | 启用、auto、上限取 `@rt.max` |
| `com.a 2` | 启用、auto、上限 2 |
| `com.a off` | 关闭、auto、上限取 `@rt.max` |
| `com.a off names:GLThread 2` | 关闭但保留模式，再次打开不必重填 |

`on` / `off` 与 `true` / `false` / `1` / `0` 等价。`names` 后可以跟空格再接列表，
也可以写成 `names:A,B`。同一个条目写两种模式视为格式错误，跳过并计入解析失败数。

兼容旧写法：`@rt=auto` 与 `@rt=RenderThread,RHI*` 等价于
`@rt=global` + 缺省的自动规则，已有配置不需要改。

`@rt` 的全部字段（模式、全局规则、上限、时间片、每条分应用条目）都计入
`policy_sig`。任何一项变化都会触发全量重扫，否则 `per_app → off` 回滚不了。

## 3. 状态所有权

RT 只有一张表：

```rust
own: HashMap<i32, Owned>   // Owned { pid, pkg, comm, allowed }
```

只有 `sched_setscheduler` 返回 0 的线程才会进入这张表。三种状态严格分开：

| 状态 | 存放位置 | 会不会被回滚 |
|---|---|---|
| 本模块提升的线程 | `own` | 会，且只在配置不再允许时 |
| 外部模块/系统设置的 RR/FIFO | 不记录 | **永远不会** |
| 符合规则但尚未提升 | 无状态，每次重新判定 | — |

配额不再用独立计数器，而是从 `own` 直接统计（`count(pid)`）。
count 与集合天然一致，不存在「线程已退出但配额没释放」的漂移。

线程退出（`forget`）只删记录、不调 `sched_setscheduler`——线程已经不存在了。
进程退出（`release_pid`）清掉该 PID 下全部记录，配额随之回落。
新线程创建后可以立刻占用刚释放的名额。

记录是否还有效要现场核对：`note` 会用一次 `sched_getscheduler` 检查内核里
该 tid 是否仍是本模块设的 RR。不是就说明线程已退出、tid 被复用，或者外部
改回了 CFS —— 记录立即作废，按新线程重新判定。否则复用了旧 tid 的新线程会
被永久当成「已提升」，既不再提升也不释放配额。

`note` 还会核对 pid：tid 被别的进程复用时，旧记录和新线程毫无关系，直接丢弃。
不丢的话，新线程会被当成「已提升」，关 RT 时连它一起降级——而它可能正是别的
模块设的 RR 线程。

全量重扫（`rt::reconcile`）做同样的账，每条记录有三种去向：缓存里 pid 与记录
一致且仍符合策略的保留；pid 变了（tid 被复用）只丢记录，**不对现承租人调
`sched_setscheduler`**；缓存里没有或不再符合的撤销降级。

## 4. 生命周期

```
启动
  rt::init()        先看有没有上次异常退出留下的时间片备份，有就还原
  rt::prepare()     有应用启用才备份原值并写入配置值

新线程 / 线程改名 / 配置变更
  rt::note(tid, pid, pkg, comm, allowed, cfg)
    ├ 记录 pid 与当前 pid 不同（tid 被复用）：丢弃记录，当新线程处理
    ├ 记录已失效（内核不是 RR）：丢弃记录，当新线程处理
    ├ 已在 own：按新配置复核，合格保留（并刷新 comm / 允许集合），不合格降级
    ├ 不在 own 且已是 RR/FIFO：跳过，不入表（外部线程）
    ├ 不在 own 且配额已满：跳过
    └ 否则 sched_setscheduler 并记账

配置热更新
  rt::prune()       遍历 own，不再符合新规则的降级，符合的保留
  rt::prepare()     改写或还原时间片

线程退出
  rt::forget(tid)   释放配额

全量扫描 / 定期亲和性校验
  rt::reconcile(cfg, cache)  缓存里没有的、不再符合的收回；pid 变了只丢记录
  affinity_check 的 ESRCH tid 也会 forget（EXIT 事件丢失时的兜底）

进程退出
  rt::release_pid() 清空该 PID 的全部记录

SIGTERM / SIGINT
  主循环检测到标志 → rt::shutdown() → 线程降级 + 时间片写回原值
```

`note` / `prune` / `reconcile` 共用同一个判定函数 `eligible(mode, comm, allowed)`：
三处都先取一次 `cfg.rt.policy(pkg)`，再调这一个函数，不各自解释一遍 `RtMatch`。
`note` 本来就拿到了 `max`，所以策略只取一次。
上限下调时 `prune` 按 tid 升序保留前 N 个，结果与 HashMap 遍历顺序无关。

## 5. 时间片

`sched_rr_timeslice_ms` 是**全局**内核参数，不支持按应用设置。因此规则是：

1. 没有任何**受管**应用时，不碰它。闸门是 `cfg.rt_active()` 而不是 `@rt` 的 scope：
   `@rt=global` 但规则文件里一个包都没有时，不会有线程被提升，此时改时间片
   只会影响别人的 RR 线程；`@rt.app` 里启用了但包没写进规则文件同理；
2. 第一个应用启用时，读原值 → 写备份文件 → 写配置值；
3. 后续热更新只改当前值，**绝不重新读取「原值」**（否则会把上次写的 3 ms 当成原值）；
4. 全部应用关闭时写回原值并删除备份；
5. 正常退出（SIGTERM）同样还原；`kill -9` 或断电靠下次启动的 `restore_stale()`；
6. 外部在两次配置之间改过这个参数时，把现值当作新的原值记录下来，恢复时
   还给它；如果关闭时发现当前值已经不是自己写的，只清记录不覆盖。

第 6 条是为了不把「用户手动调过时间片」当成自己的状态：模块只管自己写进去
的那个值，别人改了就以别人的为准。

备份文件在可执行文件同目录，名为 `.AppOpt.rt.bak`。备份目录不可写时 RT 直接不启用：
宁可没有这个功能，也不能留下无法恢复的全局状态。

## 6. 四个历史 BUG 的修复

### BUG 1：接管了别人的 RT 线程

旧实现在发现线程已是 RR/FIFO 时把它加入 `applied`，本意是「避免每轮重复
`getscheduler`」。代价是关闭 RT 时会对其他模块设置的 RT 线程调用
`sched_setscheduler(SCHED_OTHER)`，把别人的实时线程降级。

现在外部 RT 线程**不入表**，`own` 只记录自己成功提升的线程。`demote_all()`
遍历的是 `own`，结构上不可能碰到外部线程。重复查询的成本可以忽略：`note`
只在新线程或配置变更时调用，不在采样周期上。

### BUG 2：线程退出后配额不释放

旧实现 `forget(tid)` 只从 `applied` 删 tid，`per_pid` 计数器不减；进程退出时
`release_pid` 只删计数器，`applied` 里的 tid 残留。两者都会导致「配额永久
少一个」，最终该进程再也提不了新线程。

现在配额从 `own` 派生，`forget` 删记录即释放；`release_pid` 同时清掉该 PID
的全部记录。`Owned` 里带 `pid`，TID 与 PID 的对应关系是持久化的。

### BUG 3：热切换只处理了 off

旧实现只在 `prepare()` 里判断 `is_off()` 时回滚，`global ↔ per_app`、
`auto ↔ names`、应用级开关互不影响都要靠重启。

现在两条路径同时生效：

- `rt::prune(&cfg)` 在配置变更时遍历 `own`，按新配置复核每个线程；
- `rt::note()` 在规则重扫时对已提升线程做同样的复核。

仍然符合新规则的线程保留 RT，不做「降级再提升」的无谓往返。

### BUG 4：时间片备份会被覆盖

旧实现每次 `prepare()` 都读当前内核值当「原值」。第二次热更新时读到的是上次
写入的 3 ms，备份就被污染成 3 ms，退出后恢复不了。

现在原值只在第一次保存，之后 `pending_restore` 保持不变；多条应用启停共享
同一份备份，互不覆盖。

## 7. 与 S7 的关系

两者共用线程生命周期信息，但职责独立：

| | S7 | RT |
|---|---|---|
| 管什么 | CPU 亲和性（哪几个核） | 调度策略（CFS / RR） |
| 状态表 | `SchedState.threads` | `RtState.own` |
| 清理入口 | `SchedState::settle(Gone)` / 每轮缓存清理 | `rt::forget` / `rt::release_pid` / `rt::reconcile` |

S7 迁移线程时只改 `cpus_mask` 与缓存里的 `cpus`，不碰调度策略；RT 降级时只改
调度策略，不碰亲和性。两边的 `forget` 各清各的表，不会误删对方仍在用的记录。
RT 线程不参与 S7 迁移判定。

## 8. 风险

1. **SELinux**：部分 ROM 拒绝非系统域对游戏线程 `sched_setscheduler`（EPERM /
   EACCES），会触发熔断：先把已提升的线程放回 CFS，再按所有权检查恢复时间片，
   最后关闸门。ESRCH 只是线程刚好退出，只跳过该线程；其余 errno 只记录并跳过
   当前线程，不据此认定整个环境不可用。
2. **厂商调度器**：MTK fpsgo / 高通 boost 可能把线程拉回 CFS，RT 失效但不报错。
3. **优先级反转**：优先级固定为 1（RR 最低），只影响同为 RR 的线程之间的排序，
   不会压过系统 RT 线程（通常 50+）。
4. **异常退出**：时间片会被下次启动还原，但被提升的线程仍是 RR，直到进程退出。
   这是跨进程无法记录状态导致的固有限制。

## 9. 真机验证清单（未执行）

- `@rt=per_app` 只给一个应用开启，确认其他应用线程 `sched_getscheduler` 仍为 0。
- 关闭该应用后，其线程回到 0，另一个开启的应用不受影响。
- 原本是 RR 的系统线程在模块关闭后仍是 RR。
- `cat /proc/sys/kernel/sched_rr_timeslice_ms`：启用后为配置值，全部关闭后回原值。
- `kill -9` 后重启，时间片是否被 `restore_stale()` 还原。
- 同一进程反复创建/退出线程，Web 上「RT 线程数」是否始终不超过上限。
- `sched_getscheduler` 在 10 分钟后是否仍为 RR（厂商是否拉回）。
- 帧时间 1% Low / P99，对照 `@rt=off`。
