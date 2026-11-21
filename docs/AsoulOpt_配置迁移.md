# AsoulOpt 配置迁移到 AppOpt

AsoulOpt（`Magisk_AsoulOpt`，作者 nakixii）的配置在 `/data/adb/naki/asopt.conf`，
只有三样东西：一个全局 `mode`、一个全局 `rt`，以及若干行「包名 mode rt」。
AppOpt 的配置是「指令行 + 规则块」，所以要过一层转换。

`tools/asopt2appopt.py` 做这件事。

---

## 一、AsoulOpt 的配置长什么样

```
mode=0
rt=0
com.miHoYo.Yuanshen 0 0
com.tencent.tmgp.sgame 1 0
```

| 字段 | 取值 | 含义 |
|---|---|---|
| `mode` | 0 | 硬亲和：只 `sched_setaffinity` |
| | 1 | 软迁移：写 cpuset + `sched_pipeline_special` + fpsgo `boost_affinity` |
| | 2 | 硬迁移：额外写 fpsgo `fbt_attr_by_pid` |
| `rt` | 0 / 1 | 1 时对 1–2 个线程设 `SCHED_RR \| RESET_ON_FORK`，优先级 1 |

全局值写在文件开头，后面的「包名 mode rt」按包覆盖。

---

## 二、怎么用

```bash
# 1. 从手机取出配置
adb pull /data/adb/naki/asopt.conf

# 2. 转换
python3 tools/asopt2appopt.py asopt.conf -o applist.conf

# 只看解析结果，不生成
python3 tools/asopt2appopt.py asopt.conf --list-only

# 不读 asopt.conf，导出 AsoulOpt 内置的全部 324 个游戏（等价于它的白名单行为）
python3 tools/asopt2appopt.py --full -o applist.conf
```

生成的 `applist.conf` 直接替换模块里的 `/data/adb/modules/appopt/applist.conf`
即可；AppOpt 有 inotify，保存后自动重载。

---

## 三、语义映射

### 3.1 mode

| AsoulOpt | AppOpt | 等价程度 |
|---|---|---|
| `mode=0` 硬亲和 | 线程规则绑固定簇 + `@sched=off` | **等价**：都是「定死在哪几个核」 |
| `mode=1` 软迁移 | 工作线程规则放宽到 `e-core,p-core` + `@sched=on` | **近似** |
| `mode=2` 硬迁移 | 同上 | **近似** |

`mode=1/2` 在 AsoulOpt 里是通过 cpuset + WALT `sched_pipeline_special` + fpsgo
`boost_affinity` 告诉厂商调度器「我要在这组核上，请配合」。AppOpt 没有这条通道，
最接近的是 `@sched=on`：在规则允许的集合内按簇负载换。两者目的一致（让线程待在
合适的核上），实现路径不同。

> `@sched` 是**全局**开关，不能像 `mode` 那样逐游戏设置。转换脚本的处理是：
> 只要有一个游戏是 `mode=1/2` 就整体 `@sched=on`，并在文件头列出那些原本 `mode=0`
> 的应用，提示它们也会进入动态调度判定（只影响 Worker / Background 角色的线程，
> 主线程与渲染线程不受影响）。

### 3.2 rt

| AsoulOpt | AppOpt |
|---|---|
| `rt=0` | `@rt=off` |
| `rt=1` | `@rt=per_app` + `@rt.app=<包> on auto 2` |

两边用的都是 `SCHED_RR \| SCHED_RESET_ON_FORK`、优先级 1，且都只动自己提升的线程。
上限取 2，对应 AsoulOpt 金字塔里「1 个上超大核 + 1 个上中核」。

### 3.3 线程分配

AsoulOpt 是固定金字塔：**1 个线程进 hp、1 个进 p、其余命中的全进 e**，具体挑谁由
`/proc/<tid>/schedstat` 的累计运行时间决定（选最闲的）。AppOpt 没有负载挑选，
只能按线程名静态分档：

| 档位 | 线程名 |
|---|---|
| `hp-core` | MainThread、UnityMain、GameThread、`_DummyMain`、`__DummyMain`、`__DoubleMain`、MiniRainbowMain、WZM_Main、Mainloop、MINECRAFT MAIN、DAVA Engine Mai* |
| `p-core,hp-core` | RenderThread、GLThread、UnityGfx*、RHIThread、VkThread、SDLThread、GPU Submission、SCERender、SHPD Render、MiniRenderThrea*、Render T*、Draw Thread、DAVA::RhiThread、Rendering Pool、RBX Worker |
| `e-core`（mode 0）<br>`e-core,p-core`（mode 1/2） | Thread-*、FunctionMarshal、TfLite、Update Thread |

带 `*` 的是因为原字符串是被内核 `comm` 截断到 15 字节的形态
（`DAVA::RhiThread` 正好 15 字节，`MiniRenderThrea` 是 `MiniRenderThread` 的截断）。

**不写包级规则**是关键：AppOpt 对「有线级规则但本线程未命中、且没有包级规则」的线程
保持原亲和性（`@unmatched=keep`），这与 AsoulOpt「未命中名表的线程完全不动」一致。
如果写了包级规则，未命中线程会被拉到包级集合，反而比 AsoulOpt 更激进。

---

## 四、做不到等价的地方

| 项 | 说明 |
|---|---|
| 挑最闲线程上大核 | AppOpt 没有 `schedstat` 横向比较，只能按名字静态分档。多线程渲染的游戏里，AsoulOpt 可能挑到 `Thread-7` 进 hp，AppOpt 会把它和其余 `Thread-*` 一起放 e |
| 厂商调度器联动 | WALT `sched_pipeline_special`、fpsgo `boost_affinity` / `fbt_attr_by_pid` 都没有对应实现。MTK 机型上只改亲和性，厂商 boost 逻辑仍可能按自己的判断改回去 |
| 逐游戏 `@sched` | 全局开关，混合 mode 时只能整体取一个值 |
| 机型指纹表 | AsoulOpt 内置 SoC 指纹 → 三簇掩码；AppOpt 用 `cpu_capacity` 推断。两者在各自支持的机型上结果可能不同 |

反过来，AppOpt 做到而 AsoulOpt 没做的：未知 SoC 上有明确的「不适用」日志、
`cpusetsize` 按实际核数给（不是写死 4 字节）、`sched_setaffinity` 失败会区分
EPERM / ESRCH 而不是静默忽略。

---

## 五、与现有 applist.conf 合并

`tools/asopt2appopt.py --full` 生成的是纯游戏配置。如果还想保留原有的日常应用规则
（微信、QQ、抖音等），按下面三步拼：

1. **指令行只能有一份**。取并集，冲突时以你需要的为准：
   ```
   @unmatched=keep
   @sched=off          # 或 on，看你是否需要动态调度
   @rt=per_app
   @rt.app=com.x on auto 2
   ```
2. **包不重复**。同一个包在两个文件里都有规则块，AppOpt 会加载两份（CPU 集合取并集），
   通常不是你想要的，删掉其中一个。
3. **规则块直接拼接**即可，顺序不影响结果（线程规则按包索引，包级规则单独收集）。

---

## 六、验证

转换后的配置可以直接用 AppOpt 加载，看启动日志：

```
配置文件解析完成，共加载 9720 条规则
未匹配线程: keep（保持原有亲和性）
S7 动态分配: off（不采样，行为与静态规则一致）
RT 调度: per_app（2 个应用启用），每应用上限 2，RR 时间片 3 ms
```

`324 个游戏 × 30 条线程规则 = 9720` 条，解析在启动时一次完成，之后靠 mtime 判断
是否需要重载，运行期不重复解析。

真机上还需要确认：`hp-core` / `p-core` / `e-core` 是否被正确识别（看
`CPU 拓扑: ... 依据=capacity`），以及目标线程是否真的落在预期核上
（`adb shell taskset -p <tid>`）。
