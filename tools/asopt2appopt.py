#!/usr/bin/env python3
"""把 AsoulOpt 的 asopt.conf 转换成 AppOpt 的 applist.conf。

用法：
    python3 tools/asopt2appopt.py asopt.conf -o applist.conf
    python3 tools/asopt2appopt.py --full -o applist.conf      # 不读 asopt.conf，导出全部内置游戏
    python3 tools/asopt2appopt.py asopt.conf --list-only      # 只看解析结果

asopt.conf 的格式（`/data/adb/naki/asopt.conf`）：

    mode=0
    rt=0
    com.miHoYo.Yuanshen 0 0
    com.tencent.tmgp.sgame 1 0

`mode` / `rt` 是全局值，后面的行按包名覆盖。

语义对应关系见 docs/AsoulOpt_配置迁移.md。
"""

import argparse
import json
import os
import sys

# AsoulOpt 名表里出现过的线程名。原始匹配是 strcmp 精确相等，
# 长度不足 15 字节的被内核 comm 截断过，这里保留截断形态再加通配。
HP_THREADS = [
    "MainThread",
    "UnityMain",
    "GameThread",
    "_DummyMain",
    "__DummyMain",
    "__DoubleMain",
    "MiniRainbowMain",
    "WZM_Main",
    "Mainloop",
    "MINECRAFT MAIN",
    "DAVA Engine Mai*",
]

P_THREADS = [
    "RenderThread",
    "GLThread",
    "UnityGfx*",
    "RHIThread",
    "VkThread",
    "SDLThread",
    "GPU Submission",
    "SCERender",
    "SHPD Render",
    "MiniRenderThrea*",
    "Render T*",
    "Draw Thread",
    "DAVA::RhiThread",
    "Rendering Pool",
    "RBX Worker",
]

# mode=0 下放小核；mode=1/2 放宽到 e-core,p-core，留出 @sched=on 的迁移余地
E_THREADS = [
    "Thread-*",
    "FunctionMarshal",
    "TfLite",
    "Update Thread",
]

HEADER = """\
# ============================================================
# 由 tools/asopt2appopt.py 从 AsoulOpt 的 asopt.conf 转换生成
# 原始全局值：mode={mode}（{mode_desc}），rt={rt}（{rt_desc}）
# 共 {total} 个受管应用，其中 {soft} 个使用软/硬迁移
# ============================================================
#
# 转换说明：
# 1. AsoulOpt 的模型是「1 个超大核线程 + 1 个中核线程 + 其余全下放小核」，
#    运行时按 schedstat 挑「最闲」的线程上大核。AppOpt 没有负载挑选，
#    这里按线程语义静态化：
#       主线程类      → hp-core
#       图形/渲染类   → p-core,hp-core
#       其余工作线程  → e-core
# 2. 只写线程规则、不写包级规则。未命中线程名的线程保持原亲和性，
#    与 AsoulOpt「未命中名表完全不动」一致。
# 3. mode=1/2 在 AsoulOpt 里是写 cpuset + WALT/fpsgo 提示让厂商调度器配合，
#    AppOpt 无此通道，改用 @sched=on 在允许集合内按负载换簇（近似，非等价）。
#    AppOpt 的 @sched 是全局开关，不能像 mode 那样逐游戏设置。
# 4. rt=1 映射为 @rt.app=<包> on auto 2：同样用 SCHED_RR|SCHED_RESET_ON_FORK、
#    优先级 1，只提升本模块自己设置的线程。
# ============================================================

@unmatched=keep
@sched={sched}
@rt={rt_scope}
"""


def load_games(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def parse_asopt(path):
    """返回 (全局 mode, 全局 rt, [(pkg, mode, rt)])"""
    mode, rt = 0, 0
    games = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            p = line.strip()
            if not p or p.startswith("#"):
                continue
            if p.startswith("mode="):
                try:
                    mode = int(p.split("=", 1)[1].strip())
                except ValueError:
                    warn(f"第 {lineno} 行 mode 无法解析：{p}")
                continue
            if p.startswith("rt="):
                try:
                    rt = int(p.split("=", 1)[1].strip())
                except ValueError:
                    warn(f"第 {lineno} 行 rt 无法解析：{p}")
                continue
            parts = p.split()
            if len(parts) != 3:
                warn(f"第 {lineno} 行不是「包名 mode rt」，已跳过：{p}")
                continue
            pkg, m, r = parts
            try:
                games.append((pkg, int(m), int(r)))
            except ValueError:
                warn(f"第 {lineno} 行 mode/rt 不是整数，已跳过：{p}")
    return mode, rt, games


def warn(msg):
    print(f"[警告] {msg}", file=sys.stderr)


def mode_desc(m):
    return {0: "硬亲和", 1: "软迁移", 2: "硬迁移"}.get(m, f"未知({m})")


def rt_desc(r):
    return {0: "关闭", 1: "实时调度"}.get(r, f"未知({r})")


def render_app(pkg, mode, rt, out):
    soft = mode in (1, 2)
    out.append(f"# {pkg}（mode={mode} {mode_desc(mode)}，rt={rt}）")
    out.append(f"{pkg} {{")
    for name in HP_THREADS:
        out.append(f"\t{name}=hp-core")
    for name in P_THREADS:
        out.append(f"\t{name}=p-core,hp-core")
    for name in E_THREADS:
        out.append(f"\t{name}=e-core,p-core" if soft else f"\t{name}=e-core")
    out.append("}")
    out.append("")
    return soft


# ---- 内置分组（--full）：按 AsoulOpt 二进制里的 29 个分组逐组还原 ----

GROUP_HP = {
    "UnityMain",
    "GameThread",
    "__DummyMain",
    "__DoubleMain",
    "MiniRainbowMain",
    "Mainloop",
    "MINECRAFT MAIN",
    "DAVA Engine Mai",
    "MainThread",
    "WZM_Main",
    "SCELogic",
    "Update",
}
GROUP_P = {
    "RenderThread",
    "UnityGfx",
    "RHIThread",
    "SCERender",
    "SHPD Render",
    "MiniRenderThrea",
    "Render T",
    "Draw Thread",
    "DAVA::RhiThread",
    "Rendering Pool",
    "VkThread",
    "SDLThread",
    "GLThread",
    "Draw",
    "GPU Submission",
}
GROUP_E = {"Thread-", "TfLite", "FunctionMarshal", "RBX Worker", "Update Thread"}
# 原始表里被内核 comm 截断或以「-」结尾的名字，匹配时需要前缀
GROUP_WILDCARD = {"Thread-", "Render T", "MiniRenderThrea", "DAVA Engine Mai"}
GROUP_SPEC = {"hp": "hp-core", "p": "p-core,hp-core", "e": "e-core"}


def group_class(name):
    base = name.rstrip("*")
    if base in GROUP_HP:
        return "hp"
    if base in GROUP_P:
        return "p"
    if base in GROUP_E:
        return "e"
    # 名单外的新线程按工作线程处理，宁可放小核也不误升大核
    return "e"


def render_group_app(pkg, rules, out):
    """按该组实际列出的线程名生成规则块，返回是否写出了内容"""
    body = []
    for name, cnt in rules:
        if cnt == 0:  # 原始表里 count=0 表示不处理
            continue
        spec = GROUP_SPEC[group_class(name)]
        nm = name + "*" if name in GROUP_WILDCARD else name
        body.append(f"\t{nm}={spec}")
    if not body:
        return False
    out.append(f"# {pkg}")
    out.append(f"{pkg} {{")
    out.extend(body)
    out.append("}")
    out.append("")
    return True


HEADER_GROUP = """\
# ============================================================
# AsoulOpt 内置游戏表（{total} 个应用 / {groups} 组规则）
#
# 生成自 AsoulOpt Kana（versionCode 284）的内置结构：二进制里是 29 个
# 「包名数组 + 线程规则」分组。本文件逐组还原，每个应用只写它所在组
# 实际列出的线程名，而不是对全部应用套同一份 30 条名单。
#
# 簇映射：
#   主线程类      → hp-core
#   图形/渲染类   → p-core,hp-core
#   其余工作线程  → e-core
#   原始表里 count=0 的条目表示不处理，已跳过
#
# 与 AsoulOpt 的差异：原始实现按 schedstat 在候选线程里挑最闲的上大核，
# 并按 count 限制数量；AppOpt 只做静态亲和，没有负载挑选。所以这里是
# 「线程集合一致、分配策略近似」，不是逐字节等价。
# ============================================================

@unmatched=keep
@sched=off
@rt=off
"""


def emit_groups(path, output):
    """按内置分组逐组生成配置"""
    with open(path, encoding="utf-8") as f:
        groups = json.load(f)["groups"]
    total = sum(len(g["pkgs"]) for g in groups)
    out = [HEADER_GROUP.format(total=total, groups=len(groups))]
    written = 0
    for g in groups:
        for pkg in g["pkgs"]:
            if render_group_app(pkg, g["rules"], out):
                written += 1
    text = "\n".join(out).rstrip() + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"已写入 {output}：{written} 个应用，{len(groups)} 组规则（逐组还原）")
    else:
        sys.stdout.write(text)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="AsoulOpt asopt.conf → AppOpt applist.conf")
    ap.add_argument("conf", nargs="?", help="asopt.conf 路径")
    ap.add_argument("-o", "--output", help="输出文件，缺省打印到 stdout")
    ap.add_argument(
        "--full",
        action="store_true",
        help="忽略 asopt.conf 的游戏列表，导出 AsoulOpt 内置的全部游戏（mode=0 rt=0）",
    )
    ap.add_argument("--list-only", action="store_true", help="只打印解析结果，不生成配置")
    args = ap.parse_args()

    if args.full:
        groups_file = os.path.join(here, "asoulopt_groups.json")
        if os.path.exists(groups_file):
            emit_groups(groups_file, args.output)
            return
        # 兼容：没有分组数据时退回「清单 + 通用 30 条名单」
        games_file = os.path.join(here, "asoulopt_games.txt")
        if not os.path.exists(games_file):
            sys.exit(f"找不到内置清单 {games_file}，请改用位置参数指定 asopt.conf")
        entries = [(p, 0, 0) for p in load_games(games_file)]
        gmode, grt = 0, 0
    else:
        if not args.conf:
            ap.print_help()
            sys.exit("\n需要 asopt.conf，或用 --full 导出内置清单")
        if not os.path.exists(args.conf):
            sys.exit(f"找不到 {args.conf}\n可从手机取出：adb pull /data/adb/naki/asopt.conf")
        gmode, grt, games = parse_asopt(args.conf)
        # 配置里没写的包不生成；per-game 覆盖生效
        entries = games
        if not entries:
            warn("asopt.conf 里没有任何「包名 mode rt」行，只生成全局指令")

    if args.list_only:
        print(f"全局 mode={gmode}（{mode_desc(gmode)}），rt={grt}（{rt_desc(grt)}）")
        for pkg, m, r in entries:
            print(f"  {pkg:<48} mode={m} rt={r}")
        return

    # 去重：同包多次出现取第一次，AsoulOpt 也是首个命中即用
    seen = set()
    uniq = []
    for pkg, m, r in entries:
        if pkg in seen:
            warn(f"{pkg} 重复出现，取第一条")
            continue
        seen.add(pkg)
        uniq.append((pkg, m, r))

    soft_cnt = sum(1 for _, m, _ in uniq if m in (1, 2))
    # @sched 是全局开关：只要有一个游戏要迁移就开；全硬亲和则关
    sched = "on" if soft_cnt else "off"

    out = [
        HEADER.format(
            mode=gmode,
            mode_desc=mode_desc(gmode),
            rt=grt,
            rt_desc=rt_desc(grt),
            total=len(uniq),
            soft=soft_cnt,
            sched=sched,
            rt_scope="per_app" if any(r == 1 for _, _, r in uniq) else "off",
        )
    ]

    rt_apps = [(pkg, r) for pkg, _, r in uniq if r == 1]
    if rt_apps:
        out.append("# RT：只对原本 rt=1 的应用开启，上限 2 个线程（对应 AsoulOpt 的 1 hp + 1 p）")
        for pkg, _ in rt_apps:
            out.append(f"@rt.app={pkg} on auto 2")
        out.append("")
    else:
        out.append("# 原始配置里没有 rt=1 的应用，不生成 @rt.app")
        out.append("")

    if sched == "on" and soft_cnt != len(uniq):
        hard = [p for p, m, _ in uniq if m == 0]
        out.append(
            f"# 注意：@sched=on 是全局的，下面 {len(hard)} 个原本 mode=0 的硬亲和应用"
        )
        out.append("# 也会进入动态调度判定（只影响 Worker/Background 角色的线程）：")
        for i in range(0, len(hard), 6):
            out.append("#   " + "  ".join(hard[i : i + 6]))
        out.append("")

    out.append("# ==================== 规则 ====================")
    out.append("")

    for pkg, m, r in uniq:
        render_app(pkg, m, r, out)

    text = "\n".join(out).rstrip() + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(
            f"已写入 {args.output}：{len(uniq)} 个应用，{soft_cnt} 个迁移模式，"
            f"{len(rt_apps)} 个 RT，@sched={sched}"
        )
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
