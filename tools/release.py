#!/usr/bin/env python3
"""把已构建好的模块包同时发到 GitHub Release 与 Gitee Release。

用法：
    python3 tools/release.py 2.7.0-beta24
    python3 tools/release.py 2.7.0-beta24 --dry-run
    python3 tools/release.py 2.7.0-beta24 --only gitee

只做「发包」这一段，不构建。构建仍用 ./build.sh -a all。
之所以单独抽出来：beta8~beta23 的代码和 tag 都推了，但 Gitee 一直没建
Release，包自然也没有——两个平台手工点两次，迟早漏一个。

幂等：Release 已存在就复用，附件已存在就跳过，缺哪个补哪个。
令牌从 ~/.git-credentials 读（Gitee 那条是 32 位私人令牌，GitHub 那条是 PAT）。

发完包会顺手写 modules_update/AppOpt.json 与 changelog.md（KernelSU/Magisk 的
更新检查就吃这两个文件），记得把它们提交到 master —— module.prop 的 updateJson
指向的就是 Gitee master 上的 raw 地址。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GH_REPO = "JiangXue5/AppOptR"
GITEE_REPO = "JiangXue_2004/AppOptR"
TIMEOUT = 180


def credentials() -> dict[str, str]:
    """取两个平台的令牌；不打印、不落盘。

    优先环境变量（CI 用 secrets 注入），读不到再回落到 `~/.git-credentials`（本地）。
    CI 里没有凭证文件，也不该把令牌写进仓库，所以顺序不能反。
    """
    out: dict[str, str] = {}
    for key, env in (("github", "GITHUB_TOKEN"), ("gitee", "GITEE_TOKEN")):
        val = os.environ.get(env, "").strip()
        if val:
            out[key] = val
    if len(out) == 2:
        return out

    path = os.path.expanduser("~/.git-credentials")
    if not os.path.exists(path):
        return out
    text = open(path, encoding="utf-8").read()
    for host, key in (("github.com", "github"), ("gitee.com", "gitee")):
        if key in out:  # 环境变量优先，文件只补缺
            continue
        m = re.search(rf"https://[^:]+:([^@]+)@{re.escape(host)}", text)
        if m:
            out[key] = m.group(1)
    return out


def changelog_section(version: str) -> str:
    """取 CHANGELOG 里这一版的正文，到下一个 `## ` 为止。"""
    path = os.path.join(ROOT, "CHANGELOG.md")
    text = open(path, encoding="utf-8").read()
    m = re.search(rf"^## {re.escape(version)}（[^）]*）\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        sys.exit(f"CHANGELOG.md 里没有 {version} 这一节")
    return m.group(1).strip()


def packages(version: str) -> list[str]:
    dist = os.path.join(ROOT, "dist")
    found = sorted(
        os.path.join(dist, n)
        for n in os.listdir(dist)
        if n.startswith(f"AppOpt-{version}-") and n.endswith(".zip")
    )
    if not found:
        sys.exit(f"dist/ 下没有 AppOpt-{version}-*.zip，先跑 ./build.sh -a all")
    return found


def is_beta(version: str) -> bool:
    """测试版：正式版号只有 2.7.0 这种，带连字符的是 beta/rc。"""
    return "-" in version


def ci_note() -> str:
    """在 Actions 里跑时标一下构建来源；本地手动发版不写，免得谎报。"""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return ""
    sha = os.environ.get("GITHUB_SHA", "")[:7]
    run = os.environ.get("GITHUB_RUN_ID", "")
    tail = f"，[运行 {run}](https://github.com/{GH_REPO}/actions/runs/{run})" if run else ""
    return f"\n> CI 构建：GitHub Actions，提交 `{sha}`{tail}\n"


def body_for(version: str) -> str:
    return (
        f"## {version}\n\n{changelog_section(version)}\n"
        f"{ci_note()}\n"
        "---\n"
        "装机：Magisk / KernelSU 刷入 zip；arm64 设备选 `arm64-v8a`，"
        "模拟器或 x86 设备选 `x86_64`。"
    )


def gh_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def release_github(version: str, token: str, files: list[str], dry: bool) -> str:
    tag = f"v{version}"
    api = f"https://api.github.com/repos/{GH_REPO}/releases"
    r = requests.get(f"{api}/tags/{tag}", headers=gh_headers(token), timeout=30)
    if r.status_code == 404:
        if dry:
            print(f"[dry] 新建 GitHub Release {tag}")
            return f"https://github.com/{GH_REPO}/releases/tag/{tag}"
        r = requests.post(
            api,
            headers=gh_headers(token),
            json={
                "tag_name": tag,
                "name": tag,
                "body": body_for(version),
                # 测试版标 prerelease：Release 列表默认不把它当成稳定版
                "prerelease": is_beta(version),
            },
            timeout=60,
        )
        if r.status_code >= 300:
            sys.exit(f"GitHub 建 Release 失败：{r.status_code} {r.text[:200]}")
    elif r.status_code >= 300:
        sys.exit(f"GitHub 查 Release 失败：{r.status_code} {r.text[:200]}")

    rel = r.json()
    have = {a["name"] for a in rel.get("assets", [])}
    for path in files:
        name = os.path.basename(path)
        if name in have:
            print(f"  跳过（已存在）{name}")
            continue
        if dry:
            print(f"[dry] 上传 GitHub {name}")
            continue
        with open(path, "rb") as fh:
            up = requests.post(
                f"https://uploads.github.com/repos/{GH_REPO}/releases/{rel['id']}/assets",
                params={"name": name},
                headers={**gh_headers(token), "Content-Type": "application/zip"},
                data=fh.read(),
                timeout=TIMEOUT,
            )
        if up.status_code >= 300:
            sys.exit(f"GitHub 上传 {name} 失败：{up.status_code} {up.text[:200]}")
        print(f"  上传 GitHub {name}")
    return rel.get("html_url") or f"https://github.com/{GH_REPO}/releases/tag/{tag}"


def release_gitee(version: str, token: str, files: list[str], dry: bool) -> str:
    tag = f"v{version}"
    api = f"https://gitee.com/api/v5/repos/{GITEE_REPO}/releases"
    r = requests.get(f"{api}/tags/{tag}", params={"access_token": token}, timeout=30)
    # Gitee 对不存在的 tag 返回 200 + null，不是 404；只看状态码会在 r.json() 上崩
    exists = r.status_code == 200 and r.json() is not None
    if not exists and r.status_code not in (200, 404):
        sys.exit(f"Gitee 查 Release 失败：{r.status_code} {r.text[:200]}")
    if not exists:
        if dry:
            print(f"[dry] 新建 Gitee Release {tag}")
            return f"https://gitee.com/{GITEE_REPO}/releases/tag/{tag}"
        # Gitee 的 tag 不存在时会报错，但 tag 已由 git push 推过，正常不会走到这
        r = requests.post(
            api,
            data={
                "access_token": token,
                "tag_name": tag,
                # 测试版与正式版分开命名：Release 列表默认展示正式版，
                # 测试版要一眼看出是 CI 出的、可以随时作废
                "name": (
                    f"AppOpt {version} 测试版（CI 构建）"
                    if is_beta(version)
                    else f"AppOpt {version}"
                ),
                "body": body_for(version),
                "prerelease": "true" if is_beta(version) else "false",
                "target_commitish": "experimental",
            },
            timeout=60,
        )
        if r.status_code >= 300:
            sys.exit(f"Gitee 建 Release 失败：{r.status_code} {r.text[:200]}")

    rel = r.json()
    if rel is None:
        sys.exit("Gitee 返回了空 Release 对象")
    have = {a.get("name") for a in rel.get("assets") or []}
    for path in files:
        name = os.path.basename(path)
        if name in have:
            print(f"  跳过（已存在）{name}")
            continue
        if dry:
            print(f"[dry] 上传 Gitee {name}")
            continue
        with open(path, "rb") as fh:
            up = requests.post(
                f"{api}/{rel['id']}/attach_files",
                params={"access_token": token},
                files={"file": (name, fh, "application/zip")},
                timeout=TIMEOUT,
            )
        if up.status_code >= 300:
            sys.exit(f"Gitee 上传 {name} 失败：{up.status_code} {up.text[:200]}")
        print(f"  上传 Gitee {name}")
    return f"https://gitee.com/{GITEE_REPO}/releases/tag/{tag}"


def module_meta() -> tuple[str, int]:
    """从 module/module.prop 读 version / versionCode。

    不采信命令行给的版本号：设备上比的就是 module.prop 里的 versionCode，
    两者不一致时更新提示要么不出现、要么反复出现。
    """
    text = open(os.path.join(ROOT, "module", "module.prop"), encoding="utf-8").read()
    ver = re.search(r"^version=(.+)$", text, re.M)
    code = re.search(r"^versionCode=(\d+)$", text, re.M)
    if not ver or not code:
        sys.exit("module/module.prop 里没有 version / versionCode")
    return ver.group(1).strip(), int(code.group(1))


def write_update_json(version: str, files: list[str], dry: bool) -> None:
    """写 modules_update/AppOpt.json 与 changelog.md。

    KernelSU / Magisk 的更新接口只接受一个 zipUrl，这里固定给 arm64 包：
    x86 是模拟器，本来也不靠管理器更新。changelog 用 raw 链接，
    管理器会直接展示正文。
    """
    arm = [f for f in files if "arm64" in os.path.basename(f)]
    if not arm:
        print("没有 arm64 包，跳过 update.json")
        return
    name = os.path.basename(arm[0])
    url = f"https://gitee.com/{GITEE_REPO}/releases/download/v{version}/{name}"
    prop_ver, code = module_meta()
    if prop_ver != version:
        print(f"! module.prop 里是 {prop_ver}，命令行是 {version}，更新检查会按 {prop_ver} 比较")
    data = {
        "version": prop_ver,
        "versionCode": code,
        "zipUrl": url,
        "changelog": f"https://gitee.com/{GITEE_REPO}/raw/master/modules_update/changelog.md",
    }
    out = os.path.join(ROOT, "modules_update")
    if dry:
        print(f"[dry] 写 modules_update/AppOpt.json -> {prop_ver} ({code})")
        return
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "AppOpt.json"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    with open(os.path.join(out, "changelog.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(changelog_section(prop_ver).rstrip() + "\n")
    print(f"  已写 modules_update/AppOpt.json（{prop_ver} / {code}）")
    print("  记得把 modules_update/ 提交到 master，否则设备看到的最新版还是旧的")


def main() -> None:
    ap = argparse.ArgumentParser(description="双平台发包")
    ap.add_argument("version", help="形如 2.7.0-beta24，不带 v")
    ap.add_argument("--dry-run", action="store_true", help="只打印将要做什么")
    ap.add_argument("--only", choices=["github", "gitee"], help="只发一个平台")
    args = ap.parse_args()

    version = args.version.lstrip("v")
    files = packages(version)
    creds = credentials()
    print(f"版本 {version}，包 {len(files)} 个")
    for f in files:
        print(f"  {os.path.basename(f)}  {os.path.getsize(f) // 1024} KB")

    if args.only in (None, "github"):
        if "github" not in creds:
            sys.exit("没有 GitHub 令牌：设 GITHUB_TOKEN，或写进 ~/.git-credentials")
        print("GitHub:")
        print("  " + release_github(version, creds["github"], files, args.dry_run))
    if args.only in (None, "gitee"):
        if "gitee" not in creds:
            sys.exit("没有 Gitee 令牌：设 GITEE_TOKEN，或写进 ~/.git-credentials")
        print("Gitee:")
        print("  " + release_gitee(version, creds["gitee"], files, args.dry_run))
        # 只在 Gitee 发了（或双发）时写：zipUrl 指向 Gitee 的 Release 附件
        write_update_json(version, files, args.dry_run)


if __name__ == "__main__":
    main()
