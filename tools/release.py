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


def body_for(version: str) -> str:
    return (
        f"## {version}\n\n{changelog_section(version)}\n\n"
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
            json={"tag_name": tag, "name": tag, "body": body_for(version)},
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
                "name": f"AppOpt {version} 测试版",
                "body": body_for(version),
                "prerelease": "true",
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


if __name__ == "__main__":
    main()
