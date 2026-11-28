#!/usr/bin/env bash
#
# AppOptR 构建脚本
#
# 完成：工具链检查 → 编译 eBPF → 编译用户态 → 按架构组织模块目录 → 打包 ZIP
#
# 用法：
#   ./build.sh -a arm64        构建 arm64-v8a（默认，静态 musl，不需要 NDK）
#   ./build.sh -a x64          构建 x86_64
#   ./build.sh -a all          两个架构都构建
#   ./build.sh -a arm64 --skip-ebpf
#   ./build.sh                 构建当前主机架构（仅 Termux 等 Android 主机有意义）
#
# 说明：
#   - 产物输出到 dist/，不覆盖 modules_update/ 下的正式发布包。
#   - 构建目录 .build/、cargo 的 target/ 均不入库。
#   - 默认目标是 *-unknown-linux-musl（静态单体，无动态依赖）。Rust 的 musl
#     目标自带 crt 与 libc.a，链接器用随工具链分发的 rust-lld，因此不需要
#     NDK。之前默认的 *-linux-android 反而编不过：代码用了 SCHED_OTHER，
#     且 inotify_rm_watch 的 wd 在 bionic 下是 u32，与 Linux 签名不同。
#   - 需要 NDK 时可显式覆盖：APPOPT_ARM64_TRIPLE=aarch64-linux-android
#   - eBPF 目标 bpfel 与宿主架构无关，两个架构共用同一份 AppOpt-ebpf。
#   - 缺少工具链时脚本明确报错退出，不会伪造产物。

set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
DIST="$ROOT/dist"
WORK="$ROOT/.build"
EBPF_TRIPLE="bpfel-unknown-none"

ARCH="host"
SKIP_EBPF=0
OUT_DIR="$DIST"

say() { printf '%s\n' "$*"; }
die() {
	printf '错误: %s\n' "$*" >&2
	exit 1
}

usage() {
	sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
	case "$1" in
	-a | --arch)
		[ $# -ge 2 ] || die "-a 需要参数（arm64 / x64 / all / host）"
		ARCH="$2"
		shift 2
		;;
	-o | --out)
		[ $# -ge 2 ] || die "-o 需要目录参数"
		OUT_DIR="$2"
		shift 2
		;;
	--skip-ebpf)
		SKIP_EBPF=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		die "未知参数: $1（-h 查看用法）"
		;;
	esac
done

case "$ARCH" in
host | arm64 | x64 | all) ;;
*) die "无效架构: $ARCH（arm64 / x64 / all / host）" ;;
esac

# 当前主机对应的 ABI 目录名
host_abi() {
	case "$(uname -m)" in
	aarch64 | arm64) echo "arm64-v8a" ;;
	x86_64 | amd64) echo "x86_64" ;;
	*) die "不识别的主机架构: $(uname -m)" ;;
	esac
}

abi_of() {
	case "$1" in
	arm64) echo "arm64-v8a" ;;
	x64) echo "x86_64" ;;
	esac
}

triple_of() {
	case "$1" in
	arm64) echo "${APPOPT_ARM64_TRIPLE:-aarch64-unknown-linux-musl}" ;;
	x64) echo "${APPOPT_X64_TRIPLE:-x86_64-unknown-linux-musl}" ;;
	esac
}

# musl 静态链接的两个变量都必须显式给：
#   - linker 默认会去找主机 cc，链接阶段报「cannot find -lc」
#   - self-contained 让 rustc 用自带 crt 与 libc.a，而不是主机的 glibc
#
# 只能设目标专属的 `CARGO_TARGET_<TRIPLE>_RUSTFLAGS`。设全局 RUSTFLAGS 会把
# `-C link-self-contained` 一起传给 eBPF 编译，bpfel-unknown-none 不支持该
# 选项，构建会在「编译 eBPF」这一步直接失败——这个坑已经踩过一次
musl_linker_env() {
	local triple="$1" upper linker_var flags_var
	upper=$(printf '%s' "$triple" | tr 'a-z-' 'A-Z_')
	linker_var="CARGO_TARGET_${upper}_LINKER"
	flags_var="CARGO_TARGET_${upper}_RUSTFLAGS"
	if [ -z "${!linker_var:-}" ]; then
		export "${linker_var}=rust-lld"
	fi
	if [ -z "${!flags_var:-}" ]; then
		export "${flags_var}=-C link-self-contained=yes"
	fi
}

# ---------- 1. 基础工具 ----------
say "==> 检查构建工具"
for cmd in cargo rustc zip; do
	command -v "$cmd" >/dev/null 2>&1 || die "缺少 $cmd，请先安装"
done
say "    cargo: $(cargo --version)"
say "    rustc: $(rustc --version)"
say "    zip:   $(command -v zip)"

# Web 前端由 include_str! 在编译期嵌入，必须存在
[ -f "$ROOT/web/index.html" ] || die "缺少 web/index.html，用户态程序无法编译"
say "    web:   web/index.html ($(wc -c <"$ROOT/web/index.html") 字节)"

# ---------- 2. Rust 工具链 ----------
# 交叉构建需要目标架构的 std 与链接器，缺失时直接说明缺什么
check_target() {
	local arch="$1" triple
	triple=$(triple_of "$arch")
	if ! rustup target list --installed 2>/dev/null | grep -qx "$triple"; then
		die "缺少 Rust target $triple，请执行: rustup target add $triple"
	fi
	case "$triple" in
	*-musl)
		# 静态 musl：crt 与 libc.a 由 rust 自带，链接器用 rust-lld。
		# 用户显式设过 LINKER / RUSTFLAGS 时不覆盖
		musl_linker_env "$triple"
		;;
	*)
		# *-android 或其它目标走外部链接器，*_TRIPLE 可覆盖成 musl/gnu
		local linker_var
		linker_var="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER"
		if [ -z "${!linker_var:-}" ]; then
			if [ "$arch" = "arm64" ]; then
				command -v aarch64-linux-android-clang >/dev/null 2>&1 ||
					[ -n "${ANDROID_NDK_HOME:-}${NDK:-}" ] ||
					die "缺少 aarch64 交叉链接器（aarch64-linux-android-clang 或 ANDROID_NDK_HOME）"
			else
				command -v x86_64-linux-android-clang >/dev/null 2>&1 ||
					[ -n "${ANDROID_NDK_HOME:-}${NDK:-}" ] ||
					die "缺少 x86_64 交叉链接器（x86_64-linux-android-clang 或 ANDROID_NDK_HOME）"
			fi
		fi
		;;
	esac
}

# ---------- 3. eBPF 工具链 ----------
check_ebpf() {
	command -v bpf-linker >/dev/null 2>&1 ||
		die "缺少 bpf-linker，请执行: cargo install bpf-linker --locked"
	rustup toolchain list 2>/dev/null | grep -q '^nightly' ||
		die "缺少 nightly 工具链，请执行: rustup toolchain install nightly"
	rustup component list --toolchain nightly --installed 2>/dev/null | grep -q '^rust-src' ||
		die "nightly 缺少 rust-src，请执行: rustup component add rust-src --toolchain nightly"
}

build_ebpf() {
	# eBPF 目标只支持极少数 codegen 选项。全局 RUSTFLAGS 里的 linker 参数
	# （例如 `-C link-self-contained`）会让这一步直接报
	# "option ... is not supported on this target"，提前说出来省得排查
	if [ -n "${RUSTFLAGS:-}" ]; then
		say "    注意: 检测到全局 RUSTFLAGS，eBPF 目标可能不支持其中某些选项"
	fi
	say "==> 编译 eBPF 程序 ($EBPF_TRIPLE)"
	(
		cd "$ROOT/AppOpt-ebpf"
		cargo +nightly build --release --locked --target "$EBPF_TRIPLE" -Z build-std=core
	)
	EBPF_OBJ="$ROOT/AppOpt-ebpf/target/$EBPF_TRIPLE/release/AppOpt-ebpf"
	[ -f "$EBPF_OBJ" ] || die "eBPF 产物缺失: $EBPF_OBJ"
	say "    $(wc -c <"$EBPF_OBJ") 字节"
}

# ---------- 4. 用户态编译 ----------
build_userspace() {
	local arch="$1" triple="$2" out
	say "==> 编译用户态程序 ($arch)"
	if [ "$arch" = "host" ]; then
		cargo build --release --locked --manifest-path "$ROOT/AppOpt/Cargo.toml"
		out="$ROOT/AppOpt/target/release/AppOpt"
	else
		cargo build --release --locked --manifest-path "$ROOT/AppOpt/Cargo.toml" --target "$triple"
		out="$ROOT/AppOpt/target/$triple/release/AppOpt"
	fi
	[ -f "$out" ] || die "用户态产物缺失: $out"
	BIN_USR="$out"
	say "    $(wc -c <"$out") 字节"
}

# ---------- 5. 打包 ----------
package() {
	local abi="$1"
	# 第二参数只改包名后缀，不参与目录布局（host 调试包用 -dev 与正式包区分）
	local suffix="${2:-}"
	local stage zipname version
	stage="$WORK/module-$abi"
	version=$(sed -n 's/^version=//p' "$ROOT/module/module.prop" | head -1)
	[ -n "$version" ] || die "无法从 module/module.prop 读取 version"

	rm -rf "$stage"
	mkdir -p "$stage/bin/$abi" "$stage/webroot"
	# 模块脚本与配置保持原样，不做任何改写
	cp "$ROOT/module/module.prop" "$ROOT/module/applist.conf" \
		"$ROOT/module/applist.asoulopt.conf" \
		"$ROOT/module/customize.sh" "$ROOT/module/service.sh" \
		"$ROOT/module/daemon.sh" "$ROOT/module/hotinstall.sh" "$ROOT/module/action.sh" \
		"$stage/"
	# 脚本必须可执行：hotinstall.sh 由 KernelSU 热安装直接 exec，
	# action.sh 由管理器的「操作」按钮直接 exec，0644 会在设备上报 Permission denied
	chmod 0755 "$stage"/*.sh
	cp -r "$ROOT/module/META-INF" "$stage/"
	cp "$ROOT/web/index.html" "$stage/webroot/index.html"
	cp "$BIN_USR" "$stage/bin/$abi/AppOpt"
	if [ "$SKIP_EBPF" -eq 0 ]; then
		cp "$EBPF_OBJ" "$stage/bin/$abi/AppOpt-ebpf"
	fi
	chmod 0755 "$stage/bin/$abi/AppOpt"

	mkdir -p "$OUT_DIR"
	zipname="$OUT_DIR/AppOpt-$version-$abi$suffix.zip"
	rm -f "$zipname"
	(
		cd "$stage"
		zip -qr "$zipname" .
	)
	say "==> 模块包: $zipname"
	unzip -l "$zipname" | sed 's/^/    /'
}

# ---------- 执行 ----------
EBPF_OBJ=""
if [ "$SKIP_EBPF" -eq 0 ]; then
	check_ebpf
else
	say "==> 跳过 eBPF 编译（--skip-ebpf），模块包将不含 AppOpt-ebpf"
fi

case "$ARCH" in
host)
	# 默认构建只在「Rust 宿主就是 Android」时有意义（Termux）。
	# 普通 Linux/macOS 上 cargo build 出的是宿主 ELF，按 uname -m 塞进
	# android ABI 目录后刷进设备必然起不来：缺 bionic，解释器路径也不对。
	# 这里必须拦住，否则一个 ./build.sh 就能做出「看起来正常」的坏包
	HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
	HOST_SUFFIX=""
	case "$HOST_TRIPLE" in
	*android*) ;;
	*)
		if [ "${ALLOW_NON_ANDROID_HOST:-0}" != "1" ]; then
			die "默认构建的 Rust host 是 $HOST_TRIPLE（非 Android），产物无法在设备上运行。
       请改用交叉编译：./build.sh -a arm64 ｜ -a x64 ｜ -a all
       只做本地逻辑验证时，设 ALLOW_NON_ANDROID_HOST=1，产物名会带 -dev 后缀"
		fi
		say "    警告: host 为 $HOST_TRIPLE，产物仅供本地调试，不可发布"
		HOST_SUFFIX="-dev"
		;;
	esac
	BIN_USR=""
	build_userspace "host" ""
	if [ "$SKIP_EBPF" -eq 0 ]; then
		build_ebpf
	fi
	package "$(host_abi)" "$HOST_SUFFIX"
	;;
arm64 | x64)
	check_target "$ARCH"
	BIN_USR=""
	build_userspace "$ARCH" "$(triple_of "$ARCH")"
	if [ "$SKIP_EBPF" -eq 0 ]; then
		build_ebpf
	fi
	package "$(abi_of "$ARCH")"
	;;
all)
	# 两个架构共用一次 eBPF 编译
	if [ "$SKIP_EBPF" -eq 0 ]; then
		build_ebpf
	fi
	check_target arm64
	check_target x64
	BIN_USR=""
	build_userspace "arm64" "$(triple_of arm64)"
	package "$(abi_of arm64)"
	build_userspace "x64" "$(triple_of x64)"
	package "$(abi_of x64)"
	;;
esac

say "完成。"
