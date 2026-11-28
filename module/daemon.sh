#!/system/bin/sh
#
# 守护进程的启停。三个入口共用，判断只写一遍：
#   service.sh     开机 late_start 阶段
#   hotinstall.sh  KernelSU 热安装后（模块文件已换，service.sh 不会再执行）
#   action.sh      管理器「操作」按钮，手动重启
#
# 调用方自己设好 MODDIR（模块根目录）再 source 本文件；本文件只定义函数，
# 不产生任何副作用。

DAEMON=AppOpt
PIDFILE="$MODDIR/appopt.pid"
LOG_FILE="$MODDIR/appopt.log"
LOG_MAX_KB=1024

# 按进程名找 pid。不用 pidof：APatch 与各版本 Magisk 自带 busybox 的实现不一，
# 有的只认完整路径；/proc/*/comm 在 Android 4.4 之后都能读。
# comm 上限 15 字符，AppOpt 只有 6 个，不会被截断（AppOpt-ebpf 是另一个名字，
# 不会误伤）
daemon_pids() {
	for _d in /proc/[0-9]*; do
		[ -r "$_d/comm" ] || continue
		[ "$(cat "$_d/comm" 2>/dev/null)" = "$DAEMON" ] || continue
		printf '%s\n' "${_d#/proc/}"
	done
}

daemon_running() {
	[ -n "$(daemon_pids)" ]
}

# sleep 0.1 在 toybox 与常见 busybox 上都支持，但极老的 busybox 编译时关了
# 小数支持，会直接报错。那种情况下退化成 1 秒，等待总时长仍然有上限
_nap() {
	sleep 0.1 2>/dev/null || sleep 1
}

# 停旧进程，必须等到它真的消失再返回。
# AppOpt 用 flock 做单实例锁：旧进程没退干净时，新进程拿到 EWOULDBLOCK 会
# 静默 exit(0)，日志里只留一行「已有实例」——现象就是「更新完还是旧版本」
daemon_stop() {
	if ! daemon_running; then
		rm -f "$PIDFILE"
		return 0
	fi
	for _p in $(daemon_pids); do
		kill "$_p" 2>/dev/null
	done
	_i=0
	while [ "$_i" -lt 30 ] && daemon_running; do
		_i=$((_i + 1))
		_nap
	done
	if daemon_running; then
		# 卡在不可中断的 syscall 上时 TERM 不生效，只能 KILL。
		# 代价是这期间绑好的线程保持现状，下一次扫描会重新套规则
		for _p in $(daemon_pids); do
			kill -9 "$_p" 2>/dev/null
		done
		_i=0
		while [ "$_i" -lt 20 ] && daemon_running; do
			_i=$((_i + 1))
			_nap
		done
	fi
	rm -f "$PIDFILE"
	! daemon_running
}

# 起新进程。返回非零表示没起来，调用方不要谎报成功
daemon_start() {
	# 日志按大小轮转：模块目录在 /data，长时间运行不轮转会把分区写满
	if [ -f "$LOG_FILE" ] && [ "$(wc -c <"$LOG_FILE" 2>/dev/null || echo 0)" -gt $((LOG_MAX_KB * 1024)) ]; then
		mv -f "$LOG_FILE" "$LOG_FILE.1"
	fi
	# 旧版安装脚本把主程序权限压成 0644，升级上来的设备不会重跑 customize.sh
	# 的恢复逻辑，这里兜一次；失败不阻塞，真正原因会在日志里是 Permission denied
	[ -x "$MODDIR/$DAEMON" ] || chmod 0755 "$MODDIR/$DAEMON" 2>/dev/null
	cd "$MODDIR" || return 1
	nohup "./$DAEMON" -w >>"$LOG_FILE" 2>&1 &
	echo $! >"$PIDFILE"
	# 起来就退出（端口被占、配置损坏、单实例锁没放）不能当成成功
	_nap
	_nap
	_nap
	kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null || {
		rm -f "$PIDFILE"
		return 1
	}
	return 0
}

# 版本号从 module.prop 读，不去执行二进制：-v 会先做 eBPF 探测，
# 在刚重启的机器上可能白等几秒
daemon_version() {
	sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1
}
