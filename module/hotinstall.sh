#!/system/bin/sh
#
# KernelSU 热安装后的回调（customize.sh 里设 MODULE_HOT_RUN_SCRIPT=hotinstall.sh）。
#
# 为什么需要它：热安装只替换模块目录里的文件，模块脚本（service.sh）不会重跑，
# 内存里跑的还是旧二进制——不重启设备就一直是旧版本。这里把守护进程换掉。
#
# 失败不影响安装结果，最坏情况退回「重启设备后生效」。

MODDIR=${0%/*}
# 被 exec 时 $0 是脚本绝对路径；万一从当前目录用相对名调用，退回 PWD
[ -d "$MODDIR" ] || MODDIR=.
cd "$MODDIR" || exit 1
. "${MODDIR}/daemon.sh"

OLD_PID="$(daemon_pids | head -1)"
if [ -z "$OLD_PID" ]; then
	echo "[hotinstall] 没有在跑的旧进程，直接启动"
elif daemon_stop; then
	echo "[hotinstall] 已停止旧进程（pid $OLD_PID）"
else
	echo "[hotinstall] 旧进程（pid $OLD_PID）未能退出，新进程可能被单实例锁挡掉"
fi

if daemon_start; then
	echo "[hotinstall] 已切换到 $(daemon_version)（pid $(cat "$PIDFILE")），无需重启设备"
else
	echo "[hotinstall] 新进程启动失败，详见 ${LOG_FILE}；重启设备后仍会按新版本启动"
	exit 1
fi
