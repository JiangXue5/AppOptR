#!/system/bin/sh
#
# 管理器模块页的「操作」按钮。
#
# 模块更新后，如果这次安装没走热安装（老版本 KernelSU、APatch、Magisk），
# 点一下这里就能把守护进程换成磁盘上的新二进制，同样不用重启设备。
# 输出会显示在管理器的操作结果里。

MODDIR=${0%/*}
# 被 exec 时 $0 是脚本绝对路径；万一从当前目录用相对名调用，退回 PWD
[ -d "$MODDIR" ] || MODDIR=.
cd "$MODDIR" || exit 1
. "${MODDIR}/daemon.sh"

echo "AppOpt：重启守护进程"
if ! daemon_stop; then
	echo "旧进程未能退出，仍尝试启动（可能被单实例锁挡掉）"
fi
if daemon_start; then
	echo "已启动：$(daemon_version)，pid $(cat "$PIDFILE")"
	echo "面板：http://127.0.0.1:8889"
else
	echo "启动失败，详见 ${LOG_FILE}"
	exit 1
fi
