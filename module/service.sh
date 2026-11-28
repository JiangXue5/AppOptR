wait_sys_boot_completed() {
	local i=9
	until [ "$(getprop sys.boot_completed)" == "1" ] || [ $i -le 0 ]; do
		i=$((i-1))
		sleep 9
	done
}
wait_sys_boot_completed
MODDIR=${0%/*}
cd "$MODDIR" || exit 0

# 启停逻辑与 hotinstall.sh / action.sh 共用一份：权限兜底、日志轮转、
# 单实例判断都在 daemon.sh 里，避免三处各写一套后走样
. "${MODDIR}/daemon.sh"

# 已经在跑就别再起一个。AppOpt 自带 flock 单实例锁，第二个进程会静默退出，
# 但先判断一次能少一条「已有实例」的误导日志（热安装刚跑过时会走到这里）
if daemon_running; then
	echo "[$(date '+%F %T')] 守护进程已在运行（pid $(cat "$PIDFILE" 2>/dev/null)），跳过启动" >>"$LOG_FILE"
else
	daemon_start || echo "[$(date '+%F %T')] 启动失败，详见 appopt.log" >>"$LOG_FILE"
fi

# core_ctl：部分内核在低负载时会把整个簇下电，绑在该簇上的线程随之被挤走。
# 把 min_cpus 拉到 max_cpus 能让核心常在线，代价是待机功耗与发热上升，
# 所以默认不动。确需开启时在模块目录建一个空的 keep_cores 文件：
#   touch /data/adb/modules/AppOpt/keep_cores
# 首次启用会把每个簇的 min_cpus 原值记进 core_ctl.bak；删掉 keep_cores 后
# 下次启动按记录恢复。直接卸载模块时服务脚本不会再执行，重启由内核恢复默认值。
CORE_CTL_BAK=${MODDIR}/core_ctl.bak
if [ -f "${MODDIR}/keep_cores" ]; then
	[ -f "$CORE_CTL_BAK" ] || : > "$CORE_CTL_BAK"
	for MAX_CPUS in /sys/devices/system/cpu/cpu*/core_ctl/max_cpus; do
		[ -e "$MAX_CPUS" ] || continue
		MIN_CPUS=${MAX_CPUS%/*}/min_cpus
		[ -e "$MIN_CPUS" ] || continue
		MAX=$(cat "$MAX_CPUS" 2>/dev/null)
		MIN=$(cat "$MIN_CPUS" 2>/dev/null)
		[ -n "$MAX" ] && [ -n "$MIN" ] || continue
		# 只记第一次看到的原值：重复启动时 min 可能已经是上次写入的 max
		grep -q "^${MIN_CPUS} " "$CORE_CTL_BAK" 2>/dev/null || echo "${MIN_CPUS} ${MIN}" >> "$CORE_CTL_BAK"
		[ "$MIN" = "$MAX" ] && continue
		chmod u+w "$MIN_CPUS" 2>/dev/null
		echo "$MAX" > "$MIN_CPUS" 2>/dev/null
		chmod u-w "$MIN_CPUS" 2>/dev/null
	done
elif [ -f "$CORE_CTL_BAK" ]; then
	while read -r MIN_CPUS MIN; do
		[ -e "$MIN_CPUS" ] && [ -n "$MIN" ] || continue
		chmod u+w "$MIN_CPUS" 2>/dev/null
		echo "$MIN" > "$MIN_CPUS" 2>/dev/null
		chmod u-w "$MIN_CPUS" 2>/dev/null
	done < "$CORE_CTL_BAK"
	rm -f "$CORE_CTL_BAK"
fi

# 如需暂停绿厂 oiface，删掉下面一行的 #；恢复则把 0 改成 1
# [ -n "$(getprop persist.sys.oiface.enable)" ] && setprop persist.sys.oiface.enable 0

# 如需禁用米系机型 joyose，删掉下面 pm 命令前的 #
# pm disable-user com.xiaomi.joyose; pm clear com.xiaomi.joyose
