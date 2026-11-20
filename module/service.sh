wait_sys_boot_completed() {
	local i=9
	until [ "$(getprop sys.boot_completed)" == "1" ] || [ $i -le 0 ]; do
		i=$((i-1))
		sleep 9
	done
}
wait_sys_boot_completed
MODDIR=${0%/*}
cd $MODDIR

# 日志写入模块目录，超过 1 MiB 时启动前轮转一次，避免无限增长
LOG_FILE=${MODDIR}/appopt.log
LOG_MAX_KB=1024
if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE")" -gt $((LOG_MAX_KB * 1024)) ]; then
	mv -f "$LOG_FILE" "${LOG_FILE}.1"
fi
nohup ${MODDIR}/AppOpt -w >>"$LOG_FILE" 2>&1 &

for MAX_CPUS in /sys/devices/system/cpu/cpu*/core_ctl/max_cpus; do
	if [ -e "$MAX_CPUS" ] && [ "$(cat $MAX_CPUS)" != "$(cat ${MAX_CPUS%/*}/min_cpus)" ]; then
		chmod a+w "${MAX_CPUS%/*}/min_cpus"
		echo "$(cat $MAX_CPUS)" > "${MAX_CPUS%/*}/min_cpus"
		chmod a-w "${MAX_CPUS%/*}/min_cpus"
	fi
done

# 如需暂停绿厂oiface请将下面29行的#号注释删掉，恢复则将0改成1
# [ -n "$(getprop persist.sys.oiface.enable)" ] && setprop persist.sys.oiface.enable 0

# 如需禁用米系机型joyose请将下面32行pm命令前的#号删掉
# pm disable-user com.xiaomi.joyose; pm clear com.xiaomi.joyose
