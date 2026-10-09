#!/bin/ash
set -eu
work=$1; owner=$2; boot=$3; expected=$4; shift 4
pid=; child_start=; child_rc=; watchdog=; watcher_start=; watcher_exe=; ending=0
guard() {
 [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ] &&
 [ -d "$work" ] && [ ! -L "$work" ] && [ ! -L "$work/owner.txt" ] &&
 [ "$(cat "$work/owner.txt")" = "$owner" ]
}
same_process() {
 p=$1; started=$2; executable=$3
 [ "$p" -gt 1 ] && [ -n "$started" ] &&
 [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ] &&
 [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$executable" ] &&
 [ "$(awk '{print $22}' /proc/$p/stat 2>/dev/null)" = "$started" ]
}
owned_scan() {
 guard || return 1
 for f in /proc/[0-9]*/exe; do
  executable=$(readlink "$f" 2>/dev/null) || continue
  case "$executable" in
   "$work/current-harness"|"$work/minimal-cli")
    p=$(printf '%s\n' "$f" | cut -d/ -f3)
    [ "$p" -gt 1 ] || return 1
    started=$(awk '{print $22}' /proc/$p/stat 2>/dev/null) || continue
    printf '%s %s %s\n' "$p" "$started" "$executable";;
   "$work"/*) echo ERROR_unexpected_owned_executable >&2; return 1;;
  esac
 done
}
finish() {
 rc=$?; [ "$ending" = 0 ] || exit "$rc"; ending=1; trap - EXIT HUP INT TERM; set +e
 safe=1; guard || safe=0
 if [ "$safe" = 1 ]; then
  owned_scan > "$work/cleanup-targets.txt" || safe=0
  if [ -s "$work/cleanup-targets.txt" ] && [ "$child_rc" = 0 ]; then
   echo ERROR_owned_process_survived_harness; rc=1
  fi
  if [ "$safe" = 1 ]; then
   while read -r p started executable; do
    guard && same_process "$p" "$started" "$executable" || { echo ERROR_cleanup_identity; safe=0; continue; }
    echo "OWNED_TERM $p $started $executable"
    kill -TERM "$p" || { echo ERROR_cleanup_signal; safe=0; }
   done < "$work/cleanup-targets.txt"
   i=0
   while [ "$i" -lt 5 ]; do
    owned_scan > "$work/remaining-pids.txt" || { safe=0; break; }
    [ -s "$work/remaining-pids.txt" ] || break
    sleep 1; i=$((i+1))
   done
   [ ! -s "$work/remaining-pids.txt" ] || { echo ERROR_cleanup_owned_alive; safe=0; }
  fi
 fi
 if [ -n "$pid" ] && [ -z "$child_rc" ]; then
  if [ -e /proc/$pid ]; then
   echo ERROR_unreaped_live_child; safe=0; rc=1
  else wait "$pid"; child_rc=$?; fi
 fi
 [ -z "$child_rc" ] || echo "HARNESS_EXIT $child_rc"
 [ "$child_rc" = 0 ] || rc=1
 if [ -n "$watchdog" ]; then
  if [ -e /proc/$watchdog ]; then
   if guard && same_process "$watchdog" "$watcher_start" "$watcher_exe"; then
    kill -TERM "$watchdog" 2>/dev/null || rc=1
   else echo ERROR_watchdog_identity; rc=1; fi
  fi
  wait "$watchdog" 2>/dev/null
 fi
 exec 3>&- 3<&-
 [ ! -f "$work/harness.log" ] || { echo HARNESS_LOG_BEGIN; cat "$work/harness.log"; echo HARNESS_LOG_END; }
 [ ! -f "$work/monitor.log" ] || { echo MONITOR_LOG_BEGIN; cat "$work/monitor.log"; echo MONITOR_LOG_END; }
 if [ "$safe" = 1 ] && guard; then echo OWNED_PROCESSES_ZERO; echo CLEANUP_VERIFIED; else echo CLEANUP_UNVERIFIED; rc=1; fi
 echo "FINAL $rc"; exit "$rc"
}
guard
trap finish EXIT; trap 'echo WATCHDOG_OR_SIGNAL_ABORT; exit 124' HUP INT TERM
[ "$(sha256sum "$work/current-harness" | awk '{print $1}')" = "$expected" ]
[ "$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)" -ge 32768 ] || { echo ERROR_prestart_memory; exit 1; }
[ ! -e "$work/watchdog.fifo" ] && [ ! -e "$work/identity.txt" ]
mkfifo "$work/watchdog.fifo"; exec 3<>"$work/watchdog.fifo"
parent_pid=$$; parent_exe=$(readlink /proc/$$/exe); parent_start=$(awk '{print $22}' /proc/$$/stat)
# The watchdog's builtin read timeout leaves no external sleep process behind.
/bin/ash -c '
 signal_parent() {
  [ "$(cat /proc/sys/kernel/random/boot_id)" = "$1" ] && [ "$2" -gt 1 ] &&
  [ "$(readlink /proc/$2/exe 2>/dev/null)" = "$4" ] &&
  [ "$(awk '\''{print $22}'\'' /proc/$2/stat 2>/dev/null)" = "$3" ] &&
  [ "$(cat "$5/owner.txt")" = "$6" ] || return 1
  kill -TERM "$2"
 }
 i=0
 while [ "$i" -lt 80 ]; do
  read -r -t 1 stop <&3 && exit 0
  [ "$(cat /proc/sys/kernel/random/boot_id)" = "$1" ] &&
  [ "$2" -gt 1 ] && [ "$(readlink /proc/$2/exe)" = "$4" ] &&
  [ "$(awk '\''{print $22}'\'' /proc/$2/stat)" = "$3" ] &&
  [ "$(cat "$5/owner.txt")" = "$6" ] || exit 1
  available=$(awk '\''/^MemAvailable:/ {print $2}'\'' /proc/meminfo)
  printf "MEMAVAILABLE %s\n" "$available"
  if [ "$available" -lt 16384 ]; then echo ERROR_monitor_memory; signal_parent "$@"; exit 1; fi
  if [ -f "$5/identity.txt" ]; then
   p=$(awk '\''{print $1}'\'' "$5/identity.txt"); started=$(awk '\''{print $2}'\'' "$5/identity.txt")
   if [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$5/current-harness" ] &&
      [ "$(awk '\''{print $22}'\'' /proc/$p/stat 2>/dev/null)" = "$started" ]; then
    awk '\''/^VmRSS:/ {print "RSS " $2} /^VmHWM:/ {print "HWM " $2}'\'' /proc/$p/status 2>/dev/null || true
   fi
  fi
  i=$((i+1))
 done
 echo ERROR_harness_timeout; signal_parent "$@"; exit 1
' watchdog "$boot" "$parent_pid" "$parent_start" "$parent_exe" "$work" "$owner" > "$work/monitor.log" 2>&1 & watchdog=$!
watcher_start=$(awk '{print $22}' /proc/$watchdog/stat); watcher_exe=$(readlink /proc/$watchdog/exe)
# The child's self-recorded start time survives even an immediately passing test.
/bin/ash -c '
 work=$1; shift
 printf "%s %s\n" "$$" "$(awk '\''{print $22}'\'' /proc/$$/stat)" > "$work/identity.txt"
 cd "$work"
 exec env TMPDIR="$work/tmp" MOSDNS_RS_TEST_BIN="$work/minimal-cli" MOSDNS_TEST_BINARY="$work/minimal-cli" RUST_TEST_THREADS=1 ./current-harness "$@"
' child "$work" "$@" > "$work/harness.log" 2>&1 3>&- & pid=$!
set +e
wait "$pid"; child_rc=$?
set -e
guard
[ -f "$work/identity.txt" ]
read -r recorded_pid child_start < "$work/identity.txt"
[ "$recorded_pid" = "$pid" ] && [ "$pid" -gt 1 ] && [ "$child_start" -gt 0 ]
echo "HARNESS_IDENTITY $pid $child_start $work/current-harness"
exit "$child_rc"
