#!/usr/bin/env bash
# Round-2 num_ext sweep. Runs every case in parallel (08-run.sh is lane-safe
# via LANE=) and classifies the outcome.
#   sweep.sh OP TAG NUM_EXT...        e.g. sweep.sh readdir p 3 17 18 20
set -u
. /var/tmp/samsung-lab/lanes/exfat/r2/env.sh
OP=${1:?op}; TAG=${2:?tag}; shift 2
cd "$LAB"

pids=()
for N in "$@"; do
  IMG="$R2/img/${TAG}${N}.img"
  LOG="$R2/logs/${OP}-${TAG}${N}.log"
  ( LANE=x${OP}${TAG}${N} TIMEOUT=${TIMEOUT:-75} \
      "$LAB/scripts/08-run.sh" "$IMG" exfat exfat_core,exfat_fs "$OP" > "$LOG" 2>&1 ) &
  pids+=($!)
done
wait "${pids[@]}" 2>/dev/null

for N in "$@"; do
  LOG="$R2/logs/${OP}-${TAG}${N}.log"
  # NB: classify on the guest transcript only. 08-run.sh's own verdict line
  # contains the literal string "LAB: done" even when the run failed.
  GUEST=$(sed -n '/^LAB: fs=/,/^=== verdict/p' "$LOG")
  if grep -aqE "Unable to handle|Internal error|Oops|Kernel panic" "$LOG"; then V="OOPS"
  elif printf '%s' "$GUEST" | grep -aq '^LAB: done'; then
      if grep -aq "Filesystem is corrupted" "$LOG"; then V="clean(post-copy reject)"
      else V="clean(listed)"; fi
  elif grep -aq "rcu_preempt detected stalls" "$LOG"; then V="HANG(rcu stall)"
  else V="HANG/timeout"; fi
  PC=$(grep -aoE "pc : \[<[0-9a-f]+>\]" "$LOG" | head -1)
  LR=$(grep -aoE "lr : \[<[0-9a-f]+>\]" "$LOG" | head -1)
  printf "  %-8s num_ext=%-4s %-24s %s %s\n" "$OP" "$N" "$V" "$PC" "$LR"
done
# keep the box tidy: the initramfs staging dirs are 75 MB each
for N in "$@"; do rm -rf "$LAB/build/ird-x${OP}${TAG}${N}"; done
