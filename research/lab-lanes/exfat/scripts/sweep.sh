#!/usr/bin/env bash
# Sweep num_ext across benign / boundary / overflow, for one OP.
# Runs all cases in PARALLEL (08-run.sh is lane-safe via LANE=).
# Usage: sweep.sh OP NUM_EXT...
set -u
LAB=/var/tmp/samsung-lab
LANE_DIR=$LAB/lanes/exfat
OP=${1:?op}; shift

cd "$LAB"

# 1. craft every image first (outside any run)
for NE in "$@"; do
  IMG="$LANE_DIR/img/ne${NE}.img"
  [ -f "$IMG" ] || nix develop --command python3 "$LANE_DIR/scripts/mkcase.py" \
      "$IMG" "$NE" >/dev/null 2>&1
done

# 2. fire them all off concurrently
pids=()
for NE in "$@"; do
  IMG="$LANE_DIR/img/ne${NE}.img"
  LOG="$LANE_DIR/logs/${OP}-ne${NE}.log"
  (
    LANE=exfat_${OP}_${NE} TIMEOUT=60 \
      "$LAB/scripts/08-run.sh" "$IMG" exfat exfat_core,exfat_fs "$OP" \
      > "$LOG" 2>&1
  ) &
  pids+=($!)
done
wait "${pids[@]}" 2>/dev/null

# 3. classify
for NE in "$@"; do
  LOG="$LANE_DIR/logs/${OP}-ne${NE}.log"
  if grep -aqE "Unable to handle|Internal error|Oops|Kernel panic" "$LOG"; then
      V="CRASH"
  elif grep -aq "LAB: done" "$LOG"; then
      if grep -aq "Filesystem is corrupted" "$LOG"; then
          V="clean(entry rejected)"
      else
          V="clean(entry listed)"
      fi
  else
      V="HANG/timeout"
  fi
  PC=$(grep -aoE "pc : \[<[0-9a-f]+>\]" "$LOG" | head -1)
  NAME=$(grep -aoE "^-rw[^ ]* +[0-9]+ +[0-9]+ +[0-9]+ +[0-9]+ .*" "$LOG" | head -1 | awk '{print $NF}')
  printf "  num_ext=%-4s %-22s %s %s\n" "$NE" "$V" "$PC" "${NAME:-}"
done
