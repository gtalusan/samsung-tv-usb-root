#!/usr/bin/env bash
# lanes/ntfs: parallel mutation campaign against the shipped szdrv NTFS engine.
#
#   campaign.sh NAME SEED_START COUNT MODE [OP] [PAR]
#
# Everything lives in /dev/shm (the box's zpool is at 0 bytes free).
# Uses the shared vendor kernel + shipped szdrv_core.ko/szdrv.ko unchanged.
set -uo pipefail
export TMPDIR=${TMPDIR:-/dev/shm}
PY=${PY:-python3}

W=/dev/shm/ntfslane
NAME=${1:?name}
S0=${2:?seed start}
N=${3:?count}
MODE=${4:-mix}
OP=${5:-readdir}
PAR=${6:-10}
SEED_IMG=${SEED_IMG:-$W/img/small.img}

RES=$W/res-$NAME
mkdir -p "$RES/crash" "$RES/logs"
: > "$RES/verdicts.txt"

run_one() {
  local seed=$1
  local img=/dev/shm/ntfslane/tmp-$NAME-$seed.img
  local log=/dev/shm/ntfslane/tmp-$NAME-$seed.log
  local desc
  desc=$($PY $W/tools/mutate.py "$SEED_IMG" "$img" "$seed" "$MODE" 2>&1) || {
    echo "$seed MUTFAIL $desc" >> "$RES/verdicts.txt"; rm -f "$img"; return; }
  local v
  v=$(TIMEOUT=${TIMEOUT:-40} /var/tmp/samsung-lab/lanes/ntfs/scripts/fuzzrun.sh "$img" "$log" "$OP")
  echo "$seed $v $desc" >> "$RES/verdicts.txt"
  if [ "$v" != "OK" ] && [ "$v" != "REJECT" ]; then
    cp "$img" "$RES/crash/$seed.img"
    cp "$log" "$RES/logs/$seed.log"
  fi
  rm -f "$img" "$log"
}
export -f run_one
export RES NAME MODE OP PY W SEED_IMG

seq "$S0" $((S0 + N - 1)) | xargs -P "$PAR" -I{} bash -c 'run_one {}'
echo "=== $NAME: $(wc -l < "$RES/verdicts.txt") runs ==="
awk '{print $2}' "$RES/verdicts.txt" | sort | uniq -c | sort -rn
