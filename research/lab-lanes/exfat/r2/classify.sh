#!/usr/bin/env bash
# Re-classify already-captured sweep logs without re-running QEMU.
#   classify.sh LOG...
set -u
for LOG in "$@"; do
  GUEST=$(sed -n '/^LAB: fs=/,/^=== verdict/p' "$LOG")
  if grep -aqE "Unable to handle|Internal error|Oops|Kernel panic" "$LOG"; then V="OOPS"
  elif printf '%s' "$GUEST" | grep -aq '^LAB: done'; then
      if grep -aq "Filesystem is corrupted" "$LOG"; then V="clean(post-copy reject)"
      else V="clean(listed)"; fi
  elif grep -aq "rcu_preempt detected stalls" "$LOG"; then V="HANG(rcu stall)"
  else V="HANG/timeout"; fi
  PC=$(grep -aoE "pc : \[<[0-9a-f]+>\]" "$LOG" | head -1)
  printf "  %-34s %-24s %s\n" "$(basename "$LOG")" "$V" "$PC"
done
