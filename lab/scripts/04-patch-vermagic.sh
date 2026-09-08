#!/usr/bin/env bash
# Retarget the vendor .ko files at our lab kernel.
#
# The Samsung modules declare:
#   vermagic=9518079, release SMP preempt mod_unload ARMv7 p2v8
# our kernel declares:
#   vermagic=4.1.10 SMP preempt mod_unload ARMv7 p2v8
#
# Note what is IDENTICAL: "SMP preempt mod_unload ARMv7 p2v8". Those tokens are
# the ABI-relevant ones (spinlock size, preemption model, module unload
# support, CPU arch, phys/virt patching) and the lab kernel was configured to
# match them exactly. Only the release token differs -- Samsung stuffed a build
# number where the version normally goes. So this patch is a rename, not a
# compatibility lie: we are not forcing a module built for a different ABI.
#
# CONFIG_MODVERSIONS is off in the lab kernel, so there are no symbol CRCs to
# fight; the loader checks vermagic and then resolves symbols by name.
#
# Our replacement is SHORTER than the original, so it is patched in place and
# NUL-padded. .modinfo is a run of NUL-terminated key=value strings, and the
# extra NULs simply read back as empty entries.
set -euo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
SRC_DIR=${1:-$LAB/fw/modules}
OUT_DIR=${2:-$LAB/build/modules}

OLD='vermagic=9518079, release SMP preempt mod_unload ARMv7 p2v8 '
NEW='vermagic=4.1.10 SMP preempt mod_unload ARMv7 p2v8 '

mkdir -p "$OUT_DIR"

python3 - "$SRC_DIR" "$OUT_DIR" "$OLD" "$NEW" <<'PY'
import os, sys, pathlib

src_dir, out_dir, old, new = sys.argv[1:5]
old_b, new_b = old.encode(), new.encode()
if len(new_b) > len(old_b):
    sys.exit("replacement longer than original; in-place patch impossible")
pad = b"\x00" * (len(old_b) - len(new_b))

wanted = {
    "exfat_core.ko", "exfat_fs.ko",      # lead-004
    "szdrv.ko", "szdrv_core.ko",         # lead-005
    "ext4.ko", "jbd2.ko", "mbcache.ko",  # lead-006
}

patched = skipped = 0
for p in sorted(pathlib.Path(src_dir).rglob("*.ko")):
    if p.name not in wanted:
        continue
    data = p.read_bytes()
    n = data.count(old_b)
    if n == 0:
        print(f"  SKIP  {p.name}: vermagic string not found")
        skipped += 1
        continue
    data = data.replace(old_b, new_b + pad)
    out = pathlib.Path(out_dir) / p.name
    out.write_bytes(data)
    print(f"  ok    {p.name:16s} ({n} occurrence, {len(data)} bytes)")
    patched += 1

print(f"\npatched {patched}, skipped {skipped} -> {out_dir}")
PY

echo
echo "=== verify ==="
for f in "$OUT_DIR"/*.ko; do
  printf "  %-16s %s\n" "$(basename "$f")" "$(strings -a "$f" | grep -a '^vermagic=' || echo MISSING)"
done
