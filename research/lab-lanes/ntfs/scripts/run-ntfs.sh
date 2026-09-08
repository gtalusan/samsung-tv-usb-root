#!/usr/bin/env bash
# lanes/ntfs runner. Mirrors scripts/08-run.sh exactly (same vendor kernel, same
# QEMU line, same init logic) with two lane-local changes:
#
#   1. It builds its initramfs in lanes/ntfs/build/ird instead of the shared
#      build/ird, and writes its cpio to lanes/ntfs/build/ird.cpio.gz. That
#      removes this lane from the shared-state contention entirely -- no other
#      lane's run can clobber ours mid-flight and vice versa.
#   2. It additionally stages lanes/ntfs/shim/ntfsshim.ko, which supplies the
#      two symbols (__sdp_dma_virt_to_phys, mem_section) that szdrv_core.ko
#      needs and that the lab kernel does not export. See shim/ntfsshim.c for
#      the full justification and the fidelity caveat.
#
# The Samsung modules themselves are still copied byte-for-byte from
# fw/modules/ -- unmodified, exactly as 08-run.sh does it.
#
#   ./run-ntfs.sh IMAGE [FS] [MODS] [OP]
#   GDB=1 halts with a gdbstub on :1234 ; TIMEOUT=n guards the run.
set -euo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
LANE=$LAB/lanes/ntfs
IMG=${1:?usage: run-ntfs.sh IMAGE [FS] [MODS] [OP]}
FS=${2:-szdrv}
MODS=${3:-ntfsshim,szdrv_core,szdrv}
OP=${4:-readdir}
TIMEOUT=${TIMEOUT:-90}

KSRC=$LAB/vendor/linux-4.1.10
ZIMAGE=$KSRC/arch/arm/boot/zImage
IRD=$LANE/build/ird
OUT=$LANE/logs/$(basename "$IMG").log

[ -f "$ZIMAGE" ] || { echo "no vendor zImage"; exit 1; }
[ -f "$IMG" ]    || { echo "no such image: $IMG"; exit 1; }
mkdir -p "$LANE/logs" "$LANE/build"

rm -rf "$IRD"; mkdir -p "$IRD"/{bin,dev,proc,sys,mnt,lib/modules}
cp "$LAB/build/busybox-armhf" "$IRD/bin/busybox"
chmod +x "$IRD/bin/busybox"
for a in sh mount umount ls cat dmesg insmod lsmod poweroff sleep echo losetup dd hexdump; do
  ln -sf busybox "$IRD/bin/$a"
done
# UNPATCHED vendor modules, exactly as extracted from the firmware
find "$LAB/fw/modules" -name '*.ko' -exec cp {} "$IRD/lib/modules/" \; 2>/dev/null || true
# lane-local shim (NOT a Samsung binary; see shim/ntfsshim.c)
cp "$LANE/shim/ntfsshim.ko" "$IRD/lib/modules/" 2>/dev/null || true
cp "$IMG" "$IRD/test.img"
mknod -m 600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$IRD/dev/null" c 1 3 2>/dev/null || true

cat > "$IRD/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null

get_arg() { for a in $(cat /proc/cmdline); do case "$a" in "$1"=*) echo "${a#*=}"; return;; esac; done; }
FS=$(get_arg lab.fs);   [ -n "$FS" ] || FS=szdrv
MODS=$(get_arg lab.mods)
OP=$(get_arg lab.op);   [ -n "$OP" ] || OP=readdir

echo "LAB: fs=$FS op=$OP mods=$MODS"
IFS=,
for m in $MODS; do
  insmod /lib/modules/"$m".ko && echo "LAB: insmod $m ok" || echo "LAB: insmod $m FAILED"
done
unset IFS
echo "LAB: modbase ---"; cat /proc/modules; echo "LAB: modbase end"

echo "LAB: mounting /test.img as $FS (loop)"
mount -t "$FS" -o ro,loop /test.img /mnt && echo "LAB: mount OK" || echo "LAB: mount FAILED"

case "$OP" in
  readdir) echo "LAB: readdir ---"; ls -la /mnt 2>&1 | head -40; echo "LAB: readdir done";;
  stat)    echo "LAB: stat ---"; for f in /mnt/*; do ls -l "$f" 2>&1 | head -2; done;;
esac

echo "LAB: done"
poweroff -f
INIT
chmod +x "$IRD/init"

( cd "$IRD" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) \
  > "$LANE/build/ird.cpio.gz"

GDB_ARGS=()
[ "${GDB:-0}" = "1" ] && GDB_ARGS=(-S -gdb tcp::1234)

set +e
timeout "$TIMEOUT" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 2 -m 1024 \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -kernel "$ZIMAGE" -initrd "$LANE/build/ird.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8 lab.fs=$FS lab.mods=$MODS lab.op=$OP" \
  -nographic -no-reboot "${GDB_ARGS[@]}" 2>&1 | tee "$OUT"
rc=$?
set -e

echo
echo "=== verdict: $(basename "$IMG") ==="
grep -q "LAB: done" "$OUT" && echo "  completed cleanly" \
  || echo "  *** did NOT reach 'LAB: done' (rc=$rc) -- hang or crash ***"
grep -aiE "Unable to handle|Oops|BUG:|Kernel panic|Internal error|corrupt|slab" "$OUT" | head -20 || true
echo "  log: $OUT"
