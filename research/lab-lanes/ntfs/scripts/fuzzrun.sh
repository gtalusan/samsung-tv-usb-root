#!/usr/bin/env bash
# lanes/ntfs: lean single-image runner for parallel campaigns.
#
#   fuzzrun.sh IMAGE OUTLOG [OP]
#
# Same fidelity as scripts/08-run.sh (shared vendor kernel, shipped .ko files,
# byte-for-byte) but:
#   * only the 3 modules under test go into the initramfs, and the whole thing
#     is assembled in /dev/shm, so hundreds of runs cost no disk;
#   * output goes to the named log, nothing else is written.
#
# Env: TIMEOUT (default 40), OP (default readdir), GDB/GDBPORT as in 08-run.sh.
set -uo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
LANE=$LAB/lanes/ntfs
IMG=${1:?usage: fuzzrun.sh IMAGE OUTLOG [OP]}
OUT=${2:?usage: fuzzrun.sh IMAGE OUTLOG [OP]}
OP=${3:-readdir}
MOUNTOPT=${MOUNTOPT:-ro}
TIMEOUT=${TIMEOUT:-40}

KSRC=$LAB/vendor/linux-4.1.10
W=$(mktemp -d /dev/shm/ntfsfuzz.XXXXXX)
trap 'rm -rf "$W"' EXIT

mkdir -p "$W"/ird/{bin,dev,proc,sys,mnt,lib/modules}
cp "$LAB/build/busybox-armhf" "$W/ird/bin/busybox"; chmod +x "$W/ird/bin/busybox"
for a in sh mount umount ls cat dmesg insmod poweroff losetup head; do
  ln -sf busybox "$W/ird/bin/$a"
done
cp "$LANE/shim-r2/ntfsshim.ko" "$LAB/fw/modules/szdrv_core.ko" "$LAB/fw/modules/szdrv.ko" \
   "$W/ird/lib/modules/"
cp "$IMG" "$W/ird/test.img"
mknod -m 600 "$W/ird/dev/console" c 5 1 2>/dev/null
mknod -m 666 "$W/ird/dev/null" c 1 3 2>/dev/null

cat > "$W/ird/init" <<INIT
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
insmod /lib/modules/ntfsshim.ko
insmod /lib/modules/szdrv_core.ko
insmod /lib/modules/szdrv.ko
echo "LAB: modbase ---"; cat /proc/modules; echo "LAB: modbase end"
losetup /dev/loop0 /test.img
echo "LAB: mounting"
mount -t szdrv -o ${MOUNTOPT:-ro} /dev/loop0 /mnt && echo "LAB: mount OK" || echo "LAB: mount FAILED"
case "$OP" in
  readdir) echo "LAB: readdir ---"; ls -la /mnt 2>&1 | head -40; echo "LAB: readdir done";;
  stat)    echo "LAB: stat ---"; for f in /mnt/*; do ls -l "\$f" 2>&1 | head -2; done; echo "LAB: stat done";;
  read)    echo "LAB: read ---"; for f in /mnt/*; do cat "\$f" 2>&1 | head -2; done; echo "LAB: read done";;
esac
echo "LAB: done"
poweroff -f
INIT
chmod +x "$W/ird/init"
( cd "$W/ird" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) > "$W/ird.cpio.gz"

GDB_ARGS=(); [ "${GDB:-0}" = "1" ] && GDB_ARGS=(-S -gdb tcp::${GDBPORT:-1236})
timeout "$TIMEOUT" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 1 -m 512 \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -kernel "$KSRC/arch/arm/boot/zImage" -initrd "$W/ird.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8" \
  -nographic -no-reboot "${GDB_ARGS[@]}" > "$OUT" 2>&1
rc=$?
if grep -qaE "Unable to handle|Oops|BUG:|Kernel panic|Internal error|stack-protector|slab corruption|bad page" "$OUT"; then
  if grep -qa "LAB: done" "$OUT"; then echo "CRASH-SURVIVED"; else echo "CRASH"; fi
elif grep -qa "LAB: done" "$OUT"; then
  if grep -qa "LAB: mount OK" "$OUT"; then echo "OK"; else echo "REJECT"; fi
else
  echo "HANG(rc=$rc)"
fi
