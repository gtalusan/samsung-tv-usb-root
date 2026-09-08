#!/usr/bin/env bash
# lanes/ntfs: mount an image READ-WRITE with the shipped szdrv driver, let the
# driver do whatever it does at mount time ($RmMetadata / $MYLOG creation),
# unmount, and dump the resulting image back out over the serial line.
#
#   rwdump.sh IN.img OUT.img [EXTRA_SHELL]
#
# Needed because the driver's own write paths ($MYLOG journal) cannot be
# produced by mkntfs, and the image lives in the initramfs (RAM) so it is
# otherwise lost at poweroff.
set -uo pipefail
export TMPDIR=${TMPDIR:-/dev/shm}

LAB=${LAB:-/var/tmp/samsung-lab}
LANE=$LAB/lanes/ntfs
IMG=${1:?usage: rwdump.sh IN.img OUT.img}
OUTIMG=${2:?usage: rwdump.sh IN.img OUT.img}
EXTRA=${3:-}
TIMEOUT=${TIMEOUT:-120}
KSRC=$LAB/vendor/linux-4.1.10
W=$(mktemp -d /dev/shm/ntfsdump.XXXXXX)
trap 'rm -rf "$W"' EXIT

mkdir -p "$W"/ird/{bin,dev,proc,sys,mnt,lib/modules}
cp "$LAB/build/busybox-armhf" "$W/ird/bin/busybox"; chmod +x "$W/ird/bin/busybox"
for a in sh mount umount ls cat dmesg insmod poweroff losetup head gzip base64 sync touch mkdir dd; do
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
losetup /dev/loop0 /test.img
echo "LAB: mounting rw"
mount -t szdrv -o rw /dev/loop0 /mnt && echo "LAB: mount OK" || echo "LAB: mount FAILED"
$EXTRA
sync
umount /mnt && echo "LAB: umount OK" || echo "LAB: umount FAILED"
losetup -d /dev/loop0
echo "LAB: DUMP-BEGIN"
gzip -c /test.img | base64
echo "LAB: DUMP-END"
echo "LAB: done"
poweroff -f
INIT
chmod +x "$W/ird/init"
( cd "$W/ird" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) > "$W/ird.cpio.gz"

timeout "$TIMEOUT" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 1 -m 512 \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -kernel "$KSRC/arch/arm/boot/zImage" -initrd "$W/ird.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8" \
  -nographic -no-reboot > "$W/serial.log" 2>&1

grep -a "LAB:\|SZDrv (loop0)" "$W/serial.log" | grep -av DUMP
sed -n '/LAB: DUMP-BEGIN/,/LAB: DUMP-END/p' "$W/serial.log" \
  | sed '1d;$d' | tr -d '\r' | base64 -d | gzip -dc > "$OUTIMG"
echo "wrote $OUTIMG ($(stat -c%s "$OUTIMG") bytes)"
