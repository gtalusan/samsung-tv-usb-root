#!/usr/bin/env bash
# lanes/ntfs round-2 runner.
#
# Identical to scripts/08-run.sh in fidelity terms except:
#   * it also copies lanes/ntfs/shim-r2/ntfsshim.ko into the initramfs
#     (two symbols szdrv_core needs that the vexpress lab kernel does not have;
#     see shim-r2/ntfsshim.c for the justification and the fidelity caveat),
#   * it uses explicit losetup + mount so the mount syscall comes from a normal
#     process, and
#   * it prints /proc/modules so a crash PC can be resolved to a module offset.
#
# Kernel: the SHARED vendor kernel (vendor/linux-4.1.10), never a lane-private
# one. Modules: byte-for-byte as shipped.
#
#   ./run3.sh IMAGE [FS] [MODS] [OP]
#   GDB=1 GDBPORT=1236   halt at boot with a gdbstub
#   TIMEOUT=n            wall-clock guard
set -euo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
LANE=$LAB/lanes/ntfs
IMG=${1:?usage: run3.sh IMAGE [FS] [MODS] [OP]}
FS=${2:-szdrv}
MODS=${3:-ntfsshim,szdrv_core,szdrv}
OP=${4:-mount}
TIMEOUT=${TIMEOUT:-90}
TAG=${TAG:-r2}

KSRC=$LAB/vendor/linux-4.1.10
ZIMAGE=$KSRC/arch/arm/boot/zImage
IRD=$LANE/build/ird-$TAG
OUT=$LANE/logs/$(basename "$IMG").$TAG.log

mkdir -p "$LANE/logs" "$LANE/build"
rm -rf "$IRD"; mkdir -p "$IRD"/{bin,dev,proc,sys,mnt,lib/modules,root,tmp}
cp "$LAB/build/busybox-armhf" "$IRD/bin/busybox"; chmod +x "$IRD/bin/busybox"
for a in sh mount umount ls cat dmesg insmod lsmod poweroff sleep echo losetup dd hexdump mkdir env head; do
  ln -sf busybox "$IRD/bin/$a"
done
find "$LAB/fw/modules" -name '*.ko' -exec cp {} "$IRD/lib/modules/" \; 2>/dev/null || true
cp "$LANE/shim-r2/ntfsshim.ko" "$IRD/lib/modules/"
cp "$IMG" "$IRD/test.img"
mknod -m 600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$IRD/dev/null" c 1 3 2>/dev/null || true

cat > "$IRD/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
cd /
get_arg() { for a in $(cat /proc/cmdline); do case "$a" in "$1"=*) echo "${a#*=}"; return;; esac; done; }
FS=$(get_arg lab.fs);   [ -n "$FS" ] || FS=szdrv
MODS=$(get_arg lab.mods)
OP=$(get_arg lab.op);   [ -n "$OP" ] || OP=mount

echo "LAB: fs=$FS op=$OP mods=$MODS"
IFS=,
for m in $MODS; do
  insmod /lib/modules/"$m".ko && echo "LAB: insmod $m ok" || echo "LAB: insmod $m FAILED"
done
unset IFS
echo "LAB: modbase ---"; cat /proc/modules; echo "LAB: modbase end"

losetup /dev/loop0 /test.img && echo "LAB: losetup ok" || echo "LAB: losetup FAILED"
echo "LAB: mounting /dev/loop0 as $FS"
mount -t "$FS" -o ro /dev/loop0 /mnt && echo "LAB: mount OK" || echo "LAB: mount FAILED"

case "$OP" in
  readdir) echo "LAB: readdir ---"; ls -la /mnt 2>&1 | head -40; echo "LAB: readdir done";;
  stat)    echo "LAB: stat ---"; for f in /mnt/*; do ls -l "$f" 2>&1 | head -2; done; echo "LAB: stat done";;
esac
echo "LAB: done"
poweroff -f
INIT
chmod +x "$IRD/init"

( cd "$IRD" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) \
  > "$LANE/build/ird-$TAG.cpio.gz"

GDB_ARGS=(); [ "${GDB:-0}" = "1" ] && GDB_ARGS=(-S -gdb tcp::${GDBPORT:-1236})
set +e
timeout "$TIMEOUT" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 2 -m 1024 \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -kernel "$ZIMAGE" -initrd "$LANE/build/ird-$TAG.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8 lab.fs=$FS lab.mods=$MODS lab.op=$OP" \
  -nographic -no-reboot "${GDB_ARGS[@]}" 2>&1 | tee "$OUT"
rc=$?
set -e
echo; echo "=== verdict: $(basename "$IMG") [$TAG] ==="
grep -q "LAB: done" "$OUT" && echo "  completed cleanly" \
  || echo "  *** did NOT reach 'LAB: done' (rc=$rc) ***"
grep -aiE "Unable to handle|Oops|BUG:|Kernel panic|Internal error" "$OUT" | head -8 || true
echo "  log: $OUT"
