#!/usr/bin/env bash
# lane-ext4 wrapper around the shared scripts/08-run.sh.
#
# Why a wrapper: 08-run.sh rebuilds build/ird from fw/modules on every run, and
# this lane needs one extra module in the initramfs (lane_ext4_shim.ko, which
# supplies __sdp_dma_virt_to_phys + mem_section for jbd2). Editing 08-run.sh or
# dropping files into fw/modules would affect the other two lanes, so instead we
# copy the shim into the initramfs tree and repack it, then boot that.
#
# This duplicates only the cpio/QEMU tail of 08-run.sh; the initramfs contents,
# vendor kernel, and unmodified fw/modules all come from the shared harness.
#
#   ./run-ext4.sh IMAGE [MODS] [OP] [TIMEOUT]
# Default MODS deliberately loads the shim first:
#   lane_ext4_shim,mbcache,jbd2,ext4
set -euo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
LANE=$LAB/lanes/ext4
IMG=${1:?usage: run-ext4.sh IMAGE [MODS] [OP] [TIMEOUT]}
MODS=${2:-lane_ext4_shim,mbcache,jbd2,ext4}
OP=${3:-readdir}
TMO=${4:-60}   # triage default; hung guest makes no progress after ~30s

KSRC=$LAB/vendor/linux-4.1.10
ZIMAGE=$KSRC/arch/arm/boot/zImage
IRD=$LAB/build/ird-ext4lane
TAG=$(basename "$IMG" .img)
LOG=$LANE/logs/$TAG.log

[ -f "$ZIMAGE" ] || { echo "no vendor zImage"; exit 1; }
[ -f "$IMG" ] || { echo "no such image: $IMG"; exit 1; }
[ -f "$LANE/shim/lane_ext4_shim.ko" ] || { echo "shim not built"; exit 1; }

# --- stage initramfs exactly as 08-run.sh does, plus our shim ---------------
rm -rf "$IRD"; mkdir -p "$IRD"/{bin,dev,proc,sys,mnt,lib/modules}
cp "$LAB/build/busybox-armhf" "$IRD/bin/busybox"; chmod +x "$IRD/bin/busybox"
for a in sh mount umount ls cat dmesg insmod lsmod poweroff sleep echo losetup dd hexdump; do
  ln -sf busybox "$IRD/bin/$a"
done
# UNMODIFIED vendor modules, byte-for-byte from the firmware
find "$LAB/fw/modules" -name '*.ko' -exec cp {} "$IRD/lib/modules/" \; 2>/dev/null || true
# lane-local harness shim (NOT a vendor binary; clearly named)
cp "$LANE/shim/lane_ext4_shim.ko" "$IRD/lib/modules/"
cp "$IMG" "$IRD/test.img"
mknod -m 600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$IRD/dev/null" c 1 3 2>/dev/null || true

cat > "$IRD/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null

get_arg() { for a in $(cat /proc/cmdline); do case "$a" in "$1"=*) echo "${a#*=}"; return;; esac; done; }
MODS=$(get_arg lab.mods)
OP=$(get_arg lab.op);   [ -n "$OP" ] || OP=readdir
MOPT=$(get_arg lab.mopt); [ -n "$MOPT" ] || MOPT=ro

echo "LAB: fs=ext4 op=$OP mods=$MODS"
IFS=,
for m in $MODS; do
  insmod /lib/modules/"$m".ko && echo "LAB: insmod $m ok" || echo "LAB: insmod $m FAILED"
done
unset IFS
cat /proc/modules > /dev/console 2>/dev/null

echo "LAB: mounting /test.img as ext4 (loop)"
mount -t ext4 -o ${MOPT:-ro},loop /test.img /mnt && echo "LAB: mount OK" || echo "LAB: mount FAILED"

case "$OP" in
  readdir) echo "LAB: readdir ---"; ls -la /mnt 2>&1 | head -40; echo "LAB: readdir done";;
  stat)    echo "LAB: stat ---"; for f in /mnt/*; do ls -l "$f" 2>&1 | head -2; done; echo "LAB: stat done";;
  read)    echo "LAB: read ---"; for f in /mnt/*; do echo "-- $f"; dd if="$f" bs=64 count=1 2>/dev/null | hexdump -C | head -4; done; echo "LAB: read done";;
esac

echo "LAB: done"
poweroff -f
INIT
chmod +x "$IRD/init"

( cd "$IRD" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) > "$LAB/build/ird-ext4lane.cpio.gz"

GDB_ARGS=()
[ "${GDB:-0}" = "1" ] && GDB_ARGS=(-S -gdb tcp::${GDBPORT:-1235})

set +e
timeout "$TMO" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 2 -m 1024 \
  -kernel "$ZIMAGE" \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -initrd "$LAB/build/ird-ext4lane.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8 lab.mods=$MODS lab.op=$OP lab.mopt=${MOPT:-ro}" \
  -nographic -no-reboot "${GDB_ARGS[@]}" 2>&1 | tee "$LOG"
rc=$?
set -e

echo
echo "=== verdict: $TAG ==="
grep -q "LAB: done" "$LOG" && echo "  completed cleanly" \
  || echo "  *** did NOT reach 'LAB: done' (rc=$rc) -- hang or crash ***"
grep -aiE "Unable to handle|Oops|BUG:|Kernel panic|Internal error|EXT4-fs error|EXT4-fs warning" "$LOG" | head -15 || true
echo "  log: $LOG"
