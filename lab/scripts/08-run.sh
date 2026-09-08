#!/usr/bin/env bash
# Boot the vendor kernel and drive a filesystem image through an UNMODIFIED
# Samsung driver.
#
#   ./scripts/08-run.sh IMAGE [FS] [MODS] [OP]
#     IMAGE  filesystem image, embedded in the initramfs and loop-mounted
#     FS     mount type              (default exfat)
#     MODS   comma-separated modules (default exfat_core,exfat_fs)
#     OP     mount|readdir|stat|none (default readdir)
#
#   GDB=1      halt at boot with a gdbstub on :1234
#   TIMEOUT=n  wall-clock guard, default 60s (a hang IS a result)
#
# Fidelity notes -- nothing in the path under test is modified:
#   * kernel      : vendor tree linux-4.1.10-tizen5.5 + Muse.M-Tizen_release_defconfig
#   * vermagic    : "9518079, release SMP preempt mod_unload ARMv7 p2v8" (native,
#                   via the reconstructed include/linux/vdlp_version.h)
#   * modules     : taken straight from fw/modules/, byte-for-byte as shipped
#                   on the TV. No vermagic patch, no offset patch, no shim.
#   * ABI parity  : cred@0x320 fs@0x35c i_size@0x38 s_bdev@0x7c -- verified to
#                   match the offsets hardcoded in the vendor binaries.
# Consequence: any crash here is the vendor driver's behaviour, not an artefact.
# (Exploit constants must still come from the vendor uImage/.ko, never from
# this kernel -- it is a trigger-and-observe rig, not the target.)
set -euo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
IMG=${1:?usage: 08-run.sh IMAGE [FS] [MODS] [OP]}
FS=${2:-exfat}
MODS=${3:-exfat_core,exfat_fs}
OP=${4:-readdir}
TIMEOUT=${TIMEOUT:-60}

KSRC=$LAB/vendor/linux-4.1.10
ZIMAGE=$KSRC/arch/arm/boot/zImage
LANE=${LANE:-$(basename "${IMG%.*}")}
IRD=$LAB/build/ird-$LANE
OUT=$LAB/out/$LANE-$(basename "$IMG").log

[ -f "$ZIMAGE" ] || { echo "no vendor zImage - run scripts/07-build-vendor-kernel.sh"; exit 1; }
[ -f "$IMG" ]    || { echo "no such image: $IMG"; exit 1; }

# ---- initramfs: busybox + shipped modules + the image under test -----------
rm -rf "$IRD"; mkdir -p "$IRD"/{bin,dev,proc,sys,mnt,lib/modules}
cp "$LAB/build/busybox-armhf" "$IRD/bin/busybox"
chmod +x "$IRD/bin/busybox"
for a in sh mount umount ls cat dmesg insmod lsmod poweroff sleep echo losetup dd hexdump; do
  ln -sf busybox "$IRD/bin/$a"
done
# UNPATCHED vendor modules, exactly as extracted from the firmware
cp "$LAB"/fw/modules/*.ko "$IRD/lib/modules/" 2>/dev/null || true
find "$LAB/fw/modules" -name '*.ko' -exec cp {} "$IRD/lib/modules/" \; 2>/dev/null || true
cp "$IMG" "$IRD/test.img"
mknod -m 600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$IRD/dev/null" c 1 3 2>/dev/null || true

cat > "$IRD/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null

get_arg() { for a in $(cat /proc/cmdline); do case "$a" in "$1"=*) echo "${a#*=}"; return;; esac; done; }
FS=$(get_arg lab.fs);   [ -n "$FS" ] || FS=exfat
MODS=$(get_arg lab.mods)
OP=$(get_arg lab.op);   [ -n "$OP" ] || OP=readdir

echo "LAB: fs=$FS op=$OP mods=$MODS"
IFS=,
for m in $MODS; do
  insmod /lib/modules/"$m".ko && echo "LAB: insmod $m ok" || echo "LAB: insmod $m FAILED"
done
unset IFS

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
  > "$LAB/build/ird-$LANE.cpio.gz"

# ---- boot ------------------------------------------------------------------
GDB_ARGS=()
if [ "${GDB:-0}" = "1" ]; then
  GDB_ARGS=(-S -gdb tcp::${GDBPORT:-1234})
  echo "gdbstub :1234 (halted). Attach:"
  echo "  docker run --rm -it --network host -v $LAB:/work localhost/samsung-kbuild \\"
  echo "    gdb-multiarch /work/vendor/linux-4.1.10/vmlinux -ex 'target remote localhost:1234'"
fi

set +e
timeout "$TIMEOUT" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 2 -m 1024 \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -kernel "$ZIMAGE" -initrd "$LAB/build/ird-$LANE.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8 lab.fs=$FS lab.mods=$MODS lab.op=$OP" \
  -nographic -no-reboot "${GDB_ARGS[@]}" 2>&1 | tee "$OUT"
rc=$?
set -e

echo
echo "=== verdict: $(basename "$IMG") ==="
grep -q "LAB: done" "$OUT" && echo "  completed cleanly" \
  || echo "  *** did NOT reach 'LAB: done' (rc=$rc) -- hang or crash ***"
grep -aiE "Unable to handle|Oops|BUG:|stack-protector|Kernel panic|Internal error|corrupt|slab" "$OUT" | head -20 || true
echo "  log: $OUT"
