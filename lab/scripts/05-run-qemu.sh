#!/usr/bin/env bash
# Boot the lab kernel with a filesystem image attached as /dev/vda.
#
#   ./scripts/05-run-qemu.sh IMAGE [FS] [MODS] [OP]
#     IMAGE  filesystem image to hand the guest (becomes /dev/vda)
#     FS     mount type            (default exfat)
#     MODS   comma-separated .ko   (default exfat_core,exfat_fs)
#     OP     mount|readdir|stat|none (default readdir)
#
#   GDB=1     start stopped with a gdbstub on :1234 for stepping the parser
#   TIMEOUT=n wall-clock guard (default 60s); a parser that hangs is a result
#
# The guest always powers off by itself; the interesting output is the serial
# log, which is teed to out/<image>.log.
set -euo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
IMG=${1:?usage: 05-run-qemu.sh IMAGE [FS] [MODS] [OP]}
FS=${2:-exfat}
MODS=${3:-exfat_core,exfat_fs}
OP=${4:-readdir}
TIMEOUT=${TIMEOUT:-60}

ZIMAGE=$LAB/src/linux-4.1.10/arch/arm/boot/zImage
INITRD=$LAB/build/initramfs.cpio.gz
LOG=$LAB/out/$(basename "$IMG").log

[ -f "$ZIMAGE" ] || { echo "no zImage - run the container kernel build"; exit 1; }
[ -f "$INITRD" ] || { echo "no initramfs - run 03-build-initramfs.sh"; exit 1; }

GDB_ARGS=()
if [ "${GDB:-0}" = "1" ]; then
  GDB_ARGS=(-S -gdb tcp::1234)
  echo "gdbstub on :1234 (guest halted). Attach with:"
  echo "  docker run --rm -it --network host -v $LAB:/work localhost/samsung-kbuild \\"
  echo "    gdb-multiarch /work/src/linux-4.1.10/vmlinux -ex 'target remote localhost:1234'"
fi

# 'virt' machine: virtio-blk for the image, PL011 for console, no DTB juggling.
# -no-reboot so a panic ends the run instead of looping.
set +e
timeout "$TIMEOUT" qemu-system-arm \
  -M virt -cpu cortex-a15 -smp 2 -m 512 \
  -kernel "$ZIMAGE" \
  -initrd "$INITRD" \
  -drive file="$IMG",format=raw,if=none,id=hd0,readonly=on \
  -device virtio-blk-device,drive=hd0 \
  -append "console=ttyAMA0 panic=-1 loglevel=8 lab.fs=$FS lab.mods=$MODS lab.op=$OP" \
  -nographic -no-reboot \
  "${GDB_ARGS[@]}" 2>&1 | tee "$LOG"
rc=$?
set -e

echo
echo "=== verdict for $(basename "$IMG") ==="
if grep -q "LAB: done" "$LOG"; then
  echo "  guest completed cleanly"
else
  echo "  *** guest did NOT reach 'LAB: done' (rc=$rc) ***"
fi
grep -aiE "Unable to handle kernel|Oops|BUG:|stack-protector|stack overflow|Kernel panic|Internal error|corrupt" "$LOG" | head -20 || true
echo "  full log: $LOG"
