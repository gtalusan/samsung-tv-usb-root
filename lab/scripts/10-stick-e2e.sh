#!/usr/bin/env bash
# E2E the USB stick payload on the vendor kernel (no trigger, no UEP --
# those need the device): p2 (vfat) mount, stage1 staging, dropbear exec+listen.
#   LANE=stick-e2e TIMEOUT=120 scripts/10-stick-e2e.sh /path/tv-usb-stick.img
set -euo pipefail
LAB=${LAB:-/var/tmp/samsung-lab}
KSRC=$LAB/vendor/linux-4.1.10
ZIMAGE=$KSRC/arch/arm/boot/zImage
STICK=${1:?usage: 10-stick-e2e.sh STICK-IMG}
LANE=${LANE:-stick-e2e}
TMO=${TIMEOUT:-120}
IRD=$LAB/build/ird-$LANE
OUT=$LAB/out/$LANE.log

[ -f "$STICK" ] || { echo "no stick img $STICK"; exit 1; }
# p2 offset from the MBR (aviariable-partition build)
SECP2=$(sfdisk -d "$STICK" 2>/dev/null | awk '/img2/{for(i=1;i<=NF;i++){if($i=="start=")o=$(i+1); if($i=="size=")z=$(i+1)} print(o*512)}')
SECSZ=$(sfdisk -d "$STICK" 2>/dev/null | awk '/img2/{for(i=1;i<=NF;i++){if($i=="size=")z=$(i+1)} print(z*512)}')
[ -n "$SECP2" ] || { echo "cannot parse p2 offset"; exit 1; }
echo "p2 offset=$SECP2 size=$SECSZ bytes"
rm -rf "$IRD"; mkdir -p "$IRD"/bin
cp "$LAB/build/busybox-armhf" "$IRD/bin/busybox"; chmod +x "$IRD/bin/busybox"
for a in sh mount dd cat cmp mknod poweroff echo grep od head cp chmod mkdir \
         losetup netstat pgrep ps ls ln sleep printf; do ln -sf busybox "$IRD/bin/$a"; done
# stage1/parseinfo have #!/bin/bash shebangs (TV truth: /bin/sh -> bash).
# Lab: busybox sh covers ${0%/*}, $((arith)) and fd<>; wrap it as "bash".
printf '#!/bin/sh\nexec /bin/sh "$@"\n' > "$IRD/bin/bash"
chmod +x "$IRD/bin/bash"
cp "$STICK" "$IRD/stick.img"
mknod -m 600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$IRD/dev/null" c 1 3 2>/dev/null || true

cat > "$IRD/init" <<'INIT'
#!/bin/sh
mkdir -p /proc /sys /dev /tmp /mnt/p2 /opt
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /dev/pts; mount -t devpts devpts /dev/pts 2>/dev/null

echo "== mount stick p2 (vfat) via loop with offset =="
# MBR: p2 starts at LBA 526336 (sector 512B) = 0x10126000
get_arg() { for a in $(cat /proc/cmdline); do case "$a" in "$1"=*) echo "${a#*=}"; return;; esac; done; }
P2OFF=$(get_arg lab.p2off); P2LEN=$(get_arg lab.p2len)
losetup -o $P2OFF /dev/loop7 /stick.img && echo "losetup OK"
mount -t vfat /dev/loop7 /mnt/p2 || true
dmesg | tail -6 | grep -iE "fat|loop" || dmesg | tail -6
mount -t vfat /dev/loop7 /mnt/p2 && echo "VFAT MOUNT OK"
ls -l /mnt/p2

echo "== run stage1 exactly as the LPE would (root, from the stick) =="
/mnt/p2/stage1.sh; rc=$?
echo "stage1 rc=$rc"

echo "== did /opt get populated? (stage1 falls back to /tmp/.opt: /opt is a dir here) =="
ls -l /opt/bin /opt/etc/dropbear 2>/dev/null
ls -l /tmp/.opt/bin /tmp/.opt/etc/dropbear 2>/dev/null
echo "== root authorized_keys =="
ls -l /root/.ssh/authorized_keys && head -1 /root/.ssh/authorized_keys | cut -c1-40
echo "== is dropbear alive and listening? =="
ps | grep -v grep | grep dropbear && echo "DROPBEAR PROCESS OK"
netstat -tln 2>/dev/null | grep ":22 " && echo "DROPBEAR LISTEN :22 OK"
echo "== UEP-down exec-probe simulation (dropbear -V) =="
/opt/bin/dropbearmulti dropbear -V 2>&1 | head -1 && echo "EXEC PROBE OK"

echo "LAB: stick e2e done"
poweroff -f
INIT
chmod +x "$IRD/init"

( cd "$IRD" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) > "$LAB/build/ird-$LANE.cpio.gz"

set +e
timeout "$TMO" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 2 -m 1024 \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -kernel "$ZIMAGE" -initrd "$LAB/build/ird-$LANE.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8 lab.p2off=$SECP2 lab.p2len=$SECSZ" \
  -nographic -no-reboot 2>&1 | tee "$OUT"
echo
grep -q "LAB: stick e2e done" "$OUT" && echo "=== e2e: COMPLETED ===" || echo "=== e2e: FAILED ==="
grep -E "VFAT MOUNT OK|DROPBEAR PROCESS OK|DROPBEAR LISTEN :22 OK|EXEC PROBE OK|stage1 rc=" "$OUT" || true
