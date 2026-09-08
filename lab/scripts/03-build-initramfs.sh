#!/usr/bin/env bash
# Build the guest initramfs: static ARM busybox + the retargeted vendor modules
# + an init that loads a filesystem driver and mounts the image under test.
#
# The init is deliberately dumb and non-interactive: QEMU is launched per test
# case, the guest mounts /dev/vda, does the minimum to reach the parser, prints
# a marker, and powers off. Anything other than a clean "LAB: done" marker in
# the log means the parser did something interesting.
set -euo pipefail

LAB=${LAB:-/var/tmp/samsung-lab}
IRD=$LAB/initramfs
BB=$LAB/build/busybox-armhf
MODS=$LAB/build/modules

[ -x "$BB" ] || { echo "missing $BB (see recipe step 1)"; exit 1; }

rm -rf "$IRD"
mkdir -p "$IRD"/{bin,sbin,dev,proc,sys,mnt,lib/modules}

cp "$BB" "$IRD/bin/busybox"
chmod +x "$IRD/bin/busybox"
for a in sh mount umount ls cat dmesg insmod lsmod poweroff sleep echo mkdir dd hexdump; do
  ln -sf busybox "$IRD/bin/$a"
done
ln -sf ../bin/busybox "$IRD/sbin/insmod"

cp "$MODS"/*.ko "$IRD/lib/modules/" 2>/dev/null || true

# Device nodes: CONFIG_DEVTMPFS_MOUNT handles /dev, but console must exist
# before devtmpfs is up or the kernel cannot open stdio for init.
mknod -m 600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$IRD/dev/null"    c 1 3 2>/dev/null || true

cat > "$IRD/init" <<'INIT'
#!/bin/sh
# Guest init. Kernel cmdline drives it:
#   lab.fs=<exfat|szdrv|ext4|vfat>   which driver to load and mount as
#   lab.mods=<mod1,mod2>             modules to insmod in order
#   lab.op=<mount|readdir|stat|none> how far to drive the parser
mount -t proc  proc  /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null

get_arg() {
  for a in $(cat /proc/cmdline); do
    case "$a" in "$1"=*) echo "${a#*=}"; return;; esac
  done
}

FS=$(get_arg lab.fs);   [ -n "$FS" ]   || FS=exfat
MODS=$(get_arg lab.mods)
OP=$(get_arg lab.op);   [ -n "$OP" ]   || OP=readdir

echo "LAB: booting fs=$FS op=$OP mods=$MODS"

IFS=,
for m in $MODS; do
  echo "LAB: insmod $m"
  insmod /lib/modules/"$m".ko || echo "LAB: insmod $m FAILED"
done
unset IFS

echo "LAB: modules loaded:"; lsmod; echo "LAB: /proc/modules:"; cat /proc/modules

if [ -b /dev/vda ]; then
  echo "LAB: mounting /dev/vda as $FS"
  # errors=continue etc. are deliberately NOT passed: we want default vendor
  # behaviour, and storaged on the TV mounts with its own option string.
  mount -t "$FS" -o ro /dev/vda /mnt && echo "LAB: mount OK" || echo "LAB: mount FAILED"

  case "$OP" in
    readdir)
      echo "LAB: readdir ---"
      ls -la /mnt 2>&1 | head -40
      echo "LAB: readdir done"
      ;;
    stat)
      echo "LAB: stat ---"
      for f in /mnt/*; do echo "-- $f"; ls -l "$f" 2>&1 | head -3; done
      ;;
    none) : ;;
  esac
else
  echo "LAB: no /dev/vda present"
fi

echo "LAB: done"
poweroff -f
INIT
chmod +x "$IRD/init"

cd "$IRD"
find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$LAB/build/initramfs.cpio.gz"
echo "initramfs: $(stat -c%s "$LAB/build/initramfs.cpio.gz") bytes"
echo "modules inside: $(ls "$IRD/lib/modules/" | tr '\n' ' ')"
