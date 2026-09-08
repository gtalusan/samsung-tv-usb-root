#!/usr/bin/env bash
set -euo pipefail
LAB=${LAB:-/var/tmp/samsung-lab}
KSRC=$LAB/vendor/linux-4.1.10
IRD=$LAB/build/ird-kmem
OUT=$LAB/out/kmem-test.log
BANNER_VIRT=$(awk '$3=="linux_banner"{print $1}' "$KSRC/System.map")
rm -rf "$IRD"; mkdir -p "$IRD"/{bin,dev,proc,sys,tmp,lib/modules}
cp "$LAB/build/busybox-armhf" "$IRD/bin/busybox"; chmod +x "$IRD/bin/busybox"
for a in sh mount insmod ls cat dd hexdump poweroff mknod echo; do ln -sf busybox "$IRD/bin/$a"; done
cp "$LAB/payload/research_kmem.ko" "$IRD/lib/modules/"
mknod -m600 "$IRD/dev/console" c 5 1 2>/dev/null || true
mknod -m666 "$IRD/dev/null" c 1 3 2>/dev/null || true
cat > "$IRD/init" <<INIT
#!/bin/sh
mkdir -p /proc /sys /dev /tmp
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
insmod /lib/modules/research_kmem.ko enable=1 && echo 'KMEM INSMOD OK'
ls -l /dev/kmem
A=\$(cat /sys/module/research_kmem/parameters/test_addr)
echo "KMEM TEST ADDRESS=\$A"
echo 'KMEM READ BEFORE:'
dd if=/dev/kmem bs=1 skip=\$((A)) count=13 2>/dev/null | hexdump -C
printf X >/tmp/x
dd if=/tmp/x of=/dev/kmem bs=1 seek=\$((A)) count=1 conv=notrunc 2>/dev/null
echo 'KMEM READ AFTER:'
dd if=/dev/kmem bs=1 skip=\$((A)) count=13 2>/dev/null | hexdump -C
echo 'KMEM TEST DONE'
poweroff -f
INIT
chmod +x "$IRD/init"
(cd "$IRD" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) >$LAB/build/ird-kmem.cpio.gz
nix develop $LAB/nixenv --command timeout 90 qemu-system-arm -M vexpress-a15 -cpu cortex-a15 -smp 2 -m 1024 \
 -dtb "$KSRC/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" -kernel "$KSRC/arch/arm/boot/zImage" \
 -initrd "$LAB/build/ird-kmem.cpio.gz" -append 'console=ttyAMA0 panic=-1 loglevel=8' \
 -nographic -no-reboot 2>&1 | tee "$OUT"
grep -q 'KMEM TEST DONE' "$OUT"
