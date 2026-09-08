#!/bin/bash
set -euo pipefail
LAB=${LAB:-/var/tmp/samsung-lab}
KERNEL=$LAB/vendor/linux-4.1.10
MOD=$LAB/payload/research-kmem
make -C "$KERNEL" M="$MOD" ARCH=arm \
  CROSS_COMPILE=/opt/ct/gcc-6.4.0-nolibc/arm-linux-gnueabi/bin/arm-linux-gnueabi- \
  modules
cp "$MOD/research_kmem.ko" "$LAB/payload/research_kmem.ko"
