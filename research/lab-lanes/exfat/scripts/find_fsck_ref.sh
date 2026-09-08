#!/bin/bash
# Which function emits "Filesystem is corrupted ...Please run fsck"?
# Strategy: the string lives in .rodata.str1.4. Find its offset, then find the
# literal-pool word in .text holding that offset, then attribute the pool user.
cd /work/fw/modules

echo "=== string offset within .rodata.str1.4 ==="
readelf -p .rodata.str1.4 exfat_core.ko | grep -n "Please run fsck"

echo
echo "=== all R_ARM_ABS32 relocs into .rodata.str1.4 with their .text sites ==="
readelf -rW exfat_core.ko | awk '/rodata/ && /ABS32/ {print}' | head -40
