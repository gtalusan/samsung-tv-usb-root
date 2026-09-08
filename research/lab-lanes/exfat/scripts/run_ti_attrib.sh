#!/bin/bash
cd /work/fw/modules
for M in exfat_core exfat_fs; do
  echo "==================== $M.ko ===================="
  arm-linux-gnueabi-objdump -d $M.ko 2>/dev/null > /tmp/$M.dis
  readelf -sW $M.ko | awk '$4=="FUNC"{printf "%s %s %s\n",$2,$3,$8}' > /tmp/$M.funcs
  python3 /work/lanes/exfat/scripts/ti_attrib.py /tmp/$M.dis /tmp/$M.funcs
  echo
done
