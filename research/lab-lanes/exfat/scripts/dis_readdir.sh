#!/bin/bash
# Dump ffsReadDir and look for the validation that rejects our crafted entry set.
cd /work/fw/modules
S=$(readelf -sW exfat_core.ko | awk '$4=="FUNC" && $8=="ffsReadDir"{print $2; exit}')
Z=$(readelf -sW exfat_core.ko | awk '$4=="FUNC" && $8=="ffsReadDir"{print $3; exit}')
echo "ffsReadDir at 0x$S size $Z"
START=$((0x$S))
END=$((0x$S + Z))
arm-linux-gnueabi-objdump -d --start-address=$START --stop-address=$END exfat_core.ko \
  | grep -nE "bl\s|cmp|beq|bne|ldrb|ldrh" | head -80
