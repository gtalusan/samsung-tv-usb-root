#!/bin/bash
# Find the real rendering of the SP-mask idiom. In szdrv (control) it must
# exist. ARM encoding for "bic rX, rY, #0x1fc0" is e3c??d7f (rot=13,imm=0x7f).
cd /work/fw/modules

echo "########## control szdrv.ko: all bic instructions ##########"
arm-linux-gnueabi-objdump -d szdrv.ko 2>/dev/null | grep -E "\sbic" | head -20

echo
echo "########## szdrv.ko: look for the raw e3c...d7f encoding ##########"
arm-linux-gnueabi-objdump -d szdrv.ko 2>/dev/null | grep -E "e3c[0-9a-f]{2}d7f" | head -10

echo
echo "########## szdrv.ko: 'mov rX, sp' followed shortly by bic ##########"
arm-linux-gnueabi-objdump -d szdrv.ko 2>/dev/null | grep -nE -A3 "mov.*, sp$" | grep -E "bic" | head -10
