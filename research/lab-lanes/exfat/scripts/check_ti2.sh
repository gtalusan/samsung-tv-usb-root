#!/bin/bash
# Validate the search pattern against a module KNOWN to have the construct
# (szdrv, per the ntfs lane) before trusting a negative result for exfat.
cd /work/fw/modules

echo "########## control: szdrv.ko (known to have the pattern) ##########"
arm-linux-gnueabi-objdump -d szdrv.ko 2>/dev/null > /tmp/szdrv.dis
echo "--- any 'bic' involving sp ---"
grep -nE "bic.*, sp," /tmp/szdrv.dis | head -5
echo "--- raw encoding e3cd?d7f / any bic with sp source ---"
grep -cE "bic" /tmp/szdrv.dis
echo "--- ldr [rX, #12] count ---"
grep -cE "ldr.*, \[.*, #12\]" /tmp/szdrv.dis

echo
for M in exfat_core exfat_fs; do
  echo "########## $M.ko ##########"
  arm-linux-gnueabi-objdump -d $M.ko 2>/dev/null > /tmp/$M.dis
  echo "--- 'bic' involving sp ---"
  grep -nE "bic.*, sp," /tmp/$M.dis || echo "    NONE"
  echo "--- total bic ---"; grep -cE "\sbic" /tmp/$M.dis
  echo "--- ldr [rX,#12] total ---"; grep -cE "ldr.*, \[.*, #12\]" /tmp/$M.dis
done
