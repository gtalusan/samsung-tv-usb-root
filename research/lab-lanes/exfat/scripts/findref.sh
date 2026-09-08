#!/bin/bash
# Locate which function references the "Filesystem is corrupted" string
# (.rodata.str1.4 + 0xc8) in exfat_core.ko.
cd /work/fw/modules

echo "=== relocations targeting .rodata.str1.4 (section 11) ==="
readelf -rW exfat_core.ko | grep -E "rodata\.str1\.4" | head -40

echo
echo "=== function symbol table (sorted) ==="
readelf -sW exfat_core.ko | awk '$4=="FUNC"{printf "%s %s %s\n", $2, $3, $8}' | sort > /tmp/funcs.txt
wc -l /tmp/funcs.txt
