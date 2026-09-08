#!/bin/bash
# Definitive: locate every current_thread_info() SP-mask site in the exFAT
# modules and attribute each to its containing function.
# Pattern validated against szdrv.ko (control): "bic rX, rX, #8128" (0x1fc0).
cd /work/fw/modules

for M in exfat_core exfat_fs szdrv; do
  echo "==================== $M.ko ===================="
  arm-linux-gnueabi-objdump -d $M.ko 2>/dev/null > /tmp/$M.dis
  readelf -sW $M.ko | awk '$4=="FUNC"{printf "%s %s %s\n",$2,$3,$8}' | sort > /tmp/$M.funcs

  N=$(grep -cE "bic\s+r[0-9]+, r[0-9]+, #8128" /tmp/$M.dis)
  echo "SP-mask (#8128) sites: $N"

  grep -oE "^ *[0-9a-f]+:\s+e3c[0-9a-f]{2}d7f" /tmp/$M.dis \
    | awk -F: '{gsub(/ /,"",$1); print $1}' \
    | while read -r off; do
        T=$((0x$off))
        FN=$(awk -v t="$T" '{s=strtonum("0x" $1); e=s+$2; if (t>=s && t<e) print $3}' /tmp/$M.funcs)
        # what offset is loaded right after the mask pair?
        LD=$(grep -A4 "^ *$off:" /tmp/$M.dis | grep -oE "ldr\s+r[0-9]+, \[r[0-9]+, #(12|16)\]" | head -1)
        printf "   0x%-6s %-34s %s\n" "$off" "${FN:-<unknown>}" "${LD:-}"
      done
  echo
done
