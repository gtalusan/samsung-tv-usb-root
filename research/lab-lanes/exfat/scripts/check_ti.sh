#!/bin/bash
# Find the legacy current_thread_info() pattern in the exFAT modules:
#     bic rX, sp, #0x1fc0 ; bic rX, rX, #0x3f   (sp & ~0x1fff)
#     ldr rY, [rX, #12]                          expects thread_info->task
# On the current lab kernel [+12] is addr_limit (KERNEL_STACK_LARGE=y), so any
# path hitting this is UNRELIABLE and any result on it is provisional.
cd /work/fw/modules

for M in exfat_core exfat_fs; do
  echo "==================== $M.ko ===================="
  arm-linux-gnueabi-objdump -d $M.ko > /tmp/$M.dis 2>/dev/null

  echo "--- SP-mask sites (bic ...,sp,#0x1fc0) ---"
  grep -nE "bic.*sp, #8128|bic.*sp, #0x1fc0" /tmp/$M.dis || echo "    (none)"

  echo "--- [+12] loads following a mask (candidate ti->task) ---"
  grep -nE -A4 "bic.*sp, #8128" /tmp/$M.dis | grep -E "ldr.*#12\]" || echo "    (none)"

  echo "--- which functions contain a SP-mask site ---"
  for off in $(grep -oE "^ *[0-9a-f]+:.*bic.*sp, #8128" /tmp/$M.dis | awk -F: '{gsub(/ /,"",$1); print $1}'); do
    readelf -sW $M.ko | awk -v t=$((0x$off)) '$4=="FUNC"{s=strtonum("0x" $2); e=s+$3; if (t>=s && t<e) print "    " $8 "  (site 0x" sprintf("%x",t) ")"}'
  done
  echo
done
