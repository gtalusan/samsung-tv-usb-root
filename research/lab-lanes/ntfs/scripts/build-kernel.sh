#!/usr/bin/env bash
# lanes/ntfs PRIVATE kernel build.
#
# Same vendor tree and same Muse.M defconfig as scripts/07-build-vendor-kernel.sh,
# with ONE deliberate change:
#
#     # CONFIG_KERNEL_STACK_LARGE is not set
#     # CONFIG_IRQ_STACK is not set          (IRQ_STACK depends on it)
#
# WHY. CONFIG_KERNEL_STACK_LARGE inserts `void *tinfo_ptr` at offset 0 of
# struct thread_info (arch/arm/include/asm/thread_info.h:62) which pushes
# .task from 0x0c to 0x10, and it changes current_thread_info() into a
# DEREFERENCE of the stack base:
#     *(unsigned long *)(sp & ~(THREAD_SIZE-1))     [thread_info.h:122]
# The shipped Samsung modules do neither: they compute
#     bic rX,sp,#0x1fc0 ; bic rX,rX,#0x3f ; ldr rY,[rX,#12]
# i.e. thread_info AT the stack base with .task at 0x0c. Survey of all 161
# shipped .ko files: 148 sites read [+12] after that mask, ZERO read [+16],
# and none performs the stack-base dereference. So the shipped modules are a
# non-KERNEL_STACK_LARGE build, whatever Muse.M-Tizen_release_defconfig says.
#
# Corroboration: the Muse.M KASAN / KUBSAN / LICENSING defconfig variants in the
# same tree carry NO CONFIG_KERNEL_STACK_* line at all, and arch/arm/Kconfig:327
# gives KERNEL_STACK_LARGE `default n`. LICENSING_release still has SMACK + SFD +
# UEP, so it is a plausible shipping config.
#
# Everything else is inherited from scripts/07 so the two kernels stay comparable.
#
# The vendor tree is treated READ-ONLY: we build with O= into a lane-private
# directory and never touch vendor/linux-4.1.10/.config.
set -euo pipefail

LAB=/work
SRC=$LAB/lanes/ntfs/ksrc
OUT=$LAB/lanes/ntfs/ksrc
JOBS=${JOBS:-8}

mkdir -p "$OUT"
cd "$SRC"

if [ ! -f "$OUT/.config" ]; then
  make ARCH=arm Muse.M-Tizen_release_defconfig
fi

[ -f include/linux/compiler-gcc6.h ] || \
  cp include/linux/compiler-gcc5.h include/linux/compiler-gcc6.h 2>/dev/null || true

# Same emulator/plumbing deltas as scripts/07, plus the thread_info fix.
cat >> "$OUT/.config" <<'EOF'
# CONFIG_ARCH_SDP is not set
CONFIG_ARCH_MULTIPLATFORM=y
CONFIG_ARCH_MULTI_V7=y
CONFIG_ARCH_VEXPRESS=y
CONFIG_ARCH_VEXPRESS_CA9X4=y
CONFIG_USE_OF=y
CONFIG_ARM_APPENDED_DTB=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_INITRD=y
# vexpress console (the SDP defconfig selects a different UART driver, so the
# PL011 used by QEMU's vexpress-a15 must be enabled explicitly or the guest
# boots with no console and QEMU exits silently)
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
CONFIG_ATAGS=y
# CONFIG_POWER_SAVING_MODE is not set
# CONFIG_ALWAYS_INSTANT_ON is not set
# CONFIG_VDFS4 is not set
# CONFIG_VDFS4_DEBUG is not set
# CONFIG_MMC is not set
# CONFIG_SDP_AVS is not set
# CONFIG_SDP_BUSERR is not set
# CONFIG_SDP_BUSMON is not set
# CONFIG_SDP_RUNTIME_PM is not set
# CONFIG_EMRG_SAVE_KLOG is not set
# CONFIG_SECURITY_SFD is not set
# CONFIG_SECURITY_SFD_MODE_ENFORCE is not set
# CONFIG_SECURITY_SFD_SECURECONTAINER_MODE_ENFORCE is not set
# --- the lane-private change ---
# CONFIG_KERNEL_STACK_LARGE is not set
# CONFIG_IRQ_STACK is not set
EOF

make ARCH=arm olddefconfig

echo "=== thread_info-relevant options ==="
grep -E "^(CONFIG_KERNEL_STACK_LARGE|CONFIG_KERNEL_STACK_SMALL|CONFIG_IRQ_STACK)=" "$OUT/.config" || echo "  (all unset - good)"

make ARCH=arm HOSTCFLAGS="-Wall -O2 -fcommon -Wno-error" -j"$JOBS" zImage dtbs 2>&1 | tail -8

echo "=== ABI parity assertion (must match the shipped binaries) ==="
gdb-multiarch -q -batch -ex "set pagination off" \
  -ex 'print/x (int)&((struct task_struct *)0)->cred' \
  -ex 'print/x (int)&((struct task_struct *)0)->fs' \
  -ex 'print/x (int)&((struct inode *)0)->i_size' \
  -ex 'print/x (int)&((struct super_block *)0)->s_bdev' \
  -ex 'print/x (int)&((struct thread_info *)0)->task' \
  "$OUT/vmlinux" 2>&1 | grep "= 0x"
echo "want: cred=0x320 fs=0x35c i_size=0x38 s_bdev=0x7c  thread_info.task=0xc"
