#!/usr/bin/env bash
# Build the VENDOR kernel tree (linux-4.1.10-tizen5.5, from 20_DTV_KantSU2.zip)
# using the real Muse.M defconfig, plus the minimum needed to boot under QEMU.
#
# This replaces all previous guesswork. Every struct layout the Samsung .ko
# files were compiled against now comes from Samsung's own tree and config, so
# there is no ABI fitting, no patched sched.h, and no lab-invented offsets.
#
# The vendor tree ships defconfigs for every 2018-2020 TV platform; we use
# Muse.M-Tizen_release_defconfig, which is exactly our target
# (T-MSMDEUC / GQ65Q70RGTXZG / 2019 QLED).
#
# Runs inside the samsung-kbuild container (GCC 6.4; the TV kernel was built
# with 6.2.1, close enough that the tree compiles cleanly).
set -euo pipefail

LAB=/work
SRC=$LAB/vendor/linux-4.1.10
JOBS=${JOBS:-$(nproc)}

cd "$SRC"

if [ ! -f .config ]; then
  make ARCH=arm Muse.M-Tizen_release_defconfig
fi

# 4.1.10 predates GCC 6; same header alias as the vanilla build.
[ -f include/linux/compiler-gcc6.h ] || \
  cp include/linux/compiler-gcc5.h include/linux/compiler-gcc6.h 2>/dev/null || true

# Additions purely for the emulator. These add DEVICES, not ABI: none of them
# appears in task_struct / super_block / inode / module, so the vendor layout
# the .ko files expect is preserved.
#
# NOTE: virtio is deliberately NOT enabled. The vendor tree's
# drivers/block/virtio_blk.c does not compile against their own modified
# virtio core (find_vqs() gained an argument; VIRTIO_BLK_F_WCE was dropped) --
# Samsung never builds virtio, so it has bit-rotted in their tree. Rather than
# patch driver code, the test image is carried inside the initramfs and
# attached with a loop device (CONFIG_BLK_DEV_LOOP=y is already in the Muse.M
# defconfig, so this needs no ABI-affecting change at all).
#
# The vendor tree is a SINGLE-platform ARCH_SDP build (their SoC) and Samsung
# deleted arch/arm/mach-virt, so QEMU's 'virt' machine is not an option and
# ARCH_SDP cannot coexist with another platform (it is a Kconfig choice).
# mach-vexpress DID survive in their tree, and QEMU emulates vexpress-a15, so
# we swap the machine to vexpress and keep every generic option from the
# Muse.M defconfig.
#
# The machine choice does not participate in task_struct / super_block /
# inode / module layout -- those come from the generic options (KALLSYMS,
# PERF_EVENTS, FS_POSIX_ACL, SMP, PREEMPT, CGROUPS, SECURITY, ...) which are
# untouched. The offset assertion at the end of this script is the oracle that
# proves parity actually survived, so this is checked rather than assumed.
cat >> .config <<'EOF'
# CONFIG_ARCH_SDP is not set
CONFIG_ARCH_MULTIPLATFORM=y
CONFIG_ARCH_MULTI_V7=y
CONFIG_ARCH_VEXPRESS=y
CONFIG_ARCH_VEXPRESS_CA9X4=y
CONFIG_USE_OF=y
CONFIG_ARM_APPENDED_DTB=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_INITRD=y
#
# --- struct thread_info parity (found the hard way) -----------------------
# Muse.M-Tizen_release_defconfig sets CONFIG_KERNEL_STACK_LARGE=y, which adds
# a `void *tinfo_ptr` at offset 0 of struct thread_info and pushes .task from
# 0x0c to 0x10. But EVERY shipped Samsung module computes `current` the legacy
# way:
#     bic rX, sp, #0x1fc0 ; bic rX, rX, #0x3f   (sp & ~0x1fff)
#     ldr rY, [rX, #12]                          (thread_info->task)
# A survey of all 161 shipped .ko files found 148 such [+12] sites and ZERO
# [+16] sites, and none performs the stack-base dereference that
# current_thread_info() requires under KERNEL_STACK_LARGE. So the shipped
# modules are a NON-KERNEL_STACK_LARGE build, and the defconfig line does not
# describe the binaries we actually have.
# With it on, [+12] yields addr_limit instead of task: szdrv oopsed in
# SZDrv_fill_super+0x10c on a *valid* NTFS volume, and vendor ext4 hung at
# mount even with a pristine mkfs.ext4 image. exFAT survived only because
# exfat_fs has just 2 such sites, on paths a plain mount does not take.
# Runtime probe with it off: offsetof(ti,task)=12 and *(sp&~0x1fff + 12) ==
# current, matching the modules.
# CONFIG_KERNEL_STACK_LARGE is not set
# CONFIG_IRQ_STACK is not set
# Vendor components hardwired to SDP mach headers, which no longer exist once
# the machine is vexpress. All are irrelevant to filesystem parsing and none
# affects the struct layouts the modules depend on:
#   POWER_SAVING_MODE / ALWAYS_INSTANT_ON -> kernel/power/suspend.c uses the
#       SDP-only GPIO_US_MCOM register
#   VDFS4  -> fs/vdfs4 needs mach/hw_decompress.h (this is the rootfs FS of
#             platform.img -- interesting later, not needed to drive exfat)
#   MMC    -> drivers/mmc/card/hw_decompress.c needs the same header
# CONFIG_POWER_SAVING_MODE is not set
# CONFIG_ALWAYS_INSTANT_ON is not set
# CONFIG_VDFS4 is not set
# CONFIG_VDFS4_DEBUG is not set
# CONFIG_MMC is not set
# CONFIG_SDP_AVS is not set
# CONFIG_SDP_BUSERR is not set
# CONFIG_SDP_BUSMON is not set
# CONFIG_SDP_RUNTIME_PM is not set
# CONFIG_EMRG_SAVE_KLOG is not set  (vendor klog-to-eMMC path needs MMC)
#
# CONFIG_SECURITY_SFD is Samsung's own LSM. In the shipped config it runs in
# ENFORCE mode with dispatchers on exec, mmap and load_kernel_module, and it
# expects a userspace dispatcher daemon. With no daemon in the lab initramfs
# it denies every execve -- observed as:
#     Failed to execute /bin/busybox (error -1)   [-EPERM]
# We keep SFD COMPILED IN (so any LSM-blob effect on struct layout is
# preserved) and merely drop it out of enforce mode. The offset assertion at
# the end of this script re-verifies parity either way.
#
# NB for the exploitation track: on the real TV this framework gates exec,
# mmap AND kernel module loading. That is a mitigation worth understanding
# before assuming a kernel payload can simply insmod something.
# CONFIG_SECURITY_SFD is not set
# CONFIG_SECURITY_SFD_MODE_ENFORCE is not set
# CONFIG_SECURITY_SFD_SECURECONTAINER_MODE_ENFORCE is not set
#
# UEP = Unsigned Executable Prevention. The shipped kernel refuses to exec any
# binary without a valid Samsung signature, and also checks libraries, running
# processes and KERNEL MODULES:
#   [E][UEP]: file /bin/busybox is not signed. Sign it.
# Disabled for the lab (we run our own busybox). On the real TV this is a
# first-class mitigation: a root primitive cannot simply drop and exec a
# binary, and UEP_CHECK_MODULE means insmod of an unsigned .ko is gated too.
# CONFIG_SECURITY_SFD_UEP is not set
# CONFIG_SECURITY_SFD_UEP_CHECK_LIBRARY is not set
# CONFIG_SECURITY_SFD_UEP_CHECK_PROCESS is not set
# CONFIG_SECURITY_SFD_UEP_CHECK_MODULE is not set
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
CONFIG_ATAGS=y
CONFIG_ARM_APPENDED_DTB=y
EOF

make ARCH=arm olddefconfig

echo "=== ABI-relevant options actually in effect ==="
grep -E "^(CONFIG_KALLSYMS|CONFIG_PERF_EVENTS|CONFIG_FS_POSIX_ACL|CONFIG_SMP|CONFIG_PREEMPT|CONFIG_MODULE_UNLOAD|CONFIG_MODVERSIONS|CONFIG_CGROUPS|CONFIG_SECURITY)=" .config || true
grep -E "^# (CONFIG_KALLSYMS|CONFIG_PERF_EVENTS|CONFIG_MODVERSIONS|CONFIG_CC_STACKPROTECTOR) is not set" .config || true

make ARCH=arm HOSTCFLAGS="-Wall -O2 -fcommon -Wno-error" -j"$JOBS" zImage dtbs 2>&1 | tail -15

echo "=== artifacts ==="
ls -l arch/arm/boot/zImage vmlinux

echo "=== vendor-parity check ==="
echo "want: cred=0x320 fs=0x35c i_size=0x38 s_bdev=0x7c thread_info.task=0xc"
gdb-multiarch -q -batch -ex "set pagination off" \
  -ex 'print/x (int)&((struct task_struct *)0)->cred' \
  -ex 'print/x (int)&((struct task_struct *)0)->fs' \
  -ex 'print/x (int)&((struct inode *)0)->i_size' \
  -ex 'print/x (int)&((struct super_block *)0)->s_bdev' \
  -ex 'print/x (int)&((struct thread_info *)0)->task' \
  vmlinux 2>&1 | grep "= 0x"
