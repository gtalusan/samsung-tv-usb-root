#!/usr/bin/env bash
# Build Linux 4.1.10 for QEMU 'virt' (ARMv7), configured to match the vendor
# kernel's ABI-relevant options so the extracted Samsung .ko files can be
# insmod'ed against it.
#
# Runs inside the samsung-kbuild container (GCC 6.4 cross toolchain).
set -euo pipefail

LAB=/work
SRC=$LAB/src/linux-4.1.10
JOBS=${JOBS:-$(nproc)}

cd "$LAB/src"
[ -d linux-4.1.10 ] || tar -xf linux-4.1.10.tar.xz
cd "$SRC"

# 4.1.10 predates GCC 6 and only ships compiler-gcc{3,4,5}.h; the version
# dispatch in compiler-gcc.h then fails on our 6.4 toolchain. The gcc5 header
# is correct for 6.x here (no new attribute handling is needed).
[ -f include/linux/compiler-gcc6.h ] || \
  cp include/linux/compiler-gcc5.h include/linux/compiler-gcc6.h

# ---------------------------------------------------------------------------
# Base: 'virt' machine. vexpress needs a DTB and more device plumbing; virt
# gives us virtio-blk (to hand the crafted filesystem image to the guest) and
# a PL011 console with almost no configuration.
# ---------------------------------------------------------------------------
if [ ! -f .config ]; then
  make ARCH=arm vexpress_defconfig
fi

# ---------------------------------------------------------------------------
# ABI parity with the vendor kernel. The vendor modules carry:
#   vermagic = "9518079, release SMP preempt mod_unload ARMv7 p2v8"
# Every token there implies a config option, and each one that differs changes
# struct layouts or locking primitives and would desync the module's view of
# kernel structures:
#   SMP         -> CONFIG_SMP           (spinlock_t size, per-cpu layout)
#   preempt     -> CONFIG_PREEMPT
#   mod_unload  -> CONFIG_MODULE_UNLOAD
#   ARMv7       -> CONFIG_CPU_V7
#   p2v8        -> CONFIG_ARM_PATCH_PHYS_VIRT
# CONFIG_SECURITY is enabled because the vendor runs SMACK, and it adds
# ->i_security to struct inode; omitting it would shift every field after it.
# ---------------------------------------------------------------------------
cat >> .config <<'EOF'
CONFIG_ARCH_VIRT=y
CONFIG_SMP=y
CONFIG_PREEMPT=y
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_MODULE_FORCE_UNLOAD=y
# deliberately NOT set: CONFIG_MODVERSIONS (we patch vermagic, symbol CRCs
# would be an additional and unnecessary mismatch to fight)
CONFIG_ARM_PATCH_PHYS_VIRT=y
CONFIG_SECURITY=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_NLS=y
CONFIG_NLS_DEFAULT="utf8"
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_ISO8859_1=y
CONFIG_NLS_UTF8=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_TMPFS=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_MAGIC_SYSRQ=y
# --- instrumentation: we WANT to detect corruption in the lab, even though
# --- the real TV kernel has none of this. That asymmetry is the point: the
# --- lab detects, the target is defenceless.
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_FRAME_POINTER=y
CONFIG_ARM_UNWIND=y
CONFIG_DEBUG_STACKOVERFLOW=y
CONFIG_SCHED_STACK_END_CHECK=y
CONFIG_CC_STACKPROTECTOR_STRONG=y
CONFIG_DEBUG_SLAB=y
CONFIG_DEBUG_SPINLOCK=n
CONFIG_PANIC_ON_OOPS=y
# --- struct module ABI parity (this is load-bearing) ---------------------
# The vendor .ko files embed a __this_module whose .exit / .arch / unload
# fields are laid out per the VENDOR kernel's struct module. In 4.1 the
# CONFIG_KALLSYMS block (symtab/strtab/sect_attrs/notes_attrs) sits BEFORE
# the CONFIG_MODULE_UNLOAD block (source_list/target_list/exit/refcnt), so
# enabling KALLSYMS here while the vendor built without it shifts every
# field the module loader touches after that point -- which is exactly where
# add_usage_links() oopsed (use->target NULL).
# Evidence the vendor kernel has KALLSYMS off: its uImage contains no
# "kallsyms" or "/proc/kallsyms" strings at all.
# Cost: oops traces lose symbol names. That is fine -- resolve addresses with
# gdb-multiarch against vmlinux, which we do anyway.
# --- struct inode parity -------------------------------------------------
# The vendor modules read inode->i_size at 0x38; a build without POSIX ACLs
# puts it at 0x30. The missing 8 bytes are i_acl + i_default_acl. Without
# this, exfat's i_size_read() spins forever on a bogus seqcount (observed:
# infinite loop in bdev_open+0x74).
CONFIG_FS_POSIX_ACL=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_EXT4_FS_POSIX_ACL=y
# --- struct task_struct parity ------------------------------------------
# Vendor: cred @ 0x320, fs @ 0x35c (delta 0x3c). A stock build gives delta
# 0xb8 because struct thread_struct embeds debug_info with the ARM hardware
# breakpoint slots, which CONFIG_HAVE_HW_BREAKPOINT (selected via
# CONFIG_PERF_EVENTS on ARMv7) pulls in. Dropping perf shrinks that gap.
# This is config parity, NOT a struct patch: nothing in the kernel source is
# modified, so the lab kernel stays a legitimate 4.1.10 build.
# CONFIG_PERF_EVENTS is not set
# CONFIG_HAVE_HW_BREAKPOINT is not set
# CONFIG_HW_BREAKPOINT is not set
# Remaining delta (cred +36, fs +4) is NOT yet solved. Config-level fitting
# was attempted and abandoned: CONFIG_SCHEDSTATS also embeds sched_statistics
# inside sched_entity (inline in task_struct), overshooting cred to 0x40c.
# Toggling configs has cascading layout effects -- use the real vendor .config.
# cred sat at 0x2fc (need 0x320, +36) and fs at cred+0x38 (need +0x3c, +4).
#   sched_info (via SCHEDSTATS)  = +32 \ both sit before cred
#   sched_task_group (CGROUP_SCHED) = +4 /
#   last_switch_count (DETECT_HUNG_TASK) = +4, between cred and fs
# Do NOT use BLK_DEV_IO_TRACE for the +4: it selects TRACEPOINTS, which adds
# fields to struct module and re-breaks module loading.
# These three are guesses that happen to land the offsets; replace them with
# the real vendor .config (18_DTV_KantM2 / 20_DTV_KantS2_0) when available.
CONFIG_EXPERT=y
# CONFIG_KALLSYMS is not set
# CONFIG_KALLSYMS_ALL is not set
# CONFIG_MODULE_SIG is not set
# CONFIG_DEBUG_SET_MODULE_RONX is not set
# CONFIG_FTRACE is not set
# CONFIG_TRACEPOINTS is not set
CONFIG_GDB_SCRIPTS=y
CONFIG_KGDB=y
CONFIG_KGDB_SERIAL_CONSOLE=y
EOF

make ARCH=arm olddefconfig

echo "=== effective config (ABI-relevant) ==="
grep -E "^CONFIG_(SMP|PREEMPT|MODULE_UNLOAD|CPU_V7|ARM_PATCH_PHYS_VIRT|SECURITY|MODVERSIONS|DEBUG_SLAB|CC_STACKPROTECTOR)" .config || true

make ARCH=arm HOSTCFLAGS="-Wall -O2 -fomit-frame-pointer -fcommon -Wno-error" -j"$JOBS" zImage modules 2>&1 | tail -20

echo "=== artifacts ==="
ls -l arch/arm/boot/zImage vmlinux
echo "=== our kernel's vermagic (modules must match this) ==="
strings -a fs/nls/nls_cp437.ko 2>/dev/null | grep -a ^vermagic= || \
  echo "vermagic=$(cat include/config/kernel.release 2>/dev/null) ..."
