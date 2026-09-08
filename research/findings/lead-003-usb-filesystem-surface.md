# Lead 003 — USB filesystem attack surface (kernel), incl. proprietary NTFS

**Status:** surface enumeration, no bug yet. This is the strongest ingress
candidate found so far — it is kernel-side, auto-triggered, and closed-source.
Out of scope for the bounty (2019 model); research only.

## What the TV will mount from a USB stick

`storaged` (`/usr/lib/storaged/module_block.so`, built from `storaged-1.0.0`)
drives mounting. Filesystem types it dispatches on:

| FS | Implementation | Origin | Notes |
|---|---|---|---|
| `vfat` / `msdos` | **built into the kernel** | upstream | FAT12/16/32 |
| `exfat` | `exfat_core.ko` + `exfat_fs.ko` | Samsung (sdFAT lineage), `license=GPL` | `exFAT: Core Version %s` |
| `ext4` | `ext4.ko` (+`jbd2.ko`, `mbcache.ko`) | upstream | |
| `ntfs` | **`szdrv.ko` + `szdrv_core.ko`** | **`license=SamsungProprietary`** | see below |
| `squashfs`, `fuse` | built into the kernel | upstream | not used by the USB automount path |

**Not supported** (no driver, no kernel string): HFS/HFS+, UDF, ISO9660, XFS,
btrfs, F2FS, JFS, ReiserFS, minix (an `fsck.minix` binary exists but no driver).

Mount options observed in `module_block.so`:

```
uid=0,gid=10001,dmask=0000,fmask=0111,iocharset=utf8,shortname=mixed,errors=continue,usefree,flush,nfs
smackfsroot=System::Shared
```

`fmask=0111` strips the execute bit from files. Whether `MS_NOSUID`/`MS_NODEV`/
`MS_NOEXEC` are also applied is **unconfirmed** — no such strings appear, so the
flags are likely passed numerically; needs a decompile of `block_mount_device`.

## The interesting part: NTFS is Samsung-proprietary kernel code

`storaged` contains `src/block/ntfs.c` with `ntfs_mount`, and the log string
gives the dispatch away:

```
%s: %s(%d) > Calling mount with %s %s szdrv %lu %s
%s: %s(%d) > Storage Mounted [ntfs]
```

So an NTFS volume is mounted with fstype **`szdrv`**. There is no `ntfs.ko`, no
`ntfs-3g`, and no NTFS support in the kernel image — `szdrv_core.ko` *is* the
NTFS implementation:

```
szdrv_core.ko   289,466 bytes   license=SamsungProprietary
  "NTFS Version : %hd.%hd"
  parse_mft_entry            check_mft_entry_hdr
  parse_mft_entry_cont       parse_mft_entry_header
  check_mft_file
  "%s: MFT entry %u: Fixup offset is invalid: 0x%hx"
  "%s: MFT entry %u: Fixup entries is invalid: 0x%hx"
  "%s: MFT entry %u: invalid attribute offset: 0x%hx 0x%hx"
  "Invalid ATTR List %p"     "Invalid bnode %p, dp %p"
```

That is ~283 KB of closed-source, in-kernel MFT / fixup-array / attribute-list /
index-B-tree parsing, operating on fully attacker-controlled bytes.

`szdrv.ko` (GPL, 79 KB) is the thin VFS shim that calls `register_filesystem`
with name `szdrv`; `szdrv_core.ko` is the proprietary engine underneath.

## Why this is the best lead so far

1. **Trigger is trivial and physical:** insert a USB stick. `storaged` uses a
   udev monitor (`udev_monitor_filter_add_match_subsystem_devtype`) and calls
   `block_mount` / `block_mount_device` automatically. No pairing, no network,
   no Dev Mode, no user confirmation beyond plugging it in.
2. **Modules load on demand** — `/etc/modprobe.d/modprobe.conf` aliases
   `fs-szdrv → szdrv`, `fs-exfat → exfat_fs`, `fs-sntfs → sntfs_fs`, so the
   kernel pulls the parser in when the filesystem type is detected.
3. **It lands in the kernel**, where the mitigations are worst (see below).
4. **Closed source, no upstream review.** Unlike ext4/vfat, `szdrv_core` has
   never had public scrutiny or syzkaller coverage. Samsung's exFAT has a
   history of CVEs; this NTFS engine has had none found because nobody has
   looked at it.

Kernel context that makes a corruption bug here worth a lot (from the hardening
audit): **Linux 4.1.10** (2015 kernel, built Dec 2024), **no stack protector**,
**no kernel text write-protect**, **no KASLR**, **no module signing**,
`kptr_restrict` unset. The SamyGO researcher already has a working, verified
kernel LPE payload for 1500.9 and is blocked purely on *delivery* — a kernel-mode
filesystem parser bug is a delivery mechanism.

## Next steps

1. Load `szdrv_core.ko` into the Ghidra project (ARM32, 4.1.10 module) and map
   `parse_mft_entry` / `parse_mft_entry_header` / `check_mft_entry_hdr` /
   the fixup-array handling. Fixup arrays are the classic NTFS bug class:
   an `update sequence array` offset/count that is validated loosely lets you
   write outside the MFT record buffer.
2. Confirm the mount flags in `block_mount_device` (`MS_NOSUID`/`MS_NODEV`).
3. Differential-fuzz the parser: `ntfs-3g`/`mkntfs` to generate volumes, mutate
   MFT records, and run against `szdrv` under an ARM VM with the same kernel.
   Note this needs a 4.1.10 ARM kernel + the proprietary module — QEMU + the
   extracted `uImage` is the realistic harness.
4. Same treatment for `exfat_core.ko` (63 KB, GPL so easier — and Samsung exFAT
   has prior CVEs worth diffing against this vintage).

## Caveat

Testing this means writing malformed filesystems to a USB stick and plugging it
into your own TV. Worst realistic case is a boot loop / corrupted storage, so
have the USB recovery path (`T-MSMDEUC.zip`, already downloaded and verified)
ready before starting.
