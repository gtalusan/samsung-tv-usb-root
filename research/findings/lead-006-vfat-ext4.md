# Lead 006 — vfat/msdos + ext4: unpatched 2018-era CVEs, and a Samsung vendor patch in ext4

**Status:** ext4 — **multiple known CVEs appear UNPATCHED in this build**, with
the vulnerable code shape confirmed by decompilation (not just by string
absence). The strongest is **CVE-2018-1093** (out-of-bounds read in
`ext4_validate_block_bitmap`), verified down to the faulting `ldr` instruction.
vfat/msdos — post-4.1 hardening commits are absent, but severity is capped at
DoS because `fat_ent_read()` already bounds-checks entries in 4.1.10.
No exploit written; no dynamic testing (no device access).
Out of scope for the bounty (2019 model); research only.

## Targets

| Target | Path | Size | sha256 (first 16) |
|---|---|---|---|
| `ext4.ko` | `…/modules/4.1.10/kernel/fs/ext4/ext4.ko` | 469,730 | `2dff03de09c82c18` |
| `jbd2.ko` | `…/modules/4.1.10/kernel/fs/jbd2/jbd2.ko` | 92,270 | `fbeb17bafaf8ffb3` |
| `mbcache.ko` | `…/modules/4.1.10/kernel/fs/mbcache.ko` | 16,130 | `87e5ad67823d99b6` |
| vfat/msdos | built into `out/uImage` (no `.ko`) | — | — |

`ext4.ko`: ELF32 ARM, `Type: REL`, `vermagic=9518079, release SMP preempt
mod_unload ARMv7 p2v8`, 566 `FUNC` symbols retained (module symbol tables are
not stripped — this made the analysis far easier than the userland binaries).

FAT is confirmed built-in, not a module — the kernel image contains
`fs/fat/{cache,dir,fatent,inode,namei_vfat,nfs}.c`. `fs/ext4/*.c` paths do **not**
appear in `uImage`, consistent with ext4 being module-only.

## VERIFIED: this is NOT stock 4.1.10 — Samsung ships a vendor patch in ext4

`ext4.ko` contains the mount-option token **`case_insensitive`**, which does not
exist anywhere in upstream v4.1.10:

```
0005a930  "%ccase_insensitive"   <- referenced by _ext4_show_options.isra.13 @ 0x28cec
0005cdc8  "case_insensitive"     <- in the match_table_t, token id 63
```

Upstream 4.1.10 `fs/ext4/super.c` has 69 `Opt_*` enumerators, ending at
`Opt_nojournal_checksum`, and **no** case-related option (`grep case_insensit
super.c` → nothing). Upstream's later case-folding feature (v5.2,
`ext4_has_feature_casefold`) spells its option **`casefold`**, never
`case_insensitive`. So this token is a **Samsung addition**, not a backport.

A second post-4.1 string is present: `"...called with null fname?!?"` — in
upstream this lives in `fs/ext4/dir.c` and *is* in 4.1.10, so that one is not
evidence of a patch (checked; listed here to record the negative).

**Consequence for this lane:** stock-source reasoning is not sufficient. Every
verdict below was therefore checked against the *binary*, not just the tree.
The vendor `case_insensitive` code path is itself unaudited attack surface —
Samsung-written string comparison in the ext4 directory-lookup path — and is
flagged as future work.

## VERIFIED UNPATCHED: CVE-2018-1093 — OOB read in `ext4_validate_block_bitmap`

Upstream fix: commit **`7dac4a1726a9`** *"ext4: add validity checks for bitmap
block numbers"* (`Cc: stable`, text says *"This issue has been assigned
CVE-2018-1093"*). It adds two things:

1. range checks in `ext4_valid_block_bitmap()`:
   `if (offset < 0 || EXT4_B2C(sbi, offset) >= sb->s_blocksize || …)`
2. a new guard in `ext4_read_block_bitmap_nowait()` with the distinctive error
   string `"Invalid block bitmap block %llu in block_group %u"`.

### Evidence the fix is absent

String markers from the fix — all **ABSENT** from `ext4.ko`:

```
"Invalid block bitmap block"   ABSENT
"Invalid inode bitmap blk"     ABSENT
```

while the surrounding 4.1.10-era strings **are** present, proving the strings
survived compilation and the absence is meaningful:

```
"Cannot get buffer for block bitmap - block_group = %u, block_bitmap = %llu"
"Cannot read block bitmap - block_group = %u, block_bitmap = %llu"
"bg %u: block %llu: invalid block bitmap"
```

Decompiled `ext4_read_block_bitmap_nowait` @ `0x000110b0` — the added guard is
simply not there; it goes from `ext4_block_bitmap()` straight to `__getblk_gfp()`:

```c
uVar15 = ext4_block_bitmap(param_1,iVar2);
puVar3 = (uint *)__getblk_gfp(...,(int)uVar15,...);   /* no range check on uVar15 */
```

Decompiled `ext4_validate_block_bitmap` @ `0x00010300` (body 856 bytes; extent
verified intact with `CheckExtent.java`, so this is not the truncation pitfall):

```c
local_48 = param_3 * *(int *)(iVar4 + 0xc) + *(int *)(*(int *)(iVar4 + 0x44) + 0x14);
lVar11  = ext4_block_bitmap(param_1,param_2);          /* attacker-controlled */
uVar8   = (int)lVar11 - local_48 >> (*(uint *)(iVar4 + 0x34) & 0xff);  /* offset */
uVar7   = uVar8;
if ((int)uVar8 < 0) { uVar7 = uVar8 + 0x1f; }          /* signed! only rounding */
if ((*(uint *)(param_4[7] + ((int)uVar7 >> 5) * 4) >> (uVar8 & 0x1f) & 1) != 0) {
```

`param_4[7]` is `bh->b_data`. The index derives from
`ext4_block_bitmap(desc) - group_first_block`, is treated as **signed**, and is
never compared against `sb->s_blocksize`. The `< 0` test is arithmetic rounding
for the shift, not a bounds check.

Faulting instruction sequence (`DumpAsm.java 0x10478 0x104c4`):

```
00010484  bl   0x0002913c          ; ext4_block_bitmap()  -> attacker value
0001049c  ldr  r2,[r11,#-0x44]     ; group_first_block
000104a0  sub  r3,r3,r2            ; offset = blk - group_first_block
000104a8  mov  r3,r3, asr r1       ; >> cluster_bits   (ARITHMETIC shift: signed)
000104b0  add  r0,r3,#0x1f
000104b8  cpylt r3,r0              ; negative-rounding only
000104bc  mov  r3,r3, asr #0x5     ; /32 -> word index
000104c0  ldr  r3,[r2,r3,lsl #0x2] ; *** OOB READ: bh->b_data[idx] ***
```

`0x104c0` is the out-of-bounds load. With a 64-bit `ext4_block_bitmap` value the
index is fully attacker-chosen and can be far outside the 1–4 KB buffer, in
either direction.

**Verdict: ABSENT (still vulnerable).** Class: OOB **read** → info leak / panic.
Not a write primitive, so on its own this is a DoS-plus-oracle, not code exec.

## VERIFIED UNPATCHED: three more from the 2018 cluster

| CVE | Upstream fix | Marker checked | Verdict |
|---|---|---|---|
| **CVE-2018-11412** `ext4_read_inline_data()` memcpy with untrusted length | `117166efb1ee` "do not allow external inodes for inline data" | `"inline data xattr refers to an external xattr inode"` | **ABSENT → vulnerable** |
| **CVE-2018-1095** `ext4_xattr_check_entries()` xattr size validation | fix **renames** `ext4_xattr_check_names` → `ext4_xattr_check_entries` | binary exports **`ext4_xattr_check_names`** (the pre-fix name); no `ext4_xattr_check_entries` symbol | **ABSENT → vulnerable** |
| **CVE-2018-1092** `ext4_iget()` root dir with zero `i_links_count` | adds `"root inode unallocated"` | string ABSENT | **ABSENT → vulnerable** (marker-only evidence) |

The `ext4_xattr_check_names` symbol is the cleanest single proof in this report:
the upstream fix *renamed the function*, so the old name existing in the symbol
table is direct evidence of pre-fix code, independent of string tables.

`inline_data` is heavily present (29 string hits, `ext4_convert_inline_data_*`,
`ext4_try_to_write_inline_data`, …), so CVE-2018-11412's code is compiled in,
not configured out.

## vfat/msdos: hardening commits absent, but severity capped

Post-4.1 `fs/fat` fixes checked against `uImage`:

| Commit | Subject | Marker | Verdict |
|---|---|---|---|
| `0afa9626667c` | fat: validate `->i_start` before using | `"invalid start cluster (i_pos"` | ABSENT |
| `a3082d526f2d` | fat: add simple validation for directory inode | `"corrupted directory (invalid entries)"` / `"(invalid i_start)"` | ABSENT |
| `34df117414d7` | fat: fix error message for bogus number of directory entries | `"bogus number of directory entries"` | ABSENT |

Baseline sanity — 4.1.10-era FAT strings that *are* present, proving the image's
FAT strings are intact and the absences above are real:

```
"%s: detected the cluster chain loop (i_pos %lld)"
"Corrupted directory (i_pos %lld)"
" (%s) Directory bread(block %llu) failed"
"(%s) FAT read failed (blocknr %llu)"
```

**A trap I nearly fell into, recorded so nobody repeats it:** commit
`0afa9626667c` *also* reflows the cluster-chain-loop message from two source
lines onto one. The shipped image has it on one line, which looks like the fix is
present. It is not evidence — C concatenates adjacent string literals, so 4.1.10's
two-line spelling compiles to the identical byte sequence. Only the *added guard
string* is a valid marker, and that is absent.

**Severity assessment (why FAT is the weaker lane):** in 4.1.10,
`fat_ent_read()` already does
`if (entry < FAT_START_ENT || sbi->max_cluster <= entry) return -EIO;`, so a wild
cluster number is rejected at the FAT-entry layer. `fat_valid_entry()` does not
exist in 4.1.10 (introduced later); the missing `fat_get_cluster()` guard
therefore mostly exposes the pre-existing `BUG_ON(MSDOS_I(inode)->i_start == 0)`
— a panic/DoS, not memory corruption. I could not confirm `CONFIG_BUG` from the
image (no `"kernel BUG at"` string found), so whether that `BUG_ON` compiles to a
trap or to nothing is **UNDETERMINED**.

## Reachability (USB threat model)

Verified in `storaged`'s `module_block.so`:

```
/home/abuild/rpmbuild/BUILD/storaged-1.0.0/src/block/ext4.c
ext4_match      ext4_mount
"%s: %s(%d) > ext4 search magic : 0x%2x, 0x%2x"
"%s: %s(%d) > failed to match with ext4(%s)"
"%s: %s(%d) > Storage Mounted[ext4]"
```

So ext4 is detected by on-disk magic and mounted automatically, same as exfat
(`"Storage Mounted [exfat]"`). `libblkid` probes `ext2/ext3/ext4/vfat/exfat/ntfs`.
Chain: **insert USB → udev → `block_mount_device` → `mount(…, "ext4", …)` →
`ext4_fill_super` → group-descriptor / bitmap parsing → `ext4_validate_block_bitmap`**.
No pairing, no network, no Developer Mode.

`ext4.ko` is a module, but `/etc/modprobe.d/modprobe.conf` and normal
`get_fs_type()` autoloading pull it in on demand.

Combined with the kernel hardening already established (Linux 4.1.10, **no stack
protector, no KASLR, no RODATA/text write-protect, no module signing,
`kptr_restrict` unset**), an OOB read here leaks kernel memory with no
mitigation to defeat — useful as the info-leak half of a chain whose LPE half
the SamyGO researcher already has.

## Negative results (do not re-tread)

- The single-line `"detected the cluster chain loop"` string is **not** evidence
  of `0afa9626667c` (string-literal concatenation). See above.
- `"called with null fname?!?"` **is** in upstream 4.1.10 `fs/ext4/dir.c`; it is
  not a backport marker.
- `ext4_valid_block_bitmap`'s `if ((int)uVar8 < 0)` is **not** a bounds check —
  it is the standard negative-rounding idiom before an arithmetic right shift.
- `ext4_validate_block_bitmap` body extent is intact (856 bytes over a 860-byte
  range) — this function is *not* affected by the ARM/Thumb truncation pitfall.
- FAT is not a promising memory-corruption target on this build:
  `fat_ent_read()` bounds-checks entries, capping the missing guards at DoS.
- CVE-2016-10208 (meta_bg): `add_new_gdb_meta_bg` / `ext4_convert_meta_bg` are
  present but I did **not** verify the fix state. UNDETERMINED, not claimed.

## What I did NOT cover

- `jbd2.ko` and `mbcache.ko` were identified and hashed but not analysed
  (CVE-2018-10882/10883 live in jbd2 — untested here).
- The extent-tree CVEs (CVE-2018-10876/10877/10878/10879/10880/10881) were not
  individually verified; given four confirmed-absent fixes from the same 2018
  batch, they are *likely* also unpatched, but that is **inference, not verified**.
- No dynamic testing: no device, and no ARM VM harness was built.
- The Samsung `case_insensitive` vendor code path was located but not decompiled.
- CVE-2018-1092's verdict rests on a missing string only; I did not decompile
  `ext4_iget` to confirm the missing check (weaker evidence than 1093/1095).

## Next steps

1. **Decompile the vendor `case_insensitive` path** — Samsung-written name
   comparison reached during directory lookup on a mounted volume is unaudited,
   vendor-specific attack surface, and is the most likely place to find a *write*
   primitive rather than a read. Start at `_ext4_show_options.isra.13 @ 0x28cec`
   for the option, then find the consumer in `ext4_find_entry` / `ext4_match`.
2. Verify the extent-tree 2018 cluster (10876–10881) individually — those include
   OOB **writes** (`ext4_ext_drop_refs`, `ext4_update_inline_data`), which matter
   far more than 1093's read.
3. Check `jbd2.ko` for CVE-2018-10882/10883.
4. Build a QEMU ARM harness with this exact `uImage` + `ext4.ko` and replay
   crafted images (`debugfs`/`mke2fs` + targeted group-descriptor corruption)
   to confirm CVE-2018-1093 dynamically.
5. Confirm `CONFIG_BUG` state to settle FAT's `BUG_ON` severity.

## Reproduce

```sh
cd $REPO

# import (already done; project VfatExt4, program ext4.ko)
nix develop --command bash -c '
  source tools/ghidra-env.sh; export GHIDRA_REPO=local
  ghidra_project VfatExt4 ignored -import binaries/ext4.ko -analysisTimeoutPerFile 2400'

# the OOB read
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh VfatExt4 ext4.ko DecompileFns.java ext4_validate_block_bitmap'
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh VfatExt4 ext4.ko DumpAsm.java 0x10478 0x104c4'
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh VfatExt4 ext4.ko CheckExtent.java 0x10300 0x10660'

# vendor patch discovery
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh VfatExt4 ext4.ko Ext4FindString.java case_insensitive'
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh VfatExt4 ext4.ko Ext4MatchTable.java 0x5cdc8'

# upstream-vs-binary string delta (fetch sources first, ~22 KB)
B="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain"
mkdir -p /tmp/v4110/ext4 && for f in super.c inline.c extents.c namei.c xattr.c \
  balloc.c ialloc.c inode.c dir.c mballoc.c ext4.h; do
  curl -sL "$B/fs/ext4/$f?h=v4.1.10" -o /tmp/v4110/ext4/$f; done
python3 tools/ext4_string_delta.py binaries/ext4.ko /tmp/v4110/ext4 16

# fix-marker checks
strings -a binaries/ext4.ko | grep -aF "Invalid block bitmap block"          # ABSENT
strings -a binaries/ext4.ko | grep -aF "inline data xattr refers"            # ABSENT
strings -a binaries/ext4.ko | grep -aF "ext4_xattr_check_names"              # PRESENT (pre-fix name)
strings -a $FIRMWARE_WORKDIR/out/uImage | grep -aF "invalid start cluster"  # ABSENT
```

Upstream patches used: `7dac4a1726a9` (CVE-2018-1093), `117166efb1ee`
(CVE-2018-11412), `0afa9626667c`, `a3082d526f2d`, `34df117414d7` (fs/fat),
fetched via `git.kernel.org/…/stable/linux.git/patch/?id=<hash>`.
