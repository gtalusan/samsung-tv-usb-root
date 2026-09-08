# Lead 005 — `szdrv_core.ko`: OOB reads in Samsung's proprietary in-kernel NTFS parser

**Status:** three confirmed out-of-bounds **read** primitives reachable at plain
mount time; no write primitive found yet. The classic USA/fixup bug class is
**absent** (properly validated) — that negative result is recorded below so
nobody re-treads it. Out of scope for the bounty (2019 model); research only.

| | |
|---|---|
| Module | `szdrv_core.ko` — the NTFS engine |
| Size / SHA256 | 289,466 bytes / `34927818d41ada950db63cfb57be0301489bb3cf24ff1569763aa89edd393bd5` |
| BuildID | `a4360fc0b488314087c2b3920dfa7c691da99b38` |
| Shim | `szdrv.ko`, 79,822 bytes, `c58b8af5c7a08c86823c70f0f5afa9acc29f2372e549b9c4b0edf28abcece1db` |
| License | `SamsungProprietary` (core) / `GPL` (shim) |
| Arch | ELF32 ARM, `ET_REL`, **not stripped** (348 `FUNC` symbols, full names retained) |
| Ghidra project | `SzdrvNtfs`, program `szdrv_core.ko` |

## Load layout (verified, not assumed)

Ghidra maps the `ET_REL` object with `.text` at **`0x10028`** (image base
`0x10000`, `.note.gnu.build-id` occupies `0x10000..0x10023`). So:

```
ghidra_addr = elf_symbol_value + 0x10028
```

Code is **ARM mode, not Thumb** — no bit-0 tagging, and the truncation pitfall
from the CEC work does not apply here. Verified with `SzdrvSurvey.java`:

```
=== FUNCTIONS: 371  (bodies <=8 bytes: 25) ===
  block .text size=0x2dd4c instructionBytes=0x2dbb0 functionBodyBytes=0x2dbb0
  ORPHANED (insn not in any function) = 0x0 bytes
```

Zero orphaned instruction bytes: function recovery is complete, so "no xrefs"
answers in this program can be trusted.

## Reachability — verified call chain, triggered by plain mount

```
szdrv.ko:  SZDrv_mount -> mount_bdev -> SZDrv_fill_super -> SZDrv_MountVol   (UND import)
szdrv_core.ko:
  SZDrv_MountVol @0x323f4
    -> SZDrv_ffsMountVol @0x3105c
       -> parse_vbr @0x1a6c4                    (boot sector)
       -> load_metadata_files @0x3bde0          (12 call sites to parse_mft_entry)
          -> get_mft_entry_with_sector @0x11f34 (reads $MFT, entry 0)
          -> parse_mft_entry @0x22a74
             -> check_attrs @0x12bb0
             -> parse_attrs @0x16100
                -> proc_data_attr @0x1324c
                -> proc_nres_attr @0x15b90
```

`load_metadata_files` reads MFT entry 0 and calls `parse_mft_entry` on it
immediately (decompile line ~75/91). **No readdir, open or read is needed** —
inserting the USB stick is sufficient, since `storaged` automounts.

## NEGATIVE RESULT — the fixup/USA bug class is properly closed

This is the bug class the task flagged as highest-value. It is **not present**.

`pre_proc_fixup_array` @ `0x106bc` itself performs no validation: it compares the
USN at `rec+usa_ofs` with `rec+0x1fe`, then writes `usa_count-1` halfwords at
`rec+0x3fe + n*0x200`. But **all four read-path callers validate first**:

| caller | validation before the call |
|---|---|
| `get_mft_entry` @0x214fc | `check_mft_entry_hdr` |
| `get_mft_entry_with_sector` @0x11f34 | `check_mft_entry_hdr` |
| `get_idx_record` @0x178fc | inline `rec[4]==vol[0x8c] && rec[6]==vol[0x90]` |
| `get_idx_record_with_sector` @0x14128 | same inline pair |

`check_mft_entry_hdr` @ `0x11a98` is strict:

- `usa_ofs` (rec+4) must be exactly **`0x2A` or `0x30`**
- `usa_count` (rec+6) must equal `vol+0x74` = `(mft_record_size>>9)+1`
- `attrs_offset` (rec+0x14) must equal `(usa_ofs + usa_count*2 + 7) & ~7`
- `bytes_allocated` (rec+0x1c) must equal `vol+0x68` (`mft_record_size`)
- `bytes_in_use` (rec+0x18) `<=` `bytes_allocated`

`parse_vbr` @ `0x1a6c4` in turn forces `mft_record_size ∈ {0x400, 0x1000}` and
`idx_record_size == 0x1000`, with a cluster-size allowlist
`{0x200,0x800,0x2000,0x8000}`. Since `usa_count` is *derived* from the validated
record size and the buffer is allocated at exactly that size, the fixup writes
land inside the buffer by construction. **Do not re-tread this path.**

(Note `post_proc_fixup_array` @ `0x10770`, the write path, *does* self-validate
`usa_ofs ∈ {0x2a, 0x30, vol[0x8c]}` — the asymmetry is real but harmless.)

## FINDING 1 — off-by-one in the attribute walk (`parse_mft_entry` @ `0x22a74`)

The bound on the attribute offset is applied **after** the attribute is used, and
uses `<` where `<=` is required.

Disassembly (`DumpAsm.java 0x22ac8 0x22b90`):

```
00022ad8  ldrh r4,[r5,#0x14]     ; r4 = ofs = mrec->attrs_offset
00022adc  ldr  r3,[r5,#0x1c]     ; r3 = mrec->bytes_allocated
00022ae0  cmp  r4,r3
00022ae4  bhi  0x00022b88        ; entry check: reject only if ofs > allocated
00022ae8  ldr  r3,[r5,r4]        ; type = *(u32*)(rec + ofs)
...
00022b1c  bl   0x00016100        ; parse_attrs(rec+ofs)          <-- USED
00022b28  ldr  r2,[r6,#0x4]      ; attr->length
00022b2c  ldr  r3,[r5,#0x1c]     ; bytes_allocated
00022b30  add  r4,r4,r2          ; ofs += attr->length
00022b34  cmp  r3,r4
00022b3c  bcc  0x00022b84        ; reject only if allocated < ofs   <-- CHECKED AFTER
00022b40  ldr  r3,[r5,r4]        ; type = *(u32*)(rec + ofs)  <-- ofs may == allocated
```

Because the comparison is `bytes_allocated < ofs` (strictly less), **`ofs ==
bytes_allocated` passes**. `check_mft_entry_hdr` forces `bytes_allocated` to equal
the allocation size, so the load at `0x22b40` reads 4 bytes **past the end of the
record buffer**. If those out-of-bounds bytes are not `0xFFFFFFFF`, the loop body
executes on a fully out-of-bounds attribute header, and `check_attrs` then reads
`attr->length` at `rec+allocated+4`.

**Attacker recipe:** with `mft_record_size = 0x400`, `attrs_offset` is forced to
`0x38`; supply one attribute with `length = 0x3c8` (≥`0x18`, 8-aligned,
≤`mft_record_size`, so `check_attrs` passes). Then `ofs = 0x38 + 0x3c8 = 0x400 ==
bytes_allocated` → passes → OOB load. The same shape exists in the second walk
(attribute-list extension records) at `0x22c60`+.

## FINDING 2 — unvalidated `name_length` on non-resident attributes (`proc_data_attr` @ `0x1324c`)

`check_attrs` has two branch-dependent gaps, both verified from disassembly
(`DumpAsm.java 0x12bb0 0x12dd0`):

```
00012bd0  ldrb r12,[r1,#0x8]     ; r12 = attr->non_resident
00012bd4  cmp  r12,#0x0
00012bd8  bne  0x00012c30        ; GAP 1: skip the size test when non-resident
00012bdc  ldr  r6,[r0,#0x240]
00012be0  ldr  r6,[r6,#0x68]     ; vol->mft_record_size
00012be4  cmp  lr,r6
00012be8  bls  0x00012c30        ; (resident only) reject attr_len > mft_record_size
...
00012d00  cmp  r12,#0x0
00012d04  beq  0x00012d68        ; GAP 2: name checks run ONLY when resident
00012d08  ldrh lr,[r1,#0xc]      ; non-resident falls through to flags/id checks only
```

- **GAP 1:** `attr_len > mft_record_size` is **never tested for non-resident
  attributes**. Only `attr_len >= 0x18` and `attr_len & 7 == 0` apply.
- **GAP 2:** the name-validation block at `0x12d68` (which enforces
  `name_offset == 0x18` and derives the expected content offset) is reached
  **only when `non_resident == 0`**. Types `0x10,0x30,0x40,0x70,0x90,0xd0` are
  forced resident at `0x12d60`, so they are safe; but types
  `0x20,0x50,0x60,0x80,0xb0,0xc0,0xe0,0x100` reach `0x12d08` with the name
  fields entirely unvalidated.

`proc_data_attr` then copies the name using that unvalidated length:

```
000132d0  ldrb r3,[r2,#0x9]      ; name_length (u8, up to 255)
00013410  cmp  r3,#0x0
00013414  add  r2,r2,#0x40       ; non-resident: src = attr + 0x40
0001341c  mov  r12,r3, lsl #0x1  ; byte count = name_length * 2
0001342c  ldrh r0,[r2],#0x2      ; copy loop, halfword at a time
00013434  strh r0,[r1],#0x2
```

**Destination is safe — explicitly checked, not assumed.** Prologue is
`stmdb sp!,{r4..r11,r12,lr,pc}` (44 bytes) + `sub sp,sp,#0x224`, buffer at
`r11-0x22c`. That gives 0x22c = 556 bytes of frame space for a maximum write of
`255*2 + 2 = 512` bytes. The 258-halfword buffer is deliberately sized for a
255-character name plus terminator. **This is not a stack overflow; do not
re-tread it.**

**Source is not safe.** For a non-resident DATA attribute (type `0x80`), the read
spans `attr+0x40 .. attr+0x23E` — up to **574 bytes beyond the attribute
header** — with no relationship to `attr_len` or the record end. The attribute
header can legally sit in the last `0x18` bytes of the record, so the read runs
roughly 550 bytes past the buffer. The out-of-bounds bytes are copied into a
kernel structure that subsequently drives name comparison
(`SZDrv_nls_uniname_cmp`) and attribute ordering.

## FINDING 3 — unvalidated `mapping_pairs_offset` (`proc_nres_attr` @ `0x15b90`)

```
00015bf0  ldrh r3,[r4,#0x20]     ; mapping_pairs_offset, raw u16 from disk
00015bf4  cpy  r2,r4
00015bfc  ldrb r4,[r4,r3]        ; first mapping-pairs byte at attr + that offset
00015c00  add  r7,r2,r3
```

No bound is applied to `mapping_pairs_offset` before it indexes the attribute.
Combined with GAP 1 (non-resident `attr_len` unbounded), this is a second
independent OOB read source, and it feeds the runlist decoder
(`len_bytes = b & 0xf`, `ofs_bytes = b >> 4`), so the OOB byte steers how many
further bytes are consumed.

## Buffer provenance — which OOB reads actually leave the object

`get_mft_entry` picks one of two buffers (decompile @ `0x214fc`):

- **`SZDrv_malloc(vol[0x68])`** when the record straddles a block boundary —
  a dedicated heap allocation of *exactly* `mft_record_size`. Reading past it
  touches adjacent SLAB objects.
- **`SZDrv_buf_getblk(...)`** otherwise — a pointer *into* a larger cache block,
  where a small overread may stay within the block (benign).

The attacker selects the path via VBR geometry (`sectors_per_cluster`,
`mft_record_size`) and the `$MFT` start cluster, so the malloc path is reachable
by construction. This matters: it is the difference between a harmless read and
an infoleak of adjacent kernel heap.

## Severity, honestly

All three are **reads**, not writes. Realistic impact:

1. **Kernel heap infoleak** — OOB bytes land in the attribute name, which drives
   comparison and ordering, and for a DATA attribute the name is the ADS name
   (potentially observable as a filename via directory listing). Not yet traced
   to a userspace-visible sink; treat as **unconfirmed exfiltration**.
2. **Mount-time crash / DoS** — unmapped read → kernel oops on a device that
   automounts. This one is near-certain.

Given no KASLR, no stack protector, and no module signing on this kernel, an
infoleak is a genuinely useful primitive for the delivery problem — but on its
own it is not code execution. **I did not find a write primitive.** The
attribute-walk off-by-one is the most promising place to keep looking, because a
fully OOB attribute header steers subsequent length arithmetic.

## Comparison with public NTFS bug history

`CVE-2018-12931` (`ntfs_attr_find` OOB, Linux `ntfs.ko`) and `CVE-2023-26607`
(OOB read in `ntfs_attr_find`, `fs/ntfs`) are the *same bug class* as Finding 1:
attribute-walk bounds applied incorrectly. Neither CVE applies directly — this is
a wholly separate proprietary implementation sharing no code with upstream — but
they confirm the class is real and historically exploitable. `CVE-2022-1973`,
`CVE-2023-26544`, `CVE-2023-26606` (ntfs3 UAF/OOB) are in code absent here.

## Next steps

1. Trace whether the OOB name bytes from Finding 2 reach userspace (directory
   listing of an ADS name, or `SZDrv_XattrList` @ `0x22cc8`). That decides
   infoleak vs. crash-only.
2. Follow the fully-OOB attribute header from Finding 1 into `proc_nres_attr`
   runlist decoding — an OOB-controlled `attr_len`/`mapping_pairs_offset`
   combination is the most plausible route to a write.
3. Audit `check_idx_entry` @ `0x14700`, `check_idx_entry_bdata` @ `0x10220` and
   `update_large_index` @ `0x1c404` for the index-B-tree classes (entry length 0
   → infinite loop; `Invalid bnode %p` / `Invalid child %p` strings suggest
   in-tree checks worth diffing).
4. Build an ARM harness: the parse functions take `(vol, buf, ...)` and are
   largely self-contained, so `parse_mft_entry` can be driven under `qemu-arm`
   with a synthetic vol struct — much cheaper than booting the real kernel.

## Reproduce

```sh
cd $REPO
# import (already done; project SzdrvNtfs)
nix develop --command bash -c '
  source tools/ghidra-env.sh; export GHIDRA_REPO=local
  ghidra_project SzdrvNtfs ignored -import binaries/szdrv_core.ko -analysisTimeoutPerFile 2400'

# load-layout / recovery sanity check
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh SzdrvNtfs szdrv_core.ko SzdrvSurvey.java'

# the three findings
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh SzdrvNtfs szdrv_core.ko DumpAsm.java 0x22ac8 0x22b90'   # Finding 1
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh SzdrvNtfs szdrv_core.ko DumpAsm.java 0x12bb0 0x12dd0'   # Finding 2 gaps
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh SzdrvNtfs szdrv_core.ko DumpAsm.java 0x15b90 0x15c40'   # Finding 3

# annotations (9 plate comments + SZDRV bookmarks)
nix develop --command bash -c 'export GHIDRA_REPO=local GHIDRA_WRITE=1
  tools/ghidra-run.sh SzdrvNtfs szdrv_core.ko SzdrvAnnotate.java'
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh SzdrvNtfs szdrv_core.ko SzdrvShowAnn.java'
```

ELF symbol value → Ghidra address: `+0x10028`.

## Caveat

Testing means writing a crafted NTFS volume to a USB stick and inserting it into
the owner's own TV. Expected worst case is a kernel oops at mount (the device
automounts, so it will retry). Have the verified USB recovery image
(`T-MSMDEUC.zip`) ready first.
