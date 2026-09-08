# Lead 004 — exFAT: unbounded kernel stack overflow from directory metadata (CVE-2023-4273 class, unfixed)

**Status:** **strong lead — vulnerable code shape VERIFIED PRESENT in this
build.** The upstream fix for this exact defect (commit `d42334578eba`,
Jul 2023, → CVE-2023-4273) is **absent** from this binary. Reachable by listing
a directory on an attacker-supplied USB stick. Not dynamically confirmed — no
TV access, no emulation run. Out of scope for the bounty (2019 model); research
on owned hardware only.

## Target identification

| | |
|---|---|
| `exfat_core.ko` | 63,502 bytes, `sha256 a96d482e769f080567bdef5ae1cbe411da1cc7c3477646281ffe5a871e8bcde4` |
| `exfat_fs.ko` | 29,342 bytes, `sha256 a6a21fc58bdb748fc97b810d1aacf42552570059495e42f40de7c38f743c93ab` |
| Type | ELF32 ARM, `ET_REL`, 172 FUNC symbols (not stripped) |
| `vermagic` | `9518079, release SMP preempt mod_unload ARMv7 p2v8` |
| `license` | `GPL` (both) |
| **Driver version** | **`1.1.11p1(13-FEB-2013)`** |

### Version pinning (VERIFIED)

The task noted the format string `exFAT: Core Version %s`; the actual constant
it consumes sits immediately before it in `.rodata.str1.4`:

```
$ readelf -p .rodata.str1.4 exfat_core.ko
  [   270]  1.1.11p1(13-FEB-2013)
  [   289]  6exFAT: Core Version %s\n
```

`exfat_fs.ko` carries the identical string at `.rodata.str1.4[0x1f8]` before
`exFAT: FS Version %s`. So **both halves are 1.1.11p1, dated 13 February 2013** —
an 11-year-old driver in a December 2024 firmware build. `.modinfo` carries only
`license`/`depends`/`vermagic`; no author/version/srcversion, so this string is
the only version evidence.

## Source match

Samsung has not published the TV/VD 1.1.11p1 drop in a fetchable form
(`opensource.samsung.com` is Cloudflare-gated and returns a JS challenge to
curl). The closest public source of the same lineage is the Samsung
"exfat-nofuse" / sdFAT family, version **1.2.9**:

```
https://raw.githubusercontent.com/andy-padavan/rt-n56u/master/trunk/linux-3.0.x/fs/exfat/
```

**Match confidence: high, for structure; approximate, for version.** Evidence:

- **153 of 171** binary FUNC symbols appear verbatim in the 1.2.9 sources
  (`exfat_core.c`, `exfat_api.c`, `exfat_nls.c`, `exfat_cache.c`,
  `exfat_blkdev.c`, `exfat_bitmap.c`, `exfat_oal.c`, `exfat_upcase.c`,
  `exfat_data.c`). Unmatched are `Bitmap_*` (macros in 1.2.9), module
  init/exit, and small helpers (`my_itoa`, `my_log2`, `__wstrlen`, …).
- The `ffs*` / `Fs*` API split, `ffsMountVol`, `FS_FUNC_T` dispatch vector and
  `ENTRY_SET_CACHE_T` layout are all present, identifying the old Samsung
  exfat-nofuse/sdFAT lineage rather than mainline `fs/exfat`.
- Field offsets line up: `get_uni_name_from_ext_entry` is the 8th pointer in
  `FS_FUNC_T`, i.e. offset `0x1c`, and both call sites in the binary invoke
  `fs_func+0x1c`.
- The binary is an **exFAT-only trim**: it has `exfat_mount` but no
  `fat16_mount`/`fat32_mount`, and no `fat_*` twins of the exFAT functions.

Because 1.1.11p1 predates 1.2.9, the source is used as a *reading aid*; **every
claim below was confirmed against the binary itself.**

## The defect

`exfat_get_uni_name_from_ext_entry` @ `0x00011be8` (Ghidra; symtab `0x1bc4`,
`.text` rebased by `+0x10024`).

Decompiled:

```c
bVar1 = *(byte *)(iVar3 + 1);                       /* num_ext, raw on-disk byte */
iVar3 = get_entry_set_in_dir(param_1,param_2,param_3,0,&local_2c);
if (iVar3 != 0) {
  if ((2 < *(uint *)(iVar3 + 0xc)) && (local_2c = local_2c + 0x20, 1 < bVar1)) {
    psVar6 = param_4;                               /* caller's buffer */
    do {
      ...                                           /* copy <=15 u16 from one entry */
      psVar8 = psVar6 + 0xf;
      ...
      local_2c = local_2c + 0x10;
      psVar6 = psVar8;
    } while (param_4 + (uint)bVar1 * 0xf + -0xf != psVar8);   /* end = buf + 15*num_ext */
  }
  kfree(iVar3);
}
```

Disassembly, the three lines that matter:

```
00011c20  ldrb r5,[r0,#0x1]     ; num_ext -- RAW BYTE from the on-disk file dentry
00011c48  cmp  r3,#0x2          ; only guard: es->num_entries > 2
00011c70  mla  r5,r3,r5,r4      ; end = uniname + 0x1e*num_ext   (r3 = 0x1e = 30)
00011c74  sub  r5,r5,#0x1e
```

Every `cmp`/`subs` in the whole function:

```
00011c14 cmp r0,#0x0    00011c3c subs r9,r0,#0x0   00011c48 cmp r3,#0x2
00011c54 cmp r5,#0x1    00011c84 cmp r0,r7         00011ca0 cmp r2,#0x0
00011cac cmp r3,r4      00011cbc cmp r5,r4
```

There is **no comparison against 255, 256 (`MAX_NAME_LENGTH`) or any length
cap**. The write extent is `30 * num_ext` bytes, `num_ext` being an unvalidated
`u8` read straight from the directory entry — up to **7,650 bytes**.

Additionally at `0x11ca8`, a fragment containing an early NUL branches to
`0x11cb8`, which advances to the next entry and **continues the loop** —
precisely the "short fragment" behaviour that CVE-2026-64296 describes for the
sibling function.

### Sinks: fixed-size kernel stack buffers

| Caller | Buffer | Size | Overflow when |
|---|---|---|---|
| `ffsGetStat` @ `0x122e4` | `short local_234[260]` | 520 B | `num_ext >= 18` |
| `ffsReadDir` @ `0x12694` | `short local_234[256]` | 512 B | `num_ext >= 18` |

Both call `fs_func+0x1c` with `&local_234`:

```
ffsGetStat  : (**(code **)(*(int *)(iVar7 + 0x80) + 0x1c))(iVar8,param_1 + -0x88,...,local_234,&local_254);
ffsReadDir  : (**(code **)(*(int *)(iVar9 + 0x80) + 0x1c))(iVar7,local_260 + 2,local_26c,local_234,local_260);
```

Overflow arithmetic (buffer 520 B, allocation `0x20*(num_ext+1) + 0x10`):

```
num_ext   es->num_entries   loop end = 30*num_ext   bytes past a 520-B buffer
   17           18                 510                        0
   18           19                 540                       20
  100          101                3000                     2480
  254          255                7620                     7100
```

In `ffsReadDir` only `short local_34` separates `local_234` from the saved
register area, so the overflow reaches saved `r4-r11`, `lr` and `pc` almost
immediately. There is **no stack protector in this kernel** (verified earlier
from `uImage`: no `__stack_chk`, no `stack-protector` panic string), so nothing
detects the smash.

### Constraint on the attacker

The loop breaks when an entry's type != `0x202` (`TYPE_EXTEND`), so the
attacker must supply `num_ext` genuine `0xC1` name dentries in the entry set —
which is simply a matter of authoring the directory. `get_entry_set_in_dir`
allocates and copies `0x20*(num_ext+1)+0x10` bytes for them, so the entry set
is large enough to hold them; nothing there caps `num_ext`.

## Upstream: this is CVE-2023-4273, and the fix is missing

`CVE-2023-4273` — *"the file name reconstruction function … file name
characters are copied into a stack variable, a local privileged attacker could
use this flaw to overflow the kernel stack"* (CVSS 6.7/7.8).

Fixed upstream by **`d42334578eba1390859012ebb91e1e556d51db49`**, "exfat: check
if filename entries exceeds max filename length", Namjae Jeon, 13 Jul 2023,
`Cc: stable`, **`Reviewed-by: Sungjong Seo <sj1557.seo@samsung.com>`**:

```diff
 static int exfat_get_uniname_from_ext_entry(...)
+	unsigned int uni_len = 0, len;
...
-		exfat_extract_uni_name(ep, uniname);
+		len = exfat_extract_uni_name(ep, uniname);
+		uni_len += len;
+		if (len != EXFAT_FILE_NAME_LEN || uni_len >= MAX_NAME_LENGTH)
+			break;
 		uniname += EXFAT_FILE_NAME_LEN;
```

`exfat_get_uniname_from_ext_entry` is the mainline descendant of this driver's
`exfat_get_uni_name_from_ext_entry`; same role, same loop, same missing cap.
**Neither guard is present in this binary** (see the `cmp` inventory above).
The driver predates the fix by a decade and there is no sign of a backport.

The related **CVE-2026-64296** ("exfat: bound uniname advance in
`exfat_find_dir_entry()`") documents the same primitive in the sibling lookup
path and explicitly notes that `exfat_get_uniname_from_ext_entry()` *"already
stops on a short fragment (the lockstep `len != EXFAT_FILE_NAME_LEN` guard added
in commit d42334578eba)"* — a guard this build never received. This build's
`exfat_find_dir_entry` @ `0x13c68` should be audited for the same shape
(uses `u16 entry_uniname[16]`); **not yet examined — see next steps.**

## Reachability

**Trigger: insert a USB stick with a crafted exFAT volume, then let anything
list the directory.** No pairing, no network, no Developer Mode.

- `storaged` automounts on udev events (from lead-003).
- `exfat_fs.ko` exports `exfat_iterate` (readdir) and `exfat_lookup`; the
  `ffsReadDir` path is driven by `exfat_iterate`, i.e. an ordinary
  `readdir()`/`ls`. The TV's media scanner enumerating the stick is enough —
  **no file needs to be opened**.
- `ffsGetStat` is reached via `exfat_getattr`/`exfat_iget` (a `stat`).

This is a *kernel-mode* write with no canary, no KASLR, no module signing and
`kptr_restrict` unset. It is exactly the "delivery" primitive the SamyGO
researcher lacks for their already-working 1500.9 kernel LPE.

**Confidence:** high that the code shape and the missing guard are real (read
directly from the binary at instruction level). **Unproven:** that a crafted
volume actually reaches `num_ext >= 18` through `get_entry_set_in_dir`'s
entry-type state machine on this exact build, and that the resulting corruption
is controllable rather than just a panic. Both need dynamic testing.

## Negative results (checked, NOT vulnerable — do not re-tread)

- **`__load_upcase_table` @ `0x14838`** — this is the CVE-2020-10720 /
  Sony PS4/PS5 `UVFAT_readupcasetable` (CVE-2022-3349) bug class. The `skip`
  path *does* let `index` exceed `0xFFFF` (`uVar12 = uVar12 + uVar11` on a u32),
  but **both table indices are masked before use**:
  `col = (uVar12 & 0xffff) >> 8` (0..0xFF into a 0x100-entry table) and
  `row = uVar12 & 0xff` (0..0xFF into a 0x100-entry row). No OOB write.
  Matches the already-fixed `get_col_index(u16)`/`get_row_index(u16)` shape.
- **`get_entry_set_in_dir` @ `0x11794` num_ext=255 wrap** — `param_4 & 0xff`
  makes `num_entries` wrap to 0, shrinking the allocation to `0x10` *and*
  returning early past all entry-type validation. Tempting, but the consumer's
  `2 < es->num_entries` guard then fails and the copy loop never runs. **Real
  truncation bug, dead in this call path.** Worth re-checking against any other
  consumer of `es->num_entries`.
- **`extract_uni_name_from_name_entry` @ `0x12b60`** — bounded in isolation:
  copies at most 15 u16 (`i < 30, i += 2`) from a single entry. The defect is
  purely in its caller's iteration count.
- **`load_alloc_bitmap` @ `0x1465c`** — allocation size and fill loop bound are
  the same variable (`n = ((size-1) >> sector_size_bits) + 1`); no OOB in this
  function.

### Noted but not a finding

**`exfat_mount` @ `0x137cc`** performs *no* validation of the boot sector
beyond `num_fats != 0`:

```
*(iVar3 + 0x1c) = 1 << *(sbyte *)(param_2 + 0x6d);      /* sectors_per_clu_bits, raw */
uVar2 = bits + sector_size_bits;
*(iVar3 + 0x14) = 1 << (uVar2 & 0xff);                  /* cluster_size */
*(iVar3 + 0x44) = 1 << (uVar2 - 5 & 0xff);              /* dentries_per_clu */
```

Shifts ≥ 32 are undefined in C and on ARM a variable shift by ≥32 yields 0
rather than trapping, so this produces nonsense geometry rather than a direct
write. It is an *amplifier* for other bugs (poisoned `cluster_size` /
`dentries_per_clu`), not a primitive on its own. Mainline later added
`exfat_calibrate_blocksize` / explicit BPB validation; this build has none.

## Next steps

1. **Audit `exfat_find_dir_entry` @ `0x13c68`** for the CVE-2026-64296 shape
   (`u16 entry_uniname[16]`, per-entry advance vs. accumulated length). Not yet
   examined; it is the sibling of the confirmed bug and upstream needed a
   *separate* fix for it.
2. **Build the PoC volume.** `mkfs.exfat` a small image, then hand-edit a
   directory: file dentry `0x85` with `num_ext = 0x40`, stream `0xC0`, then 64
   name dentries `0xC1` each holding 15 non-NUL UTF-16 chars. Listing that
   directory drives `ffsReadDir` 30*64 = 1920 bytes into a 512-byte frame.
3. **Emulate before touching hardware.** QEMU ARM + the extracted `uImage`
   (raw kernel at file offset 0x40, load 0x80008000) with `exfat_core.ko`/
   `exfat_fs.ko` insmod'ed, then mount the crafted image via loop device.
   This is the only safe way to confirm the overflow and see what it hits.
4. **Confirm `MS_NOSUID`/`MS_NODEV`** in `block_mount_device` (still open from
   lead-003) — matters for post-exploitation, not for this trigger.
5. Check whether `exfat_fs.ko`'s `exfat_iterate` imposes any name-length cap of
   its own before calling into core (skimmed, none seen; not proven).

## Reproduce

```sh
cd $REPO

# version + hashes
readelf -p .rodata.str1.4 binaries/exfat_core.ko | head -30
sha256sum binaries/exfat_core.ko binaries/exfat_fs.ko

# import (already done; project ExfatCore)
nix develop --command bash -c '
  source tools/ghidra-env.sh; export GHIDRA_REPO=local
  ghidra_project ExfatCore ignored -import binaries/exfat_core.ko -analysisTimeoutPerFile 2400'

# the defect
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh ExfatCore exfat_core.ko DecompileFns.java \
    exfat_get_uni_name_from_ext_entry ffsGetStat ffsReadDir get_entry_set_in_dir'

# the missing bound, at instruction level
nix develop --command bash -c 'export GHIDRA_REPO=local
  tools/ghidra-run.sh ExfatCore exfat_core.ko DumpAsm.java 0x11be8 0x11cec' | grep -E "cmp|mla|ldrb"

# annotations (writes) + read-back
nix develop --command bash -c 'export GHIDRA_REPO=local GHIDRA_WRITE=1
  tools/ghidra-run.sh ExfatCore exfat_core.ko ExfatAnnotate.java'
nix develop --command bash -c 'export GHIDRA_REPO=local GHIDRA_WRITE=0
  tools/ghidra-run.sh ExfatCore exfat_core.ko ExfatShowAnnotations.java'

# upstream fix
curl -s "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=d42334578eba1390859012ebb91e1e556d51db49"
```

**Ghidra address caution:** `.text` in this `ET_REL` module is rebased by
`+0x10024`, so `ghidra_addr = symtab_addr + 0x10024`. All eight annotated
addresses were verified against `readelf -sW` before use — an earlier draft put
`ffsReadDir` at `0x12670`, which silently landed inside `ffsGetStat`.

## Caveat

Testing means writing a malformed filesystem to a USB stick and inserting it
into the owner's own TV. A successful overflow smashes a kernel stack frame with
no canary: expect a panic/reboot loop, not a clean failure. Emulate first, and
have the verified USB recovery image (`T-MSMDEUC.zip`) ready.
