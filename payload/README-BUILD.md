# Payload build and verification

## Static Dropbear

The target's shipped `/usr/bin/bash` is ARM EABI5 soft-float. The payload is a
stripped, static ARMv7 soft-float executable built with musl, so it does not
depend on the TV's loader or glibc.

```sh
nix build .#dropbear-tv
file result/bin/dropbearmulti
install -m755 result/bin/dropbearmulti payload/dropbearmulti
```

The flake defines an `armv7l-unknown-linux-musleabi` soft-float cross system,
fetches Dropbear 2022.83 by a pinned source hash, applies
`dropbear-authorized-keys-opt.patch`, and builds with Nix's static musl stdenv.
No container, external toolchain, or manually downloaded source tree is needed.

Current output:

```text
SHA-256 cc4bb32fa9f79bd0368dd836b69ff9708e2d887e26b7eef4bea6923b1fd4a826d
ELF 32-bit LSB executable, ARM, EABI5, statically linked, stripped
Flags: 0x5000200, Version5 EABI, soft-float ABI
```

Host-side verification under `qemu-arm` generated a Dropbear Ed25519 host key,
started the ARM server, authenticated root with an OpenSSH Ed25519 key, and ran
`id` plus a remote-command marker successfully.

The patch changes root's allowlist from read-only
`/root/.ssh/authorized_keys` to `/opt/etc/dropbear/authorized_keys`. The image
builder runs the included `dropbearkey` applet under `qemu-arm` to generate
fresh per-stick Ed25519 and RSA host keys. Generated keys live in ignored
`payload/store/`; they are never part of the repository.

## Runtime lifecycle

Persistent state is limited to `/opt/bin/dropbearmulti` and
`/opt/etc/dropbear/*`. Stage1 atomically acquires a boot-local `/tmp` guard and
lazy-unmounts p1 before slower installation work, then:

* atomically replaces payload/key allowlist files only when hashes differ;
* preserves installed host keys;
* recreates `/run/systemd/system/dropbear-root.service`;
* starts key-only root SSH with `Restart=always`;
* verifies both service state and a port-22 listener.

The USB and p2 stay present, no sectors are changed, and `/root` is untouched.
The volatile guard disappears at reboot so the still-armed stick can recreate
the runtime service.

## Optional research module

`--research-kmem` includes `payload/research_kmem.ko`; default images omit it.
The module is built for vermagic:

```text
9518079, release SMP preempt mod_unload ARMv7 p2v8
```

It creates root-only `/dev/kmem` with fault-safe `probe_kernel_read/write` and
requires `enable=1` plus `CAP_SYS_RAWIO`. See `lab/README.md` for the vendor-tree
build and QEMU self-test. The module source is dual-licensed
`GPL-2.0-only OR AGPL-3.0-only` for Linux GPL-symbol compatibility.
