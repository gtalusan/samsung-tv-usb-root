# Vendor-kernel QEMU lab

This lab boots Samsung's Linux 4.1.10 Muse.M configuration on QEMU vexpress,
then loads the shipped filesystem modules byte-for-byte. It verifies trigger
reachability and payload behavior; target addresses always come from the
shipped uImage/module, never the lab kernel.

## Required local artifacts (not included)

Place under a working directory (`LAB`, default `/var/tmp/samsung-lab`):

```text
vendor/linux-4.1.10/     Samsung GPL source tree
fw/modules/*.ko          modules extracted from your own firmware
build/busybox-armhf      static ARM BusyBox for initramfs
```

The exact source configuration used during development was
`Muse.M-Tizen_release_defconfig`, with `include/linux/vdlp_version.h`
reconstructed to produce the shipped vermagic:

```text
9518079, release SMP preempt mod_unload ARMv7 p2v8
```

The source defconfig's `CONFIG_KERNEL_STACK_LARGE=y` disagrees with every
shipped module's hardcoded `thread_info.task` offset; the lab disables it so
the module ABI matches the physical TV. Do not patch C structs to fake ABI.

## Build

```sh
podman build -f lab/Dockerfile.kbuild -t samsung-kbuild lab
podman run --rm -v "$LAB:$LAB" -w "$LAB" samsung-kbuild \
  bash scripts/07-build-vendor-kernel.sh
```

## Filesystem trigger

```sh
cd "$LAB"
LANE=exfat TIMEOUT=90 ./scripts/08-run.sh IMAGE.img \
  exfat exfat_core,exfat_fs readdir
```

The runner is lane-safe: each run gets a separate initramfs, log and optional
GDB port. `GDB=1 GDBPORT=4519` starts halted with a gdbstub.

## Complete USB payload

`lab/scripts/12-full-stick-e2e.sh` embeds a generated two-partition stick,
mounts p2, triggers p1, and verifies a dropbear process/listener. During
development it produced:

```text
P2 MOUNT OK
P1 MOUNT OK
DROPBEAR PROCESS OK
DROPBEAR LISTEN :22 OK
DROPBEAR EXEC OK
FULL USB E2E: PASS
```

## Optional kmem self-test

Build `payload/research_kmem.ko`, place it under `$LAB/payload`, then run:

```sh
LAB="$LAB" lab/scripts/13-kmem-test.sh
```

It verifies root-only `/dev/kmem` against the module's own writable buffer.

## Notes

* `09-devmem-proof.sh` is a negative test: the target has
  `CONFIG_DEVMEM=n`; creating the device node returns `ENXIO`.
* `02`–`05` are the early generic harness scripts. `07`/`08` are the current
  vendor-tree path.
* QEMU has no Samsung SDP machine. vexpress changes the board, not the ABI
  offsets asserted before each filesystem test.
