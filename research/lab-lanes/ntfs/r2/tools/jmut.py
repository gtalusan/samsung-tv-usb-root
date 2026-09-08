#!/usr/bin/env python3
"""lanes/ntfs: mutate the driver-created $MYLOG journal superblock.

    jmut.py IN.img OUT.img SEED

The $MYLOG journal is created by szdrv itself on the first read-write mount
(`make_log_file: success!`). Its superblock sits at the last cluster of the
file; on the rw1.img seed that is image byte offset 0x210000 and starts with
magic 0xABCF107E. On every later rw mount `SZDrv_journal_open` reads it, so it
is fully attacker-controlled input on the plain-insert path.
"""
import random
import struct
import sys

SB = 0x210000
FIELDS = [(0x00, 4, "magic"), (0x04, 4, "f04"), (0x08, 4, "f08"),
          (0x0C, 4, "f0c"), (0x10, 4, "f10"), (0x14, 4, "f14"),
          (0x18, 4, "f18"), (0x1C, 4, "f1c"), (0x20, 4, "f20"),
          (0x24, 4, "f24"), (0x28, 4, "f28"), (0x2C, 4, "f2c")]
VALS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x200, 0x1000, 0x10000, 0x7FFFFFFF,
        0x80000000, 0xFFFFFFFF, 0xFFFFFFF8, 0x0000FFFF, 0xABCF107E]


def main():
    src, dst, seed = sys.argv[1], sys.argv[2], int(sys.argv[3])
    rng = random.Random(seed)
    d = bytearray(open(src, "rb").read())
    off, size, name = rng.choice(FIELDS)
    val = rng.choice(VALS) if rng.random() < 0.8 else rng.getrandbits(32)
    old = struct.unpack_from("<I", d, SB + off)[0]
    struct.pack_into("<I", d, SB + off, val)
    open(dst, "wb").write(d)
    print(f"jsb {name}@0x{off:x} 0x{old:x} -> 0x{val:x}")


if __name__ == "__main__":
    main()
