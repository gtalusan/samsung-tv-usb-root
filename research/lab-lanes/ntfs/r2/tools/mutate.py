#!/usr/bin/env python3
"""lanes/ntfs: structured NTFS mutator.

    mutate.py IN.img OUT.img SEED [mode]

Takes a real `mkntfs` volume and changes exactly one field (or one small byte
run), so that any crash can be attributed to that field. Prints a one-line
description of the mutation, which the campaign driver records next to the
verdict.

Records are un-fixed-up before mutation and re-fixed-up afterwards, so the USA
stays self-consistent: we are testing the *parser*, not the fixup validation
(round 0 already proved the fixup path is correctly validated).
"""
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ntfslab import Ntfs, attrs  # noqa: E402

INTERESTING8 = [0x00, 0x01, 0x02, 0x07, 0x08, 0x0F, 0x10, 0x7F, 0x80, 0xFE, 0xFF]
INTERESTING16 = [0x0000, 0x0001, 0x0008, 0x0018, 0x0028, 0x0030, 0x0038, 0x003F,
                 0x0040, 0x00FF, 0x0100, 0x01FF, 0x0200, 0x03F8, 0x03FF, 0x0400,
                 0x0401, 0x0FFF, 0x1000, 0x7FFF, 0x8000, 0xFFF8, 0xFFFF]
INTERESTING32 = INTERESTING16 + [0x00010000, 0x7FFFFFFF, 0x80000000,
                                 0xFFFFFFF8, 0xFFFFFFFF]

REC_HDR_FIELDS = [
    (0x04, 2, "usa_ofs"), (0x06, 2, "usa_count"), (0x10, 2, "seq"),
    (0x12, 2, "link_count"), (0x14, 2, "attrs_offset"), (0x16, 2, "flags"),
    (0x18, 4, "bytes_in_use"), (0x1C, 4, "bytes_allocated"),
    (0x20, 8, "base_mft_record"), (0x28, 2, "next_attr_instance"),
    (0x2C, 4, "mft_record_number"),
]

ATTR_COMMON = [
    (0x00, 4, "type"), (0x04, 4, "length"), (0x08, 1, "non_resident"),
    (0x09, 1, "name_length"), (0x0A, 2, "name_offset"), (0x0C, 2, "flags"),
    (0x0E, 2, "instance"),
]
ATTR_RES = [(0x10, 4, "value_length"), (0x14, 2, "value_offset"),
            (0x16, 1, "res_flags")]
ATTR_NRES = [(0x10, 8, "lowest_vcn"), (0x18, 8, "highest_vcn"),
             (0x20, 2, "mapping_pairs_offset"), (0x22, 2, "compression_unit"),
             (0x28, 8, "allocated_size"), (0x30, 8, "data_size"),
             (0x38, 8, "initialized_size")]


def poke(buf, off, size, val):
    if size == 1:
        buf[off] = val & 0xFF
    elif size == 2:
        struct.pack_into("<H", buf, off, val & 0xFFFF)
    elif size == 4:
        struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)
    elif size == 8:
        struct.pack_into("<Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)


def pick_val(rng, size):
    tbl = {1: INTERESTING8, 2: INTERESTING16, 4: INTERESTING32,
           8: INTERESTING32}[size]
    if rng.random() < 0.75:
        return rng.choice(tbl)
    return rng.getrandbits(size * 8)


def mutate(v, rng, mode):
    if mode == "vbr":
        off, size, name = rng.choice([
            (0x0B, 2, "bytes_per_sector"), (0x0D, 1, "sectors_per_cluster"),
            (0x28, 8, "total_sectors"), (0x30, 8, "mft_lcn"),
            (0x38, 8, "mftmirr_lcn"), (0x40, 1, "clusters_per_mft_record"),
            (0x44, 1, "clusters_per_idx_record"),
        ])
        old = v.d[off:off + size].hex()
        val = pick_val(rng, size if size <= 4 else 4)
        poke(v.d, off, size, val)
        return f"vbr {name}@0x{off:x}/{size} {old} -> 0x{val:x}"

    nrec = rng.randrange(0, int(os.environ.get("NREC", "16")))
    raw = v.read_rec(nrec)
    rec = Ntfs.unfixup(raw, v.bps)
    if rec[0:4] != b"FILE":
        return None

    if mode == "rechdr":
        off, size, name = rng.choice(REC_HDR_FIELDS)
        old = rec[off:off + size].hex()
        val = pick_val(rng, size if size <= 4 else 4)
        poke(rec, off, size, val)
        desc = f"rec{nrec} hdr {name}@0x{off:x}/{size} {old} -> 0x{val:x}"
    elif mode == "attrhdr":
        al = [(o, t, ln) for (o, t, ln) in attrs(rec) if t != 0xFFFFFFFF]
        if not al:
            return None
        o, t, ln = rng.choice(al)
        nres = rec[o + 8]
        fields = ATTR_COMMON + (ATTR_NRES if nres else ATTR_RES)
        fo, size, name = rng.choice(fields)
        if o + fo + size > len(rec):
            return None
        old = rec[o + fo:o + fo + size].hex()
        val = pick_val(rng, size if size <= 4 else 4)
        poke(rec, o + fo, size, val)
        desc = (f"rec{nrec} attr@0x{o:x} type=0x{t:x} nres={nres} "
                f"{name}@+0x{fo:x}/{size} {old} -> 0x{val:x}")
    elif mode == "runlist":
        al = [(o, t, ln) for (o, t, ln) in attrs(rec)
              if t != 0xFFFFFFFF and rec[o + 8] == 1]
        if not al:
            return None
        o, t, ln = rng.choice(al)
        mpo = struct.unpack_from("<H", rec, o + 0x20)[0]
        base = o + mpo
        if base >= len(rec):
            return None
        n = rng.randrange(1, 9)
        pos = base + rng.randrange(0, min(16, max(1, len(rec) - base)))
        old = rec[pos:pos + n].hex()
        blob = bytes(rng.getrandbits(8) for _ in range(n))
        rec[pos:pos + n] = blob
        desc = (f"rec{nrec} attr@0x{o:x} type=0x{t:x} runlist@0x{pos:x} "
                f"{old} -> {blob.hex()}")
    elif mode == "value":
        al = [(o, t, ln) for (o, t, ln) in attrs(rec)
              if t != 0xFFFFFFFF and rec[o + 8] == 0]
        if not al:
            return None
        o, t, ln = rng.choice(al)
        vofs = struct.unpack_from("<H", rec, o + 0x14)[0]
        vlen = struct.unpack_from("<I", rec, o + 0x10)[0]
        if vofs >= len(rec) or vlen == 0:
            return None
        span = min(vlen, len(rec) - (o + vofs))
        pos = o + vofs + rng.randrange(0, max(1, span))
        n = rng.randrange(1, 5)
        old = rec[pos:pos + n].hex()
        blob = bytes(rng.getrandbits(8) for _ in range(n))
        rec[pos:pos + n] = blob
        desc = (f"rec{nrec} attr@0x{o:x} type=0x{t:x} value@0x{pos:x} "
                f"{old} -> {blob.hex()}")
    elif mode == "raw":
        pos = rng.randrange(0x10, len(rec) - 8)
        n = rng.randrange(1, 5)
        old = rec[pos:pos + n].hex()
        blob = bytes(rng.getrandbits(8) for _ in range(n))
        rec[pos:pos + n] = blob
        desc = f"rec{nrec} raw@0x{pos:x} {old} -> {blob.hex()}"
    else:
        raise SystemExit(f"unknown mode {mode}")

    v.write_rec(nrec, Ntfs.refixup(rec, v.bps))
    return desc


def main():
    src, dst, seed = sys.argv[1], sys.argv[2], int(sys.argv[3])
    mode = sys.argv[4] if len(sys.argv) > 4 else "mix"
    rng = random.Random(seed)
    if mode == "mix":
        mode = rng.choice(["rechdr", "attrhdr", "attrhdr", "runlist",
                           "value", "raw", "vbr"])
    v = Ntfs(src)
    for _ in range(20):
        d = mutate(v, rng, mode)
        if d:
            v.save(dst)
            print(d)
            return
    raise SystemExit("no mutation produced")


if __name__ == "__main__":
    main()
