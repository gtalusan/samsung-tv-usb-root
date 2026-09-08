#!/usr/bin/env python3
"""lanes/ntfs: locate a file by $FILE_NAME in the MFT and decode its $DATA runlist.

    findfile.py IMG [NAME]

Prints, for every MFT record that has a $FILE_NAME, the name and the decoded
data runs.  Used to find the driver-created `$MYLOG` journal file so that its
*contents* (not just its MFT record) can be mutated.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ntfslab import Ntfs, attrs  # noqa: E402


def decode_runs(rec, o):
    """Decode NTFS mapping pairs of the non-resident attribute at offset o."""
    mpo = struct.unpack_from("<H", rec, o + 0x20)[0]
    p = o + mpo
    lcn = 0
    vcn = struct.unpack_from("<Q", rec, o + 0x10)[0]
    runs = []
    while p < len(rec):
        b = rec[p]
        if b == 0:
            break
        lsz, osz = b & 0xF, b >> 4
        p += 1
        if lsz == 0 or p + lsz + osz > len(rec):
            break
        ln = int.from_bytes(rec[p:p + lsz], "little")
        p += lsz
        if osz:
            off = int.from_bytes(rec[p:p + osz], "little", signed=True)
            p += osz
            lcn += off
            runs.append((vcn, lcn, ln))
        else:
            runs.append((vcn, None, ln))  # sparse
        vcn += ln
    return runs


def main():
    v = Ntfs(sys.argv[1])
    want = sys.argv[2] if len(sys.argv) > 2 else None
    nrec = 64
    for n in range(nrec):
        try:
            raw = v.read_rec(n)
        except Exception:
            break
        if len(raw) < v.mft_record_size:
            break
        rec = Ntfs.unfixup(raw, v.bps)
        if rec[0:4] != b"FILE":
            continue
        names = []
        datas = []
        for (o, t, ln) in attrs(rec):
            if t == 0xFFFFFFFF:
                break
            if t == 0x30 and rec[o + 8] == 0:
                vofs = struct.unpack_from("<H", rec, o + 0x14)[0]
                nl = rec[o + vofs + 0x40]
                nm = rec[o + vofs + 0x42:o + vofs + 0x42 + nl * 2].decode(
                    "utf-16-le", "replace")
                names.append(nm)
            if t == 0x80:
                if rec[o + 8]:
                    datas.append(("nres", decode_runs(rec, o), o))
                else:
                    vl = struct.unpack_from("<I", rec, o + 0x10)[0]
                    datas.append(("res", vl, o))
        if not names:
            continue
        if want and want not in names:
            continue
        print(f"rec {n}: names={names}")
        for kind, info, o in datas:
            if kind == "nres":
                for (vcn, lcn, ln) in info:
                    if lcn is None:
                        print(f"    $DATA @0x{o:x} sparse vcn={vcn} len={ln}")
                    else:
                        print(f"    $DATA @0x{o:x} vcn={vcn} lcn={lcn} len={ln} "
                              f"byteoff=0x{lcn * v.cluster:x} "
                              f"bytelen=0x{ln * v.cluster:x}")
            else:
                print(f"    $DATA @0x{o:x} resident len=0x{info:x}")


if __name__ == "__main__":
    main()
