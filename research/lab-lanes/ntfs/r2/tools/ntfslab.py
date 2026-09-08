#!/usr/bin/env python3
"""lanes/ntfs: minimal NTFS image inspector / mutator.

Everything here operates on a real `mkntfs` image so that only the field under
test differs from a known-good volume. No structure is synthesised from scratch:
that would make a crash impossible to attribute.
"""
import struct
import sys


class Ntfs:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.d = bytearray(f.read())
        b = self.d
        self.bps = struct.unpack_from("<H", b, 0x0B)[0]
        self.spc = b[0x0D]
        self.total_sectors = struct.unpack_from("<Q", b, 0x28)[0]
        self.mft_lcn = struct.unpack_from("<Q", b, 0x30)[0]
        self.mftmirr_lcn = struct.unpack_from("<Q", b, 0x38)[0]
        cpm = struct.unpack_from("<b", b, 0x40)[0]
        self.mft_record_size = (1 << -cpm) if cpm < 0 else cpm * self.bps * self.spc
        cpi = struct.unpack_from("<b", b, 0x44)[0]
        self.idx_record_size = (1 << -cpi) if cpi < 0 else cpi * self.bps * self.spc
        self.cluster = self.bps * self.spc
        self.mft_off = self.mft_lcn * self.cluster

    def info(self):
        return (f"bps={self.bps} spc={self.spc} cluster={self.cluster} "
                f"sectors={self.total_sectors} mft_lcn={self.mft_lcn} "
                f"mft_off=0x{self.mft_off:x} mft_rec={self.mft_record_size} "
                f"idx_rec={self.idx_record_size}")

    def rec_off(self, n):
        return self.mft_off + n * self.mft_record_size

    def read_rec(self, n):
        o = self.rec_off(n)
        return bytearray(self.d[o:o + self.mft_record_size])

    def write_rec(self, n, rec):
        assert len(rec) == self.mft_record_size
        o = self.rec_off(n)
        self.d[o:o + self.mft_record_size] = rec

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.d)

    # ---- fixup (USA) helpers -------------------------------------------
    @staticmethod
    def unfixup(rec, bps=512):
        """Apply the USA to a raw record: replace the last 2 bytes of each
        sector with the saved originals. Returns a new bytearray."""
        r = bytearray(rec)
        usa_ofs, usa_cnt = struct.unpack_from("<HH", r, 4)
        for i in range(1, usa_cnt):
            src = usa_ofs + 2 * i
            dst = i * bps - 2
            r[dst:dst + 2] = r[src:src + 2]
        return r

    @staticmethod
    def refixup(rec, bps=512):
        """Recompute the USA over a record: bump the USN, save each sector's
        last 2 bytes into the array and stamp the USN in their place."""
        r = bytearray(rec)
        usa_ofs, usa_cnt = struct.unpack_from("<HH", r, 4)
        usn = struct.unpack_from("<H", r, usa_ofs)[0]
        usn = (usn + 1) & 0xFFFF
        if usn == 0:
            usn = 1
        struct.pack_into("<H", r, usa_ofs, usn)
        for i in range(1, usa_cnt):
            dst = i * bps - 2
            struct.pack_into("<H", r, usa_ofs + 2 * i, *struct.unpack_from("<H", r, dst))
            struct.pack_into("<H", r, dst, usn)
        return r


def attrs(rec):
    """Yield (offset, type, length) for each attribute in an UNFIXED-UP record."""
    ofs = struct.unpack_from("<H", rec, 0x14)[0]
    while ofs + 4 <= len(rec):
        t = struct.unpack_from("<I", rec, ofs)[0]
        if t == 0xFFFFFFFF:
            yield (ofs, t, 0)
            return
        ln = struct.unpack_from("<I", rec, ofs + 4)[0]
        yield (ofs, t, ln)
        if ln == 0:
            return
        ofs += ln


def dump_rec(v, n):
    raw = v.read_rec(n)
    rec = Ntfs.unfixup(raw, v.bps)
    if rec[0:4] != b"FILE":
        print(f"rec {n}: not FILE ({bytes(rec[0:4])!r})")
        return
    usa_ofs, usa_cnt = struct.unpack_from("<HH", rec, 4)
    seq = struct.unpack_from("<H", rec, 0x10)[0]
    link = struct.unpack_from("<H", rec, 0x12)[0]
    aofs = struct.unpack_from("<H", rec, 0x14)[0]
    flags = struct.unpack_from("<H", rec, 0x16)[0]
    used, alloc = struct.unpack_from("<II", rec, 0x18)
    print(f"rec {n} @0x{v.rec_off(n):x}: usa_ofs=0x{usa_ofs:x} usa_cnt={usa_cnt} "
          f"seq={seq} link={link} attrs_ofs=0x{aofs:x} flags=0x{flags:x} "
          f"used=0x{used:x} alloc=0x{alloc:x}")
    for (o, t, ln) in attrs(rec):
        if t == 0xFFFFFFFF:
            print(f"   @0x{o:03x}  END")
            break
        nres = rec[o + 8]
        nlen = rec[o + 9]
        nofs = struct.unpack_from("<H", rec, o + 0x0A)[0]
        extra = ""
        if nres == 0:
            vlen, vofs = struct.unpack_from("<IH", rec, o + 0x10)
            extra = f"res vlen=0x{vlen:x} vofs=0x{vofs:x}"
        else:
            svcn, evcn = struct.unpack_from("<QQ", rec, o + 0x10)
            mpo = struct.unpack_from("<H", rec, o + 0x20)[0]
            alen, dsize, isize = struct.unpack_from("<QQQ", rec, o + 0x28)
            extra = (f"nres svcn={svcn} evcn={evcn} mp_ofs=0x{mpo:x} "
                     f"alloc=0x{alen:x} data=0x{dsize:x} init=0x{isize:x}")
        print(f"   @0x{o:03x}  type=0x{t:02x} len=0x{ln:x} nres={nres} "
              f"nlen={nlen} nofs=0x{nofs:x} {extra}")


if __name__ == "__main__":
    v = Ntfs(sys.argv[1])
    print(v.info())
    for n in [int(x) for x in (sys.argv[2:] or ["0", "5"])]:
        dump_rec(v, n)
