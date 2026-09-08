# Provenance — Samsung Tizen TV (2019 Muse)

## Device

| | |
|---|---|
| Model | `GQ65Q70RGTXZG` (Q70R, 65", DE) |
| Platform | 2019 "Muse-M" (`T-MSM*`), Tizen 5.0.0, Linux 4.1.10, ARMv7 |
| Installed FW | `T-MSMDEUC-1500.9`, `B1970101/070404`, BT - S |
| Build ID | `T-MSMDEUC-REL-202412040406` (build date 2024-12-03) |
| Owner | Simon (physical device on hand; firmware pulled from Samsung CDN) |

## Firmware acquisition

Downloaded from the model's own Samsung support page listing:

```
https://org.downloadcenter.samsung.com/Content/FM/202502/20250205100005098/T-MSMDEUC.zip
```

- `fileVersion` 1500.9, dated 05.02.2025, `Last-Modified: Wed, 05 Feb 2025 01:50:38 GMT`
- size `1561941345` bytes, `sha256 0fe14f11e7b503762d42b49db37a799313d78da1d02c29c523fb01aed98d07ff`
- Matches the version installed on the TV exactly.

`upgrade.msd` md5 `4e133d007059457dc9c9302bb25b3cf7` — matches the vendor's own
`info.txt`, which also self-documents the crypto:

```
used key type: MuseM Rel key decrypted aes key/MuseM Rel key private rsa key
partitions: 12345678910121314151819
```

## Decryption / extraction chain

Working tree lives **outside this repo** at `~/git/samsung-q70r` (≈4.5 GB).

1. `unixtract` (theubusu) — MSD 1.1 (`MSDU11`) container, AES-128 key
   `282e70fd55e2ad741c4df96138d62980` ("MuseM", `T-MSM*`, 2019) from its
   bundled `keys.ukf`. Yields 8 partitions.
   - NB: `bugficks/msddecrypt` does **not** carry a T-MSM key; that route
     dead-ends on this platform.
2. `vdfs-unpack` (gtors) — `platform.img` is Samsung VDFS4
   (`VDFS2007`, `mkfs.vdfs ... -h sha256`, zlib). Yields 42,146 files.

### Local patch to vdfs-unpack (required for correctness)

Upstream's "hashed" (`hZip`, `magic[0]=='h'`, `sign_type=1`) path assumed the
whole pre-descriptor region was a single compression stream. For multi-chunk
files a zlib reader stops cleanly at the end of chunk 1, so **961 multi-chunk
files were silently truncated to their first chunk** while only 58 raised an
error. `wpa_supplicant`, `libsqlite3`, `libQt5Core`, `System.Private.CoreLib.dll`
and others were affected.

Real layout:

```
[compressed chunks][comp_extent table n*16][sha256 hashes n*32][160B trailer][descriptor]
```

Each `comp_extent` carries ASCII magic `"XT"`, and **chunks are not stored in
blob order** (entry i is chunk i, wherever it lives). Fix validates on the `XT`
magic and enforces `unpacked_size`, so truncation can no longer pass silently.
Result: 0 failures, rootfs 730 MB -> 1.5 GB (2.29 GB logical).

Patch: `~/git/samsung-q70r/vdfs-unpack-hashed-chunks.patch` (worth upstreaming).

Verification (independent of the extractor):
- `uImage` = valid u-boot image, Linux-4.1.10, built Tue Dec 3 2024, CRCs intact
- `dtb.bin` parses as a device tree
- 3,679 ELFs checked, 0 truncated section-header tables

## Scope status — READ BEFORE FILING

**This device is OUT OF SCOPE for the Samsung TV bounty.** `samsungtvbounty.com`
eligibility is explicit: *"Models from years 2022 to 2026."* A 2019 set misses
that window.

Do not confuse the `securityUpdates` page (which *does* list `T-MSMDEUC`, since
2019 sets still receive updates) with the reward scope. They are different lists.

Samsung TV publishes no reward table; amounts are "at Samsung's sole and complete
discretion". Pwn2Own has no TV category as of Ireland 2025. The frequently cited
"$5M paid" / "$827,925 to 113 researchers" figures are **Samsung Mobile**, a
separate program.

Work here is therefore research on owned hardware, not bounty-directed. Anything
found that also reproduces on a 2022+ model would need re-validation on that
model before it is worth filing.

## Prior art on this platform

- **No public root exists for 2019 Muse.** SamyGO thread (Aug 2026) on
  `19_MUSEL_UHD_BASIC` / `T-MSLDEUC` **1500.9** — same generation, same FW
  version, same kernel — is unresolved. Dead ends recorded there: Dev Mode
  `12345` dialog is a silent no-op (kills the sdb lane); browser RCE dead
  (Chromium 63 / V8 6.3, Chrome-70 fix backported); factory menu has no
  secure-boot/downgrade toggle; DLNA/GStreamer 63-CVE diff produced zero crashes.
  A kernel LPE is *already written and verified* against real 1500.9 vmlinux —
  **delivery is the only missing piece.**
  That researcher explicitly flags `hdmicec-service` (root) as an unexplored lead.
- That researcher cannot decrypt their own firmware: `keys.ukf` has **MuseM**
  (`T-MSM*`) but **no MuseL** entry. This workspace is on the lucky side of that split.
- `synacktiv/samsung-q60t-exploit` — 2020 Q60T (`T-NKL`, Tizen 5.5), full public
  chain (V8 + kernel LPE). Its browser entry point is patched on 1500.9.
- `chris-ritsen/samsung-tv-root` — working root on 2022 QN90B and 2026 QN90F via
  `SVE-2025-50109` SDB package-name injection; presupposes Dev Mode.

## Current target

`/usr/bin/hdmicec-service` — ARM32 PIE, stripped, 659,172 bytes,
BuildID `cb8b3ee8addd81d982bcdae5b9f984c10a35757c`.

Runs as **root**, confirmed from its unit file (no `NoNewPrivileges`, no
`CapabilityBoundingSet`, no `PrivateTmp`):

```
[Service]
Type=dbus
BusName=org.tizen.tv.hdmicec
User=root
Group=users
ExecStart=/usr/bin/hdmicec-service
SupplementaryGroups=system_share
```

Started at boot via `basic.target.wants` and both
`vdtizen-bootseq-{PNP,factory}-starter.target.wants`.

Attack surface: HDMI-CEC frames from any attached HDMI device — reachable
without network access or pairing.

Staged in `binaries/` with selected proprietary deps in `binaries/lib/`.
