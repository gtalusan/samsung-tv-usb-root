# Firmware and model compatibility

This page records only firmware archives that were downloaded, decrypted and
inspected. It distinguishes physical proof from static binary compatibility.
Do not install firmware from another region or model to use this exploit.

## Classification

| Class | Meaning |
|---|---|
| **Hardware verified** | Complete USB-to-root chain was exercised on the named television. |
| **Zero-delta static profile** | The vulnerable modules, frame geometry, kernel symbols, gadgets, UEP gate and cave were independently recovered and match the hardware-verified profile. No hardware run was performed. |
| **Static candidate** | The vulnerability and control geometry are present, but important per-target chain stages remain unresolved or untested. |
| **Vulnerable, chain incomplete** | The defect is present, but changed kernel/module code requires a new payload chain. |
| **Architecturally incompatible / unobtained** | The current chain cannot transfer, or the relevant module bytes were not recovered. |

Static compatibility does not prove that a TV accepts a downgrade, recovery
package or cross-region archive. It also does not prove the exact removable
media mount name, enumeration timing, watchdog behavior or runtime text
permissions on another set.

## Hardware-verified target

| Model | Platform | Firmware family | Version | Result |
|---|---|---|---:|---|
| Samsung GQ65Q70RGTXZG | 2019 Muse.M | `T-MSMDEUC` | 1500.9 | **Hardware verified**: root Bash, UEP bypass and key-only root Dropbear. |

The physical set mounted p1 and p2 as `/opt/media/USBDriveA1` and
`/opt/media/USBDriveA2`. That exact suffix assignment is not claimed for other
models.

## T-MSM / Muse.M: current `tv` profile

The repository's `--exploit-profile tv` is a **T-MSM Muse.M family profile**.
The following artifacts are shared by every T-MSM archive analyzed:

```text
exfat_core.ko SHA-256 a96d482e769f080567bdef5ae1cbe411da1cc7c3477646281ffe5a871e8bcde4
exfat_fs.ko   SHA-256 a6a21fc58bdb748fc97b810d1aacf42552570059495e42f40de7c38f743c93ab
vermagic: 9518079, release SMP preempt mod_unload ARMv7 p2v8
exFAT: 1.1.11p1 (13-FEB-2013)
```

The complete static profile is unchanged:

| Purpose | Address/offset |
|---|---:|
| saved `r4` / `sp` / `pc` from `UNI_NAME_T.name` | `+520` / `+552` / `+556` |
| `call_usermodehelper` | `0xc003a2e4` |
| `memcpy` | `0xc02014c0` |
| `v7_coherent_kern_range` | `0xc001cee8` |
| `schedule_timeout_uninterruptible` | `0xc051edcc` |
| UEP verification gate | `0xc01d49b8` |
| `ldm ip,{r2,r3,r4,r7-r10,sp,lr,pc}` | `0xc053107c` |
| copy window | `0xc010a158` |
| post-copy `r1` saver | `0xc04a4e5c` |
| cache-flush wrapper | `0xc0012b94` |
| zero cave | `0xc0008358..0xc0009000` |
| cave base / copy destination | `0xc0008400` / `0xc00083d8` |

### Earlier European T-MSMDEUC releases

All six archives use the same exFAT modules and complete static chain profile as
1500.9. They are zero-delta candidates for the `tv` profile, not hardware proof.

| Version | Archive | Official Samsung image | ZIP SHA-256 | Classification |
|---:|---|---|---|---|
| 1420.0 | `T-MSMDEUC.zip` | [20240305120640418](https://downloadcenter.samsung.com/content/FM/202403/20240305120640418/T-MSMDEUC.zip) | `c3a6330205a4a131556acee035aed6b22648ebcaca58426434866647b2c92888` | Zero-delta static profile |
| 1419.0 | `T-MSMDEUC_1419.0_USB.zip` | [20230915101847157](https://org.downloadcenter.samsung.com/content/FM/202309/20230915101847157/T-MSMDEUC_1419.0_USB.zip) | `a94cefa427767c44a9ba7c705ca326b80a6eed63eda96153673b40ce209a2f8a` | Zero-delta; uImage identical to 1406.4 |
| 1406.4 | `T-MSMDEUC.zip` | [20230907093050379](https://downloadcenter.samsung.com/content/FM/202309/20230907093050379/T-MSMDEUC.zip) | `eea082ff32ad661d6b6db819eb3c7fcee055166e585ce5594c5f8c2d5212f1c3` | Zero-delta; uImage identical to 1419.0 |
| 1409.0 | `T-MSMDEUC_1409.0_USB.zip` | [20221004103832153](https://downloadcenter.samsung.com/content/FM/202210/20221004103832153/T-MSMDEUC_1409.0_USB.zip) | `5b44e6329369227a48c98a8708c9f4364aea1df243d3d3e2fc869cd35069041d` | Zero-delta static profile |
| 1401.0 | `T-MSMDEUC.zip` | [20220811155606462](https://downloadcenter.samsung.com/content/FM/202208/20220811155606462/T-MSMDEUC.zip) | `96a16ec96a091642a12fcc077026b16fad1df674df06d1a244cf0882721193aa` | Zero-delta static profile |
| 1395.2 | `T-MSMDEUC.zip` | [20220608141944915](https://downloadcenter.samsung.com/content/FM/202206/20220608141944915/T-MSMDEUC.zip) | `3c563f8954085129b918a1c2f70fce484a5590bce304c0e66d3e360e0c5f9825` | Zero-delta static profile |

Numerical version order does not always match build chronology; for example,
1409.0 predates the later 1406.4 recovery release.

### 2019 regional T-MSM families

The regional kernels are not whole-file identical, but all chain-critical
addresses and byte windows were independently recovered at the same values.
Their exFAT and relevant media-management binaries match the European baseline.

| Region/family | Version/archive | Official representative models | Image SHA-256 | Classification |
|---|---|---|---|---|
| Europe `T-MSMDEUC` | 1500.9 `T-MSMDEUC.zip` | `GQ65Q70RGTXZG`, `QE65Q60RATXXU`, `QE65Q70RATXXU`, `QE65Q80RATXXU`, `UE65RU8000UXXU` | `0fe14f11e7b503762d42b49db37a799313d78da1d02c29c523fb01aed98d07ff` | Hardware verified on the GQ65Q70R; zero-delta static for the other listed official mappings |
| North America `T-MSMAKUC` | 1500.5 `T-MSMAKUC.zip` | `QN65Q70RAFXZA`, `UN65RU8000FXZA`, `QN65Q70RAFXZC` | `c3884c215d7ba3904db1e8bb5b44618ec6573a1485c29d8db201a92f97fd340e` | Zero-delta static profile |
| Asia/Africa/Latin America `T-MSMUABC` | 1501.1 `T-MSMUABC.zip` | `QA65Q60RAKXXL`, `QA65Q70RAKXXL`, `QA65Q80RAKXXL`, `UA65RU8000KXXL` | `ad1f334ff79e232d793d8df0de2f10ea197748df4340eb5333bc74dd46acaf64` | Zero-delta static profile |

Official image URLs:

- [`T-MSMDEUC` 1500.9](https://org.downloadcenter.samsung.com/Content/FM/202502/20250205100005098/T-MSMDEUC.zip)
- [`T-MSMAKUC` 1500.5](https://org.downloadcenter.samsung.com/Content/FM/202412/20241209181612097/T-MSMAKUC.zip)
- [`T-MSMUABC` 1501.1](https://org.downloadcenter.samsung.com/Content/FM/202512/20251218135236161/T-MSMUABC.zip)

Only exact model codes mapped by Samsung's support pages/API are listed. A
marketing name or nearby panel size is not sufficient evidence by itself.

## Earlier platforms requiring separate profiles

The old Samsung exFAT defect and saved-register geometry remain present on the
2017 and 2018 representatives. Their chain addresses and UEP implementation do
not match T-MSM, so the current image must not be used unchanged.

| Platform/family | Version / representative | UMH | coherent range | memcpy | park | `ldm ip` | copy window | Result |
|---|---|---:|---:|---:|---:|---:|---:|---|
| 2017 Kant-M `T-KTMDEUC` | 1410.1 / `QE55Q8FAMTXXU` | `0xc00389c4` | `0xc001bfbc` | `0xc023e740` | `0xc0506f44` | `0xc051adec` | `0xc0100904` (`r5` length) | Static candidate; new UEP/saver/cache chain required |
| 2018 Kant-M2 `T-KTM2DEUC` | 1400.2 / `QE55Q8FNATXXU` | `0xc0039a78` | `0xc001cba8` | `0xc01fa720` | `0xc04cc05c` | `0xc04dde3c` | `0xc010598c` (`r4` length) | Static candidate; new UEP/saver/cache chain required |
| 2016 Jazz-M `T-JZMDEUC` | 1270.1 / `UE55KS8000TXXU` | — | — | — | — | — | — | Linux 3.10.30; exFAT bytes unobtained and the T-MSM cave is occupied |

Artifact provenance:

| Family | Official archive | ZIP SHA-256 | `uImage` SHA-256 | `exfat_core.ko` SHA-256 |
|---|---|---|---|---|
| `T-KTMDEUC` | [`T-KTMDEUC.zip`](https://org.downloadcenter.samsung.com/content/FM/202605/20260507184411893/T-KTMDEUC.zip) | `ac092bae5cd86ec4eb76d3fe85df12f6036a6caeb4488e3c345eae95138149c7` | `0d950f3d70b51aa43303998a8a8f6cbf21dddf8f041edd4e7d5560699a00ae2a` | `bca8156fcc0134f3ca471f0738abd5cac642a177be47cf307f8c2b6e2509d11c` |
| `T-KTM2DEUC` | [`T-KTM2DEUC.zip`](https://org.downloadcenter.samsung.com/content/FM/202607/20260729103150980/T-KTM2DEUC.zip) | `0f30e46098495e88f809b637b977c7f3da55ae1603f3ce71d10bf057ace2ada4` | `5a9f1c491e0125836a3c75fec0f56b3064563316b06c0e0ecb6f073a185021f5` | `22f43de04d7ee4ff4183e99474e4b3c0a02a3690f1aa0636961daceebfe602cf` |
| `T-JZMDEUC` | [`T-JZMDEUC.zip`](https://org.downloadcenter.samsung.com/content/FM/202606/20260626164359504/T-JZMDEUC.zip) | `8a186b75e18c9ffd00c3cba38b4c392429d49cae9316ce48d2161a0ff6def8c4` | `6d3001125a0e02d52486759e9c470e2d5d3e9882df69c5b21073c5ef6e076326` | unobtained |

Both Kant modules retain `uniname=fp-560` and the same saved-slot offsets
`+520..+556`. The shared static cave remains `0xc0008358..0xc0009000`.
Neither kernel contains the 2019 UEP neutralizer bytes.

## Newer vulnerable families with incomplete chains

Samsung retained the out-of-tree split exFAT driver through the representatives
below. Each contains the unchecked `num_ext` copy and the same saved-slot
geometry, but none has a complete port of the cave/UEP/cache payload.

| Year/platform/family | Version / representative | Kernel | UMH | memcpy | `ldm ip` | Cave | UEP candidate | Result |
|---|---|---|---:|---:|---:|---|---:|---|
| 2020 NikeL `T-NKLAKUC` | 2740.1 / `QN43Q60TBFXZA` | 4.1.10 | `0xc003b87c` | `0xc020b120` | `0xc05455bc` | `0xc0008358..0xc0009000` | `0xc01de028` | Vulnerable, chain incomplete |
| 2021 NikeM2 `T-NKM2AKUC` | 2301.1 / `QN55QN90AAFXZA` | 4.1.10 | `0xc003bcc4` | `0xc0219620` | `0xc0563afc` | `0xc0008358..0xc0009000` | `0xc01e8168` | Vulnerable, chain incomplete |
| 2022 PontusM `T-PTMAKUC` | 1720.7 / `QN55QN90BAFXZA` | 5.4.77 | `0xc00420ac` | `0xc06a9440` | `0xc06f03bc` | `0xc00082e0..0xc0009000` | `0xc0282088` | Vulnerable, chain incomplete |

Artifact provenance:

| Family | Official archive | ZIP SHA-256 | Module SHA-256 (`core` / `fs`) |
|---|---|---|---|
| `T-NKLAKUC` | [`T-NKLAKUC.zip`](https://org.downloadcenter.samsung.com/content/FM/202605/20260515084518023/T-NKLAKUC.zip) | `5421c65e17d8dc4f0730a2e7bb2dfacdb78f00fab8205321f98a56dbdddcda7a` | `9905f0dd05deac7431b4e004288e9960ad6150a1f0959ea0506cc20ccc763d48` / `ecba9abb41246e94310c1f4cefb887e54a3c7f554220e747b71715a0fb6cff42` |
| `T-NKM2AKUC` | [`T-NKM2AKUC.zip`](https://org.downloadcenter.samsung.com/content/FM/202601/20260121115125883/T-NKM2AKUC.zip) | `69ed1790ea152b6cca34d82e1716fc9c1bfd5d9a771803570b2558874488e9b8` | `a81c783e4404be6ef1274272a38ef0da87afab530878d2783d1d5199eee0710a` / `7b8bcfa0e6e4e22f0d2c60f7ea4a59530d88598d551ccbca203249f823fd5a2d` |
| `T-PTMAKUC` | [`T-PTMAKUC_T-PTMLAKUC.zip`](https://org.downloadcenter.samsung.com/content/FM/202604/20260423144051468/T-PTMAKUC_T-PTMLAKUC.zip) | `fb6a8058350f634f997ff3f2bcdf6ea1ae038c8a54771189c930e3c1f359b7c1` | `de344de5cf25039d0d8603f978dc04105738add9478f842d0c63db81b9f0fc70` / `ba0208535b331b6452890313c1377faebba65951490c1d59455391b07a0d8581` |

PontusM still loads Samsung's split `exfat_fs.ko`/`exfat_core.ko`; it did not
migrate this path to an in-tree driver. Its vulnerable function has no stack
canary, standard Linux module-signature enforcement returns false, and the
kernel contains the build-time diagnostic for absent strict kernel W^X.
Samsung UEP/SFD remains the relevant execution gate.

## What may safely be reused

* For the listed T-MSM images, the current `tv` profile needs no static numeric
  changes. Confirm the exact model/firmware and media path before physical use.
* For Kant, Nike and Pontus, only the exFAT filesystem construction and
  `+520..+556` frame geometry transfer. Every kernel address must come from the
  matching shipped image.
* No firmware, decrypted partition, proprietary module or generated USB image
  is distributed by this repository. The URLs and hashes above are provenance,
  not redistribution or installation advice.
