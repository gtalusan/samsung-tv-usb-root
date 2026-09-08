# Lead 001 — `GetDeviceModelNameProcessing`: unterminated stack buffer + length-blind copy

**Status:** unconfirmed static lead. Not validated dynamically. **Out of scope**
for the Samsung TV bounty (2019 model; scope is 2022–2026) — research only.

| | |
|---|---|
| Binary | `/usr/bin/hdmicec-service`, ARM32 PIE, stripped, BuildID `cb8b3ee8addd81d982bcdae5b9f984c10a35757c` |
| Firmware | `T-MSMDEUC-1500.9` (`T-MSMDEUC-REL-202412040406`), Tizen 5.0.0 |
| Function | `CCECMsgReceiver::GetDeviceModelNameProcessing(CECMessage const&)` @ `0x0004b4e8` |
| Privilege | runs as **root** (`User=root`, no `NoNewPrivileges`/`CapabilityBoundingSet`) |
| Reachability | HDMI-CEC frame from any attached HDMI device; no network, no pairing |

## Observation

```c
void CCECMsgReceiver::GetDeviceModelNameProcessing(CCECMsgReceiver *this, CECMessage *param_1)
{
  char acStack_3c [16];          // never memset
  ...
  if (CVar1 == (CECMessage)0x89) {
    MEMCPY<char,unsigned_char>(acStack_3c,(uchar *)(param_1 + 3),0xd);   // 13 bytes, fixed
  } else {
    MEMCPY<char,unsigned_char>(acStack_3c,(uchar *)(param_1 + 6),10);    // 10 bytes, fixed
  }
  sVar5 = strlen(acStack_3c);                                   // no NUL guaranteed
  FUN_00047754(local_54,acStack_3c,acStack_3c + sVar5);         // std::string(begin,end)
  CECStateInfo::SetSoundBarModelName(uVar8,local_54);
}
```

Two distinct problems:

1. **No length parameter.** The signature takes only `CECMessage const&` — unlike
   its sibling handlers, it never receives or consults the received frame length.
   It copies a fixed 13 (or 10) bytes from the frame body regardless of how many
   bytes actually arrived, so a short frame yields stale/uninitialised bytes from
   the message buffer.
2. **Unterminated buffer feeding `strlen`.** `acStack_3c[16]` is not zeroed and
   13 attacker-controlled bytes are written into it. If the attacker sets all 13
   to non-NUL, `strlen` runs past index 12 through the 3 uninitialised bytes and
   onward into adjacent stack memory until it meets a zero byte. The resulting
   length then bounds a `std::string` construction, copying adjacent stack
   contents into the "soundbar model name".

Read-only over-read, no attacker-controlled write. Realistic impact is stack
**information disclosure** into a value that is stored via
`CECStateInfo::SetSoundBarModelName` and plausibly surfaced through vconf / UI /
D-Bus — that exposure path is **not yet traced**.

## Why this looks like a real inconsistency, not a false positive

The sibling handler `CCECMsgReceiver::SetOSDNameProcessing` @ `0x0004b704`
receives the length and validates it properly:

```c
if (param_2 < 2)        { /* reject */ }
else if (param_2 < 0x11) {                       // <= 16
    STRNCPY(abStack_3e + 2, param_1 + 2, param_2 - 2);
    abStack_3e[param_2] = 0;                     // 18-byte buffer, 2 bytes slack
}
```

So the codebase does know how to bound these, and `abStack_3e[18]` is
deliberately oversized. `GetDeviceModelNameProcessing` simply does not
participate in that discipline. That asymmetry suggests other handlers among
the 92 `CCECMsgReceiver::*Processing` methods are worth the same pass.

## Checked and found NOT vulnerable

- `CCECMsgSender::CECApi_VendorCommand` @ `0x45db4` — rejects `n > 14` before `memcpy`.
- `CCECMsgSender::CECApi_VendorCommandWithID` @ `0x45ea4` — rejects `n > 13`.
- `CCECMsgReceiver::SetOSDNameProcessing` @ `0x4b704` — bounded, see above.
- `CCECMsgReceiver::ProcessVCReceiverOptionData` @ `0x48a9c` — fortified
  `__snprintf_chk(buf, 100, 1, 100, ...)` into a 100-byte buffer.

(The `CECApi_*` family is the **TX** path — `CCECMsgSender` — and is not directly
attacker-reachable. Initial triage wrongly prioritised it; the attacker-facing
surface is `CCECMsgReceiver::*Processing(CECMessage const&)`.)

## Next steps

1. Determine the maximum frame length the driver hands up from `/dev/micom-cec`
   and whether `CECMessage` is a fixed 16-byte buffer — this bounds problem (1).
2. Trace `SetSoundBarModelName` to its observable sink (vconf key? UI string?
   D-Bus property?). No observable sink ⇒ severity collapses to near zero.
3. Audit the remaining `CCECMsgReceiver::*Processing` handlers for the same
   length-blind pattern; prioritise any that write rather than read.
4. Harness the parser under `qemu-arm` and replay malformed frames.

## Reproduction environment

Ghidra project: `samsung/build/ghidra-projects/SamsungTV` (local, 2,470 functions).

```sh
cd samsung
nix develop
export GHIDRA_REPO=local
tools/ghidra-run.sh SamsungTV hdmicec-service MapCecSurface.java
tools/ghidra-run.sh SamsungTV hdmicec-service DecompileFns.java 0x4b4e8
```
