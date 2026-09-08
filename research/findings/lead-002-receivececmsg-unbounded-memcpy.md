# Lead 002 — `CECRx::ReceiveCECMsg`: unbounded `memcpy` into a 17-byte heap chunk

**Status: CLOSED — latent defect, proven NOT reachable.** The copy is genuinely
unguarded, but every producer passes a validated length and there is no other
caller. Kept as a record so it is not re-investigated, and as a regression
watch-point: it is one caller-edit away from being exploitable.
Out of scope for the bounty (2019 model); research only.

| | |
|---|---|
| Function | `CECRx::ReceiveCECMsg(unsigned char*, unsigned char)` @ `0x00072c50` |
| Copy site | `0x00072d16` (bookmarked `CEC-PARSER`) |
| Privilege | root (`hdmicec-service`, `User=root`, no hardening directives) |

## The primitive

```c
void CECRx::ReceiveCECMsg(uchar *buf, uchar len)
{
  n = (uint)len;                       // full byte, 0..255
  p = operator_new(0x11, nothrow);     // 17-byte allocation
  /* zeroes 17 bytes */
  memcpy(p, buf, n);                   // <-- NO BOUNDS CHECK
  ...
  ecore_main_loop_thread_safe_call_async(m_ProcessCECMsg, p);
}
```

`len` is a full byte and the copy is unguarded, so `len > 17` would overflow the
17-byte chunk by up to 238 bytes, with fully attacker-controlled contents, in a
root process. `m_ProcessCECMsg` later does `operator delete(p, 0x11)` — the 17
is hardcoded on both sides.

## Why it is not reachable today

Both producers in `CCECFileDescriptor::Read` @ `0x0008208c` clamp before
invoking the dispatch callback:

- **`/dev/micom-cec`** (fd type 0): `read(fd, &buf, 0x14)` into a 20-byte stack
  area, then `if (n - 1U < 0x11)` — unsigned, so accepts only `1..17`.
- **`/dev/ttyS2` UART** (fd type 1): `memset(buf,0,0xff); read(fd, buf, 0xff)`
  into `local_124[256]`, then a framing state machine:
  - sync on `0xFF,0xFE`
  - expected length = `(b0 & 0x1f) + 1` → `1..32`
  - bytes accumulate at `this[count + 0x15]` (object buffer `0x15..0x47`, 51 bytes — fits 32)
  - XOR checksum over `this[1..count]` must equal the trailing byte
  - callback fires only when `count - 1 < 0x11` → `1..17`

So a frame declaring length 18–32 is accumulated but never dispatched, and the
copy never sees `n > 17`.

## RESOLVED — the question that decided it

The functor is `std::function<void (unsigned char*, unsigned char)>`, installed by
`CCECFileDescriptor::SetFunctorForRxMsg` @ `0x81ff4`. The decompiler showed only
`(**(code**)(this+0x54))(this+0x48)` because it did not model the extra
arguments; the disassembly does.

**Both call sites pass the checked value.**

micom @ `0x820c4`:
```
820c4  subs r3,r0,#0x1
820c6  cmp  r3,#0x10
820c8  bhi  <skip>          ; accept n in 1..17
820d4  strb r0,[r2,#0x0]    ; length stored = r0 = the value just checked
```

UART @ `0x821be`:
```
821be  subs r1,#0x1
821c0  cmp  r1,#0x10
821c2  bhi  <skip>          ; accept r1 in 1..17
821d0  strb.w r10,[r2,#0x0] ; length stored = r10
```
`r10` looked like a second, unchecked value — it is not. At `0x82146`,
`ands r10,r1,#0xff`, i.e. r10 is derived from r1, on a path reached only when
`count == expected` (`0x82142 cmp r1,r3 / bne`), with
`expected = (b0 & 0x1f) + 1 <= 32`. Checked value and used value are the same.

**Binding resolved.** `CECRx::CECRx` @ `0x72ec4` calls `SetFunctorForRxMsg` with a
PC-relative literal (`literal@0x6301c = 0xfffffd25`, `+PC = 0x62c51`) — Thumb
address of `ReceiveCECMsg` itself. Xrefs confirm the path is closed:
`ReceiveCECMsg` has no internal callers (only the EXTERNAL export reference),
`SetFunctorForRxMsg` has exactly one caller (`CECRx::CECRx`), and `Read` has
exactly one caller (`t_ThreadFunc`).

The `local_138` / `this+0x48` discrepancy I flagged was my misreading of the
decompiler: `this+0x48` is the `std::function` object, not the frame buffer; the
buffer pointer is passed separately (`str r4,[r1]` / `str.w lr,[r1]`).

## Next steps

Ingress is exhausted. Remaining surface is **downstream of** the 17-byte frame:

1. Sweep the 92 `CCECMsgReceiver::*Processing(CECMessage const&)` handlers for
   length-blind copies that **write** (lead-001 is a read). `ProcessInterfaceMsg`
   is the dispatcher; handlers that take no length parameter are the tell.
2. Close out lead-001 by tracing `SetSoundBarModelName` to an observable sink.
3. Check function-body truncation before trusting any xref result in this binary
   (`CheckExtent.java`) — several bodies are cut short by Thumb misdetection.

## Database state

Ghidra project `samsung/build/ghidra-projects/SamsungTV`, program `hdmicec-service`.

Annotated via `tools/ghidra/AnnotateCecParser.java` (plate comments on all 9
parser-path functions, 19 `CEC-PARSER` bookmarks, `/CEC/CecFrame` 17-byte struct).

**Boundary repair:** ARM/Thumb detection had truncated `ReceiveCECMsg`'s body to
58 bytes (`0x72c50..0x72c89`) while 262 instruction bytes existed in the range —
the `memcpy` and `operator_new` were orphaned, belonging to no function, and were
invisible to body-scoped reference queries. `tools/ghidra/FixFunctionBodies.java`
recomputed it from flow: 58 → 252 bytes. **Other functions in this binary are
likely truncated the same way; treat any "no xrefs" result as suspect until the
body is checked** (`tools/ghidra/CheckExtent.java`).
