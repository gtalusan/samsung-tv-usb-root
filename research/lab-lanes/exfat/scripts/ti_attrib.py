#!/usr/bin/env python3
"""Attribute each current_thread_info() SP-mask site to its containing function.

The idiom in the shipped Samsung modules is:
    bic rX, rX, #8128   (0x1fc0)
    bic rX, rX, #63     (0x3f)      -> rX = sp & ~0x1fff = thread_info
    ldr rY, [rX, #12]               -> expects thread_info->task

On the current lab kernel CONFIG_KERNEL_STACK_LARGE=y puts ->task at +16 and
->addr_limit at +12, so any exercised site is a fidelity hazard.

Usage: ti_attrib.py MODULE.dis MODULE.funcs
  .dis   = arm-linux-gnueabi-objdump -d output
  .funcs = "addr size name" lines from readelf -sW ($4=="FUNC")
"""
import re
import sys

dis_path, funcs_path = sys.argv[1], sys.argv[2]

funcs = []
for line in open(funcs_path):
    p = line.split()
    if len(p) >= 3:
        try:
            funcs.append((int(p[0], 16), int(p[1]), p[2]))
        except ValueError:
            pass
funcs.sort()


def owner(addr):
    for s, sz, n in funcs:
        if s <= addr < s + sz:
            return n
    return "<none>"


lines = open(dis_path, errors="replace").read().splitlines()
mask_re = re.compile(r"^\s*([0-9a-f]+):\s+e3c[0-9a-f]{2}d7f")
ldr_re = re.compile(r"ldr\s+(r\d+|ip|fp|lr), \[(r\d+|ip|fp|lr), #(\d+)\]")

hits = []
for i, ln in enumerate(lines):
    m = mask_re.match(ln)
    if not m:
        continue
    addr = int(m.group(1), 16)
    load = ""
    for j in range(i + 1, min(i + 8, len(lines))):
        lm = ldr_re.search(lines[j])
        if lm and lm.group(3) in ("12", "16"):
            load = f"ldr {lm.group(1)}, [{lm.group(2)}, #{lm.group(3)}]"
            break
    hits.append((addr, owner(addr), load))

print(f"{len(hits)} SP-mask site(s)")
by_fn = {}
for addr, fn, load in hits:
    by_fn.setdefault(fn, []).append((addr, load))
for fn in sorted(by_fn):
    sites = by_fn[fn]
    loads = [l for _, l in sites if l]
    flag = "  <-- reads [+12]" if loads else ""
    print(f"  {fn:38s} {len(sites)} site(s){flag}")
    for a, l in sites:
        print(f"      0x{a:06x}  {l}")
