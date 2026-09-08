#!/usr/bin/env python3
"""Decide whether the exFAT readdir/stat code path touches the broken
current_thread_info() idiom on the current lab kernel.

Rationale: CONFIG_KERNEL_STACK_LARGE=y moves thread_info->task from +12 to +16.
Vendor modules read [+12]. Any function on our exercised path that does the
SP-mask + [+12] load is a fidelity hazard and its results are provisional.
"""
import re
import sys

MASK = re.compile(r"^\s*([0-9a-f]+):\s+e3c[0-9a-f]{2}d7f")
LDR = re.compile(r"ldr\s+(?:r\d+|ip|fp|lr), \[(?:r\d+|ip|fp|lr), #(\d+)\]")

PATHS = {
    "exfat_core": [
        "ffsReadDir", "ffsGetStat",
        "exfat_get_uni_name_from_ext_entry",
        "get_entry_set_in_dir", "extract_uni_name_from_name_entry",
        "get_entry_in_dir", "exfat_get_entry_type",
        "nls_uniname_to_cstring", "nls_cstring_to_uniname",
    ],
    "exfat_fs": [
        "exfat_iterate", "exfat_lookup", "exfat_getattr",
        "exfat_fill_super", "exfat_setattr",
    ],
}


def load(mod):
    funcs = []
    for line in open(f"logs/{mod}.funcs"):
        p = line.split()
        if len(p) >= 3:
            try:
                funcs.append((int(p[0], 16), int(p[1]), p[2]))
            except ValueError:
                pass
    sites = []
    lines = open(f"logs/{mod}.dis", errors="replace").read().splitlines()
    for i, ln in enumerate(lines):
        m = MASK.match(ln)
        if not m:
            continue
        off = None
        for j in range(i + 1, min(i + 8, len(lines))):
            lm = LDR.search(lines[j])
            if lm and lm.group(1) in ("12", "16"):
                off = lm.group(1)
                break
        sites.append((int(m.group(1), 16), off))
    return funcs, sites


for mod, names in PATHS.items():
    funcs, sites = load(mod)
    print(f"==== {mod}.ko ====")
    for name in names:
        ent = [f for f in funcs if f[2] == name]
        if not ent:
            print(f"  {name:38s} NOT PRESENT")
            continue
        s, sz, _ = ent[0]
        inside = [(a, o) for a, o in sites if s <= a < s + sz]
        if not inside:
            verdict = "clean (no SP-mask)"
        else:
            reads12 = [a for a, o in inside if o == "12"]
            verdict = (f"HAZARD: {len(inside)} SP-mask, "
                       f"{len(reads12)} read [+12]" if reads12
                       else f"SP-mask x{len(inside)} but no [+12] load")
        print(f"  {name:38s} 0x{s:06x}+{sz:<5d} {verdict}")
    print()
