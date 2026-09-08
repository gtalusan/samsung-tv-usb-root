#!/usr/bin/env python3
"""Find which function references .rodata.str1.4+0xc8
("Filesystem is corrupted ...Please run fsck").

In an ET_REL ARM module a string reference is a literal-pool word carrying the
addend, patched by an R_ARM_ABS32 reloc against the string section. So: find
.rel.text entries whose r_offset lands in a literal pool and whose stored
addend is 0xc8, then attribute the pool address to a function.
"""
import struct
import subprocess
import sys

KO = "/work/fw/modules/exfat_core.ko"

# section headers
out = subprocess.run(["readelf", "-SW", KO], capture_output=True, text=True).stdout
sections = {}
for line in out.splitlines():
    line = line.strip()
    if not line.startswith("["):
        continue
    try:
        idx = int(line[1:line.index("]")].strip())
    except ValueError:
        continue
    parts = line[line.index("]") + 1:].split()
    if len(parts) >= 5:
        sections[idx] = {"name": parts[0], "off": int(parts[3], 16),
                         "size": int(parts[4], 16)}

str_idx = next(i for i, s in sections.items() if s["name"] == ".rodata.str1.4")
text_idx = next(i for i, s in sections.items() if s["name"] == ".text")
print(f".rodata.str1.4 = section {str_idx}, .text = section {text_idx}")

data = open(KO, "rb").read()
text_off = sections[text_idx]["off"]

# functions
funcs = []
out = subprocess.run(["readelf", "-sW", KO], capture_output=True, text=True).stdout
for line in out.splitlines():
    p = line.split()
    if len(p) >= 8 and p[3] == "FUNC":
        try:
            funcs.append((int(p[1], 16), int(p[2]), p[7]))
        except ValueError:
            pass
funcs.sort()


def owner(a):
    for s, sz, n in funcs:
        if s <= a < s + sz:
            return n
    return "<none>"


# relocations in .rel.text against .rodata.str1.4
out = subprocess.run(["readelf", "-rW", KO], capture_output=True, text=True).stdout
hits = []
for line in out.splitlines():
    p = line.split()
    if len(p) >= 5 and p[1].startswith("0000") and "ABS32" in line:
        try:
            r_off = int(p[0], 16)
        except ValueError:
            continue
        sym = p[4] if len(p) > 4 else ""
        if "str1.4" not in sym and "rodata" not in sym:
            continue
        # addend is stored in the word at r_off within .text
        fpos = text_off + r_off
        if fpos + 4 > len(data):
            continue
        addend = struct.unpack_from("<I", data, fpos)[0]
        if addend == 0xC8 and "str1.4" in sym:
            hits.append((r_off, addend, owner(r_off), sym))

print(f"\n{len(hits)} literal-pool reference(s) with addend 0xc8:")
for r_off, addend, fn, sym in hits:
    print(f"  .text+0x{r_off:06x}  addend=0x{addend:x}  in {fn}  ({sym})")

if not hits:
    print("\n(none via that filter; dumping ALL str1.4 relocs with addends)")
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 5 and "ABS32" in line and "str1.4" in line:
            try:
                r_off = int(p[0], 16)
            except ValueError:
                continue
            fpos = text_off + r_off
            if fpos + 4 > len(data):
                continue
            addend = struct.unpack_from("<I", data, fpos)[0]
            print(f"  .text+0x{r_off:06x} addend=0x{addend:04x} in {owner(r_off)}")
