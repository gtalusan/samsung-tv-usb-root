#!/usr/bin/env python3
"""Extract exported-symbol addresses from a raw ARM Linux-4.1 kernel image.

The kernel's __ksymtab section stores, per exported symbol, a
`struct kernel_symbol { unsigned long value; const char *name; }` pair
(include/linux/export.h), where `name` points into __ksymtab_strings.
So an exported symbol's *exact* function address is recoverable without
kallsyms: find the symbol-name string, then find the 8-byte pair whose
second word equals the string's address; the first word is the address.

This is how the TV uImage (no kallsyms, no symtab) is navigated.

Usage:
  python3 tools/ksymtab_scan.py KERNEL.BIN BASE_ADDR SYM [SYM...]
  e.g. BASE_ADDR = 0xc0008000 for the T-MSM uImage raw kernel.
"""
import struct
import sys


def find_symbol(img: bytes, base: int, name: str, verbose=False):
    needle = name.encode() + b"\x00"
    addrs = []
    off = 0
    while True:
        off = img.find(needle, off)
        if off < 0:
            break
        addrs.append(base + off)
        off += 1
    results = []
    for addr in addrs:
        # scan for kernel_symbol{value, name=addr} — alignment-agnostic
        tgt = struct.pack("<I", addr)
        p = 0
        while True:
            p = img.find(tgt, p)
            if p < 0 or p < 4:
                break
            if p % 8 in (0, 4):          # accept either half-word alignment
                value = struct.unpack_from("<I", img, p - 4)[0]
                results.append((addr, value))
            p += 4
    return results


def main():
    path, base_s, *names = sys.argv[1:]
    img = open(path, "rb").read()
    base = int(base_s, 0)
    for name in names:
        res = find_symbol(img, base, name)
        if not res:
            print(f"{name}: NOT FOUND")
        for (saddr, value) in res:
            # sanity: value must be inside the kernel virtual range
            sane = 0xC0000000 <= value < 0xF0000000
            print(f"{name}: string@{saddr:#x} -> value={value:#x}"
                  + ("" if sane else "  (suspicious: outside kernel range)"))


if __name__ == "__main__":
    main()
