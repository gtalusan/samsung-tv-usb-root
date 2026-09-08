"""Attribute .rodata string references in an ARM ET_REL module to their
containing function, by decoding .rel.text and reading the in-place addend.

Usage:
  relscan.py MODULE.ko --list                 # histogram of reloc target symbols
  relscan.py MODULE.ko SECTIONNAME [ADDEND..] # sites referencing SECTION(+addend)
"""
import struct
import sys

KO = sys.argv[1]
d = open(KO, 'rb').read()
shoff, = struct.unpack_from('<I', d, 0x20)
shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x2e)
secs = []
for i in range(shnum):
    o = shoff + i * shentsize
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from('<10I', d, o)
    secs.append(dict(name=name, typ=typ, off=off, size=size, link=link, info=info))
strtaboff = secs[shstrndx]['off']
for s in secs:
    o = strtaboff + s['name']
    s['n'] = d[o:d.index(b'\0', o)].decode()
text = [s for s in secs if s['n'] == '.text'][0]
symtab = [s for s in secs if s['n'] == '.symtab'][0]
strtab = secs[symtab['link']]


def sym(idx):
    o = symtab['off'] + idx * 16
    nm, val, size, info, other, shndx = struct.unpack_from('<IIIBBH', d, o)
    p = strtab['off'] + nm
    return d[p:d.index(b'\0', p)].decode(), val, size, info & 0xf, shndx


funcs = sorted((v, sz, n) for i in range(symtab['size'] // 16)
               for (n, v, sz, t, sh) in [sym(i)] if t == 2)


def owner(a):
    for v, sz, n in funcs:
        if v <= a < v + sz:
            return n
    return "?"


rel = [s for s in secs if s['n'] == '.rel.text'][0]
entries = []
for i in range(rel['size'] // 8):
    off, info = struct.unpack_from('<II', d, rel['off'] + i * 8)
    n, v, sz, t, sh = sym(info >> 8)
    tgt = n if n else (secs[sh]['n'] if sh < len(secs) else '?')
    addend, = struct.unpack_from('<I', d, text['off'] + off)
    entries.append((off, tgt, addend, info & 0xff))

if sys.argv[2] == '--list':
    hist = {}
    for off, tgt, addend, rtyp in entries:
        hist[tgt] = hist.get(tgt, 0) + 1
    for k, v in sorted(hist.items(), key=lambda kv: -kv[1]):
        print("%6d  %s" % (v, k))
else:
    want_sec = sys.argv[2]
    want = [int(x, 0) for x in sys.argv[3:]] or None
    for off, tgt, addend, rtyp in entries:
        if tgt == want_sec and (want is None or addend in want):
            print(".text+0x%06x  addend=0x%x  rtype=%d  in %s" % (off, addend, rtyp, owner(off)))
