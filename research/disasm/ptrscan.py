# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
import struct, re, io, sys
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w
d = open(r'<WORKDIR>\BACKUP_20260910\ARDUMP_1A400000.bin', 'rb').read()
BASE = 0x3A400000
TAB = d.index(b'000000019 __func__.42001')
syms = {}
for m in re.finditer(r'^([0-9a-f]{16}) .{7} \.text\t([0-9a-f]{16}) (.+)$', d[TAB:].decode('ascii', 'replace'), re.M):
    syms[m.group(3).strip()] = int(m.group(1), 16)

def sym_of(a):
    best = None
    for n, v in syms.items():
        if v <= a < v + 0x8000 and (best is None or v > best[1]):
            best = (n, v)
    return best

for va in (0x3a624ec8,):
    needle = struct.pack('<Q', va)
    st = 0
    cnt = 0
    while True:
        i = d.find(needle, st)
        if i < 0:
            break
        s = sym_of(BASE + i)
        print('ptr to %#x @file 0x%x VA %#x in %s' % (va, i, BASE + i, s[0] if s else '?'))
        print('  ctx: %s' % d[i - 16:i + 64].hex())
        cnt += 1
        st = i + 1
    print('total ptrs to %#x: %d' % (va, cnt))
    # also 4-byte low-half references (adrp-loaded page + add handled separately) - check any 4B match
    n4 = struct.pack('<I', va & 0xFFFFFFFF)
    c2 = 0
    st = 0
    locs = []
    while True:
        i = d.find(n4, st)
        if i < 0:
            break
        locs.append(i)
        st = i + 1
        c2 += 1
    print('4B low matches: %d' % c2, [hex(BASE + x) for x in locs[:8]])
