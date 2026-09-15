# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
# z_bootrom_scan.py - scan BootROM dump for peripheral address constants (movw/movt pairs)
import io, sys, struct, re
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w

d = open(r'<WORKDIR>\BACKUP_20260910\BOOTROM_4G_DUMP.bin', 'rb').read()
print('BootROM dump: %d B' % len(d))
print('head 16B:', d[:16].hex())

# ARM32 Thumb: movw Rd,#imm16 = 0xF2/0xF3 prefix... word-level decode of movw/movt pairs is messy.
# Simpler: the BootROM is mostly LITERAL-LOAD based (LDR rX,[PC,#imm] -> literal pools hold full 32-bit addresses).
# Scan 4-byte words for values that look like peripheral base addresses (0x80000000-0xFFFFFFFF except code range).
addr_words = {}
n = len(d) // 4
for idx in range(n):
    v = struct.unpack_from('<I', d, idx * 4)[0]
    if 0xE0000000 <= v <= 0xFFFFFFFF or 0xFFF00000 <= v <= 0xFFFFFFFF or 0x80000000 <= v < 0xE0000000:
        addr_words.setdefault(v, []).append(idx * 4)
buckets = {}
for v, locs in addr_words.items():
    buckets.setdefault(v >> 20, []).append(v)
print('address constant buckets (by 1MB):')
for b in sorted(buckets):
    vals = sorted(set(buckets[b]))
    print('  %#010x MB: %d unique' % (b << 20, len(vals)), ['%#x' % v for v in vals[:6]])
