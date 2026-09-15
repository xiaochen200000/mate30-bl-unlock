# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
# z_dis_fblock.py - ARM64 disasm of FB LockState source + userlock NV read + certify relock
import io, sys
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w
from capstone import *

d = open(r'<WORKDIR>\BACKUP_20260910\ARDUMP_1A400000.bin', 'rb').read()
BASE = 0x3A400000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

# symbol lookup from embedded nm table
TAB = d.index(b'000000019 __func__.42001')
syms = {}
for m in __import__('re').finditer(r'^([0-9a-f]{16}) .{7} \.text\t([0-9a-f]{16}) (.+)$', d[TAB:].decode('ascii', 'replace'), __import__('re').M):
    syms[m.group(3).strip()] = int(m.group(1), 16)

def sym_of(addr):
    best = None
    for n, v in syms.items():
        if v <= addr and (best is None or v > best[1]):
            best = (n, v)
    return best

def dis(addr, n, label=''):
    s = sym_of(addr)
    print('==== %s @%08x (%s) ====' % (label or (s[0] if s else '?'), addr, s[0] if s else '?'))
    code = d[addr - BASE: addr - BASE + n]
    for i in md.disasm(code, addr):
        tgt = ''
        if i.mnemonic in ('bl', 'b') and i.op_str.startswith('#'):
            try:
                ta = int(i.op_str[1:], 16)
                ts = sym_of(ta)
                if ts and ta - ts[1] < 0x4000:
                    tgt = '   ; <%s+0x%x>' % (ts[0], ta - ts[1])
            except Exception:
                pass
        print('%08x  %-10s %s%s' % (i.address, i.mnemonic, i.op_str, tgt))
    print()

dis(0x3a4274f0, 240, 'FB_LockState_source')
dis(0x3a426a28, 240, 'USER_lock_NV_read')
dis(0x3a4276d8, 64, 'pathA_probe')
dis(0x3a424ef8, 424, 'cmd_hwdog_certify_relock')
