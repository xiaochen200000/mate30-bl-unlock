# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
# z_dis_uploadstorage.py - FULL disasm of usbcmd_upload_storage_func: decode command syntax + semantics
import io, sys, re
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w
from capstone import *

d = open(r'<WORKDIR>\BACKUP_20260910\ARDUMP_1A400000.bin', 'rb').read()
BASE = 0x3A400000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
TAB = d.index(b'000000019 __func__.42001')
syms = {}
for m in re.finditer(r'^([0-9a-f]{16}) .{7} \.text\t([0-9a-f]{16}) (.+)$', d[TAB:].decode('ascii', 'replace'), re.M):
    syms[m.group(3).strip()] = int(m.group(1), 16)

def sym_of(addr):
    best = None
    for n, v in syms.items():
        if v <= addr < v + 0x8000 and (best is None or v > best[1]):
            best = (n, v)
    return best

addr = syms['usbcmd_upload_storage_func']
print('usbcmd_upload_storage_func @%08x (0x400B)' % addr)
c = d[addr - BASE: addr - BASE + 0x400]
for i in md.disasm(c, addr):
    ann = ''
    if i.mnemonic in ('bl',) and i.op_str.startswith('#'):
        try:
            ta = int(i.op_str[1:], 16)
            s = sym_of(ta)
            if s:
                ann = '   ; <%s+0x%x>' % (s[0], ta - s[1])
        except Exception:
            pass
    print('%08x  %-9s %s%s' % (i.address, i.mnemonic, i.op_str, ann))
