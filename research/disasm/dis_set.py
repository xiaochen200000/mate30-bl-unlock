# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
# z_dis_set.py - disasm certify_set handler + lock state string + fblock info
import io, sys
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w
from capstone import *

d = open(r'<WORKDIR>\BACKUP_20260910\ARDUMP_1A400000.bin', 'rb').read()
BASE = 0x3A400000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

FUNCS = {
    'cmd_hwdog_certify_set': (0x3a4250a0, 684),
    'get_lock_state_string': (0x3a412f7c, 328),
    'nve_fblock_info': (0x3a4273e4, 268),
    'oeminfo_lock_stat_write': (0x3a426b94, 552),
}

def dis(name):
    addr, n = FUNCS[name]
    print('==== %s @%08x ====' % (name, addr))
    code = d[addr - BASE: addr - BASE + n]
    for i in md.disasm(code, addr):
        print('%08x  %-10s %s' % (i.address, i.mnemonic, i.op_str))
    print()

dis('get_lock_state_string')
dis('nve_fblock_info')
dis('cmd_hwdog_certify_set')

# dump strings referenced around the handler region for context
for va, ln in [(0x3a635628, 0x40), (0x3a635648, 0x60), (0x3a635400, 0x80)]:
    off = va - BASE
    print('STR @%08x: %r' % (va, d[off:off + ln]))
