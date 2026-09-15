# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
# z_dis_unlock64.py - ARM64 disasm of unlock flow + lock getters
import io, sys, struct
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w
from capstone import *

d = open(r'<WORKDIR>\BACKUP_20260910\ARDUMP_1A400000.bin', 'rb').read()
BASE = 0x3A400000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

FUNCS = {
    'get_bootinfo_lock_status': (0x3a412f40, 60),
    'get_bootinfo_fblock_status': (0x3a413238, 44),
    'fastboot_unlock_execute_func': (0x3a4132d8, 204),
    'usr_fastboot_unlock': (0x3a42534c, 884),
    'fastboot_lock_stat_initial': (0x3a413594, 356),
}

def dis(name):
    addr, n = FUNCS[name]
    print('==== %s @%08x (%dB) ====' % (name, addr, n))
    code = d[addr - BASE: addr - BASE + n]
    for i in md.disasm(code, addr):
        print('%08x  %-10s %s' % (i.address, i.mnemonic, i.op_str))
    print()

dis('usr_fastboot_unlock')
dis('get_bootinfo_lock_status')
dis('get_bootinfo_fblock_status')
dis('fastboot_unlock_execute_func')
dis('fastboot_lock_stat_initial')
