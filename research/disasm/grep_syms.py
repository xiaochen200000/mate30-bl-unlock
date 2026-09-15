# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
import re, io, sys
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w
d = open(r'<WORKDIR>\BACKUP_20260910\ARDUMP_1A400000.bin', 'rb').read()
TAB = d.index(b'000000019 __func__.42001')
for m in re.finditer(r'^([0-9a-f]{16}) .{7} \.text\t([0-9a-f]{16}) (.+)$', d[TAB:].decode('ascii', 'replace'), re.M):
    n = m.group(3).strip()
    if any(k in n.lower() for k in ('certify', 'hwdog', 'rdmode', 'fblock', 'lock_stat', 'nve')):
        print(m.group(1), m.group(2), n)
