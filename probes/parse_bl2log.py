# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
# z_parse_bl2log.py - parse the captured bl2.bin log buffer format (baseline for failure analysis)
import io, sys, re, struct
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w

d = open(r'<WORKDIR>\DIAG_DUMP\bl2.bin', 'rb').read()
print('bl2.bin size: %d' % len(d))

# find printable log runs (the BL2 log entries we saw: '[2292425][cpu0]BL2: Booting fastboot...')
runs = []
st = 0
while True:
    i = d.find(b'[', st)
    if i < 0:
        break
    j = d.find(b'\x00', i)
    if j < 0:
        j = min(i + 300, len(d))
    seg = d[i:j]
    if re.match(rb'^\[\d+\]\[cpu\d\]', seg):
        runs.append((i, seg))
    st = i + 1
print('log entries found: %d' % len(runs))
for off, seg in runs:
    print('  @0x%05x: %r' % (off, seg[:110]))

# log buffer boundaries: first and last entry
if runs:
    print('log region: 0x%05x - 0x%05x' % (runs[0][0], runs[-1][0] + len(runs[-1][1])))
    # head of buffer
    print('buffer head 32B: %s' % d[runs[0][0] - 32:runs[0][0]].hex())
