# -*- coding: utf-8 -*-
# 归档自 z_scan_dumps.py：扫描目录改为命令行参数，逻辑未动。
# z_scan_dumps.py - scan the captured RAM dumps for boot logs / failure strings
import io, sys, re, os
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w

D = sys.argv[1] if len(sys.argv) > 1 else '.'
KEYS = [b'bootfail', b'BOOT FAIL', b'fail', b'error', b'Error', b'ERROR', b'panic', b'Panic',
        b'xloader', b'XLOADER', b'bl2', b'BL2', b'BL31', b'fastboot', b'FastBoot', b'reboot',
        b'download', b'Download', b'upgrade', b'verify', b'verifyfail', b'cert', b'RSA', b'rsa',
        b'log_version', b'BFM', b'bfm', b'bootmode', b'boot_mode', b'errno']

for fn in os.listdir(D):
    p = os.path.join(D, fn)
    d = open(p, 'rb').read()
    nz = sum(1 for b in d if b)
    print('==== %s (%dB, nonzero=%.1f%%) ====' % (fn, len(d), 100.0 * nz / max(1, len(d))))
    # printable runs
    runs = re.findall(rb'[\x20-\x7e]{10,}', d)
    print('  printable runs (>=10ch): %d' % len(runs))
    shown = 0
    for r in runs:
        lr = r.lower()
        if any(k.lower() in lr for k in (b'fail', b'error', b'boot', b'download', b'verify', b'log', b'panic', b'reset', b'wdt', b'reboot')):
            print('   HIT: %r' % r[:120])
            shown += 1
            if shown >= 12:
                break
    if shown == 0 and runs:
        for r in runs[:8]:
            print('   str: %r' % r[:100])
