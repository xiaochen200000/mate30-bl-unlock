# -*- coding: utf-8 -*-
# 归档自 z_backup_dd.py：仅参数化 adb 与输出路径，逻辑未动。
# z_backup_dd.py - FIRST-THING backup of device-unique partitions via adb+dd (root required)
#  Priority: 基带(modemnvm_*/modem_secure) oeminfo 字库(nvme) cust misc bootfail_info(留证)
import io, sys, os, time, hashlib, subprocess
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w

ADB = os.environ.get('ADB', 'adb')   # 或写死你的 adb.exe 完整路径
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'BACKUP_DEVICE')
# (partition, size cap for sanity) - DEVICE-UNIQUE data per user directive
PARTS = [
    ('oeminfo', 100663296),
    ('nvme', 5242880),
    ('modemnvm_factory', 16777216),
    ('modemnvm_backup', 16777216),
    ('modemnvm_cust', 16777216),
    ('modemnvm_update', 16777216),
    ('modem_secure', 8912896),
    ('cust', 268435456),
    ('modem_fw', 67108864),
    ('misc', 2097152),
    ('bootfail_info', 2097152),
]

def log(m):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), m), flush=True)

def adb(*args, tmo=300, binary=False):
    try:
        r = subprocess.run([ADB] + list(args), capture_output=True, timeout=tmo)
        if binary:
            return r.stdout or b''
        return ((r.stdout or b'') + (r.stderr or b'')).decode('utf-8', 'replace').strip()
    except Exception as e:
        return 'ERR %r' % e

def wait_device(minutes=30):
    t0 = time.time()
    while time.time() - t0 < minutes * 60:
        o = adb('devices', tmo=15)
        for ln in o.splitlines()[1:]:
            p = ln.split()
            if len(p) == 2 and p[1] == 'device':
                return True
            if len(p) == 2 and p[1] == 'unauthorized':
                log('adb UNAUTHORIZED - need screen confirm')
        time.sleep(5)
    return False

def sh(cmd, tmo=300):
    return adb('shell', cmd, tmo=tmo)

def main():
    os.makedirs(OUT, exist_ok=True)
    log('waiting for adb device (authorized)...')
    if not wait_device():
        log('NO adb device - abort')
        return 1
    log('device online')
    # root check: su first, fallback adb root
    idw = sh('id')
    log('id: %s' % idw[:80])
    root = False
    if 'uid=0' in idw:
        root = True
        SU = ''
    else:
        s = sh('su -c id')
        if 'uid=0' in s:
            root = True
            SU = 'su -c '
        else:
            r = adb('root', tmo=30)
            log('adb root -> %s' % r[:60])
            time.sleep(2)
            idw = sh('id')
            if 'uid=0' in idw:
                root = True
                SU = ''
    if not root:
        log('NO ROOT - cannot dd partitions. Backup aborted (device-unique data untouched).')
        return 2
    log('root OK - starting partition backup')
    # partition map for verification
    tbl = sh('cat /proc/partitions', tmo=60)
    open(os.path.join(OUT, '_proc_partitions.txt'), 'w', encoding='utf-8', errors='replace').write(tbl)
    byname = sh('ls -l /dev/block/by-name/', tmo=60)
    open(os.path.join(OUT, '_by_name.txt'), 'w', encoding='utf-8', errors='replace').write(byname)
    log('partition table saved (%d, %d bytes)' % (len(tbl), len(byname)))
    ok = 0
    for name, cap in PARTS:
        dev = None
        for ln in byname.splitlines():
            if ln.rstrip().endswith(' ' + name) or ln.rstrip().endswith(' -> ' + name):
                m = re.search(r'/dev/block/(\S+)', ln) if False else None
                # by-name entries are symlinks: lrwxrwxrwx root root ... name -> /dev/block/mmcblk0pNN
                mm = re.search(r'->\s*(\S+)', ln)
                if mm:
                    dev = mm.group(1)
                break
        if not dev:
            # fallback: search whole by-name listing case-insensitive
            for ln in byname.splitlines():
                if name in ln:
                    mm = re.search(r'->\s*(\S+)', ln)
                    if mm:
                        dev = mm.group(1)
                    break
        if not dev:
            log('%-18s NOT FOUND in by-name (skip)' % name)
            continue
        # size check
        szs = sh('blockdev --getsize64 %s' % dev, tmo=30)
        try:
            sz = int(szs)
        except Exception:
            sz = -1
        if sz > cap * 2:
            log('%-18s size %s > cap*2 - SKIP (safety)' % (name, szs))
            continue
        t0 = time.time()
        d = adb('shell', '%s dd if=%s bs=4194304' % (SU, dev), tmo=900, binary=True)
        if len(d) < 4096:
            log('%-18s dd FAIL (%d B)' % (name, len(d)))
            continue
        dst = os.path.join(OUT, '%s.img' % name)
        open(dst, 'wb').write(d)
        h = hashlib.sha256(d).hexdigest()
        log('%-18s %d B (%.0fs) sha=%s' % (name, len(d), time.time() - t0, h[:16]))
        ok += 1
    log('BACKUP DONE: %d/%d partitions -> %s' % (ok, len(PARTS), OUT))
    return 0

import re
sys.exit(main())
