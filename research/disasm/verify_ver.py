# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
# z_verify_ver.py - is boot_android_ORIG == BOOT_132 stripped? find ramdisk 132 source
import io, sys, hashlib
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w

def sha(b):
    return hashlib.sha256(b).hexdigest()[:20]

boot_pkg = open(r'<WORKDIR>\_ARCH\misc\BOOT_132.bin', 'rb').read()
print('BOOT_132.bin:', len(boot_pkg), 'magic:', boot_pkg[:8].hex())
i = boot_pkg.find(b'ANDROID!')
print('ANDROID! at offset:', i)
if i >= 0:
    stripped = boot_pkg[i:]
    print('stripped len:', len(stripped), 'sha:', sha(stripped))
    # package header version strings
    hdr = boot_pkg[:i]
    for pat in (b'10.1.0', b'TAS', b'132', b'11.0.0', b'102.'):
        p = hdr.find(pat)
        if p >= 0:
            print('hdr string @%d: %r' % (p, hdr[max(0, p-8):p+40]))

orig = open(r'<WORKDIR>\FINAL\root\boot_android_ORIG.img', 'rb').read()
print('boot_android_ORIG:', len(orig), 'sha:', sha(orig))
if i >= 0:
    n = min(len(orig), len(stripped))
    same = stripped[:n] == orig[:n]
    print('MATCH (first %d B): %s' % (n, same))
    if not same:
        # find first diff
        for j in range(0, n, 4096):
            if stripped[j:j+4096] != orig[j:j+4096]:
                print('first diff block @0x%x: pkg=%s orig=%s' % (j, stripped[j:j+16].hex(), orig[j:j+16].hex()))
                break

# ramdisk provenance: search version strings in flash_ORIG
rd = open(r'<WORKDIR>\rootwork\RAMDISK_flash_ORIG.img', 'rb').read()
print()
print('RAMDISK_flash_ORIG:', len(rd), 'magic:', rd[:8].hex())
for pat in (b'10.1.0', b'132', b'11.0.0', b'176', b'185'):
    cnt = 0
    p = 0
    hits = []
    while True:
        q = rd.find(pat, p)
        if q < 0:
            break
        hits.append((q, rd[max(0, q-10):q+30]))
        p = q + 1
        cnt += 1
        if cnt >= 3:
            break
    for h in hits:
        print('  %r @%d: %r' % (pat, h[0], h[1]))
