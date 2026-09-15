# -*- coding: utf-8 -*-
# 归档自 HG_REPO 会话脚本：路径已去本机化（<WORKDIR> 为占位），逻辑未动。
# z_pollute_diag.py - BootROM pollution investigation (user's main line):
#  READ-ONLY dump of all leftover-debug state at FRESH boot, then FULL cleanup
#  (including 0x21E98 OPC slot that every previous chain cleanup MISSED).
import io, sys, os, time, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import v62b_final as V
    import z_ar_read as Z
except ImportError:
    print('本归档脚本依赖会话期模块 v62b_final.py / z_ar_read.py（未随仓库分发，见 README）。')
    print('如需实际运行，请自行准备这两个模块放到本目录；当前仅可作只读记录参考。')
    sys.exit(2)

def log(m):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), m), flush=True)

def find_port():
    import serial.tools.list_ports
    for q in serial.tools.list_ports.comports():
        if q.vid == 0x12D1 and q.pid == 0x3609:
            return q.device
    return None

REGIONS = [
    ('BootRAM 0x21E00 (desc/OPC)', 0x21E00),
    ('FPB 0xE0002000', 0xE0002000),
    ('DWT 0xE0001000', 0xE0001000),
    ('DBG 0xE000ED00', 0xE000ED00),
    ('ROM 0x800 (0x930 handoff)', 0x800),
    ('ADBG 0xE0004000', 0xE0004000),
    ('BROMREG 0x80000000', 0x80000000),
    ('BROMREG2 0x80000040', 0x80000040),
    ('BROMREG3 0x80000200', 0x80000200),
    ('BROMREG4 0x80001000', 0x80001000),
]

def main():
    p = find_port()
    if not p:
        log('no COM'); return 1
    s = V.open_ser(p)
    if not s:
        log('open fail'); return 1
    r = V.session_start(s)[:1]
    log('session: %r' % r)
    if r != b'\x07':
        log('not 07'); return 1
    # bare CD answer BEFORE any upload (raw 0x21E04 status word)
    raw = Z.cd_read(s, 1, 1.5)
    log('bare CD @FRESH (0x21E04 raw): %r' % (raw.hex() if raw else 'none'))
    if not V.upload_plain(s, open(V.XL_IMG, 'rb').read(), 0x22000, 'xloader', send_tail=True):
        log('xloader FAIL'); return 1
    s2, p2 = V.find_xloader_session(p, s)
    if not s2:
        log('no xloader session'); return 1
    log('xloader session on %s' % p2)
    model, lit = Z.probe_model(s2)
    if not model:
        log('probe FAIL'); return 1
    log('model=%s lit=%#x' % (model, lit))
    if not Z.selftest(s2, model, lit):
        log('selftest FAIL'); return 1
    M = Z.MODELS[model]
    if not Z.arm(s2, model, lit, 0x21E00):
        log('arm FAIL'); return 1

    dumps = {}
    for name, addr in REGIONS:
        Z.write_mem(s2, M['cursor'], struct.pack('<I', addr))
        d = Z.cd_read(s2, Z.CHUNK, 3.0)
        dumps[name] = d
        log('read %s: %d B' % (name, len(d)))
        fn = r'<WORKDIR>\diag_%s.bin' % name.split(' ')[0].replace('0x', '')
        open(fn, 'wb').write(d)
    # ---- analyze ----
    bram = dumps.get('BootRAM 0x21E00 (desc/OPC)', b'')
    if len(bram) >= 0x100:
        log('0x21E04 status word: %s' % bram[4:8].hex())
        log('0x21E90..0x21EC0: %s' % bram[0x90:0xC0].hex())
        nz = [(0x21E00 + i, b) for i, b in enumerate(bram[0x80:0x100]) if b]
        log('0x21E80-0x21F00 nonzero bytes: %s' % (['%x=%02x' % x for x in nz[:24]] or 'NONE'))
    fpb = dumps.get('FPB 0xE0002000', b'')
    if len(fpb) >= 0x48:
        log('FP_CTRL: %s' % fpb[0:4].hex())
        for i in range(8):
            log('FP_COMP%d: %s' % (i, fpb[8 + i * 4:12 + i * 4].hex()))
    dwt = dumps.get('DWT 0xE0001000', b'')
    if len(dwt) >= 0x40:
        log('DWT_CTRL: %s' % dwt[0:4].hex())
        for i in range(4):
            log('DWT_COMP%d: %s  MASK: %s  FUNC: %s' % (
                i, dwt[0x20 + i * 4:0x24 + i * 4].hex(),
                dwt[0x24 + i * 4:0x28 + i * 4].hex(),
                dwt[0x28 + i * 4:0x2C + i * 4].hex()))
    dbg = dumps.get('DBG 0xE000ED00', b'')
    if len(dbg) >= 0x100:
        log('DEMCR: %s' % dbg[0xFC:0x100].hex())
        log('VTOR: %s' % dbg[0x08:0x0C].hex())
    adbg = dumps.get('ADBG 0xE0004000', b'')
    if len(adbg) >= 0x90:
        log('ADBG DBGBVR0: %s  DBGBCR0: %s' % (adbg[0x30:0x34].hex(), adbg[0x34:0x38].hex()))
        log('ADBG DBGDSCR: %s' % adbg[0x88:0x8C].hex())
    for rn in ('BROMREG 0x80000000', 'BROMREG2 0x80000040', 'BROMREG3 0x80000200', 'BROMREG4 0x80001000'):
        blk = dumps.get(rn, b'')
        if len(blk) >= 0x10:
            log('%s: head16=%s' % (rn.split(' ')[0], blk[:16].hex()))
    rom = dumps.get('ROM 0x800 (0x930 handoff)', b'')
    if len(rom) >= 0x160:
        prist = open(r'<WORKDIR>\BACKUP_20260910\BOOTROM_4G_DUMP.bin', 'rb').read()
        seg_new = rom[0x100:0x160]      # 0x900..0x960
        seg_old = prist[0x900:0x960]
        same = seg_new == seg_old
        log('ROM 0x900-0x960 vs pristine dump: %s' % ('IDENTICAL' if same else 'DIFFERENT'))
        if not same:
            log('  new: %s' % seg_new.hex())
            log('  old: %s' % seg_old.hex())
        log('0x930 area 16B: %s' % rom[0x130:0x140].hex())

    # ---- FULL CLEANUP (incl the previously-missed 0x21E98) ----
    log('--- cleanup: FPB all 8 comps + DWT + 0x21E98 OPC slot + 0x21E04 ---')
    cleanup = [
        ('DEMCR', 0xE000EDFC, b'\x00' * 4),
        ('FP_CTRL', 0xE0002000, b'\x00' * 4),
    ]
    for i in range(8):
        cleanup.append(('FP_COMP%d' % i, 0xE0002008 + i * 4, b'\x00' * 4))
    cleanup += [
        ('DWT_CTRL', 0xE0001000, b'\x00' * 4),
    ]
    for i in range(4):
        cleanup += [
            ('DWT_COMP%d' % i, 0xE0001020 + i * 0x10, b'\x00' * 4),
            ('DWT_MASK%d' % i, 0xE0001024 + i * 0x10, b'\x00' * 4),
            ('DWT_FUNC%d' % i, 0xE0001028 + i * 0x10, b'\x00' * 4),
        ]
    cleanup += [
        ('0x21E98 OPC slot', 0x21E98, b'\x00' * 0x40),
        ('0x21E04 status', 0x21E04, b'\x00' * 4),
    ]
    bad = 0
    for nm, addr, blob in cleanup:
        if not Z.write_mem(s2, addr, blob):
            log('cleanup %s: WRITE FAIL' % nm); bad += 1
    log('cleanup writes done, %d failures' % bad)
    # verify re-read
    Z.write_mem(s2, M['cursor'], struct.pack('<I', 0x21E00))
    bram2 = Z.cd_read(s2, Z.CHUNK, 3.0)
    log('verify 0x21E04: %s (want 00000000)' % bram2[4:8].hex())
    log('verify 0x21E98..: %s' % bram2[0x98:0xB8].hex())
    Z.write_mem(s2, M['cursor'], struct.pack('<I', 0xE0002000))
    fpb2 = Z.cd_read(s2, Z.CHUNK, 3.0)
    log('verify FP_CTRL: %s  COMP0-3: %s %s %s %s' % (
        fpb2[0:4].hex(), fpb2[8:12].hex(), fpb2[12:16].hex(),
        fpb2[16:20].hex(), fpb2[20:24].hex()))
    try:
        s2.close(); s.close()
    except Exception:
        pass
    log('session closed - device left CLEAN at BootROM')
    return 0

sys.exit(main())
