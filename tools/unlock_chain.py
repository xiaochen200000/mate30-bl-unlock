# -*- coding: utf-8 -*-
"""
unlock_chain.py — Mate30 (Kirin 990 4G) 解锁主脚本 · 交互式版（自包含）
================================================================================
由会话验证脚本 z_unlock_chain2.py + v62b_final.py + z_ar_read.py 合并重构：
协议时序、payload 汇编、补丁表逐字节保留，交互层重做，路径全部入 config.ini。

流程:
  [等待会话] 07=全流程 / AA=快速通道(热恢复已 arm 的会话)
  [BootROM]  null 载荷（解密后）@0x22000 → 舞步（软件总线重启 / 手动 TP4009）
  [xloader]  喂 BD sec_usb_xloader.img → xloader 接管 → 会话迁移(端口消失→重现)
  [staging]  UCE @0x60000000 → fastboot 容器 @0x1A400000 → TEE 原位解密 20s
  [任意读]   probe(基址判别) → selftest(装桩验证) → arm(三处补丁, 1024B/帧)
  [明文验证] 读回向量表 0d000014 → 7 处补丁逐个写入 + 读回验证
  [BL2]      staging @0x1E400000 (tail=启动触发) → 等端口消失 → 等 fastboot 枚举
  [fastboot] oem get-bootinfo / lock-state info(只读) → upload_storage 分区备份
  [解锁]     --unlock: oem unlock <任意16B> → getvar unlocked 确认

用法:
    python unlock_chain.py                 # 跑到 fastboot 就绪 + 只读探状态 + 分区备份
    python unlock_chain.py --unlock        # fastboot 就绪后继续执行解锁
    python unlock_chain.py --config x.ini

依赖:
    pip install pyserial keystone-engine pyusb     (pyusb 仅分区备份需要)
    + 自备组件（见 README）: 官方 BD 固件包、null 载荷解密模块 kirin_loader.py、
      BL2 镜像、fastboot.exe（Android platform-tools）
"""
import argparse
import binascii
import configparser
import os
import struct
import subprocess
import sys
import threading
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
USB_VID, USB_PID = 0x12D1, 0x3609        # 华为 USB Download Mode (CDC)
FB_USB_VID, FB_USB_PID = 0x18D1, 0xD00D  # fastboot 枚举 (Google idVendor 惯例)
CHUNK = 0x400                            # 1024B/帧
ACK, NAK = 0xAA, 0x55

# ---- 任意读: 两种基址模型（keystone 汇编 + capstone 复核）----
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
STUB_HEAD = bytes.fromhex('2de9f04f')
LIT_ORIG = 0x60014088                # getter 字面量原值

FB_BASE = 0x1A400000                 # fastboot 容器暂存地址（DDR）
FB_VEC = bytes.fromhex('0d000014')   # fastboot 向量表 SP（明文实锤）
BL2_ADDR = 0x1E400000                # BL2 staging（tail=启动触发）
UCE_ADDR = 0x60000000                # UCE 加载地址

# ---- 解锁补丁表（文件偏移 = 相对 fastboot 明文基址 0x1A400000，详见 docs/03）----
P1_BYTES = bytes.fromhex('00008052c0035fd6')    # mov w0,#0; ret
GATE_BYTES = bytes.fromhex('20008052c0035fd6')  # mov w0,#1; ret
PATCHES = [
    ('P1 isec_userlock_check', 0x26DBC, P1_BYTES),                    # 任意码解锁
    ('P-gate lock_state_chk', 0x12CF0, GATE_BYTES),                   # 命令权限门放行
    ('P6 logo_checksum', 0x88118, P1_BYTES),                          # logo 校验恒过
    ('P5b avb_is_unlocked', 0xD452C, GATE_BYTES),                     # AVB 视为已解锁
    ('P2 hwdog_certify_gate', 0x25100, bytes.fromhex('1f2003d5')),    # certify 会话门 NOP
    ('P7a bootinfo_lock_status', 0x12F40, P1_BYTES),                  # 锁显示强制 0
    ('P5 check_boot_mode', 0x5460, P1_BYTES),                         # 启动模式校验放行
]
BACKUP_PARTS = [
    # 基带族
    'modem_secure', 'nvme', 'modemnvm_factory', 'modemnvm_backup', 'modemnvm_img',
    'modemnvm_update', 'modemnvm_cust', 'modem_patch_nv', 'modem_fw', 'modem_driver',
    # 锁态族
    'oeminfo', 'frp', 'secure_storage',
    # 引导族
    'bl2', 'fastboot', 'vector', 'vrl', 'vrl_backup', 'vbmeta', 'vbmeta_system',
    'vbmeta_vendor', 'vbmeta_odm', 'vbmeta_cust', 'vbmeta_hw_product',
    'recovery_vbmeta', 'erecovery_vbmeta', 'erecovery_kernel', 'erecovery_ramdisk',
    'erecovery_vendor', 'splash2', 'dts', 'dto', 'trustfirmware', 'teeos',
    'hisee_img', 'hhee', 'fw_lpm3', 'ptable',
]

STUB_LOG = 'unlock_chain.log'


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


# ---------------------------------------------------------------- 串口层
def find_port():
    try:
        for p in serial.tools.list_ports.comports():
            if p.vid == USB_VID and p.pid == USB_PID:
                return p.device
    except Exception:
        pass
    return None


def find_port_safe(tmo=5):
    """带超时的端口枚举——卡死的 CDC 会让 pyserial 枚举阻塞。"""
    res = {}

    def _thr():
        res['p'] = find_port()
    th = threading.Thread(target=_thr, daemon=True)
    th.start()
    th.join(tmo)
    return res.get('p')


def open_ser(port):
    for _t in range(6):
        try:
            s = serial.Serial(port, 115200, timeout=2, write_timeout=2, rtscts=True)
            s.dtr = True
            s.rts = True
            time.sleep(0.2)
            return s
        except Exception:
            time.sleep(0.7)
    return None


def open_ser_safe(p, tmo=6):
    """带超时的串口打开——卡死的 CDC 会让 open 阻塞数分钟。"""
    res = {}

    def _thr():
        res['s'] = open_ser(p)
    th = threading.Thread(target=_thr, daemon=True)
    th.start()
    th.join(tmo)
    return res.get('s')


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
    """会话试探帧 @0x22001，BootROM FRESH 态应答 07。"""
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


def cd_probe(s, tmo=2.0, n=16):
    return wr(s, cdq(1), n, tmo)


def cd_read(s, n=1, tmo=2.5):
    """发 CD 收 n 字节。未 arm 时设备回 1B；arm 后回 1024B。
    ★ arm 态下 n<1024 时读完后必须 drain 残余，否则污染下一帧应答。"""
    drain(s)
    s.write(cdq(1))
    s.flush()
    buf = bytearray()
    t0 = time.time()
    while len(buf) < n and time.time() - t0 < tmo:
        b = s.read(n - len(buf))
        if b:
            buf += b
            t0 = time.time()
        else:
            time.sleep(0.01)
    if n < CHUNK:
        time.sleep(0.2)
        drain(s)
    return bytes(buf)


def bug2_write(s, addr, val4, tries=3):
    """head 重发式任意写（无 tail）——BootROM 期写原语。"""
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


def write_mem(s, addr, blob, tries=3):
    """HEAD+DATA 单帧写（不发 TAIL）——xloader 期写原语。"""
    if len(blob) > CHUNK:
        raise ValueError('blob too large')
    for t in range(tries):
        r = wr(s, head(addr, len(blob)))
        if r and r[0] == ACK:
            r = wr(s, data(1, blob))
            if r and r[0] == ACK:
                return True
            ui.info('  data NAK/none (%s)' % (r.hex() if r else 'none'))
        else:
            ui.info('  head NAK/none (%s)' % (r.hex() if r else 'none'))
        time.sleep(0.3)
    return False


def upload_plain(s, blob, addr, name):
    """完整镜像下载: HEAD + 1024B DATA 帧 + TAIL，严格 ACK 门控。"""
    ok = False
    for h in range(5):
        drain(s)
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
    t0 = time.time()
    while off < len(blob):
        c = blob[off:off + 1024]
        seq += 1
        got = False
        for attempt in range(8):
            drain(s)
            ack = wr(s, data(seq, c), 1, 2.0)
            if ack and ack[:1] == b'\xaa':
                got = True
                break
            ui.info('%s 帧重试 #%d @%d (ack=%s)' % (
                name, attempt + 1, off, ack.hex() if ack else 'none'))
            time.sleep(0.3)
        if not got:
            ui.error('%s 数据帧失败 @%d（8 次重试）' % (name, off))
            ui.progress_end()
            return False
        off += len(c)
        ui.progress(off, len(blob), label=name,
                    rate='%.0f B/s' % (off / max(time.time() - t0, 0.1)))
    tok = False
    for t in range(6):
        drain(s)
        r = wr(s, tail(seq + 1), 1, 2.0)
        if r and r[:1] == b'\xaa':
            tok = True
            break
        ui.warn('%s tail 重试 #%d (r=%s)' % (name, t + 1, r.hex() if r else 'none'))
        time.sleep(0.5)
    ui.progress_end()
    if not tok:
        ui.error('%s tail 未确认（6 次重试）' % name)
        return False
    ui.step(True, '%s 上传完成 (%d B, tail=ACK)' % (name, len(blob)))
    return True


# ---------------------------------------------------------------- 任意读（xloader 阶段）
def stub_image(model, cursor):
    return bytes.fromhex(MODELS[model]['stub_code']) + struct.pack('<I', cursor & 0xFFFFFFFF)


def probe_model(s):
    """阶段1（纯数据）: 判别基址模型。返回 (model, lit_addr) 或 (None, None)。"""
    ui.phase('任意读: 基址模型探测（纯数据写，不碰代码）')
    for cand, mdl in ((MODELS['NEW']['getter_lit'], 'NEW'), (MODELS['OLD']['getter_lit'], 'OLD')):
        M = MODELS[mdl]
        ui.info('写 getter 字面量候选 0x%X <- 0x23014 ...' % cand)
        if not write_mem(s, cand, struct.pack('<I', 0x23014)):
            continue
        r = cd_read(s, 1, 2.0)
        ui.info('CD 应答: %s' % (r.hex() if r else 'none'))
        if r and r[0] == M['probe_expect']:
            ui.step(True, '模型判定: %s（基址 0x%X）' % (mdl, M['img_base']))
            return mdl, cand
        ui.info('候选不匹配（预期 %02X）' % M['probe_expect'])
    ui.error('两个候选均未命中——不要继续，检查设备状态')
    return None, None


def getter_read(s, lit, addr, n=1):
    """getter 字面量读 n 字节（每字节一次重定位 + 一次 CD）。"""
    out = bytearray()
    for i in range(n):
        if not write_mem(s, lit, struct.pack('<I', (addr + i) & 0xFFFFFFFF)):
            return None
        r = cd_read(s, 1, 2.0)
        if not r:
            return None
        out.append(r[0])
    return bytes(out)


def selftest(s, model, lit):
    """阶段2: 装桩 + getter 读回验证（不碰代码）。"""
    M = MODELS[model]
    ui.phase('任意读: 装桩 + 读回验证')
    if not write_mem(s, M['stub'], stub_image(model, 0x1A400000)):
        ui.error('桩写入失败')
        return False
    ui.step(True, '桩 48B 写入')
    got = getter_read(s, lit, M['stub'], 4)
    ui.info('读回桩头 4B: %s（期望 %s）' % (got.hex() if got else 'none', STUB_HEAD.hex()))
    if got != STUB_HEAD:
        ui.error('桩读回不匹配')
        return False
    site = getter_read(s, lit, M['bl_getter'], 4)
    ui.info('读回补丁点 A @0x%X: %s（期望原始 %s）'
            % (M['bl_getter'], site.hex() if site else 'none', ORIG_A.hex()))
    if site != ORIG_A:
        ui.error('补丁点内容与预期不符——基址模型可能有误，中止')
        return False
    ui.step(True, '写原语/桩/补丁点全部验证通过')
    return True


def arm(s, model, lit, cursor):
    """阶段3: 三处代码补丁 + 试读。激活 1024B/帧 任意读。"""
    M = MODELS[model]
    ui.phase('任意读: 打代码补丁（A/B/C）')
    for name, addr, blob, orig in (('A bl->stub', M['bl_getter'], bytes.fromhex(M['patch_a']), ORIG_A),
                                   ('B nop-strb', M['strb'], bytes.fromhex(M['patch_b']), ORIG_B),
                                   ('C b.w-epi', M['bl_send'], bytes.fromhex(M['patch_c']), ORIG_C)):
        if not write_mem(s, addr, blob):
            ui.error('补丁 %s 写入失败——可 restore 恢复' % name)
            return False
        ui.step(True, '%s @0x%X' % (name, addr))
    if not write_mem(s, M['cursor'], struct.pack('<I', cursor & 0xFFFFFFFF)):
        ui.error('游标设置失败')
        return False
    d = cd_read(s, CHUNK, 3.0)
    ui.info('CD 试读 @0x%X: %d B  head=%s' % (cursor, len(d), d[:16].hex()))
    if len(d) == CHUNK:
        ui.step(True, '任意读已激活: 1024 B/帧')
        return True
    ui.error('试读未满帧——可 restore 后排查')
    return False


def restore(s, model):
    """把三处补丁点的原始字节写回（解除 arm）。"""
    M = MODELS[model]
    ui.phase('恢复原始字节')
    ok = True
    for addr, orig in ((M['bl_getter'], ORIG_A), (M['strb'], ORIG_B), (M['bl_send'], ORIG_C),
                       (M['getter_lit'], struct.pack('<I', LIT_ORIG))):
        if not write_mem(s, addr, orig):
            ok = False
            ui.warn('restore @0x%X 失败' % addr)
    ui.step(ok, 'restore %s' % ('完成' if ok else '部分失败'))
    return ok


# ---------------------------------------------------------------- 会话迁移与舞步
def find_xloader_session(old_port, old_s):
    """xloader 接管后 USB 重初始化 = 端口消失→重现。
    P4a 同句柄快探(4s) → P4b 监视端口消失→重现(240s) → P4c VBUS 触发(8 轮)。"""
    ui.info('P4a: 同句柄快探 (4s)')
    t0 = time.time()
    while time.time() - t0 < 4:
        for n in (1, 4):
            r = wr(old_s, cdq(1), n, 0.5)
            if r and len(r) >= 1:
                ui.step(True, '同句柄命中: %s (%dB)' % (r.hex(), len(r)))
                return old_s, old_port
        time.sleep(0.1)
    ui.info('同句柄无应答，关闭旧句柄')
    try:
        old_s.close()
    except Exception:
        pass
    ui.info('P4b: 监视端口消失→重现 (xloader usb3_reset 签名, 240s)')

    def poll_watch():
        return '端口在位' if find_port() else '端口已消失（重初始化中）'

    ui.countdown('端口迁移监视', 240, poll=poll_watch, tick=1)
    gone_seen = False
    t_gone = None
    t0 = time.time()
    while time.time() - t0 < 240:
        p = find_port()
        if p is None:
            if not gone_seen:
                gone_seen = True
                t_gone = time.time()
                ui.info('端口消失 @%.0fs (usb 重初始化签名)' % (time.time() - t0))
        elif gone_seen:
            ui.info('端口回升 @%.0fs——抢会话' % (time.time() - t_gone))
            for attempt in range(20):
                s = open_ser_safe(p)
                if s:
                    for n in (1, 4):
                        r = wr(s, cdq(1), n, 1.0)
                        if r and len(r) >= 1:
                            ui.step(True, '重初始化后命中: %s (%dB) @try %d'
                                    % (r.hex(), len(r), attempt + 1))
                            return s, p
                    st = session_start(s)
                    if st[:1] == b'\x07':
                        ui.step(True, '重初始化后 FRESH 会话 (07)')
                        return s, p
                    try:
                        s.close()
                    except Exception:
                        pass
                time.sleep(0.1)
            gone_seen = False
        time.sleep(0.1)
    ui.warn('P4c: VBUS 触发（close/reopen x 8）')
    for i in range(8):
        p = find_port()
        if p:
            s = open_ser(p)
            if s:
                drain(s)
                for n in (1, 4):
                    r = wr(s, cdq(1), n, 1.0)
                    if r and len(r) >= 1:
                        ui.step(True, 'VBUS 周期命中: %s' % r.hex())
                        return s, p
                try:
                    s.close()
                except Exception:
                    pass
        time.sleep(2)
    ui.error('P4: 未找到 xloader 会话')
    return None, old_port


def sw_restart(cfg):
    """总线级重启: 设备 → 父 HUB（真实 VBUS 事件）。未配置实例 ID 或失败时返回 False。"""
    if not cfg.get('device_instance') and not cfg.get('hub_instance'):
        return False
    ok = True
    for inst in (cfg.get('device_instance'), cfg.get('hub_instance')):
        if not inst:
            continue
        try:
            r = subprocess.run(['pnputil', '/restart-device', inst],
                               capture_output=True, text=True, timeout=40)
            out = ((r.stdout or '') + (r.stderr or '')).replace('\n', ' ')
            ui.info('sw_restart %s rc=%d' % (inst.split('\\')[0] + '...', r.returncode))
            if r.returncode != 0:
                ok = False
        except Exception as e:
            ui.warn('sw_restart 异常: %s' % str(e)[:80])
            ok = False
        time.sleep(1.5)
    return ok


def wait_session(cfg, timeout_s, wake_after=30):
    """轮询可用会话。返回 (serial, state): 07=FRESH BootROM / AA=head 接受(热恢复)。"""
    s = None
    state = None
    t0 = time.time()
    next_wake = time.time() + wake_after
    while time.time() - t0 < timeout_s:
        p = find_port_safe()
        if p:
            s2 = open_ser_safe(p)
            if s2:
                try:
                    s2.reset_input_buffer()
                except Exception:
                    pass
                r = session_start(s2)[:1]
                if r == b'\x07':
                    s, state = s2, '07'
                    break
                if r == b'\xaa':
                    s, state = s2, 'AA'
                    break
                try:
                    s2.close()
                except Exception:
                    pass
        if time.time() >= next_wake:
            ui.warn('%ds 无会话——自动总线唤醒' % wake_after)
            if not sw_restart(cfg):
                ui.info('（未配置 USB 实例 ID——请手动插拔一次 USB 线）')
            next_wake = time.time() + wake_after
        time.sleep(0.5)
    return s, state


# ---------------------------------------------------------------- 补丁与 BL2 启动
def fb_cli(cfg, *args, tmo=30):
    cmd = [cfg['fastboot_exe']] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=tmo)
        out = (r.stdout or '').strip() + ' | ' + (r.stderr or '').strip()
        return out.strip(' |')
    except Exception as e:
        return 'ERR %r' % e


def apply_patches(s, M):
    """明文验证 + 补丁表写入 + 逐个读回验证。"""
    if not write_mem(s, M['cursor'], struct.pack('<I', FB_BASE)):
        ui.error('cursor 设置失败')
        return False
    d = cd_read(s, CHUNK, 3.0)
    ui.info('明文头: %s' % (d[:16].hex() if d else 'none'))
    if not d or d[:4] != FB_VEC:
        ui.warn('明文头不符（预期 0d000014）——仍继续')

    for pname, poff, pbytes in PATCHES:
        ui.info('补丁 %s @0x%X' % (pname, FB_BASE + poff))
        if not write_mem(s, FB_BASE + poff, pbytes):
            ui.error('%s 写入失败——中止' % pname)
            return False
        if not write_mem(s, M['cursor'], struct.pack('<I', FB_BASE + poff)):
            ui.error('cursor 设置失败')
            return False
        chk = cd_read(s, len(pbytes), 3.0)
        if chk != pbytes:
            ui.error('%s 读回不匹配（%s ≠ %s）——中止' % (pname, chk.hex(), pbytes.hex()))
            return False
        ui.step(True, '%s 已生效' % pname)
    ui.step(True, '全部补丁生效: 任意码解锁 / 命令门 / logo / AVB / certify 门')
    return True


def bl2_boot_and_wait(cfg, s2):
    """BL2 staging（tail=启动触发）→ 等端口消失 → 等 fastboot 枚举 → 只读探状态。"""
    ui.info('BL2 staging @0x%X（tail=启动触发）' % BL2_ADDR)
    if not os.path.exists(cfg['bl2_img']):
        ui.error('找不到 BL2 镜像: %s（config bl2_img）' % cfg['bl2_img'])
        return False
    if not upload_plain(s2, open(cfg['bl2_img'], 'rb').read(), BL2_ADDR, 'bl2'):
        ui.error('BL2 staging 失败')
        return False
    ui.info('BL2 已喂——等待链执行（端口消失=链启动签名）...')
    try:
        s2.close()
    except Exception:
        pass
    gone = False
    for i in range(20):
        if find_port_safe() is None:
            gone = True
            ui.step(True, '端口消失 @+%ds——链已自发启动' % (i + 1))
            break
        time.sleep(1)
    if not gone:
        ui.warn('端口稳定 20s——尝试总线复位触发 BL2 启动')
        if not sw_restart(cfg):
            ui.info('（未配置 USB 实例 ID——请手动插拔一次 USB 线）')
        for i in range(60):
            if find_port_safe() is None:
                gone = True
                ui.step(True, '复位后端口消失——链已启动')
                break
            time.sleep(1)
    if not gone:
        ui.warn('端口未消失——记录现场（fastboot 可能已在枚举路径上）')

    ui.info('等待 fastboot 设备枚举（300s，交接期 COM 短暂重现属正常，勿拔线）...')
    fb_seen = False
    t0 = time.time()

    def poll_fb():
        out = fb_cli(cfg, 'devices', tmo=10)
        lines = [l for l in (out or '').splitlines() if l.strip() and 'List of devices' not in l]
        return 'fastboot: %s' % lines[0] if lines else '尚未枚举'

    ui.countdown('fastboot 枚举', 300, poll=poll_fb, tick=5)
    while time.time() - t0 < 300:
        out = fb_cli(cfg, 'devices', tmo=10)
        lines = [l for l in (out or '').splitlines() if l.strip() and 'List of devices' not in l]
        if lines:
            ui.step(True, 'FASTBOOT 设备: %s' % lines[0])
            fb_seen = True
            break
        if find_port_safe():
            ui.warn('COM 口回落——追加总线复位逼 fastboot 枚举')
            sw_restart(cfg)
            time.sleep(10)
        time.sleep(5)
    if not fb_seen:
        ui.error('fastboot 未枚举——插拔/重进下载模式可恢复')
        return False
    ui.info('get-bootinfo: %s' % fb_cli(cfg, 'oem', 'get-bootinfo', tmo=20))
    ui.info('lock-state: %s' % fb_cli(cfg, 'oem', 'lock-state', 'info', tmo=20))
    ui.step(True, 'fastboot 已就绪（补丁全带）')
    return True


# ---------------------------------------------------------------- 分区备份（fastboot USB）
def backup_via_usb(cfg):
    """pyusb 原生 fastboot 客户端: upload_storage:<part> + upload 流回读。"""
    try:
        import usb.core
        import usb.util
    except ImportError:
        ui.warn('缺少 pyusb（pip install pyusb）——跳过分区备份')
        return False
    dev = None
    for d in usb.core.find(find_all=True):
        if d.idVendor == FB_USB_VID and d.idProduct == FB_USB_PID:
            dev = d
            break
    if dev is None:
        ui.warn('备份: 未找到 fastboot USB 设备')
        return False
    cfgd = dev.get_active_configuration()
    ine = oute = None
    for intf in cfgd:
        i_in = [e for e in intf if (e.bEndpointAddress & 0x80) and (e.bmAttributes & 3) == 2]
        i_out = [e for e in intf if not (e.bEndpointAddress & 0x80) and (e.bmAttributes & 3) == 2]
        if i_in and i_out:
            try:
                usb.util.claim_interface(dev, intf)
            except Exception as e:
                ui.warn('claim 失败: %r' % e)
                return False
            ine, oute = i_in[0], i_out[0]
            break
    if ine is None:
        ui.warn('无 bulk 端点')
        return False

    def tx(d):
        data = d if isinstance(d, bytes) else d.encode('latin1')
        n = 0
        while n < len(data):
            n += oute.write(data[n:n + 512], 2000)
        if len(data) % 512 == 0:
            try:
                oute.write(b'', 1000)
            except Exception:
                pass

    def rx(tmo_ms):
        buf = bytearray()
        t0 = time.time()
        while time.time() - t0 < tmo_ms / 1000.0:
            try:
                pkt = ine.read(512, 500)
                buf += pkt
                if len(pkt) < 512:
                    try:
                        pkt2 = ine.read(512, 60)
                        buf += pkt2
                        if len(pkt2) < 512:
                            break
                    except Exception:
                        break
            except Exception:
                break
        return bytes(buf)

    outdir = os.path.join(cfg['out_dir'], 'PARTBACKUP')
    os.makedirs(outdir, exist_ok=True)
    okcnt = failcnt = 0
    total = len(BACKUP_PARTS)
    for idx, part in enumerate(BACKUP_PARTS, 1):
        try:
            tx('upload_storage:%s' % part)
            r = rx(10000)
            if not r:
                failcnt += 1
                ui.progress(idx, total, label='backup')
                continue
            tx('upload')
            data = bytearray()
            t0 = time.time()
            while time.time() - t0 < 25:
                try:
                    pkt = ine.read(512, 800)
                    if pkt:
                        data += pkt
                        t0 = time.time()
                    else:
                        time.sleep(0.02)
                except Exception:
                    break
            out = os.path.join(outdir, part + '.bin')
            open(out, 'wb').write(bytes(data))
            tag = 'OK' if len(data) > 4096 else 'small?'
            if len(data) > 4096:
                okcnt += 1
            else:
                failcnt += 1
            ui.info('  %-18s %d B [%s]' % (part, len(data), tag))
        except Exception as e:
            ui.warn('  %s 异常 %r' % (part, e))
            failcnt += 1
        ui.progress(idx, total, label='backup')
    ui.progress_end()
    try:
        usb.util.dispose_resources(dev)
    except Exception:
        pass
    ui.step(True, '备份完成: OK=%d FAIL=%d -> %s' % (okcnt, failcnt, outdir))
    return okcnt > 0


# ---------------------------------------------------------------- 主流程
def do_unlock(cfg):
    """oem unlock 任意码 + 读回确认。"""
    unlocked = False
    for code in ('4' * 16, 'U' * 16):
        ui.info('oem unlock %s...' % code[:4])
        out = fb_cli(cfg, 'oem', 'unlock', code, tmo=60)
        ui.info('oem unlock => %s' % out)
        if 'OKAY' in out or 'UNLOCKED' in out.upper():
            unlocked = True
            break
        if 'FAILED' in out and 'not allowed' in out.lower():
            ui.warn('%s 被拒（not allowed）——P1 未生效？' % code[:4])
    for cmd in (('oem', 'get-bootinfo'), ('getvar', 'unlocked'), ('oem', 'lock-state', 'info')):
        ui.info('%s => %s' % (' '.join(cmd), fb_cli(cfg, *cmd, tmo=20)))
    ui.step(unlocked, '解锁结果: %s' % ('成功' if unlocked else '未确认'))
    return unlocked


def main():
    global ui
    ap = argparse.ArgumentParser(description='Mate30 解锁主脚本（加载链+补丁+BL2+fastboot+解锁）')
    ap.add_argument('--config', default=os.path.join(HERE, 'config.ini'))
    ap.add_argument('--unlock', action='store_true', help='fastboot 就绪后继续执行解锁')
    ap.add_argument('--no-backup', action='store_true', help='跳过 upload_storage 分区备份')
    a = ap.parse_args()

    if not os.path.exists(a.config):
        print('缺少配置文件 %s —— 请复制 config.example.ini 为 config.ini 并填写路径。' % a.config)
        return 2
    ui = make_ui(logfile=os.path.join(HERE, STUB_LOG))
    cp = configparser.ConfigParser()
    cp.read(a.config, encoding='utf-8')
    bd_dir = cp.get('paths', 'bd_dir', fallback='').strip()
    out_dir = cp.get('paths', 'out_dir', fallback='').strip() or os.getcwd()
    cfg = {
        'bd_dir': bd_dir,
        'out_dir': out_dir,
        'port': cp.get('paths', 'port', fallback='').strip() or None,
        'kirin_dir': cp.get('paths', 'kirin_module_dir', fallback='').strip(),
        'bl2_img': cp.get('paths', 'bl2_img', fallback='').strip(),
        'fastboot_exe': cp.get('paths', 'fastboot_exe', fallback='fastboot').strip(),
        'device_instance': cp.get('paths', 'usb_device_instance', fallback='').strip(),
        'hub_instance': cp.get('paths', 'usb_hub_instance', fallback='').strip(),
        'xl_img': os.path.join(bd_dir, 'sec_usb_xloader.img'),
        'uce_img': os.path.join(bd_dir, 'sec_usb_xloader2.img'),
        'fb_img': os.path.join(bd_dir, 'sec_fastboot.img'),
    }
    for k in ('xl_img', 'uce_img', 'fb_img', 'bl2_img'):
        if not cfg[k] or not os.path.exists(cfg[k]):
            ui.error('找不到 %s: %s' % (k, cfg[k]))
            return 2

    ui.banner('Mate30 解锁主脚本（链 + 补丁 + BL2 + fastboot）')
    ui.info('BD 目录 : %s' % cfg['bd_dir'])
    ui.info('BL2     : %s' % cfg['bl2_img'])

    # ---- 0: 会话门 ----
    ui.phase('等待设备会话（07=全流程 / AA=热恢复）')
    s, state = wait_session(cfg, 600, wake_after=30)
    if not s:
        ui.error('600s 内无会话')
        return 1
    ui.step(True, 'SESSION %s' % state)

    armed_M = None
    if state == 'AA':
        # 热恢复: xloader 存活（可能已 arm）——直接 DDR 读回验证
        ui.phase('快速通道: 恢复已 arm 的 xloader 会话')
        for mname in ('NEW', 'OLD'):
            M = MODELS[mname]
            if not write_mem(s, M['cursor'], struct.pack('<I', FB_BASE)):
                continue
            d = cd_read(s, 16, 3.0)
            ui.info('恢复读回 (%s): %s' % (mname, d[:16].hex() if d else 'none'))
            if d and d[:4] == FB_VEC:
                armed_M = M
                ui.step(True, '已 arm 会话确认——fastboot 明文完好')
                break
        if armed_M is None:
            ui.warn('恢复读回失败——退回全流程（在 AA 会话上重新加载）')
    else:
        # ---- 1: null 载荷 ----
        ui.phase('P1: null 载荷')
        kirin_dir = cfg['kirin_dir']
        if not kirin_dir or not os.path.isdir(kirin_dir):
            ui.error('未配置 kirin_module_dir（null 载荷解密模块目录，见 README 自备组件）')
            return 2
        sys.path.insert(0, kirin_dir)
        try:
            import kirin_loader as K
        except ImportError as e:
            ui.error('在 %s 下找不到 kirin_loader.py: %s' % (kirin_dir, e))
            return 2
        loader_dir = getattr(K, 'LOADER_DIR', kirin_dir)
        null_blob = K.dtl(open(os.path.join(loader_dir, 'null.ktl'), 'rb').read())
        ui.step(True, 'null 载荷解密完成: %d B' % len(null_blob))
        if not upload_plain(s, null_blob, 0x22000, 'null'):
            ui.error('null 下发失败')
            return 1
        # ---- 2: 舞步（软件总线重启 x2，或按提示手动）----
        ui.phase('P2: 舞步（总线重启）')
        try:
            s.close()
        except Exception:
            pass
        t_gone = time.time()
        got07 = False
        for round_ in range(5):
            if sw_restart(cfg):
                time.sleep(2)
                sw_restart(cfg)   # 双重重启，会话重建更可靠
            else:
                ui.info('（未配置 USB 实例 ID——请手动执行 TP4009 舞步：断开 3 秒再接通）')
                ui.countdown('等待手动舞步', 60,
                             poll=lambda: '端口在位' if find_port_safe() else '端口已消失')
            for t in range(45):
                p = find_port_safe()
                if p:
                    s2 = open_ser_safe(p)
                    if s2:
                        try:
                            s2.reset_input_buffer()
                        except Exception:
                            pass
                        r = session_start(s2)
                        if r[:1] == b'\x07':
                            s = s2
                            got07 = True
                            ui.step(True, '会话重建 (07)，耗时 %.1fs' % (time.time() - t_gone))
                            break
                        try:
                            s2.close()
                        except Exception:
                            pass
                time.sleep(1)
            if got07:
                break
            ui.warn('第 %d 轮未获得 07 会话' % (round_ + 1))
        if not got07:
            ui.error('软件舞步后未获得 07 会话')
            return 1

    # ---- 3: 喂 BD xloader ----
    ui.phase('P3: 喂 BD xloader → 设备端解密运行')
    if armed_M is None:
        if not upload_plain(s, open(cfg['xl_img'], 'rb').read(), 0x22000, 'bd-xloader'):
            ui.error('xloader 下发失败')
            return 1
        # ---- 4: 找 xloader 会话 ----
        ui.phase('P4: xloader 会话迁移')
        s2, p2 = find_xloader_session(cfg['port'] or find_port_safe(), s)
        if not s2:
            ui.error('未找到 xloader 会话')
            return 1
        ui.step(True, 'xloader 会话 @%s' % p2)
        # ---- 5: staging ----
        ui.phase('staging UCE + fastboot 容器')
        if not upload_plain(s2, open(cfg['uce_img'], 'rb').read(), UCE_ADDR, 'uce'):
            ui.error('UCE 失败')
            return 1
        time.sleep(10)
        if not cd_read(s2, 1, 1.5):
            ui.warn('UCE 后会话丢失——重新寻找...')
            s2, p2 = find_xloader_session(p2, s2)
            if not s2:
                ui.error('会话丢失')
                return 1
        if not upload_plain(s2, open(cfg['fb_img'], 'rb').read(), FB_BASE, 'fb-img'):
            ui.error('fastboot 容器 staging 失败')
            return 1
        ui.info('等待 TEE 原位解密 20s...')
        time.sleep(20)
        if not cd_read(s2, 1, 1.5):
            ui.warn('fastboot 后会话丢失——重新寻找...')
            s2, p2 = find_xloader_session(p2, s2)
            if not s2:
                ui.error('会话丢失')
                return 1
        # ---- 6: 任意读 arm ----
        model, lit = probe_model(s2)
        if not model:
            ui.error('probe 失败')
            return 1
        if not selftest(s2, model, lit):
            ui.error('selftest 失败')
            return 1
        if not arm(s2, model, lit, MODELS[model]['img_base']):
            ui.error('arm 失败')
            return 1
        armed_M = MODELS[model]

    # ---- 7-10: 验证/补丁/BL2/fastboot ----
    ui.phase('补丁表 + BL2 启动 + fastboot 交接')
    if not apply_patches(s2 if armed_M is None else s, armed_M):
        return 1
    if not bl2_boot_and_wait(cfg, s2 if armed_M is None else s):
        return 1

    # ---- 11: 分区备份 ----
    if not a.no_backup:
        ui.phase('upload_storage 分区备份')
        try:
            backup_via_usb(cfg)
        except Exception as e:
            ui.warn('备份异常: %r' % e)

    # ---- 12: 解锁 ----
    if a.unlock:
        ui.phase('oem unlock（任意码）')
        do_unlock(cfg)
    else:
        ui.info('（未加 --unlock：备份完成即止；确认后可加 --unlock 执行解锁）')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\n已中断——设备断电重进下载模式可恢复')
        sys.exit(130)
