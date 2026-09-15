# -*- coding: utf-8 -*-
"""
xloader_send.py — 麒麟990 4G xloader USB 下载协议（"xmodem"）主机端实现
================================================================================
适用: xloader 接管 USB 之后（xloader 基址 0x23000, 帧处理器 rt 0x339C4）。
      与 BootROM 期帧格式相同, 唯一已知差别: CD 查询应答为 1 字节（ROM 为 4 字节）。
传输层: USB CDC 虚拟串口 (VID 0x12D1 / PID 0x3609), 115200 8N1, rtscts=True。
实证来源: SAFE_BD_4G_xloader.bin 反汇编（帧处理器 0x339C4..0x33D12）+ 白皮书
      unicorn-wp.txt §2.5 + BootROM/5G 同源副本 + 实机日志 (z_route7.log)。

每条结论标注【实证】(反汇编/实机) 或【推断】(合理假设, 上机前注意)。
"""
import struct
import time
import binascii

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    serial = None

# ---------------------------------------------------------------- constants
USB_VID = 0x12D1          # 【实证】z_route7.py / 白皮书 USB Download Mode
USB_PID = 0x3609          # 【实证】同上
MAX_DATA = 0x400          # 【实证】0x33BE6 `mov.w r1,#0x400`; 帧长必须=载荷+5
XL_HEAD_LEN = 14          # 【实证】0x33AEC `cmp r7,#0xE`
XL_TAIL_LEN = 5           # 【实证】0x33C5C `cmp r7,#5`

ACK = 0xAA                # 【实证】0x33C9C / 0x33CF2
NAK = 0x55                # 【实证】0x33CF6
# 0x07 (address/size error) 不存在于本 4G xloader 构建【实证: 分发器无此应答】


# ---------------------------------------------------------------- CRC
def crc16_hqx(data: bytes) -> int:
    """CRC-16/XMODEM: poly 0x1021, init 0x0000。【实证】
    = 设备 0x33A1C..0x33A70 查表循环(初值0) = binascii.crc_hqx(data, 0)。
    白皮书 §2.5 "XMODEM-CRC"; BootROM/5G 同源副本的表基均为标准表;
    实机 ROM 期整包下载与 xloader 期 CD 探针均按此通过。"""
    return binascii.crc_hqx(data, 0)


def _crc16_tblA_fallback(data: bytes) -> int:
    """【推断/fallback】4G dump 中 0x33A1C 的池字=0x45D28(表基+0x14)的字面解读:
    栈表 = std[5..15]+字符串尾巴。与实机行为矛盾(探针被应答=>CRC通过), 仅当
    某构建真按此执行时 CD/帧才会被静默丢弃 —— 静默时可用本函数做 A/B 对比。"""
    tbl = [0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B,
           0xC18C, 0xD1AD, 0xE1CE, 0xF1EF, 0x555B, 0x5D45, 0x2071,
           0x2C72, 0x7165]
    crc = 0
    for fp in data:
        crc = ((crc << 4) & 0xFFFF) ^ tbl[(fp >> 4) ^ (crc >> 12)]
        crc = (tbl[(fp & 0xF) ^ (crc >> 12)] ^ (crc << 4)) & 0xFFFF
    return crc


CRC = crc16_hqx  # 当前生效的 CRC（默认: 实证版）


def _crc_be(data: bytes) -> bytes:
    """CRC16 大端 2 字节。【实证】0x339FC..0x33A10: 设备按 buf[len-2]<<8|
    buf[len-1] 拼装比较 = 大端传输。"""
    return struct.pack('>H', CRC(data))


# ---------------------------------------------------------------- 帧构造
def build_head(addr: int, length: int, file_type: int = 1) -> bytes:
    """HEAD 帧, 14B。【实证】0x33AE6..0x33B78:
    [FE][00][FF][FT][LEN u32 BE][ADDR u32 BE][CRC BE]
    FT ∈ {1,2}（0x33AF4 检查）; LEN/ADDR 不校验; FT=1 为常规镜像。"""
    if file_type not in (1, 2):
        raise ValueError('file_type must be 1 or 2 (xloader 0x33AF4 check)')
    body = struct.pack('>BBBBII', 0xFE, 0x00, 0xFF, file_type, length & 0xFFFFFFFF, addr & 0xFFFFFFFF)
    return body + _crc_be(body)


def build_data(seq: int, payload: bytes) -> bytes:
    """DATA 帧。【实证】0x33B7A..0x33C56: [DA][seq][~seq][载荷][CRC BE]。
    载荷: 非末帧必须恰 1024B; 末帧 = 总长-n*1024。帧总长=载荷+5。"""
    if len(payload) > MAX_DATA:
        raise ValueError('payload > 1024')
    body = struct.pack('>BBB', 0xDA, seq & 0xFF, (~seq) & 0xFF) + payload
    return body + _crc_be(body)


def build_tail(seq: int) -> bytes:
    """TAIL 帧, 5B。【实证】0x33C58..0x33CF0: [ED][seq][~seq][CRC BE]。
    seq = 数据帧数+1（即最后一个数据帧 seq+1）。
    注意: 设备对 5 字节 tail 放行 seq 检查(0x33C5C), 但仍要求计数完成。"""
    body = struct.pack('>BBB', 0xED, seq & 0xFF, (~seq) & 0xFF)
    return body + _crc_be(body)


def build_inquiry(seq: int = 0) -> bytes:
    """INQUIRE 帧, 5B。【实证】0x33A94..0x33ABC: [CD][seq][~seq][CRC BE]。
    应答 = 1 字节状态（xloader; 默认 0x00）。ROM 期为 4 字节。"""
    body = struct.pack('>BBB', 0xCD, seq & 0xFF, (~seq) & 0xFF)
    return body + _crc_be(body)


# ---------------------------------------------------------------- 发送原语
def find_xloader_port():
    """【推断】枚举 USB Download Mode 串口（与既有脚本一致）。"""
    if serial is None:
        return None
    for p in serial.tools.list_ports.comports():
        if p.vid == USB_VID and p.pid == USB_PID:
            return p.device
    return None


def open_port(port: str, timeout=2.0):
    """【推断】115200 8N1 + 硬件流控（与既有已验证脚本一致）。"""
    ser = serial.Serial(port, 115200, timeout=timeout, write_timeout=2.0,
                        rtscts=True, dsrdtr=True)
    ser.dtr = True
    ser.rts = True
    time.sleep(0.2)
    return ser


def _drain(ser):
    try:
        n = ser.in_waiting
        if n:
            ser.read(n)
    except Exception:
        pass


def _send_and_ack(ser, frame, ack_timeout=2.0):
    """写一帧, 读 1 字节应答。返回 b'\\xaa' / b'\\x55' / 收到的其它字节 / None(超时)。
    【实证语义】0xAA=ACK, 0x55=NAK, None=CRC错或未收head前的未知帧(设备静默)。"""
    _drain(ser)
    ser.write(frame)
    ser.flush()
    old = ser.timeout
    try:
        ser.timeout = ack_timeout
        return ser.read(1)
    finally:
        ser.timeout = old


# ---------------------------------------------------------------- 主函数
def send_image_via_xloader(ser, blob: bytes, addr: int, file_type: int = 1,
                           head_retries: int = 3, data_retries: int = 3,
                           frame_delay: float = 0.0, progress=None) -> bool:
    """向 xloader 下载镜像 blob 到地址 addr。

    ser      : 已打开的 pyserial 对象（open_port()）
    blob     : 镜像字节串
    addr     : 目的地址（设备不做任何校验, 直接作为 memcpy dst;
               须为 xloader 运行期可写 RAM——SRAM 或已初始化 DDR）
    file_type: head 的 FILE_TYPE 字段, 1 或 2（默认 1）

    返回 True = tail 得到 0xAA（传输完成, 设备随即进入签名校验流程）。

    会话语义【全部实证, 见 PROTOCOL.md §3】:
      head(seq=0) -> AA;  data(seq=1..n, 每帧1024B, 末帧=余数) -> AA 每帧;
      tail(seq=n+1) -> AA; CD 随时可查状态(1字节)。
    重发策略【推断, 依据设备重发容忍(0x33B9C/0x33AE6)】: NAK/超时重发当前帧;
    head 失败重发 head（head 会重置设备状态机并改地址/长度）。
    """
    total = len(blob)
    if total == 0:
        raise ValueError('empty blob')

    # ---- head ----
    head = None
    for attempt in range(head_retries):
        head = build_head(addr, total, file_type)
        ack = _send_and_ack(ser, head)
        if ack == b'\xaa':
            break
        # NAK/超时: 直接重发 head 即可 —— 0xFE 不检查会话状态, 每次重置状态机
        time.sleep(0.3)
    else:
        return False

    # ---- data ----
    n_data = (total + MAX_DATA - 1) // MAX_DATA      # 数据帧数
    for idx in range(n_data):
        chunk = blob[idx * MAX_DATA:(idx + 1) * MAX_DATA]
        seq = idx + 1                                 # next_seq 从 1 开始
        ok = False
        for attempt in range(data_retries):
            ack = _send_and_ack(ser, build_data(seq, chunk))
            if ack == b'\xaa':
                ok = True
                break
            if ack == b'\x55':
                # NAK: 长度/seq 错。先原样重发; 设备对“重发上一帧”有容忍,
                # 对本帧 NAK 重发本帧通常可恢复【推断】。
                time.sleep(0.2)
                continue
            # 超时(静默=CRC错): 直接原样重发
            time.sleep(0.2)
        if not ok:
            return False
        if frame_delay:
            time.sleep(frame_delay)
        if progress:
            progress(min((idx + 1) * MAX_DATA, total), total)

    # ---- tail ----
    tail_seq = n_data + 1
    for attempt in range(data_retries):
        ack = _send_and_ack(ser, build_tail(tail_seq))
        if ack == b'\xaa':
            return True
        time.sleep(0.3)
    return False


def cd_probe_xloader(ser, seq: int = 1, timeout: float = 2.0):
    """xloader 期状态查询。应答 1 字节状态（默认 0x00）。
    【实证】0x33A94..0x33ABC: 应答 = *(u8*)0x60014088, 仅 1 字节。
    返回 int(0..255) / None(无应答)。
    对照: BootROM 期同一帧应答 4 字节（如 1f000000 / f11f0000）。"""
    ack = _send_and_ack(ser, build_inquiry(seq), ack_timeout=timeout)
    if not ack:
        return None
    return ack[0]


# ---------------------------------------------------------------- demo
if __name__ == '__main__':
    # 自检: 帧字节与 CRC
    h = build_head(0x1A400000, 0x30000, 1)
    assert h[:4] == bytes([0xFE, 0x00, 0xFF, 0x01])
    assert h[4:8] == struct.pack('>I', 0x30000) and h[8:12] == struct.pack('>I', 0x1A400000)
    assert h[12:14] == struct.pack('>H', crc16_hqx(h[:12]))
    d = build_data(1, b'\x00' * 1024)
    assert d[0] == 0xDA and d[1] == 0x01 and d[2] == 0xFE and len(d) == 1029
    t = build_tail(2)
    assert t[:3] == bytes([0xED, 0x02, 0xFD]) and len(t) == 5
    q = build_inquiry(1)
    assert q[:3] == bytes([0xCD, 0x01, 0xFE]) and len(q) == 5
    print('self-test OK')
    print('head :', h.hex(' '))
    print('data1:', d[:8].hex(' '), '... len', len(d))
    print('tail :', t.hex(' '))
    print('inq  :', q.hex(' '))

    port = find_xloader_port()
    print('port:', port)
    # 实际发送示例（需要设备在 xloader USB 下载态）:
    # ser = open_port(port)
    # ok = send_image_via_xloader(ser, open('blob.bin','rb').read(), 0x1A400000)
    # print('done', ok, 'cd status =', cd_probe_xloader(ser))
