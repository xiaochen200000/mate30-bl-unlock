# -*- coding: utf-8 -*-
# 归档自 z_port_listen.py：端口改为命令行参数，逻辑未动。
# z_port_listen.py - READ-ONLY listen on the three eRecovery ports (no writes)
import io, sys, time
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w
import serial, serial.tools.list_ports

PORTS = sys.argv[1:] or [p.device for p in serial.tools.list_ports.comports()]
BAUDS = [115200, 921600]

for pn in PORTS:
    for baud in BAUDS:
        try:
            s = serial.Serial(pn, baud, timeout=3)
            log = []
            t0 = time.time()
            while time.time() - t0 < 4:
                data = s.read(4096)
                if data:
                    log.append(data)
            s.close()
            blob = b''.join(log)
            print('%s @%d: %d B  %r' % (pn, baud, len(blob), blob[:120]))
            if blob:
                print('     hex: %s' % blob[:64].hex())
        except Exception as e:
            print('%s @%d: ERR %r' % (pn, baud, str(e)[:80]))
