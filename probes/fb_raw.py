# -*- coding: utf-8 -*-
# z_fbraw2.py - upload_storage data-phase reader (standalone)
import io, sys, time
if getattr(sys.stdout, '_ztw', False) is not True:
    _w = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    _w._ztw = True
    sys.stdout = _w
import usb.core, usb.util

def find_fb():
    for vid, pid in [(0x18D1, 0xD00D), (0x12D1, 0x3609)]:
        d = usb.core.find(idVendor=vid, idProduct=pid)
        if d is not None:
            return d
    return None

def setup(dev):
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except NotImplementedError:
        pass
    except Exception:
        pass
    dev.set_configuration()
    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]
    ep_out = ep_in = None
    for e in intf:
        if usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT:
            ep_out = e
        else:
            ep_in = e
    return ep_out, ep_in

def cmd_full(dev, ep_out, ep_in, s, tail_ms=1200, total_s=20):
    data = s.encode('ascii') if isinstance(s, str) else s
    dev.write(ep_out.bEndpointAddress, data, 8000)
    out = b''
    t0 = time.time()
    idle = 0
    while time.time() - t0 < total_s and idle < tail_ms:
        try:
            r = bytes(dev.read(ep_in.bEndpointAddress, 16384, 300))
        except usb.core.USBError as e:
            if 'timed out' in str(e):
                idle += 300
                continue
            raise
        idle = 0
        out += r
    return out

def main():
    dev = find_fb()
    if dev is None:
        print('NO DEVICE'); return 1
    ep_out, ep_in = setup(dev)
    print('alive:', cmd_full(dev, ep_out, ep_in, 'getvar:version', 600, 5)[:40])
    d = cmd_full(dev, ep_out, ep_in, 'upload_storage:0:64')
    print('upload_storage:0:64 -> %d B' % len(d))
    print('  hex: %s' % d[:96].hex())
    print('  repr: %r' % d[:96])
    return 0

if __name__ == '__main__':
    sys.exit(main())
