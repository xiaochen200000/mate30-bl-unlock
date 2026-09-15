# -*- coding: utf-8 -*-
"""
console_ui.py — 交互式控制台反馈组件（纯标准库，Windows 10+ 兼容）
================================================================================
给长耗时刷机/回读脚本提供统一的人机反馈：
  - phase()   大阶段横幅（一眼看清脚本跑到哪一步）
  - step()    单步结果 ✓ / ✗
  - info/warn/error  常规输出
  - progress()       单行刷新进度条（速率 + 已用时间）
  - countdown()      倒计时窗口（可带轮询回调，用于"纯静默等待"这类阶段）
  - 全部输出自动同步写入日志文件（可选）

本文件刻意不依赖任何第三方库。颜色在 Windows 10 1809+ 的经典控制台 /
Windows Terminal 下均可用；不支持 ANSI 的环境自动退化为纯文本。
"""
import ctypes
import os
import shutil
import sys
import time

# ---------------------------------------------------------------- ANSI 使能
_IS_WIN = sys.platform == 'win32'


def _enable_vt():
    """Windows 经典控制台默认不开 ANSI 转义，手动打开 ENABLE_VIRTUAL_TERMINAL_PROCESSING。"""
    if not _IS_WIN:
        return True
    try:
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)
            return True
    except Exception:
        pass
    return False


_VT_OK = _enable_vt()
_TTY = sys.stdout.isatty()
_WIDTH = max(60, (shutil.get_terminal_size((100, 24)).columns if _TTY else 100))


class _C:
    RESET = '\033[0m' if _VT_OK else ''
    DIM = '\033[2m' if _VT_OK else ''
    BOLD = '\033[1m' if _VT_OK else ''
    CYAN = '\033[36m' if _VT_OK else ''
    GREEN = '\033[32m' if _VT_OK else ''
    YELLOW = '\033[33m' if _VT_OK else ''
    RED = '\033[31m' if _VT_OK else ''


def _now():
    return time.strftime('%H:%M:%S')


class UI:
    """会话级 UI 对象。logfile 传路径则把全部非进度行同步写盘（utf-8 追加）。"""

    def __init__(self, logfile=None):
        self.logfile = logfile
        self.t0 = time.time()
        self._last_progress_len = 0

    # ---------------------------------------------------------- 内部
    def _emit(self, line, to_log=True):
        # 进度条行需要 \r 原地刷新；普通行先清掉残留的进度条
        if self._last_progress_len:
            sys.stdout.write('\r' + ' ' * self._last_progress_len + '\r')
            self._last_progress_len = 0
        print(line, flush=True)
        if to_log and self.logfile:
            try:
                with open(self.logfile, 'a', encoding='utf-8') as f:
                    f.write(line + '\n')
            except Exception:
                pass

    @staticmethod
    def _hms(sec):
        sec = int(sec)
        return '%02d:%02d:%02d' % (sec // 3600, sec % 3600 // 60, sec % 60)

    # ---------------------------------------------------------- 常规输出
    def info(self, msg):
        self._emit('%s%s%s %s' % (_C.DIM, _now(), _C.RESET, msg))

    def warn(self, msg):
        self._emit('%s%s%s %s%s%s' % (_C.DIM, _now(), _C.RESET, _C.YELLOW, msg, _C.RESET))

    def error(self, msg):
        self._emit('%s%s%s %s%s%s' % (_C.DIM, _now(), _C.RESET, _C.RED, msg, _C.RESET))

    def step(self, ok, msg):
        mark = '%s[OK]%s' % (_C.GREEN, _C.RESET) if ok else '%s[FAIL]%s' % (_C.RED, _C.RESET)
        self._emit('%s%s%s %s %s' % (_C.DIM, _now(), _C.RESET, mark, msg))

    def phase(self, title):
        bar = '=' * max(8, min(_WIDTH - 4, len(title) * 2 + 8))
        self._emit('')
        self._emit('%s== %s ==%s' % (_C.CYAN + _C.BOLD, title, _C.RESET))
        self._emit(_C.DIM + bar + _C.RESET)

    def banner(self, title):
        line = '%s== %s ==%s' % (_C.CYAN + _C.BOLD, title, _C.RESET)
        self._emit('')
        self._emit(line)
        self._emit(_C.DIM + '已运行 ' + self._hms(time.time() - self.t0) + _C.RESET)

    # ---------------------------------------------------------- 进度条
    def progress(self, done, total, label='', rate=None):
        """单行刷新进度条。非 tty 环境每 5% 打一行，避免刷屏。"""
        if total <= 0:
            return
        done = min(done, total)
        pct = done * 100.0 / total
        if not _TTY:
            if int(pct) % 5 == 0 and int(pct) != getattr(self, '_last_int_pct', -1):
                self._last_int_pct = int(pct)
                self._emit('  %s %d/%d (%.0f%%)' % (label, done, total, pct))
            return
        bar_w = min(40, _WIDTH - len(label) - 30)
        filled = int(bar_w * done / total)
        bar = _C.GREEN + '#' * filled + _C.RESET + '-' * (bar_w - filled)
        tail = ' %s' % rate if rate else ''
        line = '\r%s [%s] %5.1f%% %d/%d%s' % (label, bar, pct, done, total, tail)
        pad = self._last_progress_len - len(line)
        if pad > 0:
            line += ' ' * pad
        self._last_progress_len = len(line)
        sys.stdout.write(line)
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write('\n')
            sys.stdout.flush()
            self._last_progress_len = 0

    def progress_end(self):
        if self._last_progress_len:
            sys.stdout.write('\n')
            sys.stdout.flush()
            self._last_progress_len = 0

    # ---------------------------------------------------------- 倒计时
    def countdown(self, label, seconds, poll=None, tick=1.0):
        """倒计时 seconds 秒。poll() 可选，返回一行状态文字（如端口监视）。"""
        t0 = time.time()
        last_log = 0
        while time.time() - t0 < seconds:
            remain = seconds - (time.time() - t0)
            status = ''
            if poll:
                try:
                    status = poll() or ''
                except Exception as e:
                    status = 'poll err: %s' % str(e)[:40]
            if _TTY:
                line = '\r%s[%s 剩余 %4ds] %s' % (_C.YELLOW, label, int(remain), status)
                pad = self._last_progress_len - len(line)
                if pad > 0:
                    line += ' ' * pad
                self._last_progress_len = len(line)
                sys.stdout.write(line)
                sys.stdout.flush()
            else:
                el = time.time() - t0
                if el - last_log >= 15:
                    last_log = el
                    self._emit('  %s: %d/%ds  %s' % (label, int(el), seconds, status))
            time.sleep(tick)
        self.progress_end()


def make_ui(logfile=None):
    """便捷工厂：确保日志目录存在。"""
    if logfile:
        try:
            d = os.path.dirname(os.path.abspath(logfile))
            os.makedirs(d, exist_ok=True)
        except Exception:
            logfile = None
    return UI(logfile=logfile)
