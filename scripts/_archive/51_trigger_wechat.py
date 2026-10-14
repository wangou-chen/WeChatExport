"""S5-o —— 触发脚本：让微信进程产生数据库/AES 活动，便于 frida hook 命中。

做法（只做 Windows 消息与键鼠层面操作，不改微信文件/内存）：
  1. 找到微信主窗口，ShowWindow(SW_RESTORE) + SetForegroundWindow；
  2. 发送 Ctrl+F（打开搜索）→ 输入一个字符 → ESC，促使微信读取/写入本地库；
  3. 打印窗口标题确认操作对象。

用法：
  python 51_trigger_wechat.py [--text a]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import sys
import time

user32 = ctypes.windll.user32

SW_RESTORE = 9
VK_CONTROL = 0x11
VK_ESCAPE = 0x1B
KEYEVENTF_KEYUP = 0x0002
INPUT_KEYBOARD = 1


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]


class INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("ki", KEYBDINPUT), ("pad", ctypes.c_byte * 24)]
    _anonymous_ = ("u",)
    _fields_ = [("type", wt.DWORD), ("u", _U)]


def send_key(vk, up=False):
    inp = INPUT()
    inp.type = INPUT_KEYBOARD
    inp.ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=(KEYEVENTF_KEYUP if up else 0),
                        time=0, dwExtraInfo=None)
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def find_wechat_windows():
    found = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    def cb(hwnd, lparam):
        length = user32.GetWindowTextLengthW(hwnd)
        if length:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            cls = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls, 256)
            title = buf.value
            if title and ("微信" in title or "Weixin" in title or "WeChat" in title):
                found.append((hwnd, title, cls.value, user32.IsWindowVisible(hwnd)))
        return True

    user32.EnumWindows(cb, 0)
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", default="a")
    args = ap.parse_args()
    wins = find_wechat_windows()
    print("候选窗口 %d 个" % len(wins))
    for h, t, c, v in wins:
        print("  hwnd=0x%X visible=%s class=%s title=%s" % (h, v, c, t))
    if not wins:
        print("未找到微信窗口")
        return 1
    hwnd = [w for w in wins if w[3]][0][0] if any(w[3] for w in wins) else wins[0][0]
    user32.ShowWindow(hwnd, SW_RESTORE)
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.6)
    # Ctrl+F 搜索
    send_key(VK_CONTROL)
    send_key(0x46)          # F
    send_key(0x46, up=True)
    send_key(VK_CONTROL, up=True)
    time.sleep(0.8)
    for ch in args.text:
        vk = user32.VkKeyScanW(ord(ch)) & 0xFF
        send_key(vk)
        send_key(vk, up=True)
        time.sleep(0.3)
    time.sleep(0.8)
    send_key(VK_ESCAPE)
    send_key(VK_ESCAPE, up=True)
    print("已发送 Ctrl+F / 输入 / ESC，窗口 hwnd=0x%X" % hwnd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
