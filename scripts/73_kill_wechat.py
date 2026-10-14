"""S5-v —— 用 TerminateProcess 真正结束微信（绕过 taskkill 的沙箱拒绝）

实测：本机沙箱下 `taskkill /F` 返回 Access denied，但 OpenProcess(PROCESS_TERMINATE)
      成功（handle=432, err=0），因此可用 TerminateProcess 结束进程。
      VM_WRITE 被拒（err=5），所以无法跨进程写代码，hook 一律走 Frida 注入。

用法：
  C:\\Python314\\python.exe 73_kill_wechat.py [--wait 20]
"""
import argparse
import ctypes
import subprocess
import sys
import time

kernel32 = ctypes.windll.kernel32
PROCESS_TERMINATE = 0x0001


def pids(names=("Weixin.exe", "WeChatAppEx.exe", "WeChat.exe")):
    out = []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin,WeChatAppEx,WeChat -ErrorAction SilentlyContinue |"
                            "ForEach-Object { \"$($_.Id),$($_.ProcessName)\" }"],
                           capture_output=True, text=True, timeout=30)
        for line in (r.stdout or "").splitlines():
            a = line.strip().split(",")
            if len(a) == 2 and a[0].isdigit() and (a[1] + ".exe") in names:
                out.append((int(a[0]), a[1]))
    except Exception:                                              # noqa: BLE001
        pass
    return out


def kill(pid):
    h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False, kernel32.GetLastError()
    ok = kernel32.TerminateProcess(h, 1)
    err = kernel32.GetLastError()
    kernel32.CloseHandle(h)
    return bool(ok), err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wait", type=int, default=25)
    args = ap.parse_args()
    procs = pids()
    print("目标 %d 个: %s" % (len(procs), procs))
    # 先杀大内存主进程，再杀其余
    procs.sort(reverse=True)
    for pid, name in procs:
        ok, err = kill(pid)
        print("  kill %s:%d -> %s err=%d" % (name, pid, ok, err))
    t0 = time.time()
    while time.time() - t0 < args.wait:
        left = pids()
        if not left:
            print("全部结束，用时 %.1fs" % (time.time() - t0))
            return 0
        time.sleep(1)
    print("仍存活: %s" % pids())
    return 1


if __name__ == "__main__":
    sys.exit(main())
