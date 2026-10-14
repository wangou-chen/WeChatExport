"""S5-am —— 自动定位微信主进程并打印 PID / Weixin.dll 基址（供其它脚本使用）

不再依赖人工填写 PID（微信崩溃重启后 PID 会变）。

用法：
  C:\\Python314\\python.exe 92_where.py
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import time

kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010


def main_pid():
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-Process Weixin -ErrorAction SilentlyContinue |"
                        "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                       capture_output=True, text=True, timeout=30)
    return int((r.stdout or "0").strip() or 0)


def main():
    pid = main_pid()
    if not pid:
        print("未发现 Weixin 进程")
        return 1
    import frida
    dev = frida.get_local_device()
    s = dev.attach(pid)
    holder = {}
    sc = s.create_script(
        'const o = {pid: Process.id, mods: []};'
        'try { const m = Process.getModuleByName("Weixin.dll");'
        ' o.dll = {base: m.base.toString(), size: m.size, path: m.path}; } catch (e) { o.err = "" + e; }'
        'send(o);')
    sc.on("message", lambda m, d: holder.update(m.get("payload") or {}))
    sc.load()
    time.sleep(1.5)
    try:
        sc.unload()
    except Exception:                                              # noqa: BLE001
        pass
    s.detach()
    print(json.dumps(holder, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
