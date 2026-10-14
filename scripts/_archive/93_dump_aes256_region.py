"""S5-an —— dump AES-256 扩展函数所在区域字节，定位函数入口与调用者

背景：
  * 91 号扫描定位到 RVA 0x5937203 处连续 13 个 AESKEYGENASSIST（常量成对）→ AES-256 扩展。
  * 89 号在其上设硬件断点，运行期 0 命中 —— 因为它只在开库设密钥时调用一次。
  * 需要看这段代码的形态：函数入口在哪、调用者是谁、r8/r9 如何取参。

本脚本（只读）dump RVA 0x5936E00..0x5937300 区间字节，并标注：
  * 已有 dump（85 号）覆盖 0x5936E00..0x5937100；
  * 本脚本补齐 0x5937100..0x5937340，涵盖 AES-256 扩展函数全部。

用法：
  C:\\Python314\\python.exe 93_dump_aes256_region.py --pid <pid> [--lo 0x5937100] [--hi 0x5937340]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010


def readmem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--lo", default="0x5937100")
    ap.add_argument("--hi", default="0x5937340")
    args = ap.parse_args()

    pid = args.pid
    if not pid:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin -ErrorAction SilentlyContinue |"
                            "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                           capture_output=True, text=True, timeout=30)
        pid = int((r.stdout or "0").strip() or 0)
    lo, hi = int(args.lo, 16), int(args.hi, 16)

    import frida
    dev = frida.get_local_device()
    s = dev.attach(pid)
    holder = {}
    sc = s.create_script('try { const m = Process.getModuleByName("Weixin.dll");'
                         ' send({base: m.base.toString()}); } catch (e) { send({err: "" + e}); }')
    sc.on("message", lambda m, d: holder.update(m.get("payload") or {}))
    sc.load()
    time.sleep(1.5)
    try:
        sc.unload()
    except Exception:                                              # noqa: BLE001
        pass
    s.detach()
    base = int(holder["base"], 16)
    print("pid=%d base=0x%X  dump RVA 0x%X..0x%X" % (pid, base, lo, hi), flush=True)

    h = kernel32.OpenProcess(PQI | PVR, False, pid)
    data = readmem(h, base + lo, hi - lo)
    kernel32.CloseHandle(h)
    if not data:
        raise SystemExit("读取失败")

    # 打印，每个 AESKEYGENASSIST 位置前后各若干行
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        mark = ""
        if b"\x66\x0f\x3a\xdf" in chunk or b"\x66\x0f\x38\xdc" in chunk or \
           b"\x66\x0f\x38\xde" in chunk or b"\x66\x0f\x38\xdb" in chunk:
            mark = "   <<<"
        if b"\xcc\xcc\xcc\xcc" in chunk:
            mark += "  [int3 边界]"
        print("%08X  %-47s  %s%s" % (lo + i, chunk.hex(" "), asc, mark))
    return 0


if __name__ == "__main__":
    sys.exit(main())
