"""S5-ao —— 找 AES-256 密钥扩展函数的调用者（= SQLCipher 设密钥路径）

依据（93 号 dump）：
  RVA 0x59371E0 起是 AES-256 密钥扩展函数体（movups xmm2,[rcx+0x10] / mov edx,13 /
  13 个 aeskeygenassist 常量成对），入参 rcx = 密钥指针。
  该函数每库只执行一次，运行期点会话不会触发 → 需要找**调用它的上层函数**，
  上层每次「新开库连接」都会执行（新会话、切账号、重启登录）。

本脚本（只读）：
  1. 扫描 Weixin.dll 代码段里所有 `E8 rel32`，筛选目标落在
     [0x59371D8, 0x593729A]（该扩展函数体）内的调用点；
  2. 对每个调用点向前找 int3 对齐填充，给出所属函数入口 RVA；
  3. 输出调用点/入口清单，供硬件断点使用。

用法：
  C:\\Python314\\python.exe 94_find_keyexp_callers.py --pid <pid> [--out <json>]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import subprocess
import sys
import time

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

FUNC_LO = 0x59371D8     # AES-256 扩展函数入口（含对齐填充）
FUNC_HI = 0x593729A     # 函数体结束（93 号 dump 末条指令之后）


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def readmem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(BASE, "logs", "keyexp_callers.json"))
    args = ap.parse_args()

    pid = args.pid
    if not pid:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin -ErrorAction SilentlyContinue |"
                            "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                           capture_output=True, text=True, timeout=30)
        pid = int((r.stdout or "0").strip() or 0)

    import frida
    dev = frida.get_local_device()
    s = dev.attach(pid)
    holder = {}
    sc = s.create_script('try { const m = Process.getModuleByName("Weixin.dll");'
                         ' send({base: m.base.toString(), size: m.size}); }'
                         ' catch (e) { send({err: "" + e}); }')
    sc.on("message", lambda m, d: holder.update(m.get("payload") or {}))
    sc.load()
    time.sleep(1.5)
    try:
        sc.unload()
    except Exception:                                              # noqa: BLE001
        pass
    s.detach()
    base = int(holder["base"], 16)
    size = int(holder["size"])
    print("pid=%d base=0x%X size=%d" % (pid, base, size), flush=True)

    h = kernel32.OpenProcess(PQI | PVR, False, pid)
    if not h:
        raise SystemExit("OpenProcess 失败 err=%d" % ctypes.get_last_error())

    # 分块读取映像，找 call 目标落在扩展函数体内的位置
    callers = []
    addr, mbi = 0, MBI()
    step = 8 * 1024 * 1024
    off = 0x1000
    while off < size:
        n = min(step, size - off)
        data = readmem(h, base + off, n)
        if data:
            i = data.find(b"\xe8")
            while i >= 0 and i + 5 <= len(data):
                rel = struct.unpack_from("<i", data, i + 1)[0]
                tgt_rva = (off + i) + 5 + rel
                if FUNC_LO <= tgt_rva <= FUNC_HI:
                    callers.append((off + i, tgt_rva))
                i = data.find(b"\xe8", i + 1)
        off += n
    print("直接 call 到扩展函数的调用点 %d 个" % len(callers), flush=True)

    # 找函数入口（向前 int3 对齐填充）
    entries = []
    for c, tgt in callers:
        back = readmem(h, base + max(0x1000, c - 0x400), min(0x400, c))
        ent = None
        if back:
            for j in range(len(back) - 4, 0, -1):
                if back[j:j + 4] == b"\xcc\xcc\xcc\xcc":
                    ent = c - len(back) + j + 4
                    break
        entries.append((c, tgt, ent))
    kernel32.CloseHandle(h)

    print("\n调用点 → 目标 → 所属函数入口：", flush=True)
    for c, tgt, ent in entries[:30]:
        print("  call@0x%-8X -> 0x%-8X   entry=%s"
              % (c, tgt, ("0x%X" % ent) if ent else "?"), flush=True)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"pid": pid, "base": holder["base"],
                   "callers": [{"call": "0x%X" % c, "target": "0x%X" % t,
                                "entry": ("0x%X" % e) if e else None}
                               for c, t, e in entries]}, f, indent=1)
    print("-> %s" % args.out, flush=True)
    print("提示：下一步用硬件断点挂在 call@… 或 entry=… 上；这两个地址在"
          "「新开库连接」时必然执行（新会话/切账号/重启登录）。", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
