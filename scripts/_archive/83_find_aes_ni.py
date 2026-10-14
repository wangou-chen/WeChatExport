"""S5-ae —— 在 Weixin.dll 代码段里定位 AES-NI 指令（AESENC/AESDEC），为运行期 hook 找落点

原理：
  Windows x64 上 AES-NI 是标准指令，现代微信必然用它做 AES 加解密（SQLCipher 页解密也走它）。
  指令字节：
      AESENC  xmm1, xmm2/m128  =  66 0F 38 DC /r
      AESDEC  xmm1, xmm2/m128  =  66 0F 38 DE /r
      AESENCLAST = 66 0F 38 DD,  AESDECLAST = 66 0F 38 DF
      AESIMC  = 66 0F 38 DB,     AESKEYGENASSIST = 66 0F 3A DF /r ib
  本脚本只读扫描 Weixin.dll 的可执行区域，统计这些字节序列的出现位置（RVA），
  并输出前若干个候选地址 —— 下一步可在这些地址上挂 Interceptor 抓 xmm 寄存器。

用法：
  C:\\Python314\\python.exe 83_find_aes_ni.py --pid 16364 [--out <json>] [--max-hits 40]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import time

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

PATTERNS = {
    "AESENC": bytes.fromhex("660f38dc"),
    "AESENCLAST": bytes.fromhex("660f38dd"),
    "AESDEC": bytes.fromhex("660f38de"),
    "AESDECLAST": bytes.fromhex("660f38df"),
    "AESIMC": bytes.fromhex("660f38db"),
    "AESKEYGENASSIST": bytes.fromhex("660f3adf"),
    "PCLMULQDQ": bytes.fromhex("660f3a44"),
}


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


def module_base(pid):
    """用 powershell 取 Weixin 主进程；基址用 frida 无关的方式：走 ntdll PEB 太重，
    这里直接用 --base 覆盖，或从已知 0x7ffc927d0000 由调用方提供。"""
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--base", default="0x7ffc927d0000", help="Weixin.dll 基址（可用 79_list_modules.py 查）")
    ap.add_argument("--size", default="202039296", help="Weixin.dll 大小")
    ap.add_argument("--out", default=os.path.join(BASE, "logs", "aes_ni.json"))
    ap.add_argument("--max-hits", type=int, default=40)
    args = ap.parse_args()

    base = int(args.base, 16)
    size = int(args.size)
    h = kernel32.OpenProcess(PQI | PVR, False, args.pid)
    if not h:
        raise SystemExit("OpenProcess 失败 err=%d" % ctypes.get_last_error())

    t0 = time.time()
    hits = {k: [] for k in PATTERNS}
    scanned = 0
    text_bytes = 0
    addr, mbi = 0, MBI()
    regs = []
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        ba, sz = mbi.BaseAddress, mbi.RegionSize
        if sz <= 0:
            break
        if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                and (mbi.Protect & PAGE_NOACCESS) == 0 and ba >= base and ba < base + size):
            regs.append((ba, sz, mbi.Protect))
        nxt = ba + sz
        if nxt <= addr:
            break
        addr = nxt

    print("Weixin.dll 范围内区域 %d 个" % len(regs), flush=True)
    for ba, sz, prot in regs:
        data = readmem(h, ba, sz)
        if not data:
            continue
        scanned += sz
        for name, pat in PATTERNS.items():
            if len(hits[name]) >= args.max_hits:
                continue
            i = data.find(pat)
            while i >= 0 and len(hits[name]) < args.max_hits:
                hits[name].append({"addr": "0x%X" % (ba + i), "rva": "0x%X" % (ba + i - base)})
                i = data.find(pat, i + 1)
    kernel32.CloseHandle(h)

    print("扫描 %.0f MB，用时 %.1fs" % (scanned / 1048576, time.time() - t0), flush=True)
    for name in PATTERNS:
        v = hits[name]
        print("%-16s 命中 %d 处  示例 RVA: %s"
              % (name, len(v), [x["rva"] for x in v[:6]]), flush=True)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"pid": args.pid, "base": args.base, "size": size, "hits": hits}, f, indent=1)
    print("-> %s" % args.out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
