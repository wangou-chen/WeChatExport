"""S5-ay —— 回读内存中密钥字符串的原始上下文（确认 exe_key 与 salt 的真实切分与字节序）

60_hexscan_all.py 命中地址示例：pid=30596 addr=0x1AC6FCD30F0 / 0x1AC682822E0，
匹配模式 x'([0-9a-fA-F]{64,192})'。本脚本把这些命中位置的原始字节 dump 出来，
看清 x'...' 内部到底是 96 位 hex（64 key + 32 salt）还是别的长度/顺序。

用法：
  python 107_dump_key_context.py --db <db> [--window 128]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import os
import re
import subprocess
import sys
import time

PAGESZ, SALT = 4096, 16
kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PQI, PVR = 0x0400, 0x0010
RE = re.compile(rb"x'([0-9a-fA-F]{64,192})'")


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def pids():
    out = []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin -ErrorAction SilentlyContinue |"
                            "Sort-Object WorkingSet64 -Descending |"
                            "ForEach-Object { $_.Id }"], capture_output=True, text=True, timeout=30)
        out = [int(x) for x in (r.stdout or "").split() if x.isdigit()]
    except Exception:                                              # noqa: BLE001
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--window", type=int, default=96)
    ap.add_argument("--max", type=int, default=40)
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    db_salt = p1[:SALT].hex()
    print("目标库 salt=%s" % db_salt)

    found = 0
    for pid in pids():
        h = kernel32.OpenProcess(PQI | PVR, False, pid)
        if not h:
            continue
        addr, mbi = 0, MBI()
        while addr < 0x7FFFFFFFFFFF and found < args.max:
            if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                       ctypes.sizeof(mbi)) == 0:
                break
            if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                    and (mbi.Protect & PAGE_NOACCESS) == 0
                    and 0 < mbi.RegionSize < 700 * 1024 * 1024):
                buf = ctypes.create_string_buffer(mbi.RegionSize)
                n = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(h, ctypes.c_uint64(mbi.BaseAddress), buf,
                                              mbi.RegionSize, ctypes.byref(n)) and n.value == mbi.RegionSize:
                    data = buf.raw
                    for m in RE.finditer(data):
                        s = m.group(1).decode().lower()
                        if db_salt not in s:
                            continue
                        found += 1
                        lo = max(0, m.start() - args.window // 2)
                        hi = min(len(data), m.end() + args.window // 2)
                        ctx = data[lo:hi]
                        print("\n[%d] pid=%d addr=0x%X  hexlen=%d" % (found, pid, mbi.BaseAddress + m.start(), len(s)))
                        print("    key[:64]=%s" % s[:64])
                        print("    rest    =%s" % s[64:])
                        print("    上下文: %r" % ctx[:160])
                        if found >= args.max:
                            break
            nxt = mbi.BaseAddress + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt
        kernel32.CloseHandle(h)
    print("\n共找到 %d 处含目标 salt 的 x'...' 串" % found)
    return 0


if __name__ == "__main__":
    sys.exit(main())
