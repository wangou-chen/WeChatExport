"""S5-ag —— dump AES 代码区字节，定位函数入口与「CipherContext 取参」指令

背景（实测）：
  * Weixin.dll RVA 0x5932B90..0x5936FD0 是 AES-NI 实现；0x5932B9A 是被高频执行的 AESENC 主循环。
  * Frida 的 CpuContext 不暴露 xmm 寄存器（84 号脚本读到全空），因此改为
    「在函数入口读 GPR 拿到 CipherContext 指针，再读内存」的路线。

本脚本（只读）：
  1. dump 指定 RVA 区间的原始字节（十六进制 + 反汇编风格的首字节解析）；
  2. 向前扫描寻找函数入口候选（`push rbp` / `mov [rsp+..]` / `int3` 填充后的对齐边界）；
  3. 输出入口候选前后的指令字节，供解析「key 指针来自哪个寄存器」。

用法：
  C:\\Python314\\python.exe 85_dump_aes_code.py --pid 16364 [--base 0x...] [--out <json>]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys

BASE_DIR = r"C:\Users\Lenovo\Desktop\WeChatExport"
kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010

RANGES = [
    (0x5932B00, 0x5932E00),     # AESENC 主循环所在函数
    (0x5936E00, 0x5937100),     # AESKEYGENASSIST / AESIMC 所在函数
]


def readmem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def hexdump_lines(data, base, width=16):
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08X  %-47s  %s" % (base + off, chunk.hex(" "), asc))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--base", default="0x7ffc927d0000")
    ap.add_argument("--out", default=os.path.join(BASE_DIR, "logs", "aes_code.json"))
    args = ap.parse_args()
    base = int(args.base, 16)

    h = kernel32.OpenProcess(PQI | PVR, False, args.pid)
    if not h:
        raise SystemExit("OpenProcess 失败 err=%d" % ctypes.get_last_error())

    result = {}
    for rva_lo, rva_hi in RANGES:
        data = readmem(h, base + rva_lo, rva_hi - rva_lo)
        if not data:
            print("RVA 0x%X..0x%X 读取失败" % (rva_lo, rva_hi))
            continue
        key = "0x%X..0x%X" % (rva_lo, rva_hi)
        result[key] = {"rva_lo": rva_lo, "rva_hi": rva_hi,
                       "bytes_hex": data.hex(),
                       "lines": hexdump_lines(data, base + rva_lo)}
        print("=== RVA %s (%d 字节) ===" % (key, len(data)))
        # 打印含 AES 指令附近的 64 行
        hits = []
        for pat, name in ((b"\x66\x0f\x38\xdc", "AESENC"), (b"\x66\x0f\x38\xde", "AESDEC"),
                          (b"\x66\x0f\x3a\xdf", "AESKEYGENASSIST"), (b"\x66\x0f\x38\xdb", "AESIMC")):
            i = data.find(pat)
            while i >= 0:
                hits.append((i, name))
                i = data.find(pat, i + 1)
        hits.sort()
        for off, name in hits[:6]:
            lo = max(0, off - 32)
            hi = min(len(data), off + 48)
            print("  --- %s @RVA 0x%X ---" % (name, rva_lo + off))
            for line in hexdump_lines(data[lo:hi], base + rva_lo + lo):
                print("    " + line)
        # 函数入口候选：int3(CC) 填充后的 16 字节对齐地址
        cands = []
        i = data.find(b"\xcc\xcc\xcc\xcc")
        while i >= 0:
            start = i + 4
            if start < len(data):
                cands.append(rva_lo + start)
            i = data.find(b"\xcc\xcc\xcc\xcc", i + 1)
        print("  函数入口候选（int3 填充后）: %s" % ["0x%X" % c for c in cands[:12]])
        result[key]["entry_candidates"] = cands[:12]
    kernel32.CloseHandle(h)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    print("-> %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
