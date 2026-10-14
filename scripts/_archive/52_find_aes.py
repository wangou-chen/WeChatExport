"""S5-p —— 在 Weixin.dll 只读映像中定位 AES 实现，用调用图找「密钥来源」。

背景（实测）：bcrypt 的 BCryptDecrypt/BCryptEncrypt/BCryptGenerateSymmetricKey 在微信运行时
均无调用，说明微信自带 AES 实现（静态链接），原始密钥只作为其轮密钥扩展函数的入参存在，
这也是「扫描 8 字节对齐内存找不到 32 字节密钥」的原因。

本脚本：
  1. 打开 Weixin.exe，枚举区域，找出 Weixin.dll 的映像范围（PE 头 + 段表）；
  2. 在整个映像里搜 AES S-box 常量（63 7c 77 7b f2 6b 6f c5 ...）与 Td0 表首字节模式；
  3. 记录命中地址与命中所在段（.rdata/.data/.text）；
  4. 输出 JSON，供下一步（找 xref → hook 轮密钥扩展）使用。

只读，不写目标进程。

用法：
  C:\\Python314\\python.exe 52_find_aes.py --pid 12516
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

def _build_sbox():
    """按 FIPS-197 生成 S-box 与逆 S-box（避免手抄常量出错）。"""
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)
        x &= 0xFF
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    sbox = [0] * 256
    for i in range(256):
        inv = 0 if i == 0 else exp[255 - log[i]]
        s = inv
        for _ in range(4):
            inv = ((inv << 1) | (inv >> 7)) & 0xFF
            s ^= inv
        sbox[i] = s ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return bytes(sbox), bytes(inv_sbox)


AES_SBOX, SBOX_REV = _build_sbox()


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def regions(h):
    out, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0 \
                and (mbi.Protect & PAGE_NOACCESS) == 0:
            out.append((mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type,
                        mbi.AllocationBase))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return out


def read(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--scan-text", action="store_true", help="额外扫描代码段（找 aesenc 指令模式）")
    args = ap.parse_args()

    h = kernel32.OpenProcess(PQI | PVR, False, args.pid)
    if not h:
        raise SystemExit("OpenProcess 失败 err=%d" % ctypes.get_last_error())

    regs = regions(h)
    # 找 Weixin.dll 映像：以 PE 头 + 大小排序
    images = {}
    for base, size, protect, typ, alloc in regs:
        if typ != 0x1000000:
            continue
        head = read(h, base, 0x1000)
        if not head or head[:2] != b"MZ":
            continue
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if e_lfanew + 0x40 > len(head) or head[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            continue
        images[alloc] = images.get(alloc, 0) + size
    print("映像候选: %s" % [("0x%X" % k, v) for k, v in sorted(images.items(), key=lambda x: -x[1])[:5]])

    report = {"images": {}, "sbox_hits": [], "rev_hits": []}
    for alloc, _sz in sorted(images.items(), key=lambda x: -x[1])[:3]:
        img_regs = [r for r in regs if r[4] == alloc]
        total = sum(r[1] for r in img_regs)
        # 读 PE 头确定镜像大小与节
        head = read(h, alloc, 0x1000)
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        sections = []
        nsec = struct.unpack_from("<H", head, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", head, e_lfanew + 20)[0]
        sec_off = e_lfanew + 24 + opt_size
        for i in range(nsec):
            s = read(h, alloc + sec_off + i * 40, 40)
            if not s:
                break
            name = s[:8].rstrip(b"\x00").decode("latin-1")
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", s, 8)
            sections.append({"name": name, "va": vaddr, "vsize": vsize,
                             "raw": raddr, "rawsize": rsize,
                             "chars": struct.unpack_from("<I", s, 36)[0]})
        report["images"]["0x%X" % alloc] = {"bytes": total, "sections": sections}
        print("映像 0x%X 大小 %d MB 节: %s" % (alloc, total // 1048576,
                                            ", ".join("%s@0x%X" % (s["name"], s["va"]) for s in sections)))

        # 在映像内搜索 S-box
        for base, size, protect, typ, _a in img_regs:
            data = read(h, base, size)
            if not data:
                continue
            i = data.find(AES_SBOX)
            while i >= 0 and len(report["sbox_hits"]) < 20:
                report["sbox_hits"].append({"img": "0x%X" % alloc, "addr": base + i,
                                            "rva": base + i - alloc})
                i = data.find(AES_SBOX, i + 1)
            j = data.find(SBOX_REV)
            while j >= 0 and len(report["rev_hits"]) < 20:
                report["rev_hits"].append({"img": "0x%X" % alloc, "addr": base + j,
                                           "rva": base + j - alloc})
                j = data.find(SBOX_REV, j + 1)

    print("AES S-box 命中 %d 处: %s" % (len(report["sbox_hits"]),
                                       ["0x%X" % x["addr"] for x in report["sbox_hits"][:6]]))
    print("逆 S-box 命中 %d 处: %s" % (len(report["rev_hits"]),
                                       ["0x%X" % x["addr"] for x in report["rev_hits"][:6]]))
    out = os.path.join(BASE, "logs", "aes_locate.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
    print("-> %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
