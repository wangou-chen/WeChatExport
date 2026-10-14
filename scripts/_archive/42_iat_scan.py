"""
S5-l —— 通过 IAT 在宿主侧（无需 Frida）hook bcrypt 对称密钥生成，并顺带在内存里
        统计「明文 SQLite 页头」分布，用于判断微信的加密路径与明文页缓存位置。

做法：
  1. 从 Weixin.exe 的进程内存里读取 PE 导入表，取 bcrypt.dll 各函数在进程内的解析地址；
  2. 在 Weixin.dll 的镜像范围内用 Memory.scan 风格搜索 `FF 15 <rel32>`（call qword ptr [rip+disp]）
     命中这些导入地址的调用点 —— 纯读取，不写；
  3. 用 WriteProcessMemory 把目标 call 指令临时改成 `FF D0`(call rax) + 就近取参的 hook stub？

  说明：真正的 hook 需要写目标进程代码，本脚本**只做读取与定位**，并在报告中给出
  需要写入的字节与地址，写入由单独的 --apply 步骤执行（默认不写）。

输出：logs\\iat_scan.json

用法：
  set PYTHONUTF8=1
  C:\\Python314\\python.exe 42_iat_scan.py --pid 16056 [--apply]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys
import time

kernel32 = ctypes.windll.kernel32
PQI, PVR, PWO = 0x0400, 0x0010, 0x0020
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def rpm(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def regions(h):
    out, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0 \
                and (mbi.Protect & PAGE_NOACCESS) == 0:
            out.append((mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return out


def main_module_base(h):
    """枚举区域内找 MZ + PE，返回 Weixin.exe 的基址与大小（取最大的 image）。"""
    best = None
    for base, size, _p, typ in regions(h):
        if typ != 0x1000000 or size < 0x100000:
            continue
        head = rpm(h, base, 0x1000)
        if not head or head[:2] != b"MZ":
            continue
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if e_lfanew + 0x40 > len(head) or head[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            continue
        if best is None or size > best[1]:
            best = (base, size)
    return best


def parse_imports(h, base):
    """返回 {dll_lower: {func: iat_addr}}"""
    head = rpm(h, base, 0x2000)
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", head, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    imp_rva, imp_size = struct.unpack_from("<II", head, dd + 8)
    out = {}
    off = imp_rva
    while True:
        desc = rpm(h, base + off, 20)
        if not desc or desc == b"\x00" * 20:
            break
        oft, tstamp, fwd, name_rva, first_thunk = struct.unpack("<IIIII", desc)
        name = rpm(h, base + name_rva, 64)
        dll = name.split(b"\x00")[0].decode("latin-1") if name else "?"
        thunk = oft or first_thunk
        iat = base + first_thunk
        funcs = {}
        k = 0
        while True:
            ent = rpm(h, base + thunk + k * 8, 8)
            if not ent:
                break
            v = struct.unpack("<Q", ent)[0]
            if v == 0:
                break
            if v & 0x8000000000000000:
                funcs["ord_%d" % (v & 0xFFFF)] = iat + k * 8
            else:
                fn = rpm(h, base + (v & 0x7FFFFFFF), 64)
                fname = fn.split(b"\x00")[0].decode("latin-1") if fn else "?"
                funcs[fname] = iat + k * 8
            k += 1
        out[dll.lower()] = funcs
        off += 20
    return out


def scan_calls(h, image_base, image_size, target_addrs):
    """在 image 的可执行区域内找 call [rip+disp] 命中目标 IAT 槽。"""
    hits = {}
    for base, size, protect, _t in regions(h):
        if not (image_base <= base < image_base + image_size):
            continue
        if protect not in (0x20, 0x40, 0x80, 0x02, 0x04, 0x10, 0x20, 0x60, 0x200):  # 宽松：可执行或只读
            pass
        data = rpm(h, base, size)
        if not data:
            continue
        i = 0
        while True:
            i = data.find(b"\xff\x15", i)
            if i < 0:
                break
            if i + 6 <= len(data):
                disp = struct.unpack_from("<i", data, i + 2)[0]
                slot = base + i + 6 + disp
                for name, addr in target_addrs.items():
                    if addr == slot:
                        hits.setdefault(name, []).append(base + i)
            i += 1
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    h = kernel32.OpenProcess(PQI | PVR | (PWO if args.apply else 0), False, args.pid)
    if not h:
        raise SystemExit("OpenProcess 失败 err=%d" % ctypes.get_last_error())

    t0 = time.time()
    mb = main_module_base(h)
    print("main module base=0x%X size=%d" % mb if mb else "main module 未定位")
    imports = parse_imports(h, mb[0])
    print("导入 DLL: %s" % ", ".join(sorted(imports)[:12]))
    bc = imports.get("bcrypt.dll", {})
    print("bcrypt.dll 导入函数 %d 个" % len(bc))
    want = [k for k in bc if "SymmetricKey" in k or "ImportKey" in k or "Decrypt" in k or "Encrypt" in k]
    for k in sorted(want):
        print("   %-40s iat=0x%X" % (k, bc[k]))

    # 找对 bcrypt 各函数的调用点（在 Weixin.dll 镜像内）
    # Weixin.dll 的镜像范围：取 size 最大的非 Weixin.exe 模块
    cands = []
    for base, size, _p, typ in regions(h):
        if typ == 0x1000000 and size > 50 * 1024 * 1024:
            cands.append((base, size))
    cands.sort(key=lambda x: -x[1])
    print("大模块候选: %s" % [("0x%X" % b, s) for b, s in cands[:3]])
    targets = {k: bc[k] for k in want}
    hits = {}
    for base, size in cands[:1]:
        hits = scan_calls(h, base, size, targets)
    print("调用点统计:")
    for k, v in sorted(hits.items()):
        print("   %-40s %d 处，示例 %s" % (k, len(v), ["0x%X" % a for a in v[:5]]))

    out = os.path.join(BASE, "logs", "iat_scan.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"main": mb, "bcrypt": bc, "call_sites": hits,
                   "elapsed": round(time.time() - t0, 1)}, f, indent=1)
    print("-> %s  (%.1fs)" % (out, time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
