"""S5-al —— 在 Weixin.dll 里定位所有 AES 轮密钥扩展函数（重点找 AES-256 形态）

依据（实测）：
  * 85 号 dump：RVA 0x5936EDA 是一处 AES 扩展函数，紧跟 7 个 AESKEYGENASSIST（常量 01 02 04 08 10 20 40）
    → 这是 AES-128 扩展（10 轮形态）。
  * 89 号硬件断点在该入口抓到 32 字节密钥，但 26 个数据库全部 MISS
    → 该函数属于微信其它功能（网络/消息层），不是 SQLCipher 的库密钥。
  * SQLCipher 用 AES-256（14 轮），其扩展函数应有 **两组** 轮常量序列
    （01 02 04 08 10 20 40 各出现两次，或连续 7+7 个 AESKEYGENASSIST）。

本脚本（只读）：
  1. 扫描 Weixin.dll 代码段，找所有形如 `66 0F 3A DF /r imm8`（AESKEYGENASSIST）的位置；
  2. 按「连续出现次数」聚合：≥7 个连续的视作一处扩展函数，并记录其所属函数入口附近地址；
  3. 输出每处扩展函数的 RVA、连续 AESKEYGENASSIST 个数、以及紧随其后的 imm8 常量序列
     （AES-128 形态常量为 01 02 04 08 10 20 40；AES-256 形态会出现两轮 01..40 或 01..40 再加倍）。
  供下一步用硬件断点逐处验证。

用法：
  C:\\Python314\\python.exe 91_find_aes256_expanders.py --pid <pid> [--out <json>]
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
    """用 frida 取 Weixin.dll 基址（本机 attach 可用）。"""
    import frida
    dev = frida.get_local_device()
    s = dev.attach(pid)
    holder = {}
    sc = s.create_script(
        'try { const m = Process.getModuleByName("Weixin.dll");'
        ' send({base: m.base.toString(), size: m.size}); } catch (e) { send({err: "" + e}); }')
    sc.on("message", lambda m, d: holder.update(m.get("payload") or {}))
    sc.load()
    time.sleep(1.5)
    try:
        sc.unload()
    except Exception:                                              # noqa: BLE001
        pass
    s.detach()
    return holder


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(BASE, "logs", "aes256.json"))
    args = ap.parse_args()

    pid = args.pid
    if not pid:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin -ErrorAction SilentlyContinue |"
                            "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                           capture_output=True, text=True, timeout=30)
        pid = int((r.stdout or "0").strip() or 0)
    info = module_base(pid)
    if "base" not in info:
        raise SystemExit("未取到 Weixin.dll: %s" % info)
    base = int(info["base"], 16)
    size = int(info["size"])
    print("pid=%d Weixin.dll base=0x%X size=%d" % (pid, base, size), flush=True)

    h = kernel32.OpenProcess(PQI | PVR, False, pid)
    if not h:
        raise SystemExit("OpenProcess 失败 err=%d" % ctypes.get_last_error())

    # 读入整个映像内 committed 区域
    blobs = []          # (base_addr, bytes)
    addr, mbi = 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        ba, sz = mbi.BaseAddress, mbi.RegionSize
        if sz <= 0:
            break
        if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                and (mbi.Protect & PAGE_NOACCESS) == 0 and base <= ba < base + size):
            data = readmem(h, ba, sz)
            if data:
                blobs.append((ba, data))
        nxt = ba + sz
        if nxt <= addr:
            break
        addr = nxt
    kernel32.CloseHandle(h)
    total = sum(len(d) for _b, d in blobs)
    print("读取映像 %.0f MB / %d 个区域" % (total / 1048576, len(blobs)), flush=True)

    # 找所有 AESKEYGENASSIST：66 0F 3A DF /r imm8  (长度 6 字节)
    pat = b"\x66\x0f\x3a\xdf"
    occ = []            # (addr, imm8)
    for ba, data in blobs:
        i = data.find(pat)
        while i >= 0:
            if i + 6 <= len(data):
                occ.append((ba + i, data[i + 5]))
            i = data.find(pat, i + 1)
    occ.sort()
    print("AESKEYGENASSIST 出现 %d 处" % len(occ), flush=True)

    # 聚合：相邻间隔 < 0x60 视作同一函数
    groups = []
    cur = []
    for a, imm in occ:
        if cur and a - cur[-1][0] > 0x60:
            groups.append(cur)
            cur = []
        cur.append((a, imm))
    if cur:
        groups.append(cur)
    print("聚合成 %d 个扩展函数" % len(groups), flush=True)

    # 找函数入口：向前找 int3 填充
    out = []
    for g in groups:
        first = g[0][0]
        rva = first - base
        imms = [hex(x[1]) for x in g]
        rec = {"rva_first_kga": "0x%X" % rva, "count": len(g), "imms": imms,
               "span": "0x%X" % (g[-1][0] - first)}
        out.append(rec)
        print("  RVA 0x%-10X 连续 %2d 个  常量=%s  span=0x%X"
              % (rva, len(g), imms[:16], g[-1][0] - first), flush=True)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"pid": pid, "base": info["base"], "groups": out}, f, indent=1)
    print("-> %s" % args.out, flush=True)
    print("提示：SQLCipher 用 AES-256，其扩展函数常量序列会包含两组 01 02 04 08 10 20 40", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
