"""
S5-q —— 按 wechat-extract 仓库的「踩坑」复测密钥格式与作用域

仓库（ou-o/wechat-extract，README 第 138-141 行）给出两条关键提示：
  1) 密钥在内存中的格式是 ASCII 文本  x'<64hex enc_key><32hex salt>' ，共 98 字符；
  2) 4.1+ 不缓存原始密钥，只缓存 raw key；主进程扫不到时**改扫子进程 WeChatAppEx.exe**。

本脚本据此做两件事（都只用 page-1 HMAC 预言机判定，不依赖对格式的假设）：
  A. 在全部 Weixin/WeChatAppEx 进程里精确匹配 x'<hex>'（96/64/128 位三种长度），
     直接解码候选密钥并验证；
  B. 对每个 salt 命中点邻域做 stride=1 全偏移扫描（覆盖非 8 字节对齐的文本内偏移）。

用法：
  set PYTHONUTF8=1
  python 60_hexscan_all.py --db <db> [--part i/K] [--window 65536]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import re
import subprocess
import sys
import time

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PQI, PVR = 0x0400, 0x0010
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032

RE_HEX = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
RE_ASCII64 = re.compile(rb"[0-9a-fA-F]{64}")


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def target(dbpath):
    with open(dbpath, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    return salt, mac_salt, mac_msg, p1[MAC_OFF:PAGESZ]


def pids_of(names=("Weixin.exe", "WeChatAppEx.exe", "WeChat.exe", "WeChatApp.exe")):
    out = []
    try:
        r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True)
        for line in (r.stdout or "").splitlines():
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[0] in names and p[1].isdigit():
                out.append((int(p[1]), p[0]))
    except Exception:                                              # noqa: BLE001
        pass
    if not out:                                                    # tasklist 被拒时退回 Get-Process
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-Command",
                                "Get-Process Weixin,WeChatAppEx,WeChat -ErrorAction SilentlyContinue |"
                                "ForEach-Object { \"$($_.Id),$($_.ProcessName)\" }"],
                               capture_output=True, text=True, timeout=30)
            for line in (r.stdout or "").splitlines():
                a = line.strip().split(",")
                if len(a) == 2 and a[0].isdigit():
                    out.append((int(a[0]), a[1]))
        except Exception:                                          # noqa: BLE001
            pass
    return out


def regions(h):
    regs, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                and (mbi.Protect & PAGE_NOACCESS) == 0 and 0 < mbi.RegionSize < 700 * 1024 * 1024):
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--part", default="0/1")
    ap.add_argument("--window", type=int, default=65536)
    ap.add_argument("--no-window", action="store_true")
    args = ap.parse_args()

    part_i, part_k = (int(x) for x in args.part.split("/"))
    salt, mac_salt, mac_msg, expected = target(args.db)
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512

    def verify(cand):
        if len(cand) != 32:
            return False
        mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
        return hmac_new(mk, mac_msg, sha512).digest() == expected

    procs = pids_of()
    print("进程: %s" % procs, flush=True)
    hit = None
    stats = {"hexpat": 0, "window_tried": 0, "ascii_tried": 0}
    t0 = time.time()

    for pid, name in procs:
        h = kernel32.OpenProcess(PQI | PVR, False, pid)
        if not h:
            print("  跳过 %s:%d（OpenProcess 失败 err=%d）" % (name, pid, ctypes.get_last_error()), flush=True)
            continue
        regs = regions(h)
        regs = [r for i, r in enumerate(regs) if i % part_k == part_i]
        print("-- %s:%d 区域 %d 个" % (name, pid, len(regs)), flush=True)
        for ri, (base, size) in enumerate(regs):
            buf = ctypes.create_string_buffer(size)
            n = ctypes.c_size_t(0)
            if not kernel32.ReadProcessMemory(h, ctypes.c_uint64(base), buf, size, ctypes.byref(n)) \
                    or n.value != size:
                continue
            data = buf.raw
            # A1: x'<hex>' 文本
            for m in RE_HEX.finditer(data):
                stats["hexpat"] += 1
                s = m.group(1).decode()
                for cand_hex, where in ((s[:64], "x-hex[0:64]"),
                                        (s[64:128], "x-hex[64:128]"),
                                        (s[-64:], "x-hex[-64:]")):
                    if len(cand_hex) != 64:
                        continue
                    try:
                        cand = bytes.fromhex(cand_hex)
                    except ValueError:
                        continue
                    if verify(cand):
                        hit = (cand.hex(), where, pid, name, base + m.start())
                        break
                if hit:
                    break
            if hit:
                break
            # A2: 裸 ASCII 64hex（任意偏移）
            for m in RE_ASCII64.finditer(data):
                stats["ascii_tried"] += 1
                cand = bytes.fromhex(m.group(0).decode())
                if verify(cand):
                    hit = (cand.hex(), "ascii64", pid, name, base + m.start())
                    break
            if hit:
                break
            # B: salt 邻域全偏移
            if args.no_window:
                continue
            j = data.find(salt)
            while j >= 0 and not hit:
                lo = max(0, j - args.window)
                hi = min(len(data) - 32, j + SALT + args.window)
                off = lo
                while off <= hi:
                    stats["window_tried"] += 1
                    if verify(data[off:off + 32]):
                        hit = (data[off:off + 32].hex(), "saltwin", pid, name, base + off)
                        break
                    off += 1
                j = data.find(salt, j + 1)
            if hit:
                break
            if ri % 200 == 0 and ri:
                el = time.time() - t0
                print("   [%s:%d] %d/%d 区  hexpat=%d ascii=%d win=%d %.0fs"
                      % (name, pid, ri, len(regs), stats["hexpat"], stats["ascii_tried"],
                         stats["window_tried"], el), flush=True)
        kernel32.CloseHandle(h)
        if hit:
            break

    el = time.time() - t0
    if hit:
        print("FOUND key=%s via=%s pid=%d(%s) addr=0x%X  %.0fs"
              % (hit[0], hit[1], hit[2], hit[3], hit[4], el), flush=True)
        out = os.path.join(BASE, "keys", "hexscan_%s.json" % os.path.basename(args.db))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"db": args.db, "salt": salt.hex(), "enc_key": hit[0],
                       "method": hit[1], "pid": hit[2], "proc": hit[3],
                       "addr": "0x%X" % hit[4]}, f, indent=2)
        print("-> %s" % out, flush=True)
    else:
        print("no-hit  stats=%s  %.0fs" % (stats, el), flush=True)
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
