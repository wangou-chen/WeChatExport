"""
S5-k —— 目标化候选扫描：不逐字节滑动，而是直接在内存里找「看起来像密钥的字符串/缓冲区」。

覆盖 stride-8 全量扫描漏掉的情形：
  1. UTF-16LE 编码的 64 位 hex（x64 下起始可位于 2 mod 8 字节处）
  2. ASCII 64 位 hex（任意偏移，且未包裹在 x'...' 中）
  3. base64(32B) = 44 字符
  4. 直接在 salt 命中点邻域内逐字节（stride=1）精扫

用法：
  set PYTHONUTF8=1
  C:\\Python314\\python.exe 98_targeted_scan.py --pid 16056 --db <db> --part 0/8 [--salt-window 512]
"""
import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import re
import sys
import time

kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PQI, PVR = 0x0400, 0x0010
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032

RE_ASCII_HEX = re.compile(rb"[0-9a-fA-F]{64}")
RE_UTF16_HEX = re.compile(rb"(?:[0-9a-fA-F]\x00){64}")
RE_B64 = re.compile(rb"[A-Za-z0-9+/]{43}=")


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def build_target(dbpath):
    with open(dbpath, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    return salt, mac_salt, mac_msg, p1[MAC_OFF:PAGESZ]


def enum_regions(h):
    regs, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        base, size = mbi.BaseAddress, mbi.RegionSize
        if size <= 0:
            break
        if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                and (mbi.Protect & PAGE_NOACCESS) == 0 and size < 800 * 1024 * 1024):
            regs.append((base, size))
        nxt = base + size
        if nxt <= addr:
            break
        addr = nxt
    return regs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--part", default="0/1")
    ap.add_argument("--salt-window", type=int, default=512)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    part_i, part_k = (int(x) for x in args.part.split("/"))
    salt, mac_salt, mac_msg, expected = build_target(args.db)
    h = kernel32.OpenProcess(PQI | PVR, False, args.pid)
    if not h:
        raise SystemExit("OpenProcess 失败 err=%d" % ctypes.get_last_error())
    all_regs = enum_regions(h)
    regs = [r for i, r in enumerate(all_regs) if i % part_k == part_i]
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    raw = ctypes.create_string_buffer
    rpm = kernel32.ReadProcessMemory
    u64, size_t, byref = ctypes.c_uint64, ctypes.c_size_t, ctypes.byref

    def try_key(cand, where):
        if len(cand) != 32:
            return None
        mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
        if hmac_new(mk, mac_msg, sha512).digest() == expected:
            print("FOUND key=%s where=%s" % (cand.hex(), where), flush=True)
            return cand.hex()
        return None

    t0 = time.time()
    tried = 0
    hit = None
    salt_hits = 0
    for base, size in regs:
        buf = raw(size)
        n = size_t(0)
        if not rpm(h, u64(base), buf, size, byref(n)) or n.value != size:
            continue
        data = buf.raw
        # 1) UTF-16LE hex
        for m in RE_UTF16_HEX.finditer(data):
            tried += 1
            hit = try_key(bytes.fromhex(m.group(0).decode("utf-16-le")), "utf16hex@0x%X" % (base + m.start()))
            if hit:
                break
        if hit:
            break
        # 2) ASCII hex
        for m in RE_ASCII_HEX.finditer(data):
            tried += 1
            hit = try_key(bytes.fromhex(m.group(0).decode()), "asciihex@0x%X" % (base + m.start()))
            if hit:
                break
        if hit:
            break
        # 3) base64(32B)
        for m in RE_B64.finditer(data):
            tried += 1
            try:
                k = base64.b64decode(m.group(0) + b"=")
            except Exception:                                       # noqa: BLE001
                continue
            hit = try_key(k, "b64@0x%X" % (base + m.start()))
            if hit:
                break
        if hit:
            break
        # 4) salt 命中点邻域 stride=1 精扫
        j = data.find(salt)
        while j >= 0:
            salt_hits += 1
            lo = max(0, j - args.salt_window)
            hi = min(len(data) - 32, j + SALT + args.salt_window)
            off = lo
            while off <= hi:
                tried += 1
                hit = try_key(data[off:off + 32], "saltwin@0x%X" % (base + off))
                if hit:
                    break
                off += 1
            if hit:
                break
            j = data.find(salt, j + 1)
        if hit:
            break

    print("DONE part=%d/%d regions=%d tried=%d salt_hits=%d t=%.0fs hit=%s"
          % (part_i, part_k, len(regs), tried, salt_hits, time.time() - t0, hit), flush=True)
    if hit and args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"db": args.db, "salt": salt.hex(), "enc_key": hit, "pid": args.pid}, f, indent=2)
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
