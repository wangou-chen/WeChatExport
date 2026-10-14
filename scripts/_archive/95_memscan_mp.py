"""
S5-g —— page-1 HMAC 预言机扫描（Python + OpenSSL，多进程分片）

本机实测结论（logs/、96_bench_oracle.py）：
  * Python 单线程 62k oracle/s；线程池因 GIL 反而降到 23k/s —— 线程无用。
  * 4 个独立进程实测合计 187k/s（4.3s/20 万次/进程）—— 进程级并行有效。
  * multiprocessing.Pool 在本机沙箱内因命名管道被拒（WinError 5）不可用，
    故采用「外层拉起 K 个进程 + 区域按序号取模分片」，进程间不通信。

正确性依据（与 91_find_key.py / KeyScan.cs 一致）：
  mac_key = PBKDF2-HMAC-SHA512(pass=cand, salt=page1[0:16]^0x3A, iter=2, dkLen=32)
  HMAC-SHA512(mac_key, page1[16:4032] || LE32(1)) == page1[4032:4096]
  命中概率 2^-512，命中即密钥正确。

单分片用法：
  set PYTHONUTF8=1
  python 95_memscan_mp.py --pid 16056 --db <db> --part 0/16 --stride 8
整体用法见 97_scan_all.ps1
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import time

kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PQI, PVR = 0x0400, 0x0010
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032


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
    if p1[:15] == b"SQLite format 3":
        raise SystemExit("[!] page1 已是明文 SQLite，无需解密")
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    assert len(mac_msg) == 4020, len(mac_msg)
    return salt, mac_salt, mac_msg, expected


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
    ap.add_argument("--stride", type=int, default=8)
    ap.add_argument("--part", default="0/1")
    ap.add_argument("--max", type=int, default=0)
    ap.add_argument("--out", default="")
    ap.add_argument("--maxregionsize", type=int, default=0, help="只扫小于该字节数的区域（0=不限）")
    ap.add_argument("--minregionsize", type=int, default=0, help="只扫大于该字节数的区域（0=不限）")
    args = ap.parse_args()

    part_i, part_k = (int(x) for x in args.part.split("/"))
    salt, mac_salt, mac_msg, expected = build_target(args.db)

    h = kernel32.OpenProcess(PQI | PVR, False, args.pid)
    if not h:
        raise SystemExit("OpenProcess 失败 pid=%d err=%d" % (args.pid, ctypes.get_last_error()))
    all_regs = enum_regions(h)
    if args.maxregionsize:
        all_regs = [r for r in all_regs if r[1] < args.maxregionsize]
    if args.minregionsize:
        all_regs = [r for r in all_regs if r[1] > args.minregionsize]
    regs = [r for i, r in enumerate(all_regs) if i % part_k == part_i]
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    raw = ctypes.create_string_buffer
    rpm = kernel32.ReadProcessMemory
    size_t = ctypes.c_size_t
    u64 = ctypes.c_uint64
    byref = ctypes.byref
    t0 = time.time()
    calls = 0
    nbytes = 0
    hit = None
    last_report = 0.0

    for base, size in regs:
        buf = raw(size)
        n = size_t(0)
        if not rpm(h, u64(base), buf, size, byref(n)) or n.value != size:
            continue
        data = buf.raw
        nbytes += size
        off = 0
        last = size - 32
        while off <= last:
            cand = data[off:off + 32]
            mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
            if hmac_new(mk, mac_msg, sha512).digest() == expected:
                hit = (base + off, cand.hex())
                break
            calls += 1
            off += args.stride
        if hit:
            break
        if args.max and calls >= args.max:
            break
        now = time.time()
        if now - last_report > 5:
            last_report = now
            el = now - t0
            print("  .. part=%d/%d MB=%d oracle=%d t=%.0fs rate=%.0f/s"
                  % (part_i, part_k, nbytes // 1048576, calls, el, calls / max(el, 1e-9)),
                  file=sys.stderr, flush=True)

    el = time.time() - t0
    if hit:
        print("FOUND part=%d/%d key=%s key_addr=0x%X oracle=%d t=%.0fs"
              % (part_i, part_k, hit[1], hit[0], calls, el), flush=True)
        if args.out:
            rec = {"db": args.db, "salt": salt.hex(), "enc_key": hit[1],
                   "key_addr": "0x%X" % hit[0], "pid": args.pid, "stride": args.stride}
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(rec, f, indent=2)
    else:
        print("DONE part=%d/%d regions=%d MB=%d oracle=%d t=%.0fs rate=%.0f/s no-hit"
              % (part_i, part_k, len(regs), nbytes // 1048576, calls, el, calls / max(el, 1e-9)),
              flush=True)
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
