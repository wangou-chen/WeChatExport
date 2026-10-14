"""S5-as —— 一次性抓取全部数据库密钥（4.0.3.39 内存中有 x'<64hex key><32hex salt>'）

背景（本会话实测）：
  * 微信 4.1.15.13：内存无明文密钥、自带 AES、有反调试 → 密钥不可得（已放弃）。
  * 微信 4.0.3.39：内存中确实存在 x'<64hex enc_key><32hex salt>' 文本，60_hexscan_all.py
    已命中 message_0.db 的密钥 ac52e88c…40388 并通过 page-1 HMAC 校验。
  * **每个库一把独立密钥**（26 个 salt 各不相同），因此需要按 salt 归属逐个收集。

本脚本：
  1. 收集 db_storage 下全部 .db 的 salt → {salt: db 相对路径}；
  2. 扫描所有 Weixin 进程内存，正则匹配 x'([0-9a-fA-F]{96})'，取前 64 位为密钥、后 32 位为 salt；
  3. 用 page-1 HMAC 预言机校验「该 salt 对应库」；
  4. 输出 keys/all_keys_full.json（salt → {key, db}）与逐库汇总。

用法：
  set PYTHONUTF8=1
  C:\\Python314\\python.exe 99_grab_all_keys.py --db-dir <db_storage> [--out keys\\all_keys_full.json]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct
import subprocess
import sys
import time

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PQI, PVR = 0x0400, 0x0010
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
RE_HEX = re.compile(rb"x'([0-9a-fA-F]{96})'")


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def pids_of(names=("Weixin.exe", "WeChatAppEx.exe")):
    out = []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin,WeChatAppEx -ErrorAction SilentlyContinue |"
                            "Sort-Object WorkingSet64 -Descending |"
                            "ForEach-Object { \"$($_.Id),$($_.ProcessName)\" }"],
                           capture_output=True, text=True, timeout=30)
        for line in (r.stdout or "").splitlines():
            a = line.strip().split(",")
            if len(a) == 2 and a[0].isdigit() and (a[1] + ".exe") in names:
                out.append((int(a[0]), a[1]))
    except Exception:                                              # noqa: BLE001
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
    ap.add_argument("--db-dir", required=True)
    ap.add_argument("--out", default=os.path.join(BASE, "keys", "all_keys_full.json"))
    args = ap.parse_args()

    # 1) 收集 salt → db
    dbs = {}
    for root, _d, files in os.walk(args.db_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                p = os.path.join(root, f)
                if os.path.getsize(p) < PAGESZ:
                    continue
                with open(p, "rb") as fh:
                    p1 = fh.read(PAGESZ)
                rel = os.path.relpath(p, args.db_dir)
                dbs[rel] = {
                    "path": p,
                    "salt": p1[:SALT],
                    "mac_salt": bytes(b ^ 0x3A for b in p1[:SALT]),
                    "mac_msg": p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00",
                    "expected": p1[MAC_OFF:PAGESZ],
                }
    salt2db = {}
    for rel, m in dbs.items():
        salt2db.setdefault(m["salt"].hex(), []).append(rel)
    print("库 %d 个，salt %d 个" % (len(dbs), len(salt2db)), flush=True)

    def verify(key, m):
        mk = hashlib.pbkdf2_hmac("sha512", key, m["mac_salt"], 2, 32)
        hm = hmac_mod.new(mk, m["mac_msg"], hashlib.sha512)
        hm.update(struct.pack("<I", 1))
        return hm.digest() == m["expected"]

    # 2) 扫描内存
    found = {}          # rel -> key hex
    t0 = time.time()
    procs = pids_of()
    print("进程: %s" % procs, flush=True)
    npat = 0
    for pid, name in procs:
        h = kernel32.OpenProcess(PQI | PVR, False, pid)
        if not h:
            continue
        for base, size in regions(h):
            buf = ctypes.create_string_buffer(size)
            n = ctypes.c_size_t(0)
            if not kernel32.ReadProcessMemory(h, ctypes.c_uint64(base), buf, size, ctypes.byref(n)) \
                    or n.value != size:
                continue
            data = buf.raw
            for m in RE_HEX.finditer(data):
                npat += 1
                s = m.group(1).decode().lower()
                key_hex, salt_hex = s[:64], s[64:]
                if salt_hex not in salt2db:
                    continue
                key = bytes.fromhex(key_hex)
                for rel in salt2db[salt_hex]:
                    if rel in found:
                        continue
                    if verify(key, dbs[rel]):
                        found[rel] = key_hex
                        print("  [OK] %-42s key=%s" % (rel, key_hex), flush=True)
        kernel32.CloseHandle(h)
        if len(found) == len(dbs):
            break

    print("\n扫描 x'<96hex>' 模式 %d 个，取得密钥 %d/%d，用时 %.1fs"
          % (npat, len(found), len(dbs), time.time() - t0), flush=True)

    # 3) 交叉验证：同一 salt 的多库共用密钥；输出汇总
    result = {}
    for rel, m in dbs.items():
        if rel in found:
            result[rel] = {"enc_key": found[rel], "salt": m["salt"].hex(),
                           "size_mb": round(os.path.getsize(m["path"]) / 1048576, 1)}
    missing = [r for r in dbs if r not in result]
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print("-> %s" % args.out, flush=True)
    if missing:
        print("未取到密钥的库 (%d): %s" % (len(missing), ", ".join(missing[:15])), flush=True)
        print("提示：对未命中的库，在微信里打开对应功能（朋友圈/收藏/联系人）后再跑一次。", flush=True)
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(main())
