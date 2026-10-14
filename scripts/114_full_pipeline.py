"""S6 —— 总驱动：收集全部数据库密钥并解密全部数据库（使用已验证正确的 raw-key 模式）

关键修正（本轮实测确定）：
  加密密钥 = 从内存 x'<64hex key><32hex salt>' 中取出的 **32 字节原始值，直接用作 AES-256 密钥**
  （raw-key 模式，不做 PBKDF2 派生）。
  仅有 page-1 HMAC 校验使用派生值：PBKDF2-SHA512(raw, salt^0x3A, 2, 32)。

解密实现复用 tool\\wechat-decrypt-main\\decrypt_db.py 的 decrypt_page / decrypt_database。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib
  C:\\Python314\\python.exe 114_full_pipeline.py --db-dir <db_storage> [--out <dir>] [--skip-scan]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import time

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
TOOL = os.path.join(BASE, "tool", "wechat-decrypt-main")
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PQI, PVR = 0x0400, 0x0010
RE_HEX = re.compile(rb"x'([0-9a-fA-F]{96})'")


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def load_tool():
    if TOOL not in sys.path:
        sys.path.insert(0, TOOL)
    spec = importlib.util.spec_from_file_location("dd", os.path.join(TOOL, "decrypt_db.py"))
    m = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(m)
    except SystemExit:
        pass
    return m


def pids_of():
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


def collect_dbs(db_dir):
    dbs = {}
    for root, _d, files in os.walk(db_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                p = os.path.join(root, f)
                if os.path.getsize(p) < PAGESZ:
                    continue
                with open(p, "rb") as fh:
                    p1 = fh.read(PAGESZ)
                    p2 = fh.read(PAGESZ)
                dbs[os.path.relpath(p, db_dir)] = {
                    "path": p, "salt": p1[:SALT], "page1": p1, "page2": p2,
                    "mac_salt": bytes(b ^ 0x3A for b in p1[:SALT]),
                    "mac_msg": p1[SALT:MAC_OFF] + b"\x01\x00\x00\x00", "tag": p1[MAC_OFF:PAGESZ],
                }
    return dbs


_TOOL = {"m": None}


def verify(raw_key, m):
    """判据：直接调用 tool 自己的 decrypt_page 解 page1/page2（与最终解密完全同一实现），
    要求 page1 头为 SQLite 且 page_size=4096、page2 首字节为合法 b-tree 类型。
    这样可彻底避免手工切片与工具实现不一致的问题。"""
    if _TOOL["m"] is None:
        _TOOL["m"] = load_tool()
    t = _TOOL["m"]
    try:
        d1 = t.decrypt_page(raw_key, m["page1"], 1)
        if d1[:16] != b"SQLite format 3\x00":
            return False
        if int.from_bytes(d1[16:18], "big") != PAGESZ:
            return False
        p2 = m.get("page2")
        if p2:
            d2 = t.decrypt_page(raw_key, p2, 2)
            if d2[0] not in (0x0D, 0x05, 0x0A, 0x02):
                return False
    except Exception:                                              # noqa: BLE001
        return False
    m["enc_key"] = raw_key.hex()
    return True


def scan_keys(dbs, rounds=6):
    salt2db = {}
    for rel, m in dbs.items():
        salt2db.setdefault(m["salt"].hex(), []).append(rel)
    found = {}
    for rnd in range(rounds):
        todo = [r for r in dbs if r not in found]
        if not todo:
            break
        print("[round %d] 待找密钥的库 %d 个" % (rnd + 1, len(todo)), flush=True)
        for pid in pids_of():
            h = kernel32.OpenProcess(PQI | PVR, False, pid)
            if not h:
                continue
            for base, size in regions(h):
                buf = ctypes.create_string_buffer(size)
                n = ctypes.c_size_t(0)
                if not kernel32.ReadProcessMemory(h, ctypes.c_uint64(base), buf, size,
                                                  ctypes.byref(n)) or n.value != size:
                    continue
                for mt in RE_HEX.finditer(buf.raw):
                    s = mt.group(1).decode().lower()
                    key_hex, salt_hex = s[:64], s[64:]
                    if salt_hex not in salt2db:
                        continue
                    raw = bytes.fromhex(key_hex)
                    for rel in salt2db[salt_hex]:
                        if rel in found:
                            continue
                        if verify(raw, dbs[rel]):
                            found[rel] = key_hex
                            print("   [OK] %-44s %s" % (rel, key_hex), flush=True)
            kernel32.CloseHandle(h)
            if len(found) == len(dbs):
                break
        if len(found) == len(dbs):
            break
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-dir", required=True)
    ap.add_argument("--out", default=os.path.join(BASE, "decrypted"))
    ap.add_argument("--keys-in", default=os.path.join(BASE, "keys", "all_keys_full.json"))
    ap.add_argument("--skip-scan", action="store_true")
    args = ap.parse_args()

    dbs = collect_dbs(args.db_dir)
    print("库 %d 个" % len(dbs), flush=True)

    keys = {}
    if args.skip_scan and os.path.exists(args.keys_in):
        with open(args.keys_in, encoding="utf-8") as f:
            j = json.load(f)
        keys = {k: (v["enc_key"] if isinstance(v, dict) else v) for k, v in j.items()}
        print("从 %s 载入 %d 把密钥" % (args.keys_in, len(keys)), flush=True)
    else:
        keys = scan_keys(dbs)

    print("\n取得密钥 %d/%d" % (len(keys), len(dbs)), flush=True)
    os.makedirs(os.path.dirname(args.keys_in), exist_ok=True)
    with open(args.keys_in, "w", encoding="utf-8") as f:
        json.dump({r: {"enc_key": k, "salt": dbs[r]["salt"].hex()} for r, k in keys.items()},
                  f, indent=2, ensure_ascii=False)

    tool = load_tool()
    os.makedirs(args.out, exist_ok=True)
    ok_list, fail_list = [], []
    t0 = time.time()
    for rel, m in sorted(dbs.items()):
        if rel not in keys:
            fail_list.append((rel, "无密钥"))
            continue
        raw = bytes.fromhex(keys[rel])
        dst = os.path.join(args.out, rel.replace("\\", "_").replace("/", "_"))
        try:
            ok = tool.decrypt_database(m["path"], dst, raw)
            # WAL 回填
            wal_src = m["path"] + "-wal"
            if ok and os.path.exists(wal_src):
                try:
                    n = tool.decrypt_wal(wal_src, dst, raw)
                    if n:
                        print("   %s WAL 回填 %d 帧" % (rel, n), flush=True)
                except Exception as e:                             # noqa: BLE001
                    print("   %s WAL 失败: %s" % (rel, e), flush=True)
            if ok:
                # 校验头
                with open(dst, "rb") as f:
                    head = f.read(16)
                if head == b"SQLite format 3\x00":
                    ok_list.append(rel)
                    print("  OK   %-46s %.1f MB" % (rel, os.path.getsize(dst) / 1048576), flush=True)
                else:
                    fail_list.append((rel, "头不对"))
            else:
                fail_list.append((rel, "HMAC/解密失败"))
        except Exception as e:                                     # noqa: BLE001
            fail_list.append((rel, str(e)))
    print("\n成功 %d / %d，用时 %.1fs" % (len(ok_list), len(dbs), time.time() - t0), flush=True)
    if fail_list:
        print("失败：")
        for rel, why in fail_list:
            print("   %-46s %s" % (rel, why))
    print("输出目录: %s" % args.out, flush=True)
    return 0 if ok_list else 1


if __name__ == "__main__":
    sys.exit(main())
