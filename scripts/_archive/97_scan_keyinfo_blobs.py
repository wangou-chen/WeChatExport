"""S5-aq —— 在 key_info.db 的 key_info_data 里搜数据库密钥候选（任意偏移）

依据（实测）：
  E:\\xwechat_files\\all_users\\login\\<wxid>\\key_info.db 是**未加密 SQLite**，
  表 LoginKeyInfoTable(user_name_md5, key_md5, key_info_md5, key_info_data)，
  284 行的 key_info_data 均为 180 字节 blob → 本地封装存储的登录/密钥信息。

本脚本：
  1. 取出所有 key_info_data（含 -wal 里的新数据）；
  2. 对每条 blob 的**所有字节偏移**取 32 字节窗口，用 page-1 HMAC 预言机验证；
  3. 同时验证 blob 的 hex 文本形式（若密钥以 hex 存放）；
  4. 输出命中（若有）与统计。

用法：
  set PYTHONUTF8=1
  python 97_scan_keyinfo_blobs.py --db <db> [--db-dir <dir>]
"""
import argparse
import hashlib
import hmac as hmac_mod
import os
import sqlite3
import struct
import sys

PAGESZ, SALT, MAC_OFF = 4096, 16, 4032


def targets(db, db_dir):
    out = []
    if db:
        out.append(db)
    if db_dir:
        for root, _d, files in os.walk(db_dir):
            for f in files:
                if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                    p = os.path.join(root, f)
                    if os.path.getsize(p) >= PAGESZ:
                        out.append(p)
    meta = {}
    for p in out:
        with open(p, "rb") as f:
            p1 = f.read(PAGESZ)
        salt = p1[:SALT]
        meta[p] = {
            "name": os.path.basename(p),
            "mac_salt": bytes(b ^ 0x3A for b in salt),
            "mac_msg": p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00",
            "expected": p1[MAC_OFF:PAGESZ],
        }
    return meta


def ident(cand, meta):
    hits = []
    for p, m in meta.items():
        mk = hashlib.pbkdf2_hmac("sha512", cand, m["mac_salt"], 2, 32)
        hm = hmac_mod.new(mk, m["mac_msg"], hashlib.sha512)
        hm.update(struct.pack("<I", 1))
        if hm.digest() == m["expected"]:
            hits.append(m["name"])
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=r"<数据盘>\xwechat_files\all_users\login\<你的wxid>\key_info.db")
    ap.add_argument("--db-dir", default=r"<db_storage>")
    args = ap.parse_args()

    meta = targets("", args.db_dir)
    print("用于判定的目标库 %d 个" % len(meta), flush=True)

    p = args.db.replace("\\", "/")
    con = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
    rows = list(con.execute("SELECT user_name_md5, key_md5, key_info_md5, key_info_data "
                            "FROM LoginKeyInfoTable"))
    con.close()
    print("取到记录 %d 条" % len(rows), flush=True)

    tried = 0
    hits = []
    for i, (umd5, kmd5, kimd5, blob) in enumerate(rows):
        if not isinstance(blob, (bytes, bytearray)):
            continue
        b = bytes(blob)
        # 1) 任意偏移 32 字节窗口
        for off in range(0, max(1, len(b) - 31)):
            cand = b[off:off + 32]
            tried += 1
            names = ident(cand, meta)
            if names:
                hits.append({"row": i, "where": "blob+%d" % off, "key": cand.hex(),
                             "dbs": names})
                print("*** KEY row=%d blob+%d = %s  解开: %s"
                      % (i, off, cand.hex(), ", ".join(names)), flush=True)
        # 2) hex 文本形式
        try:
            txt = b.decode("ascii")
            if len(txt) >= 64 and all(c in "0123456789abcdefABCDEF" for c in txt[:64]):
                cand = bytes.fromhex(txt[:64])
                tried += 1
                names = ident(cand, meta)
                if names:
                    hits.append({"row": i, "where": "hex", "key": cand.hex(), "dbs": names})
                    print("*** KEY row=%d hex = %s  解开: %s"
                          % (i, cand.hex(), ", ".join(names)), flush=True)
        except Exception:                                          # noqa: BLE001
            pass
        if i % 50 == 0:
            print("   .. %d/%d 行，已试 %d 个候选" % (i, len(rows), tried), flush=True)

    print("\n完成：试了 %d 个候选，命中 %d" % (tried, len(hits)), flush=True)
    if not hits:
        print("结论：密钥未以明文/裸字节形式出现在 key_info_data 中（应为加密封装）。", flush=True)
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
