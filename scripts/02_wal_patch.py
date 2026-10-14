"""
WAL 合并 + 完整性校验  (WeChatExport / S6-b)

背景：decrypt_db.py 只解密 .db 主文件，忽略 -wal。微信运行中 WAL 未 checkpoint，
      最大 64MB，直接跳过会丢失最近消息。本脚本按 WAL header salt 过滤出当前周期的
      有效 frame，逐帧解密后回填到已解密的 DB 副本。

用法（在 WeChatExport 根目录执行）：
  venv\\Scripts\\python.exe scripts\\02_wal_patch.py
"""
import os
import sys
import json
import struct
import sqlite3

from Crypto.Cipher import AES

BASE = r"<项目根>"
DB_DIR = os.path.join(BASE, "snapshot", "db_storage")
DEC_DIR = os.path.join(BASE, "decrypted")
KEYS_FILE = os.path.join(BASE, "keys", "all_keys.json")
LOG_DIR = os.path.join(BASE, "logs")

PAGE_SZ = 4096
SALT_SZ = 16
IV_SZ = 16
RESERVE_SZ = 80          # IV(16) + HMAC(64)
WAL_HDR_SZ = 32
FRAME_HDR_SZ = 24
FRAME_SZ = FRAME_HDR_SZ + PAGE_SZ
SQLITE_HDR = b"SQLite format 3\x00"

report = {"patched": [], "page1_nosalt": [], "errors": [], "checks": {}}


def decrypt_page(enc_key, page, pgno):
    """主库页面解密：page 1 前置 16 字节 salt，其余页无 salt 前缀。"""
    iv = page[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        enc = page[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(enc)
        return SQLITE_HDR + dec + b"\x00" * RESERVE_SZ
    enc = page[:PAGE_SZ - RESERVE_SZ]
    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(enc)
    return dec + b"\x00" * RESERVE_SZ


def decrypt_page_nosalt(enc_key, page):
    """备选解释：WAL 中的 page 1 frame 不带 salt 前缀。"""
    iv = page[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    enc = page[:PAGE_SZ - RESERVE_SZ]
    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(enc)
    return dec + b"\x00" * RESERVE_SZ


def patch_wal(wal_path, db_path, enc_key):
    """按 WAL header salt 过滤有效 frame，回填。返回 (有效frame数, 跳过数, 异常数)。"""
    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HDR_SZ:
        return 0, 0, 0

    patched = skipped = bad = 0
    with open(wal_path, "rb") as wf, open(db_path, "r+b") as df:
        hdr = wf.read(WAL_HDR_SZ)
        if len(hdr) < WAL_HDR_SZ:
            return 0, 0, 0
        s1 = struct.unpack(">I", hdr[16:20])[0]
        s2 = struct.unpack(">I", hdr[20:24])[0]

        while wf.tell() + FRAME_SZ <= wal_size:
            fh = wf.read(FRAME_HDR_SZ)
            if len(fh) < FRAME_HDR_SZ:
                break
            pgno = struct.unpack(">I", fh[0:4])[0]
            fs1 = struct.unpack(">I", fh[8:12])[0]
            fs2 = struct.unpack(">I", fh[12:16])[0]
            page = wf.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                break

            if pgno == 0 or pgno > 5_000_000:
                skipped += 1
                continue
            if fs1 != s1 or fs2 != s2:
                skipped += 1          # 上一 WAL 周期的残留 frame
                continue

            if pgno == 1:
                dec = decrypt_page(enc_key, page, 1)
                if dec[:16] != SQLITE_HDR:
                    alt = decrypt_page_nosalt(enc_key, page)
                    if alt[:16] == SQLITE_HDR:
                        dec = alt
                        report["page1_nosalt"].append(os.path.relpath(db_path, DEC_DIR))
                    else:
                        bad += 1
                        continue
            else:
                dec = decrypt_page(enc_key, page, pgno)

            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1

    return patched, skipped, bad


def check(db_path, full=False):
    """结构校验。返回 (quick_check, integrity_check|None)。"""
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        quick = con.execute("PRAGMA quick_check").fetchone()[0]
        integ = None
        if full:
            integ = con.execute("PRAGMA integrity_check").fetchone()[0]
        con.close()
        return quick, integ
    except Exception as e:                                   # noqa: BLE001
        return f"EXC: {e}", None


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(KEYS_FILE):
        print(f"[ERROR] 缺少密钥文件 {KEYS_FILE}（需先完成 S5 密钥提取）")
        sys.exit(1)
    keys = json.load(open(KEYS_FILE, encoding="utf-8"))
    print(f"加载 {len(keys)} 个密钥\n")

    for rel, info in sorted(keys.items()):
        dec_db = os.path.join(DEC_DIR, rel)
        wal = os.path.join(DB_DIR, rel + "-wal")
        if not os.path.exists(dec_db):
            report["errors"].append(f"{rel}: 解密副本缺失")
            print(f"SKIP  {rel}  (未解密)")
            continue

        enc_key = bytes.fromhex(info["enc_key"])
        size_mb = info.get("size_mb", 0)

        if os.path.exists(wal):
            p, s, b = patch_wal(wal, dec_db, enc_key)
            wal_mb = os.path.getsize(wal) / 1024 / 1024
            print(f"PATCH {rel:<40} wal={wal_mb:6.1f}MB  回填 {p:5d} 页  跳过 {s:5d}  异常 {b}")
            report["patched"].append({"db": rel, "pages": p, "skipped": s, "bad": b})
        else:
            print(f"NOWAL {rel:<40} ({size_mb}MB)")

        q, i = check(dec_db, full=rel.startswith(("message_", "contact", "sns")))
        report["checks"][rel] = {"quick": q, "integrity": i}
        flag = "OK " if q == "ok" else "BAD"
        extra = f" integrity={i}" if i else ""
        print(f"      {flag} quick_check={q}{extra}")

    out = os.path.join(LOG_DIR, "wal_patch_report.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    bad = [k for k, v in report["checks"].items() if v["quick"] != "ok"]
    print(f"\n{'='*70}")
    print(f"回填合计: {sum(p['pages'] for p in report['patched'])} 页")
    print(f"page1 无 salt 假设命中: {len(report['page1_nosalt'])} 次 {report['page1_nosalt'][:5]}")
    print(f"错误: {len(report['errors'])}  校验不通过: {len(bad)} {bad[:10]}")
    print(f"报告: {out}")


if __name__ == "__main__":
    main()
