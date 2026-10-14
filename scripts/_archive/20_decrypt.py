"""
S5-h —— SQLCipher 4 页面级解密（weixin 4.x 的加密库格式）

页面布局（reserved = 80, page_size = 4096）：
  page 1: [0:16] 明文 salt | [16:4032] 密文 | [4032:4096] HMAC-SHA512 tag
  page N: [0:4016] 密文      | [4016:4080] tag（末尾 16 字节恒为 0x00 padding）

密钥派生（SQLCipher 4 默认 KDF）：
  enc_key = PBKDF2-HMAC-SHA512(pass = raw_key, salt = salt, iter = 256000, dkLen = 32)
  mac_key = PBKDF2-HMAC-SHA512(pass = raw_key, salt = salt ^ 0x3A,  iter = 2,      dkLen = 32)
  tag     = HMAC-SHA512(mac_key, ciphertext || LE32(page_number))

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib
  python 20_decrypt.py --key <64hex> [--db-dir <dir>] [--out <dir>]
                                          [--only message\\message_0.db] [--verify-only]
"""
import argparse
import hashlib
import hmac as hmac_mod
import os
import struct
import sys
import time

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE, "snapshot", "db_storage")
OUT_DIR = os.path.join(BASE, "decrypted")
PAGESZ = 4096
RESERVED = 80
SALT = 16
KEY_DERIVE_ITER = 256000


def derive(raw_key, salt):
    enc = hashlib.pbkdf2_hmac("sha512", raw_key, salt, KEY_DERIVE_ITER, 32)
    mac = hashlib.pbkdf2_hmac("sha512", raw_key, bytes(b ^ 0x3A for b in salt), 2, 32)
    return enc, mac


def page_tag(mac_key, data, pgno):
    h = hmac_mod.new(mac_key, data, hashlib.sha512)
    h.update(struct.pack("<I", pgno))
    return h.digest()


def decrypt_db(path, raw_key, out_path, verify_only=False, do_verify=True):
    """返回 (页数, 是否全部校验通过, 失败页号列表)"""
    try:
        from Crypto.Cipher import AES
    except ImportError as e:                                        # noqa: BLE001
        raise SystemExit("需要 pycryptodome（PYTHONPATH 指向 %s\\lib）: %s" % (BASE, e))

    size = os.path.getsize(path)
    npages = (size + PAGESZ - 1) // PAGESZ
    with open(path, "rb") as f:
        first = f.read(PAGESZ)
    if first[:15] == b"SQLite format 3":
        if not verify_only:
            with open(path, "rb") as src, open(out_path, "wb") as dst:
                dst.write(src.read())
        return npages, True, [], True
    salt = first[:SALT]
    enc_key, mac_key = derive(raw_key, salt)

    bad = []
    out = None if verify_only else open(out_path, "wb")
    try:
        with open(path, "rb") as f:
            for pgno in range(1, npages + 1):
                page = f.read(PAGESZ)
                if len(page) < PAGESZ:
                    break
                if pgno == 1:
                    ct, tag = page[SALT:PAGESZ - 64], page[PAGESZ - 64:]
                    payload_len = PAGESZ - RESERVED - SALT
                else:
                    ct = page[:PAGESZ - RESERVED]
                    tag = page[PAGESZ - RESERVED:PAGESZ - RESERVED + 64]
                    payload_len = PAGESZ - RESERVED
                if do_verify and page_tag(mac_key, ct, pgno) != tag:
                    bad.append(pgno)
                if out is not None:
                    iv = ct[:16]
                    body = ct[16:]
                    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(body)
                    out.write(dec[:payload_len - 16])
    finally:
        if out is not None:
            out.close()
    return npages, len(bad) == 0, bad[:20], False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--db-dir", default=DB_DIR)
    ap.add_argument("--out", default=OUT_DIR)
    ap.add_argument("--only", default="")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--no-verify", action="store_true", help="跳过每页 HMAC 校验，仅解密")
    args = ap.parse_args()

    raw_key = bytes.fromhex(args.key)
    assert len(raw_key) == 32, "key 必须 32 字节"
    targets = []
    for root, _d, files in os.walk(args.db_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                rel = os.path.relpath(os.path.join(root, f), args.db_dir)
                if args.only and rel != args.only:
                    continue
                if os.path.getsize(os.path.join(root, f)) < PAGESZ:
                    continue
                targets.append(rel)
    targets.sort()
    print("目标 DB %d 个" % len(targets))
    t0 = time.time()
    okn = 0
    for rel in targets:
        src = os.path.join(args.db_dir, rel)
        dst = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            n, ok, bad, plain = decrypt_db(src, raw_key, dst, args.verify_only,
                                           do_verify=not args.no_verify)
        except Exception as e:                                      # noqa: BLE001
            print("FAIL %-40s %s" % (rel, e))
            continue
        flag = "PLAIN" if plain else ("OK  " if ok else "BAD ")
        print("%s %-40s pages=%-6d %s" % (flag, rel, n, ("失败页 %s" % bad) if bad else ""))
        if ok:
            okn += 1
    print("完成 %d/%d  耗时 %.1fs" % (okn, len(targets), time.time() - t0))
    return 0 if okn == len(targets) else 1


if __name__ == "__main__":
    sys.exit(main())
