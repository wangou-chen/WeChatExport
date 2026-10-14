"""S5-ax —— 解密主库 + 解密 WAL 帧并回填（对齐 wechat-cli 的做法）

wechat-cli 的 crypto.py 关键点：
  * decrypt_page(enc_key, page, pgno)：
        page1: iv = page[4016:4032], ct = page[16:4032]  → 输出 SQLITE_HDR + 明文 + 80B 零
        pageN: iv = page[4016:4032], ct = page[0:4016]   → 输出明文 + 80B 零
  * decrypt_wal(wal, decrypted_db, enc_key)：
        WAL 头 32B；每帧 = 24B 帧头 + 4096B 页
        帧头: pgno(0:4 BE), salt1(8:12), salt2(12:16)
        只回填 salt 匹配的帧，seek((pgno-1)*4096) 写入

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib
  python 106_decrypt_with_wal.py --key <64hex> --db <src.db> --out <dst.db>
"""
import argparse
import hashlib
import os
import struct
import sys

PAGESZ, KEY_SZ, SALT_SZ, RESERVE_SZ = 4096, 32, 16, 80
SQLITE_HDR = b"SQLite format 3\x00"
WAL_HEADER_SZ, WAL_FRAME_HEADER_SZ = 32, 24


def kdf(raw_key, salt, iterations, prf="sha512", dklen=KEY_SZ):
    return hashlib.pbkdf2_hmac(prf, raw_key, salt, iterations, dklen)


def decrypt_page(enc_key, page, pgno):
    from Crypto.Cipher import AES
    iv = page[PAGESZ - RESERVE_SZ: PAGESZ - RESERVE_SZ + 16]
    if pgno == 1:
        ct = page[SALT_SZ:PAGESZ - RESERVE_SZ]
        dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(ct)
        return SQLITE_HDR + dec + b"\x00" * RESERVE_SZ
    ct = page[:PAGESZ - RESERVE_SZ]
    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(ct)
    return dec + b"\x00" * RESERVE_SZ


def full_decrypt(db_path, out_path, key):
    size = os.path.getsize(db_path)
    npages = size // PAGESZ
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        first = fin.read(PAGESZ)
        salt = first[:SALT_SZ]
        enc_key = kdf(key, salt, 256000)
        fout.write(decrypt_page(enc_key, first, 1))
        for pgno in range(2, npages + 1):
            page = fin.read(PAGESZ)
            if len(page) < PAGESZ:
                break
            fout.write(decrypt_page(enc_key, page, pgno))
    return npages, enc_key, salt


def decrypt_wal(wal_path, db_out, enc_key):
    if not os.path.exists(wal_path):
        return 0
    wsize = os.path.getsize(wal_path)
    if wsize <= WAL_HEADER_SZ:
        return 0
    patched = 0
    with open(wal_path, "rb") as wf, open(db_out, "r+b") as df:
        hdr = wf.read(WAL_HEADER_SZ)
        ws1 = struct.unpack(">I", hdr[16:20])[0]
        ws2 = struct.unpack(">I", hdr[20:24])[0]
        frame = WAL_FRAME_HEADER_SZ + PAGESZ
        while wf.tell() + frame <= wsize:
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            if len(fh) < WAL_FRAME_HEADER_SZ:
                break
            pgno = struct.unpack(">I", fh[0:4])[0]
            s1 = struct.unpack(">I", fh[8:12])[0]
            s2 = struct.unpack(">I", fh[12:16])[0]
            ep = wf.read(PAGESZ)
            if len(ep) < PAGESZ:
                break
            if pgno == 0 or pgno > 1000000:
                continue
            if s1 != ws1 or s2 != ws2:
                continue
            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGESZ)
            df.write(dec)
            patched += 1
    return patched


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--prf", default="sha512")
    ap.add_argument("--iter", type=int, default=256000)
    ap.add_argument("--no-wal", action="store_true")
    args = ap.parse_args()

    key = bytes.fromhex(args.key)
    print("key=%s" % key.hex())
    npages, enc_key, salt = full_decrypt(args.db, args.out, key)
    print("主库解密: pages=%d salt=%s" % (npages, salt.hex()))
    if not args.no_wal:
        wal = args.db + "-wal"
        n = decrypt_wal(wal, args.out, enc_key)
        print("WAL 回填帧数=%d (%s)" % (n, wal))
    with open(args.out, "rb") as f:
        head = f.read(16)
    print("输出头 16B: %r  -> %s" % (head, "SQLite OK" if head == SQLITE_HDR else "不是 SQLite"))
    return 0 if head == SQLITE_HDR else 1


if __name__ == "__main__":
    sys.exit(main())
