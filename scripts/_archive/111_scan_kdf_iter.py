"""S5-bc —— KDF 迭代次数扫描（硬判据 page_size 必须 = 4096）

密钥已由 page-1 HMAC 确认为真（mac_key = PBKDF2-SHA512(raw, salt^0x3A, 2, 32) 命中）。
本脚本固定 mac 侧已证实的参数，只扫 enc 侧 KDF 参数：
    prf  ∈ {sha512, sha256}
    iter ∈ 1..300000 中的关键区间 + 若干常见值
    派生盐 ∈ {salt, salt^0x3A}
    AES 密钥取派生值前 32 字节
    IV = page[4016:4032)，密文 = page[16:4032)
判据：page1 明文[16:18] == 0x1000

用法：
  set PYTHONPATH=<项目根>\\lib
  python 111_scan_kdf_iter.py --db <db> --key <64hex> [--max-iter 400000]
"""
import argparse
import hashlib
import sys
import time

PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
HDR = b"SQLite format 3\x00"
PS = (4096).to_bytes(2, "big")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--max-iter", type=int, default=300000)
    ap.add_argument("--step", type=int, default=1)
    args = ap.parse_args()

    from Crypto.Cipher import AES
    raw = bytes.fromhex(args.key)
    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    ct = p1[SALT:MAC_OFF]
    iv = p1[4016:4032]

    common = [1, 2, 4, 16, 256, 1000, 1024, 2048, 4000, 4096, 8192, 10000, 16384,
              32000, 32768, 40000, 50000, 64000, 65536, 80000, 100000, 128000,
              131072, 150000, 200000, 250000, 256000]
    iters = sorted(set(list(range(1, min(args.max_iter, 2000) + 1, args.step)) + common))
    iters = [i for i in iters if i <= args.max_iter]

    t0 = time.time()
    tried = 0
    for prf in ("sha512", "sha256"):
        for ks, ksn in ((salt, "salt"), (mac_salt, "s3a")):
            for it in iters:
                tried += 1
                try:
                    enc = hashlib.pbkdf2_hmac(prf, raw, ks, it, 32)
                except Exception:                                  # noqa: BLE001
                    continue
                d = AES.new(enc, AES.MODE_CBC, iv).decrypt(ct)
                if d[:16] == HDR and d[16:18] == PS:
                    print("*** 命中 prf=%s iter=%d salt=%s" % (prf, it, ksn))
                    print("    明文前 64B: %s" % d[:64].hex())
                    print("    可读: %r" % d[:96])
                    return 0
                if tried % 2000 == 0:
                    print("   .. 试了 %d 组 (%.0fs)" % (tried, time.time() - t0), flush=True)
    print("试了 %d 组，未命中（%.0fs）" % (tried, time.time() - t0))
    return 1


if __name__ == "__main__":
    sys.exit(main())
