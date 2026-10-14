"""S5-at —— SQLCipher 参数标定：用已知正确的 page-1 HMAC + 已知的 SQLite 页头结构，
反推真实参数（KDF 迭代数、HMAC 算法、KDF PRF、reserved 大小、IV 位置）。

已知事实：
  * raw key = ac52e88c6dc8e2b5913efeb6c9fc6f81cdb9a692039257e8396f6d7479640388
    对该库 page 1 的 HMAC 在 (PBKDF2-SHA512, iter=2, salt^0x3A, HMAC-SHA512, reserved=80) 下通过。
  * 但用 PBKDF2-HMAC-SHA512(iter=256000) 解出的页面是垃圾 → 说明 enc_key 派生参数不对。

本脚本逐项枚举下列组合，找能解出「page 1 = SQLite format 3\\0」的那个：
  KDF PRF:      sha512 / sha256 / sha1
  KDF iter:     256000 / 64000 / 4096 / 2
  HMAC alg:     sha512 / sha256 / sha1
  reserved:     80 / 48 / 32 / 16
  IV 位置:      page[reserved-16 : reserved]（SQLCipher 4）或 page[0:16]（SQLCipher 3）

用法：
  python 101_calibrate_params.py --db <db> --key <64hex>
"""
import argparse
import hashlib
import hmac as hmac_mod
import struct
import sys

PAGESZ = 4096
SQLITE_HDR = b"SQLite format 3\x00"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--pages", type=int, default=3)
    args = ap.parse_args()

    try:
        from Crypto.Cipher import AES
    except ImportError as e:                                       # noqa: BLE001
        raise SystemExit("需要 pycryptodome: %s" % e)

    raw = bytes.fromhex(args.key)
    with open(args.db, "rb") as f:
        page1 = f.read(PAGESZ)
        page2 = f.read(PAGESZ)
    salt = page1[:16]
    print("salt=%s  key=%s" % (salt.hex(), raw.hex()))

    # 先确认 page-1 HMAC 在哪些参数下通过（用于确认 mac 侧参数）
    print("\n=== page-1 HMAC 校验（mac 侧参数）===")
    for hmac_alg in ("sha512", "sha256", "sha1"):
        for prf in ("sha512", "sha256", "sha1"):
            for it in (2,):
                for res in (80, 48, 32, 16):
                    mac_salt = bytes(b ^ 0x3A for b in salt)
                    try:
                        mk = hashlib.pbkdf2_hmac(prf, raw, mac_salt, it, 32)
                    except Exception:                              # noqa: BLE001
                        continue
                    ct = page1[16:PAGESZ - res]
                    tag = page1[PAGESZ - res:PAGESZ - res + 64]
                    h = hmac_mod.new(mk, ct, getattr(hashlib, hmac_alg))
                    h.update(struct.pack("<I", 1))
                    if h.digest() == tag:
                        print("  OK  prf=%s iter=%d hmac=%s reserved=%d" % (prf, it, hmac_alg, res))

    # 枚举 enc_key 派生 + 解密，看 page1 是否解出 SQLite 头
    print("\n=== enc_key 派生 + page1 解密 ===")
    tried = 0
    good = []
    for prf in ("sha512", "sha256", "sha1"):
        for it in (256000, 64000, 4096, 2, 1000):
            for hmac_alg in ("sha512", "sha256", "sha1"):
                for res in (80, 48, 32, 16):
                    for iv_mode in ("tail", "head"):
                        try:
                            enc = hashlib.pbkdf2_hmac(prf, raw, salt, it, 32)
                        except Exception:                          # noqa: BLE001
                            continue
                        tried += 1
                        if iv_mode == "tail":
                            iv = page1[PAGESZ - res:PAGESZ - res + 16]
                        else:
                            iv = page1[0:16]
                        body = page1[16:PAGESZ - res]
                        if len(body) % 16 != 0:
                            continue
                        try:
                            dec = AES.new(enc, AES.MODE_CBC, iv).decrypt(body)
                        except Exception:                          # noqa: BLE001
                            continue
                        if dec[:16] == SQLITE_HDR:
                            good.append((prf, it, hmac_alg, res, iv_mode))
                            print("  *** 命中: prf=%s iter=%d hmac=%s reserved=%d iv=%s"
                                  % (prf, it, hmac_alg, res, iv_mode))
    print("\n试了 %d 种组合，命中 %d 种" % (tried, len(good)))
    if not good:
        print("结论：page1 用任何常规参数都解不出 SQLite 头 → enc_key 不是" \
              "PBKDF2(raw, salt, iter, 32) 这种形式，或盐/HMAC 校验另有含义。")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
