"""S5-au —— 参数标定 v2（修正密文长度）：page1 密文区 = [16 : 4032)，IV = [4016 : 4032)

page-1 HMAC 已在 (PBKDF2-SHA512, iter=2, salt^0x3A, HMAC-SHA512, reserved=80) 下确认为真。
本脚本固定该 mac 侧参数，仅枚举 enc 侧参数与 IV 位置，找能解出 "SQLite format 3\\0" 的组合：
  enc KDF PRF: sha512 / sha256 / sha1
  enc KDF iter: 2 / 4096 / 64000 / 256000 / 1
  enc 派生盐:   salt / salt^0x3A
  IV:           page[4016:4032]（reserved 尾部）或 page[16:32]（密文头部）或 page[4000:4016]
用法：
  C:\\Python314\\python.exe 103_calibrate_v2.py --db <db> --key <64hex>
"""
import argparse
import hashlib
import sys

PAGESZ, SALT, MAC_OFF, RESERVED = 4096, 16, 4032, 80
SQLITE_HDR = b"SQLite format 3\x00"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()

    from Crypto.Cipher import AES
    raw = bytes.fromhex(args.key)
    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
        p2 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    ct = p1[SALT:MAC_OFF]                     # [16:4032) = 4016 B（正确密文区）
    print("salt=%s ct_len=%d" % (salt.hex(), len(ct)))

    ivs = {
        "page[4016:4032]": p1[4016:4032],
        "page[16:32]": p1[16:32],
        "page[4000:4016]": p1[4000:4016],
        "zero": b"\x00" * 16,
    }
    found = []
    tried = 0
    for prf in ("sha512", "sha256", "sha1"):
        for it in (2, 1, 4096, 64000, 256000):
            for dklen in (32, 16):
                for ksalt, ksname in ((salt, "salt"), (mac_salt, "salt^3A")):
                    try:
                        enc = hashlib.pbkdf2_hmac(prf, raw, ksalt, it, dklen)
                    except Exception:                              # noqa: BLE001
                        continue
                    for ivname, iv in ivs.items():
                        tried += 1
                        try:
                            dec = AES.new(enc, AES.MODE_CBC, iv).decrypt(ct)
                        except Exception:                          # noqa: BLE001
                            continue
                        if dec[:16] == SQLITE_HDR:
                            found.append((prf, it, dklen, ksname, ivname))
                            print("*** 命中 prf=%s iter=%d dklen=%d ksalt=%s iv=%s"
                                  % (prf, it, dklen, ksname, ivname))
    print("试了 %d 组，命中 %d 组" % (tried, len(found)))

    if not found:
        # 退化测试：直接把 raw 当 enc_key 试（有些实现用 raw key 直接用）
        for ivname, iv in ivs.items():
            try:
                dec = AES.new(raw[:32], AES.MODE_CBC, iv).decrypt(ct)
            except Exception:                                      # noqa: BLE001
                continue
            if dec[:16] == SQLITE_HDR:
                print("*** 命中：raw key 直接用作 enc_key, iv=%s" % ivname)
                found.append(("raw", 0, 32, "-", ivname))
        if not found:
            print("\n仍未命中。page1 前 32 字节（原样）: %s" % p1[:32].hex())
            print("提示：若 mac 侧确认无误但 enc 侧全不中，说明该库用的是"
                  "'raw key 直接当 AES 密钥 + 独立 IV 表' 之类的变体，需要进一步逆向。")
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
