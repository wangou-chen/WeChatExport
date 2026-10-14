"""S5-av —— 全变体搜索：固定「已证实正确的 raw key」，找出真实的页加密布局

已知：raw key 对 page1 的 HMAC 在 (PBKDF2-SHA512(raw, salt^0x3A, 2, 32), HMAC-SHA512,
密文=[16:4032), tag=[4032:4096)) 下确认为真 → raw key 与 salt 均正确。

未知：AES 使用的 enc_key 来源与 IV 位置。逐项枚举：
  enc_key 来源:   PBKDF2-SHA512(raw, salt, 256000/64000/4096/2, 32)  | raw 本身
  HMAC 算法:      sha512 / sha256（兼作 enc_key 的 kdf 记录）
  密文区间:       [16:4032) / [16:4080) / [16:4096) / [32:4032)
  IV 位置:        [4016:4032) / [4080:4096) / [16:32) / [0:16)
  密文长度:       截断为 16 的倍数

命中判据：解密结果前 16 字节 == b"SQLite format 3\\x00"

用法：
  C:\\Python314\\python.exe 104_bruteforce_layout.py --db <db> --key <64hex>
"""
import argparse
import hashlib
import sys

PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
SQLITE_HDR = b"SQLite format 3\x00"
CT_RANGES = [(16, 4032), (16, 4080), (16, 4096), (32, 4032), (16, 4016)]
IV_OFFS = [4016, 4080, 16, 0, 4000]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()

    from Crypto.Cipher import AES
    raw = bytes.fromhex(args.key)
    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)

    keys = [("raw", raw)]
    for prf in ("sha512", "sha256"):
        for it in (256000, 64000, 4096, 2):
            try:
                keys.append(("%s/%d/salt" % (prf, it),
                             hashlib.pbkdf2_hmac(prf, raw, salt, it, 32)))
            except Exception:                                      # noqa: BLE001
                pass

    tried = 0
    hits = []
    for kname, enc in keys:
        for lo, hi in CT_RANGES:
            ct_full = p1[lo:hi]
            n = (len(ct_full) // 16) * 16
            ct = ct_full[:n]
            if n < 32:
                continue
            for ivoff in IV_OFFS:
                iv = p1[ivoff:ivoff + 16]
                if len(iv) < 16:
                    continue
                tried += 1
                try:
                    dec = AES.new(enc, AES.MODE_CBC, iv).decrypt(ct)
                except Exception:                                  # noqa: BLE001
                    continue
                if dec[:16] == SQLITE_HDR:
                    hits.append((kname, lo, hi, ivoff))
                    print("*** HIT key=%s ct=[%d:%d) iv=[%d:%d)  头=%r"
                          % (kname, lo, hi, ivoff, ivoff + 16, dec[:24]))
                    # 打印更多明文，确认结构
                    print("    明文前 64B: %s" % dec[:64].hex())
                    print("    明文可读段: %r" % dec[:64])
    print("\n试了 %d 组，命中 %d 组" % (tried, len(hits)))
    if not hits:
        print("仍无命中 → 该库页加密不是「AES-CBC(enc_key, IV) + 明文 salt 头」这一族，"
              "需要反汇编确认（建议改用 wechat-cli 的 decrypt 路径对照，它曾对 4.0 生效）。")
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
