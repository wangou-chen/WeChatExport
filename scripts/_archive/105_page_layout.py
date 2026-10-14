"""S5-aw —— 用 page1 + page2 双判据搜索页加密布局

判据：
  page1 明文头必须是 b"SQLite format 3\\x00"
  page2 明文字节0 必须是 b-tree 页类型之一：0x0d / 0x05 / 0x0a / 0x02 / 0x0d
同时枚举：
  enc_key 来源: raw / PBKDF2-SHA512(raw, salt, it) for it in (256000,64000,4096,2)
                PBKDF2-SHA512(raw, salt^0x3A, it)  同上
                PBKDF2-SHA256(raw, salt, 64000)
  IV 位置:      [4016:4032) / [4080:4096) / [16:32) / [0:16) / 零
  密文起点:     16（page1 去盐） / 0
  密文终点:     4032 / 4016 / 4080 / 4096
用法：
  C:\\Python314\\python.exe 105_page_layout.py --db <db> --key <64hex>
"""
import argparse
import hashlib
import sys

PAGESZ, SALT = 4096, 16
HDR = b"SQLite format 3\x00"
BTREE = (0x0D, 0x05, 0x0A, 0x02, 0x0D)


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

    keys = [("raw", raw)]
    for prf in ("sha512", "sha256"):
        for ks, ksname in ((salt, "salt"), (mac_salt, "salt^3A")):
            for it in (256000, 64000, 4096, 2):
                try:
                    keys.append(("%s/%d/%s" % (prf, it, ksname),
                                 hashlib.pbkdf2_hmac(prf, raw, ks, it, 32)))
                except Exception:                                  # noqa: BLE001
                    pass

    iv_offs = [4016, 4080, 16, 0]
    ct_starts = [16, 0]
    ct_ends = [4032, 4016, 4080, 4096]
    zero_iv = bytes(16)

    tested = 0
    hits = []
    for kname, enc in keys:
        for cs in ct_starts:
            for ce in ct_ends:
                body = p1[cs:ce]
                n = (len(body) // 16) * 16
                if n < 32:
                    continue
                for ivoff in iv_offs + [-1]:
                    iv = zero_iv if ivoff < 0 else p1[ivoff:ivoff + 16]
                    if len(iv) < 16:
                        continue
                    tested += 1
                    try:
                        d1 = AES.new(enc, AES.MODE_CBC, iv).decrypt(body[:n])
                    except Exception:                              # noqa: BLE001
                        continue
                    if d1[:16] == HDR:
                        # page2 同参数校验
                        b2 = p2[cs:ce]
                        n2 = (len(b2) // 16) * 16
                        iv2 = zero_iv if ivoff < 0 else p2[ivoff:ivoff + 16]
                        d2 = AES.new(enc, AES.MODE_CBC, iv2).decrypt(b2[:n2])
                        ok2 = d2[0] in BTREE
                        hits.append((kname, cs, ce, ivoff, ok2))
                        print("*** HIT key=%s ct=[%d:%d) iv_off=%s page2_ok=%s"
                              % (kname, cs, ce, ivoff, ok2))
                        print("    page1 明文头: %r" % d1[:40])
                        print("    page2 首字节: 0x%02x" % d2[0])
                        if ok2:
                            print("    => 布局确定，可直接全库解密")
                            return 0
    print("试了 %d 组，命中 %d 组" % (tested, len(hits)))
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
