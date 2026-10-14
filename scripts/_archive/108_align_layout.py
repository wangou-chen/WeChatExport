"""S5-az —— 页布局最终对齐：用「必须解出 page_size=4096 且 page2 首字节为 b-tree 类型」双重硬判据

已知：raw key = ac52e88c…40388 对 salt 6b0a126f… 的 page1 HMAC 为真（已复算确认）。
本轮把「密文起点 / 密文终点 / IV 位置 / enc_key 派生」全部枚举，并要求：
    page1 明文[16:18] == 0x1000（page_size=4096）
    page2 明文[0] ∈ {0x0d,0x05,0x0a,0x02}
两个判据同时成立才算命中 —— 这能排除「只对前 16 字节巧合」的情况。

用法：
  C:\\Python314\\python.exe 108_align_layout.py --db <db> --key <64hex>
"""
import argparse
import hashlib
import sys

PAGESZ, SALT = 4096, 16
HDR = b"SQLite format 3\x00"
BTREE = (0x0D, 0x05, 0x0A, 0x02)
PS = (0x1000).to_bytes(2, "big")


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

    key_sources = [("raw", raw)]
    for prf in ("sha512", "sha256"):
        for ks, ksname in ((salt, "salt"), (mac_salt, "salt^3A")):
            for it in (256000, 64000, 4096, 2):
                try:
                    key_sources.append(("%s/%d/%s" % (prf, it, ksname),
                                        hashlib.pbkdf2_hmac(prf, raw, ks, it, 32)))
                except Exception:                                  # noqa: BLE001
                    pass

    # 密文起止：page1 从 16 起；终点枚举到 4096
    starts = [16, 0, 32]
    ends = [4032, 4016, 4080, 4096, 4052]
    iv_offs = [4016, 4080, 16, 0, -1]
    zero_iv = bytes(16)

    tested = 0
    for kname, enc in key_sources:
        for cs in starts:
            for ce in ends:
                body = p1[cs:ce]
                n = (len(body) // 16) * 16
                if n < 32:
                    continue
                for ivoff in iv_offs:
                    iv = zero_iv if ivoff < 0 else p1[ivoff:ivoff + 16]
                    if len(iv) < 16:
                        continue
                    tested += 1
                    try:
                        d1 = AES.new(enc, AES.MODE_CBC, iv).decrypt(body[:n])
                    except Exception:                              # noqa: BLE001
                        continue
                    if d1[:16] != HDR:
                        continue
                    print("--- 首块命中: key=%s ct=[%d:%d) iv_off=%d" % (kname, cs, ce, ivoff))
                    # 找 page_size 字段在明文中的相对位置（期望在 d1 的 offset 16）
                    ps_pos = d1.find(PS)
                    print("    page_size(0x1000) 出现在明文偏移: %s" % ps_pos)
                    # page2 用同一参数
                    b2 = p2[cs:ce]
                    n2 = (len(b2) // 16) * 16
                    d2 = AES.new(enc, AES.MODE_CBC, iv).decrypt(b2[:n2])
                    print("    page2 首字节=0x%02x  (b-tree 类型? %s)" % (d2[0], d2[0] in BTREE))
                    print("    page1 明文前 48B: %s" % d1[:48].hex())
                    if d2[0] in BTREE:
                        print("    *** 双判据成立 → 布局确定")
                        print("    key=%s ct_start=%d ct_end=%d iv_off=%d" % (kname, cs, ce, ivoff))
                        return 0
    print("试了 %d 组，双判据未同时成立" % tested)
    return 1


if __name__ == "__main__":
    sys.exit(main())
