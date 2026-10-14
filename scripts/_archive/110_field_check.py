"""S5-bb —— 逐字段核对：把「解密后的 page1 头部」与「规范 SQLite 头部」逐字节对比，
并对同一 key 打印 HMAC 校验的每一步，确认密钥正确性与页面解密假设的冲突点。

规范 page1 头部（SQLite）：
  0:16  "SQLite format 3\\0"
  16:18 page_size (BE) = 0x1000
  18    write_version = 1/2
  19    read_version  = 1/2
  20    reserved = 0（SQLCipher 下为 80）
  21    max_payload_frac = 64
  22    min_payload_frac = 32
  23    leaf_payload_frac = 32
  24:28 change_counter
  28:32 page_count
用法：
  python 110_field_check.py --db <db> --key <64hex>
"""
import argparse
import hashlib
import hmac as hmac_mod
import struct
import sys

PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
HDR = b"SQLite format 3\x00"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--pages", type=int, default=2)
    args = ap.parse_args()

    from Crypto.Cipher import AES
    raw = bytes.fromhex(args.key)
    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)

    print("=== 步骤 1：page-1 HMAC 复算（确认密钥正确性）===")
    mac_key = hashlib.pbkdf2_hmac("sha512", raw, mac_salt, 2, 32)
    ct = p1[SALT:MAC_OFF]
    tag = p1[MAC_OFF:PAGESZ]
    h = hmac_mod.new(mac_key, ct, hashlib.sha512)
    h.update(struct.pack("<I", 1))
    print("  ct 区间 [16:4032) len=%d" % len(ct))
    print("  mac_key      = %s" % mac_key.hex())
    print("  期望 tag     = %s" % tag.hex()[:32])
    print("  计算 tag     = %s" % h.digest().hex()[:32])
    print("  校验         = %s" % ("通过" if h.digest() == tag else "失败"))

    print("\n=== 步骤 2：enc_key 候选解密 page1，逐字段比对 ===")
    cands = [("raw32", raw[:32])]
    for prf in ("sha512", "sha256"):
        for it in (256000, 64000, 4096, 2):
            cands.append(("%s/%d/salt" % (prf, it),
                          hashlib.pbkdf2_hmac(prf, raw, salt, it, 32)))
            cands.append(("%s/%d/salt^3A" % (prf, it),
                          hashlib.pbkdf2_hmac(prf, raw, mac_salt, it, 32)))

    for name, enc in cands:
        for ivoff in (4016, 4080, 16, 0):
            iv = p1[ivoff:ivoff + 16]
            if len(iv) < 16:
                continue
            for lo, hi in ((16, 4032), (16, 4096)):
                body = p1[lo:hi]
                n = (len(body) // 16) * 16
                d = AES.new(enc, AES.MODE_CBC, iv).decrypt(body[:n])
                if d[:16] != HDR:
                    continue
                ps = int.from_bytes(d[16:18], "big")
                print("  [%s] iv_off=%d ct=[%d:%d)" % (name, ivoff, lo, hi))
                print("    前 32B: %s" % d[:32].hex())
                print("    page_size=%d  wv=%d rv=%d res=%d maxf=%d minf=%d leaff=%d"
                      % (ps, d[18], d[19], d[20], d[21], d[22], d[23]))
                if ps == 4096:
                    print("    *** page_size 正确！")
                    return 0
    print("\n  无任何候选满足 page_size=4096")
    return 1


if __name__ == "__main__":
    sys.exit(main())
