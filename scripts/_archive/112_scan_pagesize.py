"""S5-bd —— 页大小扫描：SQLCipher 页大小可为 1024/2048/4096/8192/16384/65536。

此前所有尝试都假设 page_size=4096（依据是库文件大小 4096 对齐 + 公开工具描述）。
若实际页大小不同，则 salt/密文/IV/HMAC 的偏移全部错位 → 必然全不中。
本脚本对每种页大小，用已证实正确的 raw key 尝试多种 enc_key 派生，
判据仍旧是 page1 明文 [16:18] == 该页大小（BE）。

用法：
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib
  C:\\Python314\\python.exe 112_scan_pagesize.py --db <db> --key <64hex>
"""
import argparse
import hashlib
import sys

HDR = b"SQLite format 3\x00"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()

    from Crypto.Cipher import AES
    raw = bytes.fromhex(args.key)
    with open(args.db, "rb") as f:
        blob = f.read(256 * 1024)          # 足够覆盖各种页大小的前几页

    results = []
    for ps in (4096, 8192, 16384, 65536, 2048, 1024):
        p1 = blob[:ps]
        salt = p1[:16]
        mac_salt = bytes(b ^ 0x3A for b in salt)
        cands = [("raw32", raw[:32])]
        for prf in ("sha512", "sha256"):
            for it in (256000, 64000, 4096, 2):
                try:
                    cands.append(("%s/%d/salt" % (prf, it),
                                  hashlib.pbkdf2_hmac(prf, raw, salt, it, 32)))
                    cands.append(("%s/%d/s3a" % (prf, it),
                                  hashlib.pbkdf2_hmac(prf, raw, mac_salt, it, 32)))
                except Exception:                                  # noqa: BLE001
                    pass
        for name, enc in cands:
            # 变体 1：reserved=80（IV 在 ps-80 处，密文 [16:ps-80)）
            # 变体 2：reserved=48
            # 变体 3：IV 在密文头部，密文 [16:ps)
            for res in (80, 48, 32, 16, 0):
                hi = ps - res
                body = p1[16:hi]
                n = (len(body) // 16) * 16
                if n < 32:
                    continue
                ivs = {"tail": p1[hi - 16:hi] if res >= 16 else b"\x00" * 16,
                       "head": p1[16:32],
                       "zero": b"\x00" * 16}
                for ivn, iv in ivs.items():
                    if len(iv) < 16:
                        continue
                    try:
                        d = AES.new(enc, AES.MODE_CBC, iv).decrypt(body[:n])
                    except Exception:                              # noqa: BLE001
                        continue
                    if d[:16] == HDR:
                        got_ps = int.from_bytes(d[16:18], "big")
                        results.append((ps, res, name, ivn, got_ps, d[:32].hex()))
                        if got_ps == ps:
                            print("*** 完全命中 page_size=%d reserved=%d key=%s iv=%s"
                                  % (ps, res, name, ivn))
                            print("    明文前 64B: %s" % d[:64].hex())
                            print("    可读: %r" % d[:96])
                            return 0
    if results:
        print("出现 \"SQLite format 3\" 但 page_size 字段不符的组合：")
        for r in results[:20]:
            print("  页大小假设=%d reserved=%d key=%s iv=%s → 明文page_size=%d"
                  % (r[0], r[1], r[2], r[3], r[4]))
    else:
        print("任何页大小/布局组合下都解不出 SQLite 头")
    return 1


if __name__ == "__main__":
    sys.exit(main())
