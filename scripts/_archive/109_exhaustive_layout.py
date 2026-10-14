"""S5-ba —— 严格按 SQLCipher 语义解密（含 page-size 语义修正）

上一轮观察到的关键现象：
  * page1 明文的**前 16 字节恒为 "SQLite format 3\\0"**（这在任何密钥下都可能因为
    CBC 第一块 = D(C1) xor IV 的巧合而出现，不能作为密钥正确的证据）
  * page_size 字段 = 37523（非法）→ 真正的明文并未得到
  而 page-1 HMAC 校验确实通过（已两次复算）→ raw key 与 salt 正确。

因此问题定位在「enc_key 派生」。本脚本把常见 SQLCipher 变体一次跑全，并要求
**page_size 字段必须等于 4096** 这一硬判据（唯一、不可巧合）：

  KDF:            PBKDF2-HMAC-{SHA512,SHA256,SHA1}
  iter:           256000 / 64000 / 4096 / 2
  派生盐:          salt / salt^0x3A
  输出长度:        32 / 48 / 64（取前 32 用作 AES-256）
  AES 密钥来源:    派生值前 32 字节 / 后 32 字节
  IV:             page[4016:4032] / page[4080:4096] / page[16:32]
  密文:            [16:4032) / [16:4080) / [16:4096) / [0:4016)
  还含：SQLCipher「raw key 直用」模式

用法：
  set PYTHONPATH=<项目根>\\lib
  python 109_exhaustive_layout.py --db <db> --key <64hex>
"""
import argparse
import hashlib
import sys

PAGESZ, SALT = 4096, 16
HDR = b"SQLite format 3\x00"
PS4096 = (4096).to_bytes(2, "big")


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

    cands = []
    # raw key 直用
    cands.append(("raw32", raw[:32]))
    cands.append(("raw32rev", raw[::-1][:32]))
    # 各类 KDF
    for prf in ("sha512", "sha256", "sha1"):
        for ks, ksn in ((salt, "salt"), (mac_salt, "s3a")):
            for it in (256000, 64000, 4096, 2):
                for dk in (32, 48, 64):
                    try:
                        v = hashlib.pbkdf2_hmac(prf, raw, ks, it, dk)
                    except Exception:                              # noqa: BLE001
                        continue
                    tag = "%s/%d/%s/%d" % (prf, it, ksn, dk)
                    cands.append((tag + ":first32", v[:32]))
                    if dk >= 64:
                        cands.append((tag + ":last32", v[-32:]))

    ct_ranges = [(16, 4032), (16, 4080), (16, 4096), (0, 4016), (16, 4016)]
    iv_offs = [4016, 4080, 16, 0]
    zero_iv = bytes(16)

    tested = 0
    for name, enc in cands:
        for lo, hi in ct_ranges:
            body = p1[lo:hi]
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
                except Exception:                                  # noqa: BLE001
                    continue
                # 硬判据：page_size 字段必须为 4096
                if d1[:16] == HDR and d1[16:18] == PS4096:
                    b2 = p2[lo:hi]
                    n2 = (len(b2) // 16) * 16
                    iv2 = zero_iv if ivoff < 0 else p2[ivoff:ivoff + 16]
                    d2 = AES.new(enc, AES.MODE_CBC, iv2).decrypt(b2[:n2])
                    print("*** 命中 key=%s ct=[%d:%d) iv=%s page2[0]=0x%02x"
                          % (name, lo, hi, ivoff, d2[0]))
                    print("    page1 明文[16:32]=%s" % d1[16:32].hex())
                    print("    page1 可读段: %r" % d1[:96])
                    return 0
    print("试了 %d 组，未命中（page_size 硬判据未满足）" % tested)
    print("说明：该库不是常规 SQLCipher 布局。下一步应反汇编 weixin.dll 里"
          "调用 AES 解密的 codec 函数，确认其 derive_key 参数。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
