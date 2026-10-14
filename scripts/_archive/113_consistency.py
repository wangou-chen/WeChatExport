"""S5-be —— 结构一致性检查：确认 page1 密文区长度是否与「hmac 覆盖范围」一致，
并检查现有解密产物在**任何偏移**上是否出现 SQLite 页类型与 schema 文本。

同时打印：把解密产物按 4096 切开后，统计各页首字节分布（合法 b-tree 页类型应占比很高）。

用法：
  C:\\Python314\\python.exe 113_consistency.py --enc <原始加密db> --dec <解密产物>
"""
import argparse
import collections
import sys

PAGESZ = 4096
BTREE = {0x0D, 0x05, 0x0A, 0x02, 0x00}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enc", required=True)
    ap.add_argument("--dec", required=True)
    args = ap.parse_args()

    with open(args.enc, "rb") as f:
        e = f.read(PAGESZ)
    print("加密库 page1 前 48B: %s" % e[:48].hex())
    print("  salt      = %s" % e[:16].hex())
    print("  密文[16:48]= %s" % e[16:48].hex())
    print("  [4016:4032] (IV 位?) = %s" % e[4016:4032].hex())
    print("  [4032:4096] (tag 位?) = %s" % e[4032:4096].hex()[:64])
    # 尾部 16 字节是否全零（部分实现把 padding 置零）
    print("  末 16B 是否全零: %s" % (e[4080:4096] == b"\x00" * 16))

    with open(args.dec, "rb") as f:
        d = f.read(PAGESZ * 200)
    types = collections.Counter(d[i] for i in range(0, len(d), PAGESZ))
    print("\n解密产物按 4096 切分后，各页首字节分布（前 8）:")
    for b, c in types.most_common(8):
        tag = "b-tree" if b in BTREE else ""
        print("   0x%02x : %d  %s" % (b, c, tag))
    print("\n是否含 'sqlite_master': %s" % (b"sqlite_master" in d))
    print("是否含 'CREATE TABLE': %s" % (b"CREATE TABLE" in d))
    print("是否含 'SQLite format 3': %s" % (b"SQLite format 3" in d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
