"""
S5-r —— 在微信数据目录的小文件里按 stride=1 全偏移测试 32 字节候选（含 MMKV）

动机：内存里既没有 x'<96hex>' 文本、也没有任何 8 字节对齐/任意偏移的原始密钥；
微信 4.1.x 可能把密钥放在本地配置/缓存文件（MMKV、kvdb 等）里。这类文件总大小只有几 MB，
逐个 32 字节窗口用 page-1 HMAC 预言机验证，成本极低。

用法：
  set PYTHONUTF8=1
  python 61_filescan_keys.py --root <db_storage 或数据目录> --db <db>
      [--max-size 4194304] [--stride 1]
"""
import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import time

PAGESZ, SALT, MAC_OFF = 4096, 16, 4032


def target(dbpath):
    with open(dbpath, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    return salt, mac_salt, mac_msg, p1[MAC_OFF:PAGESZ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--max-size", type=int, default=4 * 1024 * 1024)
    ap.add_argument("--stride", type=int, default=1)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    salt, mac_salt, mac_msg, expected = target(args.db)
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512

    files = []
    for root, _d, names in os.walk(args.root):
        for n in names:
            p = os.path.join(root, n)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if 0 < sz <= args.max_size:
                files.append((p, sz))
    files.sort(key=lambda x: x[1])
    total = sum(s for _p, s in files)
    print("候选文件 %d 个，合计 %.1f MB（<= %d B）" % (len(files), total / 1048576, args.max_size))

    t0 = time.time()
    tried = 0
    hit = None
    for i, (p, sz) in enumerate(files, 1):
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            continue
        last = len(data) - 32
        off = 0
        while off <= last:
            cand = data[off:off + 32]
            mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
            if hmac_new(mk, mac_msg, sha512).digest() == expected:
                hit = (cand.hex(), p, off)
                break
            tried += 1
            off += args.stride
        if hit:
            break
        if i % 20 == 0:
            print("  .. %d/%d 文件  tried=%d  %.0fs" % (i, len(files), tried, time.time() - t0),
                  file=sys.stderr, flush=True)

    el = time.time() - t0
    if hit:
        print("FOUND key=%s file=%s off=%d  文件数=%d tried=%d %.0fs"
              % (hit[0], hit[1], hit[2], len(files), tried, el))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump({"db": args.db, "salt": salt.hex(), "enc_key": hit[0],
                           "file": hit[1], "offset": hit[2]}, f, indent=2)
            print("-> %s" % args.out)
    else:
        print("no-hit 文件数=%d tried=%d %.0fs" % (len(files), tried, el))
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
