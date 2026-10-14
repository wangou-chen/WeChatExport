"""S5-ar —— 在本地搜索「明文 SQLite 页面 / SQLite 文件头」，寻找绕过密钥的路径

思路：微信的聊天库是加密的，但可能在某些位置留下未加密的 SQLite 数据：
  * 明文 SQLite 文件（文件头 "SQLite format 3\\0"）
  * 未加密的临时/缓存副本（xlog、临时目录、导出中间文件）
  * MMKV / kvdb 里的缓存页面（含 "SQLite format 3" 明文页头）
本脚本只在指定根目录下递归扫描**文件头**与**前 4KB 内是否有明文页头**，不做解密、不写文件。

用法：
  C:\\Python314\\python.exe 98_find_plain_sqlite.py [--roots <a;b;c>] [--max-size 50MB] [--deep]
"""
import argparse
import os
import sys

HDR = b"SQLite format 3\x00"
WAL = b"\x37\x7f\x06\x82"


def scan_file(p, max_size, deep):
    try:
        sz = os.path.getsize(p)
    except OSError:
        return None
    if sz < 16 or sz > max_size:
        return None
    try:
        with open(p, "rb") as f:
            head = f.read(4096)
            if head[:16] == HDR:
                return "SQLITE"
            if head[:4] == WAL:
                return "WAL"
            if not deep:
                return None
            # 深扫：整个文件里找页头（可能被嵌入）
            f.seek(0)
            data = f.read(min(sz, 8 * 1024 * 1024))
        if HDR in data:
            return "EMBEDDED"
    except OSError:
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--roots", default=(
        r"E:\xwechat_files;"
        r"C:\Users\Lenovo\AppData\Roaming\Tencent\xwechat;"
        r"C:\Users\Lenovo\AppData\Local\Tencent"))
    ap.add_argument("--max-size", type=int, default=50 * 1024 * 1024)
    ap.add_argument("--deep", action="store_true", help="在文件内部也找页头")
    ap.add_argument("--skip-db", action="store_true", help="跳过已加密的 *.db（本就知道它们是密文）")
    args = ap.parse_args()

    roots = [x.strip() for x in args.roots.split(";") if x.strip()]
    found = []
    n = 0
    for root in roots:
        if not os.path.isdir(root):
            print("[skip] %s" % root)
            continue
        print("[scan] %s" % root, flush=True)
        for dirpath, dirnames, filenames in os.walk(root):
            # 跳过明显无关的大目录
            dirnames[:] = [d for d in dirnames if d.lower() not in
                           ("xplugin", "log", "cache", "crash", "temp")]
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if args.skip_db and fn.endswith((".db", ".db-wal", ".db-shm")):
                    continue
                n += 1
                kind = scan_file(p, args.max_size, args.deep)
                if kind:
                    sz = os.path.getsize(p)
                    found.append((kind, p, sz))
                    print("  %-8s %10d B  %s" % (kind, sz, p), flush=True)
                if n % 5000 == 0:
                    print("    ..已检查 %d 个文件" % n, flush=True)

    print("\n检查文件 %d 个，命中明文 SQLite/WAL %d 个" % (n, len(found)))
    for kind, p, sz in found:
        print("  %s  %s" % (kind, p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
