"""读取微信 key_info.db（未加密 SQLite）全部表与内容，寻找数据库密钥或其加密封装。

用法：
  python 96_read_keyinfo.py [--db <path>] [--full]
"""
import argparse
import os
import sqlite3
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=r"<数据盘>\xwechat_files\all_users\login\<你的wxid>\key_info.db")
    ap.add_argument("--full", action="store_true", help="打印全部行（默认每表前 20 行）")
    args = ap.parse_args()

    p = args.db.replace("\\", "/")
    con = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    tabs = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    print("文件: %s" % args.db)
    print("表 (%d): %s" % (len(tabs), tabs))
    limit = 100000 if args.full else 20
    for t in tabs:
        cols = [c[1] for c in con.execute("PRAGMA table_info([%s])" % t)]
        n = con.execute("SELECT COUNT(*) FROM [%s]" % t).fetchone()[0]
        print("\n=== %s  rows=%d ===" % (t, n))
        print("    cols: %s" % cols)
        try:
            for i, row in enumerate(con.execute("SELECT * FROM [%s] LIMIT %d" % (t, limit))):
                vals = []
                for c, v in zip(cols, row):
                    if isinstance(v, (bytes, bytearray)):
                        vals.append("%s=%s(%dB)" % (c, bytes(v).hex(), len(v)))
                    else:
                        s = str(v)
                        vals.append("%s=%s" % (c, s if len(s) <= 80 else s[:80] + "..."))
                print("    [%d] %s" % (i, "  ".join(vals)))
        except Exception as e:                                     # noqa: BLE001
            print("    读取失败: %s" % e)
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
