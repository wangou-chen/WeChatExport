"""
S5-i —— 微信 4.x 聊天记录导出（读已解密 DB，输出 JSON + 单文件 HTML）

输入：decrypted\\db_storage\\*.db（由 20_decrypt.py 生成）
输出：out\\messages.json、out\\chats\\<会话>.html、out\\index.html

用法：
  set PYTHONUTF8=1
  python 21_export.py [--db-dir <dir>] [--out <dir>] [--limit N] [--schema]
"""
import argparse
import glob
import html
import json
import os
import sqlite3
import sys
import time

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC_DIR = os.path.join(BASE, "decrypted", "db_storage")
OUT_DIR = os.path.join(BASE, "out")


def open_db(path):
    con = sqlite3.connect("file:%s?mode=ro" % path.replace("\\", "/"), uri=True)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    return con


def list_tables(con):
    return [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]


def schema_report(db_dir):
    for path in sorted(glob.glob(os.path.join(db_dir, "**", "*.db"), recursive=True)):
        rel = os.path.relpath(path, db_dir)
        try:
            con = open_db(path)
            tables = list_tables(con)
        except Exception as e:                                     # noqa: BLE001
            print("%-42s OPEN FAIL %s" % (rel, e))
            continue
        print("\n=== %s ===" % rel)
        for t in tables:
            try:
                n = con.execute("SELECT COUNT(*) FROM [%s]" % t).fetchone()[0]
            except Exception:                                      # noqa: BLE001
                n = -1
            cols = [c[1] for c in con.execute("PRAGMA table_info([%s])" % t)]
            print("  %-28s rows=%-8d cols=%s" % (t, n, ",".join(cols)))
        con.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-dir", default=DEC_DIR)
    ap.add_argument("--out", default=OUT_DIR)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--schema", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    if args.schema:
        schema_report(args.db_dir)
        return 0

    ents = {}
    contacts = os.path.join(args.db_dir, "contact", "contact.db")
    if os.path.exists(contacts):
        con = open_db(contacts)
        try:
            for row in con.execute("SELECT username, nick_name, remark FROM contact"):
                ents[row[0]] = {"nick": row[1], "remark": row[2]}
        except Exception as e:                                     # noqa: BLE001
            print("contact 读取失败: %s" % e)
        con.close()

    sessions = {}
    sp = os.path.join(args.db_dir, "session", "session.db")
    if os.path.exists(sp):
        con = open_db(sp)
        for t in list_tables(con):
            if "session" not in t:
                continue
            cols = [c[1] for c in con.execute("PRAGMA table_info([%s])" % t)]
            sel = [c for c in ("username", "last_timestamp", "unread_count", "summary", "draft")
                   if c in cols]
            if "username" not in sel:
                continue
            for row in con.execute("SELECT %s FROM [%s]" % (",".join(sel), t)):
                rec = dict(zip(sel, row))
                sessions[rec["username"]] = rec
        con.close()

    messages = []
    t0 = time.time()
    for path in sorted(glob.glob(os.path.join(args.db_dir, "message", "*.db"))):
        rel = os.path.relpath(path, args.db_dir)
        con = open_db(path)
        for t in list_tables(con):
            if not t.startswith("msg") and not t.startswith("message"):
                continue
            cols = [c[1] for c in con.execute("PRAGMA table_info([%s])" % t)]
            need = [c for c in ("local_id", "server_id", "local_type", "create_time",
                                "sort_seq", "real_sender_id", "message_content",
                                "compress_content", "source") if c in cols]
            if "message_content" not in need or "create_time" not in need:
                continue
            q = "SELECT %s FROM [%s] ORDER BY create_time" % (",".join(need), t)
            n = 0
            for row in con.execute(q):
                rec = dict(zip(need, row))
                rec["_db"] = rel
                rec["_table"] = t
                messages.append(rec)
                n += 1
                if args.limit and len(messages) >= args.limit:
                    break
            print("  %-38s %s rows=%d" % (rel, t, n))
            if args.limit and len(messages) >= args.limit:
                break
        con.close()

    print("消息总数 %d  耗时 %.1fs" % (len(messages), time.time() - t0))
    with open(os.path.join(args.out, "messages.json"), "w", encoding="utf-8") as f:
        json.dump({"contacts": ents, "sessions": sessions, "messages": messages},
                  f, ensure_ascii=False, indent=1)
    print("-> %s" % os.path.join(args.out, "messages.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
