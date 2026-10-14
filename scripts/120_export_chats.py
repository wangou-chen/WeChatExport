"""S7 —— 导出聊天记录（解密后 → 结构化 JSON / Markdown）

输入：decrypted\\*.db（由 114_full_pipeline.py 产出，文件名为 目录_库名.db）
输出：out\\chats.json（全量结构化）、out\\chats.md（可读）、out\\INDEX.md（会话清单）

要点（来自 wechat-cli / wechat-extract 的实测经验）：
  * 消息内容：`message_content` 优先，`WCDB_CT_message_content` 指明是否 zstd 压缩（4=zstd）
  * 发送者映射：real_sender_id → 消息库 Name2Id.rowid → user_name → contact.db.contact
    → coalesce(remark, nick_name, username)
  * 群聊表名 = Msg_ + 群 ID 的 MD5（前 32 位）

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib
  python 120_export_chats.py [--dec <dir>] [--out <dir>] [--limit N]
"""
import argparse
import glob
import html
import json
import os
import re
import sqlite3
import sys
import time

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC_DIR = os.path.join(BASE, "decrypted")
OUT_DIR = os.path.join(BASE, "out")
SESSION_NAMES = {}


def open_ro(p):
    con = sqlite3.connect("file:%s?mode=ro" % p.replace("\\", "/"), uri=True)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    return con


def decompress(data, ct):
    """WCDB 压缩字段解压：ct == 4 为 zstd。"""
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if ct == 4:
        try:
            import zstandard as zstd
            return zstd.ZstdDecompressor().decompress(data).decode("utf-8", "replace")
        except Exception:                                          # noqa: BLE001
            try:
                import zstd
                return zstd.decompress(data).decode("utf-8", "replace")
            except Exception:                                      # noqa: BLE001
                return ""
    if ct in (0, None):
        try:
            return data.decode("utf-8", "replace")
        except Exception:                                          # noqa: BLE001
            return ""
    return ""


TITLE_RE = re.compile(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", re.DOTALL)


def render_content(text, local_type):
    """把原始内容渲染成人类可读文本。"""
    if not text:
        return ""
    t = text.strip()
    if t.startswith("<"):
        m = TITLE_RE.search(t)
        if m:
            return "[%s] %s" % (local_type, html.unescape(m.group(1)).strip())
        return "[%s] %s" % (local_type, t[:120])
    return t


def build_session_names(dec_dir):
    """Msg_<md5> -> 会话 username：由 session.db 的 SessionTable 反查（md5(username) 前 32 位）"""
    import hashlib
    out = {}
    p = os.path.join(dec_dir, "session_session.db")
    if not os.path.exists(p):
        cands = glob.glob(os.path.join(dec_dir, "session*.db"))
        p = cands[0] if cands else None
    if not p:
        return out
    try:
        con = open_ro(p)
        for row in con.execute("SELECT username FROM SessionTable"):
            u = row[0]
            if u:
                out[hashlib.md5(u.encode("utf-8")).hexdigest()] = u
        con.close()
    except Exception as e:                                         # noqa: BLE001
        print("  会话名映射失败: %s" % e)
    return out


def build_contacts(dec_dir):
    """username -> 显示名"""
    out = {}
    p = os.path.join(dec_dir, "contact_contact.db")
    if not os.path.exists(p):
        cands = glob.glob(os.path.join(dec_dir, "contact*.db"))
        p = cands[0] if cands else None
    if not p:
        return out
    con = open_ro(p)
    try:
        for row in con.execute("SELECT username, remark, nick_name FROM contact"):
            u, r, n = row[0], row[1], row[2]
            out[u] = (r or n or u)
    except Exception as e:                                         # noqa: BLE001
        print("  联系人读取失败: %s" % e)
    con.close()
    return out


def build_name2id(msg_db):
    """消息库内的 Name2Id: rowid -> user_name（列名是 user_name）"""
    m = {}
    try:
        con = open_ro(msg_db)
        for row in con.execute("SELECT rowid, user_name FROM Name2Id"):
            m[row[0]] = row[1]
        con.close()
    except Exception:                                              # noqa: BLE001
        pass
    return m


def export(msg_db, contacts, args):
    con = open_ro(msg_db)
    tabs = [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
    n2i = build_name2id(msg_db)
    sessions = []
    total = 0
    t0 = time.time()
    for t in tabs:
        try:
            n = con.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
        except Exception:                                          # noqa: BLE001
            continue
        if n == 0:
            continue
        cols = [c[1] for c in con.execute('PRAGMA table_info("%s")' % t)]
        want = [c for c in ("local_id", "local_type", "create_time", "real_sender_id",
                            "message_content", "WCDB_CT_message_content",
                            "source", "WCDB_CT_source") if c in cols]
        if "create_time" not in want:
            continue
        sid = t[4:]
        rows = []
        q = 'SELECT %s FROM "%s" ORDER BY create_time' % (",".join(want), t)
        for r in con.execute(q):
            rec = dict(zip(want, r))
            text = decompress(rec.get("message_content"),
                              rec.get("WCDB_CT_message_content"))
            if not text:
                text = decompress(rec.get("source"), rec.get("WCDB_CT_source"))
            lt = rec.get("local_type")
            sender = n2i.get(rec.get("real_sender_id"), "")
            ts = rec.get("create_time") or 0
            rows.append({
                "t": ts,
                "type": lt,
                "sender": contacts.get(sender, sender or str(rec.get("real_sender_id"))),
                "text": render_content(text, lt),
            })
            if args.limit and len(rows) >= args.limit:
                break
        total += len(rows)
        uname = SESSION_NAMES.get(sid, "")
        sessions.append({"table": t, "sid": sid, "username": uname,
                         "display": contacts.get(uname, uname) or uname,
                         "count": n, "exported": len(rows), "messages": rows})
        print("   %-44s rows=%-7d exported=%d" % (t, n, len(rows)), flush=True)
    con.close()
    print("   小计 %d 条，用时 %.1fs" % (total, time.time() - t0), flush=True)
    return sessions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dec", default=DEC_DIR)
    ap.add_argument("--out", default=OUT_DIR)
    ap.add_argument("--limit", type=int, default=0, help="每个会话最多导出多少条（0=全部）")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    global SESSION_NAMES
    SESSION_NAMES = build_session_names(args.dec)
    print("会话名映射 %d 个" % len(SESSION_NAMES), flush=True)
    contacts = build_contacts(args.dec)
    print("联系人 %d 个" % len(contacts), flush=True)

    all_sessions = []
    for p in sorted(glob.glob(os.path.join(args.dec, "message_message_*.db"))):
        print("\n== %s ==" % os.path.basename(p), flush=True)
        try:
            all_sessions += export(p, contacts, args)
        except Exception as e:                                     # noqa: BLE001
            print("   失败: %s" % e, flush=True)

    all_sessions.sort(key=lambda s: -s["count"])
    jpath = os.path.join(args.out, "chats.json")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump({"contacts": contacts, "sessions": all_sessions}, f,
                  ensure_ascii=False)
    print("\n-> %s (%.1f MB)" % (jpath, os.path.getsize(jpath) / 1048576), flush=True)

    mpath = os.path.join(args.out, "chats.md")
    with open(mpath, "w", encoding="utf-8") as f:
        f.write("# 微信聊天记录导出\n\n")
        f.write("会话数 %d，消息总数 %d\n\n" % (
            len(all_sessions), sum(s["count"] for s in all_sessions)))
        for s in all_sessions:
            f.write("\n## %s（%d 条）\n\n" % (s["table"], s["count"]))
            for m in s["messages"]:
                ts = m["t"]
                import datetime
                ds = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") \
                    if ts else "-"
                f.write("- `%s` **%s**: %s\n" % (ds, m["sender"], m["text"]))
    print("-> %s" % mpath, flush=True)

    ipath = os.path.join(args.out, "INDEX.md")
    with open(ipath, "w", encoding="utf-8") as f:
        f.write("# 会话索引（按消息数降序）\n\n| 会话表 | 消息数 |\n|---|---|\n")
        for s in all_sessions:
            f.write("| %s | %d |\n" % (s["table"], s["count"]))
    print("-> %s" % ipath, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
