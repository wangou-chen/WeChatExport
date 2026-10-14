"""聊天记录导出：解密库 → 结构化 JSON / Markdown / 会话索引。

要点：
  * 内容解压：WCDB_CT_message_content == 4 → zstd；== 0 → 明文
  * 内容优先 message_content，降级 source（XML 元数据）
  * 发送者经 Name2Id → contact 映射
  * 群聊正文常带 "wxid_xxx:" 前缀，可选剥离
"""
import datetime
import glob
import html
import json
import os
import re
from typing import Dict, List, Optional

from . import sessions as sess

TITLE_RE = re.compile(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", re.DOTALL)
GROUP_PREFIX_RE = re.compile(r"^wxid_[A-Za-z0-9_\-]+:\s*\n?")

MSG_TYPES = {
    1: "文本", 3: "图片", 34: "语音", 37: "好友请求", 42: "名片", 43: "视频",
    47: "表情", 48: "位置", 49: "链接/文件", 50: "语音通话", 10000: "系统",
    10002: "系统", 227633266737: "群接龙", 244813135921: "视频号",
    373662154801: "@所有人",
}


def _zstd_decompress(data: bytes) -> str:
    from ._bootstrap import ensure_dep
    for mod in ("zstandard", "zstd"):
        ensure_dep(mod)
        try:
            m = __import__(mod)
            if mod == "zstandard":
                return m.ZstdDecompressor().decompress(data).decode("utf-8", "replace")
            return m.decompress(data).decode("utf-8", "replace")
        except Exception:                                         # noqa: BLE001
            continue
    return ""


def decompress(data, ct) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if ct == 4:
        return _zstd_decompress(data)
    if ct in (0, None):
        return data.decode("utf-8", "replace")
    return ""


def render(text: str, local_type, strip_group_prefix: bool = True) -> str:
    """把原始内容渲染成人类可读文本。

    对 appmsg/图片/视频等 XML：优先取 <title>；否则按类型给出简洁占位
    （例如 [图片]），避免把原始 XML 倾倒进导出文件。
    """
    if not text:
        return ""
    t = text.strip()
    if not t.startswith("<"):
        return GROUP_PREFIX_RE.sub("", t, count=1) if strip_group_prefix else t
    name = MSG_TYPES.get(local_type, str(local_type))
    m = TITLE_RE.search(t)
    if m:
        title = html.unescape(m.group(1)).strip()
        if title:
            return "[%s] %s" % (name, title)
    # 无 title：按类型给占位，必要时附少量可辨识字段
    extra = ""
    for key in ("img", "videomsg", "appmsg", "emoji", "location", "voicemsg"):
        mm = re.search(r"<%s[^>]*>" % key, t)
        if mm:
            extra = " " + mm.group(0)[:80]
            break
    return "[%s]%s" % (name, extra)


def find_sessions(dec_dir: str, query: str) -> List[dict]:
    """按「显示名 / username / 消息表名 / 表名后缀」解析目标会话。

    query 支持：
      * 完整 username（如 wxid_xxx、12345@chatroom、gh_xxx）
      * 显示名（备注/昵称，支持子串匹配，如 "翔铭"、"pubg"）
      * Msg_xxx 表名，或其 hash 部分
    返回 [{table, username, display}]（可能多个 — 同名群/好友）
    """
    import sqlite3
    md5map = sess.session_md5_map(dec_dir)
    contact_map = sess.contacts(dec_dir)
    q = (query or "").strip().lower()
    if not q:
        return []

    hits: List[dict] = []
    seen = set()
    # 直接命中 username / 显示名
    for h, uname in md5map.items():
        disp = contact_map.get(uname, "")
        cand = (uname.lower(), (disp or "").lower())
        exact = q == cand[0] or q == cand[1]
        sub = q in cand[0] or (cand[1] and q in cand[1]) or q in h
        if exact or sub:
            table = "Msg_" + h
            if table not in seen:
                seen.add(table)
                hits.append({"table": table, "username": uname, "display": disp or uname,
                             "exact": exact})
    # 直接给 Msg_/hash
    if not hits:
        h = q[4:] if q.startswith("msg_") else q
        if len(h) == 32 and all(c in "0123456789abcdef" for c in h):
            uname = md5map.get(h, "")
            hits.append({"table": "Msg_" + h, "username": uname,
                         "display": contact_map.get(uname, uname) or uname, "exact": True})
    hits.sort(key=lambda x: (not x["exact"],))
    return hits


def export_one(dec_dir: str, out_dir: str, query: str, msg_db: str = None,
               limit: int = 0, strip_group_prefix: bool = True,
               verbose: bool = True) -> dict:
    """只导出匹配 query 的会话（单个用户/群）。返回同样的 payload 结构。"""
    targets = find_sessions(dec_dir, query)
    if not targets:
        raise ValueError("未找到匹配会话: %r" % query)
    if verbose:
        print("匹配到 %d 个会话:" % len(targets))
        for t in targets[:10]:
            print("   %-34s %-18s %s" % (t["username"], (t["display"] or "")[:16], t["table"]))

    want_tables = {t["table"] for t in targets}
    md5map = sess.session_md5_map(dec_dir)
    contact_map = sess.contacts(dec_dir)
    os.makedirs(out_dir, exist_ok=True)

    out_sessions = _collect_sessions(
        dec_dir, md5map, contact_map, want_tables=want_tables,
        limit=limit, strip_group_prefix=strip_group_prefix)

    if not out_sessions:
        raise ValueError("匹配到会话但未找到消息表（可能该会话无消息）: %r" % query)

    payload = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "source_dir": dec_dir,
        "query": query,
        "sessions_total": len(out_sessions),
        "messages_total": sum(s["count"] for s in out_sessions),
        "contacts": contact_map,
        "sessions": out_sessions,
    }
    # 文件名：单个会话用显示名，多个用 query
    if len(out_sessions) == 1:
        base = out_sessions[0]["display"] or out_sessions[0]["username"] or out_sessions[0]["sid"]
    else:
        base = query
    base = re.sub(r'[\\/:*?"<>|\s]+', "_", str(base))[:60] or "chat"
    jpath = os.path.join(out_dir, "chat_%s.json" % base)
    mpath = os.path.join(out_dir, "chat_%s.md" % base)
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    with open(mpath, "w", encoding="utf-8") as f:
        f.write("# 聊天记录：%s\n\n" % (out_sessions[0]["display"] or query))
        f.write("- username：`%s`\n- 消息数：%d\n- 导出时间：%s\n\n"
                % (out_sessions[0]["username"], payload["messages_total"],
                   payload["generated_at"]))
        for s in out_sessions:
            if len(out_sessions) > 1:
                f.write("\n## %s（%s）\n\n" % (s["display"], s["username"]))
            for m in s["messages"]:
                ts = m["time"]
                ds = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") \
                    if ts else "-"
                f.write("- `%s` **%s**：%s\n"
                        % (ds, m["sender"], m["text"] or "[%s]" % m["type_name"]))
    if verbose:
        print("-> %s (%.1f MB)" % (jpath, os.path.getsize(jpath) / 1048576), flush=True)
        print("-> %s" % mpath, flush=True)
    return payload


def _collect_sessions(dec_dir: str, md5map: dict, contact_map: dict,
                      want_tables: set = None, limit: int = 0,
                      strip_group_prefix: bool = True,
                      on_db=None) -> List[dict]:
    """收集会话消息，**按 Msg_ 表合并各分片库**、按时间排序、去重。

    微信把同一会话的消息表分片存放在 message_0/1/2/3.db，若逐库遍历会产生
    「同名同 username 的重复会话」（例如同一群出现 71505 与 44087 两条），
    因此必须按表名聚合后再输出。export() 与 export_one() 共用本函数。

    want_tables: 仅收集这些表名（None = 全部 Msg_*）
    limit:       每会话最多保留**最近** N 条（0 = 全部）
    """
    merged: Dict[str, dict] = {}
    seen: Dict[str, set] = {}
    for db in sorted(glob.glob(os.path.join(dec_dir, "message_message_*.db"))):
        if on_db:
            on_db(os.path.basename(db))
        con = sess._open_ro(db)
        try:
            n2i = sess.name2id(db)
            tables = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
            for t in tables:
                if want_tables is not None and t not in want_tables:
                    continue
                try:
                    total = con.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
                except Exception:                                 # noqa: BLE001
                    continue
                if total == 0:
                    continue
                cols = [c[1] for c in con.execute('PRAGMA table_info("%s")' % t)]
                sel = [c for c in ("local_id", "local_type", "create_time", "real_sender_id",
                                   "message_content", "WCDB_CT_message_content",
                                   "source", "WCDB_CT_source") if c in cols]
                if "create_time" not in sel:
                    continue
                sid = t[4:]
                uname = md5map.get(sid, "")
                slot = merged.setdefault(t, {
                    "table": t, "sid": sid, "username": uname,
                    "display": contact_map.get(uname, uname) or uname,
                    "count": 0, "messages": [], "shards": [],
                })
                slot["shards"].append(os.path.basename(db))
                slot["count"] += total
                keys = seen.setdefault(t, set())
                for r in con.execute('SELECT %s FROM "%s" ORDER BY create_time'
                                     % (",".join(sel), t)):
                    rec = dict(zip(sel, r))
                    text = decompress(rec.get("message_content"),
                                      rec.get("WCDB_CT_message_content"))
                    if not text:
                        text = decompress(rec.get("source"), rec.get("WCDB_CT_source"))
                    lt = rec.get("local_type")
                    sender = n2i.get(rec.get("real_sender_id"), "")
                    ts = rec.get("create_time") or 0
                    sender_name = (contact_map.get(sender, sender)
                                   or str(rec.get("real_sender_id")))
                    rendered = render(text, lt)
                    if strip_group_prefix and rendered and not rendered.startswith("["):
                        rendered = GROUP_PREFIX_RE.sub("", rendered, count=1)
                    dk = (ts, sender_name, rendered, lt)
                    if dk in keys:                 # 分片间的重复消息
                        continue
                    keys.add(dk)
                    slot["messages"].append({
                        "time": ts,
                        "type": lt,
                        "type_name": MSG_TYPES.get(lt, str(lt)),
                        "sender_id": sender or rec.get("real_sender_id"),
                        "sender": sender_name,
                        "text": rendered,
                    })
        finally:
            con.close()

    out = []
    for slot in merged.values():
        slot["messages"].sort(key=lambda m: m["time"])
        if limit:
            slot["messages"] = slot["messages"][-limit:]      # 保留最近 N 条
        slot["exported"] = len(slot["messages"])
        out.append(slot)
    out.sort(key=lambda s: -s["count"])
    return out


def export(dec_dir: str, out_dir: str, limit: int = 0, strip_group_prefix: bool = True,
           verbose: bool = True) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    md5map = sess.session_md5_map(dec_dir)
    contact_map = sess.contacts(dec_dir)
    if verbose:
        print("会话名映射 %d 个，联系人 %d 个" % (len(md5map), len(contact_map)), flush=True)

    all_sessions = _collect_sessions(
        dec_dir, md5map, contact_map, want_tables=None, limit=limit,
        strip_group_prefix=strip_group_prefix,
        on_db=(lambda name: print("== %s ==" % name, flush=True)) if verbose else None)

    payload = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "source_dir": dec_dir,
        "sessions_total": len(all_sessions),
        "messages_total": sum(s["count"] for s in all_sessions),
        "contacts": contact_map,
        "sessions": all_sessions,
    }
    jpath = os.path.join(out_dir, "chats.json")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    if verbose:
        print("-> %s (%.1f MB)" % (jpath, os.path.getsize(jpath) / 1048576), flush=True)

    mpath = os.path.join(out_dir, "chats.md")
    with open(mpath, "w", encoding="utf-8") as f:
        f.write("# 微信聊天记录导出\n\n")
        f.write("- 生成时间：%s\n- 会话 %d 个，消息 %d 条\n\n"
                % (payload["generated_at"], payload["sessions_total"],
                   payload["messages_total"]))
        for s in all_sessions:
            f.write("\n## %s（%s，%d 条）\n\n" % (s["display"] or s["username"] or s["sid"],
                                                  s["username"] or s["sid"], s["count"]))
            for m in s["messages"]:
                ts = m["time"]
                ds = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") \
                    if ts else "-"
                f.write("- `%s` **%s**：%s\n" % (ds, m["sender"], m["text"] or "[%s]" % m["type_name"]))
    if verbose:
        print("-> %s" % mpath, flush=True)

    ipath = os.path.join(out_dir, "INDEX.md")
    with open(ipath, "w", encoding="utf-8") as f:
        f.write("# 会话索引（按消息数降序）\n\n")
        f.write("| 会话 | username | 消息数 |\n|---|---|---|\n")
        for s in all_sessions:
            f.write("| %s | %s | %d |\n" % (s["display"] or "-", s["username"] or s["sid"],
                                            s["count"]))
    if verbose:
        print("-> %s" % ipath, flush=True)
    return payload
