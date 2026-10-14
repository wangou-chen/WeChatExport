"""wxarchive 命令行入口

常用：
    python -m wxarchive all                       # 一键：定位目录 → 取密钥 → 解密 → 导出
    python -m wxarchive info                      # 只打印环境与数据目录
    python -m wxarchive keys                      # 只取密钥并保存
    python -m wxarchive decrypt                   # 只解密
    python -m wxarchive export                    # 只导出（需已解密）
    python -m wxarchive sessions                  # 列出会话（需已解密）
"""
import argparse
import json
import os
import sys

from . import __version__, crypto, decrypt as dec, export as exp, keys, sessions as sess

DEFAULT_OUT = os.path.join(os.getcwd(), "out")
DEFAULT_WORK = os.path.join(os.getcwd(), "decrypted")


def _paths(args):
    explicit = getattr(args, "db_dir", None)
    db_dir = dec.resolve_db_dir(explicit)
    if not db_dir:
        if explicit:
            print("[错误] --db-dir 指定的目录不存在: %s" % explicit, file=sys.stderr)
        else:
            print("[错误] 未找到微信数据目录。请任选其一：\n"
                  "       1) --db-dir \"<db_storage 路径>\"\n"
                  "       2) 设置环境变量 WXARCHIVE_DB_DIR\n"
                  "       3) 确保微信已登录过（可自动从 %APPDATA%\\Tencent\\xwechat\\config 探测）",
                  file=sys.stderr)
        sys.exit(2)
    # 输出目录：命令行 > 环境变量 > 当前工作目录下的默认名
    work = args.work or os.environ.get("WXARCHIVE_WORK") or DEFAULT_WORK
    out = args.out or os.environ.get("WXARCHIVE_OUT") or DEFAULT_OUT
    keys_json = (args.keys_file or os.environ.get("WXARCHIVE_KEYS")
                 or os.path.join(out, "all_keys.json"))
    return db_dir, work, out, keys_json


def cmd_info(args):
    explicit = getattr(args, "db_dir", None)
    dbs = dec.resolve_db_dir(explicit)
    cfg = dec.load_project_config()
    procs = keys.find_processes()
    print("wxarchive %s" % __version__)
    print("项目根目录: %s" % dec.project_root())
    if cfg:
        print("项目配置: %s（db_dir=%s）" % (cfg.get("_path"), cfg.get("db_dir")))
    else:
        print("项目配置: 无（可用 %s 锁定数据目录，见 README §3）" % dec.CONFIG_NAME)
    print("数据目录: %s" % (dbs or "(未找到)"))
    if explicit:
        print("  ← 来源: --db-dir（显式指定）")
    elif cfg.get("db_dir"):
        print("  ← 来源: 项目配置文件")
    elif os.environ.get(dec.ENV_DB_DIR):
        print("  ← 来源: 环境变量 %s" % dec.ENV_DB_DIR)
    else:
        print("  ← 来源: 自动探测（探测源＝微信自身配置，故与本工具所在目录无关）")
        for label, path in dec.detection_sources():
            print("       %-28s %s" % (label, path))
    print("微信进程: %s" % (procs or "(未运行)"))
    if dbs:
        index = dec.collect_databases(dbs)
        print("数据库: %d 个，合计 %.1f MB"
              % (len(index), sum(os.path.getsize(m["path"]) for m in index.values()) / 1048576))
    try:
        import Crypto                                       # noqa: F401
        print("pycryptodome: OK")
    except ImportError:
        print("pycryptodome: 缺失（必需）")
    for mod in ("zstandard", "zstd"):
        try:
            __import__(mod)
            print("%s: OK" % mod)
            break
        except ImportError:
            continue
    else:
        print("zstandard/zstd: 缺失（压缩消息将无法解压）")
    return 0


def cmd_keys(args):
    db_dir, _work, out, keys_json = _paths(args)
    index = dec.collect_databases(db_dir)
    print("数据库 %d 个，开始扫内存…" % len(index))
    found = keys.scan_keys(index)
    os.makedirs(out, exist_ok=True)
    with open(keys_json, "w", encoding="utf-8") as f:
        json.dump({r: {"enc_key": k, "salt": index[r]["salt"].hex()}
                   for r, k in found.items()}, f, indent=2, ensure_ascii=False)
    print("取得密钥 %d/%d -> %s" % (len(found), len(index), keys_json))
    return 0 if found else 1


def cmd_decrypt(args):
    db_dir, work, _out, keys_json = _paths(args)
    ok, fail = dec.decrypt_all(db_dir, work, keys_json=keys_json, verbose=True)
    return 0 if ok else 1


def cmd_export(self_or_args):
    args = self_or_args
    _db, work, out, _kj = _paths(args)
    if not os.path.isdir(work):
        print("[错误] 未找到解密目录 %s，请先运行 decrypt" % work, file=sys.stderr)
        return 2
    payload = exp.export(work, out, limit=args.limit,
                         strip_group_prefix=not args.keep_group_prefix, verbose=True)
    print("完成：会话 %d，消息 %d" % (payload["sessions_total"], payload["messages_total"]))
    return 0


def cmd_chat(args):
    """按单一用户/群导出聊天记录。

    --chat 支持：显示名（子串，如 "翔铭"）、username（wxid_xxx / 12345@chatroom / gh_xxx）、
                 消息表名或 hash（Msg_xxx / 32 位 hex）。
    """
    _db, work, out, _kj = _paths(args)
    if not os.path.isdir(work):
        print("[错误] 未找到解密目录 %s，请先运行 decrypt" % work, file=sys.stderr)
        return 2
    if args.list:
        rows = sess.session_list(work)
        contacts = sess.contacts(work)
        import hashlib
        print("%-36s %-20s %s" % ("username", "显示名", "消息表"))
        for u, _ts, _un, _s in rows:
            if not u:
                continue
            print("%-36s %-20s Msg_%s" % (u, (contacts.get(u) or "")[:18],
                                          hashlib.md5(u.encode()).hexdigest()))
        return 0
    try:
        payload = exp.export_one(work, out, args.chat, limit=args.limit,
                                 strip_group_prefix=not args.keep_group_prefix,
                                 verbose=True)
    except ValueError as e:
        print("[错误] %s" % e, file=sys.stderr)
        print("提示：用 `python -m wxarchive chat --list` 查看可用的 username / 显示名。",
              file=sys.stderr)
        return 1
    print("完成：%d 个会话，%d 条消息" % (payload["sessions_total"], payload["messages_total"]))
    return 0


def cmd_sessions(args):
    _db, work, _out, _kj = _paths(args)
    rows = sess.session_list(work)
    contacts = sess.contacts(work)
    for u, ts, unread, summary in rows[:args.limit]:
        import datetime
        ds = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"
        print("%-34s %-16s unread=%-4s %s" % (u, ds, unread, (summary or "")[:40]))
    return 0


def cmd_all(args):
    db_dir, work, out, keys_json = _paths(args)
    print("=== 1/3 解密 ===")
    ok, fail = dec.decrypt_all(db_dir, work, keys_json=keys_json, verbose=True)
    if not ok:
        print("[错误] 没有任何库解密成功：微信版本可能不是 4.0.x（4.1.13+ 无内存明文密钥）",
              file=sys.stderr)
        return 1
    print("\n=== 2/3 导出 ===")
    payload = exp.export(work, out, limit=args.limit,
                         strip_group_prefix=not args.keep_group_prefix, verbose=True)
    print("\n=== 3/3 汇总 ===")
    print("会话 %d 个 / 联系人 %d 个 / 消息 %d 条"
          % (payload["sessions_total"], len(payload["contacts"]), payload["messages_total"]))
    print("输出目录: %s" % out)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="wxarchive",
                                description="微信 4.0.x 本地聊天记录导出（自足实现）")
    p.add_argument("--version", action="version", version="wxarchive %s" % __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--db-dir", default=None, help="微信 db_storage 路径（默认自动探测）")
        sp.add_argument("--work", default=None, help="解密输出目录（默认 .\\decrypted）")
        sp.add_argument("--out", default=None, help="导出目录（默认 .\\out）")
        sp.add_argument("--keys-file", default=None, help="密钥 JSON 路径")

    sp = sub.add_parser("info", help="打印环境/版本/数据目录信息")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("keys", help="只提取密钥")
    common(sp)
    sp.set_defaults(func=cmd_keys)

    sp = sub.add_parser("decrypt", help="只解密数据库")
    common(sp)
    sp.set_defaults(func=cmd_decrypt)

    sp = sub.add_parser("export", help="只导出（需已解密）")
    common(sp)
    sp.add_argument("--limit", type=int, default=0, help="每会话最多导出条数（0=全部）")
    sp.add_argument("--keep-group-prefix", action="store_true", help="保留群消息的 wxid_xxx: 前缀")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("sessions", help="列出会话（需已解密）")
    common(sp)
    sp.add_argument("--limit", type=int, default=30)
    sp.set_defaults(func=cmd_sessions)

    sp = sub.add_parser("chat", help="按单一用户/群导出聊天记录（需已解密）")
    common(sp)
    sp.add_argument("--chat", default="", help="显示名 / username / Msg_表名 或其 hash")
    sp.add_argument("--list", action="store_true", help="列出所有可用会话标识后退出")
    sp.add_argument("--limit", type=int, default=0, help="最多导出条数（0=全部）")
    sp.add_argument("--keep-group-prefix", action="store_true")
    sp.set_defaults(func=cmd_chat)

    sp = sub.add_parser("all", help="一键：解密 + 导出")
    common(sp)
    sp.add_argument("--limit", type=int, default=0)
    sp.add_argument("--keep-group-prefix", action="store_true")
    sp.set_defaults(func=cmd_all)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
