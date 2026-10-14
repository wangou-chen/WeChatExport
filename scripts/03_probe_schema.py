"""
Schema 探针 (S7 前置)

目的：解密后先摸清微信 4.x 的表结构（表名、列名、行数），再据此设计导出 SQL。
不修改任何数据，只读。

用法：
  set PYTHONPATH=<项目根>\\lib
  python <项目根>\\scripts\\03_probe_schema.py
"""
import os
import json
import sqlite3

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC_DIR = os.path.join(BASE, "decrypted")
LOG_DIR = os.path.join(BASE, "logs")

# 关注的目标库（按确认的导出范围）
TARGETS = [
    "message\\message_0.db",
    "message\\message_1.db",
    "message\\message_2.db",
    "message\\message_3.db",
    "contact\\contact.db",
    "sns\\sns.db",
    "session\\session.db",
]


def probe(rel):
    path = os.path.join(DEC_DIR, rel)
    if not os.path.exists(path):
        return {"error": "missing"}
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    out = {"size_mb": round(os.path.getsize(path) / 1024 / 1024, 1), "tables": {}}
    for (name,) in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall():
        cols = [r[1] for r in con.execute(f'PRAGMA table_info("{name}")').fetchall()]
        try:
            n = con.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        except Exception as e:                                # noqa: BLE001
            n = f"ERR {e}"
        out["tables"][name] = {"rows": n, "cols": cols}
    con.close()
    return out


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    result = {}
    for rel in TARGETS:
        info = probe(rel)
        result[rel] = info
        print("=" * 78)
        print(f"{rel}   size={info.get('size_mb')}MB   err={info.get('error', '')}")
        tables = info.get("tables", {})
        print(f"  表数: {len(tables)}")
        # 按行数降序，只看前 25 张表，避免刷屏
        for t, meta in sorted(tables.items(), key=lambda x: (x[1]["rows"] if isinstance(x[1]["rows"], int) else -1), reverse=True)[:25]:
            print(f"  {t:<28} rows={meta['rows']}")
            print(f"      cols: {', '.join(meta['cols'])}")
    out = os.path.join(LOG_DIR, "schema_probe.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\nSchema 报告 -> {out}")


if __name__ == "__main__":
    main()
