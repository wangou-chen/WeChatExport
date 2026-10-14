"""批量解密：定位数据目录 → 收集库与页面 → 扫密钥 → 解密 + WAL 回填。

路径解析优先级（均可移植，无需改代码）：
    命令行 --db-dir  >  环境变量 WXARCHIVE_DB_DIR  >  自动探测（%APPDATA% 配置 / 我的文档）
"""
import json
import os
from typing import Dict, List, Optional, Tuple

from . import crypto, keys

ENV_DB_DIR = "WXARCHIVE_DB_DIR"


def resolve_db_dir(explicit: Optional[str] = None, strict: bool = True) -> Optional[str]:
    """按优先级解析数据目录：显式参数 → 环境变量 → 自动探测。

    规则：
      * 显式参数（命令行）若给出但无效 → 返回 None（由调用方报错），**不回退**，
        避免「参数写错却静默用了别的目录」这种危险行为。
      * 环境变量同理（strict=True 时）。
      * 两者都没给 → 自动探测。
    """
    for label, cand in (("--db-dir", explicit), ("WXARCHIVE_DB_DIR", os.environ.get(ENV_DB_DIR))):
        if cand:
            if os.path.isdir(cand):
                return os.path.abspath(cand)
            if strict:
                return None            # 显式指定但无效：不回退
    return detect_db_dir()


def detect_db_dir() -> Optional[str]:
    """自动定位 db_storage：优先读 %APPDATA%\\Tencent\\xwechat\\config\\*.ini 指定的盘符。"""
    import glob
    appdata = os.environ.get("APPDATA", "")
    cfg_dir = os.path.join(appdata, "Tencent", "xwechat", "config")
    if os.path.isdir(cfg_dir):
        for ini in glob.glob(os.path.join(cfg_dir, "*.ini")):
            try:
                content = None
                for enc in ("utf-8", "gbk"):
                    try:
                        with open(ini, "r", encoding=enc) as f:
                            content = f.read(1024).strip()
                        break
                    except UnicodeDecodeError:
                        continue
                if not content or any(c in content for c in "\n\r\x00"):
                    continue
                if not os.path.isdir(content):
                    continue
                for m in glob.glob(os.path.join(content, "xwechat_files", "*", "db_storage")):
                    if os.path.isdir(m):
                        return m
            except OSError:
                continue
    home = os.path.expanduser("~")
    for m in glob.glob(os.path.join(home, "Documents", "xwechat_files", "*", "db_storage")):
        if os.path.isdir(m):
            return m
    return None


def collect_databases(db_dir: str) -> Dict[str, dict]:
    """{rel_path: {path, salt, page1, page2}}"""
    index: Dict[str, dict] = {}
    for root, _dirs, files in os.walk(db_dir):
        for fn in files:
            if not fn.endswith(".db") or fn.endswith(("-wal", "-shm")):
                continue
            path = os.path.join(root, fn)
            if os.path.getsize(path) < crypto.PAGE_SIZE:
                continue
            with open(path, "rb") as f:
                page1 = f.read(crypto.PAGE_SIZE)
                page2 = f.read(crypto.PAGE_SIZE)
            index[os.path.relpath(path, db_dir)] = {
                "path": path, "salt": page1[:crypto.SALT_SIZE],
                "page1": page1, "page2": page2,
            }
    return index


def decrypt_all(db_dir: str, out_dir: str, keys_json: Optional[str] = None,
                verbose: bool = True, threads: int = 1) -> Tuple[List[str], List[Tuple[str, str]]]:
    """解密全部库，返回 (成功列表, [(失败库, 原因)])。

    keys_json 存在且含全部密钥时可直接复用（避免重复扫内存）。
    """
    index = collect_databases(db_dir)
    if verbose:
        print("发现数据库 %d 个" % len(index))

    key_map: Dict[str, str] = {}
    if keys_json and os.path.exists(keys_json):
        try:
            with open(keys_json, encoding="utf-8") as f:
                raw = json.load(f)
            key_map = {k: (v["enc_key"] if isinstance(v, dict) else v)
                       for k, v in raw.items()}
            if verbose:
                print("从 %s 载入密钥 %d 把" % (keys_json, len(key_map)))
        except Exception as e:                                     # noqa: BLE001
            if verbose:
                print("密钥文件读取失败，将重新扫描：%s" % e)

    missing = [r for r in index if r not in key_map]
    if missing:
        if verbose:
            print("扫描内存取密钥（待找 %d 个库）…" % len(missing))
        sub = {r: index[r] for r in missing}
        got = keys.scan_keys(sub)
        key_map.update(got)
        if verbose:
            print("新取得 %d 把" % len(got))

    if keys_json:
        os.makedirs(os.path.dirname(os.path.abspath(keys_json)), exist_ok=True)
        with open(keys_json, "w", encoding="utf-8") as f:
            json.dump({r: {"enc_key": k, "salt": index[r]["salt"].hex()}
                       for r, k in key_map.items() if r in index},
                      f, indent=2, ensure_ascii=False)

    ok: List[str] = []
    fail: List[Tuple[str, str]] = []
    os.makedirs(out_dir, exist_ok=True)
    for rel, meta in sorted(index.items()):
        key_hex = key_map.get(rel)
        if not key_hex:
            fail.append((rel, "无密钥（该库当前未被微信打开）"))
            continue
        key = bytes.fromhex(key_hex)
        dst = os.path.join(out_dir, rel.replace("\\", "_").replace("/", "_"))
        try:
            npages = crypto.decrypt_db(meta["path"], dst, key)
            wal = meta["path"] + "-wal"
            if os.path.exists(wal):
                crypto.decrypt_wal(wal, dst, key)
            with open(dst, "rb") as f:
                head = f.read(16)
            if head != crypto.SQLITE_HDR:
                fail.append((rel, "输出非合法 SQLite"))
                continue
            ok.append(rel)
            if verbose:
                print("  OK   %-46s %6.1f MB  %d 页"
                      % (rel, os.path.getsize(dst) / 1048576, npages))
        except Exception as e:                                     # noqa: BLE001
            fail.append((rel, str(e)))
    if verbose:
        print("解密成功 %d / %d" % (len(ok), len(index)))
        for rel, why in fail:
            print("  失败 %-44s %s" % (rel, why))
    return ok, fail
