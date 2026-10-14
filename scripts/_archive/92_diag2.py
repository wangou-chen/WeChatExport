"""
诊断二 (S5-d) —— 定位 4.1.5.30 中密钥的存放形式

前两轮实测结论：
  - `x'<64..192 hex>'` 文本格式：全进程 0 命中（find_all_keys.py 的假设不成立）
  - page-1 HMAC 预言机在 salt 邻域 ±256KB + 单跳指针内 3.6e7 次调用：0 命中
故密钥与 salt 不同处存放，或存储形式改为：
  H1 无 `x'...'` 包裹的裸 hex 串（96/128 hex 字符）
  H2 UTF-16LE 编码的 hex 串
  H3 salt 单独以 hex 文本存放

本脚本一次遍历全部候选进程内存，检测：
  A. 任意 >=64 字符的 ASCII hex 连串，其内含某个 DB 的 salt(32 hex)
  B. UTF-16LE 形式的 hex 串（含 salt）
  C. 裸 ASCII salt hex（32 字符）出现位置与邻域
  D. 路径串 "db_storage" / "message_0.db" 的邻域（用于定位 DB handle / codec 结构）

只读，不修改任何东西。

用法：
  set PYTHONPATH=<项目根>\\lib
  set PYTHONUTF8=1
  python <项目根>\\scripts\\92_diag2.py
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import subprocess
import time

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE, "snapshot", "db_storage")
LOG_DIR = os.path.join(BASE, "logs")

kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
PQI, PVR = 0x0400, 0x0010

HEXRUN = re.compile(rb"[0-9a-fA-F]{64,}")
HEXW = re.compile(rb"(?:[0-9a-fA-F]\x00){32,}")
NEEDLES = [b"db_storage", b"message_0.db", b"contact.db"]
HEXDIGITS = set(b"0123456789abcdefABCDEF")


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def ps(cmd):
    for exe in ("powershell", "pwsh"):
        try:
            r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", cmd],
                               capture_output=True, text=True, timeout=40)
            if r.stdout.strip():
                return r.stdout.strip()
        except Exception:                                     # noqa: BLE001
            continue
    return ""


def enum_regions(h):
    regs, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def read_at(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def load_salts():
    salts = {}
    for root, _d, files in os.walk(DB_DIR):
        for f in files:
            if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                p = os.path.join(root, f)
                if os.path.getsize(p) < 4096:
                    continue
                with open(p, "rb") as fh:
                    salts[os.path.relpath(p, DB_DIR)] = fh.read(16)
    return salts


def hexdump(data, start_off, salt_off):
    lines = []
    for off in range(0, len(data), 16):
        mark = "  <<< salt-hex" if salt_off is not None and off == salt_off else ""
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data[off:off + 16])
        lines.append(f"    {off - start_off:+5d}  {data[off:off+16].hex(' '):<47} {asc}{mark}")
    return lines


def main():
    t0 = time.time()
    salts = load_salts()
    ascii_hex = {s.hex(): r for r, s in salts.items()}
    upper_hex = {s.hex().upper(): r for r, s in salts.items()}
    raw = {r: s for r, s in salts.items()}
    print(f"载入 {len(salts)} 个 salt\n")

    cmd = ("Get-Process Weixin,WeChatAppEx -ErrorAction SilentlyContinue | "
           "Sort-Object WorkingSet64 -Descending | "
           "ForEach-Object { \"$($_.Id),$($_.ProcessName),$([int]($_.WorkingSet64/1MB))\" }")
    procs = []
    for line in ps(cmd).splitlines():
        p = line.strip().split(",")
        if len(p) == 3 and p[0].isdigit():
            procs.append((int(p[0]), p[1], int(p[2])))

    report = {"hexrun_hits": [], "utf16_hits": [], "plainhex_hits": [], "needles": {}}
    for pid, name, mb in procs:
        h = kernel32.OpenProcess(PQI | PVR, False, pid)
        if not h:
            continue
        n_hexrun = n_utf16 = n_plain = 0
        for base, size in enum_regions(h):
            data = read_at(h, base, size)
            if not data:
                continue

            # A. 裸 ASCII hex 连串，内部是否含某 salt 的 32 hex
            for m in HEXRUN.finditer(data):
                n_hexrun += 1
                s = m.group(0)
                low = s.lower()
                hit = None
                for i in range(0, len(low) - 31):
                    if low[i:i + 32].decode() in ascii_hex:
                        hit = (i, low[i:i + 32].decode())
                        break
                if hit and len(report["hexrun_hits"]) < 40:
                    report["hexrun_hits"].append({
                        "pid": pid, "proc": name, "addr": base + m.start(),
                        "run_len": len(s), "salt_hex_off": hit[0],
                        "db": ascii_hex[hit[1]], "text": s[:200].decode("ascii", "replace")})

            # B. UTF-16LE hex 串
            for m in HEXW.finditer(data):
                n_utf16 += 1
                s = m.group(0).decode("utf-16-le", "ignore").lower()
                for i in range(0, max(0, len(s) - 31)):
                    if s[i:i + 32] in ascii_hex and len(report["utf16_hits"]) < 40:
                        report["utf16_hits"].append({
                            "pid": pid, "proc": name, "addr": base + m.start(),
                            "db": ascii_hex[s[i:i + 32]], "salt_off_chars": i})
                        break

            # C. 裸 ASCII salt hex
            for sh, rel in ascii_hex.items():
                j = data.find(sh.encode())
                if j >= 0:
                    n_plain += 1
                    if len(report["plainhex_hits"]) < 40:
                        report["plainhex_hits"].append({
                            "pid": pid, "proc": name, "db": rel,
                            "addr": base + j, "variant": "lower"})
            for sh, rel in upper_hex.items():
                j = data.find(sh.encode())
                if j >= 0:
                    n_plain += 1
                    if len(report["plainhex_hits"]) < 40:
                        report["plainhex_hits"].append({
                            "pid": pid, "proc": name, "db": rel,
                            "addr": base + j, "variant": "upper"})

            # D. 路径串邻域
            for nd in NEEDLES:
                j = data.find(nd)
                if j >= 0:
                    key = nd.decode()
                    if key not in report["needles"]:
                        lo = max(0, j - 256)
                        report["needles"][key] = {
                            "pid": pid, "addr": base + j,
                            "text": data[lo:j + 256].decode("latin-1"),
                            "dump": hexdump(data[lo:j + 256], lo, None)}

        kernel32.CloseHandle(h)
        report.setdefault("per_proc", {})[f"{name}:{pid}"] = {
            "hexrun": n_hexrun, "utf16": n_utf16, "plain_hex": n_plain}
        print(f"[{name} {pid}] hex连串 {n_hexrun}  UTF16hex串 {n_utf16}  裸salt-hex文本 {n_plain}")

    print(f"\n=== A. 裸 hex 连串中含 salt 的命中 ({len(report['hexrun_hits'])}) ===")
    for x in report["hexrun_hits"][:10]:
        print(f"  {x['db']}  pid={x['pid']} addr=0x{x['addr']:X} run={x['run_len']} "
              f"salt@{x['salt_hex_off']}  text={x['text'][:120]}")

    print(f"\n=== B. UTF-16LE 命中 ({len(report['utf16_hits'])}) ===")
    for x in report["utf16_hits"][:10]:
        print(f"  {x['db']}  pid={x['pid']} addr=0x{x['addr']:X} salt_char_off={x['salt_off_chars']}")

    print(f"\n=== C. 裸 ASCII salt hex 文本命中 ({len(report['plainhex_hits'])}) ===")
    for x in report["plainhex_hits"][:20]:
        print(f"  {x['db']:<38} pid={x['pid']} addr=0x{x['addr']:X} [{x['variant']}]")

    print(f"\n=== D. 路径串邻域 ===")
    for k, v in report["needles"].items():
        print(f"\n--- '{k}' @0x{v['addr']:X} pid={v['pid']} ---")
        for line in v["dump"][:24]:
            print(line)

    os.makedirs(LOG_DIR, exist_ok=True)
    out = os.path.join(LOG_DIR, "diag2.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n耗时 {time.time()-t0:.1f}s  报告 -> {out}")


if __name__ == "__main__":
    main()
