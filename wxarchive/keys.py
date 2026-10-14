"""微信数据库密钥提取（Windows，读进程内存）

原理（本机实测）：微信 4.0.x 运行期会在内存中留下 ASCII 文本
    x'<64 hex enc_key><32 hex salt>'
共 98 字符。逐进程、逐内存区域正则匹配即可。

注意：
  * 内存中同一 salt 可能残留**多把历史密钥**，因此拿到候选后必须用
    crypto.check_key()（实际解密 page1/page2）判定，不能只用 HMAC。
  * 4.1.13 及以上版本已无此明文缓存，本模块会自然找不到密钥。
"""
import ctypes
import ctypes.wintypes as wt
import os
import re
import subprocess
from typing import Dict, Iterable, List, Optional, Tuple

from . import crypto

kernel32 = ctypes.windll.kernel32

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

HEX_PATTERN = re.compile(rb"x'([0-9a-fA-F]{96})'")

DEFAULT_PROCESS_NAMES = ("Weixin.exe", "WeChat.exe", "WeChatAppEx.exe")


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def find_processes(names: Iterable[str] = DEFAULT_PROCESS_NAMES) -> List[Tuple[int, str]]:
    """返回 [(pid, name), ...]，按内存占用降序。用 PowerShell 列出（沙箱下 tasklist 可能被拒）。"""
    script = ("Get-Process %s -ErrorAction SilentlyContinue |"
              "Sort-Object WorkingSet64 -Descending |"
              "ForEach-Object { \"$($_.Id),$($_.ProcessName)\" }"
              % ",".join(n[:-4] for n in names))
    out: List[Tuple[int, str]] = []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                           capture_output=True, text=True, timeout=30)
        for line in (r.stdout or "").splitlines():
            parts = line.strip().split(",")
            if len(parts) == 2 and parts[0].isdigit() and (parts[1] + ".exe") in names:
                out.append((int(parts[0]), parts[1]))
    except Exception:                                             # noqa: BLE001
        pass
    return out


def _regions(h) -> List[Tuple[int, int]]:
    regs, addr, mbi = [], 0, MEMORY_BASIC_INFORMATION()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                and (mbi.Protect & PAGE_NOACCESS) == 0
                and 0 < mbi.RegionSize < 700 * 1024 * 1024):
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def iter_key_candidates(pids: Optional[List[Tuple[int, str]]] = None):
    """产出 (pid, proc_name, addr, enc_key_hex, salt_hex)"""
    for pid, name in (pids if pids is not None else find_processes()):
        h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            continue
        try:
            for base, size in _regions(h):
                buf = ctypes.create_string_buffer(size)
                read = ctypes.c_size_t(0)
                if not kernel32.ReadProcessMemory(h, ctypes.c_uint64(base), buf, size,
                                                  ctypes.byref(read)) or read.value != size:
                    continue
                for m in HEX_PATTERN.finditer(buf.raw):
                    s = m.group(1).decode().lower()
                    yield pid, name, base + m.start(), s[:64], s[64:]
        finally:
            kernel32.CloseHandle(h)


def scan_keys(db_index: Dict[str, dict], pids=None, attempts: int = 3) -> Dict[str, str]:
    """扫描内存，返回 {db_rel_path: enc_key_hex}。

    db_index: {rel_path: {"salt": bytes, "page1": bytes, "page2": bytes}}
    判定用 crypto.check_key()（实际解密），而非 HMAC。
    """
    salt2dbs: Dict[str, List[str]] = {}
    for rel, meta in db_index.items():
        salt2dbs.setdefault(meta["salt"].hex(), []).append(rel)

    found: Dict[str, str] = {}
    for _ in range(attempts):
        if len(found) >= len(db_index):
            break
        for _pid, _name, _addr, key_hex, salt_hex in iter_key_candidates(pids):
            for rel in salt2dbs.get(salt_hex, ()):
                if rel in found:
                    continue
                key = bytes.fromhex(key_hex)
                meta = db_index[rel]
                if crypto.check_key(key, meta["page1"], meta.get("page2")):
                    found[rel] = key_hex
        if not found:
            break
    return found
