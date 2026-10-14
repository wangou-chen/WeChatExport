"""S5-w —— 探针：搞清楚微信到底由谁拉起、命令行是什么

实测背景：
  * 启动器 Weixin.exe 里 hook kernel32!CreateProcessW 后，子进程通知始终没有出现，
    但微信确实被拉起了（18:11:38 起一套新进程树）——说明进程创建走的是别的路径
    （如 ntdll!NtCreateUserProcess / CreateProcessInternalW / 调试器方式）。
  * 需要知道「真正的微信主进程」的命令行参数，才能自己用 CREATE_SUSPENDED 拉起它并挂 hook。

本脚本（只读）：
  1. 列出所有 Weixin.exe / WeChatAppEx.exe 的 PID 与内存；
  2. 对每个 Weixin.exe 进程，读 PEB 里的 CommandLine 与 ImagePathName；
  3. 统计每个进程内 Weixin.dll 的 committed 字节数（判断谁是主进程）；
  4. 输出 JSON 供下一步使用。

用法：
  python 74_probe_procs.py [--out <json>]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import subprocess
import sys

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
PQI, PVR = 0x0400, 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PROCESS_BASIC_INFORMATION = 0


class UNICODE_STRING64(ctypes.Structure):
    _fields_ = [("Length", wt.USHORT), ("MaximumLength", wt.USHORT),
                ("_pad", wt.DWORD), ("Buffer", ctypes.c_uint64)]


class PBI64(ctypes.Structure):
    _fields_ = [("Reserved1", ctypes.c_uint64), ("PebBaseAddress", ctypes.c_uint64),
                ("Reserved2_0", ctypes.c_uint64), ("Reserved2_1", ctypes.c_uint64),
                ("UniqueProcessId", ctypes.c_uint64), ("Reserved3", ctypes.c_uint64)]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def read(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def cmdline_of(h):
    pbi = PBI64()
    rl = ctypes.c_ulong(0)
    st = ntdll.NtQueryInformationProcess(h, PROCESS_BASIC_INFORMATION, ctypes.byref(pbi),
                                         ctypes.sizeof(pbi), ctypes.byref(rl))
    if st != 0 or not pbi.PebBaseAddress:
        return {"err": "NtQueryInformationProcess 0x%X" % (st & 0xFFFFFFFF)}
    # PEB->ProcessParameters(OFF 0x20) -> CommandLine(0x70) / ImagePathName(0x60)
    offs = {"ImagePathName": 0x60, "CommandLine": 0x70}
    res = {"peb": "0x%X" % pbi.PebBaseAddress}
    for name, off in offs.items():
        pp = read(h, pbi.PebBaseAddress + 0x20, 8)
        if not pp:
            res[name] = "PEB 读取失败"
            continue
        ppa = struct.unpack("<Q", pp)[0]
        us = read(h, ppa + off, 16)
        if not us:
            res[name] = "US 读取失败"
            continue
        length, maxlen, _pad, bufptr = struct.unpack("<HHIQ", us)
        if length == 0 or bufptr == 0:
            res[name] = ""
            continue
        raw = read(h, bufptr, length)
        res[name] = raw.decode("utf-16-le", "replace") if raw else "字符串读取失败"
    return res


def dll_bytes(h, needle="Weixin.dll"):
    total = 0
    addr, mbi = 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                and (mbi.Protect & PAGE_NOACCESS) == 0 and mbi.Type == 0x1000000):
            head = read(h, mbi.BaseAddress, 0x1000)
            if head and head[:2] == b"MZ":
                # 读导入/节名太麻烦，这里用「.text 段里是否含 Weixin.dll 特征」近似：
                # 直接按映像大小累加，主进程映像最大
                total = max(total, mbi.RegionSize)
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return total


def procs():
    out = []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin,WeChatAppEx -ErrorAction SilentlyContinue |"
                            "ForEach-Object { \"$($_.Id),$($_.ProcessName),$([int]($_.WorkingSet64/1MB))\" }"],
                           capture_output=True, text=True, timeout=30)
        for line in (r.stdout or "").splitlines():
            a = line.strip().split(",")
            if len(a) == 3 and a[0].isdigit():
                out.append((int(a[0]), a[1], int(a[2])))
    except Exception:                                              # noqa: BLE001
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=r"<项目根>\logs\proc_probe.json")
    args = ap.parse_args()
    res = []
    for pid, name, mb in sorted(procs(), key=lambda x: -x[2]):
        h = kernel32.OpenProcess(PQI | PVR, False, pid)
        if not h:
            res.append({"pid": pid, "name": name, "mb": mb, "err": "OpenProcess"})
            continue
        info = cmdline_of(h)
        big = dll_bytes(h)
        kernel32.CloseHandle(h)
        rec = {"pid": pid, "name": name, "mb": mb, "largest_image": big}
        rec.update(info)
        res.append(rec)
        print("pid=%-6d %-14s MB=%-5d largest_image=%-10d" % (pid, name, mb, big))
        if "CommandLine" in rec:
            print("        cmd: %s" % (rec["CommandLine"] or "")[:200])
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    print("-> %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
