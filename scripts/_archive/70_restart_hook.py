"""S5-s —— 带 hook 重启微信，在「读 DB 文件」之后立即扫内存定位密钥结构

思路（应对「4.1.x 不把密钥以明文 32 字节缓存在内存里」的实测结论）：
  1. CreateProcessW(CREATE_SUSPENDED) 挂起启动启动器，frida.attach 装 hook，再恢复；
  2. hook kernel32!ReadFile / ReadFileEx / ntdll!NtReadFile，记录被读文件路径；
     一旦发现正在读 *.db，就置一个「时间窗」标志；
  3. 宿主侧在时间窗内对目标进程做指针扫描：
       候选 = 内存中每个 8 字节值 v（且 v 指向可读内存）→ [
                  v 处的 16 字节（salt 命中？），
                  v 处的 32 字节（原始密钥？），
                  v 处的 96 字节 ASCII hex（raw key 文本？）]
     全部用 page-1 HMAC 预言机筛，命中概率 2^-512。
  4. 找到 salt 命中 → 打印其地址与邻域堆，供第二轮取密钥。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python -u 70_restart_hook.py --exe <Weixin.exe> --db <db> [--rounds 3] [--seconds 240]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import subprocess
import sys
import threading
import time

import frida

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(BASE, "logs")
DEFAULT_EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"

kernel32 = ctypes.windll.kernel32
CREATE_SUSPENDED = 0x00000004
PQI, PVR = 0x0400, 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
                ("lpTitle", wt.LPWSTR), ("dwX", wt.DWORD), ("dwY", wt.DWORD),
                ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD),
                ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE),
                ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def create_suspended(exe):
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = kernel32.CreateProcessW(None, exe, None, None, False, CREATE_SUSPENDED, None,
                                 os.path.dirname(exe), ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise SystemExit("CreateProcessW 失败 err=%d" % ctypes.get_last_error())
    return pi


def pids_of(names=("Weixin.exe", "WeChatAppEx.exe")):
    out = []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin,WeChatAppEx -ErrorAction SilentlyContinue |"
                            "ForEach-Object { \"$($_.Id),$($_.ProcessName)\" }"],
                           capture_output=True, text=True, timeout=30)
        for line in (r.stdout or "").splitlines():
            a = line.strip().split(",")
            if len(a) == 2 and a[0].isdigit() and (a[1] + ".exe") in names:
                out.append((int(a[0]), a[1]))
    except Exception:                                              # noqa: BLE001
        pass
    return out


def regions(h, part=(0, 1)):
    regs, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                and (mbi.Protect & PAGE_NOACCESS) == 0 and 0 < mbi.RegionSize < 700 * 1024 * 1024):
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    i, k = part
    return [r for n, r in enumerate(regs) if n % k == i]


def readmem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


HOOK_JS = r"""
const targets = ["ReadFile", "ReadFileEx"];
let hooked = 0;
const dbRe = /\.db$/i;
let lastNotify = 0;
function modOf(name) {
    const cands = ["kernel32.dll", "KERNEL32.DLL", "KernelBase.dll", "kernelbase.dll"];
    for (let i = 0; i < cands.length; i++) {
        try { return Process.getModuleByName(cands[i]).getExportByName(name); } catch (e) {}
    }
    return null;
}
function pathFromHandle(h) {
    try {
        const buf = Memory.alloc(2048);
        const n = new NativeFunction(modOf("GetFinalPathNameByHandleW"), "uint32",
            ["pointer", "pointer", "uint32", "uint32"])(h, buf, 1024, 0);
        if (n > 0) return buf.readUtf16String();
    } catch (e) {}
    return "";
}
targets.forEach(function (name) {
    const addr = modOf(name);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) { this.h = args[0]; },
        onLeave: function (retval) {
            if (retval.toInt32() === 0) return;
            const p = pathFromHandle(this.h);
            if (p && dbRe.test(p)) {
                const now = Date.now();
                if (now - lastNotify > 2000) {
                    lastNotify = now;
                    send({ stage: "db-read", path: p, t: now });
                }
            }
        }
    });
    hooked++;
});
send({ stage: "hook", hooked: hooked, exports: targets.length });
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--db", required=True)
    ap.add_argument("--seconds", type=int, default=240)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--window", type=float, default=6.0, help="命中读 DB 后持续扫内存的秒数")
    args = ap.parse_args()
    os.makedirs(LOG, exist_ok=True)

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    print("target salt=%s" % salt.hex(), flush=True)

    db_read = {"t": 0.0, "path": ""}
    hook_state = {"hooked": None}

    # ---------- 1) 挂起启动启动器并装 hook ----------
    print("killing existing Weixin...", flush=True)
    os.system('taskkill /F /IM Weixin.exe /T >NUL 2>&1')
    time.sleep(3)
    pi = create_suspended(args.exe)
    print("launcher suspended pid=%d" % pi.dwProcessId, flush=True)
    dev = frida.get_local_device()
    ls = dev.attach(pi.dwProcessId)

    def on_msg(m, data):
        p = m.get("payload") or {}
        if p.get("stage") == "hook":
            hook_state["hooked"] = p.get("hooked")
            print("hook installed=%s" % p.get("hooked"), flush=True)
        elif p.get("stage") == "db-read":
            db_read["t"] = time.time()
            db_read["path"] = p["path"]
            print("DB READ: %s" % p["path"], flush=True)

    lsc = ls.create_script(HOOK_JS)
    lsc.on("message", on_msg)
    lsc.load()
    kernel32.ResumeThread(pi.hThread)
    print("launcher resumed; waiting for main process and db reads ...", flush=True)

    hit = None
    t_end = time.time() + args.seconds
    rounds = 0
    while time.time() < t_end and rounds < args.rounds:
        time.sleep(1)
        if not db_read["t"]:
            continue
        # 读 DB 后立即扫（在所有 Weixin/WeChatAppEx 进程里）
        rounds += 1
        print("[round %d] 扫描内存（窗口 %.1fs）…" % (rounds, args.window), flush=True)
        t_round = time.time()
        cands = verified = 0
        for pid, name in pids_of():
            h = kernel32.OpenProcess(PQI | PVR, False, pid)
            if not h:
                continue
            for base, size in regions(h):
                data = readmem(h, base, size)
                if not data:
                    continue
                # 收集区域内「像指针」的 8 字节值集合
                ptrs = set()
                for off in range(0, len(data) - 8 + 1, 8):
                    v = int.from_bytes(data[off:off + 8], "little")
                    if 0x10000 < v < 0x7FFFFFFFFFFF:
                        ptrs.add(v)
                for v in ptrs:
                    blk = readmem(h, v, 192)
                    if not blk:
                        continue
                    if blk[:SALT] == salt:
                        print("  [SALT] pid=%d(%s) ptr=0x%X" % (pid, name, v), flush=True)
                    cands += 1
                    for want, tag in ((32, "raw32"), (16, "salt16")):
                        pass
                    # 候选1：v 处 32 字节当作原始密钥
                    for off in (0, 16, 32, 64, 96, 128, 160):
                        if off + 32 > len(blk):
                            break
                        cand = blk[off:off + 32]
                        mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
                        verified += 1
                        if hmac_new(mk, mac_msg, sha512).digest() == expected:
                            hit = (pid, name, v + off, cand.hex(), "ptr32")
                            break
                    if hit:
                        break
                if hit:
                    break
            kernel32.CloseHandle(h)
            if hit:
                break
        dt = time.time() - t_round
        print("[round %d] 指针=%d 预言机=%d %.0fs hit=%s" % (rounds, cands, verified, dt, hit), flush=True)
        if hit:
            break
        db_read["t"] = 0.0

    try:
        lsc.unload()
    except Exception:                                              # noqa: BLE001
        pass
    try:
        ls.detach()
    except Exception:                                              # noqa: BLE001
        pass

    if hit:
        out = os.path.join(BASE, "keys", "restart_hook_key.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"db": args.db, "salt": salt.hex(), "enc_key": hit[3],
                       "pid": hit[0], "proc": hit[1], "addr": "0x%X" % hit[2],
                       "method": hit[4]}, f, indent=2)
        print("FOUND key=%s (%s) -> %s" % (hit[3], hit[4], out), flush=True)
    else:
        print("no-hit after %d rounds" % rounds, flush=True)
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
