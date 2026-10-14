"""S5-ak —— 用 Windows 硬件断点（调试寄存器）抓 AES 密钥扩展入参：零代码改写

为什么用硬件断点：
  * 87 号用 Frida Interceptor 在 AES 密钥扩展内部挂点，改写了热路径指令 → 微信崩溃；
  * 硬件断点由 CPU 的 DR0..DR3 实现，**不修改目标进程任何一个字节**，
    只在命中时由内核投递 EXCEPTION_SINGLE_STEP，因此不存在「改写破坏代码」的故障模式。

流程：
  1. DebugActiveProcess(pid) 把目标挂为调试对象（此时其线程被挂起）；
  2. 枚举所有线程，对每个线程 SetThreadContext 设置
        DR0 = Weixin.dll 基址 + 0x5936EDA（AES 密钥扩展入口）
        DR7 = 0x1（L0 本地执行断点使能）+ 0x100（LE 精确数据，可省略）
  3. ContinueDebugEvent 放行；命中时读该线程上下文取 rcx/rdx/r8/r9，
     用 ReadProcessMemory 读出指针内容（r8 = 输入密钥，32 字节）；
  4. 用 page-1 HMAC 预言机验证；命中打印 KEY；
  5. 结束后清除断点（DR7=0）并 DebugActiveProcessStop 干净分离。

用法（在你的终端跑，微信需已运行）：
  C:\\Python314\\python.exe -u 89_hwbreak_keyexp.py --pid <pid> --db <db> [--seconds 120]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import subprocess
import sys
import time

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
# 91 号扫描结果：RVA 0x5937203 处连续 13 个 AESKEYGENASSIST、常量成对 (1,1,2,2,4,4,8,8,10,10,20,20,40)
# → AES-256 密钥扩展（SQLCipher 用 AES-256）。函数入口在其前若干字节，一并作为断点候选。
KEYEXP_RVAS = [0x5937203, 0x59371E0, 0x59371F0, 0x5937230, 0x5937240]

kernel32 = ctypes.windll.kernel32
DEBUG_PROCESS = 0x00000001
THREAD_SUSPEND_RESUME = 0x0002
TH32CS_SNAPTHREAD = 0x00000004

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9
EXCEPTION_SINGLE_STEP = 0x80000004
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001


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


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
                ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long), ("dwFlags", wt.DWORD)]


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", wt.DWORD), ("ExceptionFlags", wt.DWORD),
                ("ExceptionRecord", ctypes.c_void_p), ("ExceptionAddress", ctypes.c_void_p),
                ("NumberParameters", wt.DWORD), ("ExceptionInformation", ctypes.c_void_p * 15)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wt.DWORD)]


class DEBUG_EVENT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("Exception", EXCEPTION_DEBUG_INFO),
                    ("pad", ctypes.c_byte * 160)]
    _anonymous_ = ("u",)
    _fields_ = [("dwDebugEventCode", wt.DWORD), ("dwProcessId", wt.DWORD),
                ("dwThreadId", wt.DWORD), ("u", _U)]


class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [("ControlWord", wt.DWORD), ("StatusWord", wt.DWORD), ("TagWord", wt.DWORD),
                ("ErrorOffset", wt.DWORD), ("ErrorSelector", wt.DWORD),
                ("DataOffset", wt.DWORD), ("DataSelector", wt.DWORD),
                ("RegisterArea", ctypes.c_byte * 80), ("Cr0NpxState", wt.DWORD)]


class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", wt.DWORD), ("MxCsr", wt.DWORD),
        ("SegCs", wt.WORD), ("SegDs", wt.WORD), ("SegEs", wt.WORD), ("SegFs", wt.WORD),
        ("SegGs", wt.WORD), ("SegSs", wt.WORD), ("EFlags", wt.DWORD),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64), ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64), ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64), ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64), ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64), ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64), ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64), ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64), ("Rip", ctypes.c_uint64),
        ("FltSave", FLOATING_SAVE_AREA),
        ("VectorRegister", ctypes.c_byte * 416), ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64), ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64), ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64)]


CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
WANT = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS


def readmem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def threads_of(pid):
    out = []
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == -1:
        return out
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(THREADENTRY32)
    ok = kernel32.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid:
            out.append(te.th32ThreadID)
        ok = kernel32.Thread32Next(snap, ctypes.byref(te))
    kernel32.CloseHandle(snap)
    return out


def arm_thread(tid, bp_addr):
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME | 0x0008 | 0x0010 | 0x0040, False, tid)
    if not h:
        return False
    ctx = CONTEXT64()
    ctx.ContextFlags = WANT
    if not kernel32.GetThreadContext(h, ctypes.byref(ctx)):
        kernel32.CloseHandle(h)
        return False
    ctx.Dr0 = bp_addr
    ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
    ctx.Dr7 = 0x1                      # L0 使能，执行断点，1 字节长度
    ok = bool(kernel32.SetThreadContext(h, ctypes.byref(ctx)))
    kernel32.CloseHandle(h)
    return ok


def disarm_thread(tid):
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME | 0x0008 | 0x0010 | 0x0040, False, tid)
    if not h:
        return
    ctx = CONTEXT64()
    ctx.ContextFlags = WANT
    if kernel32.GetThreadContext(h, ctypes.byref(ctx)):
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
        ctx.Dr7 = 0
        kernel32.SetThreadContext(h, ctypes.byref(ctx))
    kernel32.CloseHandle(h)


def verify(mac_salt, mac_msg, expected, raw, stride=4):
    if not raw or len(raw) < 32:
        return []
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    out = []
    for off in range(0, len(raw) - 31, stride):
        cand = raw[off:off + 32]
        mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
        if hmac_new(mk, mac_msg, sha512).digest() == expected:
            out.append((off, cand.hex()))
    return out


def wperm(pid):
    return kernel32.OpenProcess(0x0400 | 0x0010 | 0x0008 | 0x0020 | 0x0002, False, pid)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--base", default="")
    ap.add_argument("--rva", default="", help="覆盖断点 RVA（十六进制），默认用 KEYEXP_RVAS 的第一个")
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--out", default=os.path.join(BASE, "keys", "key_hwbreak.json"))
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("目标 salt=%s" % salt.hex(), flush=True)

    pid = args.pid
    if not pid:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin -ErrorAction SilentlyContinue |"
                            "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                           capture_output=True, text=True, timeout=30)
        pid = int((r.stdout or "0").strip() or 0)
    print("目标 pid=%d" % pid, flush=True)

    # 取 Weixin.dll 基址（只读）
    import frida
    dev = frida.get_local_device()
    s0 = dev.attach(pid)
    holder = {}
    probe = s0.create_script(
        'try { const m = Process.getModuleByName("Weixin.dll"); send({base: m.base.toString()}); }'
        ' catch (e) { send({err: "" + e}); }')
    probe.on("message", lambda m, d: holder.update(m.get("payload") or {}))
    probe.load()
    time.sleep(1.5)
    try:
        probe.unload()
    except Exception:                                              # noqa: BLE001
        pass
    s0.detach()
    base = int(args.base, 16) if args.base else int(holder.get("base", "0"), 16)
    if not base:
        raise SystemExit("未取到 Weixin.dll 基址")
    rva = int(args.rva, 16) if args.rva else KEYEXP_RVAS[0]
    bp = base + rva
    print("断点地址 = 0x%X (base 0x%X + RVA 0x%X)" % (bp, base, rva), flush=True)
    print("候选 RVA 列表（若本地址无命中，可用 --rva 逐个试）: %s"
          % ["0x%X" % x for x in KEYEXP_RVAS], flush=True)

    if not kernel32.DebugActiveProcess(pid):
        raise SystemExit("DebugActiveProcess 失败 err=%d（可能已有调试器附加）"
                         % ctypes.get_last_error())
    print("已附加为调试器（零代码改写）", flush=True)

    armed = [t for t in threads_of(pid) if arm_thread(t, bp)]
    print("已武装线程 %d 个" % len(armed), flush=True)

    confirmed = []
    de = DEBUG_EVENT()
    t0 = time.time()
    seen_single = 0
    try:
        while time.time() - t0 < args.seconds:
            if not kernel32.WaitForDebugEvent(ctypes.byref(de), 1000):
                continue
            code = de.dwDebugEventCode
            cont = DBG_CONTINUE
            if code == EXCEPTION_DEBUG_EVENT:
                ex = de.Exception.ExceptionRecord
                if ex.ExceptionCode == EXCEPTION_SINGLE_STEP and \
                        int(ex.ExceptionAddress or 0) == bp:
                    seen_single += 1
                    tid = de.dwThreadId
                    h = kernel32.OpenThread(0x0008 | 0x0010, False, tid)
                    regs = {}
                    if h:
                        ctx = CONTEXT64()
                        ctx.ContextFlags = WANT
                        if kernel32.GetThreadContext(h, ctypes.byref(ctx)):
                            regs = {"rcx": ctx.Rcx, "rdx": ctx.Rdx, "r8": ctx.R8,
                                    "r9": ctx.R9, "rsp": ctx.Rsp, "rip": ctx.Rip}
                        kernel32.CloseHandle(h)
                    print("BREAK #%d tid=%d r8=0x%X rcx=0x%X"
                          % (seen_single, tid, regs.get("r8", 0), regs.get("rcx", 0)), flush=True)
                    hp = wperm(pid)
                    if hp:
                        for reg in ("r8", "rcx", "rdx", "rsp"):
                            addr = regs.get(reg, 0)
                            if not addr:
                                continue
                            raw = readmem(hp, addr, 256)
                            if raw:
                                print("   %s[0:32]=%s" % (reg, raw[:32].hex()), flush=True)
                                for off, kh in verify(mac_salt, mac_msg, expected, raw):
                                    print("   *** KEY from %s+%d: %s" % (reg, off, kh), flush=True)
                                    confirmed.append({"reg": reg, "off": off, "key": kh})
                        kernel32.CloseHandle(hp)
                    if confirmed:
                        kernel32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
                        break
                else:
                    cont = DBG_EXCEPTION_NOT_HANDLED if de.Exception.dwFirstChance else DBG_CONTINUE
            elif code == CREATE_THREAD_DEBUG_EVENT:
                arm_thread(de.dwThreadId, bp)
            kernel32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)
    except KeyboardInterrupt:
        print("用户中断", flush=True)
    finally:
        for t in threads_of(pid):
            disarm_thread(t)
        kernel32.DebugActiveProcessStop(pid)
        print("已分离调试器、清除断点", flush=True)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"db": args.db, "salt": salt.hex(), "breakpoint": "0x%X" % bp,
                   "enc_key": confirmed[0]["key"] if confirmed else None,
                   "confirmed": confirmed, "breaks": seen_single}, f, indent=1,
                  ensure_ascii=False)
    print("断点命中 %d 次，确认 key %d -> %s" % (seen_single, len(confirmed), args.out),
          flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
