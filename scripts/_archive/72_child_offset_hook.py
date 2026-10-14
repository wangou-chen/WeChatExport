"""S5-u —— 启动器 CreateProcessW 门控 + 子进程偏移 hook（抓 codec 密钥）

本机约束（均已实测）：
  * frida.device.spawn() 卡死；frida.attach(已存在进程) 正常；
  * Weixin.exe 是启动器，CreateProcessW 拉起真正主进程后自身退出；
  * hook kernel32 的 API 必须用 Process.getModuleByName(m).getExportByName(f)
    （Module.getExportByName 在此环境为 undefined）。

流程：
  1. CreateProcessW(CREATE_SUSPENDED) 启动启动器 → attach → 装 CreateProcessW 门控 hook → 恢复；
  2. 门控回调给出子进程 (pid, tid)；
  3. 宿主 SuspendThread(tid) → attach 子进程 → hook Weixin.dll + OFFSET →
     ResumeThread(tid)（用 launcher 侧 OpenThread 得到的句柄数值，或宿主自己 OpenThread）；
  4. 命中 codec 函数即 dump rcx/rdx 指向内存，用 page-1 HMAC 预言机验证；
  5. 安全阀：退出前恢复所有被挂起的线程。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python -u 72_child_offset_hook.py --db <db> --offset 0x3486140 [--seconds 90]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import time

import frida

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"
kernel32 = ctypes.windll.kernel32
CREATE_SUSPENDED = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002
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


def create_suspended(exe):
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = kernel32.CreateProcessW(None, exe, None, None, False, CREATE_SUSPENDED, None,
                                 os.path.dirname(exe), ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise SystemExit("CreateProcessW 失败 err=%d" % ctypes.get_last_error())
    return pi


def suspend_tid(tid):
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        return False
    kernel32.SuspendThread(h)
    kernel32.CloseHandle(h)
    return True


def resume_tid(tid):
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        return False
    kernel32.ResumeThread(h)
    kernel32.CloseHandle(h)
    return True


GATE_JS = r"""
function findExport(mods, fn) {
    for (let i = 0; i < mods.length; i++) {
        try { return Process.getModuleByName(mods[i]).getExportByName(fn); } catch (e) {}
    }
    return null;
}
const addr = findExport(["kernel32.dll", "KERNEL32.DLL", "KernelBase.dll"], "CreateProcessW");
if (!addr) { send({ stage: "gate", hooked: 0 }); }
else {
    Interceptor.attach(addr, {
        onEnter: function (args) { this.pi = args[8]; },
        onLeave: function (retval) {
            if (retval.toInt32() === 0 || this.pi.isNull()) return;
            send({ stage: "child", pid: this.pi.add(8).readU32(), tid: this.pi.add(12).readU32() });
        }
    });
    send({ stage: "gate", hooked: 1 });
}
"""


def child_js(offset):
    return r"""
const OFF = %s;
let mod = null;
try { mod = Process.getModuleByName("Weixin.dll"); } catch (e) {}
if (!mod) { send({ stage: "err", msg: "child: Weixin.dll 未加载" }); }
else {
    const target = mod.base.add(OFF);
    let prologue = "";
    try {
        prologue = Array.from(new Uint8Array(target.readByteArray(16)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { prologue = "READFAIL"; }
    send({ stage: "probe", base: mod.base.toString(), target: target.toString(), prologue: prologue });
    function dump(p, n) {
        try {
            return Array.from(new Uint8Array(p.readByteArray(n)))
                .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
        } catch (e) { return "FAIL"; }
    }
    try {
        Interceptor.attach(target, {
            onEnter: function () {
                const c = this.context;
                send({ stage: "hit", rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                       rcx64: dump(c.rcx, 64), rdx64: dump(c.rdx, 64), rsp48: dump(c.rsp, 48) });
            }
        });
        send({ stage: "hooked" });
    } catch (e) { send({ stage: "err", msg: "child attach 失败: " + e }); }
}
""" % hex(offset)


def verify(mac_salt, mac_msg, expected, blobs):
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    out = []
    for tag, blob in blobs.items():
        if not blob or blob == "FAIL":
            continue
        try:
            raw = bytes.fromhex(blob)
        except ValueError:
            continue
        for off in range(0, max(1, len(raw) - 31)):
            cand = raw[off:off + 32]
            if len(cand) < 32:
                break
            mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
            if hmac_new(mk, mac_msg, sha512).digest() == expected:
                out.append((tag, off, cand.hex()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--db", required=True)
    ap.add_argument("--offset", default="0x3486140")
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--out", default="")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    off = int(args.offset, 16)

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("salt=%s offset=0x%X" % (salt.hex(), off), flush=True)

    print("killing existing Weixin (TerminateProcess) ...", flush=True)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "killwx", os.path.join(os.path.dirname(os.path.abspath(__file__)), "73_kill_wechat.py"))
        km = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(km)
        for _pid, _n in km.pids():
            km.kill(_pid)
    except Exception as e:                                        # noqa: BLE001
        print("kill helper 失败: %s" % e, flush=True)
    time.sleep(4)
    pi = create_suspended(args.exe)
    print("launcher suspended pid=%d" % pi.dwProcessId, flush=True)
    dev = frida.get_local_device()
    ls = dev.attach(pi.dwProcessId)
    gate = ls.create_script(GATE_JS)

    state = {"child_pid": 0, "child_tid": 0, "suspended": False}
    hits = []
    confirmed = []
    cs = None

    def on_gate(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "gate":
            print("gate hooked=%s" % p.get("hooked"), flush=True)
        elif st == "child":
            state["child_pid"] = p["pid"]
            state["child_tid"] = p["tid"]
            if suspend_tid(p["tid"]):
                state["suspended"] = True
            print("child pid=%d tid=%d suspended=%s" % (p["pid"], p["tid"], state["suspended"]),
                  flush=True)

    def on_child(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "probe":
            print("probe base=%s target=%s prologue=%s"
                  % (p.get("base"), p.get("target"), p.get("prologue")), flush=True)
        elif st == "hooked":
            print("child hook installed", flush=True)
        elif st == "hit":
            hits.append(p)
            print("HIT rcx64=%s" % p.get("rcx64"), flush=True)
            print("    rdx64=%s" % p.get("rdx64"), flush=True)
            for tag, o, kh in verify(mac_salt, mac_msg, expected,
                                     {"rcx": p.get("rcx64"), "rdx": p.get("rdx64"),
                                      "rsp": p.get("rsp48")}):
                print("  *** KEY from %s+%d: %s" % (tag, o, kh), flush=True)
                confirmed.append((tag, o, kh))
        else:
            print("[child] " + json.dumps(p, ensure_ascii=False), flush=True)

    gate.on("message", on_gate)
    gate.load()
    kernel32.ResumeThread(pi.hThread)
    print("launcher resumed", flush=True)

    csc = None
    t0 = time.time()
    attached = False
    while time.time() - t0 < args.seconds:
        time.sleep(0.4)
        if state["child_pid"] and not attached:
            try:
                cs = dev.attach(state["child_pid"])
            except Exception as e:                                 # noqa: BLE001
                print("attach child 重试: %s" % e, flush=True)
                continue
            attached = True
            csc = cs.create_script(child_js(off))
            csc.on("message", on_child)
            csc.load()
            if state["suspended"]:
                resume_tid(state["child_tid"])
                state["suspended"] = False
                print("child tid=%d resumed" % state["child_tid"], flush=True)
        if confirmed and len(confirmed) >= 1:
            break

    for s in (csc, gate):
        try:
            if s:
                s.unload()
        except Exception:                                          # noqa: BLE001
            pass
    for s in (cs, ls):
        try:
            if s:
                s.detach()
        except Exception:                                          # noqa: BLE001
            pass
    if state["suspended"]:
        resume_tid(state["child_tid"])
        print("safety-resume tid=%d" % state["child_tid"], flush=True)

    if confirmed and args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        rec = {"db": args.db, "salt": salt.hex(), "enc_key": confirmed[0][2],
               "offset": hex(off), "source": confirmed[0][0], "hits": len(hits)}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
        print("-> %s" % args.out, flush=True)
    print("hits=%d confirmed=%d" % (len(hits), len(confirmed)), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
