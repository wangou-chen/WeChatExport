"""
S5-m4 —— 启动器子进程门控抓密钥（Windows / 本机沙箱约束下的可用方案）

本机实测约束：
  * frida.device.spawn() 卡死在 winjector 注入（notepad 也卡）；
  * frida.attach(已存在进程) 正常；
  * Weixin.exe 是启动器，CreateProcessW 拉起真正主进程后自身退出。
方案：hook 启动器的 CreateProcessW，在它返回之后立刻对该子进程主线程 SuspendThread，
      宿主 attach 子进程 → 装 bcrypt 密钥 hook → ResumeThread，让子进程继续初始化。
      这样密钥生成（启动早期）落在 hook 覆盖范围内。

安全阀：所有被 Suspend 的线程都会被登记，脚本退出前全部恢复，不会留下卡死进程。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe -u 45_frida_launcher.py [--exe <Weixin.exe>] [--seconds 300]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import time

import frida

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
LOG = os.path.join(BASE, "logs")
DEFAULT_EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"

kernel32 = ctypes.windll.kernel32
CREATE_SUSPENDED = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002


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


def suspend_thread(tid):
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        return None, ctypes.get_last_error()
    prev = kernel32.SuspendThread(h)
    kernel32.CloseHandle(h)
    return prev, 0


def resume_thread(tid):
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        return False
    kernel32.ResumeThread(h)
    kernel32.CloseHandle(h)
    return True


GATE_JS = r"""
let hooked = 0;
const seenMods = {};
function flagOf(name) { return seenMods[name] = true; }
["kernel32.dll", "KernelBase.dll"].forEach(function (m) {
    let addr = null;
    try { addr = Module.getExportByName(m, "CreateProcessW"); } catch (e) {}
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.pi = args[8];
            this.flags = args[5].toInt32();
            this.app = args[1].isNull() ? "" : args[1].readUtf16String();
        },
        onLeave: function (retval) {
            if (retval.toInt32() === 0 || this.pi.isNull()) return;
            const pid = this.pi.add(8).readU32();
            const tid = this.pi.add(12).readU32();
            send({stage: "child", pid: pid, tid: tid, flags: this.flags, app: this.app});
        }
    });
    hooked++;
});
send({stage: "gate", hooked: hooked, pid: Process.id});
"""

BCRYPT_JS = r"""
const seen = {};
function toHex(p, n) {
    if (p.isNull() || n <= 0 || n > 8192) return "";
    try {
        const u8 = new Uint8Array(p.readByteArray(n));
        let s = "";
        for (let i = 0; i < u8.length; i++) s += ("0" + u8[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return "READFAIL"; }
}
let n = 0;
["BCryptGenerateSymmetricKey", "BCryptImportKey"].forEach(function (name) {
    let addr = null;
    try { addr = Process.getModuleByName("bcrypt.dll").getExportByName(name); } catch (e) {}
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            let cb, sec;
            if (name === "BCryptGenerateSymmetricKey") {
                cb = args[3].toInt32(); sec = toHex(args[4], cb);
                this.payload = { api: name, cb: cb, secret_hex: sec, keyobj: args[2].toString() };
            } else {
                cb = args[5].toInt32(); sec = toHex(args[6], cb);
                this.payload = { api: name, cb: cb, secret_hex: sec };
            }
            this.payload.ret = this.returnAddress.toString();
            this.payload.stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 10).map(function (a) { return a.toString(); });
        },
        onLeave: function (retval) {
            if (!this.payload) return;
            this.payload.status = retval.toInt32();
            const k = this.payload.api + ":" + this.payload.secret_hex;
            if (seen[k]) return;
            seen[k] = true;
            send(this.payload);
        }
    });
    n++;
});
send({stage: "install", hooked: n, pid: Process.id});
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--seconds", type=int, default=300)
    ap.add_argument("--no-kill", action="store_true")
    args = ap.parse_args()
    os.makedirs(LOG, exist_ok=True)
    out = os.path.join(LOG, "frida_child_keys.jsonl")
    fh = open(out, "a", encoding="utf-8")
    keys = {"n": 0}
    suspended = []
    child = {}
    dev = frida.get_local_device()

    if not args.no_kill:
        os.system('taskkill /F /IM Weixin.exe /T >NUL 2>&1')
        time.sleep(3)
        print("existing Weixin killed", flush=True)

    def key_handler(tag):
        def h(m, data):
            p = m.get("payload") or {}
            st = p.get("stage")
            if st in ("gate", "install"):
                print("[%s] %s" % (tag, json.dumps(p, ensure_ascii=False)), flush=True)
                return
            if st == "child":
                if not child:
                    prev, err = suspend_thread(p["tid"])
                    if prev is None:
                        print("[gate] SuspendThread 失败 tid=%d err=%d" % (p["tid"], err), flush=True)
                        child.update(p); child["suspended"] = False
                    else:
                        suspended.append(p["tid"])
                        child.update(p); child["suspended"] = True
                print("[%s] child pid=%d tid=%d flags=0x%X app=%s" %
                      (tag, p["pid"], p["tid"], p.get("flags", 0), p.get("app")), flush=True)
                return
            keys["n"] += 1
            p["src"] = tag
            fh.write(json.dumps(p, ensure_ascii=False) + "\n")
            fh.flush()
            print("[%s KEY] %s cb=%s %s" % (tag, p.get("api"), p.get("cb"),
                                            p.get("secret_hex", "")[:64]), flush=True)
        return h

    pi = create_suspended(args.exe)
    print("launcher suspended pid=%d tid=%d" % (pi.dwProcessId, pi.dwThreadId), flush=True)
    ls = dev.attach(pi.dwProcessId)
    lsc = ls.create_script(GATE_JS)
    lsc.on("message", key_handler("launcher"))
    lsc.load()
    kernel32.ResumeThread(pi.hThread)
    print("launcher resumed", flush=True)

    t0 = time.time()
    cs = csc = None
    while time.time() - t0 < args.seconds:
        time.sleep(0.5)
        if child and child.get("pid") and cs is None:
            pid = child["pid"]
            try:
                cs = dev.attach(pid)
            except Exception as e:                                 # noqa: BLE001
                print("attach child %d 失败: %s" % (pid, e), flush=True)
                cs = None
            if cs is not None:
                print("attached child pid=%d" % pid, flush=True)
                csc = cs.create_script(BCRYPT_JS)
                csc.on("message", key_handler("child"))
                csc.load()
                if child.get("suspended"):
                    resume_thread(child["tid"])
                    print("child tid=%d resumed" % child["tid"], flush=True)
                    suspended = [t for t in suspended if t != child["tid"]]

    for s in (csc, lsc):
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
    for tid in suspended:                                          # 安全阀：不留挂起线程
        resume_thread(tid)
        print("safety-resume tid=%d" % tid, flush=True)
    fh.close()
    print("captured keys: %d" % keys["n"], flush=True)
    print("-> %s" % out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
