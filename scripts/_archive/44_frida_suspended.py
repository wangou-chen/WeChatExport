"""
S5-m2 —— Windows 原生「挂起启动 + Frida attach + 恢复」抓密钥

背景（实测）：在本机沙箱下
  * frida.device.spawn() 会卡死在 winjector 注入阶段（对 notepad 也一样），
  * 但 frida.attach(已有进程) 正常（已对 Weixin.exe、测试进程验证）。
故改用 Windows 原生 API 完成「挂起启动」：
  CreateProcessW(CREATE_SUSPENDED) -> frida.attach(pid) -> 装 hook -> 找到主线程 -> ResumeThread

输出：logs\\frida_spawn_keys.jsonl

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python -u 44_frida_suspended.py [--exe <Weixin.exe>] [--seconds 240]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import time

import frida

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(BASE, "logs")
DEFAULT_EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"

kernel32 = ctypes.windll.kernel32
CREATE_SUSPENDED = 0x00000004
TH32CS_SNAPTHREAD = 0x00000004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


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


def create_suspended(exe):
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = kernel32.CreateProcessW(None, exe, None, None, False,
                                 CREATE_SUSPENDED, None,
                                 os.path.dirname(exe), ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise SystemExit("CreateProcessW 失败 err=%d" % ctypes.get_last_error())
    return pi


def set_thread_suspended(pid, tid, count):
    """对指定线程增加/减少挂起计数（未持有句柄时用 OpenThread）。"""
    THREAD_SUSPEND_RESUME = 0x0002
    h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        return False
    for _ in range(count):
        kernel32.ResumeThread(h)
    kernel32.CloseHandle(h)
    return True


JS = r"""
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
function install() {
    let mod;
    try { mod = Process.getModuleByName("bcrypt.dll"); } catch (e) { return -1; }
    let n = 0;
    mod.enumerateExports().forEach(function (e) {
        if (e.name !== "BCryptGenerateSymmetricKey" && e.name !== "BCryptImportKey") return;
        Interceptor.attach(e.address, {
            onEnter: function (args) {
                let cb, sec;
                if (e.name === "BCryptGenerateSymmetricKey") {
                    cb = args[3].toInt32();
                    sec = toHex(args[4], cb);
                    this.payload = { api: e.name, cb: cb, secret_hex: sec, keyobj: args[2].toString() };
                } else {
                    cb = args[5].toInt32();
                    sec = toHex(args[6], cb);
                    this.payload = { api: e.name, cb: cb, secret_hex: sec, blob: args[4].toString() };
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
    return n;
}
send({stage: "install", hooked: install()});
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--seconds", type=int, default=240)
    ap.add_argument("--keep", action="store_true", help="脚本退出时不结束微信")
    args = ap.parse_args()
    os.makedirs(LOG, exist_ok=True)
    out = os.path.join(LOG, "frida_spawn_keys.jsonl")
    fh = open(out, "a", encoding="utf-8")

    pi = create_suspended(args.exe)
    pid = pi.dwProcessId
    print("suspended pid=%d tid=%d" % (pid, pi.dwThreadId), flush=True)

    session = frida.attach(pid)
    print("frida attached", flush=True)
    script = session.create_script(JS)
    stats = {"n": 0}

    def on_message(m, data):
        p = m.get("payload") or {}
        if p.get("stage") == "install":
            print("hooked=%s" % p.get("hooked"), flush=True)
            return
        stats["n"] += 1
        fh.write(json.dumps(p, ensure_ascii=False) + "\n")
        fh.flush()
        print("[%s] cb=%s secret=%s ret=%s" % (p["api"], p["cb"], p.get("secret_hex", "")[:64],
                                               p.get("ret")), flush=True)

    script.on("message", on_message)
    script.load()
    print("script loaded; resuming main thread", flush=True)
    kernel32.ResumeThread(pi.hThread)
    print("resumed", flush=True)

    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    try:
        script.unload()
    except Exception:                                              # noqa: BLE001
        pass
    try:
        session.detach()
    except Exception:                                              # noqa: BLE001
        pass
    fh.close()
    print("captured events: %d" % stats["n"], flush=True)
    if not args.keep:
        # 脚本结束时保留微信运行（不 kill），仅关闭句柄
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
    print("-> %s" % out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
