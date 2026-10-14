"""S5-x —— 直接对「微信主进程命令行」做挂起启动，并对 codec 偏移邻域做多点 hook

实测线索（本会话）：
  * 主进程命令行: "D:\\Program Files (x86)\\Tencent\\Weixin\\Weixin.exe" --scene=taskbarpins
  * 启动器并非用 kernel32!CreateProcessW 拉起主进程（门控 hook 未触发），
    因此改为「由我们直接 CREATE_SUSPENDED 启动主进程」。
  * frida.attach(挂起进程) 可用；frida.spawn 不可用（winjector 卡死）。
  * 4.1.12.26 的 codec 偏移为 0x3486140（本机 4.1.13.65），故在该地址邻域
    0x3486100..0x3486180 每 16 字节挂一个点，谁先触发即真实入口。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python -u 75_suspended_multihook.py --db <db> [--lo 0x3486100] [--hi 0x3486180] [--step 16]
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
EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"
CMDLINE = '"%s" --scene=taskbarpins' % EXE
kernel32 = ctypes.windll.kernel32
CREATE_SUSPENDED = 0x00000004
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


def create_suspended(cmdline, workdir):
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = kernel32.CreateProcessW(None, cmdline, None, None, False, CREATE_SUSPENDED, None,
                                 workdir, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise SystemExit("CreateProcessW 失败 err=%d" % ctypes.get_last_error())
    return pi


JS_TMPL = r"""
const LO = %(lo)s, HI = %(hi)s, STEP = %(step)s;
let mod = null;
try { mod = Process.getModuleByName("Weixin.dll"); } catch (e) {}
if (!mod) { send({ stage: "err", msg: "Weixin.dll 未加载" }); }
else {
    send({ stage: "mod", base: mod.base.toString(), size: mod.size });
    let installed = 0, failed = 0, probes = [];
    for (let off = LO; off <= HI; off += STEP) {
        const target = mod.base.add(off);
        let pro = "";
        try {
            pro = Array.from(new Uint8Array(target.readByteArray(8)))
                .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
        } catch (e) { pro = "READFAIL"; }
        probes.push({ off: off, prologue: pro });
        try {
            Interceptor.attach(target, {
                onEnter: function () {
                    const c = this.context;
                    function dump(p, n) {
                        try {
                            return Array.from(new Uint8Array(p.readByteArray(n)))
                                .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
                        } catch (e) { return "FAIL"; }
                    }
                    send({ stage: "hit", off: this.__off,
                           rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                           rcx64: dump(c.rcx, 64), rdx64: dump(c.rdx, 64), rsp48: dump(c.rsp, 48) });
                }
            });
            installed++;
        } catch (e) { failed++; }
    }
    send({ stage: "installed", installed: installed, failed: failed, probes: probes });
}
"""


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
    ap.add_argument("--db", required=True)
    ap.add_argument("--lo", default="0x3486100")
    ap.add_argument("--hi", default="0x3486180")
    ap.add_argument("--step", type=int, default=16)
    ap.add_argument("--seconds", type=int, default=100)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("salt=%s  hook 区间 %s..%s step=%d" % (salt.hex(), args.lo, args.hi, args.step), flush=True)

    print("先结束现有微信（TerminateProcess）…", flush=True)
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

    pi = create_suspended(CMDLINE, os.path.dirname(EXE))
    print("main suspended pid=%d tid=%d" % (pi.dwProcessId, pi.dwThreadId), flush=True)
    dev = frida.get_local_device()
    session = dev.attach(pi.dwProcessId)
    print("attached", flush=True)
    body = JS_TMPL % {"lo": args.lo, "hi": args.hi, "step": args.step}
    script = session.create_script(body)
    hits = []
    confirmed = []
    installed = {"n": 0}

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "mod":
            print("Weixin.dll base=%s size=%s" % (p.get("base"), p.get("size")), flush=True)
        elif st == "installed":
            installed["n"] = p.get("installed")
            print("installed=%s failed=%s" % (p.get("installed"), p.get("failed")), flush=True)
            for pr in p.get("probes", [])[:8]:
                print("   off=0x%X prologue=%s" % (pr["off"], pr["prologue"]), flush=True)
        elif st == "hit":
            hits.append(p)
            print("HIT off=0x%X rcx=%s" % (p.get("off", 0), p.get("rcx")), flush=True)
            print("   rcx64=%s" % p.get("rcx64"), flush=True)
            print("   rdx64=%s" % p.get("rdx64"), flush=True)
            for tag, o, kh in verify(mac_salt, mac_msg, expected,
                                     {"rcx": p.get("rcx64"), "rdx": p.get("rdx64"),
                                      "rsp": p.get("rsp48")}):
                print("   *** KEY from %s+%d: %s" % (tag, o, kh), flush=True)
                confirmed.append((tag, o, kh))
        else:
            print(json.dumps(p, ensure_ascii=False), flush=True)

    script.on("message", on_msg)
    script.load()
    kernel32.ResumeThread(pi.hThread)
    print("resumed; waiting %ds" % args.seconds, flush=True)
    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(1)
            if confirmed:
                break
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
    if confirmed and args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"db": args.db, "salt": salt.hex(), "enc_key": confirmed[0][2],
                       "source": confirmed[0][0], "hits": len(hits)}, f, indent=2)
        print("-> %s" % args.out, flush=True)
    print("hits=%d confirmed=%d" % (len(hits), len(confirmed)), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
