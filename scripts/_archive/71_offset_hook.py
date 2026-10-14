"""S5-t —— 直接用我们已知的 codec 偏移在启动期抓密钥（版本 4.1.13.65）

来源：stargazer-2026/wechat-4.1.12-decrypt 的 find_key.py
  "hook codec 配置函数 (weixin.dll 偏移 0x3486140), rcx 指向的结构前 32 字节 = password"
该偏移出自 4.1.12.26；本机是 4.1.13.65，因此：
  * 先校验 base+offset 处是否是合法函数入口（常见 prologue），
  * 再挂 hook，命中即 dump rcx/rdx 指向的内存并直接用 page-1 HMAC 预言机验证 32 字节候选。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe -u 71_offset_hook.py --db <db> [--offset 0x3486140] [--seconds 90]
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
import time

import frida

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
DEFAULT_EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"
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


def create_suspended(exe):
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = kernel32.CreateProcessW(None, exe, None, None, False, CREATE_SUSPENDED, None,
                                 os.path.dirname(exe), ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise SystemExit("CreateProcessW 失败 err=%d" % ctypes.get_last_error())
    return pi


JS_TMPL = r"""
const OFF = %(off)s;
let mod = null;
try { mod = Process.getModuleByName("Weixin.dll"); } catch (e) {}
if (!mod) { send({stage: "err", msg: "Weixin.dll 未加载"}); }
else {
    const target = mod.base.add(OFF);
    let prologue = "";
    try { prologue = Array.from(new Uint8Array(target.readByteArray(16))).map(function (b) {
        return ("0" + b.toString(16)).slice(-2); }).join(""); } catch (e) { prologue = "READFAIL"; }
    send({stage: "probe", base: mod.base.toString(), target: target.toString(),
          prologue: prologue, size: mod.size});
    try {
        Interceptor.attach(target, {
            onEnter: function (args) {
                const c = this.context;
                function dump(p, n) {
                    try { const u8 = new Uint8Array(p.readByteArray(n));
                        return Array.from(u8).map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
                    } catch (e) { return "FAIL"; }
                }
                send({stage: "hit", rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                      r8: c.r8.toString(), r9: c.r9.toString(),
                      rcx64: dump(c.rcx, 64), rdx64: dump(c.rdx, 64),
                      rsp48: dump(c.rsp, 48)});
            }
        });
        send({stage: "hooked"});
    } catch (e) {
        send({stage: "err", msg: "Interceptor.attach 失败: " + e});
    }
}
"""


def verify_candidates(mac_salt, mac_msg, expected, blobs):
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    out = []
    for tag, blob in blobs.items():
        if not blob or blob == "FAIL":
            continue
        try:
            raw = bytes.fromhex(blob)
        except ValueError:
            continue
        for off in range(0, max(1, len(raw) - 32) + 1):
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
    args = ap.parse_args()
    off = int(args.offset, 16)

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("target salt=%s  offset=0x%X" % (salt.hex(), off), flush=True)

    print("killing existing Weixin ...", flush=True)
    os.system('taskkill /F /IM Weixin.exe /T >NUL 2>&1')
    time.sleep(3)
    pi = create_suspended(args.exe)
    print("launcher suspended pid=%d" % pi.dwProcessId, flush=True)
    dev = frida.get_local_device()
    ls = dev.attach(pi.dwProcessId)
    script = ls.create_script(JS_TMPL % {"off": hex(off)})

    hits = []
    probe = {}

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "probe":
            probe.update(p)
            print("probe: base=%s target=%s prologue=%s size=%s"
                  % (p.get("base"), p.get("target"), p.get("prologue"), p.get("size")), flush=True)
        elif st == "hooked":
            print("hook installed", flush=True)
        elif st == "hit":
            print("HIT rcx=%s rdx=%s" % (p.get("rcx"), p.get("rdx")), flush=True)
            print("  rcx64=%s" % p.get("rcx64"), flush=True)
            print("  rdx64=%s" % p.get("rdx64"), flush=True)
            hits.append(p)
            found = verify_candidates(mac_salt, mac_msg, expected,
                                      {"rcx": p.get("rcx64"), "rdx": p.get("rdx64"),
                                       "rsp": p.get("rsp48")})
            for tag, o, keyhex in found:
                print("  *** KEY CONFIRMED from %s+%d: %s" % (tag, o, keyhex), flush=True)
        else:
            print(json.dumps(p, ensure_ascii=False), flush=True)

    script.on("message", on_msg)
    script.load()
    kernel32.ResumeThread(pi.hThread)
    print("resumed; waiting up to %ds" % args.seconds, flush=True)
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
        ls.detach()
    except Exception:                                              # noqa: BLE001
        pass
    confirmed = []
    for p in hits:
        confirmed += verify_candidates(mac_salt, mac_msg, expected,
                                       {"rcx": p.get("rcx64"), "rdx": p.get("rdx64"),
                                        "rsp": p.get("rsp48")})
    if args.out and confirmed:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"db": args.db, "salt": salt.hex(), "enc_key": confirmed[0][2],
                       "offset": hex(off), "source": confirmed[0][0],
                       "hits": len(hits)}, f, indent=2)
        print("-> %s" % args.out, flush=True)
    print("hits=%d confirmed=%d" % (len(hits), len(confirmed)), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
