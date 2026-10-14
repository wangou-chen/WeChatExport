"""S5-aa —— 挂起启动 + 「等 Weixin.dll 出现后立即装 hook」

修正上一版 75_suspended_multihook.py 的时序缺陷：
  CREATE_SUSPENDED 创建进程时 Weixin.dll 尚未映射（198MB，加载需时间），
  上一版在 attach 后立刻 getModuleByName 必然失败（实测 {"msg":"Weixin.dll 未加载"}）。
本版：agent 在目标进程内以 50ms 间隔轮询 Weixin.dll，出现后立刻装 hook，再通知宿主恢复进程。

用法（请在你自己的 PowerShell 里跑，令牌正常，微信可正常读写 E:）：
  $env:PYTHONUTF8="1"
  $env:PYTHONPATH="C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg"
  C:\\Python314\\python.exe -u 78_suspended_wait_hook.py `
      --db "E:\\xwechat_files\\wxid_usdvuhs727dr22_2291\\db_storage\\message\\message_0.db" `
      --lo 0x3486000 --hi 0x3486400 --step 8 --seconds 150 `
      --out C:\\Users\\Lenovo\\Desktop\\WeChatExport\\keys\\key.json
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

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
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
const WAIT_MODULE_MS = %(wait_ms)d;
const t0 = Date.now();
let installed = 0, failed = 0, donep = false;
const probes = [];

function dump(p, n) {
    try {
        return Array.from(new Uint8Array(p.readByteArray(n)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { return "FAIL"; }
}

function installAll() {
    let mod = null;
    try { mod = Process.getModuleByName("Weixin.dll"); } catch (e) { mod = null; }
    if (!mod) {
        if (Date.now() - t0 > WAIT_MODULE_MS) {
            send({ stage: "timeout-wait-module", waited_ms: Date.now() - t0 });
            return true;
        }
        return false;
    }
    if (donep) return true;
    donep = true;
    send({ stage: "mod", base: mod.base.toString(), size: mod.size, pid: Process.id,
           waited_ms: Date.now() - t0 });
    for (let off = LO; off <= HI; off += STEP) {
        const target = mod.base.add(off);
        let pro = "";
        try { pro = dump(target, 8); } catch (e) { pro = "READFAIL"; }
        probes.push({ off: off, prologue: pro });
        try {
            const myOff = off;
            Interceptor.attach(target, {
                onEnter: function () {
                    const c = this.context;
                    send({ stage: "hit", off: myOff,
                           rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                           rcx64: dump(c.rcx, 64), rdx64: dump(c.rdx, 64),
                           r8: c.r8.toString(), r9: c.r9.toString(),
                           rsp64: dump(c.rsp, 64) });
                }
            });
            installed++;
        } catch (e) { failed++; }
    }
    send({ stage: "installed", installed: installed, failed: failed, probes: probes });
    return true;
}

if (!installAll()) {
    const iv = setInterval(function () {
        if (installAll()) clearInterval(iv);
    }, 50);
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
    ap.add_argument("--lo", default="0x3486000")
    ap.add_argument("--hi", default="0x3486400")
    ap.add_argument("--step", type=int, default=8)
    ap.add_argument("--seconds", type=int, default=150)
    ap.add_argument("--wait-module", type=int, default=90)
    ap.add_argument("--out", default="")
    ap.add_argument("--no-kill", action="store_true")
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("salt=%s  hook %s..%s step=%d  等模块上限 %ds"
          % (salt.hex(), args.lo, args.hi, args.step, args.wait_module), flush=True)

    if not args.no_kill:
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "killwx", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "73_kill_wechat.py"))
            km = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(km)
            n = len(km.pids())
            for _pid, _n in km.pids():
                km.kill(_pid)
            print("已结束 %d 个残留微信进程" % n, flush=True)
        except Exception as e:                                    # noqa: BLE001
            print("清理失败: %s" % e, flush=True)
        time.sleep(4)

    pi = create_suspended(CMDLINE, os.path.dirname(EXE))
    print("main suspended pid=%d tid=%d" % (pi.dwProcessId, pi.dwThreadId), flush=True)
    dev = frida.get_local_device()
    session = dev.attach(pi.dwProcessId)
    print("attached（进程仍挂起，agent 已在内部轮询 Weixin.dll）", flush=True)

    hits = []
    confirmed = []
    ready = {"v": False}

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "mod":
            print("Weixin.dll 已加载: base=%s size=%s（等待 %.0f ms）"
                  % (p["base"], p["size"], p.get("waited_ms", 0)), flush=True)
        elif st == "installed":
            ready["v"] = True
            print("hook 装好: installed=%s failed=%s" % (p["installed"], p["failed"]), flush=True)
            for pr in p.get("probes", [])[:6]:
                print("   off=0x%X prologue=%s" % (pr["off"], pr["prologue"]), flush=True)
        elif st == "timeout-wait-module":
            print("!! 等待 Weixin.dll 超时（%.0f ms）" % p.get("waited_ms", 0), flush=True)
            ready["v"] = True
        elif st == "hit":
            hits.append(p)
            print("HIT off=0x%X  rcx=%s" % (p.get("off", 0), p.get("rcx")), flush=True)
            print("   rcx64=%s" % p.get("rcx64"), flush=True)
            print("   rdx64=%s" % p.get("rdx64"), flush=True)
            for tag, o, kh in verify(mac_salt, mac_msg, expected,
                                     {"rcx": p.get("rcx64"), "rdx": p.get("rdx64"),
                                      "rsp": p.get("rsp64")}):
                print("   *** KEY from %s+%d: %s" % (tag, o, kh), flush=True)
                confirmed.append((tag, o, kh))
        else:
            print(json.dumps(p, ensure_ascii=False), flush=True)

    script = session.create_script(JS_TMPL % {"lo": args.lo, "hi": args.hi,
                                              "step": args.step,
                                              "wait_ms": args.wait_module * 1000})
    script.on("message", on_msg)
    script.load()
    # 等 agent 确认 hook 装好（或超时）后再恢复主线程，保证 hook 早于 codec 初始化
    t_wait = time.time()
    while not ready["v"] and time.time() - t_wait < args.wait_module + 20:
        time.sleep(0.2)
    kernel32.ResumeThread(pi.hThread)
    print("main 已恢复，等待命中（%ds）…" % args.seconds, flush=True)

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
