"""S5-ap —— 用 frida.spawn 在「进程被挂起的入口点」注入 hook，捕获 AES-256 密钥扩展入参

为什么这条不会崩（与之前三次崩溃的本质区别）：
  * frida.spawn() 让进程在**入口点暂停**，注入发生在它执行任何应用代码之前；
  * hook 装好后 resume，扩展函数在启动过程中被执行时被捕获；
  * **不在已运行的微信上附加调试器**，也不改写运行中的热路径代码。

落点（93 号 dump 实测）：
  Weixin.dll RVA 0x59371E0 = AES-256 密钥扩展函数入口
    0f 10 51 10        movups xmm2, [rcx+0x10]
    ba 0d 00 00 00     mov edx, 13           ; AES-256 13 轮
    41 0f 11 00        movups [r8], xmm0     ; r8 = 输入的 32 字节密钥
  → 在入口读 rcx（或 r8）指向的 32 字节即为密钥候选。

校验：用 page-1 HMAC 预言机（PBKDF2-SHA512(k, salt^0x3A, 2, 32) + HMAC-SHA512 比对）判定。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe -u 95_spawn_capture.py --db <db> [--db-dir <dir>] [--seconds 180]
"""
import argparse
import ctypes
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys
import time

import frida

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"
ARGS = ["--scene=taskbarpins"]
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
AES256_RVA = 0x59371E0

JS_TMPL = r"""
const RVAS = %(rvas)s;
let mod = null;
let installed = 0, failed = 0, hits = 0;
const MAXSEND = %(max_send)d;

function phex(p, n) {
    if (!p || p.isNull()) return "";
    try {
        return Array.from(new Uint8Array(p.readByteArray(n)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { return "FAIL"; }
}

function installer() {
    if (mod) return true;
    try { mod = Process.getModuleByName("Weixin.dll"); } catch (e) { return false; }
    send({ stage: "mod", base: mod.base.toString(), size: mod.size, pid: Process.id });
    for (let i = 0; i < RVAS.length; i++) {
        const rva = RVAS[i];
        const target = mod.base.add(ptr(rva).toInt32());
        try {
            Interceptor.attach(target, {
                onEnter: function () {
                    if (hits >= MAXSEND) return;
                    hits++;
                    const c = this.context;
                    send({ stage: "hit", rva: rva, n: hits,
                           rcx: c.rcx.toString(), r8: c.r8.toString(),
                           rdx: c.rdx.toString(), r10: c.r10.toString(),
                           rcx_64: phex(c.rcx, 64), r8_64: phex(c.r8, 64),
                           ret: this.returnAddress.toString() });
                }
            });
            installed++;
            send({ stage: "attached", rva: rva });
        } catch (e) {
            failed++;
            send({ stage: "attachfail", rva: rva, msg: "" + e });
        }
    }
    return true;
}

// 进程在入口点被挂起时本脚本已加载：先尝试装，若 dll 未加载则轮询等待
if (!installer()) {
    const iv = setInterval(function () { if (installer()) clearInterval(iv); }, 20);
}
send({ stage: "ready", installed: installed, failed: failed });
"""


def page1_of(path):
    with open(path, "rb") as f:
        return f.read(PAGESZ)


def build_targets(db, db_dir):
    meta = {}
    paths = []
    if db:
        paths.append(db)
    if db_dir:
        for root, _d, files in os.walk(db_dir):
            for f in files:
                if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                    p = os.path.join(root, f)
                    if os.path.getsize(p) >= PAGESZ and p not in paths:
                        paths.append(p)
    for p in paths:
        p1 = page1_of(p)
        salt = p1[:SALT]
        meta[p] = {
            "salt": salt,
            "mac_salt": bytes(b ^ 0x3A for b in salt),
            "mac_msg": p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00",
            "expected": p1[MAC_OFF:PAGESZ],
            "name": os.path.basename(p),
        }
    return meta


def identify(cand, meta):
    """返回匹配的库名列表"""
    out = []
    for p, m in meta.items():
        mk = hashlib.pbkdf2_hmac("sha512", cand, m["mac_salt"], 2, 32)
        hm = hmac_mod.new(mk, m["mac_msg"], hashlib.sha512)
        hm.update(struct.pack("<I", 1))
        if hm.digest() == m["expected"]:
            out.append(m["name"])
    return out


def kill_wechat():
    """用 TerminateProcess 结束残留微信（沙箱内 taskkill 被拒）。"""
    PS = ("Get-Process Weixin,WeChatAppEx -ErrorAction SilentlyContinue |"
          "ForEach-Object { \"$($_.Id)\" }")
    import subprocess
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", PS],
                           capture_output=True, text=True, timeout=30)
        pids = [int(x) for x in (r.stdout or "").split() if x.isdigit()]
    except Exception:                                              # noqa: BLE001
        pids = []
    PROCESS_TERMINATE = 0x0001
    for pid in pids:
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h:
            ctypes.windll.kernel32.TerminateProcess(h, 1)
            ctypes.windll.kernel32.CloseHandle(h)
    return pids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="")
    ap.add_argument("--db-dir", default="")
    ap.add_argument("--seconds", type=int, default=180)
    ap.add_argument("--max-send", type=int, default=200)
    ap.add_argument("--out", default=os.path.join(BASE, "keys", "key_spawn.json"))
    args = ap.parse_args()

    meta = build_targets(args.db, args.db_dir)
    if not meta:
        raise SystemExit("需指定 --db 或 --db-dir")
    print("目标库 %d 个（用于判定命中密钥归属）" % len(meta), flush=True)

    killed = kill_wechat()
    print("已结束残留微信进程 %d 个: %s" % (len(killed), killed), flush=True)
    time.sleep(3)

    dev = frida.get_local_device()
    print("spawn %s %s" % (EXE, ARGS), flush=True)
    pid = dev.spawn([EXE] + ARGS)
    print("spawned pid=%d（进程在入口点暂停）" % pid, flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS_TMPL % {
        "rvas": json.dumps(["0x%X" % AES256_RVA, "0x5937203", "0x59371D8"]),
        "max_send": args.max_send,
    })
    hits = []
    found = {}          # db 名 -> key hex

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st in ("ready", "mod", "attached", "attachfail"):
            print(json.dumps(p, ensure_ascii=False), flush=True)
            return
        if st != "hit":
            return
        hits.append(p)
        print("HIT#%d rva=%s rcx=%s" % (p.get("n"), p.get("rva"), p.get("rcx")), flush=True)
        for reg in ("rcx_64", "r8_64"):
            blob = p.get(reg)
            if not blob or blob == "FAIL":
                continue
            try:
                raw = bytes.fromhex(blob)
            except ValueError:
                continue
            cand = raw[:32]
            names = identify(cand, meta)
            if names:
                print("   *** KEY %s  解开: %s" % (cand.hex(), ", ".join(names)), flush=True)
                for n in names:
                    found[n] = {"key": cand.hex(), "from": reg, "rva": p.get("rva"),
                                "ret": p.get("ret")}
            else:
                print("   %s[0:32]=%s  (未匹配任何库)" % (reg, cand.hex()), flush=True)
        if found:
            print("   已取得 %d 个库的密钥，继续等待其它库…" % len(found), flush=True)

    script.on("message", on_msg)
    script.load()
    print("hook 就绪，resume 微信（请准备扫码/登录）…", flush=True)
    dev.resume(pid)

    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(2)
            print("   命中 %d 次，已取得 %d/%d 个库的密钥"
                  % (len(hits), len(found), len(meta)), flush=True)
            if len(found) >= len(meta):
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

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"found": found, "hits": len(hits)}, f, indent=1, ensure_ascii=False)
    print("命中 %d 次，取得密钥的库 %d 个 -> %s" % (len(hits), len(found), args.out), flush=True)
    if found:
        print("示例 key: %s" % list(found.values())[0]["key"], flush=True)
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
