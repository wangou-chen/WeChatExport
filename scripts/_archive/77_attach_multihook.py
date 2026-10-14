"""S5-z —— 对「已在运行的微信」attach 并对 codec 偏移邻域挂多点 hook

用途：微信运行期间若再次打开/切换数据库（切换会话、收发消息、群操作等），
      codec 配置函数会重新触发，此时 hook 即可抓到 key。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe -u 77_attach_multihook.py --db <db> [--pid N] [--seconds 180]
"""
import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import time

import frida

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032

JS_TMPL = r"""
const LO = %(lo)s, HI = %(hi)s, STEP = %(step)s;
let mod = null;
try { mod = Process.getModuleByName("Weixin.dll"); } catch (e) {}
if (!mod) { send({ stage: "err", msg: "Weixin.dll 未加载" }); }
else {
    send({ stage: "mod", base: mod.base.toString(), size: mod.size, pid: Process.id });
    const probes = [];
    let installed = 0, failed = 0;
    for (let off = LO; off <= HI; off += STEP) {
        const target = mod.base.add(off);
        let pro = "";
        try {
            pro = Array.from(new Uint8Array(target.readByteArray(8)))
                .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
        } catch (e) { pro = "READFAIL"; }
        probes.push({ off: off, prologue: pro });
        try {
            const myOff = off;
            Interceptor.attach(target, {
                onEnter: function () {
                    const c = this.context;
                    function dump(p, n) {
                        try {
                            return Array.from(new Uint8Array(p.readByteArray(n)))
                                .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
                        } catch (e) { return "FAIL"; }
                    }
                    send({ stage: "hit", off: myOff,
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
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--lo", default="0x3486100")
    ap.add_argument("--hi", default="0x3486180")
    ap.add_argument("--step", type=int, default=16)
    ap.add_argument("--seconds", type=int, default=180)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]

    dev = frida.get_local_device()
    pid = args.pid
    if not pid:
        cand = [p for p in dev.enumerate_processes() if p.name.lower().startswith("weixin")]
        if not cand:
            raise SystemExit("未找到 Weixin 进程")
        # 取内存最大的那个（主进程）
        pid = cand[-1].pid
    print("attach pid=%d salt=%s" % (pid, salt.hex()), flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS_TMPL % {"lo": args.lo, "hi": args.hi, "step": args.step})
    hits = []
    confirmed = []

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "mod":
            print("Weixin.dll base=%s size=%s pid=%s" % (p["base"], p["size"], p["pid"]), flush=True)
        elif st == "installed":
            print("installed=%s failed=%s" % (p["installed"], p["failed"]), flush=True)
            for pr in p.get("probes", [])[:10]:
                print("   off=0x%X prologue=%s" % (pr["off"], pr["prologue"]), flush=True)
        elif st == "hit":
            hits.append(p)
            print("HIT off=0x%X" % p.get("off", 0), flush=True)
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
    t0 = time.time()
    print("waiting %ds（请在微信里切换几个会话/打开群聊，促使 DB 重开）" % args.seconds, flush=True)
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
    session.detach()
    if confirmed and args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"db": args.db, "salt": salt.hex(), "enc_key": confirmed[0][2],
                       "source": confirmed[0][0]}, f, indent=2)
        print("-> %s" % args.out, flush=True)
    print("hits=%d confirmed=%d" % (len(hits), len(confirmed)), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
