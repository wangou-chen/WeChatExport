"""S5-j (2/2) —— Frida hook：捕获 Weixin 进程内生成的所有 AES 对称密钥。

原理：微信数据库（SQLCipher/WCDB）必须调用 bcrypt!BCryptGenerateSymmetricKey 建立 AES 上下文，
      该函数的参数即为 master key：
        x64: rcx=hAlgorithm, rdx=phKey, r8=hKeyObject, r9=cbSecret, [rsp+0x28]=pbSecret
      脚本同时 hook BCryptImportKey，并追加调用栈，便于区分「数据库密钥」与其他 AES 用途。

输出：logs\\frida_aes_keys.jsonl（每行一条 {t, api, cb, secret_hex, ret, stack}）

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python 41_frida_aeskeys.py --pid 16056 [--seconds 180]
"""
import argparse
import json
import os
import sys
import time

import frida

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(BASE, "logs")

JS = r"""
const seen = {};
function hex(p, n) {
    if (p.isNull() || n <= 0 || n > 4096) return "";
    try { return Array.from(new Uint8Array(p.readByteArray(n))).map(b => ("0" + b.toString(16)).slice(-2)).join(""); }
    catch (e) { return "READFAIL"; }
}
function hits() {
    let mod;
    try { mod = Process.getModuleByName("bcrypt.dll"); } catch (e) { send({err: "bcrypt.dll 未加载: " + e}); return 0; }
    const names = ["BCryptGenerateSymmetricKey", "BCryptImportKey", "BCryptDeriveKey"];
    let n = 0;
    names.forEach(function (name) {
        let addr = null;
        mod.enumerateExports().forEach(function (e) { if (e.name === name) addr = e.address; });
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                const cb = args[3].toInt32();
                let secret = "";
                if (this.api === undefined) { this.api = name; }
                if (name === "BCryptGenerateSymmetricKey") {
                    secret = hex(args[4], cb);
                } else {
                    secret = hex(args[3], args[5] ? args[5].toInt32() : 32);
                }
                const key = name + ":" + secret.slice(0, 16);
                if (seen[key]) return;
                seen[key] = true;
                send({
                    api: name,
                    cb: cb,
                    secret_hex: secret,
                    keyobj: args[2].toString(),
                    ret: this.returnAddress.toString(),
                    stack: Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8).map(function (a) { return a.toString(); })
                });
            }
        });
        n++;
    });
    return n;
}
const hooked = hits();
send({hooked: hooked});
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--name", default="")
    ap.add_argument("--seconds", type=int, default=120)
    args = ap.parse_args()
    os.makedirs(LOG, exist_ok=True)
    out = os.path.join(LOG, "frida_aes_keys.jsonl")
    fh = open(out, "a", encoding="utf-8")

    dev = frida.get_local_device()
    procs = dev.enumerate_processes()
    cand = [p for p in procs if args.name.lower() in p.name.lower()] if args.name \
        else [p for p in procs if p.name.lower() == "weixin"]
    if not cand and args.pid:
        pid = args.pid
    else:
        pid = args.pid or cand[-1].pid
    session = dev.attach(pid)
    print("attached pid=%d" % pid)

    counts = {}
    script = session.create_script(JS)

    def on_message(m, data):
        p = m.get("payload") or {}
        if "hooked" in p:
            print("hooked functions: %d" % p["hooked"])
            return
        if "err" in p:
            print("ERR", p["err"])
            return
        counts[p.get("api", "?")] = counts.get(p.get("api", "?"), 0) + 1
        fh.write(json.dumps(p, ensure_ascii=False) + "\n")
        fh.flush()
        if len(p.get("secret_hex", "")) >= 32:
            print("[%s] cb=%s secret=%s" % (p["api"], p["cb"], p["secret_hex"][:80]))

    script.on("message", on_message)
    script.load()
    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    script.unload()
    session.detach()
    fh.close()
    print("captured: %s" % counts)
    print("-> %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
