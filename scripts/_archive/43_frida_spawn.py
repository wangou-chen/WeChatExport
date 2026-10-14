"""S5-m —— Frida spawn 微信并在启动期捕获 bcrypt 对称密钥生成

背景（实测）：微信主进程运行 14 小时，bcrypt!BCryptGenerateSymmetricKey 已不再被调用，
密钥只在**启动期**生成一次，attach 到已运行进程永远抓不到。故改为：
  device.spawn(Weixin.exe) -> attach -> 安装 hook -> resume -> 等待启动 -> 抓全部 AES 密钥
随后用 page-1 HMAC 预言机在抓到的候选里筛出真正的 DB key。

注意：spawn 会重启微信（等同于手动退出再打开）。不涉及扫码的情况下会自动登录。

输出：logs\\frida_spawn_keys.jsonl

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe 43_frida_spawn.py [--exe <Weixin.exe>] [--seconds 180] [--no-resume]
"""
import argparse
import json
import os
import sys
import time

import frida

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
LOG = os.path.join(BASE, "logs")
DEFAULT_EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"

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
                if (e.name === "BCryptGenerateSymmetricKey") {
                    const cb = args[3].toInt32();
                    const sec = toHex(args[4], cb);
                    this.payload = { api: e.name, cb: cb, secret_hex: sec, keyobj: args[2].toString() };
                } else {
                    const cb = args[3].toInt32();
                    const sec = toHex(args[4], cb);
                    this.payload = { api: e.name, cb: cb, secret_hex: sec, blob: args[5].toString() };
                }
                this.payload.ret = this.returnAddress.toString();
                this.payload.stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 10).map(function (a) { return a.toString(); });
            },
            onLeave: function (retval) {
                if (!this.payload) return;
                this.payload.status = retval.toInt32();
                if (!this.payload.secret_hex && this.payload.keyobj && this.payload.keyobj !== "0x0") {
                    this.payload.keyobj_hex = "";
                }
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
    ap.add_argument("--seconds", type=int, default=180)
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()
    os.makedirs(LOG, exist_ok=True)
    out = os.path.join(LOG, "frida_spawn_keys.jsonl")
    fh = open(out, "a", encoding="utf-8")

    dev = frida.get_local_device()
    print("spawning %s" % args.exe)
    pid = dev.spawn([args.exe])
    print("spawned pid=%d" % pid)
    session = dev.attach(pid)
    script = session.create_script(JS)
    stats = {"n": 0}

    def on_message(m, data):
        p = m.get("payload") or {}
        if p.get("stage") == "install":
            print("hooked=%s" % p.get("hooked"))
            return
        stats["n"] += 1
        fh.write(json.dumps(p, ensure_ascii=False) + "\n")
        fh.flush()
        if len(p.get("secret_hex", "")) >= 32:
            print("[%s] cb=%s secret=%s ret=%s" % (p["api"], p["cb"], p["secret_hex"], p.get("ret")))
        else:
            print("[%s] cb=%s secret_len=%d status=%s" % (p["api"], p["cb"],
                                                          len(p.get("secret_hex", "")) // 2, p.get("status")))

    script.on("message", on_message)
    script.load()
    if not args.no_resume:
        dev.resume(pid)
        print("resumed; 注意扫码登录窗口（若需要），等待密钥生成 …")
    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(1)
            if stats["n"] and time.time() - t0 > 30:
                pass
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
    print("captured events: %d" % stats["n"])
    print("-> %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
