"""S5-n —— 用 bcrypt!BCryptExportKey 导出对称密钥（hook BCryptDecrypt 取 hKey）

动机（实测）：内存里找不到 32 字节原始密钥，但 bcrypt 的 key object 一定握着它。
直接 hook BCryptDecrypt/BCryptEncrypt 拿到 hKey，再在 hook 内同步调用 BCryptExportKey
导出 BCRYPT_KEY_DATA_BLOB 的前 4 字节 payload —— BCrypt 会从密钥表还原出原始密钥字节。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe -u 50_frida_exportkey.py --pid <pid> --seconds 120
"""
import argparse
import ctypes
import json
import os
import sys
import time

import frida

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
LOG = os.path.join(BASE, "logs")
kernel32 = ctypes.windll.kernel32

JS = r"""
function phex(p, n) {
    try {
        const u8 = new Uint8Array(p.readByteArray(n));
        let s = "";
        for (let i = 0; i < u8.length; i++) s += ("0" + u8[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return "ERR:" + e; }
}

let expAddr = null;
["bcrypt.dll", "BCRYPT.dll"].forEach(function (m) {
    try { expAddr = expAddr || Process.getModuleByName(m).getExportByName("BCryptExportKey"); } catch (e) {}
});
if (!expAddr) { try { expAddr = Module.getExportByName("bcrypt.dll", "BCryptExportKey"); } catch (e) {} }

const exportKey = expAddr ? new NativeFunction(expAddr, "int",
    ["pointer", "pointer", "pointer", "uint32", "pointer", "uint32", "pointer", "uint32"]) : null;

const BLOB_TYPE = Memory.allocUtf16String("KeyDataBlob");
const seen = {};
let count = 0;
let dumped = 0;

function tryExport(hKey, tag) {
    if (!exportKey) return;
    try {
        const buf = Memory.alloc(64);
        const nOut = Memory.alloc(4);
        buf.writeU32(32);                    // BCRYPT_KEY_DATA_BLOB_HEADER.dwMagic 占位
        let st = exportKey(hKey, BLOB_TYPE, buf, 64, null, 0, nOut, 0);
        const need = nOut.readU32();
        st = exportKey(hKey, BLOB_TYPE, buf, 64, buf, 64, nOut, 0);
        const total = nOut.readU32();
        const magic = buf.readU32();
        const cbKey = buf.add(4).readU32();
        const hdr = buf.readByteArray(Math.min(total, 64));
        const keyHex = phex(buf.add(8), Math.min(cbKey, 32));
        const sig = tag + ":" + st + ":" + keyHex;
        if (seen[sig]) return;
        seen[sig] = true;
        dumped++;
        send({
            api: tag, status: st, need: need, total: total,
            magic: magic, cbKey: cbKey, key_hex: keyHex,
            header_hex: Array.from(new Uint8Array(hdr)).map(function (b) {
                return ("0" + b.toString(16)).slice(-2);
            }).join("")
        });
    } catch (e) {
        send({ api: tag, err: "" + e });
    }
}

["BCryptDecrypt", "BCryptEncrypt"].forEach(function (name) {
    let addr = null;
    try { addr = Process.getModuleByName("bcrypt.dll").getExportByName(name); } catch (e) {}
    if (!addr) { send({ info: name + " 未找到" }); return; }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            count++;
            if (dumped < 40) tryExport(args[0], name);
        }
    });
});

send({ stage: "ready", exportFound: !!exportAddr, hooked: (exportAddr ? 1 : 0) });
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--seconds", type=int, default=120)
    args = ap.parse_args()
    out = os.path.join(LOG, "frida_exportkey.jsonl")
    fh = open(out, "a", encoding="utf-8")

    dev = frida.get_local_device()
    pid = args.pid
    if not pid:
        cand = [p for p in dev.enumerate_processes() if p.name.lower().startswith("weixin")]
        cand.sort(key=lambda p: p.pid)
        pid = cand[-1].pid if cand else 0
    if not pid:
        raise SystemExit("未找到 Weixin 进程")
    print("attach pid=%d" % pid, flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS)

    def on_message(m, data):
        p = m.get("payload") or {}
        if p.get("stage") == "ready":
            print("ready: %s" % json.dumps(p, ensure_ascii=False), flush=True)
            return
        fh.write(json.dumps(p, ensure_ascii=False) + "\n")
        fh.flush()
        if p.get("key_hex"):
            print("KEY api=%s cb=%s key=%s" % (p.get("api"), p.get("cbKey"), p["key_hex"]), flush=True)
        elif p.get("err") or p.get("info"):
            print(json.dumps(p, ensure_ascii=False), flush=True)

    script.on("message", on_message)
    script.load()
    # 触发一次数据库读取（我们自己读磁盘不会进微信进程，所以只等它的常规活动）
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
    session.detach()
    fh.close()
    print("-> %s" % out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
