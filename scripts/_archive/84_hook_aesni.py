"""S5-af —— hook AES-NI 密钥扩展指令，抓 xmm 寄存器与栈，反推主密钥

依据（实测，见 logs/aes_ni.json）：
  Weixin.dll 内 AES 实现集中在 RVA 0x5932B90..0x5936FD0：
    AESENC 0x5932B9A..   AESDEC 0x5932BEA..   AESIMC 0x5936EA2..
    AESKEYGENASSIST 0x5936F4E..（31 处）
  AESKEYGENASSIST 每次执行时其输入即「原始密钥或上一轮轮密钥」，是抓 key 的最佳落点。

做法：
  1. attach 目标进程，取 Weixin.dll 基址（默认 0x7ffc927d0000，可用 79_list_modules.py 核对）；
  2. 在给定 RVA 列表上挂 Interceptor（只读寄存器，不做哈希，开销极小）；
  3. 命中时 send：RVA、xmm0-15 十六进制、rsp 512B、以及 rcx/rdx/r8/r9；
  4. 宿主侧对每个 xmm 值/栈块跑 page-1 HMAC 预言机（32 字节窗口，4 字节步长）。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python -u 84_hook_aesni.py --db <db> [--pid N] [--base 0x...] [--seconds 120]
"""
import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import subprocess
import sys
import time

import frida

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
DEFAULT_BASE = "0x7ffc927d0000"
# 从 logs/aes_ni.json 得到的候选 RVA（密钥扩展区 + 少量解密点）
DEFAULT_RVAS = [
    "0x5936F4E", "0x5936F59", "0x5936F64", "0x5936F6F", "0x5936F7A", "0x5936F85",
    "0x5936EA2", "0x5936EA7", "0x5936EC6",
    "0x5932B9A", "0x5932BEA", "0x5932BAB", "0x5932BFB",
]

JS_TMPL = r"""
const BASE = ptr("%(base)s");
const RVAS = %(rvas)s;
let installed = 0, failed = 0;
let sent = 0;
const MAX_SEND = %(max_send)d;

function hexOf(p, n) {
    try {
        return Array.from(new Uint8Array(p.readByteArray(n)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { return "FAIL"; }
}
function xmm(c, name) {
    try {
        const v = c[name];
        if (!v) return "";
        // XMM 寄存器在 Frida context 中以 16 字节向量暴露
        return hexOf(v, 16);
    } catch (e) { return ""; }
}

RVAS.forEach(function (rva) {
    const target = BASE.add(ptr(rva).toInt32());
    try {
        Interceptor.attach(target, {
            onEnter: function () {
                if (sent >= MAX_SEND) return;
                sent++;
                const c = this.context;
                const regs = {};
                ["xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
                 "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"]
                    .forEach(function (n) { regs[n] = xmm(c, n); });
                send({ stage: "hit", rva: rva,
                       regs: regs,
                       rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                       r8: c.r8.toString(), r9: c.r9.toString(),
                       ret: this.returnAddress.toString(),
                       stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                           .slice(0, 8).map(function (a) { return a.toString(); }),
                       rsp_512: hexOf(c.rsp, 512),
                       rsp_ptr0: (function () {
                           try { return c.rsp.readPointer().toString(); } catch (e) { return ""; }
                       })() });
            }
        });
        installed++;
    } catch (e) { failed++; }
});
send({ stage: "ready", installed: installed, failed: failed, pid: Process.id });
"""


def verify(mac_salt, mac_msg, expected, blob, stride=4):
    if not blob or blob == "FAIL":
        return []
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return []
    if len(raw) < 32:
        return []
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    out = []
    for off in range(0, len(raw) - 31, stride):
        cand = raw[off:off + 32]
        mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
        if hmac_new(mk, mac_msg, sha512).digest() == expected:
            out.append((off, cand.hex()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--max-send", type=int, default=200)
    ap.add_argument("--out", default=os.path.join(BASE, "logs", "aesni_hits.json"))
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("目标 salt=%s" % salt.hex(), flush=True)

    pid = args.pid
    if not pid:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin -ErrorAction SilentlyContinue |"
                            "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                           capture_output=True, text=True, timeout=30)
        pid = int((r.stdout or "0").strip() or 0)
    print("attach pid=%d base=%s" % (pid, args.base), flush=True)
    dev = frida.get_local_device()
    session = dev.attach(pid)
    script = session.create_script(JS_TMPL % {
        "base": args.base,
        "rvas": json.dumps(DEFAULT_RVAS),
        "max_send": args.max_send,
    })
    hits = []
    confirmed = []
    salt_prefix = salt.hex()

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "ready":
            print("ready installed=%s failed=%s" % (p.get("installed"), p.get("failed")), flush=True)
            return
        if st != "hit":
            return
        hits.append(p)
        print("HIT rva=%s  xmm0=%s" % (p.get("rva"), (p.get("regs") or {}).get("xmm0", "")[:32]),
              flush=True)
        # 1) xmm 寄存器
        for name, val in (p.get("regs") or {}).items():
            if val and val.startswith(salt_prefix):
                print("   *** salt 出现在 %s !" % name, flush=True)
            for off, kh in verify(mac_salt, mac_msg, expected, val):
                print("   *** KEY from %s+%d: %s" % (name, off, kh), flush=True)
                confirmed.append({"src": name, "off": off, "key": kh})
        # 2) 栈
        for off, kh in verify(mac_salt, mac_msg, expected, p.get("rsp_512")):
            print("   *** KEY from rsp+%d: %s" % (off, kh), flush=True)
            confirmed.append({"src": "rsp", "off": off, "key": kh})
        if confirmed:
            print("   key 已确认，可停止", flush=True)

    script.on("message", on_msg)
    script.load()
    print("等待 AES 指令命中（请在微信里点开几个旧会话、上翻历史）…", flush=True)
    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(2)
            print("   命中 %d 次" % len(hits), flush=True)
            if confirmed:
                break
    except KeyboardInterrupt:
        pass
    try:
        script.unload()
    except Exception:                                              # noqa: BLE001
        pass
    session.detach()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"db": args.db, "salt": salt.hex(),
                   "enc_key": confirmed[0]["key"] if confirmed else None,
                   "confirmed": confirmed, "hits": hits}, f, indent=1, ensure_ascii=False)
    print("命中 %d 次，确认 key %d 个 -> %s" % (len(hits), len(confirmed), args.out), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
