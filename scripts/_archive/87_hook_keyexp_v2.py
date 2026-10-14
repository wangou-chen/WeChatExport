"""S5-ai —— hook AES-256 密钥扩展（改进落点）读入参

上一版问题：Interceptor.attach(0x5936EDA) 报
  "unable to intercept function at ...; please file a bug"
（Frida 无法在该处建立 trampoline / 反汇编边界判定失败）。

本版改为在函数内多条指令上分别尝试挂载，谁成功用谁；寄存器在入口后未被改写，
因此读到 rcx/rdx/r8/r9 与在入口读等价。候选 RVA（依据 85 号 dump 的字节）：

  0x5936EDA  sub rsp,8                 (入口，Frida 挂不上)
  0x5936EE2  test rcx,rcx              ← 首选
  0x5936EE5  jz rel32
  0x5936EEB  test r8,r8                ← 次选（确认 r8 = 输入密钥指针）
  0x5936F4E  aeskeygenassist xmm1,xmm0,1   ← 兜底（密钥扩展第一轮常量 1）

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python -u 87_hook_keyexp_v2.py --pid N --db <db> [--seconds 90]
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
CAND_RVAS = ["0x5936EE2", "0x5936EEB", "0x5936F4E", "0x5936EE5"]

JS_TMPL = r"""
const BASE = ptr("%(base)s");
const CAND = %(cands)s;
let hits = 0;
const MAXSEND = %(max_send)d;
let okOff = null;

function phex(p, n) {
    if (!p || p.isNull()) return "";
    try {
        return Array.from(new Uint8Array(p.readByteArray(n)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { return "FAIL"; }
}
function tryAttach(off) {
    const target = BASE.add(ptr(off).toInt32());
    try {
        Interceptor.attach(target, {
            onEnter: function () {
                if (hits >= MAXSEND) return;
                hits++;
                const c = this.context;
                send({ stage: "hit", off: off, n: hits,
                       rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                       r8: c.r8.toString(), r9: c.r9.toString(),
                       rcx_64: phex(c.rcx, 64), rdx_64: phex(c.rdx, 64),
                       r8_64: phex(c.r8, 64), r9_64: phex(c.r9, 64),
                       rsp_256: phex(c.rsp, 256),
                       ret: this.returnAddress.toString(),
                       stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                           .slice(0, 8).map(function (a) { return a.toString(); }) });
            }
        });
        send({ stage: "attached", off: off });
        return true;
    } catch (e) {
        send({ stage: "attachfail", off: off, msg: "" + e });
        return false;
    }
}
let any = false;
for (let i = 0; i < CAND.length; i++) {
    if (tryAttach(CAND[i])) { any = true; break; }
}
send({ stage: "ready", any: any, pid: Process.id });
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
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--max-send", type=int, default=60)
    ap.add_argument("--out", default=os.path.join(BASE, "keys", "key_from_keyexp.json"))
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
    dev = frida.get_local_device()
    s0 = dev.attach(pid)
    holder = {}
    probe = s0.create_script(
        'try { const m = Process.getModuleByName("Weixin.dll"); send({base: m.base.toString()}); }'
        ' catch (e) { send({err: "" + e}); }')
    probe.on("message", lambda m, d: holder.update(m.get("payload") or {}))
    probe.load()
    time.sleep(1.5)
    try:
        probe.unload()
    except Exception:                                              # noqa: BLE001
        pass
    s0.detach()
    base = holder.get("base")
    if not base:
        raise SystemExit("未取到 Weixin.dll 基址: %s" % holder)
    print("attach pid=%d base=%s" % (pid, base), flush=True)

    session = dev.attach(pid)
    script = session.create_script(JS_TMPL % {"base": base,
                                              "cands": json.dumps(CAND_RVAS),
                                              "max_send": args.max_send})
    hits = []
    confirmed = []
    state = {"ready": False}

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st in ("ready", "attached", "attachfail"):
            print(json.dumps(p, ensure_ascii=False), flush=True)
            if st == "ready":
                state["ready"] = True
            return
        if st != "hit":
            return
        hits.append(p)
        print("HIT off=%s r8=%s rcx=%s" % (p.get("off"), p.get("r8"), p.get("rcx")), flush=True)
        print("   r8_64 =%s" % p.get("r8_64"), flush=True)
        print("   rcx_64=%s" % p.get("rcx_64"), flush=True)
        for reg, blob in (("r8", p.get("r8_64")), ("rcx", p.get("rcx_64")),
                          ("rdx", p.get("rdx_64")), ("rsp", p.get("rsp_256"))):
            for off, kh in verify(mac_salt, mac_msg, expected, blob):
                print("   *** KEY from %s+%d: %s" % (reg, off, kh), flush=True)
                confirmed.append({"reg": reg, "off": off, "key": kh,
                                  "hit_off": p.get("off"), "ret": p.get("ret"),
                                  "stack": p.get("stack")})
        if confirmed:
            print("   key 已确认", flush=True)

    script.on("message", on_msg)
    script.load()
    print("等待密钥扩展调用（请在微信里点开几个旧会话）…", flush=True)
    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(2)
            print("   命中 %d 次，确认 %d" % (len(hits), len(confirmed)), flush=True)
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
    print("命中 %d 次，确认 key %d -> %s" % (len(hits), len(confirmed), args.out), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
