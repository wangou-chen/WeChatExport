"""S5-ah —— hook AES-256 密钥扩展函数入口，读取其入参（密钥指针）

依据（实测 85_dump_aes_code.py 输出的字节）：
  Weixin.dll RVA 0x5936EDA 处是 AES 密钥扩展函数序言：
      sub rsp,8 / mov rax,-1 / test rcx,rcx / test r8,r8 ... 
      随后 7 个 aeskeygenassist（轮常量 01 02 04 08 10 20 40）→ 标准 AES-256 密钥扩展
  该函数入参（x64 调用约定）：
      rcx = 输出轮密钥缓冲（round keys，长度 > 240B，前 32B 即原始密钥）
      rdx = 轮数（10/12/14）
      r8  = 输入密钥指针（32B 原始密钥）
  因此 hook 该入口，读 r8（或 rcx）指向的 32 字节，即 SQLCipher 的 enc_key。

本脚本：
  1. attach 进程，取 Weixin.dll 基址；
  2. 在入口挂 Interceptor（只读寄存器指向的内存，零哈希开销）；
  3. 命中即 dump rcx/rdx/r8/r9 指向的缓冲区，并用 page-1 HMAC 预言机验证候选；
  4. 打印 `*** KEY` 即成功。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe -u 86_hook_aes_keyexp.py --pid N --db <db> [--seconds 90]
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

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
KEYEXP_RVA = "0x5936EDA"      # AES-256 密钥扩展入口（85 号 dump 得出）

JS_TMPL = r"""
const BASE = ptr("%(base)s");
const ENTRY = BASE.add(ptr("%(rva)s").toInt32());
let hits = 0;
const MAXSEND = %(max_send)d;

function phex(p, n) {
    if (p.isNull()) return "";
    try {
        return Array.from(new Uint8Array(p.readByteArray(n)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { return "FAIL"; }
}
try {
    Interceptor.attach(ENTRY, {
        onEnter: function () {
            const c = this.context;
            if (hits >= MAXSEND) return;
            hits++;
            send({
                stage: "hit",
                n: hits,
                rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                r8: c.r8.toString(), r9: c.r9.toString(),
                rcx_64: phex(c.rcx, 64),
                rdx_64: phex(c.rdx, 64),
                r8_64: phex(c.r8, 64),
                r9_64: phex(c.r9, 64),
                ret: this.returnAddress.toString(),
                stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 8).map(function (a) { return a.toString(); })
            });
        }
    });
    send({ stage: "ready", entry: ENTRY.toString(), pid: Process.id });
} catch (e) {
    send({ stage: "err", msg: "attach 失败: " + e });
}
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
    ap.add_argument("--base", default="")
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--max-send", type=int, default=80)
    ap.add_argument("--out", default=os.path.join(BASE, "keys", "key_from_keyexp.json"))
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("目标 salt=%s  目标入口 RVA=%s" % (salt.hex(), KEYEXP_RVA), flush=True)

    pid = args.pid
    if not pid:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin -ErrorAction SilentlyContinue |"
                            "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                           capture_output=True, text=True, timeout=30)
        pid = int((r.stdout or "0").strip() or 0)
    dev = frida.get_local_device()

    # 取 Weixin.dll 基址（用 frida 自带接口，避免硬编码）
    session_tmp = dev.attach(pid)
    base_holder = {}

    probe = session_tmp.create_script(
        'try { const m = Process.getModuleByName("Weixin.dll"); send({base: m.base.toString()}); }'
        ' catch (e) { send({err: "" + e}); }')
    probe.on("message", lambda m, d: base_holder.update(m.get("payload") or {}))
    probe.load()
    time.sleep(1.5)
    try:
        probe.unload()
    except Exception:                                              # noqa: BLE001
        pass
    session_tmp.detach()

    base = args.base or base_holder.get("base")
    if not base:
        raise SystemExit("未能取得 Weixin.dll 基址: %s" % base_holder)
    print("attach pid=%d Weixin.dll base=%s" % (pid, base), flush=True)

    session = dev.attach(pid)
    script = session.create_script(JS_TMPL % {"base": base, "rva": KEYEXP_RVA,
                                              "max_send": args.max_send})
    hits = []
    confirmed = []

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "ready":
            print("hook 已装在 %s" % p.get("entry"), flush=True)
            return
        if st == "err":
            print("ERR %s" % p.get("msg"), flush=True)
            return
        if st != "hit":
            return
        hits.append(p)
        print("HIT#%s rcx=%s r8=%s" % (p.get("n"), p.get("rcx"), p.get("r8")), flush=True)
        print("   r8_64 =%s" % p.get("r8_64"), flush=True)
        print("   rcx_64=%s" % p.get("rcx_64"), flush=True)
        for regname, blob in (("r8", p.get("r8_64")), ("rcx", p.get("rcx_64")),
                              ("rdx", p.get("rdx_64")), ("r9", p.get("r9_64"))):
            for off, kh in verify(mac_salt, mac_msg, expected, blob):
                print("   *** KEY from %s+%d: %s" % (regname, off, kh), flush=True)
                confirmed.append({"reg": regname, "off": off, "key": kh,
                                  "ret": p.get("ret"), "stack": p.get("stack")})
        if confirmed:
            print("   key 已确认", flush=True)

    script.on("message", on_msg)
    script.load()
    print("等待密钥扩展被调用（请在微信里点开几个旧会话）…", flush=True)
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
    print("命中 %d 次，确认 key %d 个 -> %s" % (len(hits), len(confirmed), args.out), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
