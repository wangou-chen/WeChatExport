"""S5-aj —— 静态找「AES 密钥扩展函数」的调用者，只在调用者上挂钩（避开热循环，降低崩溃风险）

背景：
  * 87 号在 AES 密钥扩展函数**内部**（test/jz/aeskeygenassist）挂 Interceptor，导致微信崩溃
    —— 这些位置在热路径/循环体内，Frida 改写指令建 trampoline 会破坏时序。
  * 85 号 dump 已确定：RVA 0x5936EDA 是 AES-256 密钥扩展函数入口，入参 r8 = 输入密钥指针。

本脚本：
  1. 只读扫描 Weixin.dll 代码段，找形如 `E8 rel32` 且 rel32 指向 0x5936EDA 的调用点（caller RVA）；
  2. 对每个 caller 的**函数入口**（向前找 int3 对齐填充边界）挂钩，命中即 dump rcx/rdx/r8/r9 与栈；
  3. 用 page-1 HMAC 预言机验证候选 32 字节。
  调用者不在加密热循环里，开库时才执行，hook 安全性显著高于函数内部。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe -u 88_find_callers_keyexp.py --pid N --db <db> [--seconds 120]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import subprocess
import sys
import time

import frida

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
KEYEXP_RVA = 0x5936EDA
kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010


def readmem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def find_callers(h, base, scan_lo=0x1000, scan_hi=0x9000000):
    """扫描 [scan_lo, scan_hi) 内的 E8 rel32，返回 call 目标为 KEYEXP_RVA 的调用点 RVA 列表。"""
    target = base + KEYEXP_RVA
    callers = []
    step = 4 * 1024 * 1024
    off = scan_lo
    while off < scan_hi:
        n = min(step, scan_hi - off)
        data = readmem(h, base + off, n)
        if data:
            i = data.find(b"\xe8")
            while i >= 0 and i + 5 <= len(data):
                rel = struct.unpack_from("<i", data, i + 1)[0]
                dst = base + off + i + 5 + rel
                if dst == target:
                    callers.append(off + i)
                i = data.find(b"\xe8", i + 1)
        off += n
    return callers


def entry_before(h, base, rva, max_back=0x200):
    """向前找 int3 填充边界，返回函数入口 RVA 候选。"""
    data = readmem(h, base + rva - max_back, max_back + 16)
    if not data:
        return None
    pat = b"\xcc"
    cands = []
    for i in range(len(data) - 4, 0, -1):
        if data[i:i + 4] == b"\xcc\xcc\xcc\xcc":
            cands.append(rva - max_back + i + 4)
            break
    return cands[0] if cands else None


JS_TMPL = r"""
const BASE = ptr("%(base)s");
const ENTRIES = %(entries)s;
const CALLSITES = %(callsites)s;
let hits = 0;
const MAXSEND = %(max_send)d;
function phex(p, n) {
    if (!p || p.isNull()) return "";
    try {
        return Array.from(new Uint8Array(p.readByteArray(n)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { return "FAIL"; }
}
function attachAt(rva, kind) {
    const t = BASE.add(ptr(rva).toInt32());
    try {
        Interceptor.attach(t, {
            onEnter: function () {
                if (hits >= MAXSEND) return;
                hits++;
                const c = this.context;
                send({ stage: "hit", kind: kind, rva: rva, n: hits,
                       rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                       r8: c.r8.toString(), r9: c.r9.toString(),
                       rcx_64: phex(c.rcx, 64), rdx_64: phex(c.rdx, 64),
                       r8_64: phex(c.r8, 64), r9_64: phex(c.r9, 64),
                       rsp_256: phex(c.rsp, 256),
                       ret: this.returnAddress.toString(),
                       stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                           .slice(0, 10).map(function (a) { return a.toString(); }) });
            }
        });
        send({ stage: "attached", kind: kind, rva: rva });
        return true;
    } catch (e) {
        send({ stage: "attachfail", kind: kind, rva: rva, msg: "" + e });
        return false;
    }
}
let n = 0;
for (let i = 0; i < ENTRIES.length; i++) { if (attachAt(ENTRIES[i], "caller-entry")) n++; }
for (let i = 0; i < CALLSITES.length && n < 8; i++) { if (attachAt(CALLSITES[i], "callsite")) n++; }
send({ stage: "ready", attached: n, pid: Process.id });
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
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--max-send", type=int, default=40)
    ap.add_argument("--out", default=os.path.join(BASE, "keys", "key_from_caller.json"))
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("目标 salt=%s  keyexp RVA=0x%X" % (salt.hex(), KEYEXP_RVA), flush=True)

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
    base = int(holder.get("base", "0"), 16)
    if not base:
        raise SystemExit("未取到基址: %s" % holder)
    print("pid=%d base=0x%X" % (pid, base), flush=True)

    h = kernel32.OpenProcess(PQI | PVR, False, pid)
    callers = find_callers(h, base)
    entries = []
    for c in callers[:20]:
        e = entry_before(h, base, c)
        if e:
            entries.append(e)
    kernel32.CloseHandle(h)
    print("找到调用点 %d 个: %s" % (len(callers), ["0x%X" % c for c in callers[:10]]), flush=True)
    print("对应函数入口 %d 个: %s" % (len(entries), ["0x%X" % e for e in entries[:10]]), flush=True)
    if not callers:
        print("未找到调用者 —— 密钥扩展可能是内联调用（编译器内联），需要换定位方式", flush=True)

    session = dev.attach(pid)
    script = session.create_script(JS_TMPL % {
        "base": "0x%X" % base,
        "entries": json.dumps(["0x%X" % e for e in entries]),
        "callsites": json.dumps(["0x%X" % c for c in callers[:8]]),
        "max_send": args.max_send,
    })
    hits = []
    confirmed = []

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st in ("ready", "attached", "attachfail"):
            print(json.dumps(p, ensure_ascii=False), flush=True)
            return
        if st != "hit":
            return
        hits.append(p)
        print("HIT kind=%s rva=%s r8=%s" % (p.get("kind"), p.get("rva"), p.get("r8")), flush=True)
        print("   r8_64 =%s" % p.get("r8_64"), flush=True)
        print("   rcx_64=%s" % p.get("rcx_64"), flush=True)
        for reg, blob in (("r8", p.get("r8_64")), ("rcx", p.get("rcx_64")),
                          ("rdx", p.get("rdx_64")), ("rsp", p.get("rsp_256"))):
            for off, kh in verify(mac_salt, mac_msg, expected, blob):
                print("   *** KEY from %s+%d: %s" % (reg, off, kh), flush=True)
                confirmed.append({"reg": reg, "off": off, "key": kh,
                                  "kind": p.get("kind"), "rva": p.get("rva"),
                                  "ret": p.get("ret"), "stack": p.get("stack")})
        if confirmed:
            print("   key 已确认", flush=True)

    script.on("message", on_msg)
    script.load()
    print("等待调用者命中（请点开 1-2 个旧会话）…", flush=True)
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
                   "confirmed": confirmed, "hits": hits,
                   "callers": ["0x%X" % c for c in callers],
                   "entries": ["0x%X" % e for e in entries]}, f, indent=1, ensure_ascii=False)
    print("命中 %d 次，确认 key %d -> %s" % (len(hits), len(confirmed), args.out), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
