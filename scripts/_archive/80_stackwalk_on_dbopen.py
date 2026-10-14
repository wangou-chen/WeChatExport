"""S5-ab —— 不依赖版本偏移：hook CreateFileW，抓「微信打开 *.db」时的调用栈与寄存器

背景（实测）：
  * 4.1.12.26 的 codec 偏移 0x3486140 在 4.1.13.65 上落在指令中间，本机现已升级到 4.1.15.13，
    跨两个大版本后偏移已不可用 → 改为运行时不依赖偏移的定位。
  * 主进程命令行 "Weixin.exe --scene=taskbarpins"，已确认加载 202MB 的 Weixin.dll。

做法：
  1. attach 到正在运行的微信主进程（取内存最大的 Weixin 进程）；
  2. hook kernel32!CreateFileW / CreateFileA，命中路径含 ".db" 时：
       - dump 关键寄存器（rcx/rdx/r8/r9）与调用栈（Thread.backtrace）；
       - 扫描调用方若干栈帧范围内的内存，逐 4 字节偏移取 32 字节候选；
       - 用 page-1 HMAC 预言机验证（误判 2^-512），命中即打印 key。
  3. 汇总所有命中点，供下一步精确定位 codec 函数。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python -u 80_stackwalk_on_dbopen.py --db <db> [--seconds 180] [--out <json>]
"""
import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import time

import frida

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032

JS = r"""
function phex(p, n) {
    try {
        return Array.from(new Uint8Array(p.readByteArray(n)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { return "FAIL"; }
}
function findExport(mods, fn) {
    for (let i = 0; i < mods.length; i++) {
        try { return Process.getModuleByName(mods[i]).getExportByName(fn); } catch (e) {}
    }
    return null;
}
const seen = {};
let hits = 0;
["CreateFileW", "CreateFileA"].forEach(function (name) {
    const addr = findExport(["kernel32.dll", "KERNEL32.DLL", "KernelBase.dll"], name);
    if (!addr) { send({ stage: "missing", api: name }); return; }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            const p = args[0];
            let path = "";
            try { path = (name === "CreateFileW") ? p.readUtf16String() : p.readAnsiString(); }
            catch (e) { path = ""; }
            this.isDb = path ? /\.db$/i.test(path) : false;
            this.path = path;
        },
        onLeave: function (retval) {
            if (!this.isDb) return;
            const h = retval.toString();
            if (h === "0xffffffffffffffff" || h === "-1") return;
            const key = this.path;
            if (seen[key]) return;
            seen[key] = true;
            hits++;
            const c = this.context;
            // 调用方栈帧扫描：从 rsp 起 4KB，逐 4 字节取 32 字节候选
            const chunks = {};
            chunks.rsp_4k = phex(c.rsp, 4096);
            chunks.rbp_2k = (c.rbp && !c.rbp.isNull()) ? phex(c.rbp.sub(512), 2048) : "";
            let bt = [];
            try {
                bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 16)
                    .map(function (a) { return a.toString(); });
            } catch (e) { bt = ["ERR:" + e]; }
            send({ stage: "dbopen", path: this.path, handle: h,
                   rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                   r8: c.r8.toString(), r9: c.r9.toString(),
                   ret: this.returnAddress.toString(), stack: bt,
                   chunks: chunks });
        }
    });
    send({ stage: "hooked", api: name });
});
send({ stage: "ready", pid: Process.id });
"""


def verify(mac_salt, mac_msg, expected, blob, stride=4):
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    if not blob or blob == "FAIL":
        return []
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return []
    out = []
    for off in range(0, max(1, len(raw) - 31), stride):
        cand = raw[off:off + 32]
        if len(cand) < 32:
            break
        mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
        if hmac_new(mk, mac_msg, sha512).digest() == expected:
            out.append((off, cand.hex()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--seconds", type=int, default=180)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("salt=%s" % salt.hex(), flush=True)

    dev = frida.get_local_device()
    cand = [p for p in dev.enumerate_processes()
            if p.name.lower().startswith("weixin")]
    if not cand:
        raise SystemExit("未找到 Weixin 进程")
    # 用 powershell 取内存最大的 Weixin 进程
    import subprocess
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-Process Weixin -ErrorAction SilentlyContinue |"
                        "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                       capture_output=True, text=True, timeout=30)
    pid = int((r.stdout or "0").strip() or 0) or cand[-1].pid
    print("attach pid=%d" % pid, flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS)
    opens = []
    confirmed = []

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st in ("ready", "hooked", "missing"):
            print(json.dumps(p, ensure_ascii=False), flush=True)
            return
        if st != "dbopen":
            print(json.dumps(p, ensure_ascii=False), flush=True)
            return
        opens.append(p)
        print("DBOPEN %s  ret=%s" % (p.get("path"), p.get("ret")), flush=True)
        for i, fr in enumerate(p.get("stack", [])[:8]):
            print("    #%d %s" % (i, fr), flush=True)
        for cname, blob in (p.get("chunks") or {}).items():
            for off, kh in verify(mac_salt, mac_msg, expected, blob):
                print("   *** KEY from %s+%d: %s" % (cname, off, kh), flush=True)
                confirmed.append({"chunk": cname, "off": off, "key": kh})
        if confirmed:
            print("   key 已确认，停止等待", flush=True)

    script.on("message", on_msg)
    script.load()
    print("等待微信打开 *.db（请在微信里点开几个旧会话/上翻历史）…", flush=True)
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
    session.detach()

    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        rec = {"db": args.db, "salt": salt.hex(),
               "enc_key": confirmed[0]["key"] if confirmed else None,
               "confirmed": confirmed, "opens": opens}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2, ensure_ascii=False)
        print("-> %s" % args.out, flush=True)
    print("db 打开事件=%d 命中 key=%d" % (len(opens), len(confirmed)), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
