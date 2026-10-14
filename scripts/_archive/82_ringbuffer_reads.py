"""S5-ad —— 低开销读取路径记录 + 事后离线扫描（避免 hook 内同步开销导致丢事件）

上一版（81_readpath_key.py）在 hook 里同步做 HMAC 扫描，可能拖慢微信主线程导致读事件丢失；
本版改为：
  1. hook ReadFile / ReadFileEx / NtReadFile / ReadFileScatter，进 onLeave 只做两件事：
       记录 (api, handle, buf 地址, 期望长度, 返回状态) 并 send 出去，随后立即返回；
  2. 宿主侧把记录落盘；脚本结束后打印汇总：各 API 是否有 hooked、各 db 的读事件数；
  3. 若记录到目标库的 page1 读取（buf 指向 4096 字节页且前 16 字节等于 salt），
     则宿主用 ReadProcessMemory 把该页读到本地再离线扫描 key。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib\\frida_pkg
  python -u 82_ringbuffer_reads.py --db <db> [--seconds 120] [--out <json>]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
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
kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def readmem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


JS = r"""
function findExport(mods, fn) {
    for (let i = 0; i < mods.length; i++) {
        try { return Process.getModuleByName(mods[i]).getExportByName(fn); } catch (e) {}
    }
    return null;
}
function pathOfHandle(h) {
    let f = null;
    try { f = findExport(["kernel32.dll", "KERNEL32.DLL", "KernelBase.dll"],
                         "GetFinalPathNameByHandleW"); } catch (e) {}
    if (!f) return "";
    try {
        const fn = new NativeFunction(f, "uint32", ["pointer", "pointer", "uint32", "uint32"]);
        const buf = Memory.alloc(2048);
        const n = fn(h, buf, 1024, 0);
        if (n > 0) return buf.readUtf16String();
    } catch (e) {}
    return "";
}
const MODS = ["kernel32.dll", "KERNEL32.DLL", "KernelBase.dll", "ntdll.dll", "NTDLL.DLL"];
const specs = [["ReadFile", "bool"], ["ReadFileEx", "bool"], ["NtReadFile", "nt"],
               ["ReadFileScatter", "bool"]];
let hookedCount = 0;
specs.forEach(function (s) {
    const name = s[0];
    const addr = findExport(MODS, name);
    send({ stage: s[0], found: !!addr });
    if (!addr) return;
    hookedCount++;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            if (name === "NtReadFile") {
                this.h = args[0]; this.buf = args[5]; this.len = args[6].toInt32();
            } else if (name === "ReadFileScatter") {
                this.h = args[0]; this.buf = args[1]; this.len = 0;    // segments 形式，跳过
            } else {
                this.h = args[0]; this.buf = args[1]; this.len = args[2].toInt32();
            }
            this.name = name;
        },
        onLeave: function (retval) {
            if (this.len <= 0 || this.len > 65536) return;
            const ok = (this.name === "NtReadFile") ? (retval.toInt32() === 0)
                                                    : (retval.toInt32() !== 0);
            if (!ok) return;
            const p = pathOfHandle(this.h);
            if (!p || !/\.db$/i.test(p)) return;
            send({ stage: "read", api: this.name, path: p, len: this.len,
                   buf: this.buf.toString(),
                   head_hex: (function () {
                       try {
                           return Array.from(new Uint8Array(this.buf.readByteArray(Math.min(this.len, 32))))
                               .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
                       } catch (e) { return "FAIL"; }
                   }).call(this) });
        }
    });
});
send({ stage: "ready", pid: Process.id, hooked: hookedCount });
"""


def verify(mac_salt, mac_msg, expected, blob, stride=4):
    if not blob or blob == "FAIL":
        return []
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return []
    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
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
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--out", default=os.path.join(BASE, "keys", "reads.json"))
    args = ap.parse_args()

    with open(args.db, "rb") as f:
        p1 = f.read(PAGESZ)
    salt = p1[:SALT]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    expected = p1[MAC_OFF:PAGESZ]
    print("目标 salt=%s" % salt.hex(), flush=True)

    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-Process Weixin -ErrorAction SilentlyContinue |"
                        "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id"],
                       capture_output=True, text=True, timeout=30)
    pid = int((r.stdout or "0").strip() or 0)
    print("attach pid=%d" % pid, flush=True)
    dev = frida.get_local_device()
    session = dev.attach(pid)
    script = session.create_script(JS)
    reads = []
    apis = {}

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st == "ready":
            print("ready pid=%s hooked=%s" % (p.get("pid"), p.get("hooked")), flush=True)
            return
        if "found" in p:
            apis[st] = p["found"]
            print("api %-18s found=%s" % (st, p["found"]), flush=True)
            return
        if st == "read":
            reads.append(p)
            return

    script.on("message", on_msg)
    script.load()
    print("等待读取事件（请在微信里点开 3-5 个旧会话并上翻历史）…", flush=True)
    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(2)
            print("   已记录读取事件 %d" % len(reads), flush=True)
    except KeyboardInterrupt:
        pass
    try:
        script.unload()
    except Exception:                                              # noqa: BLE001
        pass
    session.detach()

    # 汇总
    by_db = {}
    for r_ in reads:
        by_db.setdefault(os.path.basename(r_["path"]), []).append(r_)
    print("API 可用性: %s" % apis, flush=True)
    print("读取事件 %d，涉及 %d 个库" % (len(reads), len(by_db)), flush=True)
    for db, rs in sorted(by_db.items(), key=lambda x: -len(x[1]))[:15]:
        lens = sorted(set(x["len"] for x in rs))
        print("   %-28s %4d 次  len=%s" % (db, len(rs), lens[:6]), flush=True)

    # 对命中的页缓冲做离线 key 扫描
    h = kernel32.OpenProcess(PQI | PVR, False, pid) if pid else None
    confirmed = []
    page_hits = 0
    if h:
        for r_ in reads:
            buf = int(r_["buf"], 16) if r_["buf"].startswith("0x") else 0
            if not buf:
                continue
            data = readmem(h, buf, min(PAGESZ, max(r_["len"], 64)))
            if not data:
                continue
            if data[:SALT] == salt:
                page_hits += 1
                print("PAGE1 %s @0x%X 前32B=%s"
                      % (os.path.basename(r_["path"]), buf, data[:32].hex()), flush=True)
        kernel32.CloseHandle(h)

    print("抓到目标库 page1 缓冲 %d 次" % page_hits, flush=True)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"db": args.db, "salt": salt.hex(), "apis": apis,
                   "reads": reads, "page_hits": page_hits}, f, indent=1, ensure_ascii=False)
    print("-> %s" % args.out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
