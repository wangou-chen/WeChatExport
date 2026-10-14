"""S5-ac —— hook 数据库「读取路径」，从内存里的 page 1 反推 key 候选

上一版（80_stackwalk_on_dbopen.py）结论：CreateFileW 栈帧 4KB 内没有密钥，
说明 key 在更内层。本版改为在**读取路径**上取数：

  1. hook ReadFile / ReadFileEx / NtReadFile；
  2. 记录每个文件句柄对应的路径（用 GetFinalPathNameByHandleW）；
  3. onLeave 时若句柄对应 *.db 且本次读到了数据：
       - 把读到的前 4096 字节当作 page 1 候选（内存中的原始密文页，含明文 salt）；
       - 若前 16 字节等于目标 DB 的 salt → 命中的就是我们要的那个库；
       - 从读缓冲里取 [4032:4096] 作 HMAC tag 的期望值；
       - 扫描调用方栈帧 + 读缓冲邻域的所有 4 字节对齐窗口，找通过预言机的 32 字节 → 即 key。
  4. 若栈上仍没有，则把读到的 page1 与栈内容落盘，供离线分析。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe -u 81_readpath_key.py --db <db> [--seconds 240] [--out <json>]

跑起来后在微信里点开几个旧会话、上翻历史。
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
const gfpn = findExport(["kernel32.dll", "KERNEL32.DLL", "KernelBase.dll"],
                        "GetFinalPathNameByHandleW");
const getFinalPath = gfpn ? new NativeFunction(gfpn, "uint32",
        ["pointer", "pointer", "uint32", "uint32"]) : null;

function pathOfHandle(h) {
    if (!getFinalPath) return "";
    try {
        const buf = Memory.alloc(2048);
        const n = getFinalPath(h, buf, 1024, 0);
        if (n > 0) return buf.readUtf16String();
    } catch (e) {}
    return "";
}

// 只关心读路径
const MODS = ["kernel32.dll", "KERNEL32.DLL", "KernelBase.dll", "ntdll.dll", "NTDLL.DLL"];
[["ReadFile", 2], ["ReadFileEx", 2], ["NtReadFile", 2]].forEach(function (pair) {
    const name = pair[0];
    const addr = findExport(MODS, name);
    if (!addr) { send({ stage: "missing", api: name }); return; }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            if (name === "NtReadFile") {
                // NTSTATUS NtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
                //                     IoStatusBlock, Buffer, Length, ByteOffset, Key)
                this.h = args[0];
                this.buf = args[5];
                this.len = args[6].toInt32();
            } else {
                this.h = args[0];
                this.buf = args[1];
                this.len = args[2].toInt32();
            }
            this.name = name;
            this.ok = false;
        },
        onLeave: function (retval) {
            const p = pathOfHandle(this.h);
            if (!p || !/\.db$/i.test(p)) return;
            const rd = retval.toInt32();
            if (this.name === "NtReadFile" && rd !== 0) return;    // NTSTATUS != 0 失败
            if (this.name !== "NtReadFile" && rd === 0) return;    // BOOL 0 失败
            const n = Math.min(this.len, 8192);
            if (n <= 0) return;
            const head = phex(this.buf, n);
            const c = this.context;
            send({ stage: "dbread", path: p, api: this.name, want: this.len,
                   got: n, head_hex: head.slice(0, 256),
                   ret: this.returnAddress.toString(),
                   stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                       .slice(0, 16).map(function (a) { return a.toString(); }),
                   rsp_2k: phex(c.rsp, 2048),
                   rbp_1k: (c.rbp && !c.rbp.isNull()) ? phex(c.rbp.sub(256), 1024) : "" });
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
    ap.add_argument("--seconds", type=int, default=240)
    ap.add_argument("--out", default="")
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
    confirmed = []
    salt_seen = []

    def on_msg(m, data):
        p = m.get("payload") or {}
        st = p.get("stage")
        if st in ("ready", "hooked", "missing"):
            print(json.dumps(p, ensure_ascii=False), flush=True)
            return
        if st != "dbread":
            return
        reads.append(p)
        head = p.get("head_hex", "")
        tag = ""
        try:
            raw = bytes.fromhex(head)
            if raw[:SALT] == salt:
                tag = "  <<< 这是目标库，page1 前 16B 与 salt 一致"
                salt_seen.append(p)
        except ValueError:
            pass
        print("DBREAD %s api=%s want=%d%s" % (os.path.basename(p.get("path", "")),
                                              p.get("api"), p.get("want", 0), tag), flush=True)
        if tag:
            print("   page1[0:32]=%s" % head[:64], flush=True)
        for cname, blob in (("rsp", p.get("rsp_2k")), ("rbp", p.get("rbp_1k"))):
            for off, kh in verify(mac_salt, mac_msg, expected, blob):
                print("   *** KEY from %s+%d: %s" % (cname, off, kh), flush=True)
                confirmed.append({"chunk": cname, "off": off, "key": kh})
        if confirmed:
            print("   key 已确认", flush=True)

    script.on("message", on_msg)
    script.load()
    print("等待微信读取 *.db（请在微信里点开几个旧会话、上翻历史）…", flush=True)
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
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"db": args.db, "salt": salt.hex(),
                       "enc_key": confirmed[0]["key"] if confirmed else None,
                       "confirmed": confirmed,
                       "target_page1_reads": len(salt_seen),
                       "reads": reads}, f, indent=2, ensure_ascii=False)
        print("-> %s" % args.out, flush=True)
    print("读取事件=%d 目标库 page1 命中=%d key=%d"
          % (len(reads), len(salt_seen), len(confirmed)), flush=True)
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
