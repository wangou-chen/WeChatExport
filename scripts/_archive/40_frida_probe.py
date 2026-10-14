"""S5-j (1/2) —— Frida 探针：列出 Weixin 进程模块与相关导出/导入。

用途：定位 4.1.5.30 中「数据库密钥被写入 codec」的落点，替代硬编码偏移。
输出：logs\\frida_probe.json

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=C:\\Users\\Lenovo\\Desktop\\WeChatExport\\lib\\frida_pkg
  C:\\Python314\\python.exe 40_frida_probe.py [--pid 16056]
"""
import argparse
import json
import os
import sys
import time

import frida

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
LOG = os.path.join(BASE, "logs")

JS = r"""
const out = {modules: [], bcrypt: {}, weixin: {}};
Process.enumerateModules().forEach(function (m) {
    out.modules.push({name: m.name, base: m.base.toString(), size: m.size, path: m.path});
});
function dumpExports(modName, filter, bucket) {
    let mod;
    try { mod = Process.getModuleByName(modName); } catch (e) { return; }
    const items = [];
    mod.enumerateExports().forEach(function (e) {
        if (!filter || filter.test(e.name)) items.push({name: e.name, addr: e.address.toString(), type: e.type});
    });
    out[bucket] = {module: modName, base: mod.base.toString(), count: items.length, items: items.slice(0, 400)};
}
dumpExports("bcrypt.dll", /^(BCrypt|NTSTATUS)/, "bcrypt");
dumpExports("Weixin.dll", /(key|Key|cipher|Cipher|sqlite|SQLite|wcdb|WCDB|codec|Codec|crypt|Crypt)/, "weixin");
send(out);
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    args = ap.parse_args()
    os.makedirs(LOG, exist_ok=True)

    dev = frida.get_local_device()
    if args.pid:
        pid = args.pid
        session = dev.attach(pid)
    else:
        procs = [p for p in dev.enumerate_processes() if p.name.lower().startswith("weixin")]
        procs.sort(key=lambda p: p.pid)
        if not procs:
            raise SystemExit("未发现 Weixin 进程")
        pid = procs[-1].pid
        session = dev.attach(pid)
    print("attached pid=%d" % pid)

    result = {}
    script = session.create_script(JS)
    script.on("message", lambda m, d: result.update(m.get("payload") or {}))
    script.load()
    for _ in range(50):
        if result:
            break
        time.sleep(0.2)
    script.unload()
    session.detach()

    if not result:
        raise SystemExit("未取得探针结果")
    out = os.path.join(LOG, "frida_probe.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, ensure_ascii=False)
    print("modules=%d" % len(result.get("modules", [])))
    for m in result.get("modules", []):
        if m["name"].lower() in ("weixin.dll", "bcrypt.dll", "ncrypt.dll", "wcdb.dll",
                                 "sqlite3.dll", "wechatwin.dll"):
            print("  %-16s base=%s size=%d" % (m["name"], m["base"], m["size"]))
    b = result.get("bcrypt", {})
    print("bcrypt exports matched: %d" % b.get("count", 0))
    w = result.get("weixin", {})
    print("Weixin.dll exports matched: %d" % w.get("count", 0))
    for it in (w.get("items") or [])[:40]:
        print("   ", it["name"])
    print("-> %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
