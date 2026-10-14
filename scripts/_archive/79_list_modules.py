"""列出指定进程的模块布局，确认 Weixin.dll 的实际映射基址与大小。"""
import sys
import time

import frida

JS = r"""
const info = {};
try {
    const m = Process.getModuleByName("Weixin.dll");
    info.dll = { base: m.base.toString(), size: m.size, path: m.path };
} catch (e) { info.dllErr = "" + e; }
try {
    const m2 = Process.getModuleByName("Weixin.exe");
    info.exe = { base: m2.base.toString(), size: m2.size };
} catch (e) { info.exeErr = "" + e; }
info.n = Process.enumerateModules().length;
info.big = Process.enumerateModules().filter(function (m) { return m.size > 8 * 1024 * 1024; })
    .map(function (m) { return m.name + ":" + m.size; });
send(info);
"""


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    dev = frida.get_local_device()
    if not pid:
        for p in dev.enumerate_processes():
            if p.name.lower().startswith("weixin"):
                pid = p.pid
                break
    print("pid=%d" % pid)
    s = dev.attach(pid)
    out = []
    sc = s.create_script(JS)
    sc.on("message", lambda m, d: out.append(m))
    sc.load()
    time.sleep(2)
    for o in out:
        print(o.get("payload"))
    s.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
