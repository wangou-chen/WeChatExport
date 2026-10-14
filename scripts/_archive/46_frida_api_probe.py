"""最小探针：确认在 Weixin 进程内可用的 Frida API 形态（用于 hook CreateProcessW）。"""
import sys
import time

import frida

JS = r"""
const r = {};
r.hasModule = typeof Module;
r.hasProcess = typeof Process;
try { r.modGetExport = typeof Module.getExportByName; } catch (e) { r.modGetExport = "err"; }
try { r.modFindExport = typeof Module.findExportByName; } catch (e) { r.modFindExport = "err"; }
try { r.procGetModule = typeof Process.getModuleByName; } catch (e) { r.procGetModule = "err"; }
try { r.procFindModule = typeof Process.findModuleByName; } catch (e) { r.procFindModule = "err"; }
try { r.procFindExport = typeof Process.findExportByName; } catch (e) { r.procFindExport = "err"; }
try { r.procGetExport = typeof Process.getExportByName; } catch (e) { r.procGetExport = "err"; }
try { r.k32 = Process.getModuleByName("kernel32.dll").name; } catch (e) { r.k32err = "" + e; }
try { r.cpw = Process.getModuleByName("kernel32.dll").getExportByName("CreateProcessW").toString(); }
catch (e) { r.cpwErr = "" + e; }
try { r.cpw2 = Process.findExportByName(null, "CreateProcessW").toString(); }
catch (e) { r.cpw2Err = "" + e; }
r.mods = Process.enumerateModules().slice(0, 12).map(function (m) { return m.name; });
send(r);
"""


def main():
    dev = frida.get_local_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    if not pid:
        for p in dev.enumerate_processes():
            if p.name.lower().startswith("weixin"):
                pid = p.pid
    print("pid=%d" % pid)
    s = dev.attach(pid)
    out = []
    sc = s.create_script(JS)
    sc.on("message", lambda m, d: out.append(m))
    sc.load()
    time.sleep(1.5)
    for o in out:
        print(o.get("payload"))
    s.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
