"""
密钥提取 (S5) —— 复用已审计的 find_all_keys.py 算法

唯一的改动：find_all_keys.py 用 `tasklist` 发现 Weixin.exe，而本机沙箱拒绝 tasklist
（实测 `tasklist /FI "IMAGENAME eq Weixin.exe"` 返回 `ERROR: Access denied`，exit 1），
而 `Get-Process` 可用。故本包装仅替换 get_pid()，其余（salt 扫描、HMAC 校验、
x'<64hex_key><32hex_salt>' 模式匹配、all_keys.json 输出）全部沿用原实现，未改动。

用法：
  set PYTHONUTF8=1
  set PYTHONPATH=<项目根>\\lib
  python <项目根>\\scripts\\01_extract_keys.py [--pid N]
"""
import ctypes
import importlib.util
import os
import subprocess
import sys

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(BASE, "tool", "wechat-decrypt-main")


def detect_pid():
    """用 Get-Process 取代 tasklist，取 WorkingSet 最大的 Weixin.exe（主进程）。"""
    ps = ("Get-Process Weixin -ErrorAction SilentlyContinue | "
          "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -Expand Id")
    for exe in ("powershell", "pwsh"):
        try:
            r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", ps],
                               capture_output=True, text=True, timeout=30)
            out = (r.stdout or "").strip()
            if out.isdigit():
                return int(out)
        except Exception:                                     # noqa: BLE001
            continue
    return 0


def probe_access(pid):
    """预检 OpenProcess(VM_READ|QUERY_INFORMATION) 是否可行，避免白跑一遍内存扫描。"""
    k32 = ctypes.windll.kernel32
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x0400, 0x0010
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        err = ctypes.get_last_error() or k32.GetLastError()
        return False, f"OpenProcess 失败 (Win32 err={err}, 常见 5=拒绝访问 → 需管理员)"
    k32.CloseHandle(h)
    return True, "OpenProcess 成功"


def load_tool():
    # find_all_keys.py 第 23 行 `from config import load_config`，需工具目录在 sys.path
    if TOOL not in sys.path:
        sys.path.insert(0, TOOL)
    spec = importlib.util.spec_from_file_location(
        "find_all_keys", os.path.join(TOOL, "find_all_keys.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # main() 仅在 __main__ 下运行，import 安全
    return mod


def main():
    if "--pid" in sys.argv:
        pid = int(sys.argv[sys.argv.index("--pid") + 1])
    else:
        pid = detect_pid()
    if not pid:
        print("[ERROR] 未发现 Weixin.exe 进程，请先登录微信")
        sys.exit(1)

    print(f"[+] 目标进程 PID={pid}")
    ok, msg = probe_access(pid)
    print(f"[+] 权限预检: {msg}")
    if not ok:
        print("[中止] 请以管理员身份运行 scripts\\10_extract_keys_admin.ps1")
        sys.exit(2)

    fak = load_tool()
    fak.get_pid = lambda: (print(f"[+] PID={pid} (Get-Process 发现，已替换 tasklist)") or pid)
    fak.main()


if __name__ == "__main__":
    main()
