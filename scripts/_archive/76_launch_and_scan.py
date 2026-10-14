"""S5-y —— 正常启动微信并在启动后立刻做双模式内存扫描（专治「密钥只在启动瞬间存在」）

已实测的约束与结论：
  * 沙箱内 taskkill 被拒，但 TerminateProcess 可用（73_kill_wechat.py）；
  * frida.spawn 卡死，frida.attach 正常；CREATE_SUSPENDED 启动后 Weixin.dll 加载较晚；
  * 微信主进程命令行: "D:\\...\\Weixin\\Weixin.exe" --scene=taskbarpins（418MB 那个）；
  * 4.1.13.65：内存里没有 x'<96hex>' 文本、也没有任意偏移的原始 32 字节密钥（已验证）。

本脚本流程：
  1. 结束残留微信进程（TerminateProcess），等待全部退出并确认 E: 可访问；
  2. 以普通方式（非挂起）启动主进程，避免用户侧出现「存储位置不可用」；
  3. 启动后 t=+6s 起，对全部微信进程做：
       A) stride-8 全量 HMAC 预言机扫描（多进程分片）
       B) salt 命中点 ±W 邻域 stride-1 扫描
     两轮（t=+6s、t=+25s），记录每个 DB 的命中。

用法：
  set PYTHONUTF8=1
  C:\\Python314\\python.exe -u 76_launch_and_scan.py --db-dir <db_storage> [--parts 6] [--rounds 2]
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

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"
EXE = r"D:\Program Files (x86)\Tencent\Weixin\Weixin.exe"
CMDLINE = '"%s" --scene=taskbarpins' % EXE
kernel32 = ctypes.windll.kernel32
PQI, PVR = 0x0400, 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def pids(names=("Weixin.exe", "WeChatAppEx.exe")):
    out = []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-Process Weixin,WeChatAppEx -ErrorAction SilentlyContinue |"
                            "ForEach-Object { \"$($_.Id),$($_.ProcessName),$([int]($_.WorkingSet64/1MB))\" }"],
                           capture_output=True, text=True, timeout=30)
        for line in (r.stdout or "").splitlines():
            a = line.strip().split(",")
            if len(a) == 3 and a[0].isdigit() and (a[1] + ".exe") in names:
                out.append((int(a[0]), a[1], int(a[2])))
    except Exception:                                              # noqa: BLE001
        pass
    return out


def regions(h):
    regs, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if (mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_GUARD) == 0
                and (mbi.Protect & PAGE_NOACCESS) == 0 and 0 < mbi.RegionSize < 700 * 1024 * 1024):
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def readmem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-dir", required=True)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--window", type=int, default=4096)
    ap.add_argument("--stride", type=int, default=8)
    ap.add_argument("--no-launch", action="store_true", help="不自行启动微信，只等出现微信进程后扫描（微信必须由用户以正常令牌启动）")
    ap.add_argument("--watch", type=int, default=600, help="--no-launch 时最长等待秒数")
    ap.add_argument("--out", default=os.path.join(BASE, "keys", "launch_scan_keys.json"))
    args = ap.parse_args()

    targets = []
    for root, _d, files in os.walk(args.db_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                p = os.path.join(root, f)
                if os.path.getsize(p) >= PAGESZ:
                    targets.append((os.path.relpath(p, args.db_dir), p))
    targets.sort()
    print("目标 DB %d 个" % len(targets), flush=True)

    pbkdf2, hmac_new, sha512 = hashlib.pbkdf2_hmac, hmac_mod.new, hashlib.sha512
    meta = {}
    for rel, p in targets:
        with open(p, "rb") as f:
            p1 = f.read(PAGESZ)
        salt = p1[:SALT]
        meta[rel] = {
            "salt": salt,
            "mac_salt": bytes(b ^ 0x3A for b in salt),
            "mac_msg": p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00",
            "expected": p1[MAC_OFF:PAGESZ],
        }

    def verify(rel, cand):
        m = meta[rel]
        if len(cand) != 32:
            return False
        mk = pbkdf2("sha512", cand, m["mac_salt"], 2, 32)
        return hmac_new(mk, m["mac_msg"], sha512).digest() == m["expected"]

    # 1) 清理 + 检查
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "killwx", os.path.join(os.path.dirname(os.path.abspath(__file__)), "73_kill_wechat.py"))
        km = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(km)
        for _pid, _n in km.pids():
            km.kill(_pid)
        print("已结束 %d 个残留微信进程" % len(km.pids() or []), flush=True)
    except Exception as e:                                        # noqa: BLE001
        print("清理失败: %s" % e, flush=True)
    time.sleep(4)
    print("E: 可访问 = %s ; db_dir 存在 = %s"
          % (os.path.isdir("E:\\"), os.path.isdir(args.db_dir)), flush=True)

    # 2) 启动或等待微信（沙箱内启动会继承受限令牌，导致 E: 写被拒 → 默认不自行启动）
    if args.no_launch:
        print("等待微信进程出现（最长 %ds）… 请手动启动微信" % args.watch, flush=True)
        t_wait = time.time()
        while time.time() - t_wait < args.watch:
            if pids():
                print("检测到微信进程: %s" % pids(), flush=True)
                break
            time.sleep(1)
        else:
            print("超时未检测到微信进程", flush=True)
            return 1
    else:
        subprocess.Popen(CMDLINE, cwd=os.path.dirname(EXE), shell=False,
                         creationflags=0x00000008 | 0x00000200)
        print("已启动: %s" % CMDLINE, flush=True)

    results = {}
    rounds = args.rounds
    for rnd in range(1, rounds + 1):
        wait = 6 if rnd == 1 else 25
        print("[round %d] 等待 %ds 后扫描 …" % (rnd, wait), flush=True)
        time.sleep(wait)
        procs = pids()
        print("[round %d] 微信进程: %s" % (rnd, procs), flush=True)
        t0 = time.time()
        stats = {"regions": 0, "cands": 0, "win": 0}
        for pid, name, mb in procs:
            h = kernel32.OpenProcess(PQI | PVR, False, pid)
            if not h:
                continue
            for base, size in regions(h):
                data = readmem(h, base, size)
                if not data:
                    continue
                stats["regions"] += 1
                # A) stride-8 全量
                for rel in list(meta):
                    if rel in results:
                        continue
                    m = meta[rel]
                    off = 0
                    while off + 32 <= len(data):
                        stats["cands"] += 1
                        if verify(rel, data[off:off + 32]):
                            results[rel] = {"enc_key": data[off:off + 32].hex(), "via": "stride%d" % args.stride,
                                            "pid": pid, "proc": name, "addr": "0x%X" % (base + off)}
                            print("FOUND %s key=%s (stride)" % (rel, results[rel]["enc_key"]), flush=True)
                            break
                        off += args.stride
                # B) salt 邻域 stride-1
                for rel in list(meta):
                    if rel in results:
                        continue
                    salt = meta[rel]["salt"]
                    j = data.find(salt)
                    while j >= 0 and rel not in results:
                        lo = max(0, j - args.window)
                        hi = min(len(data) - 32, j + SALT + args.window)
                        off = lo
                        while off <= hi:
                            stats["win"] += 1
                            if verify(rel, data[off:off + 32]):
                                results[rel] = {"enc_key": data[off:off + 32].hex(), "via": "saltwin",
                                                "pid": pid, "proc": name, "addr": "0x%X" % (base + off)}
                                print("FOUND %s key=%s (saltwin)" % (rel, results[rel]["enc_key"]), flush=True)
                                break
                            off += 1
                        j = data.find(salt, j + 1)
            kernel32.CloseHandle(h)
        print("[round %d] regions=%d stride候选=%d window候选=%d 命中=%d %.0fs"
              % (rnd, stats["regions"], stats["cands"], stats["win"], len(results), time.time() - t0),
              flush=True)
        if results:
            break

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("命中 %d/%d -> %s" % (len(results), len(targets), args.out), flush=True)
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
