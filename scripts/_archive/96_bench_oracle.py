"""oracle 吞吐微基准：分离 GIL / 哈希实现 / 沙箱 三个因素。

用法：
  set PYTHONUTF8=1
  C:\\Python314\\python.exe 96_bench_oracle.py [--threads 1,4,20] [--n 200000]
"""
import argparse
import hashlib
import hmac
import os
import sys
import threading
import time

PAGESZ, SALT, MAC_OFF = 4096, 16, 4032
DB = r"C:\Users\Lenovo\Desktop\WeChatExport\snapshot\db_storage\message\message_0.db"


def load():
    with open(DB, "rb") as f:
        p1 = f.read(PAGESZ)
    mac_salt = bytes(b ^ 0x3A for b in p1[:SALT])
    msg = p1[SALT:PAGESZ - 80 + 16] + b"\x01\x00\x00\x00"
    return mac_salt, msg, p1[MAC_OFF:PAGESZ]


def loop(n, mac_salt, msg, exp, stride):
    """模拟扫描内循环：候选来自一块 16MB 假缓冲。"""
    buf = os.urandom(16 * 1024 * 1024)
    pbkdf2 = hashlib.pbkdf2_hmac
    hmac_new = hmac.new
    sha512 = hashlib.sha512
    fake_key = hashlib.sha512(b"seed").digest()
    inner = hmac_new(fake_key, digestmod=sha512)
    inner.update(msg)
    calls = 0
    off = 0
    last = len(buf) - 32
    while calls < n and off <= last:
        cand = buf[off:off + 32]
        mk = pbkdf2("sha512", cand, mac_salt, 2, 32)
        try:
            h = hmac_new(mk, digestmod=sha512)
            h.update(msg)
            if h.digest() == exp:
                return calls, True
        except Exception:
            pass
        calls += 1
        off += stride
    return calls, False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threads", default="1,4,20")
    ap.add_argument("--n", type=int, default=200000)
    ap.add_argument("--single", action="store_true", help="只跑一个线程/进程，用于多进程并行度测试")
    args = ap.parse_args()
    mac_salt, msg, exp = load()
    if args.single:
        t0 = time.perf_counter()
        calls, _ = loop(args.n, mac_salt, msg, exp, 8)
        d = time.perf_counter() - t0
        print("pid=%d calls=%d wall=%.2fs rate=%.0f/s" % (os.getpid(), calls, d, calls / d))
        return 0
    for t in (int(x) for x in args.threads.split(",")):
        per = args.n // t
        res = [0] * t
        t0 = time.perf_counter()

        def run(i):
            res[i] = loop(per, mac_salt, msg, exp, 8)[0]

        ths = [threading.Thread(target=run, args=(i,)) for i in range(t)]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        d = time.perf_counter() - t0
        tot = sum(res)
        print("threads=%2d  calls=%d  wall=%.2fs  rate=%.0f/s" % (t, tot, d, tot / d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
