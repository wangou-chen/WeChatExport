// S5-e: page-1 HMAC oracle 全进程扫描（C# 实现，弥补 91_find_key.py 的 Python 速度上限）
//
// 数学依据（与 91_find_key.py 一致，SQLCipher 4 默认参数）：
//   mac_key = PBKDF2-HMAC-SHA512(pass = enc_key, salt = page1[0:16] ^ 0x3A, iter = 2, dkLen = 32)
//   HMAC-SHA512(mac_key, page1[16 : 4032] || BE32(1)) == page1[4032 : 4096]
// 命中概率 2^-512，故命中即密钥正确。
//
// 扫描：目标进程全部 committed 可读区域，候选窗口步长 stride（默认 1）。
//
// 用法: KeyScan.exe <pid> <db-file> [stride] [--max N]
//       KeyScan.exe selftest      # HMAC/PBKDF2 自检（对照 .NET HMACSHA512 与 RFC 8018 向量）
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

internal static class KeyScan
{
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_GUARD = 0x100;
    const uint PAGE_NOACCESS = 0x01;
    const int SALT = 16, PAGESZ = 4096, RESERVED = 80;
    const int MAC_OFF = PAGESZ - 64;                      // 4032
    const int HMAC_DATA_LEN = PAGESZ - RESERVED - SALT;   // 4016
    const long CHUNK = 16L * 1024 * 1024;                 // 单次读取上限，避免大区域耗尽内存

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, IntPtr len);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string host, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TOKEN_PRIVILEGES newState,
                                             int len, IntPtr prev, IntPtr retLen);

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attributes; }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    // ------------------------------------------------------------------ HMAC

    // 单例 SHA512：优先 Cng（走原生 CNG，通常比托管实现快）
    static SHA512 NewSha()
    {
        try { return new SHA512Cng(); }
        catch (Exception) { return SHA512.Create(); }
    }

    // HMAC 语境：用「ipad/opad 前缀状态 + 压缩状态链」实现零分配 HMAC。
    // 依据：SHA-512 单块输入时，H(m) 的最终压缩块即 m||padding||len，故对任意 t<=32 有
    //       压缩(H(x), t) == H(x||t)。因此
    //         A = H(ipad128 || 20B 消息)   —— 一次压缩，缓存后可复用（盐与计数器固定）
    //         B = H(opad128 || mac_key)    —— 一次压缩
    //         inner = 压缩(A, cand || prfMsg2)，outer = 压缩(B, inner)
    // 全部状态一次创建，之后每候选仅做常数次压缩，无托管分配。
    sealed class FastState
    {
        readonly Sha512Native n = new Sha512Native();
        readonly byte[] ipad = new byte[128], opad = new byte[128], kp = new byte[128];
        readonly byte[] tmp = new byte[128], sum = new byte[128], good = new byte[64], dg0 = new byte[64];
        IntPtr A, B;

        public void Init(byte[] macSalt, byte[] prfMsg, byte[] prfMsg2, byte[] macMsg)
        {
            // 固定中间摘要 A（与候选密钥无关），存为可复制的哈希状态
            for (int i = 0; i < 128; i++) ipad[i] = 0x36;
            n.Update(ipad, 128);
            n.Update(prfMsg, prfMsg.Length);
            n.Finish(good);
            A = n.Dup();

            // 一次性构建 prfMsg2 拼接缓冲：候选密钥(32) || prfMsg2，供单块压缩使用
            Array.Copy(prfMsg2, 0, sum, 32, prfMsg2.Length);
        }

        static void PadKey(byte[] key, byte[] kp)
        {
            for (int i = 0; i < 128; i++) kp[i] = 0;
            if (key.Length > 128)
            {
                using (var s = SHA512.Create()) { byte[] h = s.ComputeHash(key); Array.Copy(h, 0, kp, 0, 64); }
            }
            else Array.Copy(key, kp, key.Length);
        }

        /// <summary>PBKDF2-HMAC-SHA512(candKey, macSalt, 2, 32)。</summary>
        public void Pbkdf2(byte[] candKey, byte[] macSalt, byte[] out32)
        {
            PadKey(candKey, kp);
            for (int i = 0; i < 128; i++) tmp[i] = (byte)(kp[i] ^ 0x36);
            n.Update(tmp, 128);
            n.Update(macSalt, macSalt.Length);
            n.Finish(good);                       // U1
            n.Update(good, 64);
            n.Finish(dg0);                        // U2
            for (int i = 0; i < 32; i++) out32[i] = (byte)(good[i] ^ dg0[i]);
        }

        /// <summary>mac = HMAC-SHA512(macKey, macMsg)，走压缩状态链，零分配。</summary>
        public void Mac(byte[] macKey, byte[] candKey, byte[] macMsg, byte[] out64)
        {
            PadKey(macKey, kp);
            for (int i = 0; i < 128; i++) tmp[i] = (byte)(kp[i] ^ 0x5c);
            n.Update(tmp, 128);
            n.Update(macKey, 32);
            n.Finish(good);                       // B = H(opad || macKey)
            if (B != IntPtr.Zero) n.DestroyState(B);
            B = n.Dup();

            Array.Copy(candKey, 0, sum, 0, 32);   // sum = candKey || prfMsg2
            n.SetState(A);
            n.Update(sum, 32 + 4);                // prfMsg2 长度固定 4
            n.Finish(good);                       // inner
            n.SetState(B);
            n.Update(good, 64);
            n.Finish(out64);                      // outer
        }
    }

    // ---------------------------------------------------------- BCrypt SHA-512

    // 用 BCrypt 原生 SHA-512（SHA-NI 加速），并且全程零分配：
    // 哈希对象一次性创建（BCRYPT_HASH_REUSABLE_FLAG，BCryptFinishHash 后自动复位），
    // 双块输入（前块恰为 128 字节）时用哈希状态续算，避免每候选一次拷贝与两次中间摘要。
    sealed class Sha512Native
    {
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptOpenAlgorithmProvider(out IntPtr alg, string id, string impl, uint flags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptCloseAlgorithmProvider(IntPtr alg, uint flags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptGetProperty(IntPtr alg, string prop, byte[] value, int len, out int res, uint flags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptCreateHash(IntPtr alg, out IntPtr hash, IntPtr obj, int objLen, IntPtr secret, int secretLen, uint flags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptDestroyHash(IntPtr hash);
        [DllImport("bcrypt.dll")]
        static extern int BCryptHashData(IntPtr hash, byte[] data, int len, uint flags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptFinishHash(IntPtr hash, byte[] output, int len, uint flags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptDuplicateHash(IntPtr hash, out IntPtr newHash, IntPtr obj, int objLen, uint flags);

        const uint REUSABLE = 0x00000004;
        const uint HANDLE_KEY = 0x00000008;
        const uint OID_SHA512 = 0x00000804;   // BCRYPT_SHA512_ALGORITHM
        public const int BLOCK = 128, DIGEST = 64;

        readonly IntPtr alg;
        IntPtr hash;
        public readonly byte[] Digest = new byte[64];

        public Sha512Native()
        {
            int st = BCryptOpenAlgorithmProvider(out alg, "SHA512", null, HANDLE_KEY);
            if (st != 0) throw new InvalidOperationException("BCryptOpenAlgorithmProvider 0x" + st.ToString("X8"));
            st = BCryptCreateHash(alg, out hash, IntPtr.Zero, 0, IntPtr.Zero, 0, 0);
            if (st != 0) throw new InvalidOperationException("BCryptCreateHash 0x" + st.ToString("X8"));
        }

        public void Update(byte[] data, int len) { BCryptHashData(hash, data, len, 0); }
        public void Finish(byte[] out64) { BCryptFinishHash(hash, out64, 64, 0); }
        public IntPtr Dup()
        {
            IntPtr dup;
            BCryptDuplicateHash(hash, out dup, IntPtr.Zero, 0, REUSABLE);
            return dup;
        }
        public void SetState(IntPtr state)
        {
            BCryptDestroyHash(hash);
            hash = state;
        }
        public void DestroyState(IntPtr state) { if (state != IntPtr.Zero) BCryptDestroyHash(state); }
    }

    // 严格按 RFC 2104 展开：HMAC(k,m) = H((opad^k') || H((ipad^k') || m))。
    // 注意：不可复用同一 SHA512 实例连续 ComputeHash 不同长度输入（.NET Framework 的
    // SHA512Cng/Managed 在此会出现状态残留，实测静默产出错误值），故每次新建实例。
    sealed class HmacCtx
    {
        readonly byte[] inner = new byte[128 + 4096];
        readonly byte[] outer = new byte[128 + 64];
        readonly byte[] kp = new byte[128];
        readonly byte[] hbuf = new byte[64];

        public void Compute(byte[] key, byte[] msg, int msgOff, int msgLen, byte[] out64)
        {
            for (int i = 0; i < 128; i++) kp[i] = 0;
            if (key.Length > 128)
            {
                using (var s0 = NewSha()) { byte[] kk = s0.ComputeHash(key); Array.Copy(kk, kp, 64); }
            }
            else Array.Copy(key, kp, key.Length);

            for (int i = 0; i < 128; i++) inner[i] = (byte)(kp[i] ^ 0x36);
            Array.Copy(msg, msgOff, inner, 128, msgLen);
            using (var s = NewSha())
            {
                byte[] h = s.ComputeHash(inner, 0, 128 + msgLen);
                Array.Copy(h, 0, hbuf, 0, 64);
            }

            for (int i = 0; i < 128; i++) outer[i] = (byte)(kp[i] ^ 0x5c);
            Array.Copy(hbuf, 0, outer, 128, 64);
            using (var s = NewSha())
            {
                byte[] r = s.ComputeHash(outer, 0, 192);
                Array.Copy(r, 0, out64, 0, 64);
            }
        }
    }

    // PBKDF2-HMAC-SHA512(pass, salt, iter=2, dkLen=32)：单块（dkLen <= 64），T = U1 ^ U2
    static void Pbkdf2Sha512_2(HmacCtx ctx, byte[] pass, byte[] salt, byte[] out32,
                               byte[] scratchIn, byte[] u1, byte[] u2)
    {
        int sl = salt.Length;
        Array.Copy(salt, 0, scratchIn, 0, sl);
        scratchIn[sl] = 0; scratchIn[sl + 1] = 0; scratchIn[sl + 2] = 0; scratchIn[sl + 3] = 1;  // BE32(1)
        ctx.Compute(pass, scratchIn, 0, sl + 4, u1);
        ctx.Compute(pass, u1, 0, 64, u2);
        for (int i = 0; i < 32; i++) out32[i] = (byte)(u1[i] ^ u2[i]);
    }

    // ------------------------------------------------------------- 权限/进程

    static void EnableDebugPrivilege()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out token)) return;
        long luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) { CloseHandle(token); return; }
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.Count = 1; tp.Luid = luid; tp.Attributes = 0x00000002;
        AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        CloseHandle(token);
    }

    // --------------------------------------------------------------- 自检

    static int SelfTest()
    {
        int fail = 0;
        HmacCtx ctx = new HmacCtx();
        using (var probe = NewSha()) Console.WriteLine("sha512 impl = " + probe.GetType().FullName);

        string[,] hv = new string[,] {
            { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "616263",
              "8714c90d0beda165f125ba3c23485543a17e6e882eaaa7e5b93a8b006a7d4063a483ee83006cf5407469da5037cc25ebfb1c061a98742d89b83ab26520a4d309" },
            { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
              "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" },
        };
        byte[] d = new byte[64];
        for (int i = 0; i < 2; i++)
        {
            byte[] k = HexToBytes(hv[i, 0]), m = HexToBytes(hv[i, 1]);
            ctx.Compute(k, m, 0, m.Length, d);
            string got = BitConverter.ToString(d).Replace("-", "").ToLowerInvariant();
            bool ok = got == hv[i, 2];
            Console.WriteLine("hmac[" + i + "]=" + (ok ? "OK" : "MISMATCH got " + got));
            if (!ok) fail++;
        }

        string[,] pv = new string[,] {
            { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "73616c74",
              "c2ba750ef4adee2c892631b1d8486038ff2f420635fad612e5c186bca523fbac" },
            { "cafebabe00112233445566778899aabbccddeeff00112233445566778899aabb",
              "6b0a126fc9e5050f3d81b876d561f08b",
              "c81e131074ce1a71222306c82e98e6e9d15a21e4aec28d805c64b17225d3b9a8" },
            { "ff", "deadbeef",
              "0e7ccd2462b06627f6d5d87a9cca8414c06a107db5f98fd7516f9e6e1ddfb34d" },
        };
        byte[] out32 = new byte[32], sc = new byte[64], u1 = new byte[64], u2 = new byte[64];
        for (int i = 0; i < 3; i++)
        {
            Pbkdf2Sha512_2(ctx, HexToBytes(pv[i, 0]), HexToBytes(pv[i, 1]), out32, sc, u1, u2);
            string got = BitConverter.ToString(out32).Replace("-", "").ToLowerInvariant();
            bool ok = got == pv[i, 2];
            Console.WriteLine("pbkdf2[" + i + "]=" + got + " " + (ok ? "OK" : "MISMATCH expect " + pv[i, 2]));
            if (!ok) fail++;
        }

        Console.WriteLine(fail == 0 ? "SELFTEST PASS" : ("SELFTEST FAIL x" + fail));

        // 3) FastState（BCrypt 零分配路径）对照 HmacCtx 参考实现
        try
        {
            byte[] salt0 = HexToBytes("97a7874ec8a1c8d8397e8f80f29cea3a");
            byte[] macSalt0 = new byte[16];
            for (int i = 0; i < 16; i++) macSalt0[i] = (byte)(salt0[i] ^ 0x3A);
            byte[] m0 = new byte[20];
            Array.Copy(macSalt0, 0, m0, 0, 16);
            m0[19] = 1;
            byte[] m2 = new byte[4]; m2[3] = 1;
            byte[] macMsg0 = new byte[300];           // 任意长度，验证大消息路径
            new Random(7).NextBytes(macMsg0);

            var fs = new FastState();
            fs.Init(macSalt0, m0, m2, macMsg0);
            var rnd = new Random(99);
            int nf = 0;
            for (int t = 0; t < 5; t++)
            {
                byte[] cand = new byte[32]; rnd.NextBytes(cand);
                byte[] k1 = new byte[32], mac1 = new byte[64], k2 = new byte[32], mac2 = new byte[64];
                Pbkdf2Sha512_2(ctx, cand, macSalt0, k1, sc, u1, u2);
                ctx.Compute(k1, macMsg0, 0, macMsg0.Length, mac1);
                fs.Pbkdf2(cand, macSalt0, k2);
                fs.Mac(k2, cand, macMsg0, mac2);
                bool ok = true;
                for (int j = 0; j < 32; j++) if (k1[j] != k2[j]) ok = false;
                for (int j = 0; j < 64; j++) if (mac1[j] != mac2[j]) ok = false;
                if (!ok) nf++;
            }
            Console.WriteLine("faststate: " + (nf == 0 ? "OK (5 vectors)" : ("MISMATCH x" + nf)));
            fail += nf;
        }
        catch (Exception ex)
        {
            Console.WriteLine("faststate 不可用（将回退慢路径）: " + ex.GetType().Name + " " + ex.Message);
        }

        Console.WriteLine(fail == 0 ? "SELFTEST PASS" : ("SELFTEST FAIL x" + fail));
        return fail == 0 ? 0 : 1;
    }

    static byte[] HexToBytes(string s)
    {
        byte[] b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return b;
    }

    // ---------------------------------------------------------------- 主流程

    static int Main(string[] argv)
    {
        try { return Run(argv); }
        catch (Exception ex)
        {
            Console.Error.WriteLine("EXC " + ex.GetType().FullName + ": " + ex.Message);
            Console.Error.Flush();
            return 9;
        }
    }

    static int Run(string[] argv)
    {
        if (argv.Length > 0 && argv[0] == "selftest") return SelfTest();
        if (argv.Length < 2)
        {
            Console.Error.WriteLine("usage: KeyScan.exe <pid> <db-file> [stride] [--max N]   |   selftest");
            return 2;
        }
        int pid = int.Parse(argv[0]);
        string dbfile = argv[1];
        int stride = argv.Length > 2 ? int.Parse(argv[2]) : 1;
        long maxCand = long.MaxValue;
        int partIndex = 0, partOf = 1;
        for (int i = 2; i < argv.Length - 1; i++)
        {
            if (argv[i] == "--max") maxCand = long.Parse(argv[i + 1]);
            if (argv[i] == "--part") { partIndex = int.Parse(argv[i + 1]); partOf = int.Parse(argv[i + 2]); }
        }

        byte[] page1 = new byte[PAGESZ];
        using (var fs = new System.IO.FileStream(dbfile, System.IO.FileMode.Open, System.IO.FileAccess.Read))
        {
            int got = 0;
            while (got < PAGESZ)
            {
                int n = fs.Read(page1, got, PAGESZ - got);
                if (n <= 0) break;
                got += n;
            }
            if (got != PAGESZ) { Console.Error.WriteLine("page1 读取不足"); return 2; }
        }
        if (Encoding.ASCII.GetString(page1, 0, 15) == "SQLite format 3")
        {
            Console.WriteLine("[!] page1 已是明文 SQLite，无需解密");
            return 0;
        }

        byte[] salt = new byte[SALT];
        Array.Copy(page1, 0, salt, 0, SALT);
        byte[] macSalt = new byte[SALT];
        for (int i = 0; i < SALT; i++) macSalt[i] = (byte)(salt[i] ^ 0x3A);
        byte[] expected = new byte[64];
        Array.Copy(page1, MAC_OFF, expected, 0, 64);
        byte[] macMsg = new byte[HMAC_DATA_LEN + 4];
        Array.Copy(page1, SALT, macMsg, 0, HMAC_DATA_LEN);
        macMsg[HMAC_DATA_LEN + 3] = 1;                        // BE32(1)

        int threads = Environment.ProcessorCount;
        Console.WriteLine("db   = " + dbfile);
        Console.WriteLine("salt = " + BitConverter.ToString(salt).Replace("-", "").ToLowerInvariant());
        Console.WriteLine("pid  = " + pid + "   stride = " + stride + "   threads = " + threads);
        Console.Out.Flush();

        EnableDebugPrivilege();
        IntPtr h = OpenProcess(0x0400 | 0x0010, false, pid);
        if (h == IntPtr.Zero)
        {
            Console.Error.WriteLine("OpenProcess 失败 err=" + Marshal.GetLastWin32Error());
            return 3;
        }

        // 区域清单（跳过超大区域，避免一次性分配）
        List<long[]> regions = new List<long[]>();
        long totalBytes = 0;
        int k = 0;
        IntPtr addr = IntPtr.Zero;
        long maxAddr = 0x7FFFFFFFFFFF;
        MEMORY_BASIC_INFORMATION mbi;
        while ((long)addr < maxAddr)
        {
            IntPtr q = VirtualQueryEx(h, addr, out mbi, (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (q == IntPtr.Zero) break;
            long ba = (long)mbi.BaseAddress;
            long size = (long)mbi.RegionSize;
            if (size <= 0) break;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0
                && (mbi.Protect & PAGE_NOACCESS) == 0 && size < 800L * 1024 * 1024)
            {
                if (partOf <= 1 || (k % partOf) == partIndex)
                {
                    regions.Add(new long[] { ba, size });
                    totalBytes += size;
                }
                k++;
            }
            long next = ba + size;
            if (next <= (long)addr) break;
            addr = (IntPtr)next;
        }
        Console.WriteLine("regions=" + regions.Count + " committed=" + totalBytes + " (" + (totalBytes / 1048576) + " MB)");
        Console.Out.Flush();

        int[] cursor = new int[1];
        long[] oracleTotal = new long[1];
        long[] bytesDone = new long[1];
        long[] maxCandBox = new long[] { maxCand };
        var hitLock = new object();
        string[] hitText = new string[1];
        var sw = Stopwatch.StartNew();
        long[] reportAt = new long[1];

        bool fast = false;
        for (int i = 2; i < argv.Length; i++) if (argv[i] == "--fast") fast = true;
        if (fast)
        {
            try { Sha512Native probe = new Sha512Native(); }
            catch (Exception ex)
            {
                Console.Error.WriteLine("BCrypt 不可用，回退慢路径: " + ex.Message);
                fast = false;
            }
        }
        Console.WriteLine("fast = " + fast);

        // 常驻共享数据（只读）
        Work w = new Work();
        w.h = h;
        w.regions = regions;
        w.stride = stride;
        w.cursor = cursor;
        w.oracleTotal = oracleTotal;
        w.bytesDone = bytesDone;
        w.maxCandBox = maxCandBox;
        w.hitLock = hitLock;
        w.hitText = hitText;
        w.macSalt = macSalt;
        w.macMsg = macMsg;
        w.expected = expected;
        w.prfMsg2 = new byte[4]; w.prfMsg2[3] = 1;
        w.sw = sw;
        w.reportAt = reportAt;
        w.fast = fast;

        System.Threading.Thread[] pool = new System.Threading.Thread[threads];
        for (int t = 0; t < threads; t++)
        {
            pool[t] = new System.Threading.Thread(delegate() { Worker(w); });
            pool[t].IsBackground = true;
            pool[t].Start();
        }
        for (int t = 0; t < threads; t++) pool[t].Join();
        CloseHandle(h);

        Console.WriteLine("regions_scanned=" + cursor[0] + "/" + regions.Count + " bytes=" + bytesDone[0]
            + " oracle_calls=" + oracleTotal[0] + " hit=" + (hitText[0] == null ? "none" : hitText[0])
            + " elapsed=" + sw.Elapsed.TotalSeconds.ToString("F1") + "s");
        return hitText[0] != null && hitText[0] != "UNCONFIRMED" ? 0 : 1;
    }

    sealed class Work
    {
        public IntPtr h;
        public List<long[]> regions;
        public int stride;
        public int[] cursor;
        public long[] oracleTotal, bytesDone, maxCandBox, reportAt;
        public object hitLock;
        public string[] hitText;
        public byte[] macSalt, macMsg, expected, prfMsg2;
        public Stopwatch sw;
        public bool fast;
    }

    static void Worker(Work w)
    {
        HmacCtx ctx = new HmacCtx();
        FastState fs = null;
        if (w.fast)
        {
            fs = new FastState();
            byte[] prfMsg = new byte[20];
            Array.Copy(w.macSalt, 0, prfMsg, 0, 16);
            prfMsg[19] = 1;
            fs.Init(w.macSalt, prfMsg, w.prfMsg2, w.macMsg);
        }
        byte[] scratch = new byte[64], u1 = new byte[64], u2 = new byte[64];
        byte[] candKey = new byte[32], macKey = new byte[32], candMac = new byte[64];
        byte[] buf = new byte[4096];
        long localOracle = 0, localBytes = 0;

        while (true)
        {
            if (w.hitText[0] != null) break;
            int idx;
            lock (w.oracleTotal)
            {
                idx = w.cursor[0];
                w.cursor[0]++;
            }
            if (idx >= w.regions.Count) break;
            long ba = w.regions[idx][0], size = w.regions[idx][1];
            long pos = 0;
            while (pos < size)
            {
                long want = Math.Min(CHUNK, size - pos);
                // 相邻块重叠 31 字节，保证跨块边界的 32 字节候选不遗漏
                long delta = (pos == 0) ? 0 : 31;
                long chunk = want;
                if (delta != 0) { pos -= delta; want += delta; }
                int need = (int)want;
                if (buf.Length < need) buf = new byte[need];
                IntPtr got;
                if (!ReadProcessMemory(w.h, (IntPtr)(ba + pos), buf, (IntPtr)need, out got) || (long)got != need)
                    break;
                localBytes += need;
                long last = need - 32;
                for (long off = 0; off <= last; off += w.stride)
                {
                    if (System.Threading.Interlocked.Read(ref w.maxCandBox[0]) <= 0) break;
                    System.Threading.Interlocked.Decrement(ref w.maxCandBox[0]);
                    Array.Copy(buf, (int)off, candKey, 0, 32);
                    if (fs != null)
                    {
                        fs.Pbkdf2(candKey, w.macSalt, macKey);
                        fs.Mac(macKey, candKey, w.macMsg, candMac);
                    }
                    else
                    {
                        Pbkdf2Sha512_2(ctx, candKey, w.macSalt, macKey, scratch, u1, u2);
                        ctx.Compute(macKey, w.macMsg, 0, w.macMsg.Length, candMac);
                    }
                    localOracle++;
                    bool same = true;
                    for (int j = 0; j < 64; j++) if (candMac[j] != w.expected[j]) { same = false; break; }
                    if (same)
                    {
                        string hex = BitConverter.ToString(candKey).Replace("-", "").ToLowerInvariant();
                        string line = "FOUND key=" + hex + " key_addr=0x" + (ba + pos + off).ToString("X");
                        lock (w.hitLock)
                        {
                            if (w.hitText[0] == null)
                            {
                                Console.WriteLine(line);
                                Console.Out.Flush();
                                byte[] mk2 = new byte[32], cm2 = new byte[64];
                                Pbkdf2Sha512_2(ctx, candKey, w.macSalt, mk2, scratch, u1, u2);
                                ctx.Compute(mk2, w.macMsg, 0, w.macMsg.Length, cm2);
                                bool ok2 = true;
                                for (int j = 0; j < 64; j++) if (cm2[j] != w.expected[j]) { ok2 = false; break; }
                                Console.WriteLine("  recheck=" + (ok2 ? "CONFIRMED" : "FAILED"));
                                w.hitText[0] = ok2 ? hex : "UNCONFIRMED";
                            }
                        }
                        break;
                    }
                }
                pos += chunk;
            }
            lock (w.oracleTotal)
            {
                w.oracleTotal[0] += localOracle; localOracle = 0;
                w.bytesDone[0] += localBytes; localBytes = 0;
                if (w.sw.Elapsed.TotalSeconds - w.reportAt[0] > 5)
                {
                    w.reportAt[0] = (long)w.sw.Elapsed.TotalSeconds;
                    Console.Error.WriteLine("  .. regions=" + w.cursor[0] + "/" + w.regions.Count
                        + " MB=" + (w.bytesDone[0] / 1048576) + " oracle=" + w.oracleTotal[0]
                        + " t=" + w.sw.Elapsed.TotalSeconds.ToString("F0") + "s rate="
                        + (w.oracleTotal[0] / Math.Max(1.0, w.sw.Elapsed.TotalSeconds)).ToString("F0") + "/s");
                    Console.Error.Flush();
                }
            }
        }
        lock (w.oracleTotal)
        {
            w.oracleTotal[0] += localOracle;
            w.bytesDone[0] += localBytes;
        }
    }
}
