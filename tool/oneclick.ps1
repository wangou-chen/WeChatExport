# ============================================================================
# 微信 4.0.3.39 聊天记录一键导出
#   无需 agent 辅助：自动定位数据目录 → 内存取密钥 → 解密全部库 → 导出记录
#
# 前提：
#   1) 微信版本必须是 4.0.3.39（4.1.13+ 内存中无明文密钥，本脚本会直接报错退出）
#   2) 微信正在运行且已登录过（保持登录态，重启无需扫码）
#   3) Python 3.10+ 且已装 pycryptodome、zstandard（frida 不需要）
#
# 用法（在你自己的 PowerShell 里，不要在受限沙箱里）：
#   powershell -ExecutionPolicy Bypass -File C:\Users\Lenovo\Desktop\WeChatExport\tool\oneclick.ps1
#   可选参数：-DbDir <数据目录> -Out <输出目录> -Python <python.exe 路径>
# ============================================================================
param(
    [string]$DbDir = "",
    [string]$Out = "C:\Users\Lenovo\Desktop\WeChatExport\out",
    [string]$Work = "C:\Users\Lenovo\Desktop\WeChatExport\decrypted",
    [string]$Python = "",
    [switch]$KeepBackup
)

$ErrorActionPreference = "Stop"
$ProjRoot = "C:\Users\Lenovo\Desktop\WeChatExport"
$Scripts = Join-Path $ProjRoot "scripts"
$ReqVer = "4.0.3.39"

function Say($m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Fail($m) { Write-Host "[错误] $m" -ForegroundColor Red; exit 1 }

Say "微信聊天记录一键导出 —— 开始"

# ---------------------------------------------------------------- 0) 找 Python
if (-not $Python) {
    foreach ($c in @("C:\Python314\python.exe", "C:\Python313\python.exe",
                     "C:\Python312\python.exe", "C:\Python311\python.exe")) {
        if (Test-Path $c) { $Python = $c; break }
    }
    if (-not $Python) {
        $cmd = Get-Command python -ErrorAction SilentlyContinue
        if ($cmd) { $Python = $cmd.Source }
    }
}
if (-not $Python -or -not (Test-Path $Python)) { Fail "未找到 python.exe，请用 -Python 指定" }
Say "Python = $Python"

$LibPath = Join-Path $ProjRoot "lib"
$env:PYTHONUTF8 = "1"
$env:PYTHONPATH = $LibPath

# ---------------------------------------------------- 1) 版本与进程检查
$wexinExe = $null
foreach ($p in @("D:\Program Files (x86)\Tencent\Weixin\Weixin.exe",
                 "C:\Program Files\Tencent\Weixin\Weixin.exe",
                 "D:\Program Files\Tencent\Weixin\Weixin.exe")) {
    if (Test-Path $p) { $wexinExe = $p; break }
}
if (-not $wexinExe) { Fail "未找到 Weixin.exe" }
$ver = (Get-Item $wexinExe).VersionInfo.FileVersion
Say "微信版本 = $ver（$wexinExe）"
if ($ver -notlike "$ReqVer*") {
    Fail "版本必须为 $ReqVer（当前 $ver）。4.1.13 及以上内存中已无明文密钥，无法一键导出。"
}

$procs = Get-Process Weixin -ErrorAction SilentlyContinue
if (-not $procs) {
    Say "微信未运行，正在启动（请登录后脚本会自动继续）…"
    Start-Process -FilePath $wexinExe -ArgumentList "--scene=taskbarpins"
    $deadline = (Get-Date).AddMinutes(3)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $procs = Get-Process Weixin -ErrorAction SilentlyContinue
        if ($procs) { break }
    }
    if (-not $procs) { Fail "微信启动失败" }
}
Say ("微信进程: " + (($procs | ForEach-Object { $_.Id }) -join ", "))

# ---------------------------------------------------- 2) 定位数据目录
if (-not $DbDir) {
    $cfgDir = Join-Path $env:APPDATA "Tencent\xwechat\config"
    if (Test-Path $cfgDir) {
        foreach ($ini in Get-ChildItem $cfgDir -Filter *.ini) {
            $root = (Get-Content $ini.FullName -Raw).Trim()
            if ($root -and (Test-Path $root)) {
                $cand = Get-ChildItem (Join-Path $root "xwechat_files") -Directory -ErrorAction SilentlyContinue |
                        ForEach-Object { Join-Path $_.FullName "db_storage" } |
                        Where-Object { Test-Path $_ }
                if ($cand) { $DbDir = $cand[0]; break }
            }
        }
    }
    if (-not $DbDir) {
        $cand = Get-ChildItem "$env:USERPROFILE\Documents\xwechat_files" -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName "db_storage" } | Where-Object { Test-Path $_ }
        if ($cand) { $DbDir = $cand[0] }
    }
}
if (-not $DbDir -or -not (Test-Path $DbDir)) { Fail "未定位到 db_storage，请用 -DbDir 指定" }
Say "数据目录 = $DbDir"
$dbCount = (Get-ChildItem $DbDir -Recurse -Filter *.db -File | Where-Object { $_.Length -ge 4096 }).Count
Say "待处理数据库 = $dbCount 个"

# ---------------------------------------------------- 3) 备份（可选）
if ($KeepBackup) {
    $bk = Join-Path $ProjRoot ("backup_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
    Say "备份到 $bk …"
    Copy-Item $DbDir $bk -Recurse -Force
    Say "备份完成"
}

# ---------------------------------------------------- 4) 取密钥 + 解密全部库
$pipeline = Join-Path $Scripts "114_full_pipeline.py"
if (-not (Test-Path $pipeline)) { Fail "缺少 $pipeline" }
Say "扫描内存取密钥并解密（约 5–30 秒）…"
& $Python -u $pipeline --db-dir $DbDir --out $Work
if ($LASTEXITCODE -ne 0) { Fail "解密流程返回失败码（可能部分库未取到密钥）" }

$okDb = (Get-ChildItem $Work -Filter *.db -File -ErrorAction SilentlyContinue).Count
Say "已解密数据库 = $okDb 个"

# ---------------------------------------------------- 5) 导出聊天记录
$exporter = Join-Path $Scripts "120_export_chats.py"
if (-not (Test-Path $exporter)) { Fail "缺少 $exporter" }
Say "导出聊天记录（约 1–5 分钟）…"
& $Python -u $exporter --dec $Work --out $Out
if ($LASTEXITCODE -ne 0) { Fail "导出失败" }

# ---------------------------------------------------- 6) 汇总
$json = Join-Path $Out "chats.json"
if (Test-Path $json) {
    $sum = & $Python -u -c @"
import json,sys
j=json.load(open(r'$json',encoding='utf-8'))
print('%d,%d,%d' % (len(j['sessions']), len(j['contacts']),
                    sum(s['count'] for s in j['sessions'])))
"@
    $parts = $sum.Split(",")
    Say "完成：会话 $($parts[0]) 个 / 联系人 $($parts[1]) 个 / 消息 $($parts[2]) 条"
}
foreach ($f in @("chats.json", "chats.md", "INDEX.md")) {
    $p = Join-Path $Out $f
    if (Test-Path $p) { Say ("产物 {0}  {1:N1} MB" -f $f, ((Get-Item $p).Length / 1MB)) }
}
Say "全部完成。输出目录：$Out"
