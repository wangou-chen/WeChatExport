# ============================================================================
# 微信 4.0.x 聊天记录导出 —— 一键脚本（调用本项目自足库 wxarchive）
#
#   无需 agent、无需外部逆向工具。仅依赖 pycryptodome + zstandard。
#
# 前提：
#   1) 微信版本为 4.0.x（本机验证 4.0.3.39）。4.1.13+ 内存中无明文密钥，会失败。
#   2) 微信正在运行且已登录过（保持登录态，重启无需扫码）。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File C:\Users\Lenovo\Desktop\WeChatExport\oneclick.ps1
#   可选：-DbDir <db_storage> -Work <解密目录> -Out <导出目录> -Python <python.exe>
# ============================================================================
param(
    [string]$DbDir = "",
    [string]$Work = "C:\Users\Lenovo\Desktop\WeChatExport\decrypted",
    [string]$Out = "C:\Users\Lenovo\Desktop\WeChatExport\out",
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$Root = "C:\Users\Lenovo\Desktop\WeChatExport"

function Say($m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Fail($m) { Write-Host "[错误] $m" -ForegroundColor Red; exit 1 }

Say "wxarchive 一键导出 —— 开始"

# 1) Python
if (-not $Python) {
    foreach ($c in @("C:\Python314\python.exe", "C:\Python313\python.exe",
                     "C:\Python312\python.exe", "C:\Python311\python.exe")) {
        if (Test-Path $c) { $Python = $c; break }
    }
    if (-not $Python) { $cmd = Get-Command python -ErrorAction SilentlyContinue; if ($cmd) { $Python = $cmd.Source } }
}
if (-not $Python -or -not (Test-Path $Python)) { Fail "未找到 python.exe，请用 -Python 指定" }
$env:PYTHONUTF8 = "1"
$env:PYTHONPATH = "$Root;$Root\lib"
Say "Python = $Python"

# 2) 版本检查（4.0.x）
$exe = $null
foreach ($p in @("D:\Program Files (x86)\Tencent\Weixin\Weixin.exe",
                 "C:\Program Files\Tencent\Weixin\Weixin.exe",
                 "D:\Program Files\Tencent\Weixin\Weixin.exe")) {
    if (Test-Path $p) { $exe = $p; break }
}
if ($exe) {
    $ver = (Get-Item $exe).VersionInfo.FileVersion
    Say "微信版本 = $ver"
    if ($ver -notlike "4.0.*") {
        Say "警告：本库仅适用于 4.0.x（4.1.13+ 已移除内存明文密钥），继续执行可能取不到密钥。" -ForegroundColor Yellow
    }
}

# 3) 依赖预检
& $Python -c "import Crypto, zstandard" 2>$null
if ($LASTEXITCODE -ne 0) { Fail "缺少依赖：请安装 pycryptodome 与 zstandard" }

# 4) 主流程
$argList = @("-u", "-m", "wxarchive", "all", "--work", $Work, "--out", $Out)
if ($DbDir) { $argList += @("--db-dir", $DbDir) }
Say "执行：wxarchive all"
& $Python @argList
if ($LASTEXITCODE -ne 0) { Fail "导出失败（详见上方输出）" }

# 5) 汇总
$json = Join-Path $Out "chats.json"
if (Test-Path $json) {
    $s = & $Python -c "import json;d=json.load(open(r'$json',encoding='utf-8'));print('%d,%d,%d'%(d['sessions_total'],len(d['contacts']),d['messages_total']))"
    $p = $s.Split(",")
    Say "完成：会话 $($p[0]) 个 / 联系人 $($p[1]) 个 / 消息 $($p[2]) 条"
}
Say "输出目录：$Out"
