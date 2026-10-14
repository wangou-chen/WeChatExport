# ============================================================================
# 微信 4.0.x 聊天记录导出 —— 一键脚本（调用本项目自足库 wxarchive）
#
#   无需 agent、无需外部逆向工具。仅依赖 pycryptodome + zstandard。
#
# 前提：
#   1) 微信版本为 4.0.x / 4.1.0.x（4.1.13+ 内存中无明文密钥，会失败）
#   2) 微信正在运行且已登录过（保持登录态，重启无需扫码）
#
# 用法（在本目录下执行，或任意位置用 -Root 指定项目根）：
#   powershell -ExecutionPolicy Bypass -File .\oneclick.ps1
#   可选：-Root <项目根> -DbDir <db_storage> -Work <解密目录> -Out <导出目录> -Python <python.exe>
#
# 可移植性：根目录默认取【本脚本所在目录】，可整目录拷贝到任意位置运行，无需改脚本。
# ============================================================================
param(
    [string]$Root = "",
    [string]$DbDir = "",
    [string]$Work = "",
    [string]$Out = "",
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"

if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.Path }
$Root = (Resolve-Path $Root).Path
if (-not $Work) { $Work = Join-Path $Root "decrypted" }
if (-not $Out)  { $Out  = Join-Path $Root "out" }

function Say($m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Fail($m) { Write-Host "[错误] $m" -ForegroundColor Red; exit 1 }

Say "wxarchive 一键导出 —— 开始"
Say "项目根目录 = $Root"

# 1) Python：参数 > PATH > 常见安装位置
if (-not $Python) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source }
    if (-not $Python) {
        # 用户级常见安装位置优先（不依赖特定用户名/机器）
        foreach ($v in @("313", "312", "311", "310")) {
            $c = Join-Path $env:LOCALAPPDATA "Programs\Python\Python$v\python.exe"
            if (Test-Path $c) { $Python = $c; break }
        }
        if (-not $Python) {
            $c = Get-ChildItem "C:\" -Filter "Python3*" -Directory -ErrorAction SilentlyContinue |
                 Sort-Object Name -Descending |
                 ForEach-Object { Join-Path $_.FullName "python.exe" } |
                 Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($c) { $Python = $c }
        }
    }
}
if (-not $Python -or -not (Test-Path $Python)) { Fail "未找到 python.exe，请用 -Python 指定" }
$env:PYTHONUTF8 = "1"
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$Root;$env:PYTHONPATH" } else { $Root }
Say "Python = $Python"

# 2) 依赖预检
& $Python -c "import Crypto, zstandard" 2>$null
if ($LASTEXITCODE -ne 0) { Fail "缺少依赖：请执行  pip install pycryptodome zstandard" }

# 3) 微信版本提示（找不到安装目录时只提示、不阻断）
$exe = $null
foreach ($p in @("$env:ProgramFiles\Tencent\Weixin\Weixin.exe",
                 "${env:ProgramFiles(x86)}\Tencent\Weixin\Weixin.exe",
                 "$env:LOCALAPPDATA\Tencent\Weixin\Weixin.exe")) {
    if ($p -and (Test-Path $p)) { $exe = $p; break }
}
if ($exe) {
    $ver = (Get-Item $exe).VersionInfo.FileVersion
    Say "微信版本 = $ver"
    if ($ver -notmatch '^4\.(0|1\.0)\.') {
        Say "警告：本工具仅适用于 4.0.x / 4.1.0.x（4.1.13+ 已移除内存明文密钥）" -ForegroundColor Yellow
    }
} else {
    Say "提示：未自动定位到 Weixin.exe（不影响；数据目录将自动探测或由 -DbDir 指定）"
}

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
