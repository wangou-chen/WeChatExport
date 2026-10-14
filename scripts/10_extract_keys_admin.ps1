# 仅在【普通会话免提权方案】失败时才需要本脚本
# 以【管理员身份】运行的 PowerShell 中执行：
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Lenovo\Desktop\WeChatExport\scripts\10_extract_keys_admin.ps1
#
# 用途：从 Weixin.exe 进程内存提取各数据库的 SQLCipher raw key
# 前置：微信必须处于登录运行状态

$ErrorActionPreference = 'Stop'
$base = 'C:\Users\Lenovo\Desktop\WeChatExport'
$env:PYTHONPATH = Join-Path $base 'lib'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

Write-Host "=== 身份与前置检查 ===" -ForegroundColor Cyan
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$isAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ("管理员: {0}" -f $isAdmin)
if (-not $isAdmin) {
    Write-Host "[中止] 未提权。请右键 PowerShell -> 以管理员身份运行，再执行本脚本。" -ForegroundColor Red
    exit 1
}

$p = Get-Process Weixin -ErrorAction SilentlyContinue |
     Sort-Object WorkingSet64 -Descending | Select-Object -First 1
if (-not $p) {
    Write-Host "[中止] Weixin.exe 未运行，请先登录微信。" -ForegroundColor Red
    exit 1
}
Write-Host ("Weixin.exe PID={0}  内存={1} MB" -f $p.Id, [int]($p.WorkingSet64 / 1MB))

Write-Host "`n=== 提取密钥 ===" -ForegroundColor Cyan
$py = 'C:\Python314\python.exe'
$script = Join-Path $base 'scripts\01_extract_keys.py'
& $py $script --pid $p.Id 2>&1 |
    Tee-Object -FilePath (Join-Path $base 'logs\extract_keys.log')
$code = $LASTEXITCODE
Write-Host "`nexit=$code"

$keys = Join-Path $base 'keys\all_keys.json'
if (Test-Path $keys) {
    Write-Host "[成功] 密钥文件已生成: $keys" -ForegroundColor Green
    Write-Host "       [[下一步]] 运行 scripts\01_decrypt.ps1"
} else {
    Write-Host "[失败] 未生成 all_keys.json，见 logs\extract_keys.log" -ForegroundColor Red
}
exit $code
