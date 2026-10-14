# S6：解密全部数据库（对快照操作，不触碰 E:\ 源库）
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File <项目根>\scripts\01_decrypt.ps1

$ErrorActionPreference = 'Stop'
$base = '<项目根>'
$env:PYTHONPATH = Join-Path $base 'lib'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

$keys = Join-Path $base 'keys\all_keys.json'
if (-not (Test-Path $keys)) {
    Write-Host "[中止] 缺少 $keys，请先完成 S5 密钥提取。" -ForegroundColor Red
    exit 1
}

$py = 'python'
$tool = Join-Path $base 'tool\wechat-decrypt-main\decrypt_db.py'

Write-Host "=== S6 全量解密主库 ===" -ForegroundColor Cyan
& $py $tool 2>&1 | Tee-Object -FilePath (Join-Path $base 'logs\decrypt_db.log')
$c1 = $LASTEXITCODE

Write-Host "`n=== S7 WAL 合并 + 完整性校验 ===" -ForegroundColor Cyan
& $py (Join-Path $base 'scripts\02_wal_patch.py') 2>&1 |
    Tee-Object -FilePath (Join-Path $base 'logs\wal_patch.log')
$c2 = $LASTEXITCODE

Write-Host "`n=== 结果 ===" -ForegroundColor Cyan
Write-Host "decrypt_db exit=$c1   wal_patch exit=$c2"
Get-ChildItem (Join-Path $base 'decrypted') -Recurse -Filter *.db |
    Sort-Object Length -Descending | Select-Object -First 15 |
    ForEach-Object { "{0,10:N1} MB  {1}" -f ($_.Length / 1MB), $_.FullName.Replace("$base\decrypted\", '') }
exit ($c1 + $c2)
