# ============================================================================
# 强化版：彻底禁止微信自动更新
#
# 上一版失败的实测原因：
#   * 防火墙规则实际未建立（扫描时规则不存在）
#   * 仅 hosts 生效 → 对「更新器直连 IP / 走未列域名 / 使用已缓存更新包」无效
#   实测时间线：setup_*.xlog 23:06:35 → 4.1.0.30\ 落盘 23:10:38 → 新版启动 23:10:49
#
# 本版核心策略：**直接从根上废掉更新器本体**
#   1. 定位安装目录下所有 WeixinUpdate*.exe，先做 SHA256 备份，
#      再用「同尺寸全零文件」原地替换 → 更新器永远无法执行（对域名/IP 一律免疫）
#   2. 防火墙出站规则按程序阻断更新器（双保险）
#   3. hosts 扩大域名列表（含更新检查与下载端点）
#   4. 删除自启项
#
# 重要前提：可在微信**运行中**替换（正在运行的是 Weixin.exe，更新器未被加载）。
#           回滚：-Restore 从备份还原更新器、删规则、清 hosts、还原自启项。
#
# 用法（管理员 PowerShell）：
#   powershell -ExecutionPolicy Bypass -File .\block_weixin_update_v2.ps1            # 预览
#   powershell -ExecutionPolicy Bypass -File .\block_weixin_update_v2.ps1 -Apply     # 执行
#   powershell -ExecutionPolicy Bypass -File .\block_weixin_update_v2.ps1 -Restore   # 回滚
# ============================================================================
param(
    [switch]$Apply,
    [switch]$Restore,
    [string]$InstallDir = "D:\Program Files (x86)\Tencent\Weixin",
    [string]$BackupDir = "C:\Users\Lenovo\Desktop\WeChatExport\update_block_backup"
)

$ErrorActionPreference = "Continue"
$Marker = "# === wxarchive: block weixin update v2 (managed) ==="
$RuleName = "wxarchive-block-weixin-update"

# 更新检查 + 下载分发端点（只封这些，不封 weixin.qq.com 主域以免影响功能）
$Domains = @(
    "dldir1.qq.com", "dldir1v6.qq.com", "dldir2.qq.com", "dldir3.qq.com",
    "dl.qq.com", "up.qq.com", "update.qq.com", "update.weixin.qq.com",
    "cdn.update.weixin.qq.com", "dldir.qq.com", "dlsw.qq.com",
    "update.tencent.com", "updatem.qq.com", "wm.qq.com"
)

function Say($m) { Write-Host $m }
function Admin { (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

# ------------------------------------------------------------------ 定位更新器
$updaters = @()
if (Test-Path $InstallDir) {
    $updaters = @(Get-ChildItem $InstallDir -Recurse -Filter "WeixinUpdate*.exe" -ErrorAction SilentlyContinue)
}
Say "安装目录 = $InstallDir"
Say ("发现更新器 {0} 个：" -f $updaters.Count)
$updaters | ForEach-Object { Say ("   {0}  ({1:N0} 字节)" -f $_.FullName, $_.Length) }

# ------------------------------------------------------------------ 回滚
if ($Restore) {
    if (-not (Admin)) { Say "[!] 需要管理员权限"; exit 1 }
    Say "`n=== 回滚 ==="
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    Say "已删除防火墙规则"

    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    $keep = Get-Content $hosts -ErrorAction SilentlyContinue |
            Where-Object { $_ -notmatch [regex]::Escape($Marker) -and
                           $_ -notmatch "^\s*127\.0\.0\.1\s+.*(qq\.com|weixin)" }
    Set-Content $hosts -Value $keep -Encoding ASCII
    Say "已清理 hosts 受管条目"

    $bak = Join-Path $BackupDir "run_weixin.txt"
    if (Test-Path $bak) {
        New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Weixin `
            -Value (Get-Content $bak -Raw).Trim() -PropertyType String -Force | Out-Null
        Say "已恢复自启项"
    }
    Get-ChildItem $BackupDir -Filter "WeixinUpdate*.bak" -ErrorAction SilentlyContinue | ForEach-Object {
        $orig = ($_.Name -replace "\.bak$", "")
        $dest = Join-Path $InstallDir (Split-Path $orig -Leaf)
        # 备份名形如 <版本目录>__WeixinUpdate.exe.bak
        $parts = $orig -split "__"
        if ($parts.Count -eq 2) { $dest = Join-Path (Join-Path $InstallDir $parts[0]) $parts[1] }
        Copy-Item $_.FullName $dest -Force
        Say "已还原更新器: $dest"
    }
    Say "回滚完成。"
    exit 0
}

# ------------------------------------------------------------------ 预览
if (-not $Apply) {
    Say "`n=== 预览（不改动任何东西）==="
    Say "1) 替换更新器为同尺寸全零文件（先做 SHA256 备份）："
    $updaters | ForEach-Object { Say ("     {0}" -f $_.FullName) }
    Say "2) 创建防火墙出站阻断规则: $RuleName"
    Say ("3) hosts 追加 {0} 个域名 -> 127.0.0.1" -f $Domains.Count)
    Say "4) 删除自启项 HKCU\...\Run\Weixin"
    Say "`n加 -Apply 执行；-Restore 回滚。"
    Say "备份目录: $BackupDir"
    exit 0
}

# ------------------------------------------------------------------ 执行
if (-not (Admin)) {
    Say "[!] 需要管理员权限：请用管理员身份运行 PowerShell 后重跑。"
    Say "    （本环境无提权能力，脚本到此停止，未做任何改动）"
    exit 1
}

New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
Say "`n=== 1/4 废掉更新器本体 ==="
foreach ($u in $updaters) {
    $verDir = Split-Path $u.FullName -Leaf
    $verName = Split-Path (Split-Path $u.FullName -Parent) -Leaf
    $bakFile = Join-Path $BackupDir ("{0}__{1}.bak" -f $verName, $u.Name)
    if (-not (Test-Path $bakFile)) {
        Copy-Item $u.FullName $bakFile -Force
        $hash = (Get-FileHash $bakFile -Algorithm SHA256).Hash
        "SHA256 $hash  $bakFile" | Add-Content (Join-Path $BackupDir "update_backup_hashes.txt")
        Say ("   备份 {0}   SHA256={1}" -f (Split-Path $bakFile -Leaf), $hash.Substring(0, 16))
    }
    $size = $u.Length
    try {
        [System.IO.File]::WriteAllBytes($u.FullName, (New-Object byte[] $size))
        Say ("   已废掉: {0}（{1:N0} 字节置零）" -f $u.FullName, $size)
    } catch {
        Say ("   [!] 替换失败（可能被占用）: {0}  {1}" -f $u.FullName, $_.Exception.Message)
    }
}

Say "`n=== 2/4 防火墙出站阻断 ==="
Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
$paths = $updaters | ForEach-Object { $_.FullName }
if ($paths.Count -gt 0) {
    $ok = 0
    foreach ($p in $paths) {
        try {
            New-NetFirewallRule -DisplayName "$RuleName" -Direction Outbound -Action Block `
                -Program $p -Profile Any -ErrorAction Stop | Out-Null
            $ok++
        } catch {
            Say ("   [!] 规则创建失败: {0}" -f $_.Exception.Message)
        }
    }
    Say ("   已创建 {0}/{1} 条程序阻断规则" -f $ok, $paths.Count)
    if ($ok -eq 0) { Say "   [!] 防火墙规则未能创建（可改用 hosts + 更新器置零兜底）" }
} else { Say "   无更新器，跳过" }

Say "`n=== 3/4 hosts 黑洞 ==="
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
if (-not (Test-Path (Join-Path $BackupDir "hosts.bak"))) {
    Copy-Item $hosts (Join-Path $BackupDir "hosts.bak") -Force
}
$cur = Get-Content $hosts -ErrorAction SilentlyContinue |
       Where-Object { $_ -notmatch [regex]::Escape($Marker) -and $_ -notmatch "^\s*127\.0\.0\.1\s+.*(qq\.com|weixin)" }
$add = @($Marker)
$Domains | ForEach-Object { $add += ("127.0.0.1`t$_") }
$add += "# === end wxarchive block v2 ==="
($cur + $add) | Set-Content $hosts -Encoding ASCII
Say ("   已写入 {0} 条域名阻断" -f $Domains.Count)

Say "`n=== 4/4 自启项 ==="
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$val = (Get-ItemProperty $key -Name Weixin -ErrorAction SilentlyContinue).Weixin
if ($val) {
    Set-Content (Join-Path $BackupDir "run_weixin.txt") $val -Encoding UTF8
    Remove-ItemProperty $key -Name Weixin -ErrorAction SilentlyContinue
    Say "   已删除自启项（原值已备份）"
} else { Say "   无自启项" }

Say "`n完成。回滚：-Restore"
Say "验证：重开微信后，若 D:\...\Weixin\ 下不再出现新版本目录，即拦截成功。"
