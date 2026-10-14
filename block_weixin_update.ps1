# ============================================================================
# 禁止微信自动更新（Windows）—— 多层阻断 + 可回滚
#
# 为什么需要：微信 4.1.13+ 移除了内存中的明文数据库密钥缓存，
# 一旦自动升级，本项目（wxarchive）将无法再取密钥。降级到 4.0.x 后必须阻断更新。
#
# 阻断层（按可靠性排序，逐层独立生效）：
#   1. 防火墙出站规则：阻断 WeixinUpdate.exe / WeixinUpdate 相关程序联网
#   2. hosts 黑洞：把腾讯下载/更新域名指向 127.0.0.1（升级包拿不到）
#   3. 自启项清理：删除 HKCU\...\Run\Weixin（减少启动即检查更新）
#   4. 更新器改名（可选 -RenameUpdater）：把 WeixinUpdate.exe 改为 .disabled
#
# 回滚：
#   -Restore   撤销 2/3/4（防火墙规则一并删除）
#
# 用法（需要管理员权限；不带 -Apply 时仅预览，不改动任何东西）：
#   powershell -ExecutionPolicy Bypass -File .\block_weixin_update.ps1
#   powershell -ExecutionPolicy Bypass -File .\block_weixin_update.ps1 -Apply
#   powershell -ExecutionPolicy Bypass -File .\block_weixin_update.ps1 -Apply -RenameUpdater
#   powershell -ExecutionPolicy Bypass -File .\block_weixin_update.ps1 -Restore
# ============================================================================
param(
    [switch]$Apply,
    [switch]$Restore,
    [switch]$RenameUpdater,
    [string]$InstallDir = "",
    [string]$BackupDir = "<项目根>\update_block_backup"
)

$ErrorActionPreference = "Continue"
$Marker = "# === wxarchive: block weixin update (managed) ==="
$RuleName = "wxarchive-block-weixin-update"

# 腾讯「下载/更新分发」端点。**只封下载域，不封 weixin.qq.com / servicewechat.com**：
# 后者承载小程序与功能接口，封了会有副作用（功能异常）。
# 升级包必须从下列 CDN 拉取，封住即拿不到升级包。
$Domains = @(
    "dldir1.qq.com", "dldir1v6.qq.com", "dldir2.qq.com", "dldir3.qq.com",
    "dl.qq.com", "up.qq.com", "update.qq.com", "update.weixin.qq.com",
    "cdn.update.weixin.qq.com"
)

function Say($m) { Write-Host $m }
function Need-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ------------------------------------------------------------------ 查找安装目录
if (-not $InstallDir) {
    foreach ($p in @("D:\Program Files (x86)\Tencent\Weixin",
                     "C:\Program Files\Tencent\Weixin",
                     "D:\Program Files\Tencent\Weixin")) {
        if (Test-Path $p) { $InstallDir = $p; break }
    }
}
Say "安装目录 = $InstallDir"
$updaters = @()
if ($InstallDir -and (Test-Path $InstallDir)) {
    $updaters = Get-ChildItem $InstallDir -Recurse -Filter "WeixinUpdate*.exe" -ErrorAction SilentlyContinue
}
Say ("找到更新器 {0} 个：" -f $updaters.Count)
$updaters | ForEach-Object { Say ("   " + $_.FullName) }

# ------------------------------------------------------------------ 回滚
if ($Restore) {
    Say "`n=== 回滚 ==="
    if (-not (Need-Admin)) { Say "[!] 需要管理员权限，请以管理员身份重开 PowerShell"; exit 1 }

    # 1) 防火墙规则
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    Say "已删除防火墙规则: $RuleName"

    # 2) hosts
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    $lines = Get-Content $hosts -ErrorAction SilentlyContinue
    $kept = $lines | Where-Object { $_ -notmatch [regex]::Escape($Marker) -and
                                    $_ -notmatch "^\s*127\.0\.0\.1\s+.*(qq\.com|weixin)" }
    Set-Content -Path $hosts -Value $kept -Encoding ASCII
    Say "已清理 hosts 中的阻断条目"

    # 3) 自启项
    $bak = Join-Path $BackupDir "run_weixin.txt"
    if (Test-Path $bak) {
        $v = (Get-Content $bak -Raw).Trim()
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
            -Name "Weixin" -Value $v -PropertyType String -Force | Out-Null
        Say "已恢复自启项: $v"
    } else { Say "未找到自启项备份，跳过" }

    # 4) 更新器改名
    Get-ChildItem $InstallDir -Recurse -Filter "WeixinUpdate*.exe.disabled" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $orig = $_.FullName -replace "\.disabled$", ""
            Move-Item $_.FullName $orig -Force
            Say "已恢复更新器: $orig"
        }
    Say "回滚完成。"
    exit 0
}

# ------------------------------------------------------------------ 预览
if (-not $Apply) {
    Say "`n=== 预览模式（不会改动任何东西）==="
    Say "1) 将创建防火墙出站阻断规则: $RuleName"
    $updaters | ForEach-Object { Say ("     阻断程序: " + $_.FullName) }
    Say "2) 将向 hosts 追加 $($Domains.Count) 个域名 -> 127.0.0.1"
    $Domains | ForEach-Object { Say ("     $_") }
    Say "3) 将删除自启项 HKCU\...\Run\Weixin（删除前备份到 $BackupDir）"
    if ($RenameUpdater) { Say "4) 将把 WeixinUpdate*.exe 改名为 *.exe.disabled" }
    else { Say "4) （未指定 -RenameUpdater，跳过改名）" }
    Say "`n加 -Apply 执行。"
    exit 0
}

# ------------------------------------------------------------------ 执行
if (-not (Need-Admin)) {
    Say "[!] 需要管理员权限：请右键 PowerShell -> 以管理员身份运行，然后重跑。"
    Say "    （本沙箱环境无法提权，需你在普通管理员终端执行）"
    exit 1
}

New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
Say "`n=== 执行阻断 ==="

# 1) 防火墙
$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) { Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue }
if ($updaters.Count -gt 0) {
    $progs = $updaters | ForEach-Object { $_.FullName }
    New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Action Block `
        -Program ($progs[0]) -Profile Any -ErrorAction SilentlyContinue | Out-Null
    Say "已创建防火墙出站阻断规则（$($progs.Count) 个程序）"
} else {
    Say "[!] 未找到更新器程序，跳过防火墙规则"
}

# 2) hosts
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
Copy-Item $hosts (Join-Path $BackupDir "hosts.bak") -Force
$cur = Get-Content $hosts -ErrorAction SilentlyContinue
$add = @($Marker)
$Domains | ForEach-Object { $add += ("127.0.0.1`t$_") }
$add += "# === end wxarchive block ==="
($cur + $add) | Set-Content -Path $hosts -Encoding ASCII
Say "已写入 hosts 阻断 $($Domains.Count) 条"

# 3) 自启项
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$val = (Get-ItemProperty -Path $key -Name "Weixin" -ErrorAction SilentlyContinue).Weixin
if ($val) {
    Set-Content -Path (Join-Path $BackupDir "run_weixin.txt") -Value $val -Encoding UTF8
    Remove-ItemProperty -Path $key -Name "Weixin" -ErrorAction SilentlyContinue
    Say "已删除自启项（原值已备份）"
} else {
    Say "无自启项，跳过"
}

# 4) 更新器改名
if ($RenameUpdater -and $updaters.Count -gt 0) {
    foreach ($u in $updaters) {
        $dst = $u.FullName + ".disabled"
        Move-Item $u.FullName $dst -Force
        Say ("已改名: " + $dst)
    }
}

Say "`n完成。回滚请运行同一脚本并加 -Restore"
Say "提示：若微信仍提示更新，说明它通过其它域名拉取，可再补 hosts 条目（观察 update_*.xlog 或其网络连接）。"
