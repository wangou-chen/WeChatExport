param(
    [Parameter(Mandatory = $true)][int]$TargetPid,
    [Parameter(Mandatory = $true)][string]$DbFile,
    [int]$Stride = 8,
    [int]$Parts = 4,
    [long]$Max = 0,
    [string]$Tag = "scan"
)
# Multi-part memory key scan launcher.
# Usage: .\94_scan.ps1 -TargetPid 16056 -DbFile <db> -Stride 8 -Parts 4 [-Max N] [-Tag name]
$ErrorActionPreference = "Continue"
$dir = "<项目根>\scripts\93_findkey_cs"
$exe = Join-Path $dir "KeyScan.exe"
$logdir = "<项目根>\logs"

$common = @()
if ($Max -gt 0) { $common += @("--max", "$Max") }

$procs = @()
for ($i = 0; $i -lt $Parts; $i++) {
    $log = Join-Path $logdir ("keyscan_{0}_p{1}.log" -f $Tag, $i)
    $errlog = Join-Path $logdir ("keyscan_{0}_p{1}.err.log" -f $Tag, $i)
    $a = @($TargetPid, $DbFile, "$Stride", "--part", "$i", "$Parts") + $common
    $procs += Start-Process -FilePath $exe -ArgumentList $a -NoNewWindow `
        -RedirectStandardOutput $log -RedirectStandardError $errlog -PassThru
}
Write-Output ("launched parts={0} pids={1}" -f $Parts, (($procs | ForEach-Object { $_.Id }) -join ","))
$procs | Wait-Process
for ($i = 0; $i -lt $Parts; $i++) {
    $log = Join-Path $logdir ("keyscan_{0}_p{1}.log" -f $Tag, $i)
    if (Test-Path $log) { Get-Content $log | Select-String "FOUND|CONFIRMED|oracle_calls" | ForEach-Object { $_.Line } }
}
