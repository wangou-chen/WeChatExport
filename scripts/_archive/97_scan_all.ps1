param(
    [Parameter(Mandatory = $true)][int]$TargetPid,
    [Parameter(Mandatory = $true)][string]$DbFile,
    [int]$Stride = 8,
    [int]$Parts = 16,
    [string]$Tag = "scan",
    [int]$PollSeconds = 30
)
# Launch K independent single-threaded Python scanner processes (region modulo split),
# then poll logs; abort the rest as soon as one reports FOUND.
$ErrorActionPreference = "Continue"
$py = "C:\Python314\python.exe"
$script = "C:\Users\Lenovo\Desktop\WeChatExport\scripts\95_memscan_mp.py"
$logdir = "C:\Users\Lenovo\Desktop\WeChatExport\logs"
$keydir = "C:\Users\Lenovo\Desktop\WeChatExport\keys"
$env:PYTHONUTF8 = "1"

$hits = @()
$procs = @()
for ($i = 0; $i -lt $Parts; $i++) {
    $out = Join-Path $logdir ("pyscan_{0}_p{1}.log" -f $Tag, $i)
    $err = Join-Path $logdir ("pyscan_{0}_p{1}.err.log" -f $Tag, $i)
    $key = Join-Path $keydir ("{0}_p{1}.key.json" -f $Tag, $i)
    $a = @($script, "--pid", "$TargetPid", "--db", $DbFile, "--stride", "$Stride",
           "--part", "$i/$Parts", "--out", $key)
    $procs += Start-Process -FilePath $py -ArgumentList $a -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
}
Write-Output ("launched {0} parts" -f $Parts)

$deadline = (Get-Date).AddHours(6)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $PollSeconds
    $found = Select-String -Path (Join-Path $logdir ("pyscan_{0}_p*.log" -f $Tag)) -Pattern "^FOUND" -ErrorAction SilentlyContinue
    if ($found) {
        $hits += $found
        Write-Output "HIT detected, terminating remaining workers"
        Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -gt (Get-Date).AddHours(-6) } |
            ForEach-Object { try { $_.Kill() } catch {} }
        break
    }
    $alive = (Get-Process python -ErrorAction SilentlyContinue | Measure-Object).Count
    $errTail = @()
    for ($i = 0; $i -lt $Parts; $i++) {
        $e = Join-Path $logdir ("pyscan_{0}_p{1}.err.log" -f $Tag, $i)
        if (Test-Path $e) { $errTail += (Get-Content $e -Tail 1) }
    }
    $rate = ($errTail | Select-String "rate=(\d+)/s" -AllMatches | ForEach-Object { [int]$_.Matches[0].Groups[1].Value } | Measure-Object -Sum).Sum
    Write-Output ("[{0}] python procs={1} sum_rate≈{2}/s" -f (Get-Date -Format "HH:mm:ss"), $alive, $rate)
    if ($alive -eq 0) { break }
}
Get-ChildItem (Join-Path $logdir ("pyscan_{0}_p*.log" -f $Tag)) -ErrorAction SilentlyContinue |
    ForEach-Object { Get-Content $_.FullName | Select-String "FOUND|DONE" | ForEach-Object { $_.Line } }
