# PATANYX -- Windows: does a login survive closing the browser?
#
# The one question cookie-probe.ps1 did not get to answer. Its cross-site half
# ran clean on 2026-08-01 (third-party cookies refused outright, same as
# Linux); its second run never reached the login page, because the browser was
# navigated somewhere else while it sat open.
#
# So this is that half ALONE: two launches, one URL, nothing to interfere with.
# Shorter is the whole point -- less time with a window open is less chance of
# the window being used.
#
# LINUX ANSWER, for comparison (cookie-persistence-probe.sh, 2026-08-01): NO.
# A persistent first-party cookie does not survive a restart and no cookie
# store is written to the profile at all, so every launch starts signed out.
# WebView2 keeps a Chromium profile and is expected to differ. Expected is not
# measured, which is why this exists.
#
# WHILE IT RUNS: the browser opens twice and closes itself each time. Each
# launch sits blank for ~25 seconds first -- that is the vault's password
# hashing at full strength, not a hang. Do not type or click in the window.
# Anything you navigate to REPLACES the probe's own navigation and voids the
# run; that is exactly what happened last time.
#
# Run:  powershell -ExecutionPolicy Bypass -File .\login-probe.ps1 -Binary .\PATANYX-debug.exe
#
# Exit: 0 = logins persist   3 = logins do not persist   2 = VOID   1 = error
param(
    [Parameter(Mandatory = $true)][string]$Binary
)

$ErrorActionPreference = "Stop"

function Invoke-Browser([string]$exe, [string[]]$browserArgs, [int]$TimeoutSec = 240) {
    $stamp = Get-Random
    $outFile = Join-Path $Work "run-$stamp.out"
    $errFile = Join-Path $Work "run-$stamp.err"
    $proc = Start-Process -FilePath $exe -ArgumentList $browserArgs -PassThru -NoNewWindow `
                          -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
        try { $proc.Kill() } catch { }
        Write-Host "  (timed out after ${TimeoutSec}s and was killed)"
    }
    $text = ""
    foreach ($f in @($outFile, $errFile)) {
        if (Test-Path $f) { $text += (Get-Content $f -Raw -ErrorAction SilentlyContinue) }
    }
    return $text
}

if (-not (Test-Path $Binary)) { Write-Error "PROBE FAIL: no binary at $Binary"; exit 1 }
$Binary = (Resolve-Path $Binary).Path
Write-Host "probing binary: $Binary ($((Get-Item $Binary).LastWriteTime))"

$Work = Join-Path ([System.IO.Path]::GetTempPath()) "patanyx-login-probe-$PID"
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$LogFile  = Join-Path $Work "hits.log"
$EmptyLst = Join-Path $Work "blocklist-empty.txt"
Set-Content -Path $EmptyLst -Value "" -Encoding ascii
# ONE profile across both launches -- survival across restarts IS the question.
$ProfileDir = Join-Path $Work "profile"
New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null

$serverJob = Start-Job -ArgumentList $LogFile -ScriptBlock {
    param($logFile)
    $listener = $null
    foreach ($p in @(8961, 8962, 8963, 9961)) {
        try {
            $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $p)
            $l.Start(); $listener = $l; Add-Content $logFile "READY $p"; break
        } catch { Add-Content $logFile "BINDFAIL $p $($_.Exception.Message)" }
    }
    if (-not $listener) { Add-Content $logFile "NOSERVER"; return }

    while ($true) {
        try {
            if (-not $listener.Pending()) { Start-Sleep -Milliseconds 25; continue }
            $client = $listener.AcceptTcpClient()
            $client.ReceiveTimeout = 2000; $client.SendTimeout = 2000
            $stream = $client.GetStream()
            $buf = New-Object byte[] 8192
            $n = 0
            try { $n = $stream.Read($buf, 0, $buf.Length) } catch {}
            $req = if ($n -gt 0) { [Text.Encoding]::ASCII.GetString($buf, 0, $n) } else { "" }
            $path = "/"
            if ($req -match '^[A-Z]+\s+(\S+)') { $path = $matches[1] }
            $cookie = "<none>"
            if ($req -match '(?im)^Cookie:\s*([^\r\n]+)') { $cookie = $matches[1].Trim() }

            if ($path -like "/login*") {
                Add-Content $logFile "LOGIN cookie=$cookie"
                $body = "<!doctype html><meta charset=utf-8><title>login</title>" +
                        "<body style=""font:16px system-ui;background:#111;color:#eee;padding:2rem"">" +
                        "<h1>signed in</h1><p>This window closes itself. Please do not touch it.</p></body>"
                $bytes = [Text.Encoding]::UTF8.GetBytes($body)
                # Max-Age makes this a PERSISTENT cookie. A session cookie is
                # SUPPOSED to die with the browser, so only this shape can
                # answer "am I still signed in tomorrow".
                $head = "HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`n" +
                        "Set-Cookie: sessionid=logged-in; Path=/; Max-Age=86400; SameSite=Lax`r`n" +
                        "Content-Length: $($bytes.Length)`r`nCache-Control: no-store`r`nConnection: close`r`n`r`n"
                $hb = [Text.Encoding]::ASCII.GetBytes($head)
                $stream.Write($hb, 0, $hb.Length); $stream.Write($bytes, 0, $bytes.Length)
            } else {
                # 404 everything else, so favicon fetches cannot masquerade as
                # measurements in the log.
                Add-Content $logFile "OTHER $path cookie=$cookie"
                $b = [Text.Encoding]::UTF8.GetBytes("not found")
                $h = "HTTP/1.1 404 Not Found`r`nContent-Type: text/plain`r`n" +
                     "Content-Length: $($b.Length)`r`nConnection: close`r`n`r`n"
                $hb = [Text.Encoding]::ASCII.GetBytes($h)
                $stream.Write($hb, 0, $hb.Length); $stream.Write($b, 0, $b.Length)
            }
            $stream.Flush(); $client.Close()
        } catch { }
    }
}

try {
    $port = $null
    foreach ($i in 1..40) {
        Start-Sleep -Milliseconds 250
        if (Test-Path $LogFile) {
            $seen = Get-Content $LogFile -ErrorAction SilentlyContinue
            if ($seen -match '^NOSERVER') { Write-Error "PROBE FAIL: no port could be bound."; exit 1 }
            $ready = $seen | Where-Object { $_ -match '^READY (\d+)$' } | Select-Object -First 1
            if ($ready) { $port = [int]($ready -replace '^READY ', ''); break }
        }
    }
    if (-not $port) { Write-Error "PROBE FAIL: the listener never reported READY."; exit 1 }
    Write-Host "  listening on $port"

    function Invoke-Visit([int]$n) {
        # Only the smoke harness's own state is cleared: the vault (its guard
        # refuses to run against an existing one) and the bookmark store. The
        # WebView2 profile holding the cookie jar is deliberately untouched --
        # its survival is the measurement.
        Get-ChildItem -Path $ProfileDir -Filter "vault.rbv*" -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $ProfileDir -Filter "store.rbs" -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        $env:PATANYX_DATA_DIR = $ProfileDir
        $env:XDG_DATA_HOME = $ProfileDir   # so this can be rehearsed on Linux
        $env:PATANYX_BLOCKLIST_PATH = $EmptyLst
        $env:PATANYX_BLOCKING_PROBE_URL = "http://127.0.0.1:$port/login"
        Write-Host "  launch $n -- do not touch the window; it closes itself"
        $out = Invoke-Browser $Binary @("--smoke-test")
        if ($out -notmatch "PROBE DONE") {
            Write-Host ""
            Write-Host "PROBE FAIL on launch ${n}: the browser never completed the probe" -ForegroundColor Red
            Write-Host "navigation, so nothing was measured." -ForegroundColor Red
            Write-Host "If a page other than the probe's was opened in that window, that is" -ForegroundColor Yellow
            Write-Host "the cause -- it replaces the navigation being measured." -ForegroundColor Yellow
            Write-Host ($out -split "`n" | Where-Object { $_ -match 'NAV url=|SMOKE FAIL' } |
                         Select-Object -First 8 | Out-String)
            exit 2
        }
    }

    Write-Host ""
    Invoke-Visit 1
    Invoke-Visit 2

    $log = Get-Content $LogFile
    $logins = @($log | Where-Object { $_ -like "LOGIN *" })
    Write-Host ""
    Write-Host "--- what the server saw ---" -ForegroundColor DarkGray
    $log | Where-Object { $_ -notmatch '^(READY|BINDFAIL)' } | ForEach-Object { Write-Host "  $_" }

    if ($logins.Count -lt 2) {
        Write-Error "CONTROL FAIL: the login page was reached $($logins.Count) time(s), not twice. Nothing measured."
        exit 2
    }

    Write-Host ""
    Write-Host "================ RESULT ================" -ForegroundColor White
    Write-Host "  launch 1 : $($logins[0])"
    Write-Host "  launch 2 : $($logins[1])"
    Write-Host ""
    if ($logins[1] -match "sessionid=logged-in") {
        Write-Host "LOGINS PERSIST on Windows." -ForegroundColor Green
        Write-Host "A site that signs you in still knows you on the next launch, the same"
        Write-Host "as an ordinary browser -- and UNLIKE Linux, where nothing survives."
        exit 0
    }
    Write-Host "LOGINS DO NOT PERSIST on Windows." -ForegroundColor Yellow
    Write-Host "The cookie was persistent (Max-Age), not a session cookie, and it was"
    Write-Host "still gone on the next launch. Every launch starts signed out of every"
    Write-Host "site -- the same as Linux."
    exit 3
}
finally {
    Stop-Job $serverJob -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $serverJob -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host ""
    Write-Host "log kept at: $LogFile" -ForegroundColor DarkGray
}
