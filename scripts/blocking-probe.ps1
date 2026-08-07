# PATANYX — Windows behavioural blocking probe.
#
# The Windows counterpart to scripts/blocking-probe.sh, and the core of the
# gate that promotes Windows out of Preview. It answers the one question a
# clean cross-compile cannot: does a blocked request actually fail to leave
# the machine on WebView2?
#
# Method: point a domain from the bundled block list AND a normal domain at a
# local server, load a page fetching both under a live content filter, and
# read which connections the server ACTUALLY received. Then repeat with
# blocking off as a negative control.
#
# HONESTY NOTE: this script has never been executed. It was written on Linux
# by someone with no Windows machine, and mirrors the Linux probe that HAS
# run. Treat a failure as "the script or the browser is wrong" and read
# before believing either.
#
# Requires: an ELEVATED PowerShell (it edits the hosts file), an interactive
# desktop session (WebView2 must create a real HWND, so this will not work
# over a session-0 service), and the WebView2 Evergreen Runtime.
#
# It no longer binds port 80. Two listeners used to race for `http://+:80/` --
# one in this script, one in the background job -- with the job's bind failure
# swallowed by `catch { return }`, so on any machine where http.sys had
# reserved :80 (which the sibling freeze probe documents as common, and which
# this team hit) the probe ran with NO SERVER and blamed the browser. It now
# uses a plain TcpListener on a high port, chosen by the job and reported back,
# so there is one listener, no URL ACL, and no silent bind failure.
#
#   powershell -ExecutionPolicy Bypass -File blocking-probe.ps1 -Binary .\patanyx-debug.exe
#
# Use the DEBUG binary. The release build sets windows_subsystem = "windows"
# and has no console, so SMOKE OK / PROBE DONE would go nowhere.

param(
    [Parameter(Mandatory = $true)][string]$Binary
)

$ErrorActionPreference = "Stop"

# Runs the browser without letting its stderr abort the probe.
#
# Windows PowerShell 5.1 wraps a native command's stderr in ErrorRecords, and
# under `$ErrorActionPreference = "Stop"` above that becomes a TERMINATING
# NativeCommandError. The debug build writes its `patanyx:` diagnostics to
# stderr by design (platform::windows::diag), and this script REQUIRES the
# debug build -- so every invocation below aborted on the browser's first diag
# line, before a single connection was measured. Found 2026-07-27 on the
# operator's machine, on the first real run: the probe died on
# `profile: user data folder is ...`, which is a line the browser is supposed
# to print.
#
# PowerShell 7 does not do this, which is why it was never noticed: the script
# was written against `pwsh` semantics and run on neither.
#
# `Stop` stays the default for everything else -- a failed hosts-file edit or a
# dead listener must still abort. This relaxes it around the ONE call where
# stderr is expected output rather than a fault.
function Invoke-Browser([string]$exe, [string[]]$browserArgs) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $exe @browserArgs 2>&1 | Out-String
    } finally {
        $ErrorActionPreference = $previous
    }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this from an elevated PowerShell: it edits the hosts file."
    exit 1
}
if (-not (Test-Path $Binary)) { Write-Error "No binary at $Binary"; exit 1 }
$Binary = (Resolve-Path $Binary).Path
Write-Host "probing binary: $Binary"
Write-Host "  built: $((Get-Item $Binary).LastWriteTime)"

$BlockedHost = "doubleclick.net"
$AllowedHost = "allowed.probe.test"
$HostsFile   = "$env:SystemRoot\System32\drivers\etc\hosts"
$Marker      = "# PATANYX-PROBE"
$LogFile     = Join-Path $env:TEMP "patanyx-probe-hits.log"

# ---- hosts file, with the original kept for restoration ---------------------
$hostsBackup = Get-Content $HostsFile -Raw
if ($hostsBackup -notmatch [regex]::Escape($Marker)) {
    Add-Content $HostsFile "`r`n$Marker`r`n127.0.0.1 $BlockedHost`r`n127.0.0.1 $AllowedHost`r`n"
}

# ---- local server ------------------------------------------------------------
#
# ONE listener, owned by the job, on a high port. The job reports the port it
# actually bound through the log file, so the main script never has to guess
# and a bind failure is loud instead of silent.
$serverJob = Start-Job -ArgumentList $LogFile, $BlockedHost, $AllowedHost -ScriptBlock {
    param($logFile, $blockedHost, $allowedHost)

    $listener = $null
    foreach ($p in @(8090, 8091, 8092, 9091)) {
        try {
            $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $p)
            $l.Start()
            $listener = $l
            Add-Content $logFile "READY $p"
            break
        } catch {
            Add-Content $logFile "BINDFAIL $p $($_.Exception.Message)"
        }
    }
    if (-not $listener) { Add-Content $logFile "NOSERVER"; return }

    $port = ($listener.LocalEndpoint).Port
    $page = @"
<!doctype html><meta charset=utf-8><title>probe</title>
<img src="http://${blockedHost}:$port/pixel-blocked.png">
<img src="http://${allowedHost}:$port/pixel-allowed.png">
<script src="http://${blockedHost}:$port/tracker.js"></script>
"@

    while ($true) {
        try {
            if (-not $listener.Pending()) { Start-Sleep -Milliseconds 25; continue }
            $client = $listener.AcceptTcpClient()
            $client.ReceiveTimeout = 2000; $client.SendTimeout = 2000
            $stream = $client.GetStream()
            $buf = New-Object byte[] 4096
            $n = 0
            try { $n = $stream.Read($buf, 0, $buf.Length) } catch {}
            $req = if ($n -gt 0) { [Text.Encoding]::ASCII.GetString($buf, 0, $n) } else { "" }

            $path = "/"
            if ($req -match '^[A-Z]+\s+(\S+)') { $path = $matches[1] }
            # The HOST HEADER is the whole measurement: both names resolve to
            # this machine, so the connection alone says nothing about which
            # domain the page asked for.
            $hostHeader = ""
            if ($req -match '(?im)^Host:\s*([^\r\n:]+)') { $hostHeader = $matches[1].Trim() }
            Add-Content $logFile "$hostHeader $path"

            $isPage = $path -eq "/probe"
            $body = if ($isPage) { [Text.Encoding]::UTF8.GetBytes($page) } else { [byte[]](0x78) }
            $ctype = if ($isPage) { "text/html; charset=utf-8" } else { "image/png" }
            $head = "HTTP/1.1 200 OK`r`nContent-Type: $ctype`r`nContent-Length: $($body.Length)`r`n" +
                    "Cache-Control: no-store`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($head)
            $stream.Write($hb, 0, $hb.Length)
            $stream.Write($body, 0, $body.Length)
            $stream.Flush()
            try { $client.Close() } catch {}
        } catch { }
    }
}

# Wait for the server to say it is up. Without this the browser launches into
# a void and every "nothing was blocked" reading is unattributable.
$probePort = $null
for ($i = 0; $i -lt 100; $i++) {
    Start-Sleep -Milliseconds 100
    if (-not (Test-Path $LogFile)) { continue }
    $lines = Get-Content $LogFile -ErrorAction SilentlyContinue
    $ready = $lines | Where-Object { $_ -like "READY *" } | Select-Object -First 1
    if ($ready) { $probePort = ($ready -split " ")[1]; break }
    if ($lines -contains "NOSERVER") { break }
}
if (-not $probePort) {
    Write-Host "" 
    Write-Host "  PROBE ABORTED: the local server never bound a port." -ForegroundColor Red
    Write-Host "  Nothing below would have meant anything: with no server, a" -ForegroundColor Red
    Write-Host "  blocked request and a browser that never asked look identical." -ForegroundColor Red
    if (Test-Path $LogFile) { Get-Content $LogFile | ForEach-Object { "    $_" } }
    Stop-Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job $serverJob -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Host "  local server on port $probePort" -ForegroundColor DarkGray
# The READY/BINDFAIL lines are bookkeeping, not hits.
Remove-Item $LogFile -ErrorAction SilentlyContinue

function Show-Hits {
    if (Test-Path $LogFile) { Get-Content $LogFile | Group-Object | ForEach-Object {
        "{0,4}  {1}" -f $_.Count, $_.Name } } else { "(none)" }
}

$fail = $null
try {
    # ---- positive: blocking ON ---------------------------------------------
    Remove-Item $LogFile -ErrorAction SilentlyContinue
    $dataDir = Join-Path $env:TEMP ("patanyx-probe-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $dataDir | Out-Null
    $env:PATANYX_DATA_DIR = $dataDir
    # NOT the positional URL: that loads at startup, before the smoke sequence
    # turns blocking on, so a pass could have come from either load.
    $env:PATANYX_BLOCKING_PROBE_URL = "http://${AllowedHost}:$probePort/probe"
    $out = Invoke-Browser $Binary @("--smoke-test")
    Remove-Item Env:\PATANYX_BLOCKING_PROBE_URL
    Write-Host ($out -split "`n" | Select-String "ENGINE|SMOKE|PROBE")

    if ($out -notmatch "PROBE DONE") {
        $fail = "the probe navigation never completed; the result is meaningless"
    }
    Write-Host "`n=== connections received, blocking ON ==="; Show-Hits
    $hits = if (Test-Path $LogFile) { Get-Content $LogFile } else { @() }
    if (-not $fail -and -not ($hits -match "^$AllowedHost /probe$")) {
        $fail = "the page never loaded, so 'nothing was blocked' proves nothing"
    }
    if (-not $fail -and -not ($hits -match "^$AllowedHost /pixel-allowed.png$")) {
        $fail = "the ALLOWED subresource never arrived: the filter is blocking everything"
    }
    if (-not $fail -and ($hits -match "^$BlockedHost ")) {
        $fail = "$BlockedHost was contacted despite being on the block list"
    }

    # ---- negative control: blocking OFF ------------------------------------
    # Without this, a "tracker not contacted" pass is indistinguishable from a
    # broken hosts mapping, a dead server or malformed markup. The positional
    # URL is fetched at startup, before blocking is enabled.
    if (-not $fail) {
        Remove-Item $LogFile -ErrorAction SilentlyContinue
        $dataDir2 = Join-Path $env:TEMP ("patanyx-probe-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dataDir2 | Out-Null
        $env:PATANYX_DATA_DIR = $dataDir2
        Invoke-Browser $Binary @("--smoke-test", "http://${AllowedHost}:$probePort/probe") | Out-Null
        Write-Host "`n=== negative control: same page, blocking OFF ==="; Show-Hits
        $ctl = if (Test-Path $LogFile) { Get-Content $LogFile } else { @() }
        if (-not ($ctl -match "^$BlockedHost ")) {
            $fail = "CONTROL: $BlockedHost was not contacted even with blocking OFF, " +
                    "so this probe cannot detect the bug it exists for"
        }
    }
}
finally {
    Stop-Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job $serverJob -Force -ErrorAction SilentlyContinue
    # Restore the hosts file exactly as found.
    Set-Content $HostsFile $hostsBackup -NoNewline
    Remove-Item Env:\PATANYX_DATA_DIR -ErrorAction SilentlyContinue
}

Write-Host ""
if ($fail) {
    Write-Host "PROBE FAIL: $fail" -ForegroundColor Red
    exit 1
}
Write-Host "PROBE OK: with blocking on, the page and its allowed subresource loaded" -ForegroundColor Green
Write-Host "  and $BlockedHost received ZERO connections."
Write-Host "CONTROL OK: with blocking off, the same page DID contact it." -ForegroundColor Green
exit 0
