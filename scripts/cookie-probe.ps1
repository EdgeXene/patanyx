# PATANYX -- Windows cookie behaviour: two questions, one run.
#
#   Q1  CROSS-SITE TRACKING. Can one third party recognise the same browser on
#       two unrelated sites? (Linux answer, measured 2026-08-01: no. WebKitGTK
#       refuses third-party cookie storage outright, and NOT because of ITP --
#       proven by disabling ITP and getting the same refusal.)
#
#   Q2  STAYING SIGNED IN. Does an ordinary first-party login cookie survive
#       closing and reopening the browser? (Linux answer: NO. Nothing writes a
#       cookie store to disk at all, so every launch starts signed out.)
#
# WebView2 is Chromium and stores its own profile; both answers are expected to
# differ from Linux, and neither may be claimed anywhere until this has run.
#
# WHY THE HOST HEADER RATHER THAN THREE ADDRESSES. One listener on Any, and the
# Host header says which name the browser asked for -- the trick
# malicious-probe.ps1 already uses, and it avoids depending on Windows binding
# 127.0.0.2 and 127.0.0.3 separately. Three names, three origins to the engine:
#
#   127.0.0.1  first-party site A
#   127.0.0.2  first-party site B   (a DIFFERENT site, same session)
#   127.0.0.3  the third party, embedded by both
#
# WHAT YOU NEED: Windows, a DEBUG build of PATANYX (the release build has no
# console and prints nothing this script can read), and this file. Nothing
# leaves the machine.
#
# Run:  powershell -ExecutionPolicy Bypass -File scripts\cookie-probe.ps1 -Binary <path to patanyx.exe>
#
# Exit codes: 0 = measured, cross-site refused   3 = measured, cross-site works
#             2 = VOID, nothing measured         1 = probe error
param(
    [Parameter(Mandatory = $true)][string]$Binary
)

$ErrorActionPreference = "Stop"

# Start-Process with file redirects, not `& $exe 2>&1`. Windows PowerShell 5.1
# turns a native command's stderr into error records and `Stop` makes the first
# one terminating -- and the debug build always writes diagnostics to stderr,
# so the direct call dies on every run. Plus this gives a timeout: without one,
# a browser that never reaches PROBE DONE hangs the script forever with a
# window open, which looks exactly like "still working". Both lessons are
# already recorded in malicious-probe.ps1.
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

if (-not (Test-Path $Binary)) {
    Write-Error "PROBE FAIL: no binary at $Binary"
    exit 1
}
$Binary = (Resolve-Path $Binary).Path
Write-Host "probing binary: $Binary ($((Get-Item $Binary).LastWriteTime))"

# GetTempPath() rather than $env:TEMP, which is null off Windows -- that is
# what lets this script's own mechanics be rehearsed against a Linux binary
# before it ever meets a Windows machine.
$Work = Join-Path ([System.IO.Path]::GetTempPath()) "patanyx-cookie-probe-$PID"
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$LogFile  = Join-Path $Work "hits.log"
$EmptyLst = Join-Path $Work "blocklist-empty.txt"
Set-Content -Path $EmptyLst -Value "" -Encoding ascii
# ONE profile for the whole run, because Q2 is about survival across restarts.
$Profile = Join-Path $Work "profile"
New-Item -ItemType Directory -Path $Profile -Force | Out-Null

# ---------------------------------------------------------------------------
# The server. Logs every request's Host header, path, and the Cookie header it
# actually received -- the browser is never asked to describe itself.
# ---------------------------------------------------------------------------
$serverJob = Start-Job -ArgumentList $LogFile -ScriptBlock {
    param($logFile)

    $listener = $null
    foreach ($p in @(8951, 8952, 8953, 9951)) {
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
            $hostHeader = ""
            if ($req -match '(?im)^Host:\s*([^\r\n:]+)') { $hostHeader = $matches[1].Trim() }
            $cookie = "<none>"
            if ($req -match '(?im)^Cookie:\s*([^\r\n]+)') { $cookie = $matches[1].Trim() }

            $setCookies = @()
            $body = ""
            $ctype = "text/html; charset=utf-8"

            # ORDER MATTERS, and for a PowerShell-only reason: `?` is a
            # WILDCARD in -like, so "/tp?*" also matches "/tp-firstparty" and
            # would swallow stage 3 into the embed branch. The bash sibling
            # cannot have this bug; the rehearsal against the Linux binary is
            # what found it. Specific pattern first.
            if ($path -like "/tp-firstparty*") {
                # THE DISAMBIGUATOR. Same host, reached top-level, so it is the
                # FIRST party and SameSite restricts nothing. A cookie here
                # means it was stored while embedded and merely not sent (which
                # is ordinary SameSite, not a defense); no cookie means the
                # third-party Set-Cookie was refused outright.
                Add-Content $logFile "TPFIRSTPARTY cookie=$cookie"
                $body = "<!doctype html><meta charset=utf-8>third party, first-party context"
            }
            elseif ($path -like "/tp?*") {
                # The third party, EMBEDDED. Three cookie shapes at once, so
                # that "nothing came back" cannot be blamed on one attribute's
                # handling over plain http (SameSite=None cannot carry Secure
                # here, and a Secure cookie would be dropped for that alone).
                $stage = "?"
                if ($path -match 'stage=([^&]+)') { $stage = $matches[1] }
                Add-Content $logFile "TP stage=$stage cookie=$cookie"
                $setCookies = @(
                    "tp_none=tracked-you; Path=/; SameSite=None",
                    "tp_lax=tracked-you; Path=/; SameSite=Lax",
                    "tp_plain=tracked-you; Path=/"
                )
                $body = "<!doctype html><meta charset=utf-8>third party"
            }
            elseif ($path -like "/login*") {
                # Q2: an ordinary persistent first-party login cookie.
                Add-Content $logFile "LOGIN host=$hostHeader cookie=$cookie"
                $setCookies = @("sessionid=logged-in; Path=/; Max-Age=86400; SameSite=Lax")
                $body = "<!doctype html><meta charset=utf-8>login page"
            }
            elseif ($path -like "/site-b*") {
                Add-Content $logFile "PAGE site-b cookie=$cookie"
                $body = @"
<!doctype html><meta charset=utf-8><title>site B</title>
<body style="font:16px system-ui;background:#111;color:#eee;padding:2rem">
<h1>site B</h1>
<iframe id="f3" src="http://127.0.0.3:$port/tp?stage=2" width="320" height="60"></iframe>
<script>
  document.getElementById('f3').onload = function () {
    setTimeout(function () { location.href = 'http://127.0.0.3:$port/tp-firstparty'; }, 250);
  };
</script></body>
"@
            }
            elseif ($path -notlike "/site-a*" -and $path -ne "/") {
                # 404 for anything unrecognised, and this matters for the log
                # rather than for the browser: the first Windows run served
                # the site-a page to every /favicon.ico request, so the log
                # carried six spurious "PAGE site-a" lines that had to be
                # decoded by hand. One of them was genuinely informative (a
                # favicon fetch to 127.0.0.1 carrying site A's cookie, which
                # is how first-party storage got confirmed) -- but that was
                # luck, not design.
                Add-Content $logFile "OTHER $path host=$hostHeader cookie=$cookie"
                $bytes404 = [Text.Encoding]::UTF8.GetBytes("not found")
                $head404 = "HTTP/1.1 404 Not Found`r`nContent-Type: text/plain`r`n" +
                           "Content-Length: $($bytes404.Length)`r`nConnection: close`r`n`r`n"
                $hb404 = [Text.Encoding]::ASCII.GetBytes($head404)
                $stream.Write($hb404, 0, $hb404.Length)
                $stream.Write($bytes404, 0, $bytes404.Length)
                $stream.Flush(); $client.Close()
                continue
            }
            else {
                Add-Content $logFile "PAGE site-a cookie=$cookie"
                $setCookies = @("fp_site_a=first-party; Path=/")
                $body = @"
<!doctype html><meta charset=utf-8><title>site A</title>
<body style="font:16px system-ui;background:#111;color:#eee;padding:2rem">
<h1>site A</h1>
<iframe id="f1" src="http://127.0.0.3:$port/tp?stage=1" width="320" height="60"></iframe>
<script>
  document.getElementById('f1').onload = function () {
    var f2 = document.createElement('iframe');
    f2.width = 320; f2.height = 60;
    f2.src = 'http://127.0.0.3:$port/tp?stage=1b';
    f2.onload = function () {
      setTimeout(function () { location.href = 'http://127.0.0.2:$port/site-b'; }, 250);
    };
    document.body.appendChild(f2);
  };
</script></body>
"@
            }

            $bytes = [Text.Encoding]::UTF8.GetBytes($body)
            $head = "HTTP/1.1 200 OK`r`nContent-Type: $ctype`r`nContent-Length: $($bytes.Length)`r`n"
            foreach ($sc in $setCookies) { $head += "Set-Cookie: $sc`r`n" }
            $head += "Cache-Control: no-store`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($head)
            $stream.Write($hb, 0, $hb.Length)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            $client.Close()
        } catch { }
    }
}

try {
    $port = $null
    foreach ($i in 1..40) {
        Start-Sleep -Milliseconds 250
        if (Test-Path $LogFile) {
            $seen = Get-Content $LogFile -ErrorAction SilentlyContinue
            if ($seen -match '^NOSERVER') {
                Write-Error "PROBE FAIL: the listener could not bind any port. Results would be meaningless."
                exit 1
            }
            $ready = $seen | Where-Object { $_ -match '^READY (\d+)$' } | Select-Object -First 1
            if ($ready) { $port = [int]($ready -replace '^READY ', ''); break }
        }
    }
    if (-not $port) { Write-Error "PROBE FAIL: the listener never reported READY."; exit 1 }
    Write-Host "  listening on $port"

    # One visit. The smoke sequence refuses to run against an existing vault,
    # and its bookmark step refuses a store left from the previous visit --
    # both correct guards, both about the harness rather than cookies. They are
    # the ONLY files removed; the Chromium profile that holds the cookie jar is
    # deliberately untouched, since its survival is half the measurement.
    function Invoke-Visit([string]$url) {
        Get-ChildItem -Path $Profile -Filter "vault.rbv*" -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $Profile -Filter "store.rbs" -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        # PATANYX_DATA_DIR is the Windows override; XDG_DATA_HOME is the unix
        # one. BOTH are set, and that is not belt-and-braces: without the
        # second, rehearsing this script against the Linux binary points the
        # vault at the REAL one in $HOME, where the smoke guard refuses to run
        # ("vault unexpectedly exists in smoke dir") and the probe cannot even
        # start. That is exactly what the first rehearsal of this file did.
        # XDG_DATA_HOME is ignored on Windows, so this costs nothing there.
        $env:PATANYX_DATA_DIR = $Profile
        $env:XDG_DATA_HOME = $Profile
        $env:PATANYX_BLOCKLIST_PATH = $EmptyLst
        $env:PATANYX_BLOCKING_PROBE_URL = $url
        $out = Invoke-Browser $Binary @("--smoke-test")
        if ($out -notmatch "PROBE DONE") {
            Write-Host "PROBE FAIL: the navigation never completed; the result is meaningless" -ForegroundColor Red
            Write-Host ($out -split "`n" | Select-Object -First 25 | Out-String)
            exit 1
        }
    }

    Write-Host ""
    Write-Host "=== run 1: site A -> third party twice -> site B -> third party top-level ===" -ForegroundColor White
    Invoke-Visit "http://127.0.0.1:$port/site-a"

    Write-Host ""
    Write-Host "=== run 2: a login cookie, then a restart ===" -ForegroundColor White
    Invoke-Visit "http://127.0.0.1:$port/login"
    Invoke-Visit "http://127.0.0.1:$port/login"

    $log = Get-Content $LogFile
    Write-Host ""
    Write-Host "--- what the server saw ---" -ForegroundColor DarkGray
    $log | Where-Object { $_ -notmatch '^(READY|BINDFAIL)' } | ForEach-Object { Write-Host "  $_" }

    $siteA  = $log | Where-Object { $_ -like "PAGE site-a*" } | Select-Object -First 1
    $s1     = $log | Where-Object { $_ -like "TP stage=1 *" } | Select-Object -First 1
    $s1b    = $log | Where-Object { $_ -like "TP stage=1b *" } | Select-Object -First 1
    $s2     = $log | Where-Object { $_ -like "TP stage=2 *" } | Select-Object -First 1
    $tpfp   = $log | Where-Object { $_ -like "TPFIRSTPARTY*" } | Select-Object -First 1
    $logins = @($log | Where-Object { $_ -like "LOGIN *" })

    # --- controls first -----------------------------------------------------
    if (-not $s1)   { Write-Error "CONTROL FAIL: the third party was never embedded; nothing measured."; exit 2 }
    if (-not $s1b)  { Write-Error "CONTROL FAIL: the second same-site embed never fired."; exit 2 }
    if (-not $s2)   { Write-Error "CONTROL FAIL: site B never embedded the third party (top-level navigation did not happen)."; exit 2 }
    if (-not $tpfp) { Write-Error "CONTROL FAIL: the third party was never reached top-level, so an empty result cannot be explained."; exit 2 }
    if ($logins.Count -lt 2) { Write-Error "CONTROL FAIL: the login page was not visited twice."; exit 2 }

    Write-Host ""
    Write-Host "================ RESULT ================" -ForegroundColor White
    Write-Host "Q1  cross-site tracking"
    Write-Host "  stage 1  (3p embedded on site A, sets) : $s1"
    Write-Host "  stage 1b (3p embedded on site A again) : $s1b"
    Write-Host "  stage 2  (3p embedded on site B)       : $s2"
    Write-Host "  stage 3  (3p AS first party)           : $tpfp"
    Write-Host ""
    Write-Host "Q2  staying signed in"
    Write-Host "  visit 1 : $($logins[0])"
    Write-Host "  visit 2 : $($logins[1])"
    Write-Host ""

    $q2 = if ($logins[1] -match "sessionid=logged-in") {
        Write-Host "STAYING SIGNED IN: YES. A login cookie survived the restart." -ForegroundColor Green
        "persist"
    } else {
        Write-Host "STAYING SIGNED IN: NO. The login cookie did not survive the restart," -ForegroundColor Yellow
        Write-Host "  so every launch starts signed out of every site." -ForegroundColor Yellow
        "nopersist"
    }
    Write-Host ""

    if ($s2 -match "tp_(none|lax|plain)=tracked-you") {
        Write-Host "CROSS-SITE TRACKING SUCCEEDS on Windows." -ForegroundColor Red
        Write-Host "One third party was handed the same cookie on two unrelated sites."
        Write-Host "This is the platform gap Linux does not have, and it is worth a"
        Write-Host "real defense -- send this output back."
        exit 3
    }
    if ($tpfp -match "tp_(none|lax|plain)=tracked-you") {
        Write-Host "NO CROSS-SITE COOKIE FLOWED -- but stage 3 shows it WAS STORED while" -ForegroundColor Yellow
        Write-Host "embedded, and merely not sent in a third-party context. That is"
        Write-Host "ordinary SameSite behaviour, not a PATANYX defense, and it must not"
        Write-Host "be claimed as one. Resolving it properly needs an HTTPS probe."
        exit 0
    }
    Write-Host "THIRD-PARTY COOKIE STORAGE IS REFUSED OUTRIGHT on Windows." -ForegroundColor Green
    Write-Host "Same result as Linux: the cookie was absent even in stage 3, where"
    Write-Host "SameSite restricts nothing -- so it was never stored at all."
    exit 0
}
finally {
    Stop-Job $serverJob -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $serverJob -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host ""
    Write-Host "log kept at: $LogFile" -ForegroundColor DarkGray
}
