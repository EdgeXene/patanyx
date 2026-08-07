# PATANYX - does WebView2 honour a rewritten Referer?
#
# THIS PROBE DECIDED THE FEATURE, on 2026-07-31: the BASELINE Referer was
# already origin-only. WebView2's default policy (strict-origin-when-cross-
# origin) trims cross-origin referrers before any host-app code runs, so the
# trim feature had nothing to do and was DELETED the same day. Exit 2, by the
# origin-only guard below, is the recorded result; docs/referrer-trimming.md
# holds the full measurement. The script stays for re-measuring if the engine
# default ever changes -- the baseline round needs no PATANYX-side code, and
# the trimming round is only meaningful if the trim code is first restored
# from the deleting commit's parent.
#
# The original question, for the record: setting a header in
# WebResourceRequested SUCCEEDS whether or not the engine sends it, so an
# "engine confirmed" row would be reporting our own request back to us.
#
# Microsoft documents header modification in that event as supported, and gives
# a SetHeader example. The same page also says the network stack adds more
# headers AFTER the handler returns, which is exactly why a long-standing
# report of Cookie and Authorization edits "having no impact" was correct for
# those two. Whether Referer survives is not documented anywhere.
#
# So this measures it from OUTSIDE: a local server records the Referer it
# actually received, with trimming off and then on. The server is the only
# witness that cannot be fooled by our own code.
#
# WHAT YOU NEED: Windows, a built PATANYX (debug or release), and this script.
# Nothing leaves the machine; the server is on 127.0.0.1.
#
# Run:  powershell -ExecutionPolicy Bypass -File scripts\referrer-probe.ps1
#
# Exit codes:  0 = trimming WORKS      -> the feature can ship
#              3 = trimming IGNORED    -> delete the code, document the limit
#              2 = VOID, no measurement (browser never loaded the page)
#              1 = probe error

param(
    # Path to the browser. Only needed if it is not beside this script and
    # this script is not inside the repository.
    [string]$Exe
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$repoRoot = Split-Path -Parent $here
# The log goes BESIDE THIS SCRIPT, not in the repo root: the usual way to run
# this is to copy the script and the exe into one folder on a Windows machine
# that has no checkout at all, and a log written to the parent of that folder
# is a log the tester has to go looking for.
$logPath = Join-Path $here "referrer-probe-log.txt"
"" | Set-Content $logPath

function Say($text, $colour = "Gray") {
    Write-Host $text -ForegroundColor $colour
    Add-Content -Path $logPath -Value $text
}

# --- the binary ------------------------------------------------------------
# Beside the script FIRST, because the common case is a folder holding just
# this file and the exe on a machine with no checkout. The repo paths are the
# fallback, for running it from a working tree.
$candidates = @()
if ($Exe) { $candidates += $Exe }
$candidates += @(
    (Join-Path $here "PATANYX.exe"),
    (Join-Path $here "patanyx.exe"),
    (Join-Path $repoRoot "target\x86_64-pc-windows-msvc\release\patanyx.exe"),
    (Join-Path $repoRoot "target\x86_64-pc-windows-msvc\debug\patanyx.exe"),
    (Join-Path $repoRoot "target\release\patanyx.exe")
)
$exe = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $exe) {
    Say "Could not find the browser." "Red"
    Say "Put PATANYX.exe in this folder, or pass one:" "Yellow"
    Say "  .\referrer-probe.ps1 -Exe C:\path\to\PATANYX.exe" "Yellow"
    exit 1
}
Say ("browser: {0}" -f $exe) "DarkGray"

# --- two origins on one machine --------------------------------------------
# The PAGE is served from 127.0.0.1 and its subresource from localhost. Same
# machine, DIFFERENT ORIGIN by the only rule that matters here (the host
# strings differ), so the request is genuinely cross-origin without needing
# DNS or a second machine.
$pagePort = 8931
$assetPort = 8932
$pageOrigin = "http://127.0.0.1:$pagePort"
$assetOrigin = "http://localhost:$assetPort"

$script:received = [System.Collections.ArrayList]::new()

function Start-Server($port, $label) {
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://+:$port/")
    try {
        $listener.Start()
    } catch {
        # + needs an ACL on some machines; fall back to the literal hosts.
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$port/")
        $listener.Prefixes.Add("http://localhost:$port/")
        $listener.Start()
    }
    Say ("  listening on {0} ({1})" -f $port, $label) "DarkGray"
    return $listener
}

try {
    $pageServer = Start-Server $pagePort "page"
    $assetServer = Start-Server $assetPort "third-party asset"
} catch {
    Say ("Could not open a port: {0}" -f $_.Exception.Message) "Red"
    Say "Another program may be using 8931/8932." "Yellow"
    exit 1
}

# The page. A deep path with a query, because the whole point is whether that
# path and query reach the other origin. The image is what carries the Referer.
$pageHtml = @"
<!doctype html><meta charset=utf-8><title>referrer probe</title>
<body style="font:16px system-ui;background:#111;color:#eee;padding:2rem">
<h1>Referrer probe</h1>
<p>Loading a third-party image from $assetOrigin ...</p>
<img src="$assetOrigin/pixel.png" width="8" height="8" alt="">
<p id="js"></p>
<script>
  // The JS-visible value, which is a SEPARATE question from the header the
  // server sees: an engine may trim one and not the other.
  document.getElementById('js').textContent = 'document.referrer = ' + document.referrer;
</script>
</body>
"@

# Serves BOTH listeners from one loop, waiting on whichever answers first.
#
# v2. THE FIRST VERSION COULD ONLY EVER REPORT VOID. It pumped the page
# listener to completion and then the asset listener -- but the page pump had
# no exit condition, so it ran until the shared deadline expired, and the asset
# pump was then handed a deadline already in the past and returned without ever
# reading the image request sitting in its queue. Two rounds, both VOID,
# regardless of what the engine actually sent. A probe that cannot produce its
# own PASS result is worse than no probe, because it reads as evidence.
function Pump-Round($seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    $pageTask = $pageServer.GetContextAsync()
    $assetTask = $assetServer.GetContextAsync()
    $sawPage = $false

    while ((Get-Date) -lt $deadline) {
        $which = [System.Threading.Tasks.Task]::WaitAny(@($pageTask, $assetTask), 500)
        if ($which -lt 0) { continue }

        if ($which -eq 0) {
            $ctx = $pageTask.Result
            $sawPage = $true
            Say ("    page request : {0}" -f $ctx.Request.Url.PathAndQuery) "DarkCyan"
            $bytes = [Text.Encoding]::UTF8.GetBytes($pageHtml)
            $ctx.Response.ContentType = "text/html; charset=utf-8"
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $ctx.Response.Close()
            # Re-arm: the browser may ask for a favicon or re-request on reload.
            $pageTask = $pageServer.GetContextAsync()
        } else {
            $ctx = $assetTask.Result
            $ref = $ctx.Request.Headers["Referer"]
            [void]$script:received.Add($ref)
            Say ("    asset request, Referer = {0}" -f $(if ($ref) { $ref } else { "<none>" })) "Cyan"
            $ctx.Response.ContentType = "image/png"
            # 1x1 transparent PNG.
            $png = [Convert]::FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
            $ctx.Response.OutputStream.Write($png, 0, $png.Length)
            $ctx.Response.Close()
            return  # got what this round exists to measure
        }
    }
    # Distinguishes "the browser never loaded anything" from "it loaded the
    # page but the image never followed". Those need completely different
    # fixes, and the old script could not tell them apart.
    if (-not $sawPage) {
        Say "    (no page request at all -- the browser did not reach the server)" "Yellow"
    } else {
        Say "    (page was served, but the third-party image was never requested)" "Yellow"
    }
}

function Run-Round($label, $trimOn) {
    $script:received.Clear()
    Say ""
    Say ("--- {0} (PATANYX_TRIM_REFERRER={1}) ---" -f $label, $(if ($trimOn) { "1" } else { "unset" })) "White"

    if ($trimOn) { $env:PATANYX_TRIM_REFERRER = "1" } else { Remove-Item Env:\PATANYX_TRIM_REFERRER -ErrorAction SilentlyContinue }

    $roundStart = Get-Date
    $url = "$pageOrigin/deep/path/page.html?token=SECRET123"
    Say ("  open this in PATANYX:  {0}" -f $url) "Yellow"
    $proc = Start-Process -FilePath $exe -ArgumentList $url -PassThru

    Pump-Round 45

    try { $proc | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    # WebView2 leaves helper processes behind that keep the port's client side
    # alive; without this the second round can inherit a warm connection and a
    # cached page, which would make round two measure round one.
    Get-Process -Name "msedgewebview2" -ErrorAction SilentlyContinue |
        Where-Object { $_.StartTime -gt $roundStart } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    if ($script:received.Count -eq 0) { return $null }
    return $script:received[0]
}

Say ""
Say "The browser will open twice. Leave each window alone; it closes itself." "White"

$before = Run-Round "BASELINE, trimming off" $false
$after = Run-Round "TRIMMING ON" $true

$pageServer.Stop(); $assetServer.Stop()

Say ""
Say "================ RESULT ================" "White"
Say ("  baseline Referer : {0}" -f $(if ($before) { $before } else { "<none>" }))
Say ("  trimmed  Referer : {0}" -f $(if ($after) { $after } else { "<none>" }))
Say ""

if (-not $before -and -not $after) {
    Say "VOID. The third-party asset was never requested, so nothing was" "Yellow"
    Say "measured. The page probably did not load. Send me referrer-probe-log.txt." "Yellow"
    exit 2
}

# The baseline must contain the PATH for this test to mean anything. If the
# engine was already sending origin-only, there is nothing to trim and the
# comparison below would report a false success.
if ($before -and ($before -notmatch "deep/path")) {
    Say "VOID. The baseline Referer carried no path, so this engine already" "Yellow"
    Say "sends origin-only and there is nothing for trimming to do. That is" "Yellow"
    Say "worth knowing, but it is not evidence the rewrite works." "Yellow"
    exit 2
}

if ($after -and ($after -notmatch "deep/path") -and ($after -match "127.0.0.1")) {
    Say "TRIMMING WORKS." "Green"
    Say "The server received the origin only. The path and the query string" "Green"
    Say "did not leave the browser. The feature can ship." "Green"
    exit 0
}

Say "TRIMMING IS IGNORED." "Red"
Say "The engine sent the full URL anyway, so the rewrite does not survive" "Red"
Say "WebView2's network stack. Delete the code and document the limit -- do" "Red"
Say "not ship a setting that quietly does nothing." "Red"
exit 3
