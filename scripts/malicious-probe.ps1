# PATANYX — Windows behavioural proof that a MALICIOUS-LISTED host is never
# contacted.
#
# The Windows counterpart to scripts/malicious-probe.sh, and it is not
# redundant with it. The two platforms enforce the malicious list in DIFFERENT
# CODE: on Linux it is wry's navigation handler; on Windows it is that plus the
# `WebResourceRequested` handler, which is also what gives Windows subresource
# coverage Linux does not have. A green run on Linux proves the list and the
# matching are right. It says nothing about whether WebView2 actually refuses
# the connection.
#
# It is also distinct from blocking-probe.ps1, which measures AD blocking
# (`RuleSet`, gated on policy.block_ads). The malicious list is a separate set
# with a separate check, deliberately, so that turning off ad blocking does not
# turn off malware blocking. Proving one proves nothing about the other.
#
# HONESTY NOTE: never executed ON WINDOWS. It HAS been rehearsed end to end
# against the Linux binary under `xvfb-run pwsh`, which exercised the listener,
# the host-header parsing, the profile isolation and all four assertions --
# and caught two real defects while doing so ($env:TEMP being null off Windows,
# and the profile variable being Windows-only so the second run tripped over
# the first run's vault). What that rehearsal CANNOT tell us is whether
# WebView2 refuses the connection, because that is the code it exists to test.
# Treat a Windows failure as "the script or the browser is wrong" and read
# before believing either.
#
# NO ELEVATION REQUIRED, and that is deliberate. blocking-probe.ps1 edits the
# hosts file and therefore needs an admin shell, which is most of why it has
# sat unrun. This one distinguishes hosts by the HOST HEADER instead: 127.0.0.1
# and 127.0.0.2 both route to this machine, one listener on IPAddress::Any
# accepts both, and the request tells us which name the browser asked for. A
# probe that needs a sacrificial machine is a probe nobody runs.
#
#   127.0.0.1  -> on the list. Must receive ZERO connections.
#   127.0.0.2  -> not on the list. Must be contacted, or the instrument is
#                 broken and every "zero" below is an artefact.
#
# THE 127.0.0.2 RISK, stated rather than hidden: Windows routes all of
# 127.0.0.0/8 to loopback, but this has not been confirmed on the tester's
# machine. If it does not work, CONTROL 1 FAILS LOUDLY and the run stops —
# which is the correct outcome. This design cannot turn that assumption into a
# false pass.
#
#   powershell -ExecutionPolicy Bypass -File malicious-probe.ps1 -Binary .\patanyx-debug.exe
#
# Use the DEBUG binary. The release build is windows_subsystem = "windows",
# has no console, and PROBE DONE would go nowhere.

param(
    [Parameter(Mandatory = $true)][string]$Binary
)

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 turns a native command's STDERR into error records,
# and `Stop` then makes the first one a TERMINATING error. The debug build --
# which this probe requires, because the release build has no console -- always
# writes at least one diagnostic line to stderr ("profile: user data folder is
# ..."), so the script could not complete a single run on a real Windows shell.
#
# blocking-probe.ps1 already solved this with exactly this helper. This script
# was written without reusing it, which is how the defect got back in.
#
# The Linux rehearsal could not catch it: pwsh 7 does not convert native stderr
# to error records the way 5.1 does. That is the precise limit of rehearsing on
# a different host, and it is worth stating rather than treating the rehearsal
# as equivalent to a Windows run.
#
# `Stop` stays the default everywhere else -- a dead listener or an unwritable
# file must still abort. This relaxes it around the ONE call where stderr is
# expected output rather than a fault.
function Invoke-Browser([string]$exe, [string[]]$browserArgs, [int]$TimeoutSec = 240) {
    # Start-Process with FILE REDIRECTS rather than `& $exe 2>&1`, for two
    # reasons, both learned the hard way:
    #
    #   1. It sidesteps the stderr-to-error-record conversion entirely, rather
    #      than relaxing $ErrorActionPreference around it. The debug build --
    #      which this probe requires, since the release build has no console --
    #      always writes diagnostics to stderr, so that conversion killed the
    #      first run of every invocation on a real Windows shell.
    #   2. It gives a TIMEOUT. Without one a browser that never reaches
    #      PROBE DONE leaves this script waiting forever with a window open and
    #      no output, which is indistinguishable from "still working" and is
    #      exactly what the tester hit.
    #
    # 240s is deliberately generous: one run is ~31s on Linux, and each does
    # the full smoke sequence including Argon2id at production parameters
    # twice. A timeout that fires on a slow machine would be worse than none.
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
Write-Host "probing binary: $Binary ($((Get-Item $Binary).LastWriteTime))"

# GetTempPath() rather than $env:TEMP, which is null off Windows. Not
# pedantry: it is what lets this script be executed against the Linux binary
# to exercise its own mechanics -- the listener, the log parsing, the four
# assertions -- before it ever meets a Windows machine. That run is how this
# very line got fixed.
$Work = Join-Path ([System.IO.Path]::GetTempPath()) "patanyx-malicious-probe-$PID"
New-Item -ItemType Directory -Path $Work -Force | Out-Null

$LogFile  = Join-Path $Work "hits.log"
$Listed   = Join-Path $Work "blocklist-listed.txt"
$EmptyLst = Join-Path $Work "blocklist-empty.txt"

# The list under test. One entry, and it must survive HostSet::acceptable --
# which rejects any rule without a dot, so a bare name like "localhost" could
# never be used here even though it resolves.
Set-Content -Path $Listed -Value "127.0.0.1" -Encoding ascii
Set-Content -Path $EmptyLst -Value "" -Encoding ascii

# ---------------------------------------------------------------------------
# One listener, on Any, logging the Host header of every request.
#
# The page it serves for /probe embeds a subresource from the LISTED host. That
# is the Windows-only half of this test: WebResourceRequested sees subresources
# and the Linux navigation handler does not, so this is coverage the sibling
# script structurally cannot provide.
# ---------------------------------------------------------------------------
$serverJob = Start-Job -ArgumentList $LogFile -ScriptBlock {
    param($logFile)

    $listener = $null
    foreach ($p in @(8947, 8948, 8949, 9947)) {
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

    # Subresource points at the LISTED host, fetched from whichever host served
    # the page. A request logged with Host 127.0.0.1 means the block leaked.
    $page = @"
<!doctype html><meta charset=utf-8><title>probe</title>
<img src="http://127.0.0.1:$port/subresource.png">
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
            # THE HOST HEADER IS THE WHOLE MEASUREMENT. Both names reach this
            # machine, so a connection alone says nothing about which host the
            # browser asked for.
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
            $client.Close()
        } catch { }
    }
}

try {
    # Wait for the bind, and FAIL if it never happened. A run against no server
    # records nothing, and nothing reads exactly like a perfect block.
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
    if (-not $port) {
        Write-Error "PROBE FAIL: the listener never reported READY."
        exit 1
    }
    Write-Host "listener ready on port $port"

    $runNo = 0
    function Invoke-Probe {
        param([string]$ListPath, [string]$Url, [int]$ExpectHosts = -1)
        $script:runNo++
        # THE BROWSER WILL VISIBLY OPEN. There is no headless mode on Windows
        # (the Linux rehearsal uses xvfb), so a real window appears and closes
        # for each of the four runs. Saying so beats an operator watching a
        # window they were not told to expect.
        Write-Host "  launching run $script:runNo of 4 -- a browser window will open and close (~30s)"
        Set-Content -Path $LogFile -Value "" -Encoding ascii
        $env:PATANYX_BLOCKLIST_PATH     = $ListPath
        $env:PATANYX_BLOCKING_PROBE_URL = $Url
        # A throwaway profile per run, so nothing carries between them. The
        # smoke sequence refuses to run against an existing vault, so without
        # this the SECOND run fails with "vault unexpectedly exists".
        #
        # BOTH variables: PATANYX_DATA_DIR is what Windows reads, XDG_DATA_HOME
        # is what Linux reads. Setting both costs nothing on Windows and is
        # what lets this script be rehearsed against the Linux binary.
        # NOT $profile -- that is a PowerShell AUTOMATIC variable holding the
        # path to the user's profile script, and assigning to it is both rude
        # and a source of very confusing failures later in a session.
        $profileDir = Join-Path $Work "profile-$(Get-Random)"
        $env:PATANYX_DATA_DIR = $profileDir
        $env:XDG_DATA_HOME    = $profileDir
        try {
            $out = Invoke-Browser $Binary @("--smoke-test")
        } finally {
            Remove-Item Env:\PATANYX_BLOCKLIST_PATH     -ErrorAction SilentlyContinue
            Remove-Item Env:\PATANYX_BLOCKING_PROBE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:\PATANYX_DATA_DIR           -ErrorAction SilentlyContinue
            Remove-Item Env:\XDG_DATA_HOME              -ErrorAction SilentlyContinue
        }
        # Without this an early exit leaves an empty log, which reads as a
        # clean pass -- the most misleading result this test can produce.
        # THE OVERRIDE MUST HAVE TAKEN EFFECT. Without this check a run where
        # PATANYX_BLOCKLIST_PATH never reached the process is INDISTINGUISHABLE
        # from a run where blocking is broken: the browser quietly uses the real
        # 390k list, which contains none of these loopback addresses, so every
        # host is contacted and the probe reports a blocking failure that is
        # really a plumbing failure. The browser prints the set actually in
        # force; this refuses to interpret a run that tested the wrong list.
        if ($ExpectHosts -ge 0) {
            if ($out -match '(?m)^BLOCKLIST hosts=(\d+)') {
                $actual = [int]$matches[1]
                if ($actual -ne $ExpectHosts) {
                    Write-Host $out
                    Write-Error @"
PROBE FAIL: the browser had $actual hosts in force, expected $ExpectHosts.
  PATANYX_BLOCKLIST_PATH did not take effect, so this run tested the shipped
  list rather than the probe's. Nothing about blocking can be concluded.
"@
                    exit 1
                }
                Write-Host "  blocklist in force: $actual host(s) -- override applied"
            } else {
                Write-Host $out
                Write-Error "PROBE FAIL: the browser never reported BLOCKLIST hosts=N. Binary too old for this probe?"
                exit 1
            }
        }
        # Kept for the failure paths below. A probe that hides the browser's
        # own account of what it decided makes the tester re-run to learn
        # what one run already knew.
        $script:lastBrowserOut = $out
        if ($out -notmatch "PROBE DONE") {
            Write-Host $out
            Write-Error "PROBE FAIL: the navigation never completed; the result is meaningless."
            exit 1
        }
        return (Get-Content $LogFile -ErrorAction SilentlyContinue)
    }

    # -----------------------------------------------------------------------
    # 1. CONTROL FIRST: the instrument works.
    #
    # Before the positive case deliberately. If an unlisted host is not
    # contacted, the server, the browser, the URL or the 127.0.0.2 assumption
    # is broken, and every "zero connections" below would be an artefact.
    # -----------------------------------------------------------------------
    Write-Host "`n=== control 1: an UNLISTED host must be contacted ==="
    $hits = Invoke-Probe -ListPath $Listed -Url "http://127.0.0.2:$port/probe" -ExpectHosts 1
    $hits | Where-Object { $_ -notmatch '^(READY|BINDFAIL)' } | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
    if (-not ($hits -match '^127\.0\.0\.2 /probe$')) {
        Write-Error @"
CONTROL FAIL: an unlisted host was not reached, so this probe cannot observe
  anything and its other results prove nothing. The most likely cause is that
  this Windows build does not route 127.0.0.2 to loopback -- see the header.
"@
        exit 1
    }

    # -----------------------------------------------------------------------
    # 2. THE POSITIVE CASE.
    # -----------------------------------------------------------------------
    Write-Host "`n=== a LISTED host must receive zero connections ==="
    $hits = Invoke-Probe -ListPath $Listed -Url "http://127.0.0.1:$port/probe" -ExpectHosts 1
    $hits | Where-Object { $_ -notmatch '^(READY|BINDFAIL)' } | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
    if ($hits -match '^127\.0\.0\.1 ') {
        # The NAV lines are the whole diagnosis: they say whether the
        # navigation handler fired at all, what host it extracted, and whether
        # the list matched. Without them a failure here is just "it did not
        # work".
        Write-Host "`n--- what the browser itself decided ---"
        ($script:lastBrowserOut -split "`n") | Where-Object { $_ -match '^(NAV |BLOCKLIST )' } | ForEach-Object { Write-Host "  $($_.Trim())" }
        Write-Error @"
PROBE FAIL: a listed host was contacted.
  Read the NAV lines above:
    no NAV line for this URL  -> NavigationStarting never fired on WebView2
    matched=Some(...)         -> the handler blocked and the engine ignored it
    matched=None              -> the set does not contain the host it should
"@
        exit 1
    }

    # -----------------------------------------------------------------------
    # 3. SUBRESOURCES — the Windows-only assertion.
    #
    # Load a page from the UNLISTED host that embeds an image from the LISTED
    # one. On Windows the WebResourceRequested handler sees subresources, so
    # this must not leave the machine. The Linux probe cannot test this at all:
    # its navigation handler never sees subresource requests, and RELEASE.md
    # states that gap rather than smoothing it over.
    # -----------------------------------------------------------------------
    Write-Host "`n=== a LISTED host must not be reached as a SUBRESOURCE either ==="
    $hits = Invoke-Probe -ListPath $Listed -Url "http://127.0.0.2:$port/probe" -ExpectHosts 1
    $hits | Where-Object { $_ -notmatch '^(READY|BINDFAIL)' } | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
    if (-not ($hits -match '^127\.0\.0\.2 /probe$')) {
        Write-Error "CONTROL FAIL: the page itself was not served, so the subresource result means nothing."
        exit 1
    }
    $leaked = [bool]($hits -match '^127\.0\.0\.1 /subresource\.png$')
    if ($IsWindows -or $null -eq $IsWindows) {
        # $IsWindows is absent on Windows PowerShell 5.1, where the answer is
        # obviously yes -- hence the null check rather than a bare test.
        if ($leaked) {
            Write-Error @"
PROBE FAIL: a listed host was contacted for a SUBRESOURCE. Navigation blocking
  works and request blocking does not, which is worse than it sounds: a
  malicious host reached this way loads with no interstitial at all.
"@
            exit 1
        }
    } else {
        # Rehearsing on Linux. The subresource IS expected to leak there: wry's
        # navigation handler never sees subresource requests, which RELEASE.md
        # states as a platform gap rather than smoothing over. Reported, not
        # asserted -- turning a known platform difference into a failure would
        # make this script unrunnable on the only machine that can rehearse it.
        if ($leaked) {
            Write-Host "  (non-Windows: subresource reached the listed host, as expected --"
            Write-Host "   this is the Linux gap, and the assertion this probe exists to make)"
        } else {
            Write-Host "  (non-Windows: subresource did NOT leak, which is better than documented)"
        }
    }

    # -----------------------------------------------------------------------
    # 4. THE MOST IMPORTANT ASSERTION IN THIS FILE: the LIST is what blocked it.
    #
    # Same binary, same URL, same everything -- an EMPTY list. The host must now
    # be contacted. Without this, "zero connections" is equally consistent with
    # the handler denying everything, a malformed URL, or the browser navigating
    # nowhere. This is the control that would have caught the ad-block defect,
    # where a rule matched nothing while the UI reported protection and every
    # unit test stayed green.
    # -----------------------------------------------------------------------
    Write-Host "`n=== control 2: with an EMPTY list, the same host IS contacted ==="
    $hits = Invoke-Probe -ListPath $EmptyLst -Url "http://127.0.0.1:$port/probe" -ExpectHosts 0
    $hits | Where-Object { $_ -notmatch '^(READY|BINDFAIL)' } | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
    if (-not ($hits -match '^127\.0\.0\.1 /probe$')) {
        Write-Error @"
CONTROL FAIL: with an empty list the host was STILL not contacted. So the block
  above was not the list doing its job -- something else is refusing this
  navigation, and the protection is unproven.
"@
        exit 1
    }

    Write-Host "`nMALICIOUS PROBE OK"
    Write-Host "  unlisted host contacted          (the instrument works)"
    Write-Host "  listed host: ZERO connections    (the block is real)"
    # Reports what was MEASURED, not what was hoped. A summary that says
    # "not fetched" after observing a fetch is the precise failure mode this
    # whole family of scripts exists to prevent.
    if ($leaked) {
        Write-Host "  listed subresource: FETCHED      (expected on Linux; a FAILURE on Windows)"
    } else {
        Write-Host "  listed subresource: not fetched  (request-level blocking holds)"
    }
    Write-Host "  empty list -> contacted again    (the LIST is what blocked it)"
    Write-Host ""
    Write-Host "NOT covered here: the per-tab override and the interstitial's own"
    Write-Host "  rendering. Both need a click in the chrome UI, which this harness"
    Write-Host "  cannot drive. Stated rather than implied."
}
finally {
    Stop-Job $serverJob -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $serverJob -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}
