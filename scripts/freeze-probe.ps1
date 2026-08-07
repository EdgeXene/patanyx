# PATANYX - watch Freeze with your own eyes.
#
# "Frozen" in the toolbar is a CLAIM. This shows you the traffic.
#
# v8. THE BASELINE CLOCK NOW STARTS WHEN THE PAGE ARRIVES, NOT WHEN THE
# SCRIPT DOES.
#
# v7 began its 12-second baseline window the moment the listener opened, so
# the tester had twelve seconds to switch windows, launch the browser, and
# get a page beaconing five times over three channels. That is not a race a
# human can win, and it cost a real run on 2026-07-27: the probe reported
# VOID (exit 2, "no traffic to freeze") when the browser had simply not been
# started yet. A correct refusal for the wrong reason -- the same failure
# shape v7 was written to eliminate, one step earlier in the run.
#
# The probe now WAITS for the first beacon before it starts measuring
# anything, for up to PAGE_TIMEOUT_SECS. Nothing about the verdict changed:
# the baseline is still twelve seconds of observed traffic, and a page that
# never loads at all still ends the run with exit 2.
#
# v7. THE VERDICT HAS A NEGATIVE CONTROL AND AN EXIT CODE.
#
# v6 could not fail. It printed "all three zero - Freeze works on Windows"
# without ever establishing that traffic was flowing when Freeze was pressed,
# so a backgrounded tab, an occluded window or a crashed page produced silence
# that read as success. It also conflated "after the mark" with "after the
# freeze": the tester marked, then pressed Freeze some seconds later, and
# every request in between counted against the freeze.
#
# Both are fixed by taking the tester's signal from the CONSOLE instead of
# from the page. A page that is frozen cannot tell this server anything -- that
# is the whole point of freezing it -- so the mark had to happen before the
# freeze, which is what made the timing ambiguous. The PowerShell window is not
# frozen. Pressing SPACE there is a signal Freeze cannot block.
#
# The run is now three measured windows:
#   BASELINE  traffic must be flowing, or there is nothing to freeze
#   FROZEN    after you press Freeze and then SPACE: expect zero
#   THAWED    after you press Unfreeze and then SPACE: traffic must RETURN
#
# THAWED is the negative control and it is what makes the middle window mean
# anything. If traffic does not come back, the silence during FROZEN was not
# Freeze doing its job, it was something else, and the run is VOID rather than
# a pass.
#
# Exits 0 only on a clean pass. Any other outcome exits non-zero, so this can
# be run by something other than a human reading colours.
#
# v5. NO ADMINISTRATOR NEEDED. Earlier versions used HttpListener, which on
# Windows requires elevation or a registered URL ACL, and defaulted to port
# 80, which http.sys often reserves for IIS even when nothing appears to use
# it. That is three independent ways to produce "localhost refused to
# connect", and we hit them. This speaks HTTP over a plain TcpListener on a
# high port, which needs no privileges at all.
#
# RUN THE SELF-TEST FIRST. It needs no browser and no WebView2, and it is what
# says the instrument is sound before you trust a reading from it:
#
#   powershell -ExecutionPolicy Bypass -File .\freeze-probe.ps1 -SelfTest
#
# Then the probe itself, in a REAL console window. Do not pipe the output:
# you signal Freeze and Unfreeze with SPACE, and a redirected console makes
# that impossible. It says so and exits 8 rather than failing part way in.
# There is nothing to pipe anyway, since everything printed also goes to
# freeze-probe-log.txt.
#
#   powershell -ExecutionPolicy Bypass -File .\freeze-probe.ps1
#
# `pwsh` works equally well; the script uses no PowerShell 7-only syntax, so
# Windows PowerShell 5.1 and PowerShell 7 both run it. Checked, not assumed.
#
# Everything it prints also goes to freeze-probe-log.txt next to the script,
# so there is one file to send back.

param([int]$Port = 8080, [switch]$SelfTest)

# The verdict, as a pure function of three windows.
#
# Separated out because this is the logic that decides whether a release ships,
# and the previous version's verdict was unreachable by any test: it lived
# inline in a finally block after a Ctrl+C. `-SelfTest` exercises every branch
# below on any machine, including one with no browser, which is the only reason
# to trust the instrument before trusting its reading.
function Get-FreezeVerdict($baseline, $frozen, $thawed, $want) {
    # `fetch` is the load-bearing channel and the only one gated on. It is
    # what the 2026-07-25 Windows defect was measured on (ten fetches left the
    # machine while the toolbar claimed none), and it is the one channel every
    # runtime and page is certain to exercise.
    #
    # ws and worker are OPPORTUNISTIC. That same run recorded ws=3 worker=0 in
    # its baseline, so requiring all three to flow would have voided a run that
    # carried a perfectly good fetch measurement -- discarding real evidence
    # because a Worker did not start. They are still measured, still reported,
    # and a leak on either is still a failure; what changed is that their
    # ABSENCE no longer destroys the run.
    if ($baseline.fetch -lt $want) {
        return @{ code = 2; text =
            ("VOID: no traffic to freeze (baseline fetch={0}, want {1}+). " -f $baseline.fetch, $want) +
            "Nothing about Freeze can be concluded." }
    }
    # The control, checked BEFORE the frozen counts on purpose: an all-zero
    # frozen window with no returning traffic is the false pass this exists to
    # prevent, and reading them the other way round would report it as success.
    if ($thawed.fetch -lt $want) {
        return @{ code = 5; text =
            ("VOID: traffic did not return after Unfreeze (fetch={0}, want {1}+). " -f $thawed.fetch, $want) +
            "The silence during FROZEN is unattributable: a backgrounded tab, an " +
            "occluded window or a dead page looks exactly like this." }
    }
    if ($frozen.fetch -gt 0) {
        return @{ code = 7; text =
            ("FAIL: {0} fetches left the machine while the tab was frozen " -f $frozen.fetch) +
            "and the toolbar said it was making no network requests." }
    }
    # A leak on a secondary channel is a real finding whether or not that
    # channel cleared the baseline bar: traffic that arrives while frozen is
    # traffic that arrives while frozen.
    $leaks = @()
    if ($frozen.ws -gt 0)     { $leaks += ("ws={0}" -f $frozen.ws) }
    if ($frozen.worker -gt 0) { $leaks += ("worker={0}" -f $frozen.worker) }
    if ($leaks.Count -gt 0) {
        return @{ code = 6; text =
            ("PARTIAL: fetch was stopped but {0} got through. " -f ($leaks -join " ")) +
            "The known Windows gaps, reproduced and now measured." }
    }
    # Zero while frozen only MEANS something for a channel that was flowing
    # beforehand. Reporting an unexercised channel as stopped is precisely the
    # silence-reads-as-success failure this probe was rewritten to eliminate,
    # so it is named rather than absorbed into the pass.
    $unproven = @()
    if ($baseline.ws -lt $want)     { $unproven += "ws" }
    if ($baseline.worker -lt $want) { $unproven += "worker" }
    if ($unproven.Count -gt 0) {
        return @{ code = 0; text =
            "PASS for fetch: it was flowing, Freeze stopped it, Unfreeze brought it back. " +
            ("NOT PROVEN for {0}: never carried traffic in the baseline, " -f ($unproven -join " and ")) +
            "so zero while frozen says nothing about them either way." }
    }
    return @{ code = 0; text = "PASS: traffic was flowing on all three, Freeze stopped all three, Unfreeze brought it back." }
}

if ($SelfTest) {
    $w = 5
    $ok  = @{ fetch = 10; ws = 10; worker = 10 }
    $nil = @{ fetch = 0;  ws = 0;  worker = 0 }
    # A baseline that mirrors the tester's real 2026-07-25 machine: fetch
    # flowing, ws thin, no Worker at all. v7 threw this run away.
    $realistic = @{ fetch = 10; ws = 3; worker = 0 }
    $cases = @(
        @{ name = "clean pass";                      b = $ok;  f = $nil; t = $ok;  want = 0 },
        @{ name = "dead page reads as VOID not pass"; b = $ok;  f = $nil; t = $nil; want = 5 },
        @{ name = "no baseline fetch";               b = $nil; f = $nil; t = $ok;  want = 2 },
        @{ name = "fetch leaks";                     b = $ok;  f = @{ fetch = 4; ws = 0; worker = 0 }; t = $ok; want = 7 },
        @{ name = "only ws/worker leak";             b = $ok;  f = @{ fetch = 0; ws = 3; worker = 2 }; t = $ok; want = 6 },
        @{ name = "leaks AND no control still VOID"; b = $ok;  f = @{ fetch = 9; ws = 0; worker = 0 }; t = $nil; want = 5 },
        # The three that v7 got wrong.
        @{ name = "no Worker no longer voids a good fetch run"; b = $realistic; f = $nil; t = $ok; want = 0;
           match = "NOT PROVEN for ws and worker" },
        @{ name = "unexercised channel is NOT reported as stopped"; b = @{ fetch = 10; ws = 10; worker = 0 };
           f = $nil; t = $ok; want = 0; match = "NOT PROVEN for worker" },
        @{ name = "a leak still fails on a channel that never cleared baseline";
           b = $realistic; f = @{ fetch = 0; ws = 0; worker = 4 }; t = $ok; want = 6 },
        @{ name = "all three flowing gives an unqualified pass"; b = $ok; f = $nil; t = $ok; want = 0;
           match = "PASS: traffic was flowing on all three" }
    )
    $bad = 0
    foreach ($c in $cases) {
        $v = Get-FreezeVerdict $c.b $c.f $c.t $w
        $got = $v.code
        if ($got -ne $c.want) {
            Write-Host ("  FAIL  {0}: expected exit {1}, got {2}" -f $c.name, $c.want, $got) -ForegroundColor Red
            $bad++
        } elseif ($c.ContainsKey("match") -and $v.text -notlike ("*" + $c.match + "*")) {
            # The code alone cannot distinguish "stopped" from "never ran";
            # both are exit 0. The wording is the only thing carrying that
            # distinction, so the wording is what gets asserted.
            Write-Host ("  FAIL  {0}: exit {1} correct but text lacked '{2}'" -f $c.name, $got, $c.match) -ForegroundColor Red
            Write-Host ("        got: {0}" -f $v.text) -ForegroundColor DarkGray
            $bad++
        } else {
            Write-Host ("  ok    {0} -> exit {1}" -f $c.name, $got) -ForegroundColor Green
        }
    }
    if ($bad) { Write-Host "SELF-TEST FAILED" -ForegroundColor Red; exit 1 }
    Write-Host "SELF-TEST OK" -ForegroundColor Green
    exit 0
}

# Print something BEFORE any logic can fail, so a dead script is never a
# silent one. Previous versions resolved the log path with
# $MyInvocation.MyCommand.Path, which can be null -- Split-Path -Parent $null
# then throws on the FIRST executable line and the script dies having printed
# nothing and written no log. That is indistinguishable from "it never ran",
# and it cost several rounds of guessing.
Write-Host ""
Write-Host "  PATANYX freeze probe v8 starting..." -ForegroundColor Cyan

# Current directory, no path gymnastics. Logging must never be able to kill
# the thing it exists to diagnose, so every write is guarded.
$logPath = "freeze-probe-log.txt"
try { "" | Set-Content -Path $logPath -ErrorAction Stop }
catch { Write-Host "  (could not write $logPath - console output only)" -ForegroundColor DarkYellow }
function Say($msg, $colour = "Gray") {
    Write-Host $msg -ForegroundColor $colour
    try { Add-Content -Path $logPath -Value $msg -ErrorAction SilentlyContinue } catch {}
}

Say ("  PowerShell {0} on {1}" -f $PSVersionTable.PSVersion, [Environment]::OSVersion.VersionString) "DarkGray"

$page = @'
<!doctype html><meta charset=utf-8><title>freeze probe</title>
<style>body{font:16px system-ui;padding:2rem;background:#14161c;color:#e9e9ee}
b{color:#7fd18f} button{font:600 18px system-ui;padding:.8rem 1.5rem;cursor:pointer;
background:#2a4d8f;color:#fff;border:0;border-radius:6px}
pre{color:#9aa0ad}</style>
<h1>PATANYX freeze probe</h1>
<p>Poking this server three ways, once a second.</p>
<ol>
<li>Wait for <b>BASELINE OK</b> in the PowerShell window.</li>
<li>Press <b>Freeze</b> in the PATANYX toolbar.</li>
<li>Switch to the PowerShell window and press <b>SPACE</b>.</li>
<li>When it asks, press <b>Unfreeze</b>, then <b>SPACE</b> again.</li>
</ol>
<p>Nothing on this page needs clicking. A frozen page cannot report anything,
which is why the signal comes from the console.</p>
<pre id=log></pre>
<script>
const log = m => { const e=document.getElementById('log');
  e.textContent = (m+"\n"+e.textContent).split("\n").slice(0,8).join("\n"); };
const beacon = k => fetch('/hit/'+k,{cache:'no-store'}).catch(()=>{});
setInterval(() => { beacon('fetch'); log('fetch'); }, 1000);
setInterval(() => {
  try { const w = new WebSocket('ws://'+location.host+'/hit/ws');
        w.onerror=()=>{}; setTimeout(()=>{try{w.close();}catch(e){}},300); } catch(e){}
}, 1000);
try {
  const src = "setInterval(()=>fetch('/hit/worker',{cache:'no-store'}).catch(()=>{}),1000)";
  const w = new Worker(URL.createObjectURL(new Blob([src],{type:'text/javascript'})));
  w.onerror = () => beacon('worker-failed');
  beacon('worker-started');
} catch(e) { beacon('worker-failed'); log('worker failed: '+e); }
</script>
'@

# The tester's signal comes from the keyboard, so a console that cannot be
# read makes the whole run impossible. Checked HERE rather than discovered 12
# seconds in: piping this script's output (or running it from CI) makes
# [Console]::KeyAvailable throw, and the previous version reached the freeze
# prompt, threw there, and then reported VOID -- a correct refusal arrived at
# for the wrong reason, and with no clue what to do about it.
#
# There is nothing to pipe anyway: everything printed also goes to
# freeze-probe-log.txt.
$consoleReadable = $true
try { $null = [Console]::KeyAvailable } catch { $consoleReadable = $false }
if (-not $consoleReadable) {
    Say ""
    Say "  This probe needs an interactive console: you signal Freeze and" "Red"
    Say "  Unfreeze by pressing SPACE, and console input is redirected here." "Red"
    Say "  Run it directly in a PowerShell window, without piping its output." "Red"
    Say "  Everything it prints already goes to $logPath." "Red"
    exit 8
}

# Plain TCP. No elevation, no URL ACL, no http.sys.
$listener = $null
foreach ($p in @($Port, 8081, 8082, 9090)) {
    try {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $p)
        $l.Start()
        $listener = $l; $Port = $p
        break
    } catch {
        Say ("  port {0} unavailable: {1}" -f $p, $_.Exception.Message) "DarkYellow"
    }
}
if (-not $listener) { Say "  Could not open any port. Send me freeze-probe-log.txt." "Red"; exit 1 }

Say ""
Say ("  OPEN THIS IN PATANYX:   http://localhost:{0}/" -f $Port) "Cyan"
Say "  Take your time -- nothing is being measured until that page loads."
Say "  There is no button to click. Wait for BASELINE OK, then this window"
Say "  will tell you exactly when to press Freeze and Unfreeze."
Say "  It ends by itself and exits with a code; no Ctrl+C needed."
Say ""

# Counters, one set per measured window. Kept separate rather than summed so
# a verdict can name WHICH window misbehaved.
$counts = @{
    baseline = @{ fetch = 0; ws = 0; worker = 0 }
    settling = @{ fetch = 0; ws = 0; worker = 0 }
    frozen   = @{ fetch = 0; ws = 0; worker = 0 }
    thawing  = @{ fetch = 0; ws = 0; worker = 0 }
    thawed   = @{ fetch = 0; ws = 0; worker = 0 }
}
# Starts in "waiting", NOT "baseline": the tester still has to open the
# browser and navigate, and measuring that interval as though it were traffic
# is what produced a VOID run in v7.
$phase = "waiting"
$workerFailed = $false
$sawFirstHit = $false
$started = Get-Date
$phaseAt = $started

# A request already in flight when Freeze was pressed is not a leak, and at a
# one-second beacon interval at most one of each kind can be. Anything still
# arriving after this window is the engine ignoring the block.
$SETTLE = [TimeSpan]::FromMilliseconds(1500)
# How long the tester gets to open the browser and load the page. Generous
# on purpose: nothing is being measured yet, so a long wait costs nothing,
# whereas a short one throws the run away before it starts.
$PAGE_TIMEOUT_SECS = 300
$BASELINE_SECS = 12
$FROZEN_SECS   = 12
$THAWED_SECS   = 12
$SIGNAL_TIMEOUT_SECS = 180
# Traffic is "flowing" at 5+ of each in a 12s window; the beacons fire once a
# second, so this tolerates a slow start without tolerating a dead page.
$WANT = 5

function Send-Reply($stream, $status, $ctype, $bodyBytes) {
    $head = "HTTP/1.1 $status`r`nContent-Type: $ctype`r`nContent-Length: $($bodyBytes.Length)`r`n" +
            "Cache-Control: no-store`r`nConnection: close`r`n`r`n"
    $hb = [Text.Encoding]::ASCII.GetBytes($head)
    $stream.Write($hb, 0, $hb.Length)
    if ($bodyBytes.Length) { $stream.Write($bodyBytes, 0, $bodyBytes.Length) }
    $stream.Flush()
}

# Drains anything typed earlier so a stray keypress cannot advance a phase the
# operator has not reached yet.
function Clear-Keys {
    try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch {}
}
function Got-Space {
    try {
        if (-not [Console]::KeyAvailable) { return $false }
        $k = [Console]::ReadKey($true)
        return ($k.Key -eq "Spacebar")
    } catch { return $false }
}

$verdict = $null   # set once, by whichever branch ends the run
$exitCode = 0

try {
    while ($true) {
        $now = Get-Date
        $inPhase = ($now - $phaseAt)

        # --- phase transitions -------------------------------------------
        switch ($phase) {
            "waiting" {
                if ($sawFirstHit) {
                    Say ""
                    Say ("  Page is beaconing. Measuring baseline for {0}s." -f $BASELINE_SECS) "Green"
                    $phase = "baseline"; $phaseAt = $now
                } elseif ($inPhase.TotalSeconds -ge $PAGE_TIMEOUT_SECS) {
                    Say ""
                    Say ("  The probe page never loaded within {0}s." -f $PAGE_TIMEOUT_SECS) "Red"
                    Say "  Nothing was measured, so nothing about Freeze can be concluded." "Red"
                    $verdict = "VOID: the probe page never reached this server. " +
                               "Check the URL was opened in PATANYX and that no other browser took it."
                    $exitCode = 2
                    $phase = "done"
                }
            }
            "baseline" {
                if ($inPhase.TotalSeconds -ge $BASELINE_SECS) {
                    $b = $counts.baseline
                    Say ""
                    # Gated on fetch alone; see Get-FreezeVerdict for why the
                    # other two are measured but not required.
                    if ($b.fetch -ge $WANT) {
                        Say ("  BASELINE OK - fetch={0} ws={1} worker={2}" -f $b.fetch, $b.ws, $b.worker) "Green"
                        $thin = @()
                        if ($b.ws -lt $WANT)     { $thin += "ws" }
                        if ($b.worker -lt $WANT) { $thin += "worker" }
                        if ($thin.Count -gt 0) {
                            Say ("  NOTE: {0} never got going, so this run cannot conclude" -f ($thin -join " and ")) "DarkYellow"
                            Say "  anything about that channel. The fetch measurement still stands." "DarkYellow"
                        }
                        Say ""
                        Say "  ---------------------------------------------------------------" "Cyan"
                        Say "   1. Press FREEZE in the PATANYX toolbar." "Cyan"
                        Say "   2. Come back here and press SPACE." "Cyan"
                        Say "  ---------------------------------------------------------------" "Cyan"
                        Clear-Keys
                        $phase = "await_freeze"; $phaseAt = $now
                    } else {
                        Say ("  BASELINE BAD - fetch={0} ws={1} worker={2} (need fetch {3}+)" -f
                            $b.fetch, $b.ws, $b.worker, $WANT) "Red"
                        if ($workerFailed) { Say "  the Worker never started" "Red" }
                        $verdict = ("VOID: no traffic to freeze (baseline fetch={0}, want {1}+). " -f $b.fetch, $WANT) +
                                   "Nothing about Freeze can be concluded."
                        $exitCode = 2
                        $phase = "done"
                    }
                }
            }
            "await_freeze" {
                if (Got-Space) {
                    Say ""
                    Say "  ============ FREEZE PRESSED ============" "Cyan"
                    Say ("  Ignoring the next {0}ms (requests already in flight)." -f $SETTLE.TotalMilliseconds) "DarkGray"
                    $phase = "settling"; $phaseAt = $now
                } elseif ($inPhase.TotalSeconds -ge $SIGNAL_TIMEOUT_SECS) {
                    $verdict = "VOID: no SPACE after Freeze within $SIGNAL_TIMEOUT_SECS seconds."
                    $exitCode = 3
                    $phase = "done"
                }
            }
            "settling" {
                if ($inPhase -ge $SETTLE) {
                    Say ("  Measuring the frozen tab for {0}s. Anything below is a LEAK." -f $FROZEN_SECS) "Yellow"
                    $phase = "frozen"; $phaseAt = $now
                }
            }
            "frozen" {
                if ($inPhase.TotalSeconds -ge $FROZEN_SECS) {
                    $f = $counts.frozen
                    Say ""
                    Say ("  FROZEN window - fetch={0} ws={1} worker={2}" -f $f.fetch, $f.ws, $f.worker) "Cyan"
                    Say ""
                    Say "  ---------------------------------------------------------------" "Cyan"
                    Say "   3. Press UNFREEZE in the PATANYX toolbar." "Cyan"
                    Say "   4. Come back here and press SPACE." "Cyan"
                    Say "      (this is the control: traffic MUST come back, or the" "Cyan"
                    Say "       silence above proved nothing about Freeze)" "Cyan"
                    Say "  ---------------------------------------------------------------" "Cyan"
                    Clear-Keys
                    $phase = "await_thaw"; $phaseAt = $now
                }
            }
            "await_thaw" {
                if (Got-Space) {
                    Say ""
                    Say "  ============ UNFREEZE PRESSED ============" "Cyan"
                    $phase = "thawing"; $phaseAt = $now
                } elseif ($inPhase.TotalSeconds -ge $SIGNAL_TIMEOUT_SECS) {
                    $verdict = "VOID: no SPACE after Unfreeze within $SIGNAL_TIMEOUT_SECS seconds. " +
                               "The frozen window cannot be trusted without the control."
                    $exitCode = 4
                    $phase = "done"
                }
            }
            "thawing" {
                # A tab coming out of a freeze may take a beat; same settle.
                if ($inPhase -ge $SETTLE) {
                    Say ("  Checking traffic returns, {0}s." -f $THAWED_SECS) "Yellow"
                    $phase = "thawed"; $phaseAt = $now
                }
            }
            "thawed" {
                if ($inPhase.TotalSeconds -ge $THAWED_SECS) {
                    $phase = "done"
                }
            }
        }
        if ($phase -eq "done") { break }

        # --- serve ---------------------------------------------------------
        if (-not $listener.Pending()) { Start-Sleep -Milliseconds 40; continue }

        $client = $listener.AcceptTcpClient()
        $client.ReceiveTimeout = 2000; $client.SendTimeout = 2000
        $stream = $client.GetStream()
        $buf = New-Object byte[] 4096
        $n = 0
        try { $n = $stream.Read($buf, 0, $buf.Length) } catch {}
        $req = if ($n -gt 0) { [Text.Encoding]::ASCII.GetString($buf, 0, $n) } else { "" }
        $path = "/"
        if ($req -match '^[A-Z]+\s+(\S+)') { $path = $matches[1] }
        if ($path.Contains("?")) { $path = $path.Split("?")[0] }

        if ($path -like "/hit/*") {
            $kind = $path -replace "^/hit/", ""
            if ($kind -eq "worker-failed") {
                $workerFailed = $true; Say "  the Worker failed to start" "Red"
            } elseif ($kind -ne "worker-started") {
                # Releases the "waiting" phase. Deliberately gated on a real
                # beacon rather than on the page GET: a document can be served
                # to something that never runs its script, and that is not
                # traffic to freeze.
                $sawFirstHit = $true
                $bucket = $counts[$phase]
                if ($bucket -and $bucket.ContainsKey($kind)) { $bucket[$kind]++ }
                # Only the frozen window is printed per-request: that is where
                # a single line is evidence rather than noise.
                if ($phase -eq "frozen") {
                    $c = switch ($kind) { "fetch" {"White"} "ws" {"Yellow"} "worker" {"Magenta"} default {"Gray"} }
                    Say ("  LEAK {0}  {1}" -f (Get-Date -Format "HH:mm:ss"), $kind) $c
                }
            }
        }

        try {
            if ($path -eq "/") {
                Send-Reply $stream "200 OK" "text/html; charset=utf-8" ([Text.Encoding]::UTF8.GetBytes($page))
            } else {
                Send-Reply $stream "200 OK" "text/plain" ([Text.Encoding]::ASCII.GetBytes("ok"))
            }
        } catch {}
        try { $client.Close() } catch {}
    }
}
finally {
    try { $listener.Stop() } catch {}
}

$b = $counts.baseline; $f = $counts.frozen; $t = $counts.thawed
Say ""
Say "  ================= RESULT =================" "Cyan"
Say ("  BASELINE  fetch={0} ws={1} worker={2}" -f $b.fetch, $b.ws, $b.worker) "DarkGray"
Say ("  FROZEN    fetch={0} ws={1} worker={2}" -f $f.fetch, $f.ws, $f.worker) "Cyan"
Say ("  THAWED    fetch={0} ws={1} worker={2}" -f $t.fetch, $t.ws, $t.worker) "DarkGray"
Say ""

if (-not $verdict) {
    $result = Get-FreezeVerdict $b $f $t $WANT
    $verdict = $result.text
    $exitCode = $result.code
}

$colour = if ($exitCode -eq 0) { "Green" } elseif ($exitCode -eq 6) { "Yellow" } else { "Red" }
Say ("  " + $verdict) $colour
Say ""
Say ("  Full log: {0}" -f $logPath) "Cyan"
Say ("  exit code {0}" -f $exitCode) "DarkGray"
exit $exitCode
