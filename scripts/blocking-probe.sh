#!/usr/bin/env bash
# BEHAVIOURAL proof that a blocked request never leaves the machine.
#
# This is the gap 296 passing tests could not close. The matcher unit tests
# prove the rules are right. The smoke gate proves a filter compiled and
# reached disk. Neither observes the network, and that is precisely where the
# ad-block bug lived: the rule was syntactically perfect, blocked nothing on
# Linux, and every test stayed green for as long as it shipped.
#
# Method: point a tracker domain from the bundled block list AND a normal
# domain at a local server, load a page that fetches both under a live content
# filter, and look at which connections the server actually received.
#
# Runs inside the Debian 13 container: it edits /etc/hosts and binds :80, and
# neither belongs anywhere near the host running the project owner's fleet.
set -euo pipefail

# Explicit, never a symlink into target/debug. That directory already exists
# from host builds, so `ln -sf trixie/debug target/debug` silently creates
# target/debug/debug and the run uses the HOST binary instead. That has now
# cost this project three separate debugging sessions.
BIN="${BIN:-./target/debug/patanyx}"
if [ ! -x "$BIN" ]; then
  echo "PROBE FAIL: no binary at $BIN (set BIN=...)" >&2
  exit 1
fi
echo "probing binary: $BIN ($(stat -c %y "$BIN" | cut -d. -f1))"

BLOCKED_HOST="doubleclick.net"
ALLOWED_HOST="allowed.probe.test"
LOG=/tmp/probe-hits.log
: > "$LOG"

grep -q "$BLOCKED_HOST" /etc/hosts 2>/dev/null || cat >> /etc/hosts <<EOF
127.0.0.1 $BLOCKED_HOST
127.0.0.1 $ALLOWED_HOST
EOF

python3 - "$LOG" <<'PY' &
import http.server, socketserver, sys, threading
log = sys.argv[1]
lock = threading.Lock()

PAGE = b"""<!doctype html><meta charset=utf-8><title>probe</title>
<img src="http://allowed.probe.test/pixel-allowed.png">
<img src="http://doubleclick.net/pixel-blocked.png">
<script src="http://doubleclick.net/tracker.js"></script>
"""

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("Host", "?").split(":")[0]
        # Record the HOST the browser actually connected for. A blocked
        # request must never produce a line here.
        with lock:
            open(log, "a").write(f"{host} {self.path}\n")
        body = PAGE if self.path == "/probe" else b"x"
        ctype = "text/html" if self.path == "/probe" else "image/png"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("127.0.0.1", 80), H).serve_forever()
PY
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 1

export WEBKIT_DISABLE_COMPOSITING_MODE=1
export XDG_DATA_HOME="$(mktemp -d)"
# The initial tab stays blank on purpose: the ONLY page load in this run is
# the probe navigation, which happens after ad blocking is on. Passing the URL
# positionally would load it once at startup with blocking OFF, and a pass
# could then have come from either load.
OUT=/tmp/probe-run.log
PATANYX_BLOCKING_PROBE_URL="http://$ALLOWED_HOST/probe" \
xvfb-run -a --server-args="-screen 0 1280x900x24" \
  "$BIN" --smoke-test >"$OUT" 2>&1 || true
grep -E "SMOKE|PROBE|ENGINE" "$OUT" || true

# Without this the run could exit before the page ever loaded, and an empty
# log would read as a clean pass.
if ! grep -q "^PROBE DONE$" "$OUT"; then
  echo "PROBE FAIL: the probe navigation never completed; result is meaningless" >&2
  exit 1
fi

echo
echo "=== connections the server actually received ==="
sort "$LOG" | uniq -c || true
echo

# The page itself must have loaded, or "nothing was blocked" would be
# indistinguishable from "nothing was requested" — the most misleading
# possible pass for this test.
if ! grep -q "^$ALLOWED_HOST /probe$" "$LOG"; then
  echo "PROBE FAIL: the page never loaded; the result proves nothing" >&2
  exit 1
fi
if ! grep -q "^$ALLOWED_HOST /pixel-allowed.png$" "$LOG"; then
  echo "PROBE FAIL: the ALLOWED subresource never arrived, so the filter is" >&2
  echo "  blocking everything rather than the block list" >&2
  exit 1
fi
if grep -q "^$BLOCKED_HOST " "$LOG"; then
  echo "PROBE FAIL: $BLOCKED_HOST was contacted despite being on the block list:" >&2
  grep "^$BLOCKED_HOST " "$LOG" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# NEGATIVE CONTROL. Everything above is worthless without it.
#
# A test that reports "the tracker was not contacted" passes just as happily
# when the page never loaded, the hosts mapping is wrong, the server is on the
# wrong port, or the image tags are malformed. So: load the SAME page through
# the positional URL, which is fetched at startup BEFORE the smoke sequence
# turns blocking on, and require that the tracker IS contacted there.
#
# If this control fails, the instrument is broken and the pass above means
# nothing -- exactly the trap the ad-block bug hid in, where every green test
# described a rule that blocked nothing.
# ---------------------------------------------------------------------------
: > "$LOG"
export XDG_DATA_HOME="$(mktemp -d)"
xvfb-run -a --server-args="-screen 0 1280x900x24" \
  "$BIN" --smoke-test "http://$ALLOWED_HOST/probe" >/dev/null 2>&1 || true

echo "=== negative control: same page, loaded BEFORE blocking is on ==="
sort "$LOG" | uniq -c || true
if ! grep -q "^$BLOCKED_HOST " "$LOG"; then
  echo >&2
  echo "CONTROL FAIL: $BLOCKED_HOST was not contacted even with blocking OFF." >&2
  echo "  The probe cannot detect the bug it exists for, so its PASS above" >&2
  echo "  proves nothing. Check the hosts mapping, the server and the page." >&2
  exit 1
fi
echo

echo "PROBE OK: with blocking on, the page and its allowed subresource loaded"
echo "  and $BLOCKED_HOST received ZERO connections."
echo "CONTROL OK: with blocking off, the same page DID contact it, so the"
echo "  probe can actually detect the failure it is testing for."
