#!/usr/bin/env bash
# BEHAVIOURAL proof that a host on the malicious-host list is never contacted.
#
# The unit tests prove HostSet matches correctly. They said exactly the same
# thing while NOTHING CONSTRUCTED IT -- eleven green tests over a module the
# compiler was reporting as dead, and a browser that blocked nothing. Only a
# run that watches the network can tell those two states apart.
#
# WHY THIS ONE CAN ACTUALLY BE RUN. scripts/blocking-probe.sh needs root, edits
# /etc/hosts and binds port 80, which is why it has sat unexecuted: nobody
# sensibly runs that against a machine they care about. This probe needs none
# of it. 127.0.0.0/8 is ALL loopback, so 127.0.0.1 and 127.0.0.2 are two
# distinct hosts as far as the browser is concerned, both already resolving,
# both reachable on an unprivileged port. A probe that requires a sacrificial
# machine is a probe that does not get run.
#
#   127.0.0.1  -> on the list. Must receive ZERO connections.
#   127.0.0.2  -> not on the list. Must be contacted, or the instrument is
#                 broken and the zero above means nothing.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${BIN:-./target/debug/patanyx}"
if [ ! -x "$BIN" ]; then
  echo "PROBE FAIL: no binary at $BIN (set BIN=...)" >&2
  exit 1
fi
echo "probing binary: $BIN ($(stat -c %y "$BIN" | cut -d. -f1))"

WORK="$(mktemp -d)"
LOG="$WORK/hits.log"
LISTED="$WORK/blocklist-listed.txt"
EMPTY="$WORK/blocklist-empty.txt"
# An unlikely port, and the run FAILS LOUDLY if it is taken rather than
# quietly producing a log nothing wrote to. That happened on the first run of
# this script -- another server held the port, no connection was ever recorded,
# and control 1 correctly refused to let the silence read as a block.
PORT=8947

printf '127.0.0.1\n' > "$LISTED"
: > "$EMPTY"

# Two servers on two loopback addresses, so the log records WHICH host the
# browser actually reached. Bound to specific addresses rather than 0.0.0.0:
# this runs on a machine with real services, and a probe has no business
# listening on a public interface even briefly.
python3 - "$LOG" "$PORT" <<'PY' &
import http.server, socketserver, sys, threading
log, port = sys.argv[1], int(sys.argv[2])
lock = threading.Lock()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("Host", "?").split(":")[0]
        with lock:
            open(log, "a").write(f"{host} {self.path}\n")
        body = b"<!doctype html><meta charset=utf-8><title>probe</title>ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
for addr in ("127.0.0.1", "127.0.0.2"):
    srv = socketserver.TCPServer((addr, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
threading.Event().wait()
PY
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$WORK"' EXIT
sleep 1

# One navigation per run, driven after startup by PATANYX_BLOCKING_PROBE_URL.
# The initial tab stays blank deliberately: a positional URL would load once
# at startup, and a pass could then have come from either load.
run_probe() {
  local list="$1" url="$2" out="$WORK/run.log"
  : > "$LOG"
  XDG_DATA_HOME="$(mktemp -d -p "$WORK")" \
  WEBKIT_DISABLE_COMPOSITING_MODE=1 \
  PATANYX_BLOCKLIST_PATH="$list" \
  PATANYX_BLOCKING_PROBE_URL="$url" \
  xvfb-run -a --server-args="-screen 0 1280x900x24" \
    "$BIN" --smoke-test >"$out" 2>&1 || true
  # Without this an early exit leaves an empty log, which reads as a clean
  # pass -- the most misleading result this test can produce.
  if ! grep -q "^PROBE DONE$" "$out"; then
    echo "PROBE FAIL: the navigation never completed; the result is meaningless" >&2
    sed -n '1,20p' "$out" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# 1. CONTROL, first: the instrument works.
#
# Deliberately before the positive case. If an unlisted host is not contacted,
# the server, the browser or the URL is broken, and every "zero connections"
# below would be an artefact rather than a block.
# ---------------------------------------------------------------------------
echo
echo "=== control 1: an UNLISTED host must be contacted ==="
run_probe "$LISTED" "http://127.0.0.2:$PORT/probe"
sort "$LOG" | uniq -c || true
if ! grep -q "^127.0.0.2 /probe$" "$LOG"; then
  echo "CONTROL FAIL: an unlisted host was not reached, so this probe cannot" >&2
  echo "  observe anything and its other results prove nothing." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. THE POSITIVE CASE.
# ---------------------------------------------------------------------------
echo
echo "=== a LISTED host must receive zero connections ==="
run_probe "$LISTED" "http://127.0.0.1:$PORT/probe"
sort "$LOG" | uniq -c || true
if grep -q "^127.0.0.1 " "$LOG"; then
  echo "PROBE FAIL: a listed host was contacted:" >&2
  grep "^127.0.0.1 " "$LOG" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. THE MOST IMPORTANT ASSERTION IN THIS FILE: the LIST is what blocked it.
#
# Same binary, same URL, same everything -- an EMPTY list. The host must now be
# contacted. Without this, "zero connections" is equally consistent with the
# navigation handler denying everything, the URL being malformed, or the probe
# navigating nowhere at all. This is the control that would have caught the
# ad-block defect, where a rule matched nothing while the UI reported
# protection and every test stayed green.
# ---------------------------------------------------------------------------
echo
echo "=== control 2: with an EMPTY list, the same host IS contacted ==="
run_probe "$EMPTY" "http://127.0.0.1:$PORT/probe"
sort "$LOG" | uniq -c || true
if ! grep -q "^127.0.0.1 /probe$" "$LOG"; then
  echo "CONTROL FAIL: with an empty list the host was STILL not contacted." >&2
  echo "  So the block above was not the list doing its job -- something else" >&2
  echo "  is refusing this navigation, and the protection is unproven." >&2
  exit 1
fi

echo
echo "MALICIOUS PROBE OK"
echo "  unlisted host contacted        (the instrument works)"
echo "  listed host: ZERO connections  (the block is real)"
echo "  empty list -> contacted again  (the LIST is what blocked it)"
echo
echo "NOT covered here: the per-tab override. Exercising 'Open anyway' needs a"
echo "  click in the chrome UI, which this harness cannot drive. It is asserted"
echo "  by scripts/blocked-banner-gate.js, which drives the real"
echo "  navigation_blocked event against the DOM harness."
# That gate did not exist when this line was first written, and the line said
# it did -- which is worse than admitting a gap, because it stops anyone
# looking. It exists now; if it is ever removed, correct this too.
