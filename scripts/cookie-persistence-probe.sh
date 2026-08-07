#!/usr/bin/env bash
# Does a FIRST-PARTY login cookie survive a restart?
#
# This is the "am I still signed in to my bank tomorrow" question, and it is
# separate from third-party blocking (scripts/thirdparty-cookie-probe.sh).
# Sites keep you signed in with a first-party cookie; if those do not persist,
# every launch starts logged out of everything.
#
# WHY IT NEEDED ITS OWN MEASUREMENT. While building the third-party probe I
# looked at a profile directory after a run, found no cookie file, and inferred
# cookies were memory-only. That inference was WRONG-BY-CONSTRUCTION: the run
# had loaded about:blank, which sets no cookies, so an empty profile proved
# nothing at all. A claim about persistence has to come from a run that
# actually stores a cookie and a second run that looks for it.
#
#   visit 1  http://127.0.0.1 sets a plain first-party cookie
#   visit 2  same profile, same origin -- does the browser send it back?
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
EMPTY="$WORK/blocklist-empty.txt"
: > "$EMPTY"
: > "$LOG"
PORT=8952
PROFILE="$WORK/profile"
mkdir -p "$PROFILE"

python3 - "$LOG" "$PORT" <<'PY' &
import http.server, socketserver, sys, threading
log, port = sys.argv[1], int(sys.argv[2])
lock = threading.Lock()

PAGE = """<!doctype html><meta charset=utf-8><title>login cookie</title>
<body style="font:16px system-ui;background:#111;color:#eee;padding:2rem">
<h1>first-party cookie</h1></body>"""

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        got = self.headers.get("Cookie", "")
        with lock:
            open(log, "a").write("VISIT cookie=%s\n" % (got if got else "<none>"))
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # What a login looks like: first-party, long-lived, with an explicit
        # Expires so it is a PERSISTENT cookie rather than a session cookie.
        # A session cookie is expected to die with the browser; only a
        # persistent one answers the question being asked here.
        self.send_header(
            "Set-Cookie",
            "sessionid=logged-in; Path=/; Max-Age=86400; SameSite=Lax")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
srv = socketserver.TCPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
threading.Event().wait()
PY
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$WORK"' EXIT
sleep 1

visit() {
  local out="$WORK/run.log"
  # The smoke sequence refuses to run against an existing vault, and its
  # bookmark step refuses a store left over from the previous visit. Both are
  # correct guards; both are about the SMOKE harness, not about cookies. They
  # are the only files removed -- the cookie jar, whatever form it takes, is
  # deliberately untouched, since its survival is the measurement.
  rm -f "$PROFILE/patanyx/vault.rbv" "$PROFILE/patanyx/vault.rbv.lock" \
        "$PROFILE/patanyx/store.rbs" 2>/dev/null || true
  rm -f "$PROFILE"/patanyx/vault.rbv.bak-* 2>/dev/null || true
  XDG_DATA_HOME="$PROFILE" \
  WEBKIT_DISABLE_COMPOSITING_MODE=1 \
  PATANYX_BLOCKLIST_PATH="$EMPTY" \
  PATANYX_BLOCKING_PROBE_URL="http://127.0.0.1:$PORT/app" \
  xvfb-run -a --server-args="-screen 0 1280x900x24" \
    "$BIN" --smoke-test >"$out" 2>&1 || true
  if ! grep -q "^PROBE DONE$" "$out"; then
    echo "PROBE FAIL: the navigation never completed; the result is meaningless" >&2
    sed -n '1,25p' "$out" >&2
    exit 1
  fi
}

echo
echo "=== visit 1: sets a persistent first-party cookie ==="
visit
V1="$(grep '^VISIT ' "$LOG" | head -1 || true)"
echo "  $V1"
if [ -z "$V1" ]; then
  echo "CONTROL FAIL: the page was never requested; nothing was measured." >&2
  exit 1
fi

echo
echo "=== what the profile holds between runs ==="
find "$PROFILE" -type f 2>/dev/null | sed "s|$PROFILE/||" | sort | head -20
COOKIEFILE="$(find "$PROFILE" -iname '*cookie*' 2>/dev/null | head -1 || true)"
if [ -n "$COOKIEFILE" ]; then
  echo "  cookie store on disk: ${COOKIEFILE#$PROFILE/} ($(stat -c %s "$COOKIEFILE") bytes)"
else
  echo "  no cookie store written to disk"
fi

: > "$LOG"
echo
echo "=== visit 2: same profile, same site ==="
visit
V2="$(grep '^VISIT ' "$LOG" | head -1 || true)"
echo "  $V2"
if [ -z "$V2" ]; then
  echo "CONTROL FAIL: visit 2 never reached the server." >&2
  exit 1
fi

echo
echo "================ RESULT ================"
if printf '%s' "$V2" | grep -q "sessionid=logged-in"; then
  echo "FIRST-PARTY COOKIES PERSIST ACROSS RESTARTS."
  echo
  echo "A site that signs you in will still know you on the next launch, the"
  echo "same as any ordinary browser. Nothing about the third-party refusal"
  echo "touches this."
  exit 0
fi
echo "FIRST-PARTY COOKIES DO NOT SURVIVE A RESTART."
echo
echo "The cookie was set with Max-Age (a persistent cookie, not a session one)"
echo "and did not come back on the next launch. Every launch therefore starts"
echo "signed out of every site."
echo
echo "That is a real privacy property, but it is NOT currently a decision --"
echo "nothing in this codebase calls webkit_cookie_manager_set_persistent_storage,"
echo "so it is a default nobody chose. It needs to become deliberate: either"
echo "owned and stated plainly on the About page, or fixed."
exit 3
