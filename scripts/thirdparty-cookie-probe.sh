#!/usr/bin/env bash
# Can a third party follow you from one site to another in this browser?
#
# WHY THIS RUNS BEFORE ANY CODE IS WRITTEN. The plan's first draft said: add
# WEBKIT_COOKIE_POLICY_ACCEPT_NO_THIRD_PARTY next to enable_itp and ship a
# toggle. WebKit documents that once ITP is enabled it takes over third-party
# cookie handling and an ACCEPT_NO_THIRD_PARTY request is treated as
# ACCEPT_ALWAYS -- so that call may do NOTHING while the code, a panel row and
# an About card all say it does. This repository has paid for that twice (an
# ad-block rule that matched nothing; referrer trimming the engine already
# did). Measure first; let the measurement decide whether code gets written.
#
# WHY THIS IS A ONE-SESSION TEST, not "visit, restart, visit again". The first
# draft of this probe did exactly that, and it was broken in a way that would
# have PASSED: PATANYX never calls webkit_cookie_manager_set_persistent_storage,
# so WebKitGTK keeps cookies in memory only and a profile directory after a run
# contains no cookie store at all. Every across-restart measurement would have
# reported "no cookie came back" no matter how the engine behaves, and read as
# protection. Within one session is also the truer question: a tracker
# correlating two sites does it while the browser is running.
#
# THE MEASUREMENT. Three loopback addresses, three distinct origins to the
# engine:
#
#   127.0.0.1  first-party site A
#   127.0.0.2  first-party site B  (a DIFFERENT site, same browser session)
#   127.0.0.3  the third party, embedded by BOTH of them
#
#   stage 1   third party embedded on site A -- sets a cookie
#   stage 1b  third party embedded on site A again -- INSTRUMENT CONTROL:
#             if the cookie does not come back even here, cookies are simply
#             not working in this harness and stage 2's silence proves nothing
#   stage 2   third party embedded on site B -- THE CROSS-SITE CASE. A cookie
#             here means one third party recognises the same browser across
#             two unrelated sites, which is precisely cross-site tracking.
#
# The server is the witness. Nothing here asks the browser to describe itself.
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
PORT=8951

python3 - "$LOG" "$PORT" <<'PY' &
import http.server, socketserver, sys, threading
log, port = sys.argv[1], int(sys.argv[2])
lock = threading.Lock()
TP = "127.0.0.3"
SITE_B = "127.0.0.2"

# Site A: embeds the third party, then AGAIN (the instrument control), then
# hands the top-level page to site B. Chained on load events rather than fixed
# sleeps where possible so the whole run fits inside PROBE_SETTLE (6s).
SITE_A = """<!doctype html><meta charset=utf-8><title>site A</title>
<body style="font:16px system-ui;background:#111;color:#eee;padding:2rem">
<h1>site A</h1>
<iframe id="f1" src="http://%s:%d/tp?stage=1" width="320" height="60"></iframe>
<script>
  // STAGE 0, the storage control: a plain FIRST-PARTY cookie, same origin as
  // this page. If even this does not come back, cookies are off entirely and
  // nothing below is about third parties at all.
  fetch('/fp-check', {credentials: 'same-origin'}).then(function () {
    document.getElementById('f1').onload = function () {
      var f2 = document.createElement('iframe');
      f2.width = 320; f2.height = 60;
      f2.src = 'http://%s:%d/tp?stage=1b';
      f2.onload = function () {
        setTimeout(function () {
          location.href = 'http://%s:%d/site-b';
        }, 300);
      };
      document.body.appendChild(f2);
    };
    // The iframe may already have loaded before the fetch resolved.
    if (document.getElementById('f1').contentDocument &&
        document.getElementById('f1').contentDocument.readyState === 'complete') {
      document.getElementById('f1').onload();
    }
  });
</script>
</body>"""

# Site B: a different first party embedding the same third party, then it
# hands the top level to the third party itself for stage 3.
SITE_B_PAGE = """<!doctype html><meta charset=utf-8><title>site B</title>
<body style="font:16px system-ui;background:#111;color:#eee;padding:2rem">
<h1>site B</h1>
<iframe id="f3" src="http://%s:%d/tp?stage=2" width="320" height="60"></iframe>
<script>
  document.getElementById('f3').onload = function () {
    setTimeout(function () {
      location.href = 'http://%s:%d/tp-firstparty';
    }, 200);
  };
</script>
</body>"""

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # "/tp?" and not "/tp": /tp-firstparty below shares the prefix, and a
        # loose match here would swallow stage 3 into the embed branch.
        if self.path.startswith("/tp?"):
            stage = self.path.split("stage=")[-1] if "stage=" in self.path else "?"
            got = self.headers.get("Cookie", "")
            with lock:
                open(log, "a").write(
                    "TP stage=%s cookie=%s\n" % (stage, got if got else "<none>"))
            body = b"<!doctype html><meta charset=utf-8>third party"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # THREE SHAPES AT ONCE, because "no cookie came back" has several
            # innocent explanations and they must be told apart:
            #
            #   tp_none  SameSite=None WITHOUT Secure. Chromium rejects this
            #            outright; WebKit's behaviour is what we are here to
            #            find out. Cannot add Secure -- this is plain http.
            #   tp_lax   SameSite=Lax, which is NOT sent in a third-party
            #            iframe by spec. Present as a reference point.
            #   tp_plain no SameSite attribute at all -- the legacy shape,
            #            and the one an old tracker would actually use.
            #
            # Whichever of these returns tells us what the engine stores and
            # sends; if none does, the instrument is broken rather than the
            # browser protected, and stage 1b catches exactly that.
            self.send_header("Set-Cookie", "tp_none=tracked-you; Path=/; SameSite=None")
            self.send_header("Set-Cookie", "tp_lax=tracked-you; Path=/; SameSite=Lax")
            self.send_header("Set-Cookie", "tp_plain=tracked-you; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/tp-firstparty"):
            # STAGE 3, the disambiguator. Same host as the third party, but
            # reached by TOP-LEVEL navigation, so it is first-party here and
            # ordinary SameSite rules do not suppress its cookies.
            #
            # This separates the two explanations for stages 1b/2 being empty:
            #   cookie present  -> it WAS stored while embedded; it simply is
            #                      not SENT in a third-party context. That is
            #                      SameSite doing its job, which every modern
            #                      engine does; not a PATANYX defense.
            #   cookie absent   -> the Set-Cookie was REFUSED outright while
            #                      embedded, i.e. third-party cookie storage
            #                      is genuinely blocked.
            got = self.headers.get("Cookie", "")
            with lock:
                open(log, "a").write(
                    "TPFIRSTPARTY cookie=%s\n" % (got if got else "<none>"))
            body = b"<!doctype html><meta charset=utf-8>third party, first-party context"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/fp-check"):
            # STAGE 0: same-origin request from site A. Was site A's own
            # first-party cookie stored and returned?
            got = self.headers.get("Cookie", "")
            with lock:
                open(log, "a").write(
                    "FIRSTPARTY cookie=%s\n" % (got if got else "<none>"))
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/site-b"):
            with lock:
                open(log, "a").write("PAGE site-b\n")
            body = (SITE_B_PAGE % (TP, port, TP, port)).encode()
        else:
            with lock:
                open(log, "a").write("PAGE site-a\n")
            body = (SITE_A % (TP, port, TP, port, SITE_B, port)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # Site A's OWN cookie: plain, first-party, no SameSite games. The
            # storage control that /fp-check reads back.
            self.send_header("Set-Cookie", "fp_site_a=first-party; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
for addr in ("127.0.0.1", "127.0.0.2", "127.0.0.3"):
    srv = socketserver.TCPServer((addr, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
threading.Event().wait()
PY
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$WORK"' EXIT
sleep 1

# The shipping configuration: ITP ON (enable_itp runs for every content
# webview) and no cookie-accept policy set by us anywhere.
PROFILE="$WORK/profile"
mkdir -p "$PROFILE"
OUT="$WORK/run.log"
echo
echo "=== one session: site A -> (third party twice) -> site B ==="
XDG_DATA_HOME="$PROFILE" \
WEBKIT_DISABLE_COMPOSITING_MODE=1 \
PATANYX_BLOCKLIST_PATH="$EMPTY" \
PATANYX_BLOCKING_PROBE_URL="http://127.0.0.1:$PORT/site-a" \
xvfb-run -a --server-args="-screen 0 1280x900x24" \
  "$BIN" --smoke-test >"$OUT" 2>&1 || true
if ! grep -q "^PROBE DONE$" "$OUT"; then
  echo "PROBE FAIL: the navigation never completed; the result is meaningless" >&2
  sed -n '1,25p' "$OUT" >&2
  exit 1
fi

echo "--- what the server saw ---"
cat "$LOG"

stage() { grep "^TP stage=$1 " "$LOG" | head -1 || true; }
S1="$(stage 1)"; S1B="$(stage 1b)"; S2="$(stage 2)"
FP="$(grep '^FIRSTPARTY ' "$LOG" | head -1 || true)"

# STAGE 0 FIRST. If a plain first-party cookie does not round-trip, this
# browser is storing no cookies at all and every "third-party cookie refused"
# reading below is an artefact of that, not a defense.
if [ -z "$FP" ]; then
  echo "CONTROL FAIL: the first-party check never ran; the page script did not" >&2
  echo "  execute, so nothing here was measured." >&2
  exit 1
fi
if ! printf '%s' "$FP" | grep -q "fp_site_a=first-party"; then
  echo
  echo "NOTE: no FIRST-PARTY cookie came back either ($FP)." >&2
  echo "  Cookies are not being stored at all in this configuration. That is a" >&2
  echo "  finding in its own right, but it means the third-party stages below" >&2
  echo "  measure storage being off -- NOT a cross-site defense. Do not read" >&2
  echo "  them as protection." >&2
  echo "  (PATANYX never calls webkit_cookie_manager_set_persistent_storage;" >&2
  echo "   whether that also disables in-memory storage is what this line is" >&2
  echo "   reporting.)" >&2
  exit 2
fi
echo "  stage 0 (first-party, same origin): $FP   <- cookies ARE stored"

# ---------------------------------------------------------------------------
# CONTROLS FIRST. Each one can turn a "protected" reading into a broken run,
# and they are checked before the result is interpreted.
# ---------------------------------------------------------------------------
if [ -z "$S1" ]; then
  echo "CONTROL FAIL: the third party was never embedded at all; nothing was measured." >&2
  exit 1
fi
if [ -z "$S1B" ]; then
  echo "CONTROL FAIL: the second same-site embed never fired, so the instrument" >&2
  echo "  cannot show whether the cookie was stored." >&2
  exit 1
fi
if [ -z "$S2" ]; then
  echo "CONTROL FAIL: site B never embedded the third party (top-level navigation" >&2
  echo "  probably did not happen), so the cross-site case was never tested." >&2
  exit 1
fi
TPFP="$(grep '^TPFIRSTPARTY ' "$LOG" | head -1 || true)"
if [ -z "$TPFP" ]; then
  echo "CONTROL FAIL: stage 3 never ran (top-level navigation to the third" >&2
  echo "  party did not happen), so an empty stage 1b/2 cannot be explained." >&2
  exit 1
fi
echo "  stage 3 (3p reached top-level)    : $TPFP"

echo
echo "================ RESULT ================"
echo "  stage 1  (3p embedded on site A, sets): $S1"
echo "  stage 1b (3p embedded on site A again): $S1B"
echo "  stage 2  (3p embedded on site B)      : $S2"
echo "  stage 3  (3p AS first party)          : $TPFP"
echo

if printf '%s' "$S2" | grep -qE "tp_(none|lax|plain)=tracked-you"; then
  echo "CROSS-SITE TRACKING SUCCEEDS."
  echo
  echo "One third party was handed the same cookie on two unrelated sites in"
  echo "one session. ITP alone does not stop this."
  echo
  echo "=> Phase 1 proceeds: add the cookie-accept policy beside enable_itp and"
  echo "   RE-RUN THIS PROBE. Stage 2 must flip to <none>. If it does not,"
  echo "   WebKit is overriding the policy because ITP owns the decision, and"
  echo "   the honest outcome is a documented limit -- not a toggle."
  exit 3
fi

# Stage 2 is empty. Stage 3 says WHY, and the two answers have very different
# consequences for what we may claim.
if printf '%s' "$TPFP" | grep -qE "tp_(none|lax|plain)=tracked-you"; then
  echo "NO CROSS-SITE COOKIE FLOWED -- but stage 3 shows the cookie WAS STORED"
  echo "while the third party was embedded; it simply is not SENT in a"
  echo "third-party context."
  echo
  echo "That is SameSite doing its job. Every modern engine does it, over plain"
  echo "http a SameSite=None cookie cannot even carry Secure, and none of it is"
  echo "a PATANYX defense. This harness therefore CANNOT distinguish ITP from"
  echo "the engine's ordinary defaults, and resolving it needs an HTTPS probe"
  echo "where a real tracker's 'SameSite=None; Secure' cookie is valid."
  echo
  echo "=> Do NOT claim third-party cookie blocking on this evidence. Also do"
  echo "   not add the accept-policy call: nothing here can show it changing"
  echo "   anything, which is the same reason referrer trimming was deleted."
  exit 2
fi

echo "THIRD-PARTY COOKIE STORAGE IS REFUSED OUTRIGHT."
echo
echo "The cookie set while the third party was embedded did not come back even"
echo "in stage 3, where that same host is the first party and SameSite imposes"
echo "no restriction at all. So it was never stored: the engine refused a"
echo "third-party Set-Cookie. First-party cookies work (stage 0), so this is"
echo "specific to the third-party context rather than cookies being off."
echo
echo "=> Phase 1 needs NO new code on this backend. An accept-policy call here"
echo "   would be a line that cannot be shown to change anything."
exit 0
