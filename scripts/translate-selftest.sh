#!/usr/bin/env bash
# The full-loop translation self-test, made reproducible.
#
# WHY THE FIXTURE EXISTS. selftest_step's restore check greps run 2's
# extraction for the marker sentences below. Run the binary bare and the first
# tab opens the live home page, which translates and restores perfectly well --
# and then fails the harness, because real English does not happen to contain
# "Hello world". The page under test must be THIS page, so the harness's
# markers and the page's text cannot drift apart: the fixture is written here,
# beside the check that reads it.
#
# WHAT IT PROVES (all against the production state machine, no reach-arounds):
#   translate en->es on a page declaring lang="en"  -> patched
#   Show original                                    -> the page reads English
#   translate again                                  -> accepted, patched again
# The corruption guard's negative case (Greek into an en model refuses, page
# untouched) is NOT re-proven here; it is pinned at the unit layer (detect.rs)
# and the state layer (state.rs, "THE CORRUPTION GUARD, proved at the state
# layer"). One fixture, one language, one clean positive loop.
#
# Needs: a debug build, xvfb-run, and PATANYX_PACK_ROOT holding en-es/
# (model.bin, lex.bin, vocab.spm). Unpack one from a published .pxpack:
#   python3 scripts/unpack-langpack.py /srv/patanyx-models/packs/en-es.pxpack <root>/en-es
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

BIN="${PATANYX_BIN:-target/debug/patanyx}"
[ -x "$BIN" ] || { echo "no debug binary at $BIN (cargo build -p patanyx)" >&2; exit 2; }
[ -n "${PATANYX_PACK_ROOT:-}" ] || { echo "set PATANYX_PACK_ROOT (must hold en-es/)" >&2; exit 2; }
[ -f "$PATANYX_PACK_ROOT/en-es/model.bin" ] || { echo "no en-es pack under $PATANYX_PACK_ROOT" >&2; exit 2; }

# The fixture is served over LOOPBACK HTTP, not file://: is_translatable_url
# refuses file: by policy (an internal page is not something a user asked to
# read in another language), and the self-test must exercise that policy, not
# carve a hole through it. A 127.0.0.1 page is what a real page is.
FIXDIR="$(mktemp -d)"
FIX="$FIXDIR/selftest-page.html"
cat > "$FIX" <<'HTML'
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Translation self-test page</title></head>
<body>
  <h1>Hello world</h1>
  <p>The quick brown fox.</p>
  <p>Good morning.</p>
  <p>This page exists so the self-test can translate something whose text it
     also knows. It is written in English and says so in its lang attribute.</p>
  <p>A second paragraph, so the patch has more than one node to land on and
     the restore has more than one node to put back.</p>
</body>
</html>
HTML

PORT_FILE="$(mktemp)"
python3 - "$FIXDIR" "$PORT_FILE" <<'PYSRV' &
import http.server, os, socketserver, sys
os.chdir(sys.argv[1])
with socketserver.TCPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler) as srv:
    open(sys.argv[2], "w").write(str(srv.server_address[1]))
    srv.serve_forever()
PYSRV
SRV_PID=$!
# Killed by PID on every exit path -- never by pattern.
trap 'kill "$SRV_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do [ -s "$PORT_FILE" ] && break; sleep 0.1; done
PORT="$(cat "$PORT_FILE")"
[ -n "$PORT" ] || { echo "fixture server never reported a port" >&2; exit 2; }

OUT="$(mktemp)"
set +e
PATANYX_TRANSLATE_SELFTEST=1 timeout 180 xvfb-run -a "$BIN" "http://127.0.0.1:$PORT/selftest-page.html" >"$OUT" 2>&1
CODE=$?
set -e
grep -E "selftest|verdict" "$OUT" | tail -8
if [ "$CODE" -ne 0 ]; then
  echo "TRANSLATE SELFTEST FAILED (exit $CODE); full log: $OUT" >&2
  exit "$CODE"
fi
echo "TRANSLATE SELFTEST OK"
rm -f "$OUT"
