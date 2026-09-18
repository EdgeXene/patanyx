#!/usr/bin/env bash
# The translator webview must not share anything with the privileged UI.
#
# WHY THIS IS A GATE AND NOT A PROBE YOU REMEMBER TO RUN.
#
# Phase 0 measured, in the product, that a translator webview on the chrome
# origin shares IndexedDB with the real chrome UI, can load the chrome document
# in a frame, and reaches the chrome protocol handler -- which answers
# /region-capture/ with a screen capture and /archive-picture/ with a DECRYPTED
# page from the encrypted archive. The fix was to give it its own origin, its
# own data store and its own handler.
#
# The unit tests in main.rs pin the STATIC half of that: the constants differ,
# the handler's route table is closed, the policies differ by exactly two
# directives. They cannot pin the half that only exists at runtime -- whether
# the engine actually partitions storage between two live webviews. Only
# running both of them does that, and this is what runs both of them.
#
# It asserts the FIX holds. It deliberately does not assert that the old
# arrangement still leaks: that would pin a defect in place, and the old
# arrangement exists only as a comparison for a human reading the report.
#
# Linux only. The Windows half of this needs a debug build on hardware, and
# until that exists the WebView2 numbers in the spike report are harness
# numbers -- which the report says.
#
# Run: scripts/translator-isolation-gate.sh
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=target/debug/patanyx
if [ ! -x "$BIN" ]; then
  echo "building the debug binary the probe lives in..."
  cargo build -p patanyx --quiet
fi

# A throwaway HOME so the gate never touches a real profile, and so each run
# starts with no residue -- a previous run's marker in a shared store reads as
# "other value" and muddies the result, which is exactly how the first
# separate-origin run was misread.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

out="$WORK/probe.jsonl"
# Defaults to 2, the separate-origin arrangement this gate exists to protect.
# Overridable ONLY so the gate's own discrimination can be proven: run it with
# 1 and every assertion below must fail, because 1 is the arrangement phase 0
# measured as leaking. A gate never seen failing is not a gate.
ARRANGEMENT="${PATANYX_ISOLATION_ARRANGEMENT:-2}"
HOME="$WORK" XDG_DATA_HOME="$WORK/share" XDG_CONFIG_HOME="$WORK/config" \
  PATANYX_ISOLATION_PROBE="$ARRANGEMENT" \
  timeout 180 xvfb-run -a "./$BIN" >"$out" 2>/dev/null || true

if [ ! -s "$out" ]; then
  echo "GATE FAIL: the probe produced no output at all." >&2
  echo "  Neither a pass nor a fail -- the harness did not run." >&2
  exit 1
fi

python3 - "$out" <<'PY'
import json, sys

path = sys.argv[1]
seen = {}
for line in open(path, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    try:
        o = json.loads(line)
    except Exception:
        continue
    seen.update(o)


def sub(key):
    v = seen.get(key)
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return {}
    return v or {}


fail = []

b = sub("b_write")
a = sub("a_read")
nav = sub("b_origin_after_navigation")
ipc = seen.get("ipc_boundary") or {}

# The probe has to have actually run the separate-origin arrangement, or every
# assertion below passes vacuously.
if not b:
    fail.append("the translator webview never reported: the probe did not run")
elif not str(b.get("origin", "")).startswith("rbtranslate"):
    fail.append(f"translator origin is {b.get('origin')!r}, expected rbtranslate")

# It must still WORK. An isolation gate that passes because the translator is
# broken is worse than no gate: it would go green the day the view stops
# loading.
if b and b.get("localStorage") != "wrote":
    fail.append(
        f"the translator could not write its own localStorage "
        f"({b.get('localStorage')!r}) -- isolation that passes because the view "
        "is broken is not isolation"
    )

# The crossings phase 0 measured.
if a:
    if a.get("localStorage") not in ("null",):
        fail.append(f"chrome UI sees translator localStorage: {a.get('localStorage')!r}")
    if a.get("indexedDB") not in ("null", "store absent"):
        fail.append(f"chrome UI sees translator IndexedDB: {a.get('indexedDB')!r}")
    if a.get("cookie") not in ("not visible",):
        fail.append(f"chrome UI sees translator cookie: {a.get('cookie')!r}")
    if a.get("broadcast") not in ("[]",):
        fail.append(f"BroadcastChannel crossed: {a.get('broadcast')!r}")
else:
    fail.append("the chrome webview never reported")

# The guard that turned out to be load-bearing: without it the translator
# navigates itself off its own document.
if nav:
    if not str(nav.get("origin", "")).startswith("rbtranslate"):
        fail.append(
            f"the translator left its own origin: ended on {nav.get('origin')!r} "
            f"({nav.get('href')!r}) -- the navigation guard is not holding"
        )
else:
    fail.append("no post-navigation origin reported")

# The privilege split itself.
if ipc.get("of_which_from_B", 0) != 0:
    fail.append(f"the translator REACHED the privileged ipc handler: {ipc}")
if ipc.get("messages_real_handler_received", 0) == 0:
    fail.append(
        "the real ipc handler received nothing at all, so 'nothing from the "
        "translator' proves nothing -- no positive control"
    )

if fail:
    print("GATE FAIL: translator isolation", file=sys.stderr)
    for f in fail:
        print(f"  - {f}", file=sys.stderr)
    sys.exit(1)

print(
    "TRANSLATOR ISOLATION OK "
    f"(origin {b.get('origin')}; chrome UI sees none of its storage; "
    f"ipc handler took {ipc.get('messages_real_handler_received')} messages "
    "and none from the translator)"
)
PY
