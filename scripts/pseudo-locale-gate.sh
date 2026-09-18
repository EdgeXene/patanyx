#!/usr/bin/env bash
# "PATANYX is internationalized" as a property CI checks, with no translator.
#
# Generates en-XA from en.ftl (every letter accented, every message padded
# ~40%, all of it non-ASCII), simulates the runtime fill over the chrome
# markup, and hunts surviving plain-ASCII words: text that never went
# through the catalog. The allowlist is exact-text with a stale-entry check,
# so an exemption whose element later gets extracted forces its own removal.
#
# Layout overflow is NOT checked here -- the DOM harness has no layout. The
# real-browser pass owns that (open every panel filled with en-XA, fail on
# scrollWidth/scrollHeight past the client box, exempt only reviewed scroll
# containers); this gate owns coverage.
#
# Run: scripts/pseudo-locale-gate.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

python3 scripts/gen-pseudo-locale.py \
  crates/app/src/chrome/i18n/locales/en.ftl "$TMP/en-XA.ftl"

if ! python3 scripts/i18n-coverage-scan.py \
    crates/app/src/chrome/index.html "$TMP/en-XA.ftl" > "$TMP/scan.out" 2>&1; then
  cat "$TMP/scan.out" >&2
  echo "GATE FAIL: English survives a pseudo-locale fill (above)." >&2
  exit 1
fi
grep '^nodes clean' "$TMP/scan.out"
echo "PSEUDO-LOCALE GATE OK"
