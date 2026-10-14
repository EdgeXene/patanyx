#!/usr/bin/env bash
# Proves site-consistency-gate.py's version check on fixture pages, never on
# the live site. The fixtures (scripts/fixtures/site-consistency/) are judged
# against a fixture Cargo.toml that ships 1.0.6, so they do not move with each
# release.
#
# The case that made this exist: on the 1.0.6 download page the gate reported
# "shows version 2.54.0", which is WebKitGTK's version in the "Getting
# WebKitGTK 2.54" section, not a PATANYX release. The gate must let that pass
# and still fail a stale PATANYX version, including one placed right after a
# sentence that names the engine.
set -u
here=$(cd "$(dirname "$0")" && pwd)
gate="$here/site-consistency-gate.py"
fx="$here/fixtures/site-consistency"
fail=0

# expect <ok|fail> <label> <site> [text the output must contain] [text it must not]
expect() {
  local want="$1" label="$2" site="$3" must="${4:-}" mustnot="${5:-}" out got
  out=$(python3 -I "$gate" --site "$fx/$site" --repo "$fx/repo" 2>&1)
  if [ $? -eq 0 ]; then got=ok; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "  FAIL $label: expected $want, got $got"; printf '%s\n' "$out" | sed 's/^/       /'; fail=1
  elif [ -n "$must" ] && ! printf '%s\n' "$out" | grep -qF -- "$must"; then
    echo "  FAIL $label: output does not say \"$must\""; printf '%s\n' "$out" | sed 's/^/       /'; fail=1
  elif [ -n "$mustnot" ] && printf '%s\n' "$out" | grep -qF -- "$mustnot"; then
    echo "  FAIL $label: output says \"$mustnot\""; printf '%s\n' "$out" | sed 's/^/       /'; fail=1
  else
    echo "  ok  $label"
  fi
}

echo "=== site-consistency-gate.py: version claims ==="
expect ok   "the WebKitGTK engine version on the download page passes" engine \
  "all pages agree" "shows version 2.54.0"
expect ok   "the version being shipped passes" current "all pages agree"
expect fail "a stale PATANYX version fails" stale \
  "landing: shows version 1.0.5 in visible text, but 1.0.6 is being shipped"
expect fail "a stale PATANYX version after an engine sentence still fails" stale-after-engine \
  "download: shows version 1.0.5 in visible text" "shows version 2.54.0"

if [ "$fail" -ne 0 ]; then echo "SITE CONSISTENCY GATE TEST FAILED"; exit 1; fi
echo "SITE CONSISTENCY GATE TEST OK"
