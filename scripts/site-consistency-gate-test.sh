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

# THE WINDOWS FRONT DOOR. The download page may name the release the served
# dl/PATANYX.exe really is (its FileVersion), when that is older than the one
# shipping. Each case copies a fixture site to a scratch folder and writes a
# stand-in exe there: a few bytes holding the version resource's FileVersion
# string, never a real binary in this repository.
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
# front_door <case> <fixture> <FileVersion or "none">
front_door() {
  mkdir -p "$scratch/$1"; cp -R "$fx/$2/." "$scratch/$1/"
  if [ "$3" != none ]; then
    mkdir -p "$scratch/$1/dl"
    python3 -I -c 'import sys; v=sys.argv[2]; open(sys.argv[1],"wb").write(b"MZ\x00\x00"+"FileVersion".encode("utf-16-le")+b"\x00\x00"+(v+"\x00").encode("utf-16-le"))' \
      "$scratch/$1/dl/PATANYX.exe" "$3"
  fi
}
expect_at() {
  local want="$1" label="$2" site="$3" must="${4:-}" mustnot="${5:-}" out got
  out=$(python3 -I "$gate" --site "$scratch/$site" --repo "$fx/repo" 2>&1)
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
front_door served front-door 1.0.5
expect_at ok "the download page may name the Windows download it really serves" served \
  "the Windows download (dl/PATANYX.exe) is 1.0.5 while 1.0.6 ships" "shows version 1.0.5"
front_door other front-door 1.0.4
expect_at fail "a version the served exe is not still fails" other \
  "download: shows version 1.0.5 in visible text"
front_door missing front-door none
expect_at fail "with no Windows download to read, the version still fails" missing \
  "download: shows version 1.0.5 in visible text"
front_door newer front-door-newer 1.0.7
expect_at fail "a front door newer than the release shipping excuses nothing" newer \
  "download: shows version 1.0.7 in visible text"
front_door landing front-door-elsewhere 1.0.5
expect_at fail "only the download page may name the front door's version" landing \
  "landing: shows version 1.0.5 in visible text"

if [ "$fail" -ne 0 ]; then echo "SITE CONSISTENCY GATE TEST FAILED"; exit 1; fi
echo "SITE CONSISTENCY GATE TEST OK"
