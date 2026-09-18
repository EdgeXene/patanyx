#!/usr/bin/env bash
# Tests for the popularity tripwire in build-blocklist.sh.
#
# WHAT MUST NOT REGRESS. The tripwire's value is entirely in refusing, so the
# tests that matter are the ones asserting it still says no: a top-10k host
# that nobody has adjudicated has to stop the build. The inverse matters just as
# much -- a confirmed host must NOT stop it, or the first deliberate decision
# wedges hourly publishing until someone deletes the check.
#
# Run:  ./scripts/test-popularity-tripwire.sh
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

SCRIPT=scripts/build-blocklist.sh
TRANCO="${BLOCKLIST_TRANCO_FILE:-/var/lib/patanyx-blocklist/tranco-top100k.txt}"
CONFIRM=scripts/blocklist-confirm.txt
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 -- expected [$2], got [$3]"; fi; }

echo "popularity tripwire"

# --- the shipped reference --------------------------------------------------
N=$(grep -cvE '^\s*(#|$)' "$TRANCO")
check "tranco snapshot holds 100k domains" "100000" "$N"
check "  rank 1 is google.com" "google.com" "$(grep -vE '^\s*(#|$)' "$TRANCO" | sed -n 1p)"
check "  no duplicate ranks" "100000" \
  "$(grep -vE '^\s*(#|$)' "$TRANCO" | sort -u | wc -l)"
# Tranco publishes `_wildcard_.<suffix>` placeholder rows. They are KEPT rather
# than stripped, because rank is line number and removing rows would shift every
# rank below them -- but the build must never MATCH one.
#
# It was asserted here that it could not: that an underscore "cannot survive
# filter_acceptable". That was false. Its class is [^a-z0-9._-], which PERMITS
# underscore, so both rows passed through intact and `_wildcard_.ph` sat at rank
# 1846 -- inside the refuse band. A feed emitting that literal string would have
# frozen publishing over a hostname that cannot resolve.
#
# The exact count is no longer pinned. Tranco controls it and moved it from four
# to two in the 2026-08-31 snapshot, which failed a test that was measuring
# upstream's editorial choices rather than our own behaviour. What is pinned
# below is the property that matters: known shape, a sane ceiling, and -- with
# the regression further down -- that a placeholder cannot produce a hit.
check "  every line is a bare host or a tranco placeholder" "0" \
  "$(grep -vE '^\s*(#|$)' "$TRANCO" | grep -v '^_wildcard_\.' \
     | grep -cvE '^[a-z0-9.-]+\.[a-z0-9-]+$' || true)"
check "  every placeholder has the known _wildcard_. form" "0" \
  "$(grep -E '^_wildcard_' "$TRANCO" | grep -cvE '^_wildcard_\.[a-z0-9.-]+$' || true)"
PLACEHOLDER_N=$(grep -c '^_wildcard_\.' "$TRANCO" || true)
check "  placeholder count stays under the ceiling (<=20)" "yes" \
  "$([ "$PLACEHOLDER_N" -le 20 ] && echo yes || echo no)"

# --- rank lookup ------------------------------------------------------------
# THE SHIPPED PROGRAM, EXTRACTED -- NOT A COPY OF IT. This used to be a
# hand-maintained duplicate of the build's awk, and on 2026-09-01 that was shown
# to be worth nothing: reverting the fix in build-blocklist.sh left every
# behavioural check here passing, because they were exercising the copy. Only
# the grep-the-shipped-script assertion noticed. A duplicate tests the duplicate.
#
# If the anchors below ever stop matching, RANK_AWK is empty and everything
# built on it fails loudly rather than silently testing nothing.
RANK_AWK=$(awk '
  /LC_ALL=C awk -v refuse=/            { grab = 1; next }
  grab && /TRANCO_FILE.*merged\.hosts/ { grab = 0 }
  grab                                 { print }
' "$SCRIPT")
check "extracted the shipped rank-lookup program" "yes" \
  "$([ -n "$RANK_AWK" ] && echo yes || echo no)"
lookup() {
  LC_ALL=C awk "$RANK_AWK" "$TRANCO" "$1" | sort -n
}
printf 'google.com\nevil-not-popular.example\ngoogll.store\n' > "$WORK/merged"
OUT=$(lookup "$WORK/merged")
check "finds a popular host with its rank" "1	google.com" "$(echo "$OUT" | sed -n 1p)"
check "  ignores hosts absent from the reference" "2" "$(echo "$OUT" | wc -l)"
check "  comment lines never become ranks" "no" \
  "$(echo "$OUT" | grep -q '^0' && echo yes || echo no)"

# --- PLACEHOLDER REGRESSION -------------------------------------------------
# The case that was live until 2026-09-01: a source emitting Tranco's own
# placeholder string. It survives filter_acceptable, and at rank 1846 it landed
# in the REFUSE band, so it would have stopped the build rather than been
# reported. Both rows are asserted, one either side of the 10000 boundary.
printf '_wildcard_.ph\n_wildcard_.com.ph\n' > "$WORK/placeholders"
check "an injected placeholder produces no hit at all" "0" \
  "$(lookup "$WORK/placeholders" | grep -c . || true)"
check "  and the shipped build skips it before keying" "yes" \
  "$(grep -qF 'if ($0 ~ /^_wildcard_\./) next' "$SCRIPT" && echo yes || echo no)"
# A placeholder row is COUNTED and only then skipped. Strip it instead and
# every rank below shifts by one, so every adjudication recorded against a rank
# silently means a different host.
#
# ASSERTED AGAINST THE SNAPSHOT ITSELF, NOT AGAINST REMEMBERED NUMBERS. The
# first version of this check pinned four literal ranks and died the same week,
# when patanyx-tranco.timer installed a new snapshot and the hosts moved -- the
# identical fault as the placeholder-count pin this file replaced, committed by
# the same hand that replaced it. What holds across refreshes is the relation:
# the host on the data line after a placeholder must receive that line's own
# number as its rank.
DATA="$WORK/tranco.data"
grep -vE '^\s*(#|$)' "$TRANCO" > "$DATA"
shift_ok=yes
checked=0
for ln in $(grep -n '^_wildcard_\.' "$DATA" | cut -d: -f1); do
  next=$((ln + 1))
  host=$(sed -n "${next}p" "$DATA")
  [ -n "$host" ] || continue
  printf '%s\n' "$host" > "$WORK/one"
  got=$(lookup "$WORK/one" | cut -f1)
  checked=$((checked + 1))
  [ "$got" = "$next" ] || shift_ok="no ($host ranked $got, should be $next)"
done
check "  a host below a placeholder keeps its own line number as rank" "yes" "$shift_ok"
check "    and at least one placeholder was actually exercised" "yes" \
  "$([ "$checked" -ge 1 ] && echo yes || echo no)"

# --- confirmed-block subtraction --------------------------------------------
subtract() {
  LC_ALL=C awk -F'\t' -v first="$1" 'FILENAME == first { ok[$0]; next } !($2 in ok)' "$1" "$2"
}
printf 'googll.store\n' > "$WORK/confirm"
echo "$OUT" > "$WORK/hits"
REMAIN=$(subtract "$WORK/confirm" "$WORK/hits")
check "confirmed host is dropped from the hits" "no" \
  "$(echo "$REMAIN" | grep -q 'googll.store' && echo yes || echo no)"
check "  unconfirmed host survives" "yes" \
  "$(echo "$REMAIN" | grep -q 'google.com' && echo yes || echo no)"

# --- EMPTY-LOOKUP REGRESSION ------------------------------------------------
# The `NR == FNR` idiom silently inverts when the first file is EMPTY: awk never
# reads a record from it, so NR and FNR stay equal into the second file and
# every line is absorbed into the lookup array instead of printed. In the build
# that meant an empty confirm list would empty popular.hits -- the tripwire
# reporting all-clear BECAUSE nothing had been adjudicated. Caught 2026-08-10.
: > "$WORK/empty-confirm"
KEPT=$(subtract "$WORK/empty-confirm" "$WORK/hits" | wc -l)
check "empty confirm list keeps every hit (not zero)" "2" "$KEPT"
check "  the shipped build guards on FILENAME, not NR==FNR" "yes" \
  "$(grep -q 'FILENAME == first { ok\[\$0\]; next }' "$SCRIPT" && echo yes || echo no)"
check "  and no bare NR==FNR lookup remains in the tripwire block" "0" \
  "$(awk '/--- popularity tripwire ---/,/^fi$/' "$SCRIPT" | grep -c 'NR == FNR { ok' || true)"

# --- the shipped confirm file -----------------------------------------------
parse_confirm() {
  sed -E 's/#.*$//; s/[[:space:]]+//g' "$CONFIRM" | grep -vE '^$' | tr 'A-Z' 'a-z' | sort -u
}
# 5 as of the 2026-08-13 warn-band review (catched.com, bc.game); when an
# adjudication adds or removes an entry, this pin moves with it.
# 15 as of 2026-09-01: the nine ShadowWhisperer onboarding confirmations added
# to the six already here. Two clusters and three individual calls; the
# clustering evidence is in the confirm file, and it is circumstantial by
# construction -- shared infrastructure between disposable domains, not an
# observed phishing page.
# 17 as of 2026-09-02: the fifteen above plus workdeadlinededicate.com and
# kettledroopingcontinuation.com, armed by that morning's Tranco snapshot and
# confirmed malicious on independent multi-vendor classification.
check "confirm file parses to 17 hosts" "17" "$(parse_confirm | wc -l)"
check "  googll.store is among them" "yes" \
  "$(parse_confirm | grep -qx 'googll.store' && echo yes || echo no)"
check "  multi-line comment blocks do not leak entries" "0" \
  "$(parse_confirm | grep -cvE '^[a-z0-9.-]+\.[a-z0-9-]+$' || true)"

# A host must never be in BOTH files -- that is a contradiction, and whichever
# won would be an accident of ordering.
check "no host is both allowlisted and confirmed" "0" \
  "$(comm -12 <(parse_confirm) \
       <(sed -E 's/#.*$//; s/[[:space:]]+//g' scripts/blocklist-allow.txt \
         | grep -vE '^$' | tr 'A-Z' 'a-z' | sort -u) | wc -l)"

# --- missing snapshot: soft by default, strict when required -----------------
# Moving the snapshot out of the repo means a fresh box has none. Hourly runs
# must degrade; a run that produces a SHIPPED list must not.
check "missing-snapshot branch honours BLOCKLIST_REQUIRE_TRIPWIRE" "yes" \
  "$(awk '/if \[ ! -f "\$TRANCO_FILE" \]/,/^  say "    regenerate/' "$SCRIPT" \
     | grep -q 'BLOCKLIST_REQUIRE_TRIPWIRE' && echo yes || echo no)"
check "  and exits when it is set" "yes" \
  "$(awk '/BLOCKLIST_REQUIRE_TRIPWIRE:-0/,/fi$/' "$SCRIPT" | grep -q 'exit 1' && echo yes || echo no)"

# --- bare public suffixes ---------------------------------------------------
# A host that IS a public suffix is the boundary every tenant sits under, so an
# entry naming one blocks the whole platform. Twenty-five AWS S3 regional
# endpoints shipped this way before 2026-08-10.
PSLF=crates/app/src/public_suffix_list.txt
check "S3 regional endpoints are exact PSL rules" "yes" \
  "$(grep -qx 's3.eu-west-1.amazonaws.com' "$PSLF" && echo yes || echo no)"
check "  and none is in the shipped list" "0" \
  "$(grep -cxE 's3[.-][a-z0-9.-]*amazonaws\.com' crates/app/src/blocklist.txt || true)"
check "  nor are the object-storage boundaries" "0" \
  "$(grep -cxE 'cf-ipfs\.com|cloudflare-ipfs\.com|storage\.yandexcloud\.net' crates/app/src/blocklist.txt || true)"
# THE OVER-CORRECTION GUARD. Honouring `*.` rules as well dropped fifty
# ec2-<ip>.compute-1.amazonaws.com hosts, each of which names ONE instance and
# is exactly the targeted protection this list exists for.
check "per-tenant EC2 hostnames are STILL blocked" "yes" \
  "$(test "$(grep -c 'compute-1\.amazonaws\.com' crates/app/src/blocklist.txt)" -gt 10 && echo yes || echo no)"
check "  and the filter uses exact rules only" "yes" \
  "$(grep -q 'EXACT rules only. Wildcards are deliberately NOT applied' "$SCRIPT" && echo yes || echo no)"

# --- thresholds still wired -------------------------------------------------
check "refuse threshold is 10000" "yes" \
  "$(grep -qx 'TRANCO_REFUSE_RANK=10000' "$SCRIPT" && echo yes || echo no)"
check "the build exits on a refuse hit" "yes" \
  "$(awk '/if \[ "\$REFUSE_N" -gt 0 \]/,/^  fi$/' "$SCRIPT" | grep -q 'exit 1' && echo yes || echo no)"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
