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
# Tranco itself publishes four `_wildcard_` placeholder rows. They are KEPT
# rather than stripped, because rank is line number and removing rows would
# shift every rank below them -- and they are inert regardless: an underscore
# cannot survive filter_acceptable, so no merged host can ever match one.
check "  every line is a bare host or a tranco placeholder" "0" \
  "$(grep -vE '^\s*(#|$)' "$TRANCO" | grep -v '^_wildcard_\.' \
     | grep -cvE '^[a-z0-9.-]+\.[a-z0-9-]+$' || true)"
check "  placeholders are exactly the 4 expected" "4" \
  "$(grep -c '^_wildcard_\.' "$TRANCO" || true)"

# --- rank lookup ------------------------------------------------------------
# The same awk the build runs: rank is line number among data lines.
lookup() {
  LC_ALL=C awk '
    NR == FNR { if ($0 ~ /^[[:space:]]*(#|$)/) next; rank[$0] = ++n; next }
    ($0 in rank) { printf "%d\t%s\n", rank[$0], $0 }
  ' "$TRANCO" "$1" | sort -n
}
printf 'google.com\nevil-not-popular.example\ngoogll.store\n' > "$WORK/merged"
OUT=$(lookup "$WORK/merged")
check "finds a popular host with its rank" "1	google.com" "$(echo "$OUT" | sed -n 1p)"
check "  ignores hosts absent from the reference" "2" "$(echo "$OUT" | wc -l)"
check "  comment lines never become ranks" "no" \
  "$(echo "$OUT" | grep -q '^0' && echo yes || echo no)"

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
check "confirm file parses to 6 hosts" "6" "$(parse_confirm | wc -l)"
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
