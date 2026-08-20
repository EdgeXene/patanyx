#!/usr/bin/env bash
# Tests for the blocklist allowlist: parsing, exact-match semantics, and the
# ceiling guard.
#
# WHY THESE MATTER MORE THAN THEIR SIZE SUGGESTS. This is the only input to the
# pipeline whose purpose is to REMOVE protection. A parse bug that silently
# matched too much would disarm the browser quietly -- no failure, no count
# anomaly large enough to notice, just hosts that stop being blocked. The
# subdomain test below is the one that matters most: if allowlisting
# `example.com` ever started removing `phish.example.com`, an attacker would
# only need one legitimate-looking apex on the list to shelter every page
# beneath it.
#
# Run:  ./scripts/test-blocklist-allow.sh
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

ALLOW=scripts/blocklist-allow.txt
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 -- expected [$2], got [$3]"; fi; }

# The parse under test, lifted from build-blocklist.sh. Kept in step by the
# assertion further down that the real script still contains this exact line.
parse() {
  sed -E 's/#.*$//; s/[[:space:]]+//g' "$1" | grep -vE '^$' | tr 'A-Z' 'a-z' | sort -u
}

echo "blocklist allowlist"

# --- the shipped file -------------------------------------------------------
N=$(parse "$ALLOW" | wc -l)
# 45 as of the 2026-08-13 reviews: warn band (zeusx.com; qrco.de,
# storage.money, solscan.io; banrisul.com.br, ccm.net, altin.in) plus the
# refuse-band arrivals that held publishing (libero.it, tiscali.it,
# telegram.com, teletype.in). When an adjudication adds or removes an entry,
# this pin moves with it -- that is the pin working. 48 as of 2026-08-15:
# the two first-party hosts (patanyx.com, the launch page; patanyx.net).
# 49 as of 2026-08-17: wa.me, the tripwire's catch at the 0.9.63 rebuild.
# 64 as of 2026-08-19: the warn-band sweep at the 0.9.64 release, the first
# time that band was adjudicated as a set. Fifteen single-source reports of
# established apexes -- a regulated broker, a university, a package
# repository, a national carrier -- plus four hosting apexes where the
# abusive page is a subdomain and taking the apex takes every customer.
# Nothing from the refuse band; none of these ever held a build.
check "shipped allowlist parses to 64 hosts" "64" "$N"
# googll.store was allowlisted for one draft on the strength of its Tranco rank
# and then removed; see the note in the allowlist. Asserted explicitly because
# the mistake is an easy one to make twice.
check "  googll.store is NOT allowlisted" "no" \
  "$(parse "$ALLOW" | grep -qx 'googll.store' && echo yes || echo no)"
check "  no comment text survives the parse" "0" "$(parse "$ALLOW" | grep -c '#' || true)"
check "  no whitespace survives" "0" "$(parse "$ALLOW" | grep -cE '[[:space:]]' || true)"
check "  every entry looks like a host" "0" \
  "$(parse "$ALLOW" | grep -cvE '^[a-z0-9.-]+\.[a-z0-9-]+$' || true)"
check "  the audit's headline FP is present" "yes" \
  "$(parse "$ALLOW" | grep -qx 'nflxvideo.net' && echo yes || echo no)"
# PhishDestroy listed the Python Package Index as a threat. If this entry ever
# goes missing, pip breaks on every machine running PATANYX.
check "  pypi.org is allowlisted" "yes" \
  "$(parse "$ALLOW" | grep -qx 'pypi.org' && echo yes || echo no)"

# The parse in this test must be the one the script actually runs.
check "test parse matches the shipped script" "yes" \
  "$(grep -qF "sed -E 's/#.*\$//; s/[[:space:]]+//g'" scripts/build-blocklist.sh && echo yes || echo no)"

# --- exact-match semantics --------------------------------------------------
# THE CRITICAL PROPERTY. Allowlisting an apex must not shelter its subdomains.
printf 'gravatar.com\nphish.gravatar.com\nevil.example\nnflxvideo.net\n' | sort > "$WORK/merged"
printf 'gravatar.com\nnflxvideo.net\n' | sort > "$WORK/allow"
comm -23 "$WORK/merged" "$WORK/allow" > "$WORK/out"
check "apex is removed" "no" "$(grep -qx 'gravatar.com' "$WORK/out" && echo yes || echo no)"
check "SUBDOMAIN OF AN ALLOWLISTED APEX STAYS BLOCKED" "yes" \
  "$(grep -qx 'phish.gravatar.com' "$WORK/out" && echo yes || echo no)"
check "unrelated host untouched" "yes" \
  "$(grep -qx 'evil.example' "$WORK/out" && echo yes || echo no)"
check "removal count is exact" "2" "$(comm -12 "$WORK/merged" "$WORK/allow" | wc -l)"

# A host in the allowlist but NOT in the merge must not corrupt the output.
printf 'notpresent.example\n' > "$WORK/allow2"
comm -23 "$WORK/merged" <(sort "$WORK/allow2") > "$WORK/out2"
check "allowlist entry absent from merge is a no-op" "4" "$(wc -l < "$WORK/out2")"

# --- ceiling guard ----------------------------------------------------------
# Exercised against the real script so the test cannot pass on a stale copy of
# the rule.
BIG=$WORK/big-allow.txt
seq 1 101 | sed 's/$/.example/' > "$BIG"
OUT=$(
  bash -c '
    set -euo pipefail
    say() { printf "%s\n" "$*" >&2; }
    OUT=/dev/null
    WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
    ALLOW_FILE='"$BIG"'
    # The guard reads a count the real script computes further up; recreate it
    # here so the extracted block runs against a realistic environment rather
    # than tripping over an unset variable and passing for the wrong reason.
    ALLOW_N=$(wc -l < "$ALLOW_FILE")
    '"$(sed -n '/^ALLOW_CEILING=100$/,/^fi$/p' scripts/build-blocklist.sh)"'
    echo "not reached"
  ' 2>&1 || true
)
check "ceiling refuses an oversized allowlist" "yes" \
  "$(echo "$OUT" | grep -q 'ceiling is 100' && echo yes || echo no)"
check "  and does not proceed" "no" \
  "$(echo "$OUT" | grep -q 'not reached' && echo yes || echo no)"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
