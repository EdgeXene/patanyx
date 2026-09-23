#!/usr/bin/env bash
# Tests for the CERT Polska (CSIRT NASK) warning-list source in
# build-blocklist.sh.
#
# THE PROPERTY THAT MATTERS MOST: with the flag off, this source contributes
# NOTHING -- no fetch, no merge entry, no snapshot, no freshness entry and no
# header text. build-blocklist.sh feeds an hourly, unattended publisher that
# signs and ships to every install; measured 2026-09-11 this feed is +21% on
# the published list, a swing the delta gate refuses until a person runs it
# once with BLOCKLIST_EXPECT_ENTRIES. A source that leaked into a disabled
# build would push ~134k unreviewed hosts to the fleet with nobody deciding.
#
# The second concern is attribution. Permission to redistribute rests on a
# written grant that asked for two things: say the data comes from CERT Polska,
# and link https://cert.pl/lista-ostrzezen/. Both must be present in NOTICE and
# in the header the build writes, and they must never drift apart.
#
# Run:  ./scripts/test-certpl.sh
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

SCRIPT=scripts/build-blocklist.sh
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 -- expected [$2], got [$3]"; fi; }
# `-e` so a pattern that begins with a dash is a pattern, not a grep option.
has() { if grep -qF -e "$2" "$SCRIPT"; then ok "$1"; else bad "$1"; fi; }

echo "cert.pl source"

# --- the disabled path ------------------------------------------------------
check "flag defaults to OFF" "yes" \
  "$(grep -qF 'ENABLE_CERTPL="${BLOCKLIST_ENABLE_CERTPL:-0}"' "$SCRIPT" && echo yes || echo no)"
has "  empty certpl.hosts is created unconditionally" ': > "$WORK/certpl.hosts"'
has "  the merge reads certpl.hosts" '"$WORK/sw.hosts" "$WORK/certpl.hosts" | sort -u'
# One line per pattern: grep -F reads an embedded newline as two patterns, and
# a two-pattern match proves nothing about their adjacency.
check "  the fetch is gated on the flag" "yes" \
  "$(grep -A1 -F 'if [ "$ENABLE_CERTPL" = "1" ]; then' "$SCRIPT" | grep -qF 'fetching CERT.pl warning list' && echo yes || echo no)"
has "  the freshness entry is gated on the flag" 'src_args+=("CERT.pl:$CERTPL_SHA'
has "  snapshots are gated on the flag" 'snapshot_pairs+=("CERT.pl:certpl")'
# THE BYTE-IDENTITY GUARD, same reasoning as ShadowWhisperer's: the block sits
# on the same line as the text after it, so an empty value leaves no blank line.
check "  header block cannot leave a blank line when empty" "yes" \
  "$(grep -qF '${CERTPL_SOURCE_BLOCK}# WHY THESE SOURCES.' "$SCRIPT" && echo yes || echo no)"
check "  and it carries a literal trailing newline, not \$( ) which strips it" "no" \
  "$(grep -qE 'CERTPL_SOURCE_BLOCK="\$\(' "$SCRIPT" && echo yes || echo no)"
check "  the block is empty by default" "yes" \
  "$(grep -qF 'CERTPL_SOURCE_BLOCK=""' "$SCRIPT" && echo yes || echo no)"

# --- the feed itself --------------------------------------------------------
check "feed URL is the official v2 list over HTTPS" "yes" \
  "$(grep -qF 'CERTPL_URL="https://hole.cert.pl/domains/v2/domains.txt"' "$SCRIPT" && echo yes || echo no)"
has "  the fetch is size-bounded" '--max-filesize 20000000 -o "$WORK/certpl.txt"'
for v in CERTPL_FLOOR CERTPL_STALE_HOURS CERTPL_DEAD_HOURS; do
  check "  $v is set" "yes" "$(grep -qE "^$v=[0-9]+$" "$SCRIPT" && echo yes || echo no)"
done
FLOOR=$(sed -n 's/^CERTPL_FLOOR=//p' "$SCRIPT")
STALE=$(sed -n 's/^CERTPL_STALE_HOURS=//p' "$SCRIPT")
DEAD=$(sed -n 's/^CERTPL_DEAD_HOURS=//p' "$SCRIPT")
# Measured 2026-09-11: 136,279 hosts. Six-month expiry drifts the size; the
# floor has to sit under that drift and above what a truncated fetch returns.
check "floor is below the measured size and above zero" "yes" \
  "$([ "$FLOOR" -lt 136279 ] && [ "$FLOOR" -gt 0 ] && echo yes || echo no)"
check "  floor clears half the measured size" "yes" \
  "$([ "$FLOOR" -ge 60000 ] && echo yes || echo no)"
check "  stale fires before dead" "yes" "$([ "$STALE" -lt "$DEAD" ] && echo yes || echo no)"
has "  the floor is enforced" 'FAIL: CERT.pl returned $CERTPL_N hosts, floor is $CERTPL_FLOOR.'

# --- normalisation ----------------------------------------------------------
# The live feed is bare lowercase ASCII with punycode IDNs and no header, but
# the full pipeline runs on it anyway. Prove it copes with the shapes it could
# meet: comments, CRLF, case, a URL row, a duplicate, an IDN.
last_field() { awk 'NF { print $NF }'; }
eval "$(sed -n '/^strip_to_host() {$/,/^}$/p' "$SCRIPT")"
printf '# not expected, but harmless\r\nEVIL.example\r\nevil.example\nhttps://x.example/p\nxn--80ak6aa92e.example\n\n' \
  > "$WORK/raw.txt"
grep -vE '^\s*(#|$)' "$WORK/raw.txt" | tr -d '\r' | last_field | strip_to_host \
  | tr 'A-Z' 'a-z' | sort -u > "$WORK/out.hosts"
check "normalisation drops comments and CRLF, lowercases and dedups" "3" "$(wc -l < "$WORK/out.hosts")"
check "  the URL row became a bare host" "yes" "$(grep -qx 'x.example' "$WORK/out.hosts" && echo yes || echo no)"
check "  punycode survives untouched" "yes" "$(grep -qx 'xn--80ak6aa92e.example' "$WORK/out.hosts" && echo yes || echo no)"

# --- the committed dataset never carries the entries --------------------------
# The grant covers the signed update channel to PATANYX users. The committed
# list is compiled into releases and mirrored to a public repository, which the
# request to CERT Polska did not describe, so the entries must never be in it.
# Checked against HEAD, not the working file: the publisher's worktree is dirty
# with an enabled build by design, and that dirt is never committed.
check "the committed blocklist.txt carries no CERT Polska block" "0" \
  "$(git show HEAD:crates/app/src/blocklist.txt 2>/dev/null | grep -c 'CERT Polska' || true)"
check "  the published list marks itself publish-only" "yes" \
  "$(grep -qF 'PUBLISH-ONLY BUILD. This list was generated for the signed update channel.' "$SCRIPT" && echo yes || echo no)"
check "  NOTICE says the entries travel only in the signed update channel" "yes" \
  "$(grep -qF 'travel ONLY in that signed update channel' NOTICE && echo yes || echo no)"

# --- attribution, the condition of the grant --------------------------------
check "NOTICE names CERT Polska as the origin of the data" "yes" \
  "$(grep -qF 'The data comes from CERT Polska.' NOTICE && echo yes || echo no)"
check "  NOTICE links the source page CERT Polska asked for" "yes" \
  "$(grep -qF 'https://cert.pl/lista-ostrzezen/' NOTICE && echo yes || echo no)"
check "  the publisher's text header carries the same statement" "yes" \
  "$(grep -qF 'THE DATA COMES FROM CERT POLSKA.' "$SCRIPT" && echo yes || echo no)"
check "  the publisher's text header carries the same link" "yes" \
  "$(grep -qF 'https://cert.pl/lista-ostrzezen/ -- $CERTPL_N hosts' "$SCRIPT" && echo yes || echo no)"
check "  NOTICE records the date permission was granted" "yes" \
  "$(grep -qF '2026-09-11 CSIRT NASK / CERT Polska replied' NOTICE && echo yes || echo no)"
check "  NOTICE does not call the CERT entries bundled" "yes" \
  "$(grep -qF 'Warning List (NOT bundled;' NOTICE && echo yes || echo no)"
check "  NOTICE does not claim the update payload carries the attribution" "yes" \
  "$(grep -qF 'in the header of every list published' NOTICE && echo no || echo yes)"
# The header must not describe this source as permissively licensed: it is not.
check "  the header does not call every source permissively licensed" "yes" \
  "$(grep -qF 'either permissively' "$SCRIPT" && echo yes || echo no)"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
