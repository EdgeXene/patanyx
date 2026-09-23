#!/usr/bin/env bash
# Tests for the ShadowWhisperer source in build-blocklist.sh.
#
# THE PROPERTY THAT MATTERS MOST is the first one: with the flag off, this
# source must contribute NOTHING -- no fetch, no merge entry, no snapshot and
# no header text. That is not a tidiness preference. build-blocklist.sh feeds
# an hourly, unattended publisher that signs and ships to every install, so a
# source that leaked into a disabled build would push ~51k unreviewed hosts to
# the fleet with nobody having decided to. Every assertion below about the
# disabled path is guarding that.
#
# The second concern is the two lists being genuinely two feeds. Lists/Malware
# commits several times a day and Lists/Scam every two to seven days; a single
# averaged threshold would report a healthy age for a frozen Malware list as
# long as Scam kept moving.
#
# Run:  ./scripts/test-shadowwhisperer.sh
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
has() { if grep -qF "$2" "$SCRIPT"; then ok "$1"; else bad "$1"; fi; }

echo "shadowwhisperer source"

# --- the disabled path ------------------------------------------------------
# The default is ON as of 2026-09-01. This assertion did not become pointless
# when it flipped -- it changed which accident it catches. Before, it guarded
# against a source shipping to the fleet that nobody had decided to enable.
# Now it guards against the decision being reversed silently: the hourly
# publisher would go on signing and shipping, just without a source the
# adjudications, thresholds and NOTICE entry all assume is present.
check "flag defaults to ON" "yes" \
  "$(grep -qF 'ENABLE_SW="${BLOCKLIST_ENABLE_SHADOWWHISPERER:-1}"' "$SCRIPT" && echo yes || echo no)"

# The empty files are created unconditionally so the merge needs no second copy
# of the enable test -- a second test is a second thing that can drift.
has "  empty sw.hosts is created unconditionally" ': > "$WORK/sw.hosts"'
has "  the merge reads sw.hosts" '"$WORK/archive.hosts" "$WORK/sw.hosts" | sort -u'

# THE BYTE-IDENTITY GUARD. ${SW_SOURCE_BLOCK} must sit on the SAME line as the
# text that follows it. On its own line, an empty value would still emit a
# newline, so a disabled build would differ from a pre-ShadowWhisperer build by
# one blank line in the shipped header -- a diff nobody would understand a
# month later, in a file whose whole job is to be reviewable in a diff.
check "  header block cannot leave a blank line when empty" "yes" \
  "$(grep -qF '${SW_SOURCE_BLOCK}${CERTPL_SOURCE_BLOCK}# WHY THESE SOURCES.' "$SCRIPT" && echo yes || echo no)"
check "  and it carries a literal trailing newline, not \$( ) which strips it" "no" \
  "$(grep -qE 'SW_SOURCE_BLOCK="\$\(' "$SCRIPT" && echo yes || echo no)"

# Snapshots must not be written for a disabled source: an empty
# ShadowWhisperer.hosts would tell review-blocklist-fps.py that a feed reports
# nothing, which reads as "uncorroborated" for every host in the list rather
# than "this feed was not consulted".
has "  snapshots are gated on the flag" 'snapshot_pairs+=("ShadowWhisperer.Scam:sw-scam"'

# --- two feeds, not one -----------------------------------------------------
for v in SW_SCAM_FLOOR SW_MALWARE_FLOOR SW_SCAM_STALE_HOURS SW_MALWARE_STALE_HOURS \
         SW_SCAM_DEAD_HOURS SW_MALWARE_DEAD_HOURS; do
  check "  $v is set" "yes" "$(grep -qE "^$v=[0-9]+$" "$SCRIPT" && echo yes || echo no)"
done

SCAM_STALE=$(sed -n 's/^SW_SCAM_STALE_HOURS=//p' "$SCRIPT")
MAL_STALE=$(sed -n 's/^SW_MALWARE_STALE_HOURS=//p' "$SCRIPT")
# Scam was EIGHT DAYS unchanged on the day it was wired in, and gaps of two to
# seven days are normal for it. A threshold at or below Malware's would have
# paged on arrival and gone on paging -- the alert fatigue Phishing.Database is
# already producing, reproduced deliberately.
check "  Scam tolerates a longer silence than Malware" "yes" \
  "$([ "$SCAM_STALE" -gt "$MAL_STALE" ] && echo yes || echo no)"
check "  Scam's threshold clears its widest observed gap (7d)" "yes" \
  "$([ "$SCAM_STALE" -gt 168 ] && echo yes || echo no)"
has "  the two lists are tracked as separate sources" '"ShadowWhisperer.Scam:$SW_SCAM_SHA'

# --- the declared-count cross-check ----------------------------------------
# Lifted from the shipped script at run time rather than copied, so this cannot
# pass against a function the build no longer has.
eval "$(sed -n '/^sw_declared_count() {$/,/^}$/p' "$SCRIPT")"
printf '#\n#    File: Malware\n# Domains: 43,848\n# Updated: 9/1/2026\n#\nevil.example\n' > "$WORK/hdr.txt"
check "declared count strips the thousands separator" "43848" "$(sw_declared_count "$WORK/hdr.txt")"
printf 'evil.example\n' > "$WORK/nohdr.txt"
check "  a file with no declaration yields empty, not zero" "" "$(sw_declared_count "$WORK/nohdr.txt")"

# --- normalisation ----------------------------------------------------------
# The ten-line comment header must not survive, and neither must case or
# duplicates. An underscore host is left alone here on purpose: rejecting
# unusable entries is filter_acceptable's job, not this pipeline's.
last_field() { awk 'NF { print $NF }'; }
eval "$(sed -n '/^strip_to_host() {$/,/^}$/p' "$SCRIPT")"
printf '#\n#    File: Scam\n# Domains: 3\n#\n#\n#\n#\n#\n#\n#\nEVIL.example\nevil.example\nhttps://x.example/path\n\n' \
  > "$WORK/raw.txt"
grep -vE '^\s*(#|$)' "$WORK/raw.txt" | tr -d '\r' | last_field | strip_to_host \
  | tr 'A-Z' 'a-z' | sort -u > "$WORK/out.hosts"
check "normalisation drops comments, lowercases and dedups" "2" "$(wc -l < "$WORK/out.hosts")"
check "  the URL row became a bare host" "yes" \
  "$(grep -qx 'x.example' "$WORK/out.hosts" && echo yes || echo no)"
check "  the duplicate collapsed" "1" "$(grep -cx 'evil.example' "$WORK/out.hosts")"

# --- floors -----------------------------------------------------------------
SCAM_FLOOR=$(sed -n 's/^SW_SCAM_FLOOR=//p' "$SCRIPT")
MAL_FLOOR=$(sed -n 's/^SW_MALWARE_FLOOR=//p' "$SCRIPT")
# Measured 2026-09-01: Scam 7,309 and Malware 43,848. Floors have to sit clear
# of ordinary churn below those and well above zero, or a truncated fetch that
# still returns HTTP 200 would ship as a real list.
check "Scam floor is below the measured size and above zero" "yes" \
  "$([ "$SCAM_FLOOR" -lt 7309 ] && [ "$SCAM_FLOOR" -gt 0 ] && echo yes || echo no)"
check "  Malware floor is below the measured size and above zero" "yes" \
  "$([ "$MAL_FLOOR" -lt 43848 ] && [ "$MAL_FLOOR" -gt 0 ] && echo yes || echo no)"
check "  each list is floored separately" "yes" \
  "$(grep -qF 'ShadowWhisperer Scam returned' "$SCRIPT" \
     && grep -qF 'ShadowWhisperer Malware returned' "$SCRIPT" && echo yes || echo no)"

# --- the adjudications this source required --------------------------------
# Its Malware list brought eighteen top-10k hosts to the tripwire. If any one
# of them loses its ruling the build stops, so the split is asserted here
# rather than rediscovered by a refusal at 03:00.
parse() { sed -E 's/#.*$//; s/[[:space:]]+//g' "$1" | grep -vE '^$' | tr 'A-Z' 'a-z' | sort -u; }
for h in bbtec.net tencentcs.com guard.io intensedebate.com localto.net \
         temporary.site clickadu.net hentaiheroes.com ztomy.com; do
  check "  $h is allowlisted" "yes" \
    "$(parse scripts/blocklist-allow.txt | grep -qx "$h" && echo yes || echo no)"
done
for h in acquaintjokinglyscoring.com bondeddarkenedswerve.com \
         buffermotivatorsuffice.com decafeligiblyhad.com ey43.com obqj2.com \
         b7510.com bangcdn.net 13o.net; do
  check "  $h is confirmed" "yes" \
    "$(parse scripts/blocklist-confirm.txt | grep -qx "$h" && echo yes || echo no)"
done
# A host in BOTH files is a contradiction the build would resolve silently by
# allowlisting it, because the allowlist is subtracted last.
check "no host is in both files" "0" \
  "$(comm -12 <(parse scripts/blocklist-allow.txt) <(parse scripts/blocklist-confirm.txt) | wc -l)"

echo ""
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
