#!/usr/bin/env bash
# Regenerates the shipped ad and tracker rule lists from ShadowWhisperer.
#
# WHAT THIS FEEDS. crates/app/src/adlist-ads.txt and adlist-tracking.txt are
# compiled into TWO separate WebKit content filters on Unix and one merged
# HostSet membership index on Windows. Two filters, not one, because WebKit
# refuses a compiled list over 150,000 rules (measured on this machine,
# 2026-09-01: 150k compiles, 200k fails with "Too many rules in JSON array")
# and the combined list already sits at ~144k. Split, each half has room to
# grow for years.
#
# MANUAL, NOT HOURLY. Ad infrastructure churns in weeks, not hours, and this
# output is checked into the repository and ships with a release -- it is not
# on the signed hourly channel the malicious blocklist uses. Run it when
# refreshing the lists, review the diff like any other source change.
#
# NO TRANCO TRIPWIRE, deliberately, where build-blocklist.sh has one. For a
# NAVIGATION blocklist, popularity is evidence of a feed error. For an ad
# blocker, popularity is the TARGET: doubleclick.net is popular precisely
# because every page calls it. The screens that do apply: the PSL (a bare
# public suffix in a request filter would drop every site hosted under it),
# the label caps, and the first-party allowlist.
#
# Run:  ./scripts/build-adlist.sh
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

OUT_ADS=crates/app/src/adlist-ads.txt
OUT_TRACKING=crates/app/src/adlist-tracking.txt
PSL_FILE=crates/app/src/public_suffix_list.txt
ALLOW_FILE=scripts/adlist-allow.txt
EXTRA_FILE=scripts/adlist-extra.txt
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

ADS_URL="https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Ads"
TRACKING_URL="https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking"

# Same fetch discipline as build-blocklist.sh: HTTPS only including redirects,
# bounded size, retries for a manual run that should not fail on one 5xx.
CURL="curl -fsSL --proto =https --proto-redir =https --retry 3 --retry-all-errors --connect-timeout 15"

# Floors, not targets. Measured 2026-09-01: Ads 27,608 hosts, Tracking 116,392.
ADS_FLOOR=20000
TRACKING_FLOOR=80000

# The WebKit ceiling, asserted per list at the end. Each list compiles alone,
# so each gets the full budget; the margin below the measured limit is why the
# split exists at all. Cosmetic selectors do NOT count against this: they ship
# as a user stylesheet (privacy::cosmetic_css), never as filter rules. The
# small reserve in the check below is headroom, not an accounting of them.
WEBKIT_RULE_CEILING=150000

say() { printf '%s\n' "$*" >&2; }

last_field() { awk 'NF { print $NF }'; }
strip_to_host() {
  sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[/?\#].*$##; s#^[^@]*@##; s#:[0-9]+$##; s#:+$##'
}

# The same self-declared count cross-check build-blocklist.sh runs on these
# files' siblings: written by the same generator as the data, so it catches
# truncation in transit, not a bad list. Warns and proceeds; floors refuse.
declared_count() {
  sed -n 's/^#[[:space:]]*Domains:[[:space:]]*//p' "$1" | head -1 | tr -cd '0-9'
}

fetch_and_normalise() {
  local label="$1" url="$2" out="$3"
  say "fetching ShadowWhisperer ($label) ..."
  $CURL --max-time 120 --max-filesize 20000000 -o "$WORK/$label.raw" "$url" || {
    say "FAIL: could not fetch $url"
    say "  outputs unchanged."
    exit 1
  }
  grep -vE '^\s*(#|$)' "$WORK/$label.raw" | tr -d '\r' | last_field | strip_to_host \
    | tr 'A-Z' 'a-z' | sort -u > "$out"
  local parsed declared
  parsed=$(wc -l < "$out")
  declared="$(declared_count "$WORK/$label.raw")"
  if [ -n "$declared" ] && [ "$declared" != "$parsed" ]; then
    say "  WARNING: $label declares $declared hosts, parsed $parsed; proceeding"
  fi
}

fetch_and_normalise Ads "$ADS_URL" "$WORK/ads.hosts"
fetch_and_normalise Tracking "$TRACKING_URL" "$WORK/tracking.hosts"

ADS_N=$(wc -l < "$WORK/ads.hosts")
TRACKING_N=$(wc -l < "$WORK/tracking.hosts")
say "  Ads      : $ADS_N hosts"
say "  Tracking : $TRACKING_N hosts"
[ "$ADS_N" -ge "$ADS_FLOOR" ] || { say "FAIL: Ads $ADS_N under floor $ADS_FLOOR."; exit 1; }
[ "$TRACKING_N" -ge "$TRACKING_FLOOR" ] || { say "FAIL: Tracking $TRACKING_N under floor $TRACKING_FLOOR."; exit 1; }

# --- acceptance -------------------------------------------------------------
#
# The blocklist's filter_acceptable, minus nothing: ASCII shape, label caps,
# no bare TLDs, no bare public suffixes. A bare `com` in a REQUEST filter is
# even worse than in a navigation list -- the compiled regex matches every
# https request on the internet and the page never loads anything again.
grep -vE '^\s*(//|$)' "$PSL_FILE" | grep -vE '^[*!]' | tr 'A-Z' 'a-z' | sort -u > "$WORK/psl.exact"

# PROTECTED_SUFFIXES, EXTRACTED FROM THE RUST SOURCE rather than copied here.
#
# WHY EXTRACTED. A second hand-maintained copy of this list is a second thing
# that can silently disagree with the first, and the disagreement is invisible
# until it ships. Parsing the array out of hostrules.rs means the pipeline
# screens on exactly what the runtime screens on, and adding a suffix there
# tightens this automatically.
#
# WHY IT IS NEEDED AT ALL, given the PSL screen directly above. Red-team pass
# 2026-09-01 found the PSL does NOT cover the whole set: 7 of the 30 protected
# suffixes are absent from the shipped PSL, including `amazonaws.com` and
# `windows.net`. A bare `amazonaws.com` reaching a compiled url-filter would
# block every request to every S3 bucket -- and this repository has already
# shipped 25 AWS regional endpoints once (see the blocklist's PSL note), so
# this is a demonstrated failure mode, not a hypothetical one. Verified: the
# entries below survived the PSL-only screen before this block existed.
sed -n '/^pub const PROTECTED_SUFFIXES/,/^\];/p' crates/app/src/platform/hostrules.rs \
  | grep -oE '"[a-z0-9.-]+"' | tr -d '"' | tr 'A-Z' 'a-z' | sort -u > "$WORK/protected.exact"
PROTECTED_N=$(wc -l < "$WORK/protected.exact")
# A parse that silently returned nothing would disable the screen it exists to
# provide, which is the failure this whole file is written against.
if [ "$PROTECTED_N" -lt 20 ]; then
  say "FAIL: parsed only $PROTECTED_N protected suffixes from hostrules.rs;"
  say "  the array moved or changed shape. Outputs unchanged."
  exit 1
fi

# THE ACCEPTANCE PREDICATE, kept deliberately in step with
# platform::hostrules::acceptable -- the gate the runtime HostSet applies.
#
# The two must agree or the platforms diverge: the Unix side compiles
# `blocked_hosts` (the raw Vec) into WebKit rules, while Windows answers from
# the HostSet index, which drops anything `acceptable` rejects. A host the
# pipeline ships but the index refuses is therefore blocked on Linux and NOT
# blocked on Windows -- silently, on one platform only. Screening here means
# what ships is what both honour. A Rust test re-asserts the agreement against
# the checked-in files, because a comment cannot enforce it.
filter_acceptable() {
  awk -v pslfile="$WORK/psl.exact" -v protfile="$WORK/protected.exact" '
    BEGIN {
      while ((getline line < pslfile) > 0) psl[line] = 1; close(pslfile)
      while ((getline line < protfile) > 0) prot[line] = 1; close(protfile)
    }
    !/^[a-z0-9._-]+$/          { next }   # non-host shapes die here
    !/\./                      { next }   # bare TLD
    /^\./                      { next }   # leading dot: breaks boundary maths
    /\.$/                      { next }   # trailing dot: same
    /\.\./                     { next }   # empty label
    (length($0) > 253)         { next }   # longer than any real host
    ($0 in psl)                { next }   # bare public suffix
    ($0 in prot)               { next }   # bare shared-platform suffix
    {
      n = split($0, parts, ".")
      if (n > 16) next
      for (i = 1; i <= n; i++) if (length(parts[i]) > 63) next
      print
    }
  '
}

# --- allow and extra --------------------------------------------------------
parse_hostfile() {
  sed -E 's/#.*$//; s/[[:space:]]+//g' "$1" 2>/dev/null \
    | grep -vE '^$' | tr 'A-Z' 'a-z' | sort -u
}
parse_hostfile "$ALLOW_FILE" > "$WORK/allow.hosts" || : > "$WORK/allow.hosts"
parse_hostfile "$EXTRA_FILE" > "$WORK/extra.hosts" || : > "$WORK/extra.hosts"

# Extras join the ADS list: every current extra is ad/SDK infrastructure, and
# a single home means the Windows merge and the Unix filters agree on where
# additions live.
finish_list() {
  # $2 may be absent: tracking gets no extras. `${2:-}` under `set -u`.
  local in="$1" extras="${2:-}"
  if [ -n "$extras" ]; then
    cat "$in" "$extras"
  else
    cat "$in"
  fi | sort -u | filter_acceptable | comm -23 - "$WORK/allow.hosts"
}
finish_list "$WORK/ads.hosts" "$WORK/extra.hosts" > "$WORK/ads.final"
finish_list "$WORK/tracking.hosts" > "$WORK/tracking.final"

ADS_FINAL=$(wc -l < "$WORK/ads.final")
TRACKING_FINAL=$(wc -l < "$WORK/tracking.final")

# The ceiling check, with a small reserve so a future in-filter rule (an
# ignore-previous-rules exception, say) cannot be the thing that tips it over.
if [ "$((ADS_FINAL + 8))" -ge "$WEBKIT_RULE_CEILING" ] \
  || [ "$TRACKING_FINAL" -ge "$WEBKIT_RULE_CEILING" ]; then
  say "FAIL: a list has outgrown WebKit's $WEBKIT_RULE_CEILING-rule ceiling"
  say "  (ads $ADS_FINAL + 8 cosmetic, tracking $TRACKING_FINAL)."
  say "  Split it further before shipping; outputs unchanged."
  exit 1
fi

TODAY=$(date -u +%Y-%m-%d)
write_out() {
  local final="$1" out="$2" label="$3" count="$4"
  cat > "$WORK/out.txt" <<HEADER
# PATANYX ad and tracker rules: $label -- $count hosts.
# Regenerate with scripts/build-adlist.sh. Retrieved $TODAY.
#
# Source: ShadowWhisperer -- https://github.com/ShadowWhisperer/BlockLists --
# Lists/$label. The Unlicense (public domain dedication); the curator states
# "I will not merge other lists", so the dedication is his own to give --
# the same test every source in blocklist.txt has to pass.
#
# Requests to these hosts and their subdomains are dropped when the Ads &
# Tracker Blocker is on. This list never blocks NAVIGATION: typing one of
# these hosts into the address bar still works, which is why entries here
# need no appeal path and the popularity tripwire does not apply.
#
# Screened against the Public Suffix List (a bare suffix would filter every
# site hosted under it), first-party hosts removed per
# scripts/adlist-allow.txt, additions from scripts/adlist-extra.txt.
HEADER
  cat "$final" >> "$WORK/out.txt"
  # Same atomic staging as build-blocklist.sh: rename within one directory.
  local tmp="$out.tmp.$$"
  cp "$WORK/out.txt" "$tmp"
  mv "$tmp" "$out"
  say "wrote $out ($count hosts)"
}
write_out "$WORK/ads.final" "$OUT_ADS" "Ads" "$ADS_FINAL"
write_out "$WORK/tracking.final" "$OUT_TRACKING" "Tracking" "$TRACKING_FINAL"

say ""
say "  ads      : $ADS_FINAL (ceiling $((WEBKIT_RULE_CEILING - 8)))"
say "  tracking : $TRACKING_FINAL (ceiling $WEBKIT_RULE_CEILING)"
say "  allow    : $(wc -l < "$WORK/allow.hosts") screened out"
say "  extra    : $(wc -l < "$WORK/extra.hosts") added"
say ""
say "Next: cargo test -p patanyx-app  -- the bundled-rules tests re-parse both"
say "      files and re-assert the ceiling and the never-block screens."
