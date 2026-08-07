#!/usr/bin/env bash
# Regenerates crates/app/src/blocklist.txt from its upstream sources.
#
# WHY THIS EXISTS. blocklist.txt has told readers to "Regenerate with
# scripts/build-blocklist.sh" since it was written, and that script did not
# exist. The list was fetched by hand, once, and its header records a
# retrieval date rather than a command. A build-time snapshot of phishing
# domains decays -- the file's own header says so -- and a regeneration
# procedure that lives in somebody's memory decays faster.
#
# WHAT IT DOES NOT DO. It does not sign or publish anything. Publishing needs
# the offline publisher key and stays a deliberate act; see
# docs/update-channel.md. This produces the input to that, and prints the
# count that the signed manifest's `entries` field has to carry.
#
# Run:  ./scripts/build-blocklist.sh
set -euo pipefail
# Byte-order collation everywhere, or sort/comm/uniq produce locale-dependent
# output and the "same" input merges differently on two machines.
export LC_ALL=C
cd "$(dirname "$0")/.."

OUT=crates/app/src/blocklist.txt
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

# The Phishing-Database ORG repo, which is where maintenance happens now; the
# personal-account mirror this script originally pulled still serves but is
# one hop further from the source of truth.
PDB_URL="https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
PHISHUNT_URL="https://phishunt.io/feed.txt"

# HTTPS only, including across redirects; a bounded size so a runaway response
# cannot fill the disk; retries because this will run unattended and a single
# transient 5xx should not freeze the fleet's list for an hour.
CURL="curl -fsSL --proto =https --proto-redir =https --retry 3 --retry-all-errors --connect-timeout 15"

# Floors, not targets. A fetch that returns a truncated file still returns
# HTTP 200, and a list that silently halves is worse than one that is a week
# stale: the browser would go on reporting a healthy count while blocking a
# fraction of what it claims. Well below the real sizes (~390k and ~650) so
# ordinary churn never trips them, high enough that a truncation cannot pass.
PDB_FLOOR=300000
PHISHUNT_FLOOR=100

# Freshness ceilings, in hours. The floors above catch a TRUNCATED feed; these
# catch a FROZEN one, which the floors structurally cannot. Measured 2026-08-06:
# Phishing.Database had not moved in five days while phishunt.io churned hourly,
# and because the merged output kept changing size and sha256 every hour,
# nothing downstream had any reason to complain while 99.8% of the list sat
# still. Phishing.Database commits 2-4x/day normally, so three unchanged days is
# well outside cadence; phishunt.io updates hourly, so a full day unchanged
# means the feed is dead. Same spirit as the floors: clear of normal churn, low
# enough that a real freeze cannot hide for long.
PDB_STALE_HOURS=72
PHISHUNT_STALE_HOURS=26

say() { printf '%s\n' "$*" >&2; }

# EXACTLY what hashes_from_lines does: `str::trim` then
# `split_whitespace().last()`. Upstream ships hosts-file-shaped lines
# ("0.0.0.0 evil.example") and, less obviously, plain hosts with TRAILING
# SPACES -- eleven of them in the current pull. Rust trims those onto hosts
# already in the list and dedups; a plain `sort -u` here would keep them as
# distinct strings and report a count eleven higher than the binary's, which
# is the figure the signed manifest depends on.
last_field() { awk 'NF { print $NF }'; }

say "fetching Phishing.Database ..."
$CURL --max-time 180 --max-filesize 40000000 -o "$WORK/pdb.txt" "$PDB_URL" || {
  say "FAIL: could not fetch $PDB_URL"
  say "  $OUT is unchanged."
  exit 1
}

# The org publishes checksums in a SEPARATE repo (Phishing-Database/checksums;
# verified real and matching on 2026-08-01 -- an earlier probe at a guessed
# path 404'd and this was wrongly written off). Verify the fetch against it.
#
# A mismatch WARNS AND PROCEEDS rather than refusing: data and checksum land
# in different repos on different pushes, so an honest skew window exists
# every hour, and freezing the fleet's refresh on their publish timing would
# cost more than it protects. What a mismatch still buys is a LOUD line in
# the publisher journal; the count floors, the acceptance filter and the
# publisher's delta gate remain the guards that actually refuse.
PDB_SHA_URL="https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-domains-ACTIVE.txt.sha256"
# Hashed ONCE, here: the checksum verification below uses it, and so does the
# source-freshness tracking further down. `|| true` is load-bearing, not
# defensive clutter -- this script runs under `set -e`, so an unguarded
# command substitution that fails (no sha256sum on PATH, an unreadable temp
# file) would EXIT THE BUILD. Hashing is bookkeeping; bookkeeping must never be
# the thing that stops a blocklist from being published.
FETCHED_SHA="$(sha256sum "$WORK/pdb.txt" 2>/dev/null | awk '{print $1}')" || true

if $CURL --max-time 30 -o "$WORK/pdb.sha256" "$PDB_SHA_URL" 2>/dev/null; then
  PUBLISHED_SHA="$(awk '{print $1}' "$WORK/pdb.sha256")"
  if [ -n "$FETCHED_SHA" ] && [ "$PUBLISHED_SHA" = "$FETCHED_SHA" ]; then
    say "  checksum: verified against Phishing-Database/checksums"
  else
    say "  WARNING: fetched file does not match the published sha256"
    say "    published: $PUBLISHED_SHA"
    say "    fetched:   $FETCHED_SHA"
    say "    proceeding -- likely publish skew between their two repos; the"
    say "    floors and the publisher's gates still stand between this and a"
    say "    bad list."
  fi
else
  say "  checksum: unavailable (repo unreachable); floors still apply"
fi

say "fetching phishunt.io ..."
$CURL --max-time 60 --max-filesize 5000000 -o "$WORK/phishunt.txt" "$PHISHUNT_URL" || {
  say "FAIL: could not fetch $PHISHUNT_URL"
  say "  $OUT is unchanged."
  exit 1
}

# --- source freshness -------------------------------------------------------
#
# WHY LOCAL CONTENT TRACKING, and not the two obvious alternatives.
#
# There is no `Last-Modified` to consult: measured 2026-08-06, a HEAD against
# the raw host returns `etag`, `cache-control: max-age=300` and `source-age`,
# and nothing else. An upstream-specific API (the GitHub commits endpoint does
# work) would cover only sources that HAVE one -- phishunt.io does not -- while
# adding an external call that can fail mid-run.
#
# What actually matters is "these exact bytes have not changed in N days", so
# measure that directly: per source, remember the sha256 of the last content
# seen and the UTC time that exact content FIRST appeared. Hash differs, the
# content is alive and firstSeen resets. Hash matches, the age grows. Being
# keyed on CONTENT rather than on a URL or a header, this survives a source
# moving hosts entirely: same bytes, same hash, unbroken timeline.
#
# STALENESS WARNS AND PROCEEDS, the same shape as the checksum-mismatch path
# above and for the same reason: a stale list still beats no list, and the
# floors remain the guards that actually refuse. Every failure in here --
# unwritable state dir, corrupt state, missing python3 or sha256sum -- degrades
# to a warning line and returns success.
SOURCE_STATE_FILE="${BLOCKLIST_SOURCE_STATE_FILE:-/var/lib/patanyx-blocklist/source-state.json}"
SOURCE_STATUS_FILE="${BLOCKLIST_SOURCE_STATUS_FILE:-/var/lib/patanyx-blocklist/source-status.json}"

# A reader that cannot tell a fresh status file from last week's will report
# last week's as current. Every failure path below therefore REMOVES the status
# file rather than leaving a stale one behind, and the file itself carries a
# generatedAt that its consumers re-check.
invalidate_status() {
  rm -f "$SOURCE_STATUS_FILE" 2>/dev/null || true
}

check_source_freshness() {
  local phishunt_hash=""
  phishunt_hash="$(sha256sum "$WORK/phishunt.txt" 2>/dev/null | awk '{print $1}')" || true

  if [ -z "$FETCHED_SHA" ] || [ -z "$phishunt_hash" ]; then
    say "  freshness: could not hash a source; staleness tracking skipped"
    invalidate_status
    return 0
  fi

  local state_dir
  state_dir="$(dirname "$SOURCE_STATE_FILE")"
  # A developer running this script by hand usually cannot create /var/lib/...
  # That is fine: the tracking skips itself and the build carries on.
  if ! mkdir -p "$state_dir" 2>/dev/null; then
    say "  freshness: cannot create $state_dir; staleness tracking skipped"
    invalidate_status
    return 0
  fi

  local result=""
  if ! result="$(python3 - "$SOURCE_STATE_FILE" "$SOURCE_STATUS_FILE" \
      "Phishing.Database:$FETCHED_SHA:$((PDB_STALE_HOURS * 3600))" \
      "phishunt.io:$phishunt_hash:$((PHISHUNT_STALE_HOURS * 3600))" <<'PY'
import json, os, sys, tempfile, time

state_path, status_path = sys.argv[1], sys.argv[2]
now = int(time.time())

sources = []
for arg in sys.argv[3:]:
    name, sha, threshold = arg.rsplit(":", 2)
    sources.append((name, sha, int(threshold)))

# A missing or corrupt state file is not an error: treat it as "never seen",
# which resets every age to zero for one run and then self-heals.
try:
    with open(state_path, encoding="utf-8") as f:
        state = json.load(f)
    if not isinstance(state, dict):
        state = {}
except Exception:
    state = {}


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


lines = []
status = {"generatedAt": iso(now), "generatedAtEpoch": now, "sources": {}}
for name, sha, threshold in sources:
    entry = state.get(name)
    # PER-ENTRY validation, not just per-file. A single entry with a garbage
    # firstSeen used to abort the whole update, which left tracking disabled
    # indefinitely -- the opposite of self-healing. Anything unreadable is
    # discarded and re-seeded from this run.
    first_seen = None
    if isinstance(entry, dict) and entry.get("sha256") == sha:
        try:
            first_seen = int(entry.get("firstSeen"))
            if first_seen <= 0 or first_seen > now:
                first_seen = None
        except (TypeError, ValueError):
            first_seen = None
    if first_seen is None:
        first_seen = now
    state[name] = {"sha256": sha, "firstSeen": first_seen}

    age = max(0, now - first_seen)
    stale = age >= threshold
    lines.append("%s\t%d\t%d\t%d" % (name, age, threshold, 1 if stale else 0))
    status["sources"][name] = {
        "sha256": sha,
        "firstSeen": iso(first_seen),
        "firstSeenEpoch": first_seen,
        "ageSeconds": age,
        "staleThresholdSeconds": threshold,
        "stale": stale,
    }


def atomic_write(path, text, mode):
    """Temp file plus rename, so a reader never sees a torn file.

    The temp name is UNIQUE, not `path + '.tmp'`: this script supports being
    run directly by hand, so a manual run can overlap a scheduled one, and a
    shared predictable temp path lets two writers truncate each other or race
    the rename.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# State holds only hashes and timestamps, but it DRIVES the warnings, so a
# forged one could silence a real freeze: keep it owner-only. The status file
# is a read-only view of the same non-sensitive facts and is world-readable so
# other tooling on the host can consume it without needing this file's
# permissions relaxed.
atomic_write(state_path, json.dumps(state, indent=2, sort_keys=True) + "\n", 0o600)
atomic_write(status_path, json.dumps(status, indent=2, sort_keys=True) + "\n", 0o644)
print("\n".join(lines))
PY
)"; then
    say "  freshness: state update failed; staleness tracking skipped (non-fatal)"
    invalidate_status
    return 0
  fi

  local name age threshold stale
  while IFS=$'\t' read -r name age threshold stale; do
    [ -n "$name" ] || continue
    if [ "$stale" = "1" ]; then
      say "  WARNING: SOURCE STALE: $name unchanged for $((age / 3600))h (threshold $((threshold / 3600))h)"
      say "    the source looks frozen. The floors still passed, so the build"
      say "    proceeds -- a stale list beats no list -- but this needs a look."
    else
      say "  freshness: $name last changed $((age / 3600))h ago (threshold $((threshold / 3600))h)"
    fi
  done <<< "$result"
}

say "tracking source freshness ..."
check_source_freshness

# The host, and only the host. Strip scheme, path, query, fragment, userinfo,
# port and any trailing colon before anything else is judged.
strip_to_host() {
  sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[/?\#].*$##; s#^[^@]*@##; s#:[0-9]+$##; s#:+$##'
}

# Phishing.Database ships MOSTLY bare hosts, already lowercase -- but not
# only. The 2026-07-31 pull carried 95 lines that were full URLs, host:port
# pairs or percent-escaped fragments, and until today they flowed through
# as-is: inert in the binary (a parsed host can never contain those bytes)
# but counted as if they protected something. Extract the host from each
# line; whatever still is not a host after that dies in filter_acceptable.
#
# BARE IPs ARE KEPT for this feed, deliberately, where phishunt's are
# dropped below: PDB curates thousands of active phishing IPs (5,466 in the
# 2026-07-31 pull) that really match address-bar navigation, while phishunt
# is a URL feed where an IP row says "a kit lives at this path on a shared
# box" -- a claim about a path, not a host.
grep -vE '^\s*(#|$)' "$WORK/pdb.txt" | tr -d '\r' | last_field | strip_to_host \
  | tr 'A-Z' 'a-z' | sort -u > "$WORK/pdb.hosts"

# phishunt ships URLs; same extraction, then the IP drop explained above.
strip_to_host < "$WORK/phishunt.txt" \
  | grep -vE '^\s*(#|$)' | tr -d '\r' | last_field | tr 'A-Z' 'a-z' \
  | grep -vE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
  | sort -u > "$WORK/phishunt.hosts"

PDB_N=$(wc -l < "$WORK/pdb.hosts")
PH_N=$(wc -l < "$WORK/phishunt.hosts")
say "  Phishing.Database : $PDB_N hosts"
say "  phishunt.io       : $PH_N hosts"

if [ "$PDB_N" -lt "$PDB_FLOOR" ]; then
  say "FAIL: Phishing.Database returned $PDB_N hosts, floor is $PDB_FLOOR."
  say "  A truncated fetch would ship a browser claiming protection it does not"
  say "  have. $OUT is unchanged."
  exit 1
fi
if [ "$PH_N" -lt "$PHISHUNT_FLOOR" ]; then
  say "FAIL: phishunt.io returned $PH_N hosts, floor is $PHISHUNT_FLOOR."
  say "  $OUT is unchanged."
  exit 1
fi

# THE SAME ACCEPTANCE RULES build.rs WILL APPLY, applied here so the count this
# script prints is the count the binary ends up with.
#
# Without this they disagree, and the disagreement is dangerous rather than
# untidy: the signed manifest's `entries` has to be the post-acceptance,
# post-dedup figure, and `install_verified_list` refuses any list parsing to
# under 90% of what was declared. A script that printed the raw line count
# would be handing the project owner a number that quietly breaks the refresh on
# every install.
#
# Mirrors hostrules::acceptable -- host charset only, at least two labels, no
# leading or trailing dot, no empty label, <=63 bytes per label, <=253 bytes,
# <=16 labels, and not a bare shared-platform suffix. Upstream really does
# ship entries that fail these: URL fragments the extraction above could not
# save, and several hundred hosts with twenty-plus labels.
#
# THE PROTECTED LIST IS PARSED OUT OF hostrules.rs, not copied here. Both ends
# of this pipeline then read the same array in the same file, which is the
# same trick hostrules.rs itself plays on build.rs with include! -- the mirror
# cannot drift because there is nothing to drift from.
PROTECTED_FILE="$WORK/protected.suffixes"
sed -n '/PROTECTED_SUFFIXES: &\[&str\]/,/^];/p' crates/app/src/platform/hostrules.rs \
  | grep -oE '"[^"]+"' | tr -d '"' > "$PROTECTED_FILE"
if [ "$(wc -l < "$PROTECTED_FILE")" -lt 20 ]; then
  say "FAIL: parsed only $(wc -l < "$PROTECTED_FILE") protected suffixes from"
  say "  hostrules.rs -- the array moved or was reformatted, and running"
  say "  without the tripwire silently disarms it. Fix the parse, then rerun."
  exit 1
fi

filter_acceptable() {
  LC_ALL=C awk -v protected_file="$PROTECTED_FILE" '
    BEGIN { while ((getline line < protected_file) > 0) protected[line] = 1 }
    /[^a-z0-9._-]/            { next }   # host bytes only; input is lowercased
    length($0) > 253          { next }
    /^\./ || /\.$/            { next }
    /\.\./                    { next }
    !/\./                     { next }   # bare TLD
    ($0 in protected)         { next }   # bare shared-platform suffix
    {
      n = split($0, parts, ".")
      if (n > 16) next
      for (i = 1; i <= n; i++) if (length(parts[i]) > 63) next
      print
    }
  '
}

cat "$WORK/pdb.hosts" "$WORK/phishunt.hosts" | sort -u | filter_acceptable > "$WORK/merged.hosts"
MERGED_N=$(wc -l < "$WORK/merged.hosts")
# Counted after filtering on both sides, so this is how many phishunt hosts
# actually reach the binary rather than how many the feed listed.
NEW_FROM_PH=$(comm -13 \
  <(filter_acceptable < "$WORK/pdb.hosts") \
  <(filter_acceptable < "$WORK/phishunt.hosts") | wc -l)

TODAY=$(date -u +%Y-%m-%d)
cat > "$WORK/out.txt" <<HEADER
# PATANYX bundled malicious-host floor.
#
# GENERATED FILE. Regenerate with scripts/build-blocklist.sh, which re-fetches
# both sources, sanitises them and rewrites this whole file. Do not hand-edit:
# the next regeneration discards anything added by hand.
#
# WHAT THIS IS. The list compiled into the binary, in force from first launch
# so protection never depends on the network having worked. It is NOT the whole
# answer: phishing domains often live hours, so a build-time snapshot decays.
# The signed refresh channel replaces this set at runtime without a restart.
#
# FORMAT. One host per line. Blank lines and lines beginning with # are
# ignored. A listed host also covers its subdomains, on label boundaries only:
# \`evil.example\` matches \`login.evil.example\` and does NOT match
# \`notevil.example\`. Hosts must be ASCII (international names arrive as
# punycode) and must have at least two labels.
#
# WHAT AN ENTRY ASSERTS. That a host has been REPORTED as phishing or malware
# distribution by one of the sources below -- not that PATANYX has verified it
# independently, and not a finding of fact about whoever operates it. One
# source publishes community-maintained reports that are retested
# automatically for activity; the other publishes detection-driven suspicion
# and says plainly that false positives occur. Neither warrants a claim
# stronger than "reported", which is why the blocked banner says exactly that
# and why the per-tab override exists.
#
# ------------------------------------------------------------------------
# SOURCES AND LICENCES
#
# Retrieved $TODAY.
#
# 1. Phishing.Database -- https://github.com/mitchellkrogza/Phishing.Database
#    phishing-domains-ACTIVE.txt -- $PDB_N hosts.
#
# MIT License
# Copyright (c) 2018-2025 Mitchell Krog - github.com/mitchellkrogza
# Copyright (c) 2018-2025 Nissar Chababy - github.com/funilrys
# Copyright (c) 2018-2025 Phishing.Database Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# 2. phishunt.io -- https://phishunt.io/ -- feed.txt -- $PH_N hosts,
#    of which $NEW_FROM_PH were not already covered by the list above.
#
# Creative Commons CC0 1.0 Universal (public domain dedication). From their
# terms: "The data distributed through phishunt.io (JSON, CSV, TXT feeds, and
# API responses) is released into the public domain under Creative Commons
# CC0 1.0." Attribution is appreciated but not required; it is given here
# because a browser that ships someone else's work should say so.
#
# Their accuracy statement, which is why this file's assertion paragraph is
# worded the way it is: "The data distributed by phishunt.io reflects
# suspicion based on automated heuristics and third-party signals. It is not
# a legal finding ... False positives and false negatives occur routinely."
#
# WHY THESE SOURCES. Both are permissively licensed and redistributable inside
# a shipped browser. Feeds that are not were evaluated and rejected: OpenPhish
# forbids making any portion of the data available to a third party, which is
# precisely what shipping it to every install does; abuse.ch restricts
# derivative works without consent. URLhaus was rejected on shape rather than
# licence -- two thirds of its entries are bare IP addresses, and the domains
# carrying the most malware URLs are raw.githubusercontent.com, github.com and
# drive.google.com, which a host-level blocklist must never contain.
# ------------------------------------------------------------------------
HEADER

cat "$WORK/merged.hosts" >> "$WORK/out.txt"
# Staged BESIDE the destination, then renamed: a rename within one directory
# is atomic, while a mv from $WORK could cross filesystems and decay into
# copy-then-delete with a torn window in the middle.
OUT_TMP="$OUT.tmp.$$"
cp "$WORK/out.txt" "$OUT_TMP"
mv "$OUT_TMP" "$OUT"

say ""
say "wrote $OUT"
say "  accepted hosts    : $MERGED_N"
say "  new from phishunt : $NEW_FROM_PH"
say ""
say "Next: cargo build   -- build.rs re-hashes and asserts >300k. Its"
say "                       'blocklist: N hosts' line must equal $MERGED_N."
say "      patanyx --emit-blocklist blocklist-N.bin"
say ""
say "\`entries\` in the signed manifest must be that same figure. It is"
say "post-acceptance and post-dedup; install_verified_list refuses any list"
say "parsing to under 90% of what was declared, so an inflated number breaks"
say "the refresh on every install rather than failing here."
