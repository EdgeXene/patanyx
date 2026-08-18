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

# PhishDestroy's PRIMARY list, and the distinction matters more than the URL
# does. The same repo also publishes community/blocklist.txt, "aggregated from
# 13+ sources" -- and that account mirrors OpenPhish, GPL-3.0 scam-database and
# others. A CC0 label on aggregated third-party data cannot grant rights the
# upstreams withheld, and OpenPhish's no-redistribution term is the exact reason
# this script already rejects it. Primary is their own investigative work, so
# CC0 is theirs to give. Never point this at the community feed.
PHISHDESTROY_URL="https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt"

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
# 183,460 on 2026-08-10. Same reasoning as the others: clear of ordinary churn,
# high enough that a truncated fetch cannot pass for a real list.
PHISHDESTROY_FLOOR=120000

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

# A SECOND TIER, because one threshold cannot say how bad it is. The 72h
# warning reads identically on day four and on day nine, so a cadence hiccup
# and a dead upstream produce the same line and the same alert -- and the alert
# is suppressed for 24h after the first, which means an escalation from
# "irregular" to "abandoned" is invisible by construction. These thresholds
# mark the point where waiting stops being the right response and finding a
# replacement source starts: a week for Phishing.Database (against a normal
# cadence of 2-4 commits a day), three days for phishunt (against hourly).
PDB_DEAD_HOURS=168
PHISHUNT_DEAD_HOURS=72
# PhishDestroy publishes daily and in practice pushes several times a day, so
# two unchanged days is already outside cadence. Its dead threshold is tighter
# than Phishing.Database's precisely BECAUSE of what happened there: a source
# added to remove a single point of failure has to be watched at least as
# closely as the one it was brought in to cover for.
PHISHDESTROY_STALE_HOURS=48
PHISHDESTROY_DEAD_HOURS=120

# phishunt is a ROLLING WINDOW, not a corpus. Measured 2026-08-10: the whole
# dataset is ~714 entries, every one of them currently-live, and their API has
# no archive -- `since=2025-01-01` returns exactly what `since=2026-08-01`
# does, because entries are pruned on their side by retention. Fetching it
# hourly and keeping only the current window therefore throws away nearly
# everything it has ever told us.
#
# It is also almost entirely INDEPENDENT of Phishing.Database: of the 713
# hosts in that measurement, 691 were absent from the 391,605-host PDB feed.
# ~15-25 genuinely new hosts appear per day. Accumulating them locally turns a
# small window into a growing source that no other feed here covers.
#
# RETENTION IS THE PRICE. phishunt prunes for a good reason -- a phishing host
# gets cleaned up, or the domain lapses and is re-registered by someone
# innocent -- so keeping entries forever converts their freshness into our
# false positives, and PATANYX ships no appeal path for a wrongly blocked host.
# Thirty days from LAST OBSERVATION, not from first: a host still being
# reported keeps its place, one that has gone quiet for a month ages out.
#
# WHY THIRTY AND NOT NINETY, which this started at. Phishing hosts live hours
# to days, so by thirty days an entry is already far past the behaviour that
# justified it -- the extra sixty days added re-registration risk in exchange
# for almost no coverage. The window is also no longer the only thing holding
# the line: the liveness gate below drops entries on DNS evidence rather than
# waiting out a clock, so this is a ceiling on how long weak evidence can
# persist, not the primary control.
PHISHUNT_ARCHIVE_DAYS=30

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

say "fetching PhishDestroy ..."
$CURL --max-time 120 --max-filesize 20000000 -o "$WORK/phishdestroy.txt" "$PHISHDESTROY_URL" || {
  say "FAIL: could not fetch $PHISHDESTROY_URL"
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

# WHY A SEED HINT IS NEEDED AT ALL. Content tracking can only measure from the
# first time IT saw a hash, so a source that was ALREADY frozen when tracking
# began reports an age starting at zero. That is not hypothetical: freshness
# tracking was added 2026-08-06, five days into a Phishing.Database freeze that
# began 2026-08-01, and the first alert therefore claimed 72h for what was
# really a nine-day outage. Every threshold in this file was calibrated against
# real cadence; an age that starts late silently raises all of them.
#
# The fix is narrow ON PURPOSE. It supplies a start date ONLY when seeding a
# source we have never recorded, and only from an upstream that can answer
# cheaply. Once a change is observed locally, observation wins forever after --
# this never overrides a measured timeline, so the objection in the block below
# (an external call that can fail mid-run) still holds and is still respected:
# failure here yields an empty hint and the old behaviour.
pdb_upstream_last_change() {
  local api="https://api.github.com/repos/Phishing-Database/Phishing.Database/commits"
  local body=""
  body="$($CURL --max-time 20 "$api?path=phishing-domains-ACTIVE.txt&per_page=1" 2>/dev/null)" || return 0
  printf '%s' "$body" | python3 -c '
import calendar, json, sys, time
try:
    commits = json.load(sys.stdin)
    stamp = commits[0]["commit"]["committer"]["date"]
    epoch = calendar.timegm(time.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ"))
    # A future or absurd date is a bad answer, not a useful hint.
    if 0 < epoch <= int(time.time()):
        print(epoch)
except Exception:
    pass
' 2>/dev/null || true
}

check_source_freshness() {
  local phishunt_hash="" phishdestroy_hash=""
  phishunt_hash="$(sha256sum "$WORK/phishunt.txt" 2>/dev/null | awk '{print $1}')" || true
  phishdestroy_hash="$(sha256sum "$WORK/phishdestroy.txt" 2>/dev/null | awk '{print $1}')" || true

  if [ -z "$FETCHED_SHA" ] || [ -z "$phishunt_hash" ] || [ -z "$phishdestroy_hash" ]; then
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

  # Probed only when there is no state file at all -- the seeding case. An
  # hourly GitHub call for a hint that would be discarded anyway is waste.
  local pdb_hint=""
  if [ ! -f "$SOURCE_STATE_FILE" ]; then
    pdb_hint="$(pdb_upstream_last_change)"
    [ -n "$pdb_hint" ] && say "  freshness: seeding Phishing.Database from its upstream commit date"
  fi

  local result=""
  if ! result="$(python3 - "$SOURCE_STATE_FILE" "$SOURCE_STATUS_FILE" \
      "Phishing.Database:$FETCHED_SHA:$((PDB_STALE_HOURS * 3600)):$((PDB_DEAD_HOURS * 3600)):$pdb_hint" \
      "phishunt.io:$phishunt_hash:$((PHISHUNT_STALE_HOURS * 3600)):$((PHISHUNT_DEAD_HOURS * 3600)):" \
      "PhishDestroy:$phishdestroy_hash:$((PHISHDESTROY_STALE_HOURS * 3600)):$((PHISHDESTROY_DEAD_HOURS * 3600)):" <<'PY'
import json, os, sys, tempfile, time

state_path, status_path = sys.argv[1], sys.argv[2]
now = int(time.time())

sources = []
for arg in sys.argv[3:]:
    name, sha, threshold, dead_threshold, hint = arg.rsplit(":", 4)
    sources.append((name, sha, int(threshold), int(dead_threshold),
                    int(hint) if hint else None))

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
for name, sha, threshold, dead_threshold, hint in sources:
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
    # WHERE THE TIMELINE STARTS, in precedence order. A locally observed change
    # is the strongest evidence and is never overridden. Failing that, an
    # upstream date is better than this instant, because it can only make the
    # age LONGER -- the direction that reveals a freeze rather than hiding one.
    # A reused timeline keeps whatever origin it was established with: a hash
    # that has not changed since it was seeded is still only a lower bound, and
    # promoting it to "observed" every hour would launder a guess into a
    # measurement. It becomes "observed" when the CONTENT changes, because that
    # is the moment we actually witness the source moving.
    origin = (entry or {}).get("origin", "observed") if first_seen is not None else None
    if origin not in ("observed", "upstream", "seeded"):
        origin = "observed"
    if first_seen is None:
        if hint is not None and 0 < hint <= now:
            first_seen = hint
            origin = "upstream"
        else:
            first_seen = now
            origin = "seeded"
    state[name] = {"sha256": sha, "firstSeen": first_seen, "origin": origin}

    age = max(0, now - first_seen)
    stale = age >= threshold
    dead = age >= dead_threshold
    lines.append("%s\t%d\t%d\t%d\t%d\t%d"
                 % (name, age, threshold, 1 if stale else 0, dead_threshold,
                    1 if dead else 0))
    status["sources"][name] = {
        "sha256": sha,
        "firstSeen": iso(first_seen),
        "firstSeenEpoch": first_seen,
        "ageSeconds": age,
        "staleThresholdSeconds": threshold,
        "stale": stale,
        # A STRICTLY WORSE STATE, not a separate one: `dead` always implies
        # `stale`, so a consumer that only knows about `stale` keeps working
        # unchanged and one that knows about both reports the worse tier.
        "deadThresholdSeconds": dead_threshold,
        "dead": dead,
        # "seeded" means the age is a LOWER BOUND: tracking started here and the
        # source may have been frozen long before. Consumers that report an age
        # to a human should say so rather than presenting it as measured.
        "firstSeenOrigin": origin,
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

  local name age threshold stale dead_threshold dead
  while IFS=$'\t' read -r name age threshold stale dead_threshold dead; do
    [ -n "$name" ] || continue
    if [ "$dead" = "1" ]; then
      say "  WARNING: SOURCE LOOKS DEAD: $name unchanged for $((age / 3600))h (threshold $((dead_threshold / 3600))h)"
      say "    past the point where this reads as a hiccup. The build still"
      say "    proceeds, but the answer here is a replacement source, not"
      say "    waiting longer."
    elif [ "$stale" = "1" ]; then
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

# PhishDestroy ships bare lowercase domains, no hosts-file prefixes and no
# URLs, and the 2026-08-10 pull contained no bare IPs at all. The same
# extraction runs anyway: a feed's shape is a fact about today's pull, not a
# guarantee, and everything here has to survive the day that changes.
grep -vE '^\s*(#|$)' "$WORK/phishdestroy.txt" | tr -d '\r' | last_field | strip_to_host \
  | tr 'A-Z' 'a-z' | sort -u > "$WORK/phishdestroy.hosts"

PDB_N=$(wc -l < "$WORK/pdb.hosts")
PH_N=$(wc -l < "$WORK/phishunt.hosts")
PD_N=$(wc -l < "$WORK/phishdestroy.hosts")
say "  Phishing.Database : $PDB_N hosts"
say "  phishunt.io       : $PH_N hosts"
say "  PhishDestroy      : $PD_N hosts"

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
if [ "$PD_N" -lt "$PHISHDESTROY_FLOOR" ]; then
  say "FAIL: PhishDestroy returned $PD_N hosts, floor is $PHISHDESTROY_FLOOR."
  say "  $OUT is unchanged."
  exit 1
fi

# --- phishunt archive -------------------------------------------------------
#
# Accumulate what the rolling window showed us, expire it at
# PHISHUNT_ARCHIVE_DAYS since last observation, and contribute the survivors
# to the merge. See the PHISHUNT_ARCHIVE_DAYS comment above for why this
# exists and why the expiry is not optional.
#
# THIS RUNS ONLY AFTER THE FLOORS PASS. A truncated phishunt fetch is exactly
# the input that must never reach a store we then trust for a month: the
# floor above refuses it, so by here the window is known-plausible. What the
# floors cannot catch -- a window that is genuinely small today -- is harmless,
# because absence never removes anything. Only the clock does.
#
# LIKE THE FRESHNESS TRACKING, EVERY FAILURE DEGRADES TO A WARNING. An
# unwritable state dir, corrupt JSON, a missing python3: the archive
# contributes nothing that run and the build carries on with the live window
# alone. A blocklist that stops publishing because a cache broke is a worse
# outcome than one that briefly forgets what it had accumulated.
PHISHUNT_ARCHIVE_FILE="${BLOCKLIST_PHISHUNT_ARCHIVE_FILE:-/var/lib/patanyx-blocklist/phishunt-archive.json}"

: > "$WORK/archive.hosts"
ARCHIVE_KEPT=0
ARCHIVE_ADDED=0
ARCHIVE_EXPIRED=0

accumulate_phishunt_archive() {
  local archive_dir
  archive_dir="$(dirname "$PHISHUNT_ARCHIVE_FILE")"
  if ! mkdir -p "$archive_dir" 2>/dev/null; then
    say "  archive: cannot create $archive_dir; accumulation skipped"
    return 0
  fi

  local report=""
  if ! report="$(python3 - "$PHISHUNT_ARCHIVE_FILE" "$WORK/phishunt.hosts" \
      "$WORK/archive.hosts" "$((PHISHUNT_ARCHIVE_DAYS * 86400))" <<'PY'
import json, os, sys, tempfile, time

archive_path, observed_path, out_path, ttl = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
now = int(time.time())

# A missing or corrupt archive is "nothing accumulated yet", not an error: it
# re-seeds from this run and self-heals. Losing the store costs coverage we
# rebuild over the following weeks; refusing to build costs the whole list.
try:
    with open(archive_path, encoding="utf-8") as f:
        loaded = json.load(f)
    hosts = loaded.get("hosts")
    if not isinstance(hosts, dict):
        hosts = {}
except Exception:
    hosts = {}

# PER-ENTRY validation, the same lesson as the freshness state: one garbage
# record must not discard the other few thousand good ones.
clean = {}
for host, rec in hosts.items():
    if not isinstance(host, str) or not host or not isinstance(rec, dict):
        continue
    try:
        first_seen = int(rec.get("firstSeen"))
        last_seen = int(rec.get("lastSeen"))
    except (TypeError, ValueError):
        continue
    # A future timestamp would postpone expiry indefinitely -- a clock skew, or
    # a tampered store, becoming permanent retention. Clamp it to now.
    if first_seen <= 0 or last_seen <= 0:
        continue
    clean[host] = {"firstSeen": min(first_seen, now), "lastSeen": min(last_seen, now)}

observed = set()
with open(observed_path, encoding="utf-8") as f:
    for line in f:
        host = line.strip()
        if host:
            observed.add(host)

added = 0
for host in observed:
    rec = clean.get(host)
    if rec is None:
        clean[host] = {"firstSeen": now, "lastSeen": now}
        added += 1
    else:
        # RE-CONFIRMATION. Still being reported, so the retention clock
        # restarts here rather than running from when we first saw it.
        rec["lastSeen"] = now

expired = 0
for host in list(clean):
    if now - clean[host]["lastSeen"] >= ttl:
        del clean[host]
        expired += 1


def atomic_write(path, text, mode):
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


# The archive DRIVES what gets blocked, so a forged one could inject hosts into
# every install's bundled list: owner-only, like the freshness state.
atomic_write(
    archive_path,
    json.dumps({"generatedAtEpoch": now, "ttlSeconds": ttl, "hosts": clean},
               indent=2, sort_keys=True) + "\n",
    0o600,
)
# Written for the merge to consume; sorted so the merge's `sort -u` has less to
# do and so a human diffing two runs sees only real changes.
atomic_write(out_path, "".join(h + "\n" for h in sorted(clean)), 0o644)
print("%d\t%d\t%d" % (len(clean), added, expired))
PY
)"; then
    say "  archive: update failed; accumulation skipped this run (non-fatal)"
    : > "$WORK/archive.hosts"
    return 0
  fi

  IFS=$'\t' read -r ARCHIVE_KEPT ARCHIVE_ADDED ARCHIVE_EXPIRED <<< "$report"
  say "  archive: $ARCHIVE_KEPT hosts retained (+$ARCHIVE_ADDED new, -$ARCHIVE_EXPIRED expired past ${PHISHUNT_ARCHIVE_DAYS}d)"
}

say "accumulating phishunt archive ..."
accumulate_phishunt_archive

# --- archive liveness gate --------------------------------------------------
#
# TIME ALONE IS THE WRONG TEST, whatever the window is set to.
# Phishing hosts live hours to days, so most retained entries are long dead and
# retention buys little; meanwhile the one real harm case -- a domain that
# lapsed and was RE-REGISTERED by somebody innocent -- becomes more likely the
# longer the window runs. Blocking a legitimate site on a sighting the source
# itself has dropped, with no appeal path, is the outcome to design against.
#
# Note the asymmetry argument in blocklist-allow.txt cuts the OTHER way here.
# For a live report, "inconclusive means keep blocking" is right. For an entry
# nobody is reporting any more, the evidence is stale and the source has moved
# on, so the same default is weaker. Hence: an archive-only entry has to show
# something beyond having once been seen.
#
# TWO WAYS TO SURVIVE. Corroboration -- still carried by Phishing.Database --
# costs nothing and is checked first. Failing that, liveness: the host still
# resolves. A host that no longer resolves cannot be serving a phishing page,
# so dropping it removes no protection while removing re-registration risk.
# Resolving is weak evidence of malice, which is why the retention ceiling
# still applies on top; this gate only ever removes entries, never extends one.
#
# BOUNDED WORK. Only archive-ONLY hosts are candidates (anything both feeds
# still report is corroborated by definition), each is rechecked at most weekly,
# and at most ARCHIVE_CHECK_BUDGET are resolved per run. At ~15-25 new hosts a
# day the steady-state candidate set is small, and the budget keeps a bad day
# from turning an hourly build into a DNS sweep.
ARCHIVE_RECHECK_DAYS=7
ARCHIVE_CHECK_BUDGET=200

gate_archive_liveness() {
  [ -s "$WORK/archive.hosts" ] || return 0

  local report=""
  if ! report="$(python3 - "$PHISHUNT_ARCHIVE_FILE" "$WORK/archive.hosts" \
      "$WORK/pdb.hosts" "$WORK/phishunt.hosts" \
      "$((ARCHIVE_RECHECK_DAYS * 86400))" "$ARCHIVE_CHECK_BUDGET" <<'PY'
import json, os, socket, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor

archive_path, out_path, pdb_path, ph_path, recheck, budget = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]))
now = int(time.time())


def load(path):
    with open(path, encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


try:
    with open(archive_path, encoding="utf-8") as f:
        data = json.load(f)
    hosts = data.get("hosts")
    if not isinstance(hosts, dict):
        raise ValueError
except Exception:
    print("SKIP\t0\t0\t0")
    sys.exit(0)

corroborated = load(pdb_path) | load(ph_path)
# Candidates: retained entries no live feed is reporting, due for a recheck.
candidates = [
    h for h, rec in hosts.items()
    if h not in corroborated
    and now - int(rec.get("lastCheck", 0) or 0) >= recheck
]
candidates.sort(key=lambda h: int((hosts[h].get("lastCheck") or 0)))
checked = candidates[:budget]


def resolves(host):
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        # A resolver hiccup is not evidence of anything. Treat it as alive and
        # try again next week rather than dropping on an infrastructure blip.
        return True


dropped = 0
if checked:
    with ThreadPoolExecutor(max_workers=20) as pool:
        for host, alive in zip(checked, pool.map(resolves, checked)):
            if alive:
                hosts[host]["lastCheck"] = now
            else:
                del hosts[host]
                dropped += 1

if dropped or checked:
    directory = os.path.dirname(archive_path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=os.path.basename(archive_path) + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps({**data, "hosts": hosts}, indent=2, sort_keys=True) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, archive_path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("".join(h + "\n" for h in sorted(hosts)))

print("OK\t%d\t%d\t%d" % (len(candidates), len(checked), dropped))
PY
)"; then
    say "  liveness: check failed; archive unchanged this run (non-fatal)"
    return 0
  fi

  local verdict cand checked dropped
  IFS=$'\t' read -r verdict cand checked dropped <<< "$report"
  if [ "$verdict" = "SKIP" ]; then
    say "  liveness: no readable archive; skipped"
  else
    say "  liveness: $cand uncorroborated, $checked resolved this run, $dropped dropped (no DNS)"
  fi
}

gate_archive_liveness

# THE SAME ACCEPTANCE RULES build.rs WILL APPLY, applied here so the count this
# script prints is the count the binary ends up with.
#
# Without this they disagree, and the disagreement is dangerous rather than
# untidy: the signed manifest's `entries` has to be the post-acceptance,
# post-dedup figure, and `install_verified_list` refuses any list parsing to
# under 90% of what was declared. A script that printed the raw line count
# would be handing over a number that quietly breaks the refresh on
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

# --- allowlist --------------------------------------------------------------
#
# Subtracted LAST, after acceptance filtering, so nothing can put a host back:
# whatever else the sources agree on, an allowlisted host does not ship. See
# scripts/blocklist-allow.txt for what an entry means and why the file exists.
#
# EXACT MATCH ONLY, deliberately. Removing `gravatar.com` must not remove a
# feed's entry for `phish.gravatar.com` -- the first is a claim about a service,
# the second about an attacker's page on it.
ALLOW_FILE=scripts/blocklist-allow.txt
# Inline `#` comments are stripped, so an entry can carry its justification on
# the same line and the file stays readable as a table.
sed -E 's/#.*$//; s/[[:space:]]+//g' "$ALLOW_FILE" 2>/dev/null \
  | grep -vE '^$' | tr 'A-Z' 'a-z' | sort -u > "$WORK/allow.hosts" || : > "$WORK/allow.hosts"
ALLOW_N=$(wc -l < "$WORK/allow.hosts")

# UPSTREAM RETRACTIONS. Phishing-Database curates false positives in its
# submission repo, and those retractions never reach the ACTIVE feed while the
# generator is down -- so a host they have already agreed is not malicious can
# go on being blocked here indefinitely. Subtracting their list closes that gap
# without waiting on their pipeline.
#
# WHY THIS IS FINE TO USE WHEN THE ADDITIONS LIST IS NOT. That repo carries no
# licence, so shipping its contents inside a browser would assume a permission
# nobody granted -- which is why the 2,472 novel domains in `additions/` are
# deliberately NOT ingested.
#
# The grounds for treating retractions differently are NOT "we distribute
# nothing, so no right is engaged". That answer only holds under US copyright,
# where an unoriginal list of domain names is thin-to-unprotectable under
# Feist. The EU/UK sui generis database right turns on EXTRACTION -- transfer of
# contents to another medium, permanent or temporary -- and this fetches the
# whole file hourly, so that element is met whether or not a byte reaches the
# output. The reasons this is still sound are narrower and worth stating
# honestly: the entries are unprotectable facts, they are consumed as a filter
# rather than copied into anything we publish, 301 records is nowhere near a
# substantial part of their database, and a published retraction exists
# precisely so downstreams apply it. Reasoning from "we never redistribute"
# invites the correct reply that distribution was never the trigger.
#
# BEST FIX IS STILL UPSTREAM: a one-line licence grant on that repo would settle
# this and unblock the additions list at the same time.
#
# NON-FATAL, and asymmetric on purpose. A failed fetch means we keep blocking
# something that may be a false positive -- a visible, overridable error. The
# alternative failure, refusing to build, ships nothing at all.
FP_URL="https://raw.githubusercontent.com/Phishing-Database/phishing/master/falsepositives/permanent/domains.list"
: > "$WORK/upstream-fp.hosts"
UPSTREAM_FP_N=0
if $CURL --max-time 60 --max-filesize 5000000 -o "$WORK/fp.raw" "$FP_URL" 2>/dev/null; then
  grep -vE '^\s*(#|$)' "$WORK/fp.raw" | tr -d '\r' | last_field | strip_to_host \
    | tr 'A-Z' 'a-z' | grep -E '^[a-z0-9.-]+\.[a-z0-9-]+$' \
    | sort -u > "$WORK/upstream-fp.hosts" || : > "$WORK/upstream-fp.hosts"
  UPSTREAM_FP_N=$(wc -l < "$WORK/upstream-fp.hosts")
  say "  upstream FPs      : $UPSTREAM_FP_N retracted hosts fetched"
else
  say "  upstream FPs      : unavailable; continuing without them"
fi

# A ceiling for the same reason the local allowlist has one, sized to the fact
# that this input is not under our control: an upstream that broke, or was
# tampered with, must not be able to empty the blocklist by declaring
# everything a false positive. Their list has sat around 300 entries.
UPSTREAM_FP_CEILING=5000
if [ "$UPSTREAM_FP_N" -gt "$UPSTREAM_FP_CEILING" ]; then
  say "  WARNING: upstream FP list has $UPSTREAM_FP_N entries (ceiling $UPSTREAM_FP_CEILING);"
  say "    ignoring it this run. A retraction list that large is a broken feed,"
  say "    not a burst of honesty."
  : > "$WORK/upstream-fp.hosts"
  UPSTREAM_FP_N=0
fi

# A guard, in the spirit of the floors: an allowlist is the one input here whose
# job is to REMOVE protection, so a corrupted or hostile one is the cheapest way
# to disarm the browser. A hundred entries is far above the twenty this started
# with and far below anything that could gut a 390k list.
ALLOW_CEILING=100
if [ "$ALLOW_N" -gt "$ALLOW_CEILING" ]; then
  say "FAIL: allowlist has $ALLOW_N entries, ceiling is $ALLOW_CEILING."
  say "  An allowlist this large stops being a list of known false positives and"
  say "  starts being a hole in the blocklist. Raise the ceiling deliberately if"
  say "  that is really what is wanted. $OUT is unchanged."
  exit 1
fi

cat "$WORK/pdb.hosts" "$WORK/phishunt.hosts" "$WORK/phishdestroy.hosts" \
  "$WORK/archive.hosts" | sort -u | filter_acceptable > "$WORK/merged.prepsl"

# --- bare public suffixes ---------------------------------------------------
#
# A host that IS a public suffix is never a legitimate blocklist entry. It is
# the boundary under which strangers register names, so blocking it blocks every
# one of them. PROTECTED_SUFFIXES is the same idea, but it is twenty-eight
# hand-picked strings compared EXACTLY, which is the gap this closes:
# `amazonaws.com` is on that list, `s3.eu-west-1.amazonaws.com` is not equal to
# it, and a feed reporting the latter would block every bucket in the region.
# Object-storage endpoints, IPFS gateways and tunnelling services all present
# the same shape, and there are far more of them than a curated list can track.
#
# The repository already ships the full Public Suffix List for credential
# matching, so the correct boundary was sitting right there unused.
#
# THIS DOES NOT MERGE THE TWO LISTS, and the argument in hostrules.rs against
# doing so still stands. That argument is about the RUNTIME: hostrules.rs is
# include!d verbatim into both build.rs and the browser and must stay textually
# identical in both, so it cannot depend on a 10,000-rule file that refreshes on
# its own schedule. This check runs HERE, at merge time, on the build machine,
# and decides only what to import. The tripwire keeps its curated list; the
# import gains a complete one.
PSL_FILE=crates/app/src/public_suffix_list.txt
: > "$WORK/psl-drops.txt"
if [ -f "$PSL_FILE" ]; then
  python3 - "$PSL_FILE" "$WORK/merged.prepsl" "$WORK/merged.raw" "$WORK/psl-drops.txt" <<'PY'
import sys

psl_path, src_path, keep_path, drop_path = sys.argv[1:5]

exact, wildcard, exception = set(), set(), set()
with open(psl_path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        rule = line.strip()
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            # An exception rule names something that is NOT a suffix, e.g.
            # `!city.kawasaki.jp` under `*.kawasaki.jp`. Those are registrable
            # and must stay blockable.
            exception.add(rule[1:].lower())
        elif rule.startswith("*."):
            wildcard.add(rule[2:].lower())
        else:
            exact.add(rule.lower())


def is_public_suffix(host):
    """EXACT rules only. Wildcards are deliberately NOT applied.

    A first attempt honoured `*.` rules too and dropped a hundred entries
    instead of thirty-one -- including fifty
    `ec2-<ip>.compute-1.amazonaws.com` hosts, Internet Computer canister ids
    under `raw.icp0.io`, and individual `localto.net` tunnels. Those are
    public suffixes by the letter of the PSL, but each names a SINGLE tenant:
    blocking one EC2 hostname blocks one instance, which is exactly the
    targeted protection this list is for. Dropping them would have quietly
    removed real coverage in the name of preventing over-blocking.

    An exact rule is different in kind. `s3.eu-west-1.amazonaws.com` and
    `dweb.link` are the boundary itself, shared by every tenant beneath them,
    so an entry naming one can only ever be a feed accident.
    """
    if host in exception:
        return False
    return host in exact


kept, dropped = [], []
with open(src_path, encoding="utf-8") as handle:
    for line in handle:
        host = line.strip()
        if not host:
            continue
        (dropped if is_public_suffix(host) else kept).append(host)

with open(keep_path, "w", encoding="utf-8") as handle:
    handle.write("".join(h + "\n" for h in kept))
with open(drop_path, "w", encoding="utf-8") as handle:
    handle.write("".join(h + "\n" for h in dropped))
PY
  PSL_DROPPED=$(wc -l < "$WORK/psl-drops.txt")
  if [ "$PSL_DROPPED" -gt 0 ]; then
    say "  public suffixes   : $PSL_DROPPED platform-scale entries refused:"
    sed 's/^/      /' "$WORK/psl-drops.txt" >&2
  else
    say "  public suffixes   : none in this merge"
  fi
else
  say "  WARNING: $PSL_FILE missing; bare public suffixes NOT screened"
  cp "$WORK/merged.prepsl" "$WORK/merged.raw"
  PSL_DROPPED=0
fi
# comm needs both sides sorted under the same collation; LC_ALL=C is set at the
# top of this script, and filter_acceptable preserves input order from a sorted
# stream, so both sides are already in byte order here.
ALLOW_REMOVED=$(comm -12 "$WORK/merged.raw" "$WORK/allow.hosts" | wc -l)
comm -23 "$WORK/merged.raw" "$WORK/allow.hosts" > "$WORK/merged.allowed"
say "  allowlist         : $ALLOW_N entries, $ALLOW_REMOVED removed from this build"

UPSTREAM_FP_REMOVED=$(comm -12 "$WORK/merged.allowed" "$WORK/upstream-fp.hosts" | wc -l)
comm -23 "$WORK/merged.allowed" "$WORK/upstream-fp.hosts" > "$WORK/merged.hosts"
say "  upstream FPs      : $UPSTREAM_FP_REMOVED removed from this build"

# --- popularity tripwire ----------------------------------------------------
#
# A feed reporting a host that millions of people use daily is far likelier to
# be wrong than right, and nothing else here knows what "popular" means:
# PROTECTED_SUFFIXES is a short curated list of platform suffixes, never meant
# to know that a given domain is a real business. This does.
#
# IT REFUSES; IT DOES NOT DECIDE. Silently dropping every popular host would be
# auto-ALLOWING, and that is the one direction that fails invisibly: a wrong
# block shows the user a banner they can override, a wrong allow shows nobody
# anything, on every install, forever. So a top-10k hit stops the build and
# waits for a human to either allowlist the host with a reason or confirm the
# block. Phishing does live on popular hosts -- `googll.store` sits in the top
# 10k and belongs on the list -- which is exactly why a machine must not settle
# this class of case on its own.
#
# TWO BANDS, because the cost of being wrong is not flat. Measured across all
# three feeds on 2026-08-10: the top 10k holds a handful of entries and each is
# catastrophic, so it refuses; the 10k-100k band holds dozens whose individual
# blast radius is far smaller, so it reports and lets the build through rather
# than halting hourly publishing on a backlog nobody has triaged yet.
#
# Allowlisted hosts never reach here -- they were subtracted above -- so the
# allowlist doubles as the record of every decision this tripwire has forced.
#
# READ FROM THE BUILD BOX, NOT THE REPO, and this is a licensing constraint
# rather than a layout preference. Tranco publishes no licence of its own, and
# the list it serves is composed from providers including Cloudflare Radar
# (CC BY-NC) and Chrome CrUX (CC BY-SA) -- a NonCommercial term this project
# cannot absorb given the Premium tier, and a ShareAlike term that has no
# business touching an Apache-2.0 tree. Committing an extract would also apply
# exactly the standard this same script refuses to apply elsewhere: the
# additions list a few hundred lines up is excluded for having no licence, and
# Tranco has the identical defect.
#
# Using it locally to decide what to ASK A HUMAN ABOUT is not redistribution,
# and no Tranco data reaches the shipped list -- the tripwire only ever selects
# hosts for adjudication. Provenance is pinned by hash in tranco-snapshot.sha256
# so a build remains reproducible without the bytes living in the repo.
TRANCO_FILE="${BLOCKLIST_TRANCO_FILE:-/var/lib/patanyx-blocklist/tranco-top100k.txt}"
TRANCO_REFUSE_RANK=10000
TRANCO_WARN_RANK=100000

if [ ! -f "$TRANCO_FILE" ]; then
  # MOVING THE SNAPSHOT OUT OF THE REPO TRADED ONE RISK FOR ANOTHER. In-repo, the
  # tripwire was armed on every clone; now a fresh checkout or a rebuilt box has
  # no snapshot and the check quietly does nothing but log a line -- the same
  # silent-absence failure blocklist-allow.txt argues against, applied to the
  # guard itself. Hourly runs should still degrade rather than halt, so the
  # default stays soft; a pipeline that produces a SIGNED, SHIPPED list sets
  # BLOCKLIST_REQUIRE_TRIPWIRE=1 and gets a refusal instead. Graceful where
  # nothing reaches a user, strict where something does.
  if [ "${BLOCKLIST_REQUIRE_TRIPWIRE:-0}" = "1" ]; then
    say "FAIL: $TRANCO_FILE is missing and BLOCKLIST_REQUIRE_TRIPWIRE=1."
    say "  This build would ship a list nobody screened for popular hosts --"
    say "  the check that keeps widely-used hosts out of it. Run"
    say "  scripts/refresh-tranco.sh, then rerun."
    say "  $OUT is unchanged."
    exit 1
  fi
  say "  popularity        : $TRANCO_FILE missing; tripwire DISABLED for this build"
  say "    regenerate it with scripts/refresh-tranco.sh"
else
  # An unrecognised snapshot is reported, not refused. The pin exists so a
  # verdict can be traced to the data that produced it; a hash that has moved
  # means the reference was refreshed without recording it, which is a
  # bookkeeping lapse and must not be able to stop a publish.
  # TWO PLACES, because the pin and the history answer different questions. The
  # committed pin records what a RELEASE was adjudicated against and only a
  # human updates it; the history log is what the weekly timer has installed
  # since. A snapshot in neither was put there out of band, which is the only
  # case worth a warning -- and it stays a warning, because provenance
  # bookkeeping must never stop a publish.
  TRANCO_PIN=scripts/tranco-snapshot.sha256
  TRANCO_HISTORY="${BLOCKLIST_TRANCO_HISTORY:-/var/lib/patanyx-blocklist/tranco-history.log}"
  TRANCO_SHA="$(sha256sum "$TRANCO_FILE" 2>/dev/null | awk '{print $1}')" || true
  if [ -n "$TRANCO_SHA" ] \
    && ! grep -qs "^$TRANCO_SHA " "$TRANCO_PIN" \
    && ! grep -qs "^$TRANCO_SHA " "$TRANCO_HISTORY"; then
    say "  WARNING: the Tranco snapshot matches no recorded hash, in either"
    say "    $TRANCO_PIN or $TRANCO_HISTORY. It was replaced out of band."
  fi
  # Rank is line number among data lines, which is why refresh-tranco.sh
  # verifies the ordering rather than trusting it.
  LC_ALL=C awk -v refuse="$TRANCO_REFUSE_RANK" '
    NR == FNR {
      if ($0 ~ /^[[:space:]]*(#|$)/) next
      rank[$0] = ++n
      next
    }
    ($0 in rank) { printf "%d\t%s\n", rank[$0], $0 }
  ' "$TRANCO_FILE" "$WORK/merged.hosts" | sort -n > "$WORK/popular.raw"

  # Already-adjudicated hosts drop out here, so the tripwire only ever reports
  # cases nobody has ruled on. Same parse as the allowlist, so a reason can ride
  # on the same line.
  CONFIRM_FILE=scripts/blocklist-confirm.txt
  sed -E 's/#.*$//; s/[[:space:]]+//g' "$CONFIRM_FILE" 2>/dev/null \
    | grep -vE '^$' | tr 'A-Z' 'a-z' | sort -u > "$WORK/confirm.hosts" \
    || : > "$WORK/confirm.hosts"
  CONFIRM_N=$(wc -l < "$WORK/confirm.hosts")
  # FILENAME, NOT `NR == FNR`. The usual idiom breaks when the first file is
  # EMPTY: awk never reads a record from it, so NR and FNR stay equal into the
  # second file and every line is swallowed into the lookup array instead of
  # being printed. Here that would mean an empty confirm list silently emptying
  # popular.hits -- the tripwire reporting all-clear precisely because nothing
  # had been adjudicated yet. Guarding on FILENAME is correct for an empty file.
  LC_ALL=C awk -F'\t' -v first="$WORK/confirm.hosts" \
    'FILENAME == first { ok[$0]; next } !($2 in ok)' \
    "$WORK/confirm.hosts" "$WORK/popular.raw" > "$WORK/popular.hits"

  POPULAR_N=$(wc -l < "$WORK/popular.hits")
  REFUSE_N=$(awk -F'\t' -v r="$TRANCO_REFUSE_RANK" '$1 <= r' "$WORK/popular.hits" | wc -l)
  say "  popularity        : $POPULAR_N in the top $TRANCO_WARN_RANK, $REFUSE_N in the top $TRANCO_REFUSE_RANK"

  if [ "$REFUSE_N" -gt 0 ]; then
    say ""
    say "FAIL: $REFUSE_N host(s) in the Tranco top $TRANCO_REFUSE_RANK are in this build:"
    awk -F'\t' -v r="$TRANCO_REFUSE_RANK" '$1 <= r { printf "    #%-7s %s\n", $1, $2 }' \
      "$WORK/popular.hits" >&2
    say ""
    say "  A host this widely used is far more likely to be a feed error than a"
    say "  discovery, and blocking it takes its subdomains with it. Decide, then"
    say "  rerun:"
    say "    - a false positive -> add it to $ALLOW_FILE with a reason"
    say "    - genuinely malicious -> add it to $CONFIRM_FILE with a reason,"
    say "      which keeps it blocked and stops the tripwire re-asking"
    say ""
    say "  $OUT is unchanged."
    exit 1
  fi

  if [ "$POPULAR_N" -gt 0 ]; then
    say "    the following are popular enough to be worth a look, but not"
    say "    catastrophic enough to hold the build:"
    awk -F'\t' '{ printf "      #%-7s %s\n", $1, $2 }' "$WORK/popular.hits" >&2
  fi
fi
MERGED_N=$(wc -l < "$WORK/merged.hosts")
# Counted after filtering on both sides, so this is how many phishunt hosts
# actually reach the binary rather than how many the feed listed.
NEW_FROM_PH=$(comm -13 \
  <(filter_acceptable < "$WORK/pdb.hosts") \
  <(filter_acceptable < "$WORK/phishunt.hosts") | wc -l)
# What PhishDestroy adds over BOTH other feeds, which is the number that says
# whether a third source was worth adding at all. Measured 2026-08-10 before it
# was wired in: 175,519 of its 183,460 were absent from Phishing.Database.
NEW_FROM_PD=$(comm -13 \
  <(cat "$WORK/pdb.hosts" "$WORK/phishunt.hosts" | sort -u | filter_acceptable) \
  <(filter_acceptable < "$WORK/phishdestroy.hosts") | wc -l)
# What the ARCHIVE alone contributes: hosts neither feed is reporting today,
# retained from a previous window. This is the whole point of accumulating, so
# it is the number to watch -- if it stays at zero, the store is not working.
NEW_FROM_ARCHIVE=$(comm -13 \
  <(cat "$WORK/pdb.hosts" "$WORK/phishunt.hosts" | sort -u | filter_acceptable) \
  <(filter_acceptable < "$WORK/archive.hosts") | wc -l)

# PERSIST THE PER-SOURCE HOST LISTS. They only ever existed inside $WORK, which
# meant nothing downstream could answer "how many feeds report this host" --
# and that is the single best signal for spotting a false positive, because a
# host only one feed has ever mentioned is far weaker evidence than one three
# agree on. review-blocklist-fps.py reads these. Best-effort: a build must not
# fail because a review aid could not be written.
SNAPSHOT_DIR="${BLOCKLIST_SNAPSHOT_DIR:-/var/lib/patanyx-blocklist/sources}"
if mkdir -p "$SNAPSHOT_DIR" 2>/dev/null; then
  for pair in "Phishing.Database:pdb" "phishunt.io:phishunt" "PhishDestroy:phishdestroy"; do
    name="${pair%%:*}" file="${pair##*:}"
    # Same temp-then-rename discipline as everywhere else: a reader must never
    # catch one of these half-written.
    if cp "$WORK/$file.hosts" "$SNAPSHOT_DIR/.$name.tmp" 2>/dev/null; then
      mv "$SNAPSHOT_DIR/.$name.tmp" "$SNAPSHOT_DIR/$name.hosts" 2>/dev/null || true
    fi
  done
  say "  snapshots         : per-source host lists written to $SNAPSHOT_DIR"
else
  say "  snapshots         : cannot write $SNAPSHOT_DIR; corroboration data skipped"
fi

TODAY=$(date -u +%Y-%m-%d)
cat > "$WORK/out.txt" <<HEADER
# PATANYX bundled malicious-host floor.
#
# GENERATED FILE. Regenerate with scripts/build-blocklist.sh, which re-fetches
# every source, sanitises them and rewrites this whole file. Do not hand-edit:
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
# automatically for activity; the others publish detection-driven suspicion,
# and one says plainly that false positives occur. None warrants a claim
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
#    Plus $ARCHIVE_KEPT hosts retained from earlier phishunt windows (see
#    "RETAINED ENTRIES" below), of which $NEW_FROM_ARCHIVE appear in neither
#    source's current output.
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
# 3. PhishDestroy -- https://phishdestroy.io/ -- list.txt (their PRIMARY
#    dataset, not the aggregated community feed) -- $PD_N hosts, of which
#    $NEW_FROM_PD were not already covered by either list above.
#
# Creative Commons CC0 1.0 Universal (public domain dedication). From their
# dataset page: "Released under CC0 1.0 Universal -- no restrictions, no
# attribution required. Use freely for research, commercial products, or ML
# training. Repository code and tooling are separately licensed under MIT."
# Attribution is given here anyway, on the same principle as phishunt above.
#
# ONLY THE PRIMARY LIST IS USED. The same repository publishes a community
# feed aggregated from 13+ upstreams, and the account mirrors OpenPhish and
# GPL-3.0 sources among others. A CC0 dedication cannot pass on rights the
# original publishers withheld, and OpenPhish's no-redistribution term is the
# very reason it is refused further down this file. Primary is PhishDestroy's
# own investigative work, which is theirs to dedicate.
#
# WHY IT WAS ADDED. A single bulk source is a single point of failure, and
# Phishing.Database stopped publishing on 2026-08-01: the floors still passed
# and the merge still succeeded while 99.8% of the entries stopped moving.
# PhishDestroy is independent of it in both feed operator and data -- 175,519 of its
# 183,460 hosts were absent from that feed when measured -- so the two are
# unlikely to go quiet together.
#
# REMOVED ENTRIES. $ALLOW_REMOVED hosts that the sources above DO report were
# dropped from this list by scripts/blocklist-allow.txt, which carries $ALLOW_N
# hosts judged to be false positives -- popular, legitimate services a feed
# reported because phishing was hosted on them once. Each entry there records
# its reason. Subdomains are unaffected: an allowlisted \`example.com\` still
# leaves a feed's \`phish.example.com\` blocked.
#
# A further $UPSTREAM_FP_REMOVED were dropped because Phishing-Database has
# themselves retracted them as false positives ($UPSTREAM_FP_N retractions
# checked). Those retractions are published in their submission repo and do not
# reach the feed above while their pipeline is down, so applying them here is
# the only way a correction reaches this list promptly.
#
# RETAINED ENTRIES. phishunt publishes a rolling window of currently-live
# sites and prunes older ones; this list keeps what that window showed for up
# to $PHISHUNT_ARCHIVE_DAYS days after a host was LAST reported. So some entries above assert
# "was reported as phishing within the last $PHISHUNT_ARCHIVE_DAYS days" rather than "is being
# reported right now". That is a weaker claim than the live feeds make, and it
# is the reason for the expiry: a host nobody has reported in a month is
# dropped rather than blocked on the strength of an old sighting. Time is not
# the only test. A retained host that no live feed still reports must also keep
# resolving in DNS, and is dropped as soon as it does not, because a host that
# resolves nowhere cannot be serving a phishing page. The per-tab override in
# the blocked banner exists for the cases this still gets wrong.
#
# WHY THESE SOURCES. All three of the sources ABOVE are permissively licensed
# and redistributable inside a shipped browser; a further input, described
# under REMOVED ENTRIES, is only ever subtracted and is never redistributed.
#
# Feeds that are not redistributable were evaluated and rejected: OpenPhish
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
say "  new from PhishDestroy: $NEW_FROM_PD"
say "  from archive only : $NEW_FROM_ARCHIVE (of $ARCHIVE_KEPT retained)"
say "  allowlisted out   : $ALLOW_REMOVED (of $ALLOW_N listed)"
say "  upstream FPs out  : $UPSTREAM_FP_REMOVED (of $UPSTREAM_FP_N retracted)"
say ""
say "Next: cargo build   -- build.rs re-hashes and asserts >300k. Its"
say "                       'blocklist: N hosts' line must equal $MERGED_N."
say "      patanyx --emit-blocklist blocklist-N.bin"
say ""
say "\`entries\` in the signed manifest must be that same figure. It is"
say "post-acceptance and post-dedup; install_verified_list refuses any list"
say "parsing to under 90% of what was declared, so an inflated number breaks"
say "the refresh on every install rather than failing here."
