#!/usr/bin/env bash
# Regenerates the Tranco popularity reference the blocklist tripwire checks
# against, at /var/lib/patanyx-blocklist/tranco-top100k.txt.
#
# THE SNAPSHOT IS NOT IN THE REPO and this script does not put it there -- see
# the WRITES TO THE BUILD BOX block below for the licensing reason. What this
# script produces FOR THE REPO is a single line in scripts/tranco-snapshot.sha256,
# and that pin is the thing to commit.
#
# RUN THIS RARELY AND DELIBERATELY. It is not on a timer, and that is the point:
# the tripwire's job is to refuse hosts that a human has not adjudicated, so a
# reference list that refreshed itself would let a domain's popularity change
# silently flip a build from passing to failing -- or, worse, quietly retire a
# tripwire that was catching something. Regenerate when the snapshot is a few
# months stale, look at what changed, then commit the updated PIN as its own
# visible change.
#
# Run:  ./scripts/refresh-tranco.sh
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

# WRITES TO THE BUILD BOX, NOT THE REPO. Tranco publishes no licence, and the
# list it serves is composed from providers including Cloudflare Radar
# (CC BY-NC) and Chrome CrUX (CC BY-SA). Local use to decide what to ask a human
# about is not redistribution; committing an extract would be. What goes in the
# repo is the HASH, in scripts/tranco-snapshot.sha256, which records which
# snapshot a build was adjudicated against without copying any of it.
OUT="${BLOCKLIST_TRANCO_FILE:-/var/lib/patanyx-blocklist/tranco-top100k.txt}"
# Overridable so tranco-autorefresh.sh can generate a CANDIDATE snapshot without
# recording its hash as though it were in use. Only an installed snapshot earns
# a line in the committed pin.
PIN="${BLOCKLIST_TRANCO_PIN:-scripts/tranco-snapshot.sha256}"
URL="https://tranco-list.eu/top-1m.csv.zip"
KEEP=100000

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

say() { printf '%s\n' "$*" >&2; }

say "fetching $URL ..."
curl -fsSL --proto =https --proto-redir =https --retry 3 --retry-all-errors \
  --connect-timeout 15 --max-time 300 --max-filesize 50000000 \
  -o "$WORK/tranco.zip" "$URL" || {
  say "FAIL: could not fetch the Tranco list. $OUT is unchanged."
  exit 1
}

python3 - "$WORK/tranco.zip" "$WORK/ranked.txt" "$KEEP" <<'PY'
import sys, zipfile

src, dst, keep = sys.argv[1], sys.argv[2], int(sys.argv[3])
with zipfile.ZipFile(src) as z:
    rows = z.read(z.namelist()[0]).decode("utf-8", "replace").splitlines()

# Rank order is the whole payload here: the build reports a rank by line number,
# so a reordering would silently misreport every rank it prints.
out = []
for i, row in enumerate(rows[:keep], 1):
    parts = row.split(",")
    if len(parts) != 2 or parts[0].strip() != str(i):
        raise SystemExit("unexpected row %d: %r -- format changed, refusing" % (i, row))
    out.append(parts[1].strip().lower())

if len(out) < keep:
    raise SystemExit("only %d rows, expected %d -- truncated download" % (len(out), keep))
with open(dst, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
PY

# The header prose survives a refresh; only the retrieval date changes. On a
# first run there is no existing file to take it from, so fall back to a stub.
if [ -f "$OUT" ] && grep -q '^# Retrieved:' "$OUT"; then
  sed -n '1,/^# Retrieved:/p' "$OUT" | sed '$d' > "$WORK/header.txt"
else
  cat > "$WORK/header.txt" <<'STUB'
# Tranco top-100,000 domains -- popularity reference for the blocklist tripwire
# in build-blocklist.sh. NOT redistributable: Tranco grants no licence and the
# list carries CC BY-NC and CC BY-SA components, so this file stays on the build
# box and only its hash is committed (scripts/tranco-snapshot.sha256).
#
# Source: https://tranco-list.eu/ (Le Pochat et al., NDSS 2019). Composed from
# Cloudflare Radar (CC BY-NC 4.0), Chrome CrUX (CC BY-SA 4.0), Majestic
# (CC BY 3.0), Cisco Umbrella and Farsight.
#
# Ranked order is preserved: line N among data lines is rank N.
#
# Regenerate with scripts/refresh-tranco.sh.
STUB
fi
{
  cat "$WORK/header.txt"
  printf '# Retrieved: %s\n#\n' "$(date -u +%Y-%m-%d)"
  cat "$WORK/ranked.txt"
} > "$WORK/out.txt"

OLD_N=0
[ -f "$OUT" ] && OLD_N=$(grep -cvE '^\s*(#|$)' "$OUT" || echo 0)
NEW_N=$(grep -cvE '^\s*(#|$)' "$WORK/out.txt")
say "  was $OLD_N domains, now $NEW_N"

install -d -m 755 "$(dirname "$OUT")"
cp "$WORK/out.txt" "$OUT.tmp.$$"
mv "$OUT.tmp.$$" "$OUT"
say "wrote $OUT"

# The pin is the only part of this that enters the repo, and it is append-only:
# an old hash still explains an old build's verdicts, so nothing is rewritten.
NEW_SHA="$(sha256sum "$OUT" | awk '{print $1}')"
if grep -q "^$NEW_SHA " "$PIN" 2>/dev/null; then
  say "  hash already recorded in $PIN"
else
  printf '%s  %s  %s\n' "$NEW_SHA" "$(date -u +%Y-%m-%d)" "$NEW_N" >> "$PIN"
  say "  recorded $NEW_SHA in $PIN"
fi
say ""
say "Commit $PIN. A domain entering the top 100k can arm a tripwire and one"
say "leaving it can disarm one, so the next build may refuse where the last"
say "passed -- that is the mechanism working, but look at it deliberately."
