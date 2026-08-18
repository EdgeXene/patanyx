#!/usr/bin/env bash
# Unit tests for the phishunt archive accumulator in build-blocklist.sh.
#
# WHY THESE AND NOT A FULL BUILD. The accumulator is the only new state in the
# pipeline, it is the only part that RETAINS a decision for weeks after the
# fact, and every one of its failure paths is supposed to degrade to a warning
# rather
# than stop a publish. Those are exactly the properties an end-to-end run
# cannot demonstrate: a real build exercises one moment in the store's life,
# while the interesting behaviour is what happens across the whole window, a corrupt
# file and a skewed clock.
#
# The accumulator's python is extracted from build-blocklist.sh at run time
# rather than copied here, for the same reason the protected-suffix list is
# parsed out of hostrules.rs: a copy would drift and the tests would go on
# passing against code that no longer ships.
#
# Run:  ./scripts/test-phishunt-archive.sh
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

SCRIPT=scripts/build-blocklist.sh
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
check() { # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 -- expected [$2], got [$3]"; fi
}

# Pull the accumulator's python body out of the shipped script: everything
# between the heredoc that starts it and the PY that closes it.
ACC=$WORK/accumulate.py
sed -n "/^      \"\$WORK\/archive.hosts\" \"\$((PHISHUNT_ARCHIVE_DAYS \* 86400))\" <<'PY'\$/,/^PY\$/p" \
  "$SCRIPT" | sed '1d;$d' > "$ACC"
if [ ! -s "$ACC" ]; then
  echo "FAIL: could not extract the accumulator from $SCRIPT -- it moved or was" >&2
  echo "  reformatted. Fix this extraction, or the tests silently test nothing." >&2
  exit 1
fi

TTL=$((30 * 86400))

# run <archive> <observed-file> [ttl] -> prints "kept<TAB>added<TAB>expired"
run() { python3 "$ACC" "$1" "$2" "$WORK/out.hosts" "${3:-$TTL}"; }

now() { date -u +%s; }

# age_entry <archive> <host> <seconds-ago>  -- rewrite lastSeen into the past
age_entry() {
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys, time
path, host, ago = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = json.load(open(path))
d["hosts"][host]["lastSeen"] = int(time.time()) - ago
json.dump(d, open(path, "w"))
PY
}

echo "phishunt archive accumulator"

# --- seeding ---------------------------------------------------------------
A=$WORK/a1.json
printf 'evil.example\nbad.example\n' > "$WORK/obs1"
R=$(run "$A" "$WORK/obs1")
check "seeds an empty archive" "2	2	0" "$R"
check "emits both hosts" "bad.example evil.example" "$(tr '\n' ' ' < "$WORK/out.hosts" | sed 's/ $//')"
check "archive file is owner-only" "600" "$(stat -c %a "$A")"

# --- accumulation across windows -------------------------------------------
# The whole point: a host that DROPS OUT of the window stays in the archive.
printf 'bad.example\nnew.example\n' > "$WORK/obs2"
R=$(run "$A" "$WORK/obs2")
check "retains a host absent from the new window" "3	1	0" "$R"
check "evil.example survived its disappearance" "yes" \
  "$(grep -qx 'evil.example' "$WORK/out.hosts" && echo yes || echo no)"

# --- expiry ----------------------------------------------------------------
age_entry "$A" evil.example $((31 * 86400))
# Both of obs2's hosts are already known by now, so nothing is added: the
# archive goes 3 -> 2 purely by dropping the expired one.
R=$(run "$A" "$WORK/obs2")
check "expires a host unseen for 31 days" "2	0	1" "$R"
check "expired host is gone from output" "no" \
  "$(grep -qx 'evil.example' "$WORK/out.hosts" && echo yes || echo no)"

# A host at 29 days is still inside the window and must NOT be dropped: the
# boundary is where an off-by-one silently shortens retention.
age_entry "$A" new.example $((29 * 86400))
R=$(run "$A" "$WORK/obs2" )
check "29-day-old host survives (boundary)" "yes" \
  "$(grep -qx 'new.example' "$WORK/out.hosts" && echo yes || echo no)"

# --- re-confirmation --------------------------------------------------------
# Retention runs from LAST observation, so a host reported again gets a fresh
# full window. Without this, long-lived phishing hosts age out while still live.
B=$WORK/b.json
printf 'old.example\n' > "$WORK/obsB"
run "$B" "$WORK/obsB" >/dev/null
SEEDED_FIRST=$(python3 -c "import json; print(json.load(open('$B'))['hosts']['old.example']['firstSeen'])")
age_entry "$B" old.example $((29 * 86400))
run "$B" "$WORK/obsB" >/dev/null          # observed again at day 29
age_entry "$B" old.example $((10 * 86400))  # 10 days after that re-confirmation
R=$(run "$B" "$WORK/obsB")
check "re-observation restarts the clock" "yes" \
  "$(grep -qx 'old.example' "$WORK/out.hosts" && echo yes || echo no)"
# Compared against the value seeded at the start, not against lastSeen: the
# whole test runs inside one second, so the two are legitimately equal and
# `firstSeen < lastSeen` would fail on correct code.
check "firstSeen is preserved across re-observation" "$SEEDED_FIRST" \
  "$(python3 -c "import json; print(json.load(open('$B'))['hosts']['old.example']['firstSeen'])")"

# --- corrupt and hostile state ---------------------------------------------
C=$WORK/c.json
echo 'this is not json' > "$C"
R=$(run "$C" "$WORK/obs1")
check "corrupt archive re-seeds instead of failing" "2	2	0" "$R"

printf '{"hosts": {"good.example": {"firstSeen": 1, "lastSeen": %s}, "bad": "not-a-record", "worse.example": {"firstSeen": "x"}}}\n' "$(now)" > "$C"
R=$(run "$C" "$WORK/obs1")
check "keeps good records, discards garbage ones" "3	2	0" "$R"

# A future lastSeen must not buy indefinite retention.
D=$WORK/d.json
printf '{"hosts": {"future.example": {"firstSeen": 1, "lastSeen": %s}}}\n' "$(( $(now) + 400 * 86400 ))" > "$D"
: > "$WORK/empty"
run "$D" "$WORK/empty" >/dev/null
check "future timestamp is clamped to now" "yes" \
  "$(python3 -c "
import json,time
d=json.load(open('$D'))['hosts']['future.example']
print('yes' if d['lastSeen'] <= int(time.time()) else 'no')")"

# --- empty window -----------------------------------------------------------
# A window that returns nothing must never be read as "retract everything".
E=$WORK/e.json
run "$E" "$WORK/obs1" >/dev/null
R=$(run "$E" "$WORK/empty")
check "empty window removes nothing" "2	0	0" "$R"

# --- non-fatal failure in the shipped script --------------------------------
# The accumulator writing to a path it cannot create must warn and continue,
# not abort a publish. Exercised through the real script's guard.
UNWRITABLE=/proc/definitely-not-writable/archive.json
OUT=$(
  BLOCKLIST_PHISHUNT_ARCHIVE_FILE=$UNWRITABLE \
  bash -c '
    set -euo pipefail
    say() { printf "%s\n" "$*" >&2; }
    WORK=$(mktemp -d); trap "rm -rf $WORK" EXIT
    : > "$WORK/phishunt.hosts"
    PHISHUNT_ARCHIVE_DAYS=30
    PHISHUNT_ARCHIVE_FILE="$BLOCKLIST_PHISHUNT_ARCHIVE_FILE"
    ARCHIVE_KEPT=0; ARCHIVE_ADDED=0; ARCHIVE_EXPIRED=0
    : > "$WORK/archive.hosts"
    '"$(sed -n '/^accumulate_phishunt_archive() {$/,/^}$/p' "$SCRIPT")"'
    accumulate_phishunt_archive
    echo "survived"
  ' 2>&1
)
check "unwritable archive dir warns and continues" "yes" \
  "$(echo "$OUT" | grep -q survived && echo yes || echo no)"
check "  and says so" "yes" \
  "$(echo "$OUT" | grep -q 'accumulation skipped' && echo yes || echo no)"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
