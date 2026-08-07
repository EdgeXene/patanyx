#!/usr/bin/env bash
# Is the compiled-in Public Suffix List still current, and still generated?
#
# WHY THIS EXISTS. `crates/app/src/public_suffix_list.txt` decides which saved
# password a page may be offered (see crates/app/src/psl.rs). It is a SNAPSHOT
# of a list that changes as registries add and retire suffixes, and it has no
# expiry of its own: a two-year-old copy compiles, passes every test, and ships
# a browser that is quietly wrong about who owns what.
#
# The failure direction is the dangerous one. A rule that exists upstream but
# is missing here makes some registrable domain LARGER -- more hosts look like
# "the same site" -- so a credential reaches further than the user agreed to.
# Nothing on screen would say so, and no unit test can notice, because the
# tests are written against the same stale file.
#
# WHY NOT IN build.rs, WHICH IS WHERE IT LOOKS LIKE IT BELONGS.
#
# A build that consults the wall clock stops being reproducible. `repro-build.sh`
# and `repro-verify.sh` exist so a tagged release can be rebuilt byte-for-byte
# later; a staleness assert in build.rs would make an old tag start FAILING to
# build on a date nobody chose, and would break offline builds of code that was
# perfectly correct when it was written. Staleness is a property of the
# DEVELOPMENT TREE, not of any particular build, so it is checked where the
# other tree-level gates are checked and never inside the compiler.
#
# NO NETWORK. It reads the header the generator wrote. Comparing against
# publicsuffix.org would turn every CI run into a third-party dependency and
# would fail closed when that host is unreachable, which is not a reason to
# stop a release.
#
# Run: scripts/psl-staleness-gate.sh   (also run by scripts/ci-trixie.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

LIST=crates/app/src/public_suffix_list.txt

# Warn early, fail late. The warning is the reminder; the failure is the
# backstop for when the reminder was ignored for two quarters running.
WARN_DAYS="${PSL_WARN_DAYS:-120}"
FAIL_DAYS="${PSL_FAIL_DAYS:-270}"

if [ ! -f "$LIST" ]; then
  echo "GATE FAIL: $LIST is missing, but psl.rs compiles it in." >&2
  echo "  Regenerate:  python3 scripts/build-psl.py" >&2
  exit 1
fi

# `|| true` on every header grep: without it `set -e` kills this script the
# instant a header line is absent, so the ONE case each check exists to explain
# -- a stripped or hand-mangled header -- exited silently with no message at
# all. Caught by running the check against that exact defect.
retrieved=$(grep -m1 '^# Retrieved:' "$LIST" | awk '{print $3}' || true)
if [ -z "$retrieved" ]; then
  echo "GATE FAIL: $LIST has no '# Retrieved:' header, so its age cannot be" >&2
  echo "  known. It is generated -- do not hand-edit it." >&2
  echo "  Regenerate:  python3 scripts/build-psl.py" >&2
  exit 1
fi

# --- the header must still describe the file -------------------------------
#
# Catches a hand-edit or a half-written file, which is the other way this data
# goes wrong. Offline, exact, and it costs nothing.
rules_line=$(grep -m1 '^# Rules:' "$LIST" || true)
if [ -z "$rules_line" ]; then
  echo "GATE FAIL: $LIST has no '# Rules:' header to check its contents" >&2
  echo "  against. It is generated -- do not hand-edit it." >&2
  echo "  Regenerate:  python3 scripts/build-psl.py" >&2
  exit 1
fi
declared=$(printf '%s' "$rules_line" | sed -E 's/^# Rules:[[:space:]]*([0-9]+).*/\1/')
declared_wild=$(printf '%s' "$rules_line" | sed -E 's/.*\(([0-9]+) wildcard.*/\1/')
declared_exc=$(printf '%s' "$rules_line" | sed -E 's/.*, ([0-9]+) exception.*/\1/')

actual=$(grep -cvE '^[[:space:]]*(#.*)?$' "$LIST")
actual_wild=$(grep -c '^\*\.' "$LIST" || true)
actual_exc=$(grep -c '^!' "$LIST" || true)

fail_count() {
  echo "GATE FAIL: $LIST says $2 $1 but contains $3." >&2
  echo "  The file is GENERATED and its header is part of it; a mismatch means" >&2
  echo "  it was hand-edited or written incompletely." >&2
  echo "  Regenerate:  python3 scripts/build-psl.py" >&2
  exit 1
}
[ "$declared"      = "$actual"      ] || fail_count "rules"           "$declared"      "$actual"
[ "$declared_wild" = "$actual_wild" ] || fail_count "wildcard rules"  "$declared_wild" "$actual_wild"
[ "$declared_exc"  = "$actual_exc"  ] || fail_count "exception rules" "$declared_exc"  "$actual_exc"

# --- age --------------------------------------------------------------------
then_s=$(date -u -d "$retrieved" +%s 2>/dev/null || true)
if [ -z "$then_s" ]; then
  echo "GATE FAIL: '# Retrieved: $retrieved' is not a date this can read." >&2
  exit 1
fi
now_s=$(date -u +%s)
age=$(( (now_s - then_s) / 86400 ))

if [ "$age" -lt 0 ]; then
  echo "GATE FAIL: $LIST claims it was retrieved $retrieved, which is in the" >&2
  echo "  future. Either the header is wrong or this machine's clock is." >&2
  exit 1
fi

echo "  psl: $actual rules ($actual_wild wildcard, $actual_exc exception), retrieved $retrieved, ${age}d old"

if [ "$age" -ge "$FAIL_DAYS" ]; then
  echo "GATE FAIL: the Public Suffix List is ${age} days old (limit ${FAIL_DAYS})." >&2
  echo "  It decides which saved password a page is offered. Every rule added" >&2
  echo "  upstream since $retrieved is one this browser does not know about," >&2
  echo "  and a missing rule makes a registrable domain WIDER -- so a" >&2
  echo "  credential reaches further than its owner agreed to, silently." >&2
  echo "" >&2
  echo "  Regenerate and commit:" >&2
  echo "      python3 scripts/build-psl.py" >&2
  echo "      cargo test -p patanyx psl::" >&2
  exit 1
fi

if [ "$age" -ge "$WARN_DAYS" ]; then
  echo "  WARNING: the Public Suffix List is ${age} days old (fails at ${FAIL_DAYS})."
  echo "           Refresh with: python3 scripts/build-psl.py"
fi

echo "PSL STALENESS OK"
