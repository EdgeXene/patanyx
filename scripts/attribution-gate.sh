#!/usr/bin/env bash
# The attribution shown inside the browser must describe the binary being built.
#
# WHY THIS IS A GATE AND NOT A REMINDER.
#
# The About panel names every third-party package compiled into this binary,
# and that list is a checked-in file. Checked-in files go stale silently. Add a
# dependency, forget to regenerate, and the browser goes on telling users it is
# built from a set of software that no longer matches what it is built from --
# and it does so with the confidence of a generated document.
#
# Under-reporting is the direction that matters. THIRD_PARTY_LICENSES.md is
# allowed to over-report because it is the union across every build; this file
# is not, because it is an answer to "what am I running". An attribution that
# omits a package is not merely untidy: MIT, BSD and ISC all require the
# copyright notice to travel with the binary, so a missing entry is a licence
# term unmet, not a formatting slip.
#
# Regenerates into a scratch directory and diffs. Never writes over the tree it
# is checking.
#
# Run: scripts/attribution-gate.sh
set -euo pipefail
cd "$(dirname "$0")/.."

LIVE=crates/app/src/chrome/attribution
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ ! -d "$LIVE" ]; then
  echo "GATE FAIL: $LIVE does not exist. Run scripts/shipping-licenses.py." >&2
  exit 1
fi

echo "regenerating attribution into a scratch directory..."
python3 scripts/shipping-licenses.py "$TMP" >/dev/null

status=0
for f in "$TMP"/*.txt; do
  name=$(basename "$f")
  if [ ! -f "$LIVE/$name" ]; then
    echo "GATE FAIL: $LIVE/$name is missing." >&2
    echo "  A shipped configuration has no attribution compiled into it." >&2
    status=1
    continue
  fi
  if ! diff -q "$f" "$LIVE/$name" >/dev/null; then
    echo "GATE FAIL: $LIVE/$name is out of date." >&2
    echo >&2
    echo "  The dependency tree no longer matches the attribution shipped in" >&2
    echo "  the binary. Packages added or removed since it was generated:" >&2
    echo >&2
    diff <(grep -E "^  [a-zA-Z0-9_-]+ [0-9]" "$LIVE/$name" || true) \
      <(grep -E "^  [a-zA-Z0-9_-]+ [0-9]" "$f" || true) |
      grep -E "^[<>]" | head -20 >&2 || true
    echo >&2
    echo "  Fix: python3 scripts/shipping-licenses.py, then commit." >&2
    status=1
  fi
done

# The reverse direction: a checked-in file for a configuration the generator no
# longer produces is an orphan, and orphans get included by a stale cfg arm.
for f in "$LIVE"/*.txt; do
  name=$(basename "$f")
  if [ ! -f "$TMP/$name" ]; then
    echo "GATE FAIL: $LIVE/$name has no matching configuration." >&2
    echo "  Either CONFIGS in scripts/shipping-licenses.py lost an entry, or" >&2
    echo "  this file is left over from a configuration that no longer ships." >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  exit 1
fi

for f in "$LIVE"/*.txt; do
  n=$(grep -m1 -oE "^[0-9]+ third-party packages" "$f" | grep -oE "^[0-9]+" || echo "?")
  printf '  %-22s %s packages\n' "$(basename "$f")" "$n"
done
echo "ATTRIBUTION OK"
