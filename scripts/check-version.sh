#!/usr/bin/env bash
# The version in crates/app/Cargo.toml and the version in the AppStream
# metainfo must be the same release number supplied by the caller.
#
# WHY THIS EXISTS. They drifted, silently, from 0.9.0 to 0.9.52. The metainfo
# even carried a comment declaring the drift resolved -- accurate the day it
# was written, wrong five bumps later, and nothing in the suite compared the
# two. AppStream's version is what a software centre shows and what
# `flatpak info` reports, so the drift told Linux users they were running a
# version that had not existed for days.
#
# Cheap enough to run everywhere: no network, no toolchain, no build.
set -euo pipefail
cd "$(dirname "$0")/.."

CARGO=crates/app/Cargo.toml
META=packaging/flatpak/io.edgexene.Patanyx.metainfo.xml

if [ -z "${EXPECTED_VERSION:-}" ]; then
  echo "GATE FAIL: EXPECTED_VERSION is required" >&2
  echo "  pass the release being built, for example EXPECTED_VERSION=0.9.66" >&2
  exit 2
fi

for f in "$CARGO" "$META"; do
  [ -f "$f" ] || { echo "GATE FAIL: $f is missing" >&2; exit 1; }
done

# The FIRST `version =` under [package]. Anchored so a dependency's version
# line can never be picked up instead -- this gate reporting a dependency's
# number as the app's would be worse than not running.
cargo_version="$(awk '
  /^\[package\]/ { in_pkg = 1; next }
  /^\[/          { in_pkg = 0 }
  in_pkg && /^version[ \t]*=/ {
    gsub(/^version[ \t]*=[ \t]*"|"[ \t]*$/, "")
    print
    exit
  }
' "$CARGO")"

# The NEWEST release entry, which is the one AppStream reports as current.
# `<releases>` is ordered newest-first by convention and appstreamcli warns
# when it is not, so the first match is the right one.
meta_version="$(grep -oE '<release[ \t]+version="[^"]+"' "$META" \
  | head -1 | sed 's/.*version="//; s/"//')"

if [ -z "$cargo_version" ]; then
  echo "GATE FAIL: no [package] version in $CARGO" >&2
  exit 1
fi
if [ -z "$meta_version" ]; then
  echo "GATE FAIL: no <release version=...> in $META" >&2
  exit 1
fi

if [ "$cargo_version" != "$meta_version" ]; then
  echo "GATE FAIL: version drift" >&2
  echo "  $CARGO : $cargo_version" >&2
  echo "  $META  : $meta_version" >&2
  echo "  Add a <release> entry for $cargo_version, newest first." >&2
  exit 1
fi

if [ "$cargo_version" != "$EXPECTED_VERSION" ]; then
  echo "GATE FAIL: release identity mismatch" >&2
  echo "  expected : $EXPECTED_VERSION" >&2
  echo "  $CARGO : $cargo_version" >&2
  echo "  $META  : $meta_version" >&2
  exit 1
fi

echo "  version ok: $cargo_version (expected == Cargo.toml == metainfo)"

# The newest release's text is what a software centre shows. 1.1.2 carried a
# DRAFT placeholder there while it was built, written so the version could be
# bumped before the copy existed; it must never ship.
newest_release="$(awk '/<release[ \t]/ { on = 1 } on { print } on && /<\/release>/ { exit }' "$META")"
if printf '%s\n' "$newest_release" | grep -q 'DRAFT'; then
  echo "GATE FAIL: the newest <release> entry in $META still says DRAFT" >&2
  exit 1
fi
echo "  release text ok: no DRAFT in the $meta_version entry"

# Negative controls. A gate that has never been observed to fail is a gate
# nobody has tested, and this one is greps that could each silently return
# empty. Plant each failure in a COPY and require it.
if [ "${PATANYX_VERSION_GATE_CONTROL:-}" != "1" ]; then
  probe="$(mktemp -d)"
  probe2="$(mktemp -d)"
  trap 'rm -rf "$probe" "$probe2"' EXIT
  mkdir -p "$probe/crates/app" "$probe/packaging/flatpak" "$probe/scripts"
  sed 's/^version = .*/version = "0.0.0-planted"/' "$CARGO" \
    > "$probe/$CARGO"
  cp "$META" "$probe/$META"
  cp "$0" "$probe/scripts/check-version.sh"
  if EXPECTED_VERSION="$EXPECTED_VERSION" PATANYX_VERSION_GATE_CONTROL=1 \
      bash "$probe/scripts/check-version.sh" \
      >/dev/null 2>&1; then
    echo "GATE FAIL: a planted version mismatch was not detected" >&2
    exit 1
  fi
  echo "  (detector verified against a planted mismatch)"
  mkdir -p "$probe2/crates/app" "$probe2/packaging/flatpak" "$probe2/scripts"
  cp "$CARGO" "$probe2/$CARGO"
  # Inside the newest <release>, not the first <p> of the file (that one is
  # the app's own description).
  awk '/<release[ \t]/ { in_rel = 1 }
       in_rel && !done && /<p>/ { sub(/<p>/, "<p>DRAFT: planted. "); done = 1 }
       { print }' "$META" > "$probe2/$META"
  cp "$0" "$probe2/scripts/check-version.sh"
  if EXPECTED_VERSION="$EXPECTED_VERSION" PATANYX_VERSION_GATE_CONTROL=1 \
      bash "$probe2/scripts/check-version.sh" \
      >/dev/null 2>&1; then
    echo "GATE FAIL: a planted DRAFT release text was not detected" >&2
    exit 1
  fi
  echo "  (detector verified against a planted DRAFT)"
fi
