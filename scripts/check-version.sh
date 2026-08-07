#!/usr/bin/env bash
# The version in crates/app/Cargo.toml and the version in the AppStream
# metainfo must be the same number.
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

echo "  version ok: $cargo_version (Cargo.toml == metainfo)"

# Negative control. A gate that has never been observed to fail is a gate
# nobody has tested, and this one is two greps that could each silently
# return empty. Plant a mismatch in a COPY and require the failure.
if [ "${PATANYX_VERSION_GATE_CONTROL:-}" != "1" ]; then
  probe="$(mktemp -d)"
  trap 'rm -rf "$probe"' EXIT
  mkdir -p "$probe/crates/app" "$probe/packaging/flatpak" "$probe/scripts"
  sed 's/^version = .*/version = "0.0.0-planted"/' "$CARGO" \
    > "$probe/$CARGO"
  cp "$META" "$probe/$META"
  cp "$0" "$probe/scripts/check-version.sh"
  if PATANYX_VERSION_GATE_CONTROL=1 bash "$probe/scripts/check-version.sh" \
      >/dev/null 2>&1; then
    echo "GATE FAIL: a planted version mismatch was not detected" >&2
    exit 1
  fi
  echo "  (detector verified against a planted mismatch)"
fi
