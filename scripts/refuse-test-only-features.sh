#!/usr/bin/env bash
# Refuses a cargo feature list that would compile a test-only surface into a
# binary someone could be handed. Called, before anything is built, by every
# script that takes a feature list from its caller: build-windows.sh,
# build-flatpak.sh and repro-build.sh (and so repro-verify.sh).
#
# Today that is one feature, the fuzz workspace's pass-throughs into the app
# (crates/app/Cargo.toml). premium-unlocked is NOT here on purpose: the
# Windows script builds it deliberately as a labelled hardware-test variant,
# and the forbidden-marker scan keeps it out of anything published.
#
# EVERY SPELLING CARGO ACCEPTS, not only a bare name: repro-build.sh forwards
# its arguments to cargo, and build-flatpak.sh expands FEATURES unquoted into
# a cargo command line, so an option can arrive in place of a feature name.
# `--features=X`, `-FX`, `-F X`, `--features X`, `pkg/X` and `--all-features`
# (which enables every declared feature, this one included) are all refused.
# Found by independent review, 2026-10-30, after the first version read only
# bare names and `pkg/` suffixes.
#
#   refuse-test-only-features.sh "<features or cargo arguments, commas and spaces>"
# Exit 0 = nothing test-only named, 3 = refused (the reason on stderr).
set -euo pipefail
REFUSED="fuzz-api"
refuse() {
  echo "BUILD REFUSED: '$1' would compile a test-only feature (the fuzz pass-throughs);" >&2
  echo "  no build script may. Fuzz with cargo fuzz in fuzz/, which enables it itself." >&2
  exit 3
}
for item in $(printf '%s' "${*:-}" | tr ',' ' '); do
  case "$item" in
    --all-features) refuse "$item" ;;
    --features=*) name="${item#--features=}" ;;
    -F?*) name="${item#-F}" ;;
    *) name="$item" ;;
  esac
  # `--features=a,b` was split on the comma above, so `name` is one feature,
  # possibly qualified by its package.
  if [ "$name" = "$REFUSED" ] || [ "${name##*/}" = "$REFUSED" ]; then
    refuse "$item"
  fi
done
