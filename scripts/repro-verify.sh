#!/usr/bin/env bash
# repro-verify.sh — prove the build is reproducible, rather than assert it.
#
# Builds twice while varying the two things that actually broke it, and fails if
# the hashes differ:
#
#   1. CARGO_HOME. This is the one that was really wrong. Dependency panic
#      locations carry the registry's absolute path, so before the fix two
#      builds of identical source differed purely because one builder's home
#      was /root and another's was not.
#   2. The source directory. Already fine — cargo passes workspace members as
#      relative paths — but varying it is what makes the test honest. Testing
#      only this is what made the build look reproducible when it was not.
#
# Deliberately NOT varied here: the toolchain (pinned by rust-toolchain.toml)
# and the host OS. Cross-OS reproducibility is a separate, harder claim and
# this script does not make it.
#
# Usage: scripts/repro-verify.sh [--features <list>] [workdir]
#
# --features is forwarded to BOTH builds, so the one-time Linux bridge build
# (`--features linux-bridge`) gets the same proof as the strict one. The
# resulting binary is then asked `--build-identity`, so a features list that
# did not take effect fails here instead of passing as a strict build.
#
# The reproduced binary is also scanned for the markers of a build that is
# never published (chat, premium-unlocked) and for unremapped build paths,
# from the one list in scripts/forbidden-build-markers.py. `--build-identity`
# cannot catch a chat build: it reports the same variant as the public one.
# A features list that compiles either in therefore fails here; this script
# proves what is about to be published, nothing else.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
FEATURES=()
if [ "${1:-}" = "--features" ]; then
  [ $# -ge 2 ] || { echo "--features needs a list" >&2; exit 2; }
  FEATURES=(--features "$2")
  shift 2
fi
WORK="${1:-$(mktemp -d)}"
CLEAN_WORK=0
[ $# -eq 0 ] && CLEAN_WORK=1
mkdir -p "$WORK"
# An `if`, not `[ ... ] && rm`: the EXIT trap's last status becomes the
# script's, so with a workdir given (nothing to clean) the `&&` form turned
# every successful run into exit 1. Measured 2026-10-11 on a reproducible
# strict build: "REPRODUCIBLE: ..." printed, exit status 1.
cleanup() { if [ "$CLEAN_WORK" = 1 ]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT

echo "workdir: $WORK"

# Build A: this checkout, this cargo home.
echo
echo "--- build A: original path, original CARGO_HOME"
CARGO_TARGET_DIR="$WORK/target-a" ./scripts/repro-build.sh "${FEATURES[@]}" >/dev/null
HASH_A="$(sha256sum "$WORK/target-a/release/patanyx" | cut -d' ' -f1)"
echo "A: $HASH_A"

# Build B: a different checkout path AND a different CARGO_HOME. Hardlinking the
# registry keeps this cheap; it is a different path, which is the whole point.
echo
echo "--- build B: different path, different CARGO_HOME"
rm -rf "$WORK/src" "$WORK/cargo"
git clone -q "$ROOT" "$WORK/src"
git -C "$WORK/src" checkout -q "$(git -C "$ROOT" rev-parse HEAD)"
mkdir -p "$WORK/cargo"
cp -al "${CARGO_HOME:-$HOME/.cargo}/registry" "$WORK/cargo/registry" 2>/dev/null \
  || cp -a "${CARGO_HOME:-$HOME/.cargo}/registry" "$WORK/cargo/registry"
( cd "$WORK/src" \
  && CARGO_HOME="$WORK/cargo" CARGO_TARGET_DIR="$WORK/target-b" \
     ./scripts/repro-build.sh "${FEATURES[@]}" >/dev/null )
HASH_B="$(sha256sum "$WORK/target-b/release/patanyx" | cut -d' ' -f1)"
echo "B: $HASH_B"

echo
if [ "$HASH_A" = "$HASH_B" ]; then
  echo "REPRODUCIBLE: $HASH_A"
  # Which variant was proven, from the binary itself (Linux builds only;
  # elsewhere the flag is not run).
  if [ "$(uname -s)" = "Linux" ]; then
    IDENT="$("$WORK/target-a/release/patanyx" --build-identity 2>/dev/null || true)"
    echo "identity: $IDENT"
    case " ${FEATURES[*]:-} " in
      *linux-bridge*) echo "$IDENT" | grep -q '"variant":"bridge"' \
        || { echo "FAIL: --features linux-bridge but the binary is not the bridge" >&2; exit 1; } ;;
      *) echo "$IDENT" | grep -q '"variant":"strict"' \
        || { echo "FAIL: expected the strict build" >&2; exit 1; } ;;
    esac
  fi
  # A and B are byte-identical here, so scanning A covers both.
  python3 -I "$ROOT/scripts/forbidden-build-markers.py" "$WORK/target-a/release/patanyx" \
    || { echo "FAIL: the reproduced binary is not one that may be published" >&2; exit 1; }
  exit 0
fi
echo "NOT REPRODUCIBLE" >&2
echo "  A: $HASH_A" >&2
echo "  B: $HASH_B" >&2
echo "Compare with: diff <(strings -a $WORK/target-a/release/patanyx | sort -u) \\" >&2
echo "                  <(strings -a $WORK/target-b/release/patanyx | sort -u)" >&2
exit 1
