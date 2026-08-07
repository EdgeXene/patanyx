#!/usr/bin/env bash
# repro-build.sh — build PATANYX so that the resulting binary depends only on
# the source, not on who built it or where.
#
# WHY THIS EXISTS. "Private by architecture" is a claim about the code. Nobody
# runs the code — they run a binary. Without a reproducible build the only way
# to believe the binary matches the source is to trust whoever produced it,
# which is exactly the trust the project is trying not to require. With one,
# anyone can rebuild and compare hashes.
#
# WHAT WAS ACTUALLY BROKEN. rustc embeds the absolute path of every source file
# that can appear in a panic location. Our own crates were already fine, because
# cargo passes workspace members as relative paths — so moving the checkout
# changed nothing and the build LOOKED reproducible. Dependencies were not: the
# binary carried strings like
#     /root/.cargo/registry/src/index.crates.io-<hash>/gtk-0.18.2/src/...
# so a verifier whose home was not /root got a different binary. Measured, on
# the same machine and same source, only CARGO_HOME differing:
#     /root/.cargo  -> 67370fab...
#     alternate     -> fa97df92...
# Both flags below are therefore load-bearing; drop either and the hash becomes
# a property of the builder's filesystem again.
#
# Usage: scripts/repro-build.sh [--features <list>]
# Prints the SHA-256 of the binary. Compare it with a published hash, or with
# what someone else's machine produces.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

# Normalize the two path roots that reach the binary. Computed at runtime rather
# than checked into .cargo/config.toml, because a hardcoded /root/.cargo would
# only ever be correct on one machine — which would defeat the entire point.
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME_DIR}=/cargo --remap-path-prefix=${ROOT}=/build ${RUSTFLAGS:-}"

# Incremental compilation splits codegen differently depending on what was built
# before, so a clean build and a rebuild can differ. Releases are never
# incremental.
export CARGO_INCREMENTAL=0

# Consumed by anything that stamps a build time. Fixed to the source's own
# commit date when we are in a git checkout, so the timestamp is a property of
# the code rather than of when the build ran.
if [ -z "${SOURCE_DATE_EPOCH:-}" ] && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)"
  [ -n "$SOURCE_DATE_EPOCH" ] && export SOURCE_DATE_EPOCH
fi

# --locked: the lockfile is an input to the binary. Resolving a fresh dependency
# version mid-build would change the output while the source looked untouched.
cargo build --release --locked "$@"

# Honour CARGO_TARGET_DIR. Hardcoding target/release meant that when the caller
# redirected the target dir, this looked at whatever stale binary happened to
# sit in the default location — so the path guard below could pass while the
# artifact just built was never examined at all.
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="$TARGET_DIR/release/patanyx"
[ -f "$BIN" ] || { echo "repro-build.sh: $BIN not produced" >&2; exit 1; }

# A leftover absolute path means the normalization missed a root and the hash is
# still builder-specific. Fail loudly rather than publish a hash that only
# verifies on this machine.
if strings -a "$BIN" | grep -qE "${CARGO_HOME_DIR}|^${ROOT}/|/\.cargo/registry"; then
  echo "repro-build.sh: FAIL — build paths are still embedded in the binary:" >&2
  strings -a "$BIN" | grep -E "${CARGO_HOME_DIR}|^${ROOT}/|/\.cargo/registry" | head -5 >&2
  exit 1
fi

echo
echo "toolchain: $(rustc --version)"
echo "commit:    $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo 'not a git checkout')"
echo "sha256:    $(sha256sum "$BIN" | cut -d' ' -f1)"
