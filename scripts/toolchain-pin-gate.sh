#!/usr/bin/env bash
# Every build path that installs its own Rust must install the pinned one.
#
# WHY THIS IS A GATE AND NOT A COMMENT. rust-toolchain.toml is a RUSTUP
# mechanism. It governs any build that goes through a rustup shim, and it
# governs nothing else. Two build paths here install a toolchain themselves and
# never consult it:
#
#   - the Flatpak, which unpacks a checksummed tarball into the sandbox and then
#     calls cargo by ABSOLUTE PATH, with no rustup present and no network to
#     fetch anything else. The manifest copies rust-toolchain.toml into the
#     build tree as a dir source; nothing reads it.
#   - packaging/Dockerfile.ci, which installs rustup with an explicit
#     --default-toolchain so an image built without the repo mounted still has
#     a compiler.
#
# Both files already SAID they tracked the pin. On 2026-08-30 the pin moved
# 1.96.0 -> 1.98.0 -- deliberately, to get off a compiler in the range affected
# by the LLVM miscompilation that Rust 1.97.1 was released to fix -- and both
# were left behind. The Flatpak is the primary Linux channel, so the effect was
# that the shipped artifact would be built by the exact compiler the bump
# existed to escape, silently, with every published hash wrong and no error
# anywhere. A comment asserting parity is not parity.
#
# SCOPE, DELIBERATELY NARROW. This checks ACTIVE BUILD CONFIGURATION only. It
# does not police documentation, and it must not: docs/reproducible-builds.md
# quotes a 1.96.0 path recovered from a shipped binary during the 2026-08-27
# path-leak investigation, and the published 0.9.65 source snapshot keeps its
# 1.96.0 pin because that pin is part of what its published hashes verify
# against. Historical evidence and current configuration are different
# categories. A gate that flattened them would make the record less true.
#
# Nightly is out of scope too: fuzz/ deliberately floats on nightly because
# libFuzzer needs -Z flags, and it produces no released artifact.
#
# Run: scripts/toolchain-pin-gate.sh
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

PIN_FILE=rust-toolchain.toml
FLATPAK=packaging/flatpak/io.edgexene.Patanyx.yml
DOCKERFILE=packaging/Dockerfile.ci

fail=0
ok()   { printf '  ok   %s\n' "$*"; }
bad()  { fail=1; printf '  FAIL %s\n' "$*" >&2; }

CHANNEL=$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$PIN_FILE")
if [ -z "$CHANNEL" ]; then
  echo "GATE FAIL: no channel found in $PIN_FILE" >&2
  exit 1
fi
echo "toolchain pin gate: canonical channel is $CHANNEL"

# 1. The Flatpak archive must BE the pinned toolchain.
URL=$(grep -oE 'https://static\.rust-lang\.org/dist/rust-[0-9]+\.[0-9]+\.[0-9]+-[a-z0-9_-]+\.tar\.gz' "$FLATPAK" || true)
if [ -z "$URL" ]; then
  bad "no Rust toolchain archive URL found in $FLATPAK"
else
  URL_VER=$(echo "$URL" | sed -E 's|.*/rust-([0-9]+\.[0-9]+\.[0-9]+)-.*|\1|')
  if [ "$URL_VER" = "$CHANNEL" ]; then
    ok "flatpak toolchain archive is $CHANNEL"
  else
    bad "flatpak installs Rust $URL_VER but $PIN_FILE pins $CHANNEL"
    printf '       %s\n' "$URL" >&2
    printf '       The sandbox has no rustup and builds with an absolute cargo path,\n' >&2
    printf '       so this archive -- not the pin -- decides the compiler.\n' >&2
  fi
fi

# 2. A checksum must accompany it. Wrong bytes fail the Flatpak build loudly,
#    which is the safe direction; a MISSING checksum would not.
if grep -qE '^\s*sha256:\s*[0-9a-f]{64}\s*$' "$FLATPAK"; then
  ok "  and carries a sha256"
else
  bad "  flatpak toolchain archive has no sha256"
fi

# 3. The CI image's explicit default must be the pinned toolchain.
DOCK_VER=$(grep -oE '\-\-default-toolchain[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' "$DOCKERFILE" \
           | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
if [ -z "$DOCK_VER" ]; then
  ok "$DOCKERFILE pins no explicit toolchain version"
elif [ "$DOCK_VER" = "$CHANNEL" ]; then
  ok "$DOCKERFILE default toolchain is $CHANNEL"
else
  bad "$DOCKERFILE installs $DOCK_VER but $PIN_FILE pins $CHANNEL"
fi

# 4. NO STALE VERSION ANYWHERE IN THOSE TWO FILES, comments included. The
#    parity claims in both are what made this look correct while it was wrong,
#    so a comment naming a version that is not the pin is itself the defect.
for f in "$FLATPAK" "$DOCKERFILE"; do
  stray=$(grep -noE '\b1\.[0-9]+\.[0-9]+\b' "$f" | grep -v ":$CHANNEL\$" || true)
  if [ -z "$stray" ]; then
    ok "no stale version literal in $f"
  else
    bad "stale version literal in $f (pin is $CHANNEL):"
    printf '       %s\n' $stray >&2
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "GATE FAIL: a build path would use a compiler other than the pinned one." >&2
  exit 1
fi
echo "toolchain pin gate: OK"
