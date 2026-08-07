#!/usr/bin/env bash
# Full Linux gate, inside the Debian 13 image built from packaging/Dockerfile.ci.
#
# The point of this script is the LAST step. Everything before it proves the
# code compiles and the tests pass, which this project has repeatedly shown is
# compatible with the browser doing nothing of the sort. The final step runs
# the real binary against the real engine and reads back what the engine says
# about itself.
set -euo pipefail
cd "$(dirname "$0")/.."

# Host artefacts were built against a different glibc and toolchain; sharing
# target/ between host and container produces confusing rebuild churn.
export CARGO_TARGET_DIR=target/trixie

echo "=== environment ==="
grep PRETTY_NAME /etc/os-release
printf 'webkit2gtk-4.1  runtime : '; pkg-config --modversion webkit2gtk-4.1
printf 'rustc                   : '; rustc --version
printf 'cargo                   : '; cargo --version

echo
echo "=== apt provenance (which repo the fixed engine came from) ==="
apt-cache policy libwebkit2gtk-4.1-0 2>/dev/null | sed -n '1,5p' || true

echo
echo "=== tests ==="
cargo test --workspace --locked
cargo test -p patanyx --features chat --locked
# The relay client compiles only under its own feature, so none of its code --
# reconnect, backoff, the drain that stops frames surviving a reconnect -- was
# covered by either line above. It had never run in CI at all.
cargo test -p patanyx-chat --features relay-client --locked
# The chrome scripts are EXECUTED, not parsed: node --check validates syntax
# and has already let a load-time ReferenceError ship. Also bans innerHTML in
# the webview that holds IPC and the vault.
./scripts/chrome-js-gate.sh
# 27 scheme/accent chromes exist; nobody eyeballs them all. Fails on any
# WCAG pair below its bar (or below the shipped Dark baseline).
python3 ./scripts/theme-contrast-gate.py
# A licence-token suite that cannot fail proves nothing: builds throwaway
# copies with each verification mechanism stubbed out (P1 signature check,
# P2 unlock-time re-verification, P3 relay expiry check) and asserts each
# suite FAILS there (after proving the unmodified copies pass). Needs
# network or a warm cargo cache: the copies resolve deps standalone.
./scripts/licence-planted-defect-gate.sh
# The relay's token-logging gate LEFT THIS REPOSITORY with the relay itself
# (commit e7f2a5a, the OSS split). It ran unconditionally here for a while
# after that, which aborts this script under `set -e` before every gate
# below it -- the first thing an outside contributor hits. Guarded rather
# than deleted so a tree that still has the relay keeps running it.
if [ -f ./scripts/relay-token-log-gate.sh ]; then
  ./scripts/relay-token-log-gate.sh
fi
# Cheap, no network, and the only thing standing between a dependency change
# and an offline Flatpak build that vendors the wrong tree.
python3 ./scripts/check-cargo-sources.py
# The app version and the AppStream version must be the same number. They
# drifted 0.9.0 -> 0.9.52 unnoticed because nothing compared them.
./scripts/check-version.sh
# The About panel names every third-party package compiled into the binary, and
# that list is a checked-in file. Add a dependency without regenerating it and
# the browser confidently attributes a set of software it is no longer built
# from. That is a licence term unmet rather than a stale document: MIT, BSD and
# ISC all require the copyright notice to travel with the binary, so a missing
# entry is a missing obligation. Regenerates into a scratch directory and diffs.
./scripts/attribution-gate.sh
# The Public Suffix List decides which saved password a page may be offered,
# and it is a dated snapshot with no expiry of its own. A stale copy compiles,
# passes every test -- the tests are written against it -- and silently widens
# registrable domains, so a credential reaches further than its owner agreed.
# Offline: reads the header the generator wrote. Warns at 120 days, fails at
# 270. Deliberately NOT in build.rs, which would make old tags stop building
# on a date nobody chose; see the header of the script.
./scripts/psl-staleness-gate.sh
# Two real transports over real sockets: discovery, a dialled link, a
# handshake, a delivered message and its acknowledgement, plus the negative
# control. Several runs, because the defect it found appeared in one run in
# three -- a single green run would have reported broken code as working.
RUNS="${DELIVERY_PROBE_RUNS:-5}" ./scripts/chat-delivery-probe.sh

echo
echo "=== release build ==="
cargo build --release --locked

echo
echo "=== the gate that matters: run it, ask the engine ==="
# A compile proves the instruction exists. This proves the engine obeyed it.
SMOKE_DATA="$(mktemp -d)"
trap 'rm -rf "$SMOKE_DATA"' EXIT
export XDG_DATA_HOME="$SMOKE_DATA"
export WEBKIT_DISABLE_COMPOSITING_MODE=1

# No PATANYX_ALLOW_OLD_ENGINE here on purpose: on a correct image the release
# binary must start WITHOUT an override. If it exits 2, the image is serving a
# below-floor engine and the whole point of Debian 13 has been lost.
out="$(xvfb-run -a --server-args="-screen 0 1280x900x24" \
        "$CARGO_TARGET_DIR/release/patanyx" --smoke-test 2>&1)" || {
  echo "$out"
  echo "GATE FAIL: release binary refused to start or crashed" >&2
  exit 1
}
echo "$out" | grep -E "ENGINE|SMOKE" || true

engine_line="$(echo "$out" | grep '^ENGINE ' || true)"
if [ -z "$engine_line" ]; then
  echo "GATE FAIL: no ENGINE line; the binary did not reach the smoke exit" >&2
  exit 1
fi
case "$engine_line" in
  *"floor ok"*|*"floor OK"*) ;;
  *) echo "GATE FAIL: engine is below the security floor -> $engine_line" >&2; exit 1 ;;
esac
case "$engine_line" in
  *"ITP enabled"*) ;;
  *) echo "GATE FAIL: ITP is not on -> $engine_line" >&2; exit 1 ;;
esac

# The hover readout's live check (ipc::smoke_readout_sequence). Its absence
# means either the sequence failed -- the smoke exit already failed above in
# that case -- or someone unchained it from the smoke run, which this catches.
echo "$out" | grep -q '^READOUT ok$' || {
  echo "GATE FAIL: the hover readout did not pass its live check" >&2
  exit 1
}

echo
echo "CI TRIXIE OK"
