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
# the webview that holds IPC and the vault. Its partner-gate entry drives all
# three disclosed placements, so CI cannot pass on the renderer merely
# existing as unreachable code again.
# Cheapest gate here and the one that invalidates the rest if it fails: if a
# build path installs a compiler other than the pinned one, every artifact
# below was produced by the wrong rustc.
echo
echo "=== lints ==="
# Separate from the test suites on purpose: a suite proves behavior, a linter
# catches the class of mistake that compiles, passes, and is still wrong. Both
# components come from the pinned toolchain, so this needs no setup the pin does
# not already provide.
# NOT --check and NOT -D warnings, deliberately, and this is the honest state
# rather than an oversight. The tree has never been rustfmt-normalized (637
# files differ) and clippy has a handful of style findings, so a hard gate here
# would fail on day one and be switched off within a week. What this does buy is
# the thing that matters: clippy actually RUNS before a release, so a real
# defect it spots is seen. Tighten to -D warnings once the backlog is cleared,
# and make that a deliberate commit rather than a side effect of this one.
cargo clippy --workspace --all-targets --locked
# RustSec advisories against the locked dependency set. Cheap, and the only
# thing that notices a dependency going bad between releases.
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "cargo audit: SKIPPED (cargo-audit not installed)"
fi

./scripts/toolchain-pin-gate.sh
./scripts/chrome-js-gate.sh
# Tab reordering broke twice from the SAME Windows API call, and the second
# time it reached real hardware in a release build because every
# other gate stayed green: nothing asserted the ABSENCE of a call. This one
# does, alongside the wry handler that revokes the engine's drop target and
# the dataTransfer payload both engines need to start a drag at all.
node ./scripts/drag-regression-gate.js
# 27 scheme/accent chromes exist; nobody eyeballs them all. Fails on any
# WCAG pair below its bar (or below the shipped Dark baseline).
python3 ./scripts/theme-contrast-gate.py
# A licence-token suite that cannot fail proves nothing: builds throwaway
# copies with each verification mechanism stubbed out (P1 signature check,
# P2 unlock-time re-verification, P3 relay expiry check) and asserts each
# suite FAILS there (after proving the unmodified copies pass). Needs
# network or a warm cargo cache: the copies resolve deps standalone.
./scripts/licence-planted-defect-gate.sh
# The licence flow END TO END in the real binary, on a throwaway key: a
# server mints, the real ring refuses the foreign token, a build carrying
# the throwaway key accepts it and a gated arm opens. Needs the licence
# server checkout beside this repo, which the public tree does not carry;
# guarded so an outside contributor is not stopped by a sibling they do not
# have, and reported so its absence is visible rather than silent.
if [ -x ../patanyx-licence-server/scripts/smoke-throwaway.sh ]; then
  ./scripts/premium-e2e-gate.sh
else
  echo "premium-e2e-gate: SKIPPED (no ../patanyx-licence-server checkout)"
fi
# The launch-day flip stays OFF the branch until the release that sells, and
# stays applicable while it waits: fails if the branch drifts so the patch
# no longer applies, or if PREMIUM_ON_SALE flips early. Delete this line and
# the patch in the launch commit itself.
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
# The literal is deliberate and moves by hand with every Cargo bump (release
# procedure step 1). Deriving it from Cargo.toml would reduce the release-identity check
# to comparing Cargo.toml with itself; 1.0.1 shipped with this still at 1.0.0.
EXPECTED_VERSION=1.0.1 ./scripts/check-version.sh
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

# The suite above must exercise the real session-and-activation gate. An
# unlocked build can pass every positive Premium test while proving nothing
# about that rule, which is the same false-green shape the planted-defect gate
# exists to prevent. Check the exact release artifact that smoke runs next;
# the compile-time warning is mandatory in every premium-unlocked binary.
unlocked_marker="UNLOCKED TEST BUILD: Premium forced on; no licence checked"
if strings -a "$CARGO_TARGET_DIR/release/patanyx" | grep -F "$unlocked_marker" >/dev/null; then
  echo "GATE FAIL: ci-trixie built premium-unlocked; licence-gate results are invalid" >&2
  exit 1
fi
echo "licence gate: real session/activation build (premium-unlocked absent)"

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

# THE CONTENT-FILTER ENGINE GATE.
#
# Asks THIS IMAGE'S WebKit whether the shipped ad and tracker rules actually
# compile. Everything above proves our code is self-consistent; this proves the
# engine accepts what we intend to ship to users.
#
# It exists because the failure it catches is SILENT. WebKit refuses a compiled
# rule list above an undocumented ceiling -- measured 2026-09-01 as exactly
# 150,000 rules on both 2.50.6 and 2.52.6 -- and refuses patterns outside the
# subset its regex engine accepts. Either refusal installs NO filter, and the
# browser then runs with ad blocking switched on in the UI and nothing actually
# blocking. Nothing in the product notices.
#
# A build-time assertion against the constant 150000 would only restate today's
# number: if a future engine LOWERS the ceiling or narrows the accepted
# patterns, the constant still passes and the release ships broken. Asking the
# engine is the only check that survives the engine changing, which is the
# whole point on the way to 1.0.
echo
echo "=== content filter compiles against this engine ==="
if ! filter_out="$(xvfb-run -a --server-args="-screen 0 1280x900x24" \
      "$CARGO_TARGET_DIR/release/patanyx" --verify-content-filter 2>&1)"; then
  echo "$filter_out"
  echo "GATE FAIL: this engine REFUSED the shipped ad/tracker rules." >&2
  echo "  Nothing would block for users, and nothing in the product would say so." >&2
  echo "  Split the rule lists further or drop the rejected pattern." >&2
  exit 1
fi
echo "$filter_out"

# The hover readout's live check (ipc::smoke_readout_sequence). Its absence
# means either the sequence failed -- the smoke exit already failed above in
# that case -- or someone unchained it from the smoke run, which this catches.
echo "$out" | grep -q '^READOUT ok$' || {
  echo "GATE FAIL: the hover readout did not pass its live check" >&2
  exit 1
}

# The affiliate partner path's live check (ipc::smoke_partner_sequence). Same
# reasoning as READOUT above: the sequence proves that partner_open opens the
# approved destination and that a caller-supplied url opens nothing, and this
# grep is what stops someone unchaining it from the smoke run without CI
# noticing.
echo "$out" | grep -q '^PARTNER ok$' || {
  echo "GATE FAIL: the affiliate partner path did not pass its live check" >&2
  exit 1
}

# The project-support destination has its own non-affiliate identifier path.
# Require the real-dispatch result so removing that path cannot leave only a
# mocked About-button test passing.
echo "$out" | grep -q '^SPONSORSHIP ok$' || {
  echo "GATE FAIL: the sponsorship path did not pass its live check" >&2
  exit 1
}

# Tab reordering has a positional-state hazard no mocked DOM can prove: the
# active Vec index must be remapped by id, malformed orders must be atomic,
# and an id-addressed close must still find its tab after a move. Pin the real
# dispatcher sequence so it cannot be silently unchained from smoke mode.
echo "$out" | grep -q '^SMOKE tabs:' || {
  echo "GATE FAIL: tab reorder did not pass its real-dispatch smoke check" >&2
  exit 1
}

echo
echo "CI TRIXIE OK"
