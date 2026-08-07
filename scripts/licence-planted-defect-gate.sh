#!/usr/bin/env bash
# Planted-defect gate for the Premium licence work, required by the design's
# P1 and P2 phases:
#
#   P1: "CI build with verification stubbed to always-true must fail the
#        gate test." A copy of crates/licence is built with signature
#        verification stubbed to always-true; its suite must FAIL.
#   P2: "Build with the unlock-time re-verification removed must fail." A
#        copy of the whole workspace is built with the verification-failure
#        arm of licence_control's evaluate_stored stubbed to always-ACTIVE;
#        the licence_control suite must FAIL.
#   P3: "Relay build with the expiry check disabled must fail." The same
#        workspace copy is built with the expiry comparison in the relay's
#        pure auth module stubbed to never-expired; the relay suite must
#        FAIL.
#
# A test suite that cannot fail proves nothing, so each phase proves the
# suite catches the defect the phase exists to prevent — and each phase
# runs the UNMODIFIED copy first, because a suite that is red for
# unrelated reasons would satisfy a naive "did it fail" check vacuously
# (found in independent review of the first version of this script).
#
# Exit codes:
#   0  gate satisfied  — every unmodified suite PASSES and every stubbed
#      suite FAILS.
#   1  gate violated   — a stubbed build PASSED its tests (the suite is
#      not testing the mechanism), or a stubbed copy failed to build/test
#      in a way that wasn't a test failure.
#   2  gate broken     — a baseline suite is not green, a stub pattern no
#      longer matches (the call site moved or was reformatted), or
#      cargo/the workspace layout is unavailable. Loud on purpose: a
#      silently vacuous gate is worse than none.
#
# Why sed-into-a-temp-copy rather than a cfg/feature trick in the real
# tree: anything compiled into the real crates is a switch that could
# accidentally ship. A mutation applied to a throwaway copy in a temp dir
# cannot leak into a real build, and the real tree is never written.
#
# The P2 phase needs the APP crate, which cannot build standalone, so it
# copies the workspace root (Cargo.toml, Cargo.lock, crates/) and runs
# `cargo test -p patanyx licence_control` there. That compiles the app's
# full dependency tree in a fresh target dir: CI needs the same system
# packages a normal app build needs, plus network or a warm cargo cache.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/crates/licence"

if ! command -v cargo >/dev/null 2>&1; then
    echo "gate broken: cargo is not on PATH" >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ============================ P1 phase =====================================
# Stub: signature verification always-true, in a detached copy of the
# licence crate.

cp -R "$SRC" "$WORK/licence"

# Detach the copy from any enclosing workspace so it builds standalone.
printf '\n[workspace]\n' >> "$WORK/licence/Cargo.toml"

TARGET="$WORK/licence/src/token.rs"

# BASELINE: the unmodified copy must be green, or a failure after stubbing
# proves nothing about verification.
set +e
BASELINE="$(cd "$WORK/licence" && CARGO_TARGET_DIR="$WORK/target" cargo test 2>&1)"
BASELINE_STATUS=$?
set -e
if [ "$BASELINE_STATUS" -ne 0 ]; then
    printf '%s\n' "$BASELINE" | tail -n 15 >&2
    echo "gate broken: the UNMODIFIED licence suite is not green; fix the" >&2
    echo "suite first — a stubbed-run failure would be unattributable." >&2
    exit 2
fi
echo "baseline: unmodified licence suite passes"

# The one and only verification call site in the crate (see the comment on
# verify_signature in token.rs). Fixed-string grep first: if this does not
# match, the call site moved and the gate must be updated, not silently
# pass.
CALL='key.verify_strict(message, signature).map_err(|_| LicenceError::BadSignature)'
if ! grep -qF "$CALL" "$TARGET"; then
    echo "gate broken: verification call site not found in $TARGET" >&2
    echo "update the CALL pattern in $0 to match the current source" >&2
    exit 2
fi

# Plant the defect: verification becomes always-true.
sed 's/key\.verify_strict(message, signature)\.map_err(|_| LicenceError::BadSignature)/Ok(())/' \
    "$TARGET" > "$TARGET.stubbed"
mv "$TARGET.stubbed" "$TARGET"

if grep -qF "$CALL" "$TARGET"; then
    echo "gate broken: the stub did not apply" >&2
    exit 2
fi
if ! grep -qF 'Ok(())' "$TARGET"; then
    echo "gate broken: the stub is not present after sed" >&2
    exit 2
fi

set +e
OUTPUT="$(cd "$WORK/licence" && CARGO_TARGET_DIR="$WORK/target" cargo test 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT" | tail -n 10

if [ "$STATUS" -eq 0 ]; then
    echo "GATE FAILURE: the licence suite PASSED with signature verification" >&2
    echo "stubbed to always-true. The tamper/wrong-key tests are not testing" >&2
    echo "verification. Do not trust this suite." >&2
    exit 1
fi
if ! printf '%s\n' "$OUTPUT" | grep -q 'test result: FAILED'; then
    echo "GATE FAILURE: the stubbed copy did not produce a test failure" >&2
    echo "(build error, or tests failed for the wrong reason — see output)." >&2
    exit 1
fi
echo "P1 phase OK: with signature verification stubbed to always-true,"
echo "the licence test suite FAILS, as the design requires."

# ============================ P2 phase =====================================
# Stub: the unlock-time re-verification in crates/app/src/licence_control.rs
# is neutered so a stored-but-INVALID token evaluates ACTIVE. The pure core
# (evaluate_stored) is unit-tested without a display, exactly so this phase
# can run headless.

if [ ! -f "$REPO_ROOT/Cargo.toml" ]; then
    echo "gate broken: $REPO_ROOT/Cargo.toml not found; the P2 phase needs" >&2
    echo "the workspace root to copy" >&2
    exit 2
fi

APPWS="$WORK/appws"
mkdir -p "$APPWS"
cp "$REPO_ROOT/Cargo.toml" "$APPWS/Cargo.toml"
if [ -f "$REPO_ROOT/Cargo.lock" ]; then
    cp "$REPO_ROOT/Cargo.lock" "$APPWS/Cargo.lock"
fi
cp -R "$REPO_ROOT/crates" "$APPWS/crates"
# Build inputs that live OUTSIDE crates/: the OCR model weights
# (include_bytes! from models/) and the LICENSE/NOTICE texts the About
# panel compiles in (include_str!). This list is the output of
#   grep -rn 'include_.*("../../../' crates/
# — re-run that grep and extend this block if a new root-level include
# appears; the copy failing loudly here is the reminder.
if [ -d "$REPO_ROOT/models" ]; then
    cp -R "$REPO_ROOT/models" "$APPWS/models"
fi
for rootfile in LICENSE NOTICE; do
    if [ -f "$REPO_ROOT/$rootfile" ]; then
        cp "$REPO_ROOT/$rootfile" "$APPWS/$rootfile"
    fi
done

TARGET2="$APPWS/crates/app/src/licence_control.rs"
if [ ! -f "$TARGET2" ]; then
    echo "gate broken: $TARGET2 not found — has licence_control moved?" >&2
    echo "update TARGET2 in $0" >&2
    exit 2
fi

# BASELINE, same reason as the P1 baseline.
set +e
BASELINE2="$(cd "$APPWS" && CARGO_TARGET_DIR="$WORK/target-app" cargo test -p patanyx licence_control 2>&1)"
BASELINE2_STATUS=$?
set -e
if [ "$BASELINE2_STATUS" -ne 0 ]; then
    printf '%s\n' "$BASELINE2" | tail -n 15 >&2
    echo "gate broken: the UNMODIFIED licence_control suite is not green;" >&2
    echo "fix the suite first — a stubbed-run failure would be unattributable." >&2
    exit 2
fi
echo "baseline: unmodified licence_control suite passes"

# The verification-failure arm of evaluate_stored — the line that makes a
# stored-but-invalid token FREE. Exactly ONE occurrence is required, so a
# second accidental match cannot silently split the stub's effect.
CALL2='Err(_) => LicenceState::Free,'
OCCURRENCES="$(grep -cF "$CALL2" "$TARGET2" || true)"
if [ "$OCCURRENCES" != "1" ]; then
    echo "gate broken: expected exactly one re-verification arm in" >&2
    echo "$TARGET2, found $OCCURRENCES — the call site moved or was" >&2
    echo "reformatted; update CALL2 in $0 to match the current source" >&2
    exit 2
fi

# Plant the defect: a stored token that fails re-verification now produces
# ACTIVE — the unlock-time re-verification removed, in effect. The state is
# fabricated directly because the licence crate deliberately exposes no
# unverified Token constructor; stubbing the state arm is the only way to
# express "invalid becomes ACTIVE" with public API.
sed 's/Err(_) => LicenceState::Free,/Err(_) => LicenceState::Active { days_left: 365 },/' \
    "$TARGET2" > "$TARGET2.stubbed"
mv "$TARGET2.stubbed" "$TARGET2"

if grep -qF "$CALL2" "$TARGET2"; then
    echo "gate broken: the P2 stub did not apply" >&2
    exit 2
fi
if ! grep -qF 'Err(_) => LicenceState::Active { days_left: 365 },' "$TARGET2"; then
    echo "gate broken: the P2 stub is not present after sed" >&2
    exit 2
fi

set +e
OUTPUT2="$(cd "$APPWS" && CARGO_TARGET_DIR="$WORK/target-app" cargo test -p patanyx licence_control 2>&1)"
STATUS2=$?
set -e

printf '%s\n' "$OUTPUT2" | tail -n 10

if [ "$STATUS2" -eq 0 ]; then
    echo "GATE FAILURE: the licence_control suite PASSED with the unlock-time" >&2
    echo "re-verification stubbed to always-ACTIVE. A stored-but-invalid token" >&2
    echo "is not being caught. Do not trust this suite." >&2
    exit 1
fi
if ! printf '%s\n' "$OUTPUT2" | grep -q 'test result: FAILED'; then
    echo "GATE FAILURE: the P2-stubbed copy did not produce a test failure" >&2
    echo "(build error, or tests failed for the wrong reason — see output)." >&2
    exit 1
fi
echo "P2 phase OK: with unlock-time re-verification stubbed to always-ACTIVE,"
echo "the licence_control suite FAILS, as the design requires."

# The P3 phase (the relay's expiry-check planted defect) moved OUT of this
# repository with the relay itself (OSS split, 2026-08-05): the relay is
# proprietary server infrastructure and its gate now lives in the relay
# repo as scripts/relay-planted-defect-gate.sh. This gate covers what this
# repository ships: P1 (token verification) and P2 (unlock-time
# re-evaluation).

echo "gate OK: both planted defects (P1, P2) are caught by their suites."
exit 0
