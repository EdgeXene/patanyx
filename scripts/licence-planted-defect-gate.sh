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
#   P5: (Phase 4, five devices) the receipt binding ignored, and the
#        activation conjunct removed from premium_active: each must FAIL
#        the licence_control suite.
#   P6: (Phase 4) the licence server's five-slot cap removed must FAIL
#        the server suite (run on a copy pointed at this tree's crate).
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
# repo as scripts/relay-planted-defect-gate.sh.

# ============================ P4 phase =====================================
# The first ENFORCED premium gate: tab_search::cross_tab_gate, called as
# the first statement of every premium IPC arm. Two halves, because the
# mechanism and its call sites rot independently:
#
#   P4a (mechanism): the gate body stubbed to always-Ok must FAIL the
#        tab_search suite -- proof the refusal rule is really tested.
#   P4b (call sites): a hand-kept list of premium commands, each of whose
#        arms must contain the gate call. The mechanism test cannot catch
#        a gate line DELETED from an arm; only a shape check can.

# The P2 phase already restored nothing -- APPWS still carries the P2 stub
# in licence_control.rs, which does not touch tab_search. Stub the gate on
# top of it; the tab_search suite never reads licence state.
TARGET4="$APPWS/crates/app/src/tab_search.rs"
if [ ! -f "$TARGET4" ]; then
    echo "gate broken: $TARGET4 not found — has tab_search moved?" >&2
    echo "update TARGET4 in $0" >&2
    exit 2
fi

# BASELINE for the tab_search suite, same reason as every other baseline.
set +e
BASELINE4="$(cd "$APPWS" && CARGO_TARGET_DIR="$WORK/target-app" cargo test -p patanyx tab_search 2>&1)"
BASELINE4_STATUS=$?
set -e
if [ "$BASELINE4_STATUS" -ne 0 ]; then
    printf '%s\n' "$BASELINE4" | tail -n 15 >&2
    echo "gate broken: the UNMODIFIED tab_search suite is not green;" >&2
    echo "fix the suite first — a stubbed-run failure would be unattributable." >&2
    exit 2
fi
echo "baseline: unmodified tab_search suite passes"

# Anchored to the refusal ALONE on its line (the gate's body): the test
# that pins the refusal quotes the same string inline, and stubbing the
# assertion instead of the body would prove nothing.
# Fixed-string, whole-line (-xF): an ERE would read the parentheses as a
# group and silently match nothing.
CALL4='        Err("premium_required")'
OCCURRENCES4="$(grep -cxF "$CALL4" "$TARGET4" || true)"
if [ "$OCCURRENCES4" != "1" ]; then
    echo "gate broken: expected exactly one refusal line in $TARGET4, found" >&2
    echo "$OCCURRENCES4 — cross_tab_gate moved or was reformatted; update" >&2
    echo "CALL4 in $0" >&2
    exit 2
fi

sed 's/^        Err("premium_required")$/        Ok(())/' "$TARGET4" > "$TARGET4.stubbed"
mv "$TARGET4.stubbed" "$TARGET4"

set +e
OUTPUT4="$(cd "$APPWS" && CARGO_TARGET_DIR="$WORK/target-app" cargo test -p patanyx tab_search 2>&1)"
STATUS4=$?
set -e

printf '%s\n' "$OUTPUT4" | tail -n 5

if [ "$STATUS4" -eq 0 ]; then
    echo "GATE FAILURE: the tab_search suite PASSED with cross_tab_gate" >&2
    echo "stubbed to always-Ok. The premium refusal is not being tested." >&2
    echo "Do not trust this suite." >&2
    exit 1
fi
if ! printf '%s\n' "$OUTPUT4" | grep -q 'test result: FAILED'; then
    echo "GATE FAILURE: the P4a-stubbed copy did not produce a test failure" >&2
    echo "(build error, or tests failed for the wrong reason — see output)." >&2
    exit 1
fi
echo "P4a phase OK: with cross_tab_gate stubbed to always-Ok, the"
echo "tab_search suite FAILS, as the first enforced gate requires."

# P4b: every premium arm calls the gate. Checked against the REAL tree
# (this is a shape check, not a build), with non-emptiness pinned so an
# emptied list cannot pass vacuously. Grow this list with every premium
# command; an arm missing from it is a premium feature the gate cannot
# vouch for.
IPC_REAL="$REPO_ROOT/crates/app/src/ipc.rs"
PREMIUM_COMMANDS=("find_tabs_search" "find_tabs_goto" "tabs_switcher_list" "tabs_batch_enter" "ocr_region_capture" "ocr_region_scan" "download_compare_request" "change_compare_request" "archive_save" "archive_search" "archive_list" "divergence_site_set" "divergence_site_clear" "divergence_sites_list" "divergence_proof_get")
if [ "${#PREMIUM_COMMANDS[@]}" -eq 0 ]; then
    echo "gate broken: PREMIUM_COMMANDS is empty" >&2
    exit 2
fi
for cmd in "${PREMIUM_COMMANDS[@]}"; do
    # The arm's first lines: from the match arm to 8 lines below. The gate
    # call must appear there — FIRST STATEMENT is the design, and 8 lines
    # of slack tolerates the arm's comment block, not a gate moved behind
    # other logic.
    ARM="$(grep -A 8 "\"$cmd\" =>" "$IPC_REAL" || true)"
    if [ -z "$ARM" ]; then
        echo "GATE FAILURE: premium command $cmd has no arm in ipc.rs —" >&2
        echo "removed without updating PREMIUM_COMMANDS, or renamed." >&2
        exit 1
    fi
    if ! printf '%s\n' "$ARM" | grep -q 'cross_tab_gate'; then
        echo "GATE FAILURE: the $cmd arm does not call cross_tab_gate in" >&2
        echo "its opening lines. The premium refusal must be the arm's" >&2
        echo "first statement." >&2
        exit 1
    fi
done
# The other direction, pinned: there is deliberately NO stop command (a
# gated stop could strand a live scan; an ungated one has nothing to
# stop). If an arm appears, this fails so the addition is reviewed here.
if grep -q '"find_tabs_stop"' "$IPC_REAL"; then
    echo "GATE FAILURE: a find_tabs_stop arm exists. The no-stop design" >&2
    echo "was deliberate (nothing runs between events; scans die by id)." >&2
    echo "If a stop is now wanted, it must be UNGATED, and this check" >&2
    echo "updated in the same change." >&2
    exit 1
fi
echo "P4b phase OK: every premium arm calls the gate in its opening lines,"
echo "and no stop arm exists."

# ============================ P5 phase =====================================
# Phase 4 (five-device activation, 2026-08-17). Two planted defects in the
# browser, each on a FRESH copy of licence_control.rs (APPWS still carries
# the P2 stub in that file, which already fails the suite; a stub on top
# of it would be unattributable):
#
#   P5a: the receipt binding ignored -- a receipt that verifies but names
#        another device (or another licence) counts as this device's. The
#        licence_control suite must FAIL.
#   P5b: the activation conjunct removed from premium_active -- a token
#        alone opens the gate on any number of machines. Must FAIL.
FRESH5="$REPO_ROOT/crates/app/src/licence_control.rs"
run_p5() { # run_p5 <label> <sed-expr> <expected-after> <must-be-gone>
    local label="$1" expr="$2" after="$3" gone="$4"
    cp "$FRESH5" "$TARGET2"
    local occ; occ="$(grep -cF "$gone" "$TARGET2" || true)"
    if [ "$occ" != "1" ]; then
        echo "gate broken: expected exactly one $label anchor in $TARGET2, found $occ;" >&2
        echo "the line moved or was reformatted -- update run_p5's expression in $0" >&2
        exit 2
    fi
    sed "$expr" "$TARGET2" > "$TARGET2.stubbed" && mv "$TARGET2.stubbed" "$TARGET2"
    if grep -qF "$gone" "$TARGET2" || ! grep -qF "$after" "$TARGET2"; then
        echo "gate broken: the $label stub did not apply" >&2
        exit 2
    fi
    set +e
    local out; out="$(cd "$APPWS" && CARGO_TARGET_DIR="$WORK/target-app" cargo test -p patanyx licence_control 2>&1)"
    local status=$?
    set -e
    printf '%s\n' "$out" | tail -n 5
    if [ "$status" -eq 0 ]; then
        echo "GATE FAILURE: the licence_control suite PASSED with $label stubbed." >&2
        echo "Do not trust this suite." >&2
        exit 1
    fi
    if ! printf '%s\n' "$out" | grep -q 'test result: FAILED'; then
        echo "GATE FAILURE: the $label-stubbed copy did not produce a test failure" >&2
        exit 1
    fi
}
# Baseline on the fresh file first (P2's stub is gone with the copy).
cp "$FRESH5" "$TARGET2"
set +e
BASELINE5="$(cd "$APPWS" && CARGO_TARGET_DIR="$WORK/target-app" cargo test -p patanyx licence_control 2>&1)"
BASELINE5_STATUS=$?
set -e
if [ "$BASELINE5_STATUS" -ne 0 ]; then
    printf '%s\n' "$BASELINE5" | tail -n 15 >&2
    echo "gate broken: the UNMODIFIED licence_control suite is not green (P5 baseline)" >&2
    exit 2
fi
run_p5 "P5a receipt binding" \
    's/\.map(|receipt| receipt\.binds(&token, &device_id))/.map(|_receipt| true)/' \
    '.map(|_receipt| true)' \
    '.map(|receipt| receipt.binds(&token, &device_id))'
echo "P5a phase OK: with the receipt binding ignored, the licence_control suite FAILS."
run_p5 "P5b activation conjunct" \
    's/session\.state\.premium_active() \&\& session\.activation == ActivationState::Activated/session.state.premium_active()/' \
    '.map(|session| {
            session.state.premium_active()
        })' \
    'session.state.premium_active() && session.activation == ActivationState::Activated'
echo "P5b phase OK: with the activation conjunct removed from premium_active,"
echo "the licence_control suite FAILS."

# ============================ P6 phase =====================================
# The server's slot cap. The licence server is a separate, private
# repository (../patanyx-licence-server, or LICENCE_SERVER_REPO); its
# suite is run on a copy whose licence-crate path dependency is pointed at
# THIS tree's copy, so the phase tests this branch's crate and needs no
# other checkout. Stub: SlotsFull -> Granted; the server suite must FAIL.
# Absent repo: SKIPPED, loudly (the public tree has no server), unless
# REQUIRE_P6=1 makes that a broken gate.
SERVER_REPO="${LICENCE_SERVER_REPO:-$REPO_ROOT/../patanyx-licence-server}"
if [ ! -f "$SERVER_REPO/Cargo.toml" ]; then
    if [ "${REQUIRE_P6:-0}" = "1" ]; then
        echo "gate broken: REQUIRE_P6=1 but no licence server at $SERVER_REPO" >&2
        exit 2
    fi
    echo "P6 phase SKIPPED: no licence server checkout at $SERVER_REPO"
    echo "(set LICENCE_SERVER_REPO, or REQUIRE_P6=1 to make this a failure)."
else
    SRVWS="$WORK/server"
    mkdir -p "$SRVWS"
    cp "$SERVER_REPO/Cargo.toml" "$SRVWS/"
    [ -f "$SERVER_REPO/Cargo.lock" ] && cp "$SERVER_REPO/Cargo.lock" "$SRVWS/"
    cp -R "$SERVER_REPO/src" "$SRVWS/src"
    # Point the path dependency at THIS tree's crate copy.
    sed -i "s|^patanyx-licence = { path = \"[^\"]*\" }|patanyx-licence = { path = \"$APPWS/crates/licence\" }|" "$SRVWS/Cargo.toml"
    grep -q "path = \"$APPWS/crates/licence\"" "$SRVWS/Cargo.toml" || { echo "gate broken: could not repoint the server's licence dependency" >&2; exit 2; }
    TARGET6="$SRVWS/src/activation.rs"
    [ -f "$TARGET6" ] || { echo "gate broken: $TARGET6 not found; the server's activation module moved" >&2; exit 2; }
    set +e
    BASELINE6="$(cd "$SRVWS" && CARGO_TARGET_DIR="$WORK/target-server" cargo test 2>&1)"
    BASELINE6_STATUS=$?
    set -e
    if [ "$BASELINE6_STATUS" -ne 0 ]; then
        printf '%s\n' "$BASELINE6" | tail -n 15 >&2
        echo "gate broken: the UNMODIFIED licence server suite is not green" >&2
        exit 2
    fi
    echo "baseline: unmodified licence server suite passes"
    CALL6='        return ActivationDecision::SlotsFull;'
    OCC6="$(grep -cxF "$CALL6" "$TARGET6" || true)"
    [ "$OCC6" = "1" ] || { echo "gate broken: expected exactly one SlotsFull return in $TARGET6, found $OCC6" >&2; exit 2; }
    sed 's/^        return ActivationDecision::SlotsFull;$/        return ActivationDecision::Granted;/' "$TARGET6" > "$TARGET6.stubbed"
    mv "$TARGET6.stubbed" "$TARGET6"
    set +e
    OUTPUT6="$(cd "$SRVWS" && CARGO_TARGET_DIR="$WORK/target-server" cargo test 2>&1)"
    STATUS6=$?
    set -e
    printf '%s\n' "$OUTPUT6" | tail -n 5
    if [ "$STATUS6" -eq 0 ]; then
        echo "GATE FAILURE: the licence server suite PASSED with the slot cap removed." >&2
        exit 1
    fi
    printf '%s\n' "$OUTPUT6" | grep -q 'test result: FAILED' || { echo "GATE FAILURE: the P6-stubbed server did not produce a test failure" >&2; exit 1; }
    echo "P6 phase OK: with the five-slot cap removed, the licence server suite FAILS."
fi

echo "gate OK: planted defects P1, P2, P4a, P5a, P5b (and P6 where the server"
echo "is present) are caught by their suites, and P4b's premium arms all refuse first."
exit 0
