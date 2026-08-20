#!/usr/bin/env bash
# The launch-day flip, and the gate that keeps it applicable until then.
#
# Premium goes on sale in ONE commit: PREMIUM_ON_SALE becomes true, the
# About page moves to present tense, and the three panel notes stop saying
# "arriving the day Premium launches". about.rs records why it must be one
# commit: a binary that says "on sale" while the page is not live, or a page
# taking money while the binary says "arriving", is the exact dishonesty the
# rest of that file exists to prevent. So the flip is NOT on the branch. It
# is docs/premium-launch/launch-day-flip.patch, prepared and verified on
# 2026-08-16 (workspace tests, chrome-js gates, premium-toolbar-gate,
# ocr-region-gate all green with it applied), and applied on launch day.
#
#   scripts/premium-launch-flip.sh check    default: the patch still applies
#                                           cleanly and the branch is still
#                                           NOT on sale (runs in ci-trixie)
#   scripts/premium-launch-flip.sh apply    launch day: apply it, run the
#                                           tests that pin it, leave it in the
#                                           working tree for the launch commit
#
# A branch that drifts until the patch no longer applies fails `check`, so
# the drift is fixed the day it happens rather than discovered on launch day.
set -euo pipefail
cd "$(dirname "$0")/.."
patch=docs/premium-launch/launch-day-flip.patch
mode="${1:-check}"

case "$mode" in
  check)
    grep -q 'pub const PREMIUM_ON_SALE: bool = false;' crates/app/src/licence_control.rs || {
      echo "premium-launch-flip: PREMIUM_ON_SALE is not false on this branch." >&2
      echo "  Either Premium launched (delete this gate and the patch in the launch commit)" >&2
      echo "  or something flipped it early, which about.rs says must never happen." >&2
      exit 1; }
    git apply --check "$patch" || {
      echo "premium-launch-flip: the launch patch no longer applies to this branch." >&2
      echo "  Re-derive it: apply by hand, verify, 'git diff > $patch', revert." >&2
      echo "" >&2
      echo "  READ docs/premium-launch/README.md FIRST. As of 2026-08-19 this" >&2
      echo "  patch still GATES FINGERPRINT DIVERGENCE, which is now free" >&2
      echo "  permanently and published as such on three website pages." >&2
      echo "  Re-deriving it by applying it as written reinstates the gate and" >&2
      echo "  takes a free feature away from everyone. Strip every Divergence" >&2
      echo "  hunk before re-deriving." >&2
      exit 1; }
    echo "premium-launch-flip OK: branch not on sale, patch applies cleanly"
    ;;
  apply)
    git diff --quiet && git diff --cached --quiet || { echo "working tree not clean; commit or stash first" >&2; exit 2; }
    git apply "$patch"
    echo "=== applied; running the tests that pin the flip ==="
    cargo test -p patanyx 'about::' 2>&1 | tail -1
    cargo test -p patanyx 'licence_control::' 2>&1 | tail -1
    ./scripts/chrome-js-gate.sh 2>&1 | tail -1
    node scripts/premium-toolbar-gate.js 2>&1 | tail -1
    node scripts/ocr-region-gate.js 2>&1 | tail -1
    node scripts/divergence-site-gate.js 2>&1 | tail -1
    echo
    echo "The flip is in the working tree. Commit it AS the launch commit, in the"
    echo "same release that sells: delete $patch and this script's check from"
    echo "ci-trixie in that commit, since neither has a job once Premium is on sale."
    ;;
  *)
    echo "usage: $0 [check|apply]" >&2; exit 2 ;;
esac
