#!/usr/bin/env bash
# The commit-time audit: the i18n gates, run BEFORE a commit exists, scoped
# to what the commit actually touches.
#
# WHY SCOPED. The hooks directory is shared by every worktree of this
# repository, and parallel sessions work on branches that have nothing to do
# with the catalog. A hook that ran the full battery on every commit would
# block a peer's unrelated work behind this branch's checks -- so the audit
# fires only when STAGED paths intersect the catalog's surface, and stays
# silent otherwise. PATANYX_PRECOMMIT=full forces everything;
# git commit --no-verify remains the documented escape hatch, and using it
# is a statement the commit message should own up to.
#
# Checks, cheapest first, fail-fast:
#   1. node --check on staged chrome *.js (a parse error ships dead buttons)
#   2. scripts/i18n-gate.sh   (catalog sync both directions, claims manifest,
#                              en-XA freshness, bare-literal tripwire)
#   3. scripts/pseudo-locale-gate.sh (unextracted-English scan)
#   4. cargo test -p patanyx  (the catalog is include_str! -- FTL edits change
#                              the binary, so the tests run when FTL or Rust
#                              is staged)
#
# Run standalone anytime: scripts/pre-commit-audit.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

staged=$(git diff --cached --name-only)
[ -n "$staged" ] || exit 0

touches() { echo "$staged" | grep -qE "$1"; }

I18N_SURFACE='^(crates/app/src/chrome/|crates/app/src/i18n\.rs|crates/app/build\.rs|scripts/i18n-|scripts/gen-pseudo-locale\.py|scripts/pseudo-locale-gate\.sh)'
RUNTIME_SURFACE='^crates/app/src/(isolation_probe\.rs|translate_channel_probe\.rs|main\.rs|platform/)'
DEPS_SURFACE='Cargo\.(toml|lock)$'
ARTIFACT_SURFACE='^(models/|shipped-artifacts\.json|scripts/artifact-manifest-gate\.py)'

full() { [ "${PATANYX_PRECOMMIT:-}" = "full" ]; }

# EVERY GATE DECIDES FOR ITSELF WHETHER IT APPLIES, and the script exits early
# only when NONE of them do.
#
# It used to exit early unless the I18N surface was staged, which put the
# attribution, artifact and isolation gates behind a condition that has nothing
# to do with what they check. A commit that added a dependency and touched no
# catalog file skipped the attribution gate completely -- the exact failure its
# own comment below describes, reintroduced by the scoping rather than by the
# gate. Found when a commit adding `javascriptcore-rs-sys` and rewriting a
# platform file produced a silent, instant OK.
if ! full \
  && ! touches "$I18N_SURFACE" \
  && ! touches "$RUNTIME_SURFACE" \
  && ! touches "$DEPS_SURFACE" \
  && ! touches "$ARTIFACT_SURFACE" \
  && ! touches '\.(rs|ftl)$'; then
  exit 0
fi

echo "pre-commit audit: staged changes reach a gated surface"

if full || touches "$I18N_SURFACE"; then
  for f in $(echo "$staged" | grep -E '^crates/app/src/chrome/.*\.js$' || true); do
    [ -f "$f" ] && node --check "$f"
  done

  bash scripts/i18n-gate.sh
  bash scripts/pseudo-locale-gate.sh
fi

if touches '\.(rs|ftl)$' || full; then
  cargo test -p patanyx --quiet 2>&1 | tail -2
fi

# The translator's isolation from the privileged UI only exists at RUNTIME:
# whether the engine actually partitions storage between two live webviews is
# not visible to a unit test. Runs the real binary under xvfb, so it is scoped
# to changes that could plausibly break it rather than every commit.
if touches "$RUNTIME_SURFACE" || full; then
  bash scripts/translator-isolation-gate.sh
fi

# A dependency change without regenerated attribution is a licence term
# unmet in the shipped About panel -- the exact miss this line exists for:
# the Fluent crates were compiled in for days before anything failed.
if touches "$DEPS_SURFACE" || full; then
  bash scripts/attribution-gate.sh
elif touches "$ARTIFACT_SURFACE"; then
  # A shipped artifact can change with no Cargo change at all -- a model
  # swapped in place touches no manifest. The crate gate would never notice,
  # which is the whole reason the register exists.
  python3 scripts/artifact-manifest-gate.py
fi

echo "pre-commit audit: OK"
