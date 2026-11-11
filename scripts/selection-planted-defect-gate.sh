#!/usr/bin/env bash
# One named mutation, one named test. An unrelated failure is never a catch.
# Temporarily edits only this job's module, restores it on every exit, and
# runs the positive control both before and after. Run without concurrent builds.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
  one-use) test_name=addon_selection::tests::one_use_binding ;;
  source-identity) test_name=addon_selection::tests::source_identity ;;
  *) echo "usage: $0 {one-use|source-identity}" >&2; exit 2 ;;
esac
source_file=crates/app/src/addon_selection.rs
mkdir -p target
scratch=$(mktemp -d "$PWD/target/selection-twin.XXXXXX")
cp "$source_file" "$scratch/original.rs"
restore() { cp "$scratch/original.rs" "$source_file"; rm -rf "$scratch"; }
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cargo test --offline -p patanyx "$test_name" -- --exact > "$scratch/control.log" 2>&1
grep -Fq 'test result: ok. 1 passed; 0 failed;' "$scratch/control.log"
python3 - "$source_file" "$1" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
if sys.argv[2] == 'one-use':
    old = 'self.pending.take().ok_or(SendError::Stale)?; // one-use boundary'
    new = 'self.pending.clone().ok_or(SendError::Stale)?; // one-use boundary'
else:
    old = 'if identity != active || identity != self.identity || pending.source != *source {'
    new = 'if false {'
if s.count(old) != 1:
    raise SystemExit('mutation target missing or ambiguous')
p.write_text(s.replace(old, new))
PY
if cargo test --offline -p patanyx "$test_name" -- --exact > "$scratch/mutant.log" 2>&1; then
  echo "FAIL: $1 survived" >&2; exit 1
fi
if ! grep -Fq "test $test_name ... FAILED" "$scratch/mutant.log" ||
   ! grep -Fq 'test result: FAILED. 0 passed; 1 failed;' "$scratch/mutant.log" ||
   ! grep -Fq 'assertion `left == right` failed' "$scratch/mutant.log"; then
  cat "$scratch/mutant.log" >&2
  echo "FAIL: build or unrelated failure, not a caught mutation" >&2; exit 1
fi
cp "$scratch/original.rs" "$source_file"
cargo test --offline -p patanyx "$test_name" -- --exact > "$scratch/restored.log" 2>&1
grep -Fq 'test result: ok. 1 passed; 0 failed;' "$scratch/restored.log"
echo "SELECTION TWIN CAUGHT: $1 (positive control and restored control passed)"
