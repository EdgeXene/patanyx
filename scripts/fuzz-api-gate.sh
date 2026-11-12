#!/usr/bin/env bash
# The `fuzz-api` feature stays a test surface, and the fuzz workspace fuzzes
# what ships. Four checks, from the repository root:
#
#   1. `fuzz-api` is not in crates/app's default features, directly or through
#      another feature;
#   2. no build, packaging, release or CI file names it (only this gate, the
#      fuzz workspace, the app's own manifest and lib.rs, and the refusal
#      helper may), and every script that takes a feature list from its
#      caller refuses it before building (refuse-test-only-features.sh);
#   3. a crate that uses `patanyx_app::fuzz_api` FAILS to compile without the
#      feature and compiles with it. Both halves, because a string scan of a
#      stripped release binary proves nothing: the module name need not survive
#      compilation, so the positive control is the compiler itself;
#   4. every crate fuzz/Cargo.lock shares with Cargo.lock resolves to a version
#      the root lock ships (fuzz/README.md, "Same versions as a release").
#
#   scripts/fuzz-api-gate.sh            all four (3 compiles the app twice)
#   scripts/fuzz-api-gate.sh --quick    1, 2 and 4 only
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
fail() { echo "fuzz-api-gate: FAIL: $*" >&2; exit 1; }

# 1. Not a default, however indirectly.
cargo metadata --format-version 1 --no-deps --manifest-path crates/app/Cargo.toml \
  | python3 -I -c '
import json, sys
pkg = next(p for p in json.load(sys.stdin)["packages"] if p["name"] == "patanyx")
feats = pkg["features"]
seen, todo = set(), list(feats.get("default", []))
while todo:
    f = todo.pop()
    if f in seen or f.startswith("dep:") or "/" in f:
        continue
    seen.add(f)
    todo.extend(feats.get(f, []))
if "fuzz-api" in seen:
    sys.exit("fuzz-api is reachable from default features: " + ", ".join(sorted(seen)))
if "fuzz-api" not in feats:
    sys.exit("crates/app declares no fuzz-api feature; this gate is checking the wrong thing")
' || fail "check 1"
echo "  ok 1: fuzz-api is not a default feature"

# 2. Nothing that builds, packages, releases or tests a shipped build names it.
# `fuzz-api` not followed by `-`, so a script that RUNS this gate is not a hit.
hits="$(grep -rIlE --exclude-dir={target,.git,node_modules,vendor,fuzz} -e 'fuzz-api([^-]|$)' -e 'fuzz_api' . \
  | grep -v -E '^\./(scripts/fuzz-api-gate\.sh|scripts/refuse-test-only-features\.sh|crates/app/Cargo\.toml|crates/app/src/lib\.rs)$' || true)"
[ -z "$hits" ] || fail "check 2: named outside the allowed files: $hits"
for f in scripts/build-windows.sh scripts/build-flatpak.sh scripts/repro-build.sh; do
  refuse="$(grep -n -m1 'refuse-test-only-features\.sh' "$f" | cut -d: -f1)"
  build="$(grep -n -m1 -E '^[^#]*(cargo (xwin )?build|docker run)' "$f" | cut -d: -f1)"
  [ -n "$refuse" ] && [ -n "$build" ] && [ "$refuse" -lt "$build" ] \
    || fail "check 2: $f does not refuse test-only features before it builds (refusal line ${refuse:-none}, first build line ${build:-none})"
done
# Every spelling cargo accepts, as repro-build.sh's arguments or as FEATURES
# expanded unquoted into the Flatpak command line (review, 2026-10-30).
for ok in '' 'chat' 'chat,relay-client' '--features chat' '--features=linux-bridge' \
          '-Fchat' '--locked --features chat,relay-client'; do
  bash scripts/refuse-test-only-features.sh "$ok" 2>/dev/null \
    || fail "check 2: the refusal helper refuses an ordinary list: '$ok'"
done
for bad in 'fuzz-api' 'chat fuzz-api' 'chat,fuzz-api' 'patanyx/fuzz-api' \
           '--features=fuzz-api' '--features=chat,fuzz-api' '--features=patanyx/fuzz-api' \
           '-Ffuzz-api' '-Fpatanyx/fuzz-api' '-F fuzz-api' '--features chat fuzz-api' \
           '--all-features' 'chat -Ffuzz-api' 'chat --all-features'; do
  if bash scripts/refuse-test-only-features.sh "$bad" 2>/dev/null; then
    fail "check 2: the refusal helper let this through: '$bad'"
  fi
done
echo "  ok 2: named only where allowed, and the three build entry points refuse it before building"

# 4. The fuzz lock fuzzes shipped versions (cheap, so before the compiles).
python3 -I - "$ROOT/Cargo.lock" "$ROOT/fuzz/Cargo.lock" <<'EOF' || fail "check 4"
import re, sys
def pkgs(path):
    out = {}
    for m in re.finditer(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', open(path).read()):
        out.setdefault(m.group(1), set()).add(m.group(2))
    return out
root, fuzz = pkgs(sys.argv[1]), pkgs(sys.argv[2])
bad = [(n, sorted(fuzz[n]), sorted(root[n])) for n in sorted(set(root) & set(fuzz)) if not fuzz[n] <= root[n]]
for n, f, r in bad:
    print(f"  {n}: fuzz resolves {f}, a release ships {r}", file=sys.stderr)
sys.exit(1 if bad else 0)
EOF
echo "  ok 4: every crate fuzz/Cargo.lock shares with Cargo.lock is a shipped version"

[ "${1:-}" = "--quick" ] && { echo "fuzz-api-gate OK (quick: 1, 2, 4)"; exit 0; }

# 3. The compiler is the positive control.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/c/src"
cat > "$work/c/Cargo.toml" <<EOF
[package]
name = "fuzz-api-consumer"
version = "0.0.0"
edition = "2021"
publish = false

[features]
with = ["patanyx/fuzz-api"]

[dependencies]
patanyx = { path = "$ROOT/crates/app" }

[patch.crates-io]
wry = { path = "$ROOT/vendor/wry" }

[workspace]
EOF
echo 'fn main() { let _ = patanyx_app::fuzz_api::hover_readout("https://example.com/"); }' > "$work/c/src/main.rs"
cp Cargo.lock "$work/c/Cargo.lock"
export CARGO_TARGET_DIR="${FUZZ_API_GATE_TARGET:-$ROOT/target/fuzz-api-gate}"
if cargo check --quiet --manifest-path "$work/c/Cargo.toml" > "$work/without.log" 2>&1; then
  fail "check 3: fuzz_api compiled WITHOUT the feature; a shipped build would carry it"
fi
grep -q 'fuzz_api' "$work/without.log" \
  || fail "check 3: the build without the feature failed for another reason: $(tail -5 "$work/without.log")"
cargo check --quiet --manifest-path "$work/c/Cargo.toml" --features with > "$work/with.log" 2>&1 \
  || fail "check 3: fuzz_api does not compile WITH the feature: $(tail -5 "$work/with.log")"
echo "  ok 3: without the feature fuzz_api does not exist; with it, it compiles"
echo "fuzz-api-gate OK (1, 2, 3, 4)"
