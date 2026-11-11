#!/usr/bin/env python3
"""Refuse a lockfile whose TLS stack is below its security floor.

Every connection PATANYX makes itself (update, engine-advisory, blocklist and
language-pack fetches, Premium activation, the chat relay, the resolver probe)
is verified by rustls through rustls-webpki, against the Mozilla roots in
webpki-roots plus, on the signature-protected fetches, the OS store. A version
below a floor here is a known way to accept a certificate the rest of the web
has stopped trusting:

  rustls         0.23.46   RUSTSEC-2026-0346, -0347, -0348, -0349
  rustls-webpki  0.103.16  RUSTSEC-2026-0382: chains through the distrusted
                           emSign intermediates (eMudhra keys generated with
                           insufficient randomness, October 2026) were accepted
  webpki-roots   1.0.10    RUSTSEC-2026-0381: emSign ECC Root CA - G3 removed.
                           0.26.11 is a shim that re-exports the resolved 1.x;
                           a pre-1.0 entry passes only when Cargo.lock shows
                           it forwarding to a vouched 1.x.

The net.rs tests pin the behaviour; this pins the versions, in every shipped
profile. A floor only ever moves up. cargo tree is evidence of what each
profile resolves, not proof of a finished binary's contents.

  python3 scripts/check-tls-floor.py              check this tree
  python3 scripts/check-tls-floor.py --self-test  check the policy itself
"""

import os
import pathlib
import subprocess
import sys
import tomllib


ROOT = pathlib.Path(os.environ.get("PATANYX_TLS_FLOOR_ROOT") or pathlib.Path(__file__).resolve().parent.parent)
FLOORS = {
    "rustls": (0, 23, 46),
    "rustls-webpki": (0, 103, 16),
    "webpki-roots": (1, 0, 10),
    "webpki-root-certs": (1, 0, 10),
}
# Below 1.0, webpki-roots MAY be a shim that carries no roots and re-exports a
# 1.x (0.26.11 is). Older 0.26 releases carry their own bundle. So a pre-1.0
# entry is exempt only when its own lock entry depends on a vouched 1.x --
# never by version number alone.
SHIM_CRATE, SHIM_BELOW = "webpki-roots", (1, 0, 0)
# Always locked: the release build cannot verify anything without them.
REQUIRED = ("rustls", "rustls-webpki", "webpki-roots")
TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc")
# Every feature set this line builds an artifact with, not a subset: a
# TLS-relevant feature can hide in any of them. The published binaries are
# the default set (scripts/build-windows.sh with FEATURES empty, and
# scripts/repro-build.sh with no --features); the other three are test builds.
PROFILES = (
    ("public", ()),
    ("chat and relay", ("--features", "chat,relay-client")),
    ("Premium test build", ("--features", "premium-unlocked")),
    ("add-on test build", ("--features", "addon-launch")),
)


def parse(version):
    """((major, minor, patch), is_prerelease). A pre-release sorts below its
    release, which is what a floor check wants."""
    core, _, pre = version.partition("-")
    parts = core.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(version)
    return tuple(int(p) for p in parts), bool(pre)


def dotted(floor):
    return ".".join(map(str, floor))


def check_locked(packages):
    """packages: [(name, version, [dependency strings])] from Cargo.lock.
    Returns (errors, vouched, shims): vouched maps a name to the versions that
    passed; shims holds the pre-1.0 webpki-roots versions proven to forward."""
    errors, vouched, present = [], {}, set()
    pending_shims = []
    for name, version, deps in packages:
        if name not in FLOORS:
            continue
        present.add(name)
        floor = FLOORS[name]
        try:
            core, pre = parse(version)
        except ValueError:
            errors.append(f"{name} {version}: unparseable version")
            continue
        if name == SHIM_CRATE and core < SHIM_BELOW:
            pending_shims.append((version, deps))
            continue
        # rustls-webpki 0.104 alphas are fixed only from alpha.8; refuse the
        # whole pre-release line rather than trust alpha numbering here.
        if name == "rustls-webpki" and core[:2] != (0, 103):
            errors.append(f"{name} {version}: outside the 0.103 line this gate vouches for (floor {dotted(floor)})")
            continue
        if core < floor or (core == floor and pre):
            errors.append(f"{name} {version}: below the security floor {dotted(floor)}")
            continue
        vouched.setdefault(name, set()).add(version)

    shims = set()
    for version, deps in pending_shims:
        # Cargo.lock names a dependency "crate" when one version is locked and
        # "crate version" when several are; a shim always sits beside its 1.x.
        forwards = [d.split()[1] for d in deps if d.split()[0] == SHIM_CRATE and len(d.split()) > 1]
        if not forwards:
            errors.append(f"{SHIM_CRATE} {version}: carries its own root bundle (no 1.x dependency); below the security floor {dotted(FLOORS[SHIM_CRATE])}")
        elif not all(f in vouched.get(SHIM_CRATE, set()) for f in forwards):
            errors.append(f"{SHIM_CRATE} {version}: forwards to {', '.join(forwards)}, which is not at or above {dotted(FLOORS[SHIM_CRATE])}")
        else:
            shims.add(version)

    for name in REQUIRED:
        if name not in present:
            errors.append(f"{name}: not in Cargo.lock; the gate cannot vouch for a stack it cannot see")
        elif name not in vouched:
            errors.append(f"{name}: no locked version at or above {dotted(FLOORS[name])}")
    return errors, vouched, shims


def check_profile(tree_lines, vouched, shims):
    """tree_lines: `cargo tree --prefix none -f {p}` output for one profile."""
    errors, seen = [], {}
    for line in tree_lines:
        fields = line.split()
        if len(fields) >= 2 and fields[0] in FLOORS and fields[1].startswith("v"):
            seen.setdefault(fields[0], set()).add(fields[1][1:])
    for name in REQUIRED:
        if not seen.get(name, set()) & vouched.get(name, set()):
            errors.append(f"{name}: no vouched version compiled into this profile")
    for name, versions in sorted(seen.items()):
        for version in sorted(versions):
            if name == SHIM_CRATE and version in shims:
                continue
            if version not in vouched.get(name, set()):
                errors.append(f"{name} {version}: compiled but not a vouched locked version")
    return errors, seen


def brotli_enabled(inverted_feature_tree):
    # Brotli certificate decompression allocates before authentication
    # (RUSTSEC-2026-0348). Off by default in rustls; it stays off.
    return 'rustls feature "brotli"' in inverted_feature_tree


def cargo_tree(target, features, *args):
    # --locked, not --offline: a fresh CI container has fetched only what the
    # Linux test steps needed, and the Windows tree needs Windows-only crates.
    # --locked still refuses any change to Cargo.lock.
    command = ["cargo", "tree", "--locked", "-p", "patanyx", "--target", target, *features, *args]
    run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if run.returncode:
        raise RuntimeError(f"{' '.join(command)}: {run.stderr.strip()}")
    return run.stdout


def main():
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    packages = [(p["name"], p["version"], p.get("dependencies", [])) for p in lock["package"]]
    errors, vouched, shims = check_locked(packages)
    if errors:
        for error in errors:
            print(f"TLS FLOOR GATE FAIL: Cargo.lock: {error}", file=sys.stderr)
        return 1
    for name in sorted(vouched):
        print(f"Cargo.lock: {name} {', '.join(sorted(vouched[name]))}")
    for version in sorted(shims):
        print(f"Cargo.lock: {SHIM_CRATE} {version} (shim, forwards to a vouched 1.x)")

    for target in TARGETS:
        for profile, features in PROFILES:
            try:
                tree = cargo_tree(target, features, "-e", "normal", "--prefix", "none", "--no-dedupe", "-f", "{p}")
                rustls_features = cargo_tree(target, features, "-e", "features", "-i", "rustls")
            except RuntimeError as error:
                print(f"TLS FLOOR GATE FAIL: {target} {profile}: {error}", file=sys.stderr)
                return 1
            errors, seen = check_profile(tree.splitlines(), vouched, shims)
            if brotli_enabled(rustls_features):
                errors.append("rustls Brotli certificate decompression is enabled")
            if errors:
                for error in errors:
                    print(f"TLS FLOOR GATE FAIL: {target} {profile}: {error}", file=sys.stderr)
                return 1
            detail = "; ".join(f"{n} {', '.join(sorted(v))}" for n, v in sorted(seen.items()))
            print(f"{target} {profile}: {detail}; Brotli off")

    print("TLS floor gate passed")
    return 0


def self_test():
    shim = ("webpki-roots", "0.26.11", ["webpki-roots 1.0.10"])
    good = [("rustls", "0.23.46", []), ("rustls-webpki", "0.103.16", []), shim, ("webpki-roots", "1.0.10", ["rustls-pki-types"])]

    def refused(packages, *needles):
        errors = check_locked(packages)[0]
        joined = " | ".join(errors)
        assert errors, f"accepted {packages}"
        for needle in needles:
            assert needle in joined, f"{packages}: expected {needle!r} in {joined!r}"

    errors, vouched, shims = check_locked(good)
    assert not errors, errors
    assert vouched["webpki-roots"] == {"1.0.10"}, "the 0.26 shim must not be vouched for as a root store"
    assert shims == {"0.26.11"}

    def swap(name, version):
        return [(n, version if n == name and v != "0.26.11" else v, d) for n, v, d in good]

    refused(swap("rustls", "0.23.45"), "rustls 0.23.45", "floor 0.23.46")
    refused(swap("rustls-webpki", "0.103.15"), "rustls-webpki 0.103.15", "floor 0.103.16")
    refused(swap("rustls-webpki", "0.103.16-rc.1"), "rustls-webpki 0.103.16-rc.1", "floor 0.103.16")
    refused(swap("rustls-webpki", "0.104.0-alpha.7"), "rustls-webpki 0.104.0-alpha.7", "outside the 0.103 line")
    refused(swap("webpki-roots", "1.0.9"), "webpki-roots 1.0.9", "floor 1.0.10")
    refused(good + [("webpki-root-certs", "1.0.9", [])], "webpki-root-certs 1.0.9", "floor 1.0.10")
    refused(good + [("webpki-roots", "1.0.9", [])], "webpki-roots 1.0.9")  # a second, older 1.x
    refused([p for p in good if p[0] != "rustls-webpki"], "rustls-webpki: not in Cargo.lock")
    refused(swap("rustls", "0.23"), "unparseable")
    assert not check_locked(good + [("webpki-root-certs", "1.0.10", [])])[0]
    # Pre-1.0 roots are exempt ONLY as a proven shim (R-001, review 2026-10-23):
    # 0.26.8 carries its own bundle and must be refused alongside a good 1.x,
    refused(good + [("webpki-roots", "0.26.8", [])], "webpki-roots 0.26.8", "carries its own root bundle")
    # a shim forwarding to an old 1.x is refused,
    refused([p for p in good if p[0] != "webpki-roots"] + [("webpki-roots", "0.26.11", ["webpki-roots 1.0.9"]), ("webpki-roots", "1.0.9", [])],
            "forwards to 1.0.9")
    # and shims or old bundles alone leave no root store to vouch for.
    refused([p for p in good if p[0] != "webpki-roots"] + [("webpki-roots", "0.26.8", [])],
            "carries its own root bundle", "webpki-roots: no locked version at or above 1.0.10")

    _, vouched, shims = check_locked(good)
    tree = ["patanyx v1.0.7 (/x)", "rustls v0.23.46", "rustls-webpki v0.103.16", "webpki-roots v0.26.11", "webpki-roots v1.0.10"]
    assert not check_profile(tree, vouched, shims)[0]
    errors, _ = check_profile(tree + ["webpki-roots v1.0.9"], vouched, shims)
    assert any("webpki-roots 1.0.9" in e for e in errors), errors
    errors, _ = check_profile(tree + ["webpki-roots v0.26.8"], vouched, shims)
    assert any("webpki-roots 0.26.8: compiled but not a vouched" in e for e in errors), errors
    errors, _ = check_profile([l for l in tree if l != "webpki-roots v1.0.10"], vouched, shims)
    assert any("webpki-roots: no vouched version compiled" in e for e in errors), errors
    errors, _ = check_profile([l for l in tree if not l.startswith("rustls-webpki")], vouched, shims)
    assert any("rustls-webpki: no vouched version compiled" in e for e in errors), errors
    assert brotli_enabled('rustls v0.23.46\n└── rustls feature "brotli"\n')
    assert not brotli_enabled('rustls v0.23.46\n└── rustls feature "ring"\n')

    print("TLS floor gate self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test() if sys.argv[1:] == ["--self-test"] else main())
