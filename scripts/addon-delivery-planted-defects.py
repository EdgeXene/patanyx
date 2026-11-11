#!/usr/bin/env python3
"""One named mutation, one exact test. Restore source even on test failure.
Run with --all for the six delivery security boundaries; no network required.
A build error, missing/ambiguous target, ignored test or unrelated failure fails
this gate, rather than counting as a detected defect.
"""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "wrong-key": (
        "crates/update/src/manifest.rs",
        "let ok = key.verify_strict(&message, &signature).is_ok();",
        "let ok = true;",
        "patanyx-update", "addon::tests::addon_signature_authority_and_domain"),
    "wrong-domain": (
        "crates/update/src/addon.rs",
        'b"PATANYX-ADDON-MANIFEST-V1\\n"',
        'b"PATANYX-ADDON-INDEX-V1\\n"',
        "patanyx-update", "addon::tests::addon_signature_authority_and_domain"),
    "tampered-file": (
        "crates/update/src/addon.rs",
        "if &actual != hash {", "if false && &actual != hash {",
        "patanyx-update", "addon::tests::addon_asset_hash_refuses_same_size_tamper"),
    "stale-index": (
        "crates/app/src/addon_install.rs",
        "if !index.succeeds(&previous) {", "if false && !index.succeeds(&previous) {",
        "patanyx", "addon_install::tests::addon_stale_index_is_persistent"),
    "redirect": (
        "crates/app/src/net.rs", ".redirects(0)", ".redirects(5)",
        "patanyx", "addon_delivery::tests::addon_delivery_agent_disables_redirects_and_bounds_time"),
    "token-url": (
        "crates/app/src/addon_delivery.rs",
        'let url = format!("{}{endpoint}", origin.trim_end_matches(\'/\'));',
        'let url = format!("{}{endpoint}?token={}", origin.trim_end_matches(\'/\'), &*auth.token);',
        "patanyx", "addon_delivery::tests::addon_delivery_success_and_token_only_in_body"),
    "activation-before-verification": (
        "crates/app/src/addon_install.rs",
        "let release = prepared.choice.release(&index)?;",
        '''let release = prepared.choice.release(&index)?;
        atomic_record(&self.root, &dir.join("active.json"), &serde_json::to_vec(&Active {
            schema: 1, manifest: patanyx_update::hex::encode(release.manifest_sha256())
        }).unwrap())?;''',
        "patanyx", "addon_install::tests::addon_open_reverifies_and_install_never_activates_unverified"),
}


def run(package, test):
    return subprocess.run(
        ["cargo", "test", "--offline", "-p", package, test, "--", "--exact", "--nocapture"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def gate(name):
    filename, old, new, package, test = CASES[name]
    path = ROOT / filename
    original = path.read_text()
    if original.count(old) != 1:
        raise RuntimeError(f"{name}: mutation target missing or ambiguous")
    baseline = run(package, test)
    if baseline.returncode != 0 or "test result: ok. 1 passed; 0 failed" not in baseline.stdout:
        print(baseline.stdout[-8000:])
        raise RuntimeError(f"{name}: positive control did not pass exactly once")
    try:
        path.write_text(original.replace(old, new, 1))
        result = run(package, test)
    finally:
        path.write_text(original)
    if (result.returncode != 101 or
            "test result: FAILED. 0 passed; 1 failed" not in result.stdout or
            f"test {test} ... FAILED" not in result.stdout or
            f"thread '{test}'" not in result.stdout):
        print(result.stdout[-8000:])
        raise RuntimeError(f"{name}: survived, failed to compile, or failed for an unrelated reason")
    print(f"CAUGHT {name}: {test}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", nargs="?", choices=CASES)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if not args.all and not args.name:
        parser.error("choose a mutation or --all")
    try:
        for name in CASES if args.all else [args.name]:
            gate(name)
    except (RuntimeError, OSError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
