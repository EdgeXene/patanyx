#!/usr/bin/env python3
"""Planted defects for the add-on host's security boundaries: one named
mutation, one exact test, the source restored even on failure. Run with --all,
or name one. A build error, a missing or ambiguous target, or a failure for an
unrelated reason fails this gate rather than counting as a caught defect.
"""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HOST = "crates/app/src/addon_host.rs"
SESSION = "crates/app/src/addon_session.rs"
ENTITLEMENT = "crates/app/src/addon_entitlement.rs"
STORE = "crates/store/src/addon.rs"
CASES = {
    # The add-on window's CSP denies the network.
    "csp-network": (
        HOST,
        "img-src 'self'; font-src 'self'; connect-src 'none'; frame-src",
        "img-src 'self'; font-src 'self'; connect-src *; frame-src",
        "patanyx", "addon_host::tests::the_csp_denies_every_network_and_frame_channel"),
    # No frame keeps the Vault open.
    "frame-presence": (
        HOST,
        "    // A frame never counts as someone being here, `presence` or not: a\n",
        "    app.touch();\n    // A frame never counts as someone being here, `presence` or not: a\n",
        "patanyx", "addon_host::tests::no_add_on_frame_counts_as_presence"),
    # Every ordinary write is checked against live Premium.
    "write-live-premium": (
        HOST,
        "\n            || crate::addon_entitlement::current() != crate::addon_entitlement::Access::Full)",
        ")",
        "patanyx", "addon_entitlement::tests::the_live_decision_is_asked_on_every_write_every_event_and_at_midnight"),
    # A sent selection reaches the add-on only while the Vault is unlocked.
    "receiver-unlocked": (
        HOST,
        "(app.vault.is_some() && session.is_ready()",
        "(session.is_ready()",
        "patanyx", "addon_selection::tests::production_delivery_goes_through_the_live_host_after_redemption"),
    # An ending session admits nothing ordinary.
    "ending-admission": (
        SESSION,
        '(Some(_), _) => Some("session_ending"),',
        "(Some(_), _) => None,",
        "patanyx", "addon_session::tests::an_ending_session_admits_only_its_one_final_save_and_the_acknowledgment"),
    # The final save is admitted once.
    "final-save-once": (
        SESSION,
        "(*f != e.flush_id || e.flush_request.is_some() || e.acked.is_some())",
        "(*f != e.flush_id || e.acked.is_some())",
        "patanyx", "addon_session::tests::the_final_save_and_the_acknowledgment_are_each_single_use"),
    # A lock asks the add-on first, before the Vault goes.
    "lock-call-site": (
        "crates/app/src/state.rs",
        "        if !crate::addon_session::on_lock(self) {\n            return;\n        }\n",
        "",
        "patanyx", "addon_session::tests::every_exit_path_ends_the_session_first"),
    # Premium ends on the day after the expiry day.
    "live-expiry": (
        ENTITLEMENT,
        "LicenceState::Active { .. } => expires_day.is_some_and(|day| today <= day),",
        "LicenceState::Active { .. } => true,",
        "patanyx", "addon_entitlement::tests::an_active_activated_licence_is_full_through_its_last_day_and_ends_the_day_after"),
    # Activation on this device stays its own requirement.
    "activation": (
        ENTITLEMENT,
        "    if session.activation != ActivationState::Activated {",
        "    if false {",
        "patanyx", "addon_entitlement::tests::activation_is_its_own_requirement"),
    # Each add-on's pages are under its own key.
    "namespace-key": (
        STORE,
        '    hasher.update(b"addon:");\n    hasher.update(id.as_bytes());\n',
        '    hasher.update(b"addon:");\n',
        "patanyx-store", "addon::tests::namespaces_and_the_archive_cannot_read_each_other"),
    # A damaged index sweeps nothing.
    "unreadable-index-sweep": (
        STORE,
        "        let indexed = self.blobs.exists(INDEX_ID);\n        let index = self.read_index()?;",
        "        let indexed = self.blobs.exists(INDEX_ID);\n        let index = self.read_index().unwrap_or(Index { schema: 1, pages: Vec::new() });",
        "patanyx-store", "addon::tests::an_unreadable_index_removes_nothing_and_a_missing_page_is_listed_unreadable"),
    # A missing index sweeps no page.
    "missing-index-sweep": (
        STORE,
        'if indexed && id.starts_with("p-")',
        'if id.starts_with("p-")',
        "patanyx-store", "addon::tests::a_missing_index_removes_no_page_version"),
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
            f"test {test} ... FAILED" not in result.stdout):
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
