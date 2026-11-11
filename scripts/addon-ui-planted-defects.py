#!/usr/bin/env python3
"""One named mutation and its exact test; always restore source. Offline only."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "locked-data": ("crates/app/src/addon_manager.rs", "if action != Action::Remove && !unlocked {", "if false && action != Action::Remove && !unlocked {", "addon_manager::tests::public_data_requires_unlock_in_every_premium_state"),
    "motion-50ms": ("crates/app/src/addon_host.rs", "let r = clamp_rect(wanted, area.2, area.3, collapsed);", "std::thread::sleep(std::time::Duration::from_millis(50)); let r = clamp_rect(wanted, area.2, area.3, collapsed);", "addon_host::window_tests::motion_host_path_p95_stays_under_two_frames"),
    "delete-quiescence": ("crates/app/src/addon_manager.rs", "action.ends_session() && !quiet", "false && action.ends_session() && !quiet", "addon_manager::tests::delete_waits_for_quiescence_without_blocking_the_caller"),
    "delete-engine": ("crates/app/src/addon_data.rs", "remove_engine(engine).map_err", "Ok::<(), std::io::Error>(()).map_err", "addon_data::tests::delete_removes_namespace_and_engine_marker_but_keeps_neighbors_and_bundle"),
    "export-overwrite": ("crates/app/src/addon_data.rs", "options.write(true).create_new(true);", "options.write(true).create(true).truncate(true);", "addon_data::tests::export_unsafe_titles_are_contents_and_existing_files_are_never_overwritten"),
    "install-premium": ("crates/app/src/addon_manager.rs", "Self::Install => true,", "Self::Install => false,", "addon_manager::tests::addon_install_requires_premium_at_admission_and_commit"),
    "update-premium": ("crates/app/src/addon_manager.rs", "Self::Update => true,", "Self::Update => false,", "addon_manager::tests::addon_update_requires_premium_at_admission_and_commit"),
    "metadata-html": ("crates/app/src/chrome/addons.js", 'parts.name.textContent = addon.name;', 'parts.name.innerHTML = addon.name;', "metadata is text"),
    # The check owed at unlock (hand test U-1; reviews R-035, R-036).
    "unlock-every-change": ("crates/app/src/chrome/addons.js", "discoveryOwed = premium && (discoveryOwed || !wasPremium);", "discoveryOwed = premium;", "a second Premium change asks nothing"),
    "unlock-held": ("crates/app/src/chrome/addons.js", 'snapshot.visible !== true || catalog.held === true', 'snapshot.visible !== true', "a held list asks nothing"),
    "unlock-unread": ("crates/app/src/chrome/addons.js", "catalog.loaded !== true || snapshot.pending", "snapshot.pending", "it waits for the saved list to be read"),
    "unlock-pending": ("crates/app/src/chrome/addons.js", "catalog.loaded !== true || snapshot.pending)", "catalog.loaded !== true)", "it waits for a running job"),
    "unlock-busy": ("crates/app/src/chrome/addons.js", 'if (error && error.message === "busy") discoveryOwed = wasPremium;', "void error;", "a busy refusal asks again at the next status"),
    "unlock-render-hook": ("crates/app/src/chrome/addons.js", "    renderMainStatus();\n    discoverIfOwed();\n", "    renderMainStatus();\n", "becoming Premium with no list held asks once"),
    "unlock-double-refresh": ("crates/app/src/chrome/addons.js", "    if (discovery) return discovery;\n", "", "opening Add-ons as the unlock check goes out sends one refresh"),
    "unlock-loaded-field": ("crates/app/src/addon_manager.rs", '"loaded": view_landed(m),', '"read": view_landed(m),', "Rust's status names the catalog fields the unlock check reads"),
    "unlock-importing": ("crates/app/src/chrome/addons.js", "if (snapshot.importing === true) return;", "if (snapshot.importing === true && false) return;", "it waits for a backup import"),
    "unlock-backup-end": ("crates/app/src/chrome/chrome.js", "        if (window.__addons) window.__addons.backupFinished(msg.data);\n", "", "the end of a backup refreshes Add-ons"),
    "unlock-import-session": ("crates/app/src/chrome/addons.js", 'data.kind === "import" && data.ok === true && !data.lock_follows) discoveryOwed = wasPremium;', 'data.kind === "import" && data.ok === true && !data.lock_follows) void 0;', "a completed import with no list held asks once"),
    "addon-white-flash": ("crates/app/src/addon_host.rs", "        .with_background_color((surface[0], surface[1], surface[2], 255))\n", "", "addon_host::window_tests::the_add_on_window_opens_in_the_chrome_surface_colour"),
    # The one-time announcement (1.1.0; plan review B-2, H-1, M-1).
    "banner-stale": ("crates/app/src/chrome/addons.js", "catalog.held !== true || catalog.stale === true ||", "catalog.held !== true ||", "the banner shows not from an expired list"),
    "banner-installed": ("crates/app/src/chrome/addons.js", "named().find((a) => !a.installed && a.available &&", "named().find((a) => a.available &&", "the banner shows not when installed"),
    "banner-announced": ("crates/app/src/chrome/addons.js", "a.available && !snapshot.announced.includes(a.id))", "a.available)", "the banner shows not once announced"),
    "banner-tour-flag": ("crates/app/src/chrome/addons.js", 'byId("addon-banner-tour").hidden = snapshot.tour !== true;', 'byId("addon-banner-tour").hidden = false;', "no tour button where the tour page may not open"),
    "banner-tour-refused": ("crates/app/src/chrome/addons.js", '      await request("site_page_open", { page: "premium_tour" });\n      return true;\n    } catch (_) {\n      return false;', '      await request("site_page_open", { page: "premium_tour" });\n      return true;\n    } catch (_) {\n      return true;', "a tour page that did not open answers nothing, and the banner stays"),
    "banner-text": ("crates/app/src/chrome/addons.js", 'byId("addon-banner-name").textContent = addon.name;', 'byId("addon-banner-name").innerHTML = addon.name;', "a current list announces the add-on it names, in its own words"),
    "unlock-landed": ("crates/app/src/addon_manager.rs", "m.view_applied > 0", "true", "addon_manager::tests::an_empty_catalog_counts_as_none_held_only_once_a_read_has_landed"),
}

def gate_check(test):
    return "::" not in test

def run(test):
    cmd = ["node", "scripts/addon-manager-gate.js"] if gate_check(test) else ["cargo", "test", "--offline", "-p", "patanyx", test, "--", "--exact", "--nocapture"]
    return subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def gate(name):
    filename, old, new, test = CASES[name]
    path = ROOT / filename
    source = path.read_text()
    if source.count(old) != 1:
        raise RuntimeError(f"{name}: missing or ambiguous mutation target")
    baseline = run(test)
    success = "ADDON MANAGER GATE OK" if gate_check(test) else "test result: ok. 1 passed; 0 failed"
    if baseline.returncode != 0 or success not in baseline.stdout:
        raise RuntimeError(f"{name}: positive control failed\n{baseline.stdout[-5000:]}")
    try:
        path.write_text(source.replace(old, new, 1))
        result = run(test)
    finally:
        path.write_text(source)
    if gate_check(test):
        caught = result.returncode == 1 and f"ADDON MANAGER GATE FAIL: {test}\n" in result.stdout
    else:
        caught = result.returncode == 101 and "test result: FAILED. 0 passed; 1 failed" in result.stdout and f"test {test} ... FAILED" in result.stdout and f"thread '{test}'" in result.stdout
    if not caught:
        raise RuntimeError(f"{name}: survived, did not compile, or unrelated failure\n{result.stdout[-5000:]}")
    print(f"CAUGHT {name}: {test}", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", nargs="?", choices=CASES)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if not args.all and not args.name: parser.error("choose one mutation or --all")
    for name in CASES if args.all else [args.name]: gate(name)
