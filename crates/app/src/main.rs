// Release builds on Windows must not allocate a console: without this the GUI
// opens with an empty black console window behind it. Debug builds keep the
// console, because --smoke-test reports SMOKE OK / SMOKE FAIL on stdout and
// scripts/smoke.ps1 runs the debug binary.
//
// The attribute only means anything on a binary, which is why it lives here
// and not in lib.rs with the rest of the app.
#![cfg_attr(
    all(windows, not(debug_assertions)),
    windows_subsystem = "windows"
)]

//! The PATANYX launcher. The browser is the `patanyx_app` library (lib.rs);
//! this file exists so the binary has an entry point and so the windows
//! subsystem attribute sits on the binary. Keep it this small: source pins
//! that forbid something read this file as well as lib.rs, but a pin that
//! requires something only looks in lib.rs.

fn main() {
    patanyx_app::run()
}
