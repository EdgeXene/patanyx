//! The window a STRICT Linux build shows instead of quitting silently when the
//! system's WebKitGTK is below the version it needs.
//!
//! Until 1.0.6 a release build on an old engine printed three lines to stderr
//! and exited 2, which a double-click shows as nothing at all. Now it says what
//! is needed and offers the fix: the system's own software updater, because the
//! engine belongs to the operating system and only its updater can change it.
//!
//! The decisions are pure functions over plain inputs (`os-release` text, which
//! updater apps exist) so they are tested without a display; `show` only draws
//! what they decide. Nothing here runs a shell: an updater app is started by
//! its exact path with fixed arguments.

#![cfg(target_os = "linux")]

/// The parts of `/etc/os-release` the advice depends on.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Distro {
    pub id: String,
    pub version_id: String,
    pub id_like: String,
    /// VERSION_CODENAME, and DEBIAN_CODENAME where a derivative states the
    /// Debian release it is built on (LMDE, for one).
    pub codename: String,
    pub debian_codename: String,
}

/// Parses `os-release` text (KEY=value lines, values optionally quoted).
pub fn parse_os_release(text: &str) -> Distro {
    let mut distro = Distro::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'').to_string();
        match key.trim() {
            "ID" => distro.id = value,
            "VERSION_ID" => distro.version_id = value,
            "ID_LIKE" => distro.id_like = value,
            "VERSION_CODENAME" => distro.codename = value,
            "DEBIAN_CODENAME" => distro.debian_codename = value,
            _ => {}
        }
    }
    distro
}

/// What the window tells the person to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Advice {
    /// Debian 12 never receives a fixed engine. No updater button: it cannot
    /// fix this, and offering one would send someone looking for an update
    /// that does not exist.
    Debian12NoFix,
    /// Open this updater app (exact path, fixed arguments).
    OpenUpdater {
        path: &'static str,
        args: &'static [&'static str],
    },
    /// No known updater app; an apt-based system gets the command to copy.
    AptCommand,
    /// Anything else: check for system updates, with the help link.
    CheckForUpdates,
}

/// The apt command shown when there is no updater app to open.
pub const APT_COMMAND: &str = "sudo apt update && sudo apt upgrade";

/// The help section on the Download page.
pub const HELP_URL: &str = "https://patanyx.net/download/#webkitgtk";

/// Known system updater apps, by exact path, with the arguments that open
/// their updates view. Order is preference.
pub const UPDATERS: &[(&str, &[&str])] = &[
    ("/usr/bin/gnome-software", &["--mode=updates"]),
    ("/usr/bin/update-manager", &[]),
    ("/usr/bin/plasma-discover", &["--mode", "Update"]),
];

/// The advice for this system. `exists` answers whether a path is an
/// executable file (injected so tests need no real files).
pub fn advice(distro: &Distro, exists: impl Fn(&str) -> bool) -> Advice {
    // Debian 12 itself, and derivatives built on it (Raspberry Pi OS, LMDE 6,
    // MX 23 and others name "bookworm" as their codename or Debian codename):
    // none of them will get the fixed engine from their own updates.
    let bookworm_based = (distro.id == "debian" && distro.version_id == "12")
        || distro.debian_codename == "bookworm"
        || (distro.codename == "bookworm"
            && (distro.id == "debian"
                || distro.id_like.split_whitespace().any(|like| like == "debian")));
    if bookworm_based {
        return Advice::Debian12NoFix;
    }
    for (path, args) in UPDATERS {
        if exists(path) {
            return Advice::OpenUpdater { path, args };
        }
    }
    let apt_based = distro.id == "debian"
        || distro.id == "ubuntu"
        || distro.id_like.split_whitespace().any(|like| like == "debian" || like == "ubuntu");
    if apt_based {
        Advice::AptCommand
    } else {
        Advice::CheckForUpdates
    }
}

/// A debug-build-only environment override; always `None` in release.
fn debug_env(name: &str) -> Option<String> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Whether `path` is a regular file someone may execute.
fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Shows the window and blocks until it is closed. Returns false when there
/// is no display to show it on, so the caller's stderr lines are the whole
/// message (a launch from a terminal over SSH, for instance).
pub fn show(engine: &crate::platform::EngineInfo) -> bool {
    use gtk::prelude::*;

    if gtk::init().is_err() {
        return false;
    }
    // Debug builds only: point the window at a sample os-release file, and
    // stand in a fake updater app, so every variant can be seen and tested on
    // one machine. Release builds read the system's own files and nothing else.
    let os_release_path = debug_env("PATANYX_DEBUG_OS_RELEASE");
    let os_release = match &os_release_path {
        Some(path) => std::fs::read_to_string(path).unwrap_or_default(),
        None => std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .unwrap_or_default(),
    };
    let fake_updater = debug_env("PATANYX_DEBUG_UPDATER_PRESENT").is_some();
    let advice = advice(&parse_os_release(&os_release), |path| {
        (fake_updater && path == UPDATERS[0].0) || is_executable(path)
    });

    let i18n = crate::i18n::I18n::bootstrap(&crate::prefs::load().ui_locale)
        .or_else(|_| crate::i18n::I18n::bootstrap("en"));
    let Ok(i18n) = i18n else {
        return false;
    };
    use crate::i18n::keys as k;
    let mut args = crate::i18n::Args::default();
    args.set("engine", engine.name);
    args.set("needed", crate::platform::join_version(engine.compiled_floor));
    args.set("running", engine.version_string());
    let mut body = i18n.resolve(k::ENGINE_WINDOW_BODY, &args);
    body.push_str("\n\n");
    match &advice {
        Advice::Debian12NoFix => body.push_str(&i18n.text(k::ENGINE_WINDOW_DEBIAN12)),
        // The button leads: a person who cannot start the browser needs the one
        // action that fixes it, not an explanation of why the browser cannot.
        Advice::OpenUpdater { .. } => body.push_str(&i18n.text(k::ENGINE_WINDOW_ACTION_BUTTON)),
        Advice::AptCommand => {
            body.push_str(&i18n.text(k::ENGINE_WINDOW_ACTION));
            body.push_str("\n\n");
            body.push_str(&i18n.text(k::ENGINE_WINDOW_COMMAND));
            body.push_str("\n");
            body.push_str(APT_COMMAND);
        }
        Advice::CheckForUpdates => body.push_str(&i18n.text(k::ENGINE_WINDOW_ACTION)),
    }
    if !matches!(advice, Advice::OpenUpdater { .. }) {
        let mut link = crate::i18n::Args::default();
        link.set("url", HELP_URL);
        body.push_str("\n\n");
        body.push_str(&i18n.resolve(k::ENGINE_WINDOW_MORE, &link));
    }

    const OPEN: gtk::ResponseType = gtk::ResponseType::Other(1);
    const COPY: gtk::ResponseType = gtk::ResponseType::Other(2);
    let dialog = gtk::MessageDialog::new(
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL,
        gtk::MessageType::Warning,
        gtk::ButtonsType::None,
        &i18n.text(k::ENGINE_WINDOW_TITLE),
    );
    dialog.set_title("PATANYX");
    dialog.set_secondary_text(Some(&body));
    // Selectable, so the command and the link can be copied by hand too.
    if let Ok(area) = dialog.message_area().downcast::<gtk::Box>() {
        for child in area.children() {
            if let Ok(label) = child.downcast::<gtk::Label>() {
                label.set_selectable(true);
            }
        }
    }
    match &advice {
        Advice::OpenUpdater { .. } => {
            let button = dialog.add_button(&i18n.text(k::ENGINE_WINDOW_OPEN_UPDATER), OPEN);
            // Drawn as the main action, so the fix is the obvious thing to press.
            button.style_context().add_class("suggested-action");
        }
        Advice::AptCommand => {
            dialog.add_button(&i18n.text(k::ENGINE_WINDOW_COPY), COPY);
        }
        _ => {}
    }
    dialog.add_button(&i18n.text(k::ENGINE_WINDOW_CLOSE), gtk::ResponseType::Close);
    dialog.set_default_response(if matches!(advice, Advice::OpenUpdater { .. }) {
        OPEN
    } else {
        gtk::ResponseType::Close
    });

    loop {
        let response = dialog.run();
        if response == OPEN {
            if let Advice::OpenUpdater { path, args } = &advice {
                // Exact path, fixed arguments, no shell, detached: the
                // updater outlives this process, which exits next.
                if let Err(e) = std::process::Command::new(path).args(*args).spawn() {
                    eprintln!("PATANYX: could not open {path}: {e}");
                }
            }
            break;
        }
        if response == COPY {
            let clipboard = gtk::Clipboard::get(&gtk::gdk::SELECTION_CLIPBOARD);
            clipboard.set_text(APT_COMMAND);
            // Keep the text available after this process exits.
            clipboard.store();
            continue;
        }
        break;
    }
    dialog.close();
    while gtk::events_pending() {
        gtk::main_iteration();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN_12: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n";
    const DEBIAN_13: &str = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_ID=\"13\"\nID=debian\n";
    const UBUNTU: &str = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n";
    const MINT: &str = "NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"22\"\n";
    const FEDORA: &str = "NAME=\"Fedora Linux\"\nVERSION_ID=41\nID=fedora\n";

    #[test]
    fn os_release_is_parsed_with_and_without_quotes() {
        let d = parse_os_release(MINT);
        assert_eq!(d.id, "linuxmint");
        assert_eq!(d.id_like, "ubuntu debian");
        assert_eq!(d.version_id, "22");
        assert_eq!(parse_os_release(FEDORA).version_id, "41");
        assert_eq!(parse_os_release(""), Distro::default());
    }

    #[test]
    fn debian_12_is_told_the_truth_and_gets_no_updater_button() {
        // Even with an updater app installed: it cannot fix this on Debian 12.
        assert_eq!(advice(&parse_os_release(DEBIAN_12), |_| true), Advice::Debian12NoFix);
    }

    #[test]
    fn debian_12_derivatives_are_recognized_by_codename() {
        let raspberry = "ID=debian\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Raspbian GNU/Linux 12 (bookworm)\"\n";
        let lmde = "ID=linuxmint\nID_LIKE=debian\nVERSION_CODENAME=faye\nDEBIAN_CODENAME=bookworm\n";
        let mx = "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n";
        for text in [raspberry, lmde, mx] {
            assert_eq!(advice(&parse_os_release(text), |_| true), Advice::Debian12NoFix, "{text}");
        }
        // Debian 13 derivatives are not caught by it.
        let trixie_based = "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n";
        assert_ne!(advice(&parse_os_release(trixie_based), |_| false), Advice::Debian12NoFix);
    }

    #[test]
    fn an_installed_updater_app_is_the_fix() {
        let only_gnome = |p: &str| p == "/usr/bin/gnome-software";
        assert_eq!(
            advice(&parse_os_release(DEBIAN_13), only_gnome),
            Advice::OpenUpdater { path: "/usr/bin/gnome-software", args: &["--mode=updates"] }
        );
        let only_ubuntu = |p: &str| p == "/usr/bin/update-manager";
        assert!(matches!(
            advice(&parse_os_release(UBUNTU), only_ubuntu),
            Advice::OpenUpdater { path: "/usr/bin/update-manager", .. }
        ));
    }

    #[test]
    fn without_an_updater_app_apt_systems_get_the_command() {
        for text in [DEBIAN_13, UBUNTU, MINT] {
            assert_eq!(advice(&parse_os_release(text), |_| false), Advice::AptCommand, "{text}");
        }
        assert_eq!(advice(&parse_os_release(FEDORA), |_| false), Advice::CheckForUpdates);
        assert_eq!(advice(&Distro::default(), |_| false), Advice::CheckForUpdates);
    }

    #[test]
    fn updater_apps_are_absolute_paths_started_without_a_shell() {
        for (path, args) in UPDATERS {
            assert!(path.starts_with("/usr/bin/"), "{path}");
            for arg in *args {
                assert!(!arg.contains([';', '&', '|', '$', '`', ' ']), "{arg}");
            }
        }
        assert!(HELP_URL.starts_with("https://"));
    }
}
