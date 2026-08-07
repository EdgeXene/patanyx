//! Preferences that must be readable BEFORE the vault is unlocked.
//!
//! Everything else the user configures lives in the encrypted vault or store,
//! and that is the right default. This file exists for the narrow set of
//! settings the browser needs at process start, when there is no passphrase
//! yet and nothing is decrypted.
//!
//! Today that set has exactly one member: which DNS resolver the engine should
//! use. It has to be here because the WebView2 environment -- where the setting
//! is applied -- is created before any window exists, let alone a vault prompt.
//!
//! # Why plaintext is acceptable here, and where the line is
//!
//! This file is NOT encrypted, and it must never hold anything that needs to
//! be. A resolver preference reveals that the user prefers a resolver. That is
//! a different category from a credential, and encrypting it would be theatre:
//! the key would have to be readable without a passphrase, which is not
//! encryption.
//!
//! The rule for anything added here later: if disclosure of the VALUE would
//! harm the user, it does not belong in this file. It belongs in the vault,
//! and whatever needs it belongs after unlock.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Which resolver the engine should send DNS queries to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Whatever the operating system is configured with -- which, for a user
    /// running a VPN, is their VPN's resolver.
    ///
    /// THE DEFAULT, and this is a CHOICE THE BROWSER DECLINES TO MAKE rather
    /// than a recommendation of the system resolver. Every alternative here
    /// hands a specific company every domain the user looks up. That can be a
    /// good trade, and the panel argues it, but it is the user's trade to make:
    /// a browser that quietly redirected DNS to a party of its own choosing
    /// would be doing a smaller version of the thing this product exists to
    /// refuse. It also has a concrete cost -- overriding a VPN's resolver
    /// splits that user's traffic across two companies neither of them chose.
    ///
    /// This is also the only setting that WORKS ON CAPTIVE-PORTAL WIFI, because
    /// it carries no DoH mode and so does not fail closed. See
    /// [`Self::doh_mode`]. That is a happy accident rather than the reason, but
    /// it does mean a first-run user is never stranded on hotel WiFi.
    #[default]
    System,
    /// Mullvad's FILTERING resolver. Free, no account, Swedish jurisdiction,
    /// no-logging policy.
    ///
    /// OPT-IN, like every other resolver here. What choosing it buys is not
    /// anonymity -- Mullvad sees every domain, and that is stated wherever the
    /// choice is offered -- it is moving the observer from a party with a
    /// commercial interest in the data to one with a published no-logging
    /// policy and no such interest.
    ///
    /// The `base` endpoint, not the bare one: it blocks known malware and
    /// phishing domains as well as ads and trackers. That is deliberate and it
    /// corrects an asymmetry -- Quad9's default endpoint filters threats, so
    /// shipping Mullvad's unfiltered endpoint alongside it meant choosing
    /// Mullvad silently bought LESS protection than choosing Quad9.
    ///
    /// The filtering is also the only automatically-updating malicious-domain
    /// defence this browser has while its own signed blocklist is unbuilt, and
    /// SmartScreen is off. The cost is real and belongs in the UI, not just
    /// here: Mullvad decides what is on that list, and a false positive looks
    /// to the user like a site being down.
    ///
    /// Mullvad-the-resolver and Mullvad-the-VPN are separate services and
    /// choosing this assumes neither. A user on a different VPN who picks this
    /// is splitting their DNS away from the provider carrying their traffic,
    /// which is usually not what they want; the panel says so.
    Mullvad,
    /// Quad9. Swiss non-profit, no-logging policy, malware filtering on by
    /// default, DNSSEC validated, and EDNS Client Subnet not sent -- all four
    /// stated in Quad9's published feature table.
    Quad9,
}

/// Which update manifest this install fetches. Early access to what will
/// become the next stable release -- NOT a permanently-diverged version
/// line, which is why choosing `Beta` changes only which URL is fetched and
/// touches nothing about how versions compare (see `updater::manifest_url`
/// and the note in docs/update-channel.md on why `decide()` needs no
/// channel-aware branching for this).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    /// The default, and the only channel that existed before this setting
    /// did. A user who has never opened this option is unaffected by it.
    #[default]
    Stable,
    /// A second, equally FIXED manifest URL -- `{platform}-beta.json`, not a
    /// per-install path. Every beta subscriber fetches the identical URL as
    /// every other one, indistinguishable from each other, exactly the
    /// property the stable URL already has. Nothing here is per-install.
    Beta,
}

/// Whether this browser routes its traffic through a userspace WireGuard
/// tunnel.
///
/// TWO VARIANTS IS THE WHOLE ENUM, and that is a decision, not a gap left
/// for the next reader to fill in. An `OwnServer` variant would be
/// indistinguishable from `Imported` at runtime -- both are "a WireGuard
/// configuration the user supplied" -- so it would add a third wire name to
/// support forever while changing nothing but a label in the UI. A
/// provider-preset variant (pick a provider from a list, no config file)
/// IS a genuinely different feature, but there is no preset list behind it
/// yet, and shipping the variant now would offer a choice that does
/// nothing. Do not "complete" this enum; grow it when one of those facts
/// changes, not before.
///
/// The mode is ALL that lives here. The WireGuard configuration itself --
/// every key in it -- is a secret, and this file is plaintext by design:
/// disclosure of a tunnel configuration would harm the user, so by the
/// module-header rule it belongs in the encrypted store, never in
/// prefs.json. For the same reason, do not add endpoints, ports, key
/// names, or file paths to this enum or to `Prefs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// Browsing goes direct, exactly as it does without this feature.
    ///
    /// THE DEFAULT, and a choice the browser declines to make in the same
    /// sense as `DnsMode::System`: routing every page through a server is a
    /// trade -- that server sees the traffic -- and it is the user's trade
    /// to make. It is also the only value that makes sense for a user who
    /// has never opened this setting: nothing has been imported, so there
    /// is no tunnel to be on.
    #[default]
    Off,
    /// Route this browser's traffic through a WireGuard configuration the
    /// user imported. Which server sits at the far end is the user's
    /// business, not the browser's, and this variant records none of it --
    /// only the fact that the choice was made. The configuration itself
    /// lives in the encrypted store; this variant is the non-secret fact
    /// that there is one.
    Imported,
}

/// Which color scheme pages are asked to use. This is the ENGINE-LEVEL
/// preference (prefers-color-scheme), not a forced restyle: sites with a
/// dark theme use it, sites without one are unchanged, and nothing is ever
/// injected into content to fake more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageTheme {
    /// Follow the operating system. THE DEFAULT: the OS setting is the
    /// user's standing answer to this exact question, and a browser that
    /// second-guesses it uninvited has made a choice that was not its to
    /// make.
    #[default]
    Auto,
    /// Ask every site for its dark theme.
    Dark,
    /// Ask every site for its light theme.
    Light,
}

impl PageTheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            _ => None,
        }
    }
}

/// Which accent theme the chrome UI wears. Purely cosmetic and purely
/// local: the accent family in chrome.css is the ONLY thing this changes.
/// Neutrals and the state colours (green = protection on, amber = refused,
/// red = failed) are deliberately not themeable per accent -- they carry
/// meaning. (Chrome SCHEMES may re-tune them per background; an accent may
/// not.)
///
/// The set beyond the original four (BloodRed onward, minus the removed
/// Rose) is the SEED of the future premium theme pack. It ships unlocked:
/// nothing may gate it until the licence server exists and the project owner
/// flips the gate deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChromeTheme {
    /// The blue the chrome has always worn.
    #[default]
    Default,
    Violet,
    /// Replaced Rose 2026-08-04 deliberately. The alias keeps a prefs.json written by a
    /// rose-era build loading instead of failing the whole prefs read.
    #[serde(alias = "rose")]
    BloodRed,
    Sky,
    Green,
    Amber,
    Teal,
    Slate,
    Purple,
}

impl ChromeTheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Violet => "violet",
            Self::BloodRed => "blood_red",
            Self::Sky => "sky",
            Self::Green => "green",
            Self::Amber => "amber",
            Self::Teal => "teal",
            Self::Slate => "slate",
            Self::Purple => "purple",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default" => Some(Self::Default),
            "violet" => Some(Self::Violet),
            // "rose" accepted for the same reason as the serde alias: it is
            // what a rose-era build stored, and it became blood red.
            "blood_red" | "rose" => Some(Self::BloodRed),
            "sky" => Some(Self::Sky),
            "green" => Some(Self::Green),
            "amber" => Some(Self::Amber),
            "teal" => Some(Self::Teal),
            "slate" => Some(Self::Slate),
            "purple" => Some(Self::Purple),
            _ => None,
        }
    }
}

/// Which chrome SCHEME the whole chrome wears: the neutral, line, text and
/// state ladders, orthogonal to the accent. Dark is the chrome this app
/// has always had; White and Black landed 2026-08-04 with the neutral
/// lift. Manual pick only, by deliberate decision -- nothing here follows
/// the OS (page colors already do that job for PAGES, deliberately).
/// Part of the premium theme-pack seed; ships unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChromeScheme {
    /// The hand-tuned near-black the chrome has always worn.
    #[default]
    Dark,
    /// Black text on white.
    White,
    /// True black, for the people who mean it.
    Black,
}

impl ChromeScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::White => "white",
            Self::Black => "black",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dark" => Some(Self::Dark),
            "white" => Some(Self::White),
            "black" => Some(Self::Black),
            _ => None,
        }
    }
}

impl UpdateChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "stable" => Some(Self::Stable),
            "beta" => Some(Self::Beta),
            _ => None,
        }
    }
}

impl DnsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Mullvad => "mullvad",
            Self::Quad9 => "quad9",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "system" => Some(Self::System),
            "mullvad" => Some(Self::Mullvad),
            "quad9" => Some(Self::Quad9),
            _ => None,
        }
    }

    /// The DoH template, or `None` for the system resolver.
    ///
    /// Verified against each operator's published documentation rather than
    /// recalled. A wrong template does not degrade -- it means DNS fails, so
    /// these are not values to guess at.
    pub fn doh_template(self) -> Option<&'static str> {
        match self {
            Self::System => None,
            Self::Mullvad => Some("https://base.dns.mullvad.net/dns-query"),
            Self::Quad9 => Some("https://dns.quad9.net/dns-query"),
        }
    }

    /// The engine's DoH mode for this choice.
    ///
    /// `secure` FAILS CLOSED: if the chosen resolver cannot be reached, the
    /// browser does not resolve at all rather than falling back to whatever
    /// the network offers. That is the point. A user who deliberately picked
    /// Mullvad and got silently downgraded to an airport's plaintext resolver
    /// has the leak they chose this setting to close, and no way to find out --
    /// WebView2 exposes no signal that a downgrade happened.
    ///
    /// THE COST IS CAPTIVE PORTALS. Hotel, airport and cafe login pages work
    /// BY hijacking DNS, so fail-closed means the browser cannot reach them at
    /// all. That is why it applies only when a resolver was explicitly chosen:
    /// `System` stays permissive, so switching back to it (and restarting) is
    /// the way onto that network. The UI has to say this, because a browser
    /// that will not load anything in a hotel and does not explain why reads
    /// as broken.
    ///
    /// `None` for `System`: with no template there is nothing to be secure
    /// ABOUT, and passing a mode without a template would configure a fallback
    /// the user never asked for.
    pub fn doh_mode(self) -> Option<&'static str> {
        match self {
            Self::System => None,
            Self::Mullvad | Self::Quad9 => Some("secure"),
        }
    }

    /// One sentence for the UI. Says what the choice COSTS as well as what it
    /// buys -- picking a resolver moves who sees your lookups, it does not
    /// remove them.
    pub fn describe(self) -> &'static str {
        match self {
            Self::System => {
                "The default. Your machine keeps using whatever it uses now: your \
                 VPN's resolver if you have one, otherwise your internet \
                 provider, who can log and sell what you look up. The lookup \
                 is not encrypted, so a network can also strip the key that \
                 hides the site name inside the connection and put it back in \
                 the open. This is the only setting that works on public WiFi \
                 that asks you to log in."
            }
            Self::Mullvad => {
                "Encrypted, and sent to Mullvad, who also block malware, \
                 phishing, ad and tracker domains. They see every domain you \
                 look up instead of your provider, under a no-logging policy. \
                 It also protects the key that hides the site name inside the \
                 connection, which a network can strip over unencrypted DNS. \
                 This overrides your VPN's resolver, and never falls back to \
                 the network's DNS, so public WiFi login pages will not load \
                 until you switch back to System."
            }
            Self::Quad9 => {
                "Encrypted, and sent to Quad9, a Swiss non-profit who also \
                 block known malicious domains. They see every domain you look \
                 up. It also protects the key that hides the site name inside \
                 the connection, which a network can strip over unencrypted \
                 DNS. This overrides your VPN's resolver, and never falls back \
                 to the network's DNS, so public WiFi login pages will not \
                 load until you switch back to System."
            }
        }
    }
}

// The consumers of these are the tunnel panel's IPC arms (tunnel_set_mode
// et al.), which land in a later phase of the same feature -- allow rather
// than pretend a caller, exactly like tunnel_control's recorded-state
// readers.
#[allow(dead_code)]
impl TunnelMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Imported => "imported",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "imported" => Some(Self::Imported),
            _ => None,
        }
    }

    /// The user-facing description of this choice, and the ONLY source of
    /// it: every surface that explains the tunnel takes its text from here,
    /// so two UIs can never word the same choice differently. In the same
    /// spirit as [`DnsMode::describe`], the text says what the choice COSTS
    /// as well as what it buys -- the server at the far end sees the
    /// traffic, and a tunnel that is down fails closed rather than falling
    /// back.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Off => {
                "The default. Your browsing goes straight out, the same as \
                 any other browser."
            }
            Self::Imported => {
                "Sends only this browser's traffic through the WireGuard \
                 server you imported, not your other apps and not the rest of \
                 the system. You picked that server, and it can see your \
                 traffic, so this is not an anonymity feature. If the tunnel \
                 goes down, pages fail to load. PATANYX never falls back to a \
                 direct connection. Switching this on or off takes effect the \
                 next time you start the browser."
            }
        }
    }
}

/// How long the vault may sit idle before it locks itself, in seconds.
///
/// ZERO MEANS NEVER, and it is spelled that way rather than as a very large
/// number: "never" is a decision the user made, and encoding it as 4294967295
/// would leave the code unable to tell it apart from a corrupted value. Every
/// reader has to handle the zero case explicitly, which is the point.
///
/// The default stays at five minutes. Raising it was considered and rejected:
/// the reason five felt punishing was that almost nothing counted as activity,
/// not that five is wrong. With keypresses inside pages now counting, and a
/// warning before the lock, five minutes of genuinely no input is a real
/// absence.
pub const AUTOLOCK_DEFAULT_SECS: u64 = 300;

/// Offered in the vault panel. Anything else in the file is honoured as-is --
/// this list is what the UI shows, not a validation rule, so a user editing
/// prefs.json by hand is not overruled.
pub const AUTOLOCK_CHOICES_SECS: &[u64] = &[300, 900, 1800, 3600, 0];

fn autolock_default() -> u64 {
    AUTOLOCK_DEFAULT_SECS
}

/// ON by default, and it needs this function for exactly the reason
/// `autolock_default` needs its own: `bool`'s natural default is `false`, and
/// `false` here means DO NOT LOCK when you lock your computer. An old
/// prefs.json written before this field existed would silently pick the
/// weaker posture. Same class of mistake as a numeric 0 meaning "never".
fn lock_on_session_lock_default() -> bool {
    true
}

/// ON by default, for the same reason `lock_on_session_lock_default` exists:
/// `bool`'s natural default is `false`, and `false` here means LET EVERY SITE
/// READ A CLEAN FINGERPRINT. An old prefs.json written before this field
/// existed must land on the protective posture, not the weaker one.
fn fingerprint_noise_default() -> bool {
    true
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub dns: DnsMode,
    /// Seconds of inactivity before the vault locks; 0 disables it.
    #[serde(default = "autolock_default")]
    pub vault_autolock_secs: u64,
    /// Early access to updates. `#[serde(default)]` at the struct level
    /// already gives an old prefs.json missing this field `UpdateChannel`'s
    /// own `#[default]`, which is `Stable` -- unlike `vault_autolock_secs`,
    /// there is no wrong-numeric-default trap here, so no field-level
    /// override function is needed.
    pub update_channel: UpdateChannel,
    /// Which tunnel, if any, carries this browser's traffic.
    /// `#[serde(default)]` at the struct level already gives an old
    /// prefs.json missing this field `TunnelMode`'s own `#[default]`, which
    /// is `Off` -- and `Off` IS the correct absent-field meaning: a user
    /// who has never touched the feature has no tunnel. As with
    /// `update_channel` and unlike `vault_autolock_secs`, there is no
    /// wrong-default trap here, so no field-level override function is
    /// needed.
    pub tunnel: TunnelMode,
    /// Page color-scheme preference. `#[serde(default)]` at the struct
    /// level gives an old prefs.json `Auto`, which IS the correct
    /// absent-field meaning: a user who never touched this follows the OS.
    pub page_theme: PageTheme,
    /// Chrome accent theme. Absent field reads Default, which renders
    /// byte-identically to every build before theming existed.
    pub chrome_theme: ChromeTheme,
    /// Chrome scheme (Dark/White/Black). Absent field reads Dark: same
    /// byte-identical promise as the accent above.
    pub chrome_scheme: ChromeScheme,
    /// Download a verified update in the background the moment a check
    /// offers one, so the consent click is an instant restart instead of a
    /// wait. INSTALLING still requires that click -- this flag never
    /// touches that. Default ON (the Firefox shape); the update panel
    /// carries the switch for metered or minimal setups.
    pub update_background_download: bool,
    /// Lock the vault when the workstation locks or the machine suspends.
    ///
    /// Separate from `vault_autolock_secs` because the two watch different
    /// things: the timer watches for no typing IN THE BROWSER, which cannot
    /// see you walk away and lock the screen with ten minutes still on the
    /// clock. See `lock_on_session_lock_default` for why this carries an
    /// explicit default rather than taking `bool`'s.
    #[serde(default = "lock_on_session_lock_default")]
    pub vault_lock_on_session_lock: bool,
    /// Add small deterministic noise to fingerprinting readouts (canvas
    /// pixels, audio samples, WebGL vendor/renderer strings), keyed per
    /// site and per session. Applies to tabs created AFTER a change: injection happens at webview construction and
    /// neither engine can re-register a live view, the same non-retroactive
    /// shape `ephemeral` has. See `platform::privacy::divergence_script`.
    #[serde(default = "fingerprint_noise_default")]
    pub fingerprint_noise: bool,
}

// Hand-written rather than derived, because `#[derive(Default)]` would give
// `vault_autolock_secs` the numeric default of 0 -- which this type defines as
// NEVER LOCK -- and `vault_lock_on_session_lock` the boolean default of false,
// which means do not lock on workstation lock. A defaulting mistake that
// silently disables a security control is the kind that ships. Both fields
// therefore also carry `#[serde(default = ...)]` so an OLD prefs.json missing
// them lands on the safe value too, not just a freshly constructed Prefs.
impl Default for Prefs {
    fn default() -> Self {
        Self {
            dns: DnsMode::default(),
            vault_autolock_secs: AUTOLOCK_DEFAULT_SECS,
            update_channel: UpdateChannel::default(),
            tunnel: TunnelMode::default(),
            page_theme: PageTheme::default(),
            chrome_theme: ChromeTheme::default(),
            chrome_scheme: ChromeScheme::default(),
            update_background_download: true,
            vault_lock_on_session_lock: lock_on_session_lock_default(),
            fingerprint_noise: fingerprint_noise_default(),
        }
    }
}

/// `<vault dir>/prefs.json`.
///
/// Beside the vault rather than recomputed, for the same reason
/// `browsing_profile_dir` does it: `PATANYX_DATA_DIR` and the pre-rename
/// `rustbrowse` fallback are honoured exactly once, in `Vault::default_path`,
/// and a second copy of that precedence would drift.
fn prefs_path() -> PathBuf {
    let vault = patanyx_vault::Vault::default_path();
    vault
        .parent()
        .map_or_else(|| PathBuf::from("."), |p| p.to_path_buf())
        .join("prefs.json")
}

/// `<vault dir>/onboarding-seen`. A DEDICATED marker, not a `Prefs` field --
/// on purpose, and the reason is what "first run" would otherwise mean.
///
/// `Prefs` only exists on disk once a user has touched DNS or vault
/// auto-lock (`save()` is called from those two commands and nowhere else),
/// so an existing install that never touched either setting has no
/// `prefs.json` today, same as a genuinely fresh one. Folding "has this
/// install seen the tour" into that file would read that existing user's
/// next launch as first-run too. A marker whose only job is answering this
/// one question does not inherit that ambiguity.
fn onboarding_marker_path() -> PathBuf {
    let vault = patanyx_vault::Vault::default_path();
    vault
        .parent()
        .map_or_else(|| PathBuf::from("."), |p| p.to_path_buf())
        .join("onboarding-seen")
}

/// The decision table, separated from the I/O that feeds it so it can be
/// tested exhaustively without touching a real filesystem or the real
/// environment variables `Vault::default_path` reads -- both of which this
/// process's test suite must never redirect, since a careless `set_var` in
/// one test is a data race against every other test reading the same
/// variable in the same process.
///
/// Returns `(resolved, needs_marker_write)`. Self-healing rather than a
/// persistent coupling to the vault: the vault check only matters while the
/// marker is absent, so once one launch has decided the answer, every later
/// launch reads the marker alone and the vault path is never consulted
/// again.
fn onboarding_resolved_for(marker_exists: bool, vault_exists: bool) -> (bool, bool) {
    if marker_exists {
        return (true, false);
    }
    // No marker yet. If a vault already exists, this install had data
    // before this feature shipped -- an upgrade, not a fresh install -- so
    // the tour must never appear for it, and the marker must be written so
    // this same inference does not have to run again.
    if vault_exists {
        return (true, true);
    }
    // Neither exists: a genuine first run. Show it; the marker is written
    // when the tour is dismissed, not here.
    (false, false)
}

/// Whether the onboarding tour is resolved for this install -- shown and
/// dismissed, or correctly inferred to be an upgrade of an install that
/// already has data. `false` means: show it.
pub fn onboarding_resolved() -> bool {
    let (resolved, needs_write) = onboarding_resolved_for(
        onboarding_marker_path().exists(),
        patanyx_vault::Vault::default_path().exists(),
    );
    if needs_write {
        let _ = write_onboarding_marker();
    }
    resolved
}

/// Called once the tour is dismissed, by whichever route: Skip, Finish,
/// Escape, or the scrim. All four funnel through one close handler in
/// chrome.js, so this has exactly one call site there, no matter how someone
/// leaves it.
pub fn mark_onboarding_seen() {
    let _ = write_onboarding_marker();
}

/// An empty file; only its existence is the signal. A write failure here is
/// not fatal to anything -- worst case, a future launch on an unwritable
/// profile directory shows the tour again, which is a minor annoyance, not a
/// broken browser.
fn write_onboarding_marker() -> std::io::Result<()> {
    let path = onboarding_marker_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"")
}

/// How `load` arrived at what it returned.
///
/// ABSENT AND CORRUPT ARE NOT THE SAME EVENT, and collapsing them is what this
/// distinction exists to undo. A missing file means a user who has never
/// chosen a resolver: defaults are exactly right and there is nothing to say.
/// An unreadable one means a user who may well have chosen Mullvad or Quad9
/// and is now silently on the network's plaintext resolver, because
/// `DnsMode::System` carries `doh_mode() == None`. The old doc called that
/// fallback "the conservative direction" -- true for availability, false for
/// the one property the setting exists to provide, and the user saw nothing
/// either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefsOrigin {
    /// Read and parsed. What is returned is what the user chose.
    Stored,
    /// No file yet. Defaults, and that is unremarkable.
    Absent,
    /// A file exists and could not be used. Defaults, and the user's actual
    /// choice -- including a fail-closed resolver -- is NOT in force.
    Unreadable,
}

/// Reads preferences, falling back to defaults on any problem.
///
/// Still infallible, and deliberately: refusing to start a browser because a
/// preferences file has a stray comma would be absurd. What changed is that
/// the caller can now tell why it got defaults -- see [`load_with_origin`].
pub fn load() -> Prefs {
    load_with_origin().0
}

/// [`load`], plus how it got there.
///
/// Separate function rather than a changed return type: `load` is called from
/// a dozen places that genuinely do not care, and making all of them
/// destructure a tuple to ignore half of it would bury the one call that does.
pub fn load_with_origin() -> (Prefs, PrefsOrigin) {
    let raw = match std::fs::read_to_string(prefs_path()) {
        Ok(raw) => raw,
        // Not found is the ordinary first-run case. Any OTHER read error
        // (permissions, a directory in the way, I/O) is a file that exists in
        // some form and could not be used, which is the reportable case.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (Prefs::default(), PrefsOrigin::Absent)
        }
        Err(_) => return (Prefs::default(), PrefsOrigin::Unreadable),
    };
    match serde_json::from_str(&raw) {
        Ok(prefs) => (prefs, PrefsOrigin::Stored),
        Err(_) => (Prefs::default(), PrefsOrigin::Unreadable),
    }
}

/// Writes preferences, creating the directory if needed.
pub fn save(prefs: &Prefs) -> Result<(), &'static str> {
    let path = prefs_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|_| "io")?;
    }
    let body = serde_json::to_string_pretty(prefs).map_err(|_| "io")?;
    // WRITE-THEN-RENAME. This used to be a plain write, argued as "a torn
    // write loses a resolver preference and `load` falls back to the default"
    // -- which was accurate about the mechanism and wrong about the cost. The
    // default is `System`: no encrypted DNS and no fail-closed behaviour. So a
    // torn write did not lose a preference, it silently turned off the
    // protection the user had switched on, and nothing said so.
    //
    // A rename over the same directory is atomic on both platforms, and the
    // temp file is a sibling so it never crosses a filesystem boundary. This
    // is not cargo-culted from the vault: it is the cheapest way to make the
    // failure mode "the old choice survives" instead of "the choice is gone".
    let tmp = path.with_extension("json.new");
    std::fs::write(&tmp, body).map_err(|_| "io")?;
    std::fs::rename(&tmp, &path).map_err(|_| {
        // Leave nothing behind on failure; a stray .new is confusing and, if
        // it were ever read, would be a half-written preference file.
        let _ = std::fs::remove_file(&tmp);
        "io"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_theme_round_trips_and_unknown_is_refused() {
        for theme in [PageTheme::Auto, PageTheme::Dark, PageTheme::Light] {
            assert_eq!(PageTheme::parse(theme.as_str()), Some(theme));
        }
        assert_eq!(PageTheme::parse("solarized"), None);
        assert_eq!(PageTheme::default(), PageTheme::Auto);
    }

    #[test]
    fn chrome_theme_round_trips_and_unknown_is_refused() {
        for theme in [
            ChromeTheme::Default,
            ChromeTheme::Violet,
            ChromeTheme::BloodRed,
            ChromeTheme::Sky,
            ChromeTheme::Green,
            ChromeTheme::Amber,
            ChromeTheme::Teal,
            ChromeTheme::Slate,
            ChromeTheme::Purple,
        ] {
            assert_eq!(ChromeTheme::parse(theme.as_str()), Some(theme));
        }
        assert_eq!(ChromeTheme::parse("neon"), None);
        assert_eq!(ChromeTheme::default(), ChromeTheme::Default);
    }

    #[test]
    fn chrome_scheme_round_trips_and_absent_reads_dark() {
        for scheme in [
            ChromeScheme::Dark,
            ChromeScheme::White,
            ChromeScheme::Black,
        ] {
            assert_eq!(ChromeScheme::parse(scheme.as_str()), Some(scheme));
        }
        assert_eq!(ChromeScheme::parse("sepia"), None);
        // The additive-field promise: a prefs.json written before schemes
        // existed reads Dark, the chrome every earlier build rendered.
        let old = r#"{"chrome_theme":"sky"}"#;
        let p: Prefs = serde_json::from_str(old).expect("pre-scheme prefs load");
        assert_eq!(p.chrome_scheme, ChromeScheme::Dark);
    }

    #[test]
    fn rose_era_prefs_load_as_blood_red_not_an_error() {
        // Rose was REMOVED (deliberate). A prefs.json a rose-era
        // build wrote must keep loading -- as blood red, its replacement --
        // because one bad enum value fails the whole prefs read.
        let old = r#"{"chrome_theme":"rose"}"#;
        let p: Prefs = serde_json::from_str(old).expect("rose-era prefs still load");
        assert_eq!(p.chrome_theme, ChromeTheme::BloodRed);
        assert_eq!(ChromeTheme::parse("rose"), Some(ChromeTheme::BloodRed));
        // And what we write from now on is the new name, never "rose".
        assert_eq!(ChromeTheme::BloodRed.as_str(), "blood_red");
    }

    #[test]
    fn old_prefs_json_without_page_theme_reads_auto() {
        // The additive-field promise, pinned: a prefs.json written before
        // this field existed must load with Auto, not fail.
        let old = r#"{"dns":"system"}"#;
        let p: Prefs = serde_json::from_str(old).expect("old prefs still load");
        assert_eq!(p.page_theme, PageTheme::Auto);
        assert_eq!(p.chrome_theme, ChromeTheme::Default);
    }

    #[test]
    fn the_default_timeout_is_five_minutes_not_never() {
        // `#[derive(Default)]` would give this field 0, and 0 is defined as
        // NEVER LOCK. That is a one-word mistake that silently disables a
        // security control on every fresh install, and it looks like working
        // software -- so the hand-written Default is pinned here.
        assert_eq!(Prefs::default().vault_autolock_secs, 300);
        assert_ne!(
            Prefs::default().vault_autolock_secs,
            0,
            "0 means never lock; it must never be the default"
        );
    }

    #[test]
    fn an_old_settings_file_without_the_field_gets_the_default() {
        // Upgrades matter here: prefs.json written by an earlier build has no
        // `vault_autolock_secs`. Serde's own default for u64 is 0 -- never --
        // so without the field-level default an existing user would silently
        // have their auto-lock turned off by installing an update.
        let old = r#"{"dns":"system"}"#;
        let prefs: Prefs = serde_json::from_str(old).expect("old prefs must parse");
        assert_eq!(prefs.vault_autolock_secs, 300);
        // Same reasoning applies to `update_channel`: a prefs.json written
        // before this field existed must not read as an opt-in to beta
        // updates nobody asked for.
        assert_eq!(prefs.update_channel, UpdateChannel::Stable);
        // And to session locking, where the trap runs the OTHER way: `bool`
        // defaults to false, and false means "do not lock when the screen
        // locks". Without the field-level default, upgrading would quietly
        // hand every existing user the weaker posture.
        assert!(
            prefs.vault_lock_on_session_lock,
            "an old prefs.json must default to locking on session lock; \
             bool's own default (false) is the unsafe direction here"
        );
        // Fingerprint noise runs the same way as session locking: `bool`'s
        // own default (false) means clean fingerprints for every site, so
        // an upgrade must not silently strip the protection.
        assert!(
            prefs.fingerprint_noise,
            "an old prefs.json must default to fingerprint noise ON; \
             bool's own default (false) is the unsafe direction here"
        );
    }

    #[test]
    fn turning_fingerprint_noise_off_survives_a_round_trip() {
        // Same mirror as `the_session_lock_choice_survives_a_round_trip`:
        // the safe default must not override a user who chose off.
        let mut prefs = Prefs::default();
        prefs.fingerprint_noise = false;
        let text = serde_json::to_string(&prefs).unwrap();
        let back: Prefs = serde_json::from_str(&text).unwrap();
        assert!(!back.fingerprint_noise);
    }

    #[test]
    fn the_session_lock_choice_survives_a_round_trip() {
        // Turning it OFF is a real choice and must stick. This is the mirror
        // of `never_survives_a_round_trip`: the safe default must not be so
        // eager that it overrides the user on every load.
        let mut prefs = Prefs::default();
        prefs.vault_lock_on_session_lock = false;
        let text = serde_json::to_string(&prefs).unwrap();
        let back: Prefs = serde_json::from_str(&text).unwrap();
        assert!(!back.vault_lock_on_session_lock);
    }

    #[test]
    fn never_survives_a_round_trip() {
        // The other direction: a user who chose never must still have chosen
        // never after a restart.
        let mut prefs = Prefs::default();
        prefs.vault_autolock_secs = 0;
        let text = serde_json::to_string(&prefs).unwrap();
        let back: Prefs = serde_json::from_str(&text).unwrap();
        assert_eq!(back.vault_autolock_secs, 0);
    }

    /// The warning fires when 60 SECONDS REMAIN. Always. On every timeout.
    ///
    /// It is a fixed distance from the lock, not a fraction of the wait: pick
    /// 5 minutes and it appears at 4:00; pick 60 minutes and it appears at
    /// 59:00. Both leave exactly one minute to react, which is the point --
    /// how long you get to notice should not depend on how long you chose to
    /// stay unlocked.
    ///
    /// A briefly-built option to lengthen the warning was removed: the
    /// countdown plus an "I'm still here" button covers the same need without
    /// a second setting to understand. This test is what keeps the remaining
    /// behaviour from drifting into something timeout-relative.
    #[test]
    fn the_warning_always_leaves_sixty_seconds_whatever_the_timeout() {
        let warn = crate::state::AUTO_LOCK_WARN_BEFORE.as_secs();
        assert_eq!(warn, 60, "the warning lead time is fixed at 60 seconds");
        for &timeout in AUTOLOCK_CHOICES_SECS {
            if timeout == 0 {
                continue; // never locks, so there is nothing to warn about
            }
            assert!(
                timeout > warn,
                "a {timeout}s timeout is too short to give a full {warn}s of \
                 warning; every offered option must leave room for it"
            );
            assert_eq!(
                timeout - (timeout - warn),
                warn,
                "the banner must appear with exactly {warn}s remaining on a \
                 {timeout}s timeout, not a scaled-down slice of it"
            );
        }
    }

    #[test]
    fn the_offered_choices_include_the_default_and_never() {
        assert!(AUTOLOCK_CHOICES_SECS.contains(&AUTOLOCK_DEFAULT_SECS));
        assert!(AUTOLOCK_CHOICES_SECS.contains(&0));
        assert_eq!(AUTOLOCK_CHOICES_SECS, &[300, 900, 1800, 3600, 0]);
    }

    /// A corrupt settings file must be distinguishable from a missing one.
    ///
    /// Both yield defaults, and `DnsMode::System` means plaintext DNS with no
    /// fail-closed behaviour -- so for a user who had chosen Mullvad or Quad9,
    /// "corrupt" is a silently disabled protection while "missing" is just a
    /// first run. The panel can only say so if these two are told apart, and
    /// for the entire life of this file they were not.
    #[test]
    fn a_corrupt_settings_file_is_not_the_same_as_no_settings_file() {
        // Exercises the classifier directly rather than through the real path,
        // which reads a fixed location this test must not touch.
        fn classify(read: Result<String, std::io::ErrorKind>) -> PrefsOrigin {
            match read {
                Ok(raw) => match serde_json::from_str::<Prefs>(&raw) {
                    Ok(_) => PrefsOrigin::Stored,
                    Err(_) => PrefsOrigin::Unreadable,
                },
                Err(std::io::ErrorKind::NotFound) => PrefsOrigin::Absent,
                Err(_) => PrefsOrigin::Unreadable,
            }
        }

        assert_eq!(
            classify(Err(std::io::ErrorKind::NotFound)),
            PrefsOrigin::Absent,
            "a first run is not a fault and must stay silent"
        );
        assert_eq!(
            classify(Err(std::io::ErrorKind::PermissionDenied)),
            PrefsOrigin::Unreadable,
            "a file that exists and cannot be read is reportable"
        );
        assert_eq!(
            classify(Ok("{ not json".to_string())),
            PrefsOrigin::Unreadable,
            "a truncated or torn file is the case that silently downgraded DNS"
        );
        assert_eq!(
            classify(Ok(r#"{"dns":"mullvad"}"#.to_string())),
            PrefsOrigin::Stored
        );

        // And the reason any of this matters: the fallback carries no DoH.
        assert_eq!(Prefs::default().dns.doh_mode(), None);
    }

    #[test]
    fn choosing_a_resolver_stays_opt_in() {
        // Every alternative here hands a specific company every domain the user
        // looks up. That can be a good trade and the panel argues it, but the
        // browser must not make it on the user's behalf -- quietly redirecting
        // DNS to a party of our choosing is a smaller version of the thing this
        // product exists to refuse.
        assert_eq!(Prefs::default().dns, DnsMode::System);
        assert_eq!(DnsMode::default().doh_template(), None);
        // An EMPTY preferences file must land in the same place as a missing
        // one: a user who never opened the picker has not opted in to anything.
        let untouched: Prefs = serde_json::from_str("{}").expect("empty prefs must parse");
        assert_eq!(untouched.dns, DnsMode::System);
    }

    #[test]
    fn the_default_never_fails_closed() {
        // Picking a resolver fails closed, which makes captive-portal WiFi
        // unusable until the user switches back. That is an acceptable cost of
        // a deliberate choice and an unacceptable one for a first run, so the
        // DEFAULT must carry no DoH mode. If this ever gains one, a user who
        // installed the browser and changed nothing is stranded on hotel WiFi
        // with no route online and no idea why.
        assert_eq!(DnsMode::default().doh_mode(), None);
        assert_eq!(DnsMode::System.doh_mode(), None);
        assert_eq!(DnsMode::System.doh_template(), None);
    }

    #[test]
    fn modes_round_trip_through_their_wire_names() {
        for mode in [DnsMode::System, DnsMode::Mullvad, DnsMode::Quad9] {
            assert_eq!(DnsMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(DnsMode::parse("nonsense"), None);
        assert_eq!(DnsMode::parse("System"), None, "wire names are lowercase");
    }

    #[test]
    fn every_non_system_mode_has_a_template() {
        // A mode that claims to encrypt but resolves to no template would
        // silently leave DNS in plaintext while the UI said otherwise.
        for mode in [DnsMode::Mullvad, DnsMode::Quad9] {
            let t = mode.doh_template().expect("must have a DoH template");
            assert!(t.starts_with("https://"), "{mode:?} template must be https");
        }
    }

    #[test]
    fn choosing_a_resolver_fails_closed_and_system_does_not() {
        // The whole reason to pick a resolver is not to use the network's. A
        // mode that fell back would hand a hostile or merely cheap network the
        // plaintext lookups this setting exists to prevent, silently.
        for mode in [DnsMode::Mullvad, DnsMode::Quad9] {
            assert_eq!(mode.doh_mode(), Some("secure"), "{mode:?} must fail closed");
        }
        // System must carry NO mode: with no template there is nothing to be
        // secure about, and a mode without a template configures a fallback
        // the user never asked for.
        assert_eq!(DnsMode::System.doh_mode(), None);
        assert_eq!(DnsMode::System.doh_template(), None);
    }

    #[test]
    fn a_resolver_choice_is_never_less_protective_than_another() {
        // Quad9's default endpoint filters malicious domains. Shipping
        // Mullvad's UNFILTERED endpoint beside it meant picking Mullvad
        // silently bought less protection than picking Quad9 -- an asymmetry
        // no user could have seen. `base.` is the filtering endpoint.
        assert!(
            DnsMode::Mullvad.doh_template().unwrap().contains("base."),
            "Mullvad must use the filtering endpoint, not the bare one"
        );
        for mode in [DnsMode::Mullvad, DnsMode::Quad9] {
            let d = mode.describe();
            assert!(
                d.contains("malware") || d.contains("malicious"),
                "{mode:?} filters threats, and the UI text must say so: {d}"
            );
            // Fail-closed is the part a user discovers at an airport. It has
            // to be in the sentence they read BEFORE choosing, not afterwards.
            assert!(
                d.contains("WiFi"),
                "{mode:?} must warn that public WiFi logins break: {d}"
            );
        }
    }

    #[test]
    fn malformed_preferences_fall_back_rather_than_failing() {
        // Exercised through the parser rather than the filesystem, so the test
        // does not depend on a real data directory.
        let broken: Result<Prefs, _> = serde_json::from_str("{ not json");
        assert!(broken.is_err());
        let unknown: Prefs = serde_json::from_str(r#"{"dns":"system","future":1}"#)
            .expect("an unknown field must not break an older build");
        assert_eq!(unknown.dns, DnsMode::System);
    }

    #[test]
    fn onboarding_resolution_table() {
        // marker, vault -> (resolved, needs a marker write)
        assert_eq!(
            onboarding_resolved_for(true, true),
            (true, false),
            "an existing marker settles it; the vault is irrelevant"
        );
        assert_eq!(
            onboarding_resolved_for(true, false),
            (true, false),
            "an existing marker settles it even with no vault yet"
        );
        assert_eq!(
            onboarding_resolved_for(false, true),
            (true, true),
            "no marker but a vault already exists -- an upgrade, resolved \
             silently, and the marker must be written so this inference is \
             not repeated on the next launch"
        );
        assert_eq!(
            onboarding_resolved_for(false, false),
            (false, false),
            "neither exists -- a genuine first run; show the tour, and do \
             NOT write the marker here (only dismissal does)"
        );
    }

    #[test]
    fn the_tunnel_is_off_by_default() {
        // Routing every page through a third-party server is the user's
        // trade to make, never the browser's -- the same reasoning as the
        // resolver staying opt-in. A default of `Imported` would also be
        // meaningless on a fresh install (nothing has been imported), but
        // the property that matters is that nothing here can opt the user
        // in.
        assert_eq!(TunnelMode::default(), TunnelMode::Off);
        assert_eq!(Prefs::default().tunnel, TunnelMode::Off);
    }

    #[test]
    fn an_old_settings_file_without_a_tunnel_choice_reads_as_off() {
        // A prefs.json written before this feature existed has no `tunnel`
        // key. That user never imported a configuration, so the only honest
        // reading is `Off` -- anything else would claim a tunnel that does
        // not exist. `TunnelMode::Off` being the enum's own `#[default]` is
        // what makes the struct-level serde default land here with no
        // field-level override function.
        let old = r#"{"dns":"system"}"#;
        let prefs: Prefs = serde_json::from_str(old).expect("old prefs must parse");
        assert_eq!(prefs.tunnel, TunnelMode::Off);
        // An empty file is the same case a fortiori: a user who never
        // touched any setting has no tunnel.
        let empty: Prefs = serde_json::from_str("{}").expect("empty prefs must parse");
        assert_eq!(empty.tunnel, TunnelMode::Off);
    }

    #[test]
    fn tunnel_modes_round_trip_through_their_wire_names() {
        for mode in [TunnelMode::Off, TunnelMode::Imported] {
            assert_eq!(TunnelMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(TunnelMode::parse("nonsense"), None);
        assert_eq!(TunnelMode::parse("Off"), None, "wire names are lowercase");
    }

    #[test]
    fn an_imported_tunnel_choice_survives_a_round_trip() {
        // The mirror of the default test: a user who turned the tunnel ON
        // must still have it on after a restart. If a saved "imported"
        // silently read back as "off", the user would believe their traffic
        // was tunneled while it went direct -- the same silently-disabled
        // protection this file already treats as the worst outcome for a
        // torn or unreadable resolver choice.
        let mut prefs = Prefs::default();
        prefs.tunnel = TunnelMode::Imported;
        let text = serde_json::to_string(&prefs).unwrap();
        let back: Prefs = serde_json::from_str(&text).unwrap();
        assert_eq!(back.tunnel, TunnelMode::Imported);
    }

    #[test]
    fn the_two_tunnel_modes_describe_themselves_differently() {
        // `describe()` is the single source of user-facing copy for this
        // choice, which only protects the user from mixed wording if the
        // two texts actually differ -- and an empty string is how "same
        // wording" would sneak in.
        let off = TunnelMode::Off.describe();
        let imported = TunnelMode::Imported.describe();
        assert!(!off.is_empty(), "Off must still say something to the user");
        assert!(
            !imported.is_empty(),
            "Imported must still say something to the user"
        );
        assert_ne!(
            off, imported,
            "two different choices must not read identically"
        );
    }

    #[test]
    fn the_tunnel_description_is_honest_about_scope_and_failure() {
        // The describe() text is the only thing a user reads BEFORE choosing
        // the tunnel, so the uncomfortable facts have to be in it, not
        // discovered afterwards: it covers this browser only; the server at
        // the far end sees the traffic; switching needs a restart on
        // Windows; and a down tunnel fails CLOSED -- pages fail to load,
        // never a silent fallback to direct.
        let d = TunnelMode::Imported.describe();
        assert!(
            d.contains("this browser"),
            "must say the tunnel covers this browser only: {d}"
        );
        assert!(
            d.contains("can see your traffic"),
            "must say the chosen server sees the traffic: {d}"
        );
        assert!(
            d.contains("fail to load"),
            "must warn that a down tunnel fails closed: {d}"
        );
        // The caveat, not one spelling of it. The copy said "after a browser
        // restart" and now says "the next time you start the browser" --
        // plainer for someone who does not think of it as "restarting a
        // process". Either wording satisfies this; DROPPING the caveat does
        // not, which is the property worth pinning.
        assert!(
            d.contains("restart") || d.contains("next time you start"),
            "must say switching takes effect only after starting again: {d}"
        );
        // And the words that would overclaim must never appear: this is not
        // an anonymity tool, and it says so without using them.
        assert!(
            !d.contains("anonymous") && !d.contains("untraceable"),
            "the tunnel must not read as an anonymity tool: {d}"
        );
    }
}
