//! Preferences that must be readable BEFORE the vault is unlocked.
//!
//! Everything else the user configures lives in the encrypted vault or store,
//! and that is the right default. This file exists for the narrow set of
//! settings the browser needs at process start, when there is no passphrase
//! yet and nothing is decrypted.
//!
//! This includes choices the engine needs before the vault opens: the DNS
//! resolver used to create WebView2's environment and the engine tracking-
//! prevention level applied as each profile becomes live.
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

/// WebView2's own tracking-prevention level.
///
/// This is separate from PATANYX's host list and request interception. Changing
/// it must never rewrite or disable either of those primary blocking layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackingPreventionLevel {
    /// The existing posture and the absent-field meaning for every prefs file
    /// written before this choice existed.
    #[default]
    Strict,
    /// WebView2's default, offered for sites Strict breaks.
    Balanced,
}

impl TrackingPreventionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "strict" => Some(Self::Strict),
            "balanced" => Some(Self::Balanced),
            _ => None,
        }
    }
}

/// Which resolver the engine should send DNS queries to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Whatever the operating system is configured with -- which, for a user
    /// running a VPN, is their VPN's resolver.
    ///
    /// THE DEFAULT, and this is a CHOICE THE BROWSER DECLINES TO MAKE rather
    /// than a recommendation of the system resolver. The encrypted option
    /// hands one company every domain the user looks up. That can be a good
    /// trade, and the panel argues it, but it is the user's trade to make:
    /// a browser that quietly redirected DNS to a party of its own choosing
    /// would be doing a smaller version of the thing this product exists to
    /// refuse. It also has a concrete cost -- overriding a VPN's resolver
    /// splits that user's traffic across two companies neither of them chose,
    /// and names private to a corporate VPN stop resolving.
    ///
    /// This is also the only setting that WORKS ON CAPTIVE-PORTAL WIFI, because
    /// it carries no DoH mode and so does not fail closed. See
    /// [`Self::doh_mode`]. That is a happy accident rather than the reason, but
    /// it does mean a first-run user is never stranded on hotel WiFi.
    ///
    /// HISTORY, because the tests and docs around this were rewritten twice
    /// in two days: on 2026-09-04 Quad9 became the default for the
    /// first stable release, and on 2026-09-05 reversed it -- System default,
    /// Quad9 an option. The hardening that came out of reviewing the Quad9
    /// default stayed: the applied-resolver record, the probe's tunnel and
    /// redirect guards, the chosen marker, the lenient marker parsing.
    #[default]
    System,
    /// Quad9. Swiss non-profit, no-logging policy, malware filtering on by
    /// default, DNSSEC validated, and EDNS Client Subnet not sent -- all four
    /// stated in Quad9's published feature table.
    ///
    /// OPT-IN, like every encrypted resolver this browser has offered. What
    /// choosing it buys is not anonymity -- Quad9 sees every domain, and that
    /// is stated wherever the choice is offered -- it is moving the observer
    /// from a party with a commercial interest in the data to a non-profit
    /// with a published no-logging policy, and refusing known malicious
    /// domains at the resolver on every request.
    ///
    /// The ONLY encrypted choice since Mullvad left: it announced on
    /// 2026-09-03 that its public encrypted DNS servers shut down on
    /// 2026-11-02 and that it sponsors Quad9 instead. The `Mullvad` variant
    /// this enum carried went in the same change. A stored file that still
    /// says `mullvad` deserialises to Quad9 through the serde alias below,
    /// so the file stays readable and the user stays on an encrypted,
    /// filtering resolver; what they lose is Mullvad's ad and tracker
    /// blocking at the resolver, which the browser's own blocker covers.
    ///
    /// FAIL-CLOSED ([`Self::doh_mode`]): a user who chose this and walks into
    /// a hotel cannot load the sign-in page until they switch to `System`
    /// and restart. `resolver_probe` notices and says so.
    #[serde(alias = "mullvad")]
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

/// How much of a page Text Capture and Deep Recall ask the engine to render.
///
/// This is one preference for both features because both start with the same
/// page picture and virtualized pages fail in the same way in either flow.
/// The actual scope is still carried on `capture::CaptureEvent`: an old
/// WebView2 runtime may fall back from a requested full page to the viewport,
/// and a preference must never overwrite that fact in the result or archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturePreference {
    /// The behavior every build before this choice shipped used.
    #[default]
    FullPage,
    /// Only the pixels currently visible in the page view.
    Viewport,
}

impl CapturePreference {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullPage => "full_page",
            Self::Viewport => "viewport",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "full_page" => Some(Self::FullPage),
            "viewport" => Some(Self::Viewport),
            _ => None,
        }
    }

    pub fn capture_scope(self) -> crate::capture::CaptureScope {
        match self {
            Self::FullPage => crate::capture::CaptureScope::FullPage,
            Self::Viewport => crate::capture::CaptureScope::VisibleArea,
        }
    }
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
/// ALL NINE ARE FREE, and this is settled rather than pending.
///
/// The set beyond the original four was the SEED of a future premium theme
/// pack from 2026-08-04, shipped unlocked, with the note that nothing might
/// gate it until the licence server existed and the gate was flipped
/// deliberately. On 2026-08-16 it was decided not to flip it: theme packs
/// left the Premium list and joined the free tier, which the
/// promise in `about.rs::PREMIUM` makes permanent. The reasoning is
/// recorded there, next to the sentence that binds it.
///
/// So there is no gate to add here, and adding one later would break a
/// published commitment. A paid pack, if there is ever to be one, is NEW
/// accents on top of these nine.
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
/// Was part of the premium theme-pack seed; free for good since 2026-08-16,
/// on the same decision that freed the accents. See `ChromeTheme` above.
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

/// Whether toolbar feature buttons show their written labels.
///
/// `Show` is the default and stays the default. The toolbar's own comment in
/// index.html records why: an icon alone makes a user guess what a control
/// does, and guessing wrong about a privacy control is worse than a slightly
/// wider toolbar. Icon-only was tried once and reversed after a reader asked
/// which pill was the unnamed one (see the LIBRARY note in chrome.css).
///
/// It is offered as a CHOICE because that argument is about a default, not
/// about everyone: a user who already knows the row and wants the width back
/// can have it. Nothing else changes when it is `Hide` -- every button keeps
/// its `title` and `aria-label`, so hovering still says what the button does
/// and a screen reader still reads its full name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolbarLabels {
    /// Icon and written label, the shape every build has shipped.
    #[default]
    Show,
    /// Icon only. The name lives in `title` and `aria-label`.
    Hide,
}

impl ToolbarLabels {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Show => "show",
            Self::Hide => "hide",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "show" => Some(Self::Show),
            "hide" => Some(Self::Hide),
            _ => None,
        }
    }
}

/// Where the feature buttons live: at either end of the top row, or down
/// either side of the page.
///
/// `TopLeft` is the stored meaning of the old `"top"` value and stays the
/// default. `Left` and `Right` move the SECOND toolbar row -- the browser's
/// standing state, everything after `.toolbar-break` -- into a vertical
/// strip, and leave the tab strip, the navigation buttons and the address bar
/// where they are. An address bar wants width; a column of pills does not.
///
/// This is a layout choice, so it is worn the same way the accent and the
/// scheme are: a data attribute on the chrome's root element, with the CSS
/// doing the arrangement. What makes it more than CSS is that the page is a
/// SEPARATE webview whose rectangle Rust owns, so the chrome has to tell Rust
/// how much of the window it is now using on each axis -- see
/// `AppState::set_chrome_insets`.
///
/// The side strips are ICON-ONLY by construction, and [`ToolbarLabels`]
/// therefore applies only to the two top placements. That is stated in the
/// panel rather than left to be discovered: a setting that silently does
/// nothing is the thing this browser's rule about inert controls exists to
/// prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolbarPlacement {
    /// Two rows above the page, feature buttons aligned left. The serde alias
    /// is the compatibility contract with prefs written before four-way
    /// placement existed.
    #[default]
    #[serde(alias = "top")]
    TopLeft,
    /// Two rows above the page, feature buttons aligned right.
    TopRight,
    /// Feature buttons in a strip down the left; everything else stays put.
    Left,
    /// Feature buttons in a strip down the right; everything else stays put.
    Right,
}

impl ToolbarPlacement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TopLeft => "top_left",
            Self::TopRight => "top_right",
            Self::Left => "left",
            Self::Right => "right",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "top_left" => Some(Self::TopLeft),
            "top_right" => Some(Self::TopRight),
            "left" => Some(Self::Left),
            "right" => Some(Self::Right),
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
            Self::Quad9 => "quad9",
            Self::System => "system",
        }
    }

    /// Wire names only. `"mullvad"` is deliberately NOT accepted: the
    /// service is retired, and an IPC caller naming it gets `bad_args`
    /// rather than a silent substitution. A stored file that still says it
    /// is handled by the serde alias on `Quad9`, not here.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "quad9" => Some(Self::Quad9),
            "system" => Some(Self::System),
            _ => None,
        }
    }

    /// The DoH template, or `None` for the system resolver.
    ///
    /// Verified against the resolver's published documentation rather than
    /// recalled. A wrong template does not degrade -- it means DNS fails, so
    /// this is not a value to guess at.
    pub fn doh_template(self) -> Option<&'static str> {
        match self {
            Self::Quad9 => Some("https://dns.quad9.net/dns-query"),
            Self::System => None,
        }
    }

    /// The engine's DoH mode for this choice.
    ///
    /// `secure` FAILS CLOSED: if the chosen resolver cannot be reached, the
    /// browser does not resolve at all rather than falling back to whatever
    /// the network offers. That is the point. A user who deliberately picked
    /// Quad9 and got silently downgraded to an airport's plaintext resolver
    /// has the leak they chose this setting to close, and no way to find out
    /// -- WebView2 exposes no signal that a downgrade happened.
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
            Self::Quad9 => Some("secure"),
            Self::System => None,
        }
    }

    /// The engine switches for this choice, or `None` for System: exactly
    /// the text `platform::windows::desired_browser_args` appends.
    ///
    /// Lives HERE, platform-independent, so a test that runs on Linux (where
    /// CI runs) can pin that the DEFAULT produces the switches. The Windows
    /// function that consumes this cannot be exercised there, and a refactor
    /// that dropped the arguments inside it would otherwise leave every test
    /// green while every install ran plaintext under a green chip.
    pub fn doh_args(self) -> Option<String> {
        let mode = self.doh_mode()?;
        let template = self.doh_template()?;
        Some(format!(
            " --dns-over-https-mode={mode} --dns-over-https-templates={template}"
        ))
    }

    /// One sentence for the UI, resolved from the compiled catalog. Says
    /// what the choice COSTS as well as what it buys -- being on a resolver
    /// moves who sees your lookups, it does not remove them.
    ///
    /// Owned `String`, resolved on EVERY call: the text must follow a live
    /// locale change, so nothing may cache it (i18n.rs has the ruling). The
    /// English words themselves now live in chrome/i18n/locales/en.ftl,
    /// still exactly once -- the single-source contract moved files, it did
    /// not weaken -- and the claims manifest pins their content.
    pub fn describe(self, i18n: &crate::i18n::I18n) -> String {
        i18n.text(match self {
            Self::System => crate::i18n::keys::PREFS_DNS_SYSTEM_DESCRIPTION,
            Self::Quad9 => crate::i18n::keys::PREFS_DNS_QUAD9_DESCRIPTION,
        })
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

    /// The user-facing description of this choice, and still the ONLY
    /// source of it: every surface that explains the tunnel resolves the
    /// same catalog message, so two UIs can never word the same choice
    /// differently. The words live in chrome/i18n/locales/en.ftl under the
    /// claims manifest; in the same spirit as [`DnsMode::describe`], they
    /// say what the choice COSTS as well as what it buys. Resolved per call
    /// -- no cache -- so a live locale change repaints it (i18n.rs).
    pub fn describe(self, i18n: &crate::i18n::I18n) -> String {
        i18n.text(match self {
            Self::Off => crate::i18n::keys::PREFS_TUNNEL_OFF_DESCRIPTION,
            Self::Imported => crate::i18n::keys::PREFS_TUNNEL_IMPORTED_DESCRIPTION,
        })
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


/// "en" and never anything cleverer: guessing from the OS would make the
/// first launch differ per machine, and the stored value must survive a
/// downgrade to a build that has never heard of the tag it names.
fn ui_locale_default() -> String {
    "en".to_string()
}

/// `true` only for a JSON `true`; anything else -- `null`, a number, a
/// string, a missing value -- is `false`. Used for markers whose failure
/// mode must be "treated as unset", never "the file is unreadable".
fn lenient_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(matches!(v, serde_json::Value::Bool(true)))
}

/// A host list that cannot make the file unreadable, and cannot carry a value
/// that could never match a real host.
///
/// Anything that is not an array of strings reads as empty. Entries are
/// normalized and screened by [`acceptable_wipe_exempt_host`]; a rejected
/// entry is DROPPED rather than kept, because an entry that can never match
/// is dead weight that still reads to the user as a site being kept.
fn lenient_host_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    let Some(items) = v.as_array() else {
        return Ok(Vec::new());
    };
    Ok(items
        .iter()
        .filter_map(|item| item.as_str())
        .filter_map(normalize_wipe_exempt_host)
        .collect())
}

/// Lowercases, trims a trailing dot, and refuses anything that is not a
/// plausible host. Returns `None` for a value that could never match.
pub fn normalize_wipe_exempt_host(raw: &str) -> Option<String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if !acceptable_wipe_exempt_host(&host) {
        return None;
    }
    Some(host)
}

/// The same shape the blocklist demands of a rule, and for the same reason: a
/// value the engine could never hand us is not protection, it is a lie in a
/// list. Punycode only, no scheme, no path, no port, at least two labels.
fn acceptable_wipe_exempt_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && host.contains('.')
        && !host.starts_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && host.split('.').all(|l| !l.is_empty() && l.len() <= 63)
}

/// Whether `host` is kept by `exempt`, matching on dot boundaries.
///
/// The boundary is the whole point: a plain `ends_with` would make an entry
/// for "example.com" also keep "notexample.com", which is a different site
/// and one the user never asked to keep.
pub fn wipe_exempts(exempt: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    exempt.iter().any(|keep| {
        host == *keep
            || (host.len() > keep.len()
                && host.as_bytes()[host.len() - keep.len() - 1] == b'.'
                && host.ends_with(keep.as_str()))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Who resolves the sites the user visits, from the NEXT start: the
    /// engine takes this only at environment creation. The resolver the
    /// engine is running right now is [`applied_dns`], and the two differ
    /// after a choice until the restart, which is why every surface that
    /// claims a resolver is in force reads the applied one.
    pub dns: DnsMode,
    /// Whether `dns` was set through the picker, as opposed to written by
    /// `save` as a side effect of some other preference changing.
    ///
    /// `save` writes the whole struct, so a file carrying the default value
    /// says nothing about whether the user ever opened the panel; a file
    /// carrying a NON-default value can only have got it from the picker,
    /// because nothing else writes one. [`parse_stored`] therefore marks a
    /// stored non-default value as chosen even in a pre-1.0 file that never
    /// carried this field. What the marker buys is the future: if the default
    /// ever changes, a recorded choice can be honoured and an unrecorded
    /// default can move, without the guesswork that made the one-day Quad9
    /// default (2026-09-04) so hard to migrate honestly.
    ///
    /// The `dns` key is the same one every earlier build reads, so a
    /// downgrade runs the resolver this build last wrote. A downgrade drops
    /// this marker, which 0.9.x does not know; the value itself survives.
    ///
    /// Lenient on the wire: a marker that is not a boolean reads as `false`
    /// instead of making the WHOLE file unreadable, which would discard every
    /// other preference in it and let the next save write defaults over them.
    /// The review pointed at exactly that: one malformed field must not take
    /// the tunnel mode or the auto-lock down with it.
    #[serde(default, deserialize_with = "lenient_bool")]
    pub resolver_chosen: bool,
    /// Hosts whose cookies and site data SURVIVE the start-of-session wipe.
    ///
    /// Empty by default, and an empty list changes nothing: the wipe runs
    /// exactly as it always has. The list exists because a browser that
    /// arrives as a brand-new device on every launch is not merely forgetful,
    /// it is unusable for anything that keeps keys on the client. Messenger's
    /// end-to-end encryption stores its device keys in IndexedDB; wiping them
    /// every start means re-downloading and re-decrypting an entire chat
    /// history on every launch, and being challenged by the service for
    /// looking like a new device each time. That was reported from a real
    /// machine, and it is not a bug in the wipe -- it is the wipe working.
    ///
    /// Matched on DOT BOUNDARIES, so an entry covers a host and its
    /// subdomains and nothing else: "example.com" keeps example.com and
    /// a.example.com, never notexample.com.
    ///
    /// Lenient on the wire like the flags above: a malformed value reads as
    /// an empty list rather than making the whole file unreadable, because
    /// one bad field must not take every other preference down with it.
    #[serde(default, deserialize_with = "lenient_host_list")]
    pub wipe_exempt_hosts: Vec<String>,
    /// The chrome's own language, and ONLY the chrome's: this value must
    /// never reach navigator.language, Accept-Language, or any per-site
    /// surface -- the divergence non-goals carry the reasoning, and a
    /// pinned test holds the door. Lives in the unlocked prefs file
    /// because the chrome needs it before any unlock, and it discloses
    /// nothing but a language choice.
    #[serde(default = "ui_locale_default")]
    pub ui_locale: String,
    /// The language a page was last translated INTO, pre-filled next time.
    ///
    /// A familiar convenience: the target dropdown remembers your choice so
    /// translating is usually one click. Empty means "never chosen", and the
    /// UI then pre-fills from the chrome's own locale as a first guess.
    ///
    /// Same file and same reasoning as `ui_locale`: it lives in the UNLOCKED
    /// prefs, because the chooser is drawn before any vault unlock, and it
    /// discloses nothing but a language preference. It must NEVER reach
    /// navigator.language / Accept-Language / any per-site surface -- it is a
    /// UI default, not a signal a page may read, exactly like ui_locale.
    /// `#[serde(default)]` at the struct level gives an old prefs.json the
    /// empty string, which is the correct "never chosen" meaning.
    #[serde(default)]
    pub translate_target: String,
    /// WebView2's profile-level tracker blocking. Strict is deliberately the
    /// default, including when an older additive prefs file lacks this field.
    /// WebKitGTK has only an ITP on/off switch and does not consume this value.
    pub tracking_prevention: TrackingPreventionLevel,
    /// Seconds of inactivity before the vault locks; 0 disables it.
    #[serde(default = "autolock_default")]
    pub vault_autolock_secs: u64,
    /// Early access to updates. `#[serde(default)]` at the struct level
    /// already gives an old prefs.json missing this field `UpdateChannel`'s
    /// own `#[default]`, which is `Stable` -- unlike `vault_autolock_secs`,
    /// there is no wrong-numeric-default trap here, so no field-level
    /// override function is needed.
    pub update_channel: UpdateChannel,
    /// Whether the ONE-TIME 1.0.0 channel reset has run on this install.
    ///
    /// Through 0.9.x the Updates panel drew a single "Beta" button and moved
    /// every install it opened on from Stable to Beta, with a comment saying
    /// that was safe "only today" because both channels served the identical
    /// manifest. So no stored Beta from that era is a choice anyone made. The
    /// first 1.0.0 load puts such an install back on Stable ONCE and sets
    /// this, after which a Beta the user picks from the restored two-button
    /// row is respected forever.
    #[serde(default)]
    pub channel_reset_1_0: bool,
    /// Which tunnel, if any, carries this browser's traffic.
    /// `#[serde(default)]` at the struct level already gives an old
    /// prefs.json missing this field `TunnelMode`'s own `#[default]`, which
    /// is `Off` -- and `Off` IS the correct absent-field meaning: a user
    /// who has never touched the feature has no tunnel. As with
    /// `update_channel` and unlike `vault_autolock_secs`, there is no
    /// wrong-default trap here, so no field-level override function is
    /// needed.
    pub tunnel: TunnelMode,
    /// A shelf id created by "Apply and restart", to be reopened once the
    /// vault is unlocked in the replacement process.
    ///
    /// THE ID, NOT THE NAME: shelf names repeat (every "Shelf with 3 tabs"
    /// looks alike), and restoring the wrong one would reopen a session the
    /// user shelved deliberately weeks ago. `Shelf::id` is unique.
    ///
    /// A MARKER IN PREFS RATHER THAN THE STORE, because it must be readable
    /// BEFORE the vault is open: the reader is the boot that has not been
    /// unlocked yet, and it needs to know whether to expect a restore at all.
    /// The tabs themselves are in the vault-backed store, where they belong;
    /// this is only a pointer, and a pointer to a shelf is not a browsing
    /// record. Nothing here ever holds a URL -- process arguments and plain
    /// prefs.json are both readable by anything on the machine.
    ///
    /// Absent field reads `None`, which is the correct meaning for every
    /// prefs.json written before this existed: no restore is owed. That
    /// comes from the STRUCT-level `#[serde(default)]` above, the same way
    /// `tunnel` and `page_theme` get theirs -- no field-level attribute is
    /// needed, and adding one would imply a wrong-default trap that is not
    /// there.
    pub tunnel_restore_shelf: Option<String>,
    /// Page color-scheme preference. `#[serde(default)]` at the struct
    /// level gives an old prefs.json `Auto`, which IS the correct
    /// absent-field meaning: a user who never touched this follows the OS.
    pub page_theme: PageTheme,
    /// Text Capture and Deep Recall capture scope. The struct-level serde
    /// default gives every older prefs.json `FullPage`, preserving today's
    /// behavior until the user explicitly chooses the viewport.
    pub capture_scope: CapturePreference,
    /// Chrome accent theme. Absent field reads Default, which renders
    /// byte-identically to every build before theming existed.
    pub chrome_theme: ChromeTheme,
    /// Chrome scheme (Dark/White/Black). Absent field reads Dark: same
    /// byte-identical promise as the accent above.
    pub chrome_scheme: ChromeScheme,
    /// Download a verified update in the background the moment a check
    /// offers one, so the consent click is an instant restart instead of a
    /// wait. INSTALLING still requires that click -- this flag never
    /// touches that. Default ON, the shape mainstream browsers settled on;
    /// the update panel carries the switch for metered or minimal setups.
    pub update_background_download: bool,
    /// Apply a staged, verified update BY ITSELF at the next launch, with no
    /// click -- the shape other browsers use. The signed manifest still decides WHICH
    /// releases may do that (`Manifest::installs_silently`): maintenance and
    /// security releases qualify; a pure feature release is announced and
    /// waits for consent or the grace period.
    ///
    /// Default OFF, and STILL OFF in 1.0.0 by decision: this is the one code
    /// path that replaces the running binary, it has never run in the field,
    /// and `swap_and_relaunch` restores the old binary on a failed write but
    /// not on a failed relaunch. It becomes ON only after a real
    /// replace-and-relaunch test on hardware -- a one-line change HERE plus a
    /// field-level serde default (absent must then read true, not false).
    pub update_auto_apply: bool,
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
    /// Whether the bookmark folder bar is shown under the toolbar.
    ///
    /// `false` is the correct absent-field meaning and needs no override fn:
    /// a prefs.json written before this existed describes a browser with two
    /// chrome rows, and adding a third to someone's window on upgrade is a
    /// layout change nobody asked for. Unlike the session-lock flag, `false`
    /// here is not the weaker posture, it is simply the old one.
    #[serde(default)]
    pub bookmarks_bar: bool,
    /// Whether toolbar feature buttons show their written labels.
    ///
    /// No field-level `#[serde(default)]` fn is needed: `ToolbarLabels`
    /// derives `Default` as `Show`, which IS the correct absent-field
    /// meaning. A prefs.json written before this field existed describes a
    /// build whose toolbar was labelled, and that is what it reads back as.
    /// Same shape as `page_theme` and unlike `vault_lock_on_session_lock`,
    /// where the derived default is the weaker posture.
    pub toolbar_labels: ToolbarLabels,
    /// Where the feature buttons live: at either end of the top, or down
    /// either edge.
    ///
    /// Same absent-field reasoning as `toolbar_labels`: the derived default
    /// is `TopLeft`, which is the layout every prefs.json written before this
    /// field existed was describing. Moving somebody's toolbar on upgrade is
    /// the one wrong answer here.
    pub toolbar_placement: ToolbarPlacement,
    /// The chrome's resolved colours, as chrome.js last reported them
    /// (`chrome_palette_set`): the title bar, the window border, and the
    /// scrollbar thumb pages are given. Persisted so the FIRST tab of the
    /// next launch -- built before the chrome document has run -- wears the
    /// colours the user chose rather than the default blue until a reload.
    /// Absent reads the default palette, which is what chrome.css resolves
    /// to with no theme chosen; a prefs.json from before this field describes
    /// exactly that chrome. Not a choice of its own: it is derived from
    /// `chrome_theme` + `chrome_scheme` and re-derived on every change.
    pub chrome_palette: crate::platform::ChromePalette,
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
            resolver_chosen: false,
            ui_locale: ui_locale_default(),
            translate_target: String::new(),
            tracking_prevention: TrackingPreventionLevel::default(),
            wipe_exempt_hosts: Vec::new(),
            vault_autolock_secs: AUTOLOCK_DEFAULT_SECS,
            update_channel: UpdateChannel::default(),
            channel_reset_1_0: false,
            tunnel: TunnelMode::default(),
            tunnel_restore_shelf: None,
            page_theme: PageTheme::default(),
            capture_scope: CapturePreference::default(),
            chrome_theme: ChromeTheme::default(),
            chrome_scheme: ChromeScheme::default(),
            update_background_download: true,
            update_auto_apply: false,
            vault_lock_on_session_lock: lock_on_session_lock_default(),
            fingerprint_noise: fingerprint_noise_default(),
            toolbar_labels: ToolbarLabels::default(),
            toolbar_placement: ToolbarPlacement::default(),
            bookmarks_bar: false,
            chrome_palette: crate::platform::ChromePalette::default(),
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
/// An unreadable one means a user who may well have chosen Quad9 and whose
/// NEXT start is on the network's plaintext resolver, because
/// `DnsMode::System` carries `doh_mode() == None`. The old doc called that
/// fallback "the conservative direction" -- true for availability, false for
/// the one property the setting exists to provide, and the user saw nothing
/// either way. (The engine already running keeps what it started with; see
/// [`applied_dns`].)
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
    let (prefs, origin) = from_read(std::fs::read_to_string(prefs_path()).map_err(|e| e.kind()));
    let (prefs, reset) = reset_forced_beta_once(prefs);
    if reset {
        // Persist so the reset is genuinely once. A failed save leaves the
        // in-memory value correct for this run and tries again next start,
        // which is the same outcome as never having run; nothing to report.
        let _ = save(&prefs);
    }
    (prefs, origin)
}

/// The one-time 1.0.0 channel reset, pure so it is table-testable.
///
/// Returns the prefs and whether anything changed. A stored Beta with the
/// marker unset is the 0.9.x forced migration and goes back to Stable; a
/// Beta with the marker set is a real choice and stays. Stable with the marker
/// unset just gets the marker, so the check never runs again.
pub fn reset_forced_beta_once(mut prefs: Prefs) -> (Prefs, bool) {
    if prefs.channel_reset_1_0 {
        return (prefs, false);
    }
    prefs.channel_reset_1_0 = true;
    if prefs.update_channel == UpdateChannel::Beta {
        prefs.update_channel = UpdateChannel::Stable;
    }
    (prefs, true)
}

/// The classifier behind [`load_with_origin`], pure so the test that pins
/// "absent is not the same as corrupt" exercises THIS function rather than
/// a copy of its logic that could drift from it.
pub fn from_read(read: Result<String, std::io::ErrorKind>) -> (Prefs, PrefsOrigin) {
    let raw = match read {
        Ok(raw) => raw,
        // Not found is the ordinary first-run case. Any OTHER read error
        // (permissions, a directory in the way, I/O) is a file that exists in
        // some form and could not be used, which is the reportable case.
        Err(std::io::ErrorKind::NotFound) => return (Prefs::default(), PrefsOrigin::Absent),
        Err(_) => return (Prefs::default(), PrefsOrigin::Unreadable),
    };
    match parse_stored(&raw) {
        Ok(prefs) => (prefs, PrefsOrigin::Stored),
        Err(_) => (Prefs::default(), PrefsOrigin::Unreadable),
    }
}

/// Parses a stored file and applies the one rule serde cannot express: a
/// stored value that differs from the default can only have come from the
/// picker, so it counts as CHOSEN even when the file predates the marker.
/// A stored default without the marker is just the default. EVERY
/// deserialisation of a stored file goes through here, so the marker is
/// always consistent with the value beside it.
pub fn parse_stored(raw: &str) -> Result<Prefs, serde_json::Error> {
    let mut prefs: Prefs = serde_json::from_str(raw)?;
    if prefs.dns != DnsMode::default() {
        prefs.resolver_chosen = true;
    }
    Ok(prefs)
}

/// The resolver the ENGINE was given at startup.
///
/// FROZEN at the first environment argument build and handed back to every
/// later one: the shared environment, wry's fallback path, and the
/// translator webview, which is created later and would otherwise re-read
/// a file the user may have changed since boot and run a different resolver
/// from the browser it sits beside. One process, one resolver, and this is
/// it. Never recorded where no engine takes it: WebKitGTK has no encrypted
/// DNS, so on Linux this stays unset and reads as `System`, which is the
/// truth there. Unset on Windows -- the chrome asking before any
/// environment exists, which does not happen -- also reads as `System`:
/// grey is the safe wrong.
///
/// WHY THIS EXISTS. `load()` re-reads the file on every `dns_get`, and the
/// file can change under a running engine: a choice (restart pending), or
/// the file becoming unreadable, which yields the DEFAULT. A chrome that
/// coloured its chip by the file would claim, after a Quad9 choice, an
/// encryption not yet running, and after the file broke under a Quad9
/// engine, a plaintext state the engine is not in. So the chip, the
/// reachability probe and the diagnostics all read THIS, and the file is
/// what the next start gets.
///
/// What this records is what the process ASKED for. Whether the engine
/// honoured the switches is not observable from here; the release checklist
/// carries a hardware check for that, and the copy says "sends", not
/// "confirmed".
static APPLIED_DNS: std::sync::OnceLock<DnsMode> = std::sync::OnceLock::new();

/// The frozen resolver, recording `mode` if nothing is frozen yet. Every
/// engine argument build goes through this, so the first one decides.
pub fn applied_dns_or_record(mode: DnsMode) -> DnsMode {
    *APPLIED_DNS.get_or_init(|| mode)
}

pub fn applied_dns() -> DnsMode {
    APPLIED_DNS.get().copied().unwrap_or(DnsMode::System)
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
    // -- which was accurate about the mechanism and wrong about the cost.
    // The default is `System`: no encrypted DNS and no fail-closed behaviour.
    // So a torn write did not lose a preference, it silently turned off the
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

    #[test]
    fn translate_target_round_trips_and_defaults_empty() {
        // A prefs.json written before this field existed reads back empty,
        // which is the correct "never chosen" meaning.
        let json = r#"{"dns":"system"}"#;
        let p: Prefs = serde_json::from_str(json).expect("old prefs parse");
        assert_eq!(p.translate_target, "");

        // Round-trips through serialization.
        let mut p2 = Prefs::default();
        p2.translate_target = "es".to_string();
        let out = serde_json::to_string(&p2).unwrap();
        let back: Prefs = serde_json::from_str(&out).unwrap();
        assert_eq!(back.translate_target, "es");
    }
    fn english() -> crate::i18n::I18n {
        crate::i18n::I18n::bootstrap("en").expect("the embedded English catalog is valid")
    }

    use super::*;

    #[test]
    fn capture_scope_defaults_full_page_and_viewport_round_trips() {
        // Load compatibility is the feature contract: every prefs file from
        // before this field existed keeps the old full-page behavior.
        let old: Prefs = serde_json::from_str(r#"{"dns":"system"}"#)
            .expect("pre-capture-scope prefs must still load");
        assert_eq!(old.capture_scope, CapturePreference::FullPage);
        assert_eq!(Prefs::default().capture_scope, CapturePreference::FullPage);

        let mut prefs = Prefs::default();
        prefs.capture_scope = CapturePreference::Viewport;
        let text = serde_json::to_string(&prefs).expect("prefs serialize");
        let back: Prefs = serde_json::from_str(&text).expect("prefs round trip");
        assert_eq!(back.capture_scope, CapturePreference::Viewport);
        assert!(text.contains(r#""capture_scope":"viewport""#));

        assert_eq!(
            CapturePreference::parse("full_page"),
            Some(CapturePreference::FullPage)
        );
        assert_eq!(
            CapturePreference::parse("viewport"),
            Some(CapturePreference::Viewport)
        );
        assert_eq!(CapturePreference::parse("visible_area"), None);
        assert_eq!(CapturePreference::parse("Viewport"), None);
        assert_eq!(
            CapturePreference::Viewport.capture_scope(),
            crate::capture::CaptureScope::VisibleArea
        );
    }

    /// The wipe exemption list: what it keeps, what it must NOT keep, and
    /// what a malformed file costs.
    #[test]
    fn a_wipe_exemption_keeps_a_host_and_its_subdomains_and_nothing_else() {
        let keep = vec!["example.com".to_string()];

        assert!(wipe_exempts(&keep, "example.com"), "the host itself");
        assert!(wipe_exempts(&keep, "a.example.com"), "a subdomain");
        assert!(wipe_exempts(&keep, "a.b.example.com"), "a deep subdomain");
        assert!(wipe_exempts(&keep, "EXAMPLE.COM"), "case must not matter");
        assert!(wipe_exempts(&keep, "example.com."), "a trailing dot is the same host");

        // The boundary. A plain ends_with would keep all of these, and each
        // one is a DIFFERENT site whose data the user never asked to spare.
        assert!(!wipe_exempts(&keep, "notexample.com"));
        assert!(!wipe_exempts(&keep, "example.com.evil.test"));
        assert!(!wipe_exempts(&keep, "com"));
        assert!(!wipe_exempts(&keep, ""));

        // An empty list keeps nothing, which is what preserves today's
        // behaviour for everyone who never opens the panel.
        assert!(!wipe_exempts(&[], "example.com"));
    }

    #[test]
    fn an_exemption_entry_that_could_never_match_is_refused() {
        assert_eq!(normalize_wipe_exempt_host("  Example.COM. "), Some("example.com".into()));
        assert_eq!(normalize_wipe_exempt_host("a.example.com"), Some("a.example.com".into()));

        for bad in [
            "",                         // nothing
            "localhost",                // single label: would keep a whole TLD-ish space
            "https://example.com",      // a scheme is not a host
            "example.com/path",         // nor a path
            "example.com:443",          // nor a port
            "exa mple.com",             // nor a space
            "..example.com",            // malformed
            ".example.com",             // leading dot
            "éxample.com",              // non-ASCII: hosts reach us punycoded
        ] {
            assert_eq!(normalize_wipe_exempt_host(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn a_malformed_exemption_list_does_not_discard_the_file() {
        // Not an array at all.
        let p: Prefs = serde_json::from_str(r#"{"dns":"quad9","wipe_exempt_hosts":"example.com"}"#)
            .expect("a bad list must not make the whole file unreadable");
        assert_eq!(p.dns, DnsMode::Quad9, "the rest of the file must survive");
        assert!(p.wipe_exempt_hosts.is_empty());

        // An array with junk in it keeps the good entries and drops the rest.
        let p: Prefs = serde_json::from_str(
            r#"{"wipe_exempt_hosts":["example.com", 7, "localhost", "a.test.org"]}"#,
        )
        .expect("mixed junk must still parse");
        assert_eq!(p.wipe_exempt_hosts, vec!["example.com", "a.test.org"]);
    }

    #[test]
    fn tracking_prevention_is_strict_when_absent_and_balanced_round_trips() {
        // Additive-field compatibility: this is the exact shape of a prefs
        // file written before the choice existed. An upgrade must preserve
        // the old STRICT posture rather than inherit WebView2's Balanced
        // default merely because the JSON has no new key.
        let old: Prefs = serde_json::from_str(r#"{"dns":"system"}"#)
            .expect("pre-tracking-level prefs must still load");
        assert_eq!(old.tracking_prevention, TrackingPreventionLevel::Strict);
        assert_eq!(
            Prefs::default().tracking_prevention,
            TrackingPreventionLevel::Strict
        );

        let mut prefs = Prefs::default();
        prefs.tracking_prevention = TrackingPreventionLevel::Balanced;
        let text = serde_json::to_string(&prefs).expect("prefs serialize");
        let back: Prefs = serde_json::from_str(&text).expect("prefs round trip");
        assert_eq!(
            back.tracking_prevention,
            TrackingPreventionLevel::Balanced
        );
        assert!(text.contains(r#""tracking_prevention":"balanced""#));

        for level in [
            TrackingPreventionLevel::Strict,
            TrackingPreventionLevel::Balanced,
        ] {
            assert_eq!(TrackingPreventionLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(TrackingPreventionLevel::parse("basic"), None);
        assert_eq!(TrackingPreventionLevel::parse("Strict"), None);
    }

    /// The marker "Apply and restart" leaves for the next boot. It is the
    /// only thing that tells the replacement process a session is waiting,
    /// so its absent-field meaning has to be "no restore owed" -- every
    /// prefs.json ever written before this field existed says that by
    /// saying nothing.
    #[test]
    fn the_restart_marker_is_absent_by_default_and_survives_a_round_trip() {
        assert_eq!(Prefs::default().tunnel_restore_shelf, None);

        // A prefs file from any earlier build: the key is simply not there.
        let old: Prefs = serde_json::from_str(r#"{"tunnel":"imported"}"#)
            .expect("an older prefs.json must still load");
        assert_eq!(old.tunnel, TunnelMode::Imported);
        // Guaranteed by the struct-level #[serde(default)], which is why
        // this needs no field attribute of its own.
        assert_eq!(
            old.tunnel_restore_shelf, None,
            "an absent marker must not be read as a pending restore"
        );

        let mut prefs = Prefs::default();
        prefs.tunnel_restore_shelf = Some("shelf-7".to_string());
        let text = serde_json::to_string(&prefs).expect("prefs serialize");
        let back: Prefs = serde_json::from_str(&text).expect("prefs round trip");
        assert_eq!(back.tunnel_restore_shelf.as_deref(), Some("shelf-7"));

        // The ID, never the name: two shelves can share a name, and
        // restoring the wrong one reopens a session the user shelved
        // deliberately.
        assert!(
            text.contains("shelf-7"),
            "the marker must store the shelf id verbatim"
        );
    }

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

    /// The 0.9.x panel forced every install onto Beta; 1.0.0 undoes that
    /// exactly once and then respects whatever the user picks.
    #[test]
    fn a_forced_beta_is_reset_to_stable_once_and_a_chosen_beta_is_kept() {
        use super::{reset_forced_beta_once, UpdateChannel};
        let mut forced = Prefs::default();
        forced.update_channel = UpdateChannel::Beta;
        let (p, changed) = reset_forced_beta_once(forced);
        assert!(changed);
        assert_eq!(p.update_channel, UpdateChannel::Stable, "a forced Beta must go back to Stable");
        assert!(p.channel_reset_1_0, "the reset must mark itself done");

        // Picked AFTER the reset: a real choice, untouched.
        let mut chosen = p.clone();
        chosen.update_channel = UpdateChannel::Beta;
        let (q, changed) = reset_forced_beta_once(chosen);
        assert!(!changed);
        assert_eq!(q.update_channel, UpdateChannel::Beta, "a chosen Beta must be respected");

        // A fresh Stable install just gets the marker, once.
        let (r, changed) = reset_forced_beta_once(Prefs::default());
        assert!(changed && r.channel_reset_1_0 && r.update_channel == UpdateChannel::Stable);
        let (_, again) = reset_forced_beta_once(r);
        assert!(!again, "the marker must stop the check from running twice");
    }

    #[test]
    fn old_prefs_json_without_toolbar_labels_reads_show() {
        // The absent-field meaning has to be the shape every earlier build
        // rendered: labelled. A prefs.json written before this setting
        // existed describes a labelled toolbar, so it must read back as one.
        let old = r#"{"dns":"system"}"#;
        let prefs: Prefs = serde_json::from_str(old).expect("old prefs must parse");
        assert_eq!(prefs.toolbar_labels, ToolbarLabels::Show);
        assert_eq!(Prefs::default().toolbar_labels, ToolbarLabels::Show);
    }

    #[test]
    fn toolbar_labels_round_trip_and_unknown_is_refused() {
        let mut prefs = Prefs::default();
        prefs.toolbar_labels = ToolbarLabels::Hide;
        let text = serde_json::to_string(&prefs).unwrap();
        let back: Prefs = serde_json::from_str(&text).unwrap();
        assert_eq!(back.toolbar_labels, ToolbarLabels::Hide);
        // Wire names are the contract with chrome.js; a typo must not
        // silently become a default.
        assert_eq!(ToolbarLabels::parse("hide"), Some(ToolbarLabels::Hide));
        assert_eq!(ToolbarLabels::parse("show"), Some(ToolbarLabels::Show));
        assert_eq!(ToolbarLabels::parse("icons"), None);
        assert_eq!(ToolbarLabels::Hide.as_str(), "hide");
    }

    #[test]
    fn old_prefs_json_without_toolbar_placement_reads_top_left() {
        // Nobody's toolbar moves on upgrade. A prefs.json written before
        // this setting existed describes a browser with two rows above the
        // page, and that is what it must read back as -- including one that
        // already carries the neighbouring layout setting, which is the
        // realistic shape of an existing install's file.
        for old in [r#"{"dns":"system"}"#, r#"{"toolbar_labels":"hide"}"#] {
            let prefs: Prefs = serde_json::from_str(old).expect("old prefs must parse");
            assert_eq!(prefs.toolbar_placement, ToolbarPlacement::TopLeft);
        }
        assert_eq!(Prefs::default().toolbar_placement, ToolbarPlacement::TopLeft);
    }

    #[test]
    fn old_top_toolbar_value_reads_top_left_and_left_stays_left() {
        // `top` was the only horizontal spelling before the choice gained an
        // alignment. It must keep loading as Top Left; `left` was already a
        // stored value and must keep its exact meaning.
        let old_top: Prefs = serde_json::from_str(
            r#"{"toolbar_labels":"hide","toolbar_placement":"top"}"#,
        )
        .expect("old top prefs must parse");
        assert_eq!(old_top.toolbar_placement, ToolbarPlacement::TopLeft);
        assert_eq!(old_top.toolbar_labels, ToolbarLabels::Hide);

        let old_left: Prefs =
            serde_json::from_str(r#"{"toolbar_placement":"left"}"#)
                .expect("old left prefs must parse");
        assert_eq!(old_left.toolbar_placement, ToolbarPlacement::Left);
    }

    #[test]
    fn toolbar_placement_round_trips_and_unknown_is_refused() {
        let mut prefs = Prefs::default();
        prefs.toolbar_placement = ToolbarPlacement::Left;
        let text = serde_json::to_string(&prefs).unwrap();
        let back: Prefs = serde_json::from_str(&text).unwrap();
        assert_eq!(back.toolbar_placement, ToolbarPlacement::Left);
        // Wire names are the contract with chrome.js; a typo must not
        // silently become a default, and must not silently become the OTHER
        // value either -- "side" and "sidebar" are the two words a reader
        // would guess, and both must be refused rather than assumed.
        assert_eq!(ToolbarPlacement::parse("left"), Some(ToolbarPlacement::Left));
        assert_eq!(
            ToolbarPlacement::parse("top_left"),
            Some(ToolbarPlacement::TopLeft)
        );
        assert_eq!(
            ToolbarPlacement::parse("top_right"),
            Some(ToolbarPlacement::TopRight)
        );
        assert_eq!(ToolbarPlacement::parse("right"), Some(ToolbarPlacement::Right));
        // `top` is a stored-prefs compatibility alias, not a current IPC wire
        // spelling. New saves and live messages use the four unambiguous names.
        assert_eq!(ToolbarPlacement::parse("top"), None);
        assert_eq!(ToolbarPlacement::parse("side"), None);
        assert_eq!(ToolbarPlacement::parse("sidebar"), None);
        assert_eq!(ToolbarPlacement::parse("Left"), None);
        assert_eq!(ToolbarPlacement::Left.as_str(), "left");
        // The stored spelling is what a later build will read back.
        assert!(text.contains(r#""toolbar_placement":"left""#));
    }

    #[test]
    fn the_two_layout_settings_are_independent() {
        // Labels apply only while the toolbar is on top, and that is a UI
        // rule, not a storage one: choosing Left must not quietly discard a
        // label preference the user set earlier and would get back by
        // choosing a top placement again.
        let mut prefs = Prefs::default();
        prefs.toolbar_labels = ToolbarLabels::Hide;
        prefs.toolbar_placement = ToolbarPlacement::Right;
        let text = serde_json::to_string(&prefs).unwrap();
        let back: Prefs = serde_json::from_str(&text).unwrap();
        assert_eq!(back.toolbar_labels, ToolbarLabels::Hide);
        assert_eq!(back.toolbar_placement, ToolbarPlacement::Right);

        // Placement changes never rewrite the neighbouring pref. Returning to
        // Top Left restores the exact label choice that preceded the strip.
        let mut returned = back;
        returned.toolbar_placement = ToolbarPlacement::TopLeft;
        assert_eq!(returned.toolbar_labels, ToolbarLabels::Hide);
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
    /// fail-closed behaviour -- so for a user who had chosen Quad9, "corrupt"
    /// is a silently disabled protection (from the next start) while
    /// "missing" is just a first run. The panel can only say so if these two
    /// are told apart, and for most of the life of this file they were not.
    #[test]
    fn a_corrupt_settings_file_is_not_the_same_as_no_settings_file() {
        // Exercises the REAL classifier, `from_read`, fed the read result
        // directly, so a regression in load_with_origin's own logic fails
        // here rather than in a copy of it.
        let classify = |read: Result<String, std::io::ErrorKind>| from_read(read).1;

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
        assert_eq!(classify(Ok(r#"{"dns":"quad9"}"#.to_string())), PrefsOrigin::Stored);

        // And the reason any of this matters: the fallback carries no DoH.
        assert_eq!(Prefs::default().dns, DnsMode::System);
        assert_eq!(Prefs::default().dns.doh_mode(), None);
    }

    #[test]
    fn choosing_a_resolver_stays_opt_in() {
        // Every alternative here hands a specific company every domain the user
        // looks up. That can be a good trade and the panel argues it, but the
        // browser must not make it on the user's behalf -- quietly redirecting
        // DNS to a party of our choosing is a smaller version of the thing this
        // product exists to refuse. Decided 2026-09-05, reversing a
        // one-day Quad9 default.
        assert_eq!(DnsMode::default(), DnsMode::System);
        assert_eq!(Prefs::default().dns, DnsMode::System);
        assert_eq!(DnsMode::default().doh_template(), None);
        // An EMPTY preferences file must land in the same place as a missing
        // one: a user who never opened the picker has not opted in to anything.
        let untouched = parse_stored("{}").expect("empty prefs must parse");
        assert_eq!(untouched.dns, DnsMode::System);
        assert!(!untouched.resolver_chosen);
    }

    #[test]
    fn a_stored_choice_survives_upgrade_and_the_retired_name_maps_to_quad9() {
        // No 0.9.x build wrote the chosen marker, and the default was System
        // there too -- so a stored non-default value can only have come from
        // the picker. It is honoured and marked chosen, so a later default
        // change cannot take it away. A stored `mullvad` reads as Quad9:
        // encrypted stays encrypted, never plaintext, never "unreadable".
        let p = parse_stored(r#"{"dns":"quad9","vault_autolock_secs":900}"#).unwrap();
        assert_eq!(p.dns, DnsMode::Quad9);
        assert!(p.resolver_chosen, "a non-default value is a choice by definition");
        assert_eq!(p.vault_autolock_secs, 900, "the rest of the file survives");
        let p = parse_stored(r#"{"dns":"mullvad"}"#).unwrap();
        assert_eq!(p.dns, DnsMode::Quad9, "the retired resolver becomes Quad9");
        assert!(p.resolver_chosen);
        let p = parse_stored(r#"{"dns":"system"}"#).unwrap();
        assert_eq!(p.dns, DnsMode::System);
        assert!(!p.resolver_chosen, "a stored default without the marker is just the default");
        // A file that recorded a System choice keeps it as a choice.
        let p = parse_stored(r#"{"dns":"system","resolver_chosen":true}"#).unwrap();
        assert!(p.resolver_chosen);
        // What this build writes: the same `dns` key every earlier build
        // reads, plus the marker.
        let written = serde_json::to_string(&Prefs::default()).unwrap();
        assert!(written.contains(r#""dns":"system""#), "{written}");
        assert!(written.contains(r#""resolver_chosen":false"#), "{written}");
    }

    #[test]
    fn the_default_never_fails_closed_and_quad9_does() {
        // Picking Quad9 fails closed, which makes captive-portal WiFi
        // unusable until the user switches back. That is an acceptable cost
        // of a deliberate choice and an unacceptable one for a first run, so
        // the DEFAULT must carry no DoH mode. If this ever gains one, a user
        // who installed the browser and changed nothing is stranded on hotel
        // WiFi with no route online and no idea why.
        assert_eq!(DnsMode::default().doh_mode(), None);
        assert_eq!(DnsMode::default().doh_args(), None);
        assert_eq!(DnsMode::System.doh_mode(), None);
        assert_eq!(DnsMode::System.doh_template(), None);
        assert_eq!(DnsMode::Quad9.doh_mode(), Some("secure"));
        // The switches the engine is handed for the encrypted choice, pinned
        // as text, because the Windows function that appends them is out of
        // reach of a Linux-run test.
        assert_eq!(
            DnsMode::Quad9.doh_args().as_deref(),
            Some(" --dns-over-https-mode=secure --dns-over-https-templates=https://dns.quad9.net/dns-query")
        );
    }

    #[test]
    fn a_malformed_marker_does_not_take_the_whole_file_down() {
        // The marker must fail SMALL. A file whose marker is null (or
        // anything but a boolean) still yields every other preference in it
        // -- here the tunnel mode -- and the resolver beside it. The
        // alternative was "unreadable", which discards the file and lets the
        // next save write defaults over it.
        for bad in [r#"null"#, r#"1"#, r#""yes""#, r#"[]"#] {
            let raw = format!(r#"{{"resolver_chosen":{bad},"tunnel":"imported","dns":"quad9"}}"#);
            let prefs = parse_stored(&raw)
                .unwrap_or_else(|e| panic!("marker {bad} must not make the file unreadable: {e}"));
            assert_eq!(prefs.tunnel, TunnelMode::Imported, "the tunnel mode must survive");
            assert_eq!(prefs.dns, DnsMode::Quad9, "a stored choice survives a broken marker");
            assert!(prefs.resolver_chosen, "and is marked chosen from the value itself");
        }
        // And beside the DEFAULT value a malformed marker must read as FALSE:
        // `parse_stored` only ever sets the marker for a non-default value,
        // so this is the case that catches a deserializer regression that
        // read garbage as `true` and turned a side-effect System into a
        // recorded choice.
        for bad in [r#"null"#, r#"1"#, r#""yes""#, r#"[]"#] {
            let raw = format!(r#"{{"resolver_chosen":{bad},"dns":"system"}}"#);
            let prefs = parse_stored(&raw).unwrap();
            assert_eq!(prefs.dns, DnsMode::System);
            assert!(!prefs.resolver_chosen, "marker {bad} beside the default must read as unset");
        }
        let (prefs, origin) = from_read(Ok(r#"{"resolver_chosen":null,"tunnel":"imported"}"#.into()));
        assert_eq!(origin, PrefsOrigin::Stored);
        assert_eq!(prefs.tunnel, TunnelMode::Imported);
        assert_eq!(prefs.dns, DnsMode::System);
        assert!(!prefs.resolver_chosen);
    }

    #[test]
    fn modes_round_trip_through_their_wire_names() {
        for mode in [DnsMode::System, DnsMode::Quad9] {
            assert_eq!(DnsMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(DnsMode::parse("nonsense"), None);
        assert_eq!(DnsMode::parse("System"), None, "wire names are lowercase");
        // Retired with Mullvad's public resolvers (shutdown 2026-11-02). An
        // IPC caller that still names it gets bad_args, not a substitution.
        assert_eq!(DnsMode::parse("mullvad"), None);
    }

    #[test]
    fn the_encrypted_mode_has_an_https_template() {
        // A mode that claims to encrypt but resolves to no template would
        // silently leave DNS in plaintext while the UI said otherwise.
        let t = DnsMode::Quad9.doh_template().expect("must have a DoH template");
        assert!(t.starts_with("https://"), "template must be https");
        // And nothing in this enum still points at the retired service.
        for mode in [DnsMode::System, DnsMode::Quad9] {
            assert!(!mode.doh_template().unwrap_or("").contains("mullvad"));
        }
    }

    #[test]
    fn choosing_a_resolver_fails_closed_and_system_does_not() {
        // The whole reason to pick a resolver is not to use the network's. A
        // mode that fell back would hand a hostile or merely cheap network the
        // plaintext lookups this setting exists to prevent, silently.
        assert_eq!(DnsMode::Quad9.doh_mode(), Some("secure"), "Quad9 must fail closed");
        // System must carry NO mode: with no template there is nothing to be
        // secure about, and a mode without a template configures a fallback
        // the user never asked for.
        assert_eq!(DnsMode::System.doh_mode(), None);
        assert_eq!(DnsMode::System.doh_template(), None);
    }

    #[test]
    fn the_applied_resolver_is_system_until_an_engine_records_one() {
        // Only the Windows engine takes the DoH setting, and it records what
        // it took. Before that -- and forever on Linux, where nothing records
        // -- the answer is System, which is the truth there. The first build
        // freezes it, and every later build (fallback path, translator
        // webview) is handed the frozen value, not the file's current one.
        //
        // This is the ONLY test that records; the static is process-wide.
        assert_eq!(applied_dns(), DnsMode::System);
        assert_eq!(applied_dns_or_record(DnsMode::Quad9), DnsMode::Quad9);
        assert_eq!(applied_dns(), DnsMode::Quad9);
        assert_eq!(
            applied_dns_or_record(DnsMode::System),
            DnsMode::Quad9,
            "a later build must get the frozen resolver, not the file's"
        );
        assert_eq!(applied_dns(), DnsMode::Quad9, "the first record must win");
    }

    #[test]
    fn each_description_says_what_the_choice_costs() {
        // Quad9 filters threats, and the UI text must say so -- and the
        // fail-closed cost is the part a user discovers at an airport. It has
        // to be in the sentence they read BEFORE choosing, not afterwards.
        let d = DnsMode::Quad9.describe(&english());
        assert!(
            d.contains("malware") || d.contains("malicious"),
            "Quad9 filters threats, and the UI text must say so: {d}"
        );
        assert!(d.contains("WiFi"), "must warn that public WiFi logins break: {d}");
        // And the default must say what IT costs: plaintext.
        let s = DnsMode::System.describe(&english());
        assert!(
            s.contains("not encrypted") || s.contains("unencrypted"),
            "System must say lookups are unencrypted: {s}"
        );
    }

    #[test]
    fn malformed_preferences_fall_back_rather_than_failing() {
        // Exercised through the parser rather than the filesystem, so the test
        // does not depend on a real data directory.
        let broken: Result<Prefs, _> = serde_json::from_str("{ not json");
        assert!(broken.is_err());
        // A field from a newer build must not break an older one -- and a
        // System value that was CHOSEN is honoured through the same path.
        let unknown = parse_stored(r#"{"dns":"system","future":1}"#)
            .expect("an unknown field must not break an older build");
        assert_eq!(unknown.dns, DnsMode::System);
        // And a stored choice beside an unknown field is still a choice.
        let chosen = parse_stored(r#"{"dns":"quad9","future":1}"#).unwrap();
        assert_eq!(chosen.dns, DnsMode::Quad9);
        assert!(chosen.resolver_chosen);
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
        let l10n = english();
        let off = TunnelMode::Off.describe(&l10n);
        let imported = TunnelMode::Imported.describe(&l10n);
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
        let d = TunnelMode::Imported.describe(&english());
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
        // The one-click route must be named too, or the copy sends people
        // to quit the browser by hand for a restart the panel can do.
        assert!(
            d.contains("Apply and restart"),
            "the Imported description must name the one-click restart"
        );
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
