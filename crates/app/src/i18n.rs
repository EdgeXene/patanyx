//! The string catalog: every user-facing sentence the Rust side owns,
//! resolved from a Fluent bundle compiled into the binary.
//!
//! THE CATALOG NEVER TOUCHES DISK AT RUNTIME. The strings being carried are
//! the product's privacy claims ("this is not an anonymity feature", "never
//! falls back to a direct connection"), and a claim loaded from a
//! user-writable file is a claim an attacker can rewrite with the product's
//! own authority. `include_str!` or nothing.
//!
//! RESOLUTION IS PER-CALL, AND THAT IS LOAD-BEARING. No `OnceLock`, no cache
//! of resolved text anywhere: a user-visible setting takes effect the moment
//! it changes, everywhere it shows, and the interface locale is such a
//! setting. A cache keyed to first use would pin the first locale forever --
//! precisely the staleness two independent red teams flagged. The bundle
//! lives on the UI thread with the rest of `AppState`; nothing here is
//! `Send`, and nothing needs to be.
//!
//! ISOLATION IS OFF, FOR NOW, AND THE FLIP IS ONE LINE. With isolation on,
//! Fluent wraps every interpolated value in invisible FSI/PDI marks -- the
//! right hardening against a filename crafted to read as part of the claim
//! around it, and a deliberate byte change to English output. The extraction
//! milestone's bar is byte-identical English, so the flip (ISOLATE_PLACEABLES
//! below) lands as its own commit, updating the affected tests in the same
//! change, once extraction has been proven against today's bytes.
//!
//! THREE STANDING RULINGS, so nobody rediscovers them as gaps:
//!
//!  - VERBATIM CARVE-OUT. Engine-authored Display texts (ConfigError's
//!    refusals, corroborate verdicts, update-refusal reasons) reach the
//!    user in English regardless of locale. Deliberate: those strings are
//!    security events quoted verbatim by contract ("do not paraphrase a
//!    security event"), and localizing them is a dedicated pass with its
//!    own review, not a side effect of this catalog. Until that pass, a
//!    non-English session shows them in English -- known, chosen, and
//!    better than a translation nobody audited.
//!
//!  - NUMBER AND DATE CONVENTIONS follow the OPERATING SYSTEM locale
//!    (toLocaleString at the call sites), not ui_locale. A German chrome
//!    on an en-US system therefore shows "8,842" amid German text. Chosen
//!    because the OS convention is what the user's other software does;
//!    revisit when a human locale ships, not before.
//!
//!  - RTL IS OUT OF SCOPE. No dir attribute handling, no layout
//!    mirroring. An RTL locale is not a catalog entry away -- it is a
//!    layout project, and pretending otherwise by accepting an "ar.ftl"
//!    would ship a broken browser. The CATALOGS table is the gate: adding
//!    an RTL tag there must come with that project, and this note is the
//!    tripwire for whoever tries.
//!
//! What websites see is none of this module's business. The interface locale
//! must never be wired toward pages -- not navigator.language, not
//! Accept-Language, not the engine's content-language surface. The ruling
//! and its reasoning live with the fingerprint-divergence non-goals; the
//! pinned test `the_locale_never_reaches_a_page_facing_surface` holds the
//! door shut from this side.

use fluent_bundle::{FluentArgs, FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

/// The English catalog, the source of truth for every message id.
const EN_FTL: &str = include_str!("chrome/i18n/locales/en.ftl");
/// The generated pseudo-locale: accented, padded, entirely non-ASCII. It is
/// compiled in as a REAL second catalog on purpose -- it keeps the whole
/// non-English path (locale set, fill snapshot, applier, live switch)
/// exercised and shippable years before any translator exists, and it is
/// what the overflow pass drives. scripts/i18n-gate.sh regenerates and
/// diffs it, so it cannot go stale against en.ftl.
const EN_XA_FTL: &str = include_str!("chrome/i18n/locales/en-XA.ftl");

/// Every locale this binary carries. One row per catalog; adding a locale
/// is one file plus one line here.
const CATALOGS: &[(&str, &str)] = &[("en", EN_FTL), ("en-XA", EN_XA_FTL)];

/// The locale tags this binary can actually speak, in table order --
/// the single source for the settings surface's list, so a locale added
/// to CATALOGS is offered without a second edit.
pub fn available_locales() -> Vec<&'static str> {
    CATALOGS.iter().map(|(t, _)| *t).collect()
}

/// Why a bootstrap refused. The distinction is load-bearing: an unknown tag
/// is an EXPECTED runtime condition (a prefs file written by a newer build
/// that carried more locales), and the caller falls back to English with an
/// id-only log. A compiled catalog failing validation is a BUILD DEFECT --
/// the i18n tests already fail on it -- and the caller panics rather than
/// silently downgrading what language the user asked for.
#[derive(Debug)]
pub enum BootstrapError {
    UnknownLocale,
    InvalidCatalog(String),
}

/// The one-line hardening flip. See the module comment before touching it.
const ISOLATE_PLACEABLES: bool = true;

/// Message ids, spelled once. A typo here is a compile error at the call
/// site and a gate failure against the catalog, instead of a runtime miss.
/// Hand-written while the catalog is five messages; generation out of
/// `build.rs` earns its keep when the bulk extraction lands.
pub mod keys {
    pub const PREFS_DNS_SYSTEM_DESCRIPTION: &str = "prefs-dns-system-description";
    pub const PREFS_DNS_QUAD9_DESCRIPTION: &str = "prefs-dns-quad9-description";
    pub const PREFS_TUNNEL_OFF_DESCRIPTION: &str = "prefs-tunnel-off-description";
    pub const PREFS_TUNNEL_IMPORTED_DESCRIPTION: &str = "prefs-tunnel-imported-description";
    pub const CHROME_BLOCKED_BODY: &str = "chrome-blocked-body";
    pub const CHROME_BLOCKED_RULE_CLAUSE: &str = "chrome-blocked-rule-clause";
    pub const CHROME_RESOLVER_BODY: &str = "chrome-resolver-body";
    pub const CHROME_RESOLVER_NAME_FALLBACK: &str = "chrome-resolver-name-fallback";
    pub const CHROME_JS_DNS_SHORT_QUAD9: &str = "chrome-js-dns-short-quad9";
    pub const CHROME_ENGINE_FLOOR_BODY: &str = "chrome-engine-floor-body";
    pub const CHROME_ENGINE_FLOOR_EVERGREEN: &str = "chrome-engine-floor-evergreen";
    pub const CHROME_ENGINE_FLOOR_BODY_RESTART: &str = "chrome-engine-floor-body-restart";

    /// Every key, for the coverage checks. A constant added above and
    /// forgotten here fails `every_key_resolves` the moment nothing else
    /// exercises it.
    pub const ALL: &[&str] = &[
        PREFS_DNS_SYSTEM_DESCRIPTION,
        PREFS_DNS_QUAD9_DESCRIPTION,
        PREFS_TUNNEL_OFF_DESCRIPTION,
        PREFS_TUNNEL_IMPORTED_DESCRIPTION,
        CHROME_BLOCKED_BODY,
        CHROME_BLOCKED_RULE_CLAUSE,
        CHROME_RESOLVER_BODY,
        CHROME_RESOLVER_NAME_FALLBACK,
        CHROME_JS_DNS_SHORT_QUAD9,
        CHROME_ENGINE_FLOOR_BODY,
        CHROME_ENGINE_FLOOR_EVERGREEN,
        CHROME_ENGINE_FLOOR_BODY_RESTART,
    ];
}

/// Runtime values for interpolation. Values cross as ARGUMENTS, never as
/// FTL source: nothing in this module concatenates a runtime string into
/// catalog text and re-parses it, which is what keeps a hostile filename
/// data instead of markup.
pub type Args<'a> = FluentArgs<'a>;

// CHROME_MSG_KEYS: the markup's marker keys, generated by build.rs from
// index.html itself so the list cannot drift from the file it describes.
include!(concat!(env!("OUT_DIR"), "/chrome_msg_keys.rs"));

pub struct I18n {
    bundle: FluentBundle<FluentResource>,
}

impl I18n {
    /// Builds the catalog for `locale`, from the CATALOGS table and nowhere
    /// else. An unknown tag is refused rather than silently anglicized; the
    /// caller decides what that means (see [`BootstrapError`]).
    ///
    /// EVERY Fluent complaint is fatal here -- parse errors, duplicate ids,
    /// anything `add_resource` returns. A duplicate id is the sharp one: the
    /// parser's own policy for duplicates is not this module's problem
    /// because the build never gets that far. The pinned test
    /// `a_duplicate_message_id_is_refused` proves the refusal instead of
    /// trusting the crate's documentation to stay true.
    pub fn bootstrap(locale: &str) -> Result<Self, BootstrapError> {
        let Some((_, ftl)) = CATALOGS.iter().find(|(t, _)| *t == locale) else {
            return Err(BootstrapError::UnknownLocale);
        };
        Self::from_ftl(locale, ftl).map_err(BootstrapError::InvalidCatalog)
    }

    fn from_ftl(locale: &str, ftl: &str) -> Result<Self, String> {
        let lang: LanguageIdentifier = locale
            .parse()
            .map_err(|e| format!("locale tag {locale:?}: {e:?}"))?;
        let resource = FluentResource::try_new(ftl.to_string())
            .map_err(|(_, errs)| format!("catalog for {locale:?} does not parse: {errs:?}"))?;
        let mut bundle = FluentBundle::new(vec![lang]);
        bundle.set_use_isolating(ISOLATE_PLACEABLES);
        bundle
            .add_resource(resource)
            .map_err(|errs| format!("catalog for {locale:?} refused: {errs:?}"))?;
        Ok(Self { bundle })
    }

    /// Resolves one message. Owned `String` out, because the text's lifetime
    /// must not be coupled to the bundle's: locale can change under any
    /// borrower, and IPC payloads need owned text anyway.
    ///
    /// A miss returns the id itself only in a build where the coverage gate
    /// and `every_key_resolves` both failed to run -- which is to say, not a
    /// build. Claims never fail open at runtime because the failure is
    /// arrested at build time; this arm exists so the signature is total,
    /// and it logs the ID, never argument values (filenames and hostnames
    /// are user data and do not belong in a log).
    pub fn resolve(&self, id: &str, args: &Args) -> String {
        let Some(message) = self.bundle.get_message(id) else {
            eprintln!("i18n: message {id:?} missing from catalog");
            return id.to_string();
        };
        let Some(pattern) = message.value() else {
            eprintln!("i18n: message {id:?} has no value");
            return id.to_string();
        };
        let mut errors = vec![];
        let out = self
            .bundle
            .format_pattern(pattern, Some(args), &mut errors)
            .into_owned();
        if !errors.is_empty() {
            // Ids only. Never the arguments.
            eprintln!("i18n: message {id:?} formatted with errors: {errors:?}");
        }
        out
    }

    /// `resolve` with no arguments, which is most claims.
    pub fn text(&self, id: &str) -> String {
        self.resolve(id, &Args::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn english() -> I18n {
        I18n::bootstrap("en").expect("the embedded English catalog is valid")
    }

    #[test]
    fn the_embedded_catalog_bootstraps() {
        english();
    }

    #[test]
    fn every_key_resolves() {
        let l10n = english();
        for id in keys::ALL {
            let out = l10n.text(id);
            assert_ne!(
                out, *id,
                "{id} fell back to its own id -- absent from en.ftl"
            );
            assert!(!out.is_empty(), "{id} resolved to nothing");
        }
    }

    #[test]
    fn an_unknown_locale_is_refused_not_anglicized() {
        assert!(matches!(
            I18n::bootstrap("de"),
            Err(BootstrapError::UnknownLocale)
        ));
    }

    #[test]
    fn every_compiled_catalog_is_valid_and_covers_every_key() {
        // Validation is FATAL at this boundary for every catalog the binary
        // carries -- a broken compiled catalog is a build defect, and this
        // is the test that makes it one.
        for (tag, _) in CATALOGS {
            let l10n = I18n::bootstrap(tag)
                .unwrap_or_else(|_| panic!("compiled catalog {tag} is invalid"));
            for id in keys::ALL {
                assert_ne!(l10n.text(id), *id, "{tag} is missing {id}");
            }
        }
    }

    #[test]
    fn a_duplicate_message_id_is_refused() {
        // The claim-swap and duplicate-key attacks both need a second
        // definition to win. Prove the bundle refuses one, rather than
        // trusting documentation.
        let err = I18n::from_ftl("en", "a = first\na = second\n");
        assert!(err.is_err(), "a duplicate id must fail the build's bundle");
    }

    #[test]
    fn a_parse_error_is_fatal() {
        assert!(I18n::from_ftl("en", "not valid ftl {").is_err());
    }

    #[test]
    fn arguments_are_data_not_ftl() {
        // A value shaped like FTL syntax must come out as the literal it is,
        // never re-parsed into a placeable.
        let l10n = I18n::from_ftl("en", "m = saved { $file } here\n").unwrap();
        let mut args = Args::default();
        args.set("file", "{ $other }");
        let out = l10n.resolve("m", &args);
        assert!(
            out.contains("{ $other }"),
            "the argument was re-interpreted: {out:?}"
        );
    }

    #[test]
    fn the_blocked_body_composes_byte_identically_to_the_old_concatenation() {
        // This sentence moved from JS string concatenation to a catalog
        // message with arguments. The English a user reads must not have
        // changed by one byte in the move, in either branch.
        let l10n = english();
        let mut args = Args::default();
        args.set("rule", "evil.example");
        let clause = l10n.resolve(keys::CHROME_BLOCKED_RULE_CLAUSE, &args);
        let mut args = Args::default();
        args.set("host", "login.evil.example");
        args.set("rulenote", clause);
        assert_eq!(
            l10n.resolve(keys::CHROME_BLOCKED_BODY, &args),
            "PATANYX did not open \u{2068}login.evil.example\u{2069} because it has been reported for phishing or malware.\u{2068} It matched the rule \u{2068}evil.example\u{2069}, which also covers its subdomains.\u{2069} If you believe this is wrong, you can open it anyway. That applies to this tab only and ends when you close it."
        );
        let mut args = Args::default();
        args.set("host", "evil.example");
        args.set("rulenote", "");
        assert_eq!(
            l10n.resolve(keys::CHROME_BLOCKED_BODY, &args),
            "PATANYX did not open \u{2068}evil.example\u{2069} because it has been reported for phishing or malware.\u{2068}\u{2069} If you believe this is wrong, you can open it anyway. That applies to this tab only and ends when you close it."
        );
    }

    #[test]
    fn the_resolver_body_composes_for_both_producers() {
        // The banner names the resolver the user chose, says what is broken,
        // and says how to get online; the fallback name reads as language.
        let l10n = english();
        assert_eq!(
            crate::resolver_probe::banner_body(&l10n, "quad9"),
            "PATANYX cannot reach \u{2068}Quad9\u{2069}, which you chose to resolve the sites you visit, so pages will not load until it can. This usually means the network is blocking it, which is common on hotel, airport and cafe WiFi before you sign in. It can also mean the connection is down, or a VPN is still reconnecting. To get online here: open DNS in the toolbar, choose System, and restart PATANYX. That sends your lookups to this network instead of to \u{2068}Quad9\u{2069}, so change it back when you leave."
        );
        assert!(crate::resolver_probe::banner_body(&l10n, "system")
            .contains("cannot reach \u{2068}your DNS service\u{2069}, which you chose"));
        // The retired name must not resolve to a proper noun any more.
        assert!(crate::resolver_probe::banner_body(&l10n, "mullvad")
            .contains("cannot reach \u{2068}your DNS service\u{2069}"));
    }

    #[test]
    fn locally_argued_messages_compose_byte_identically_every_branch() {
        // Each of these replaced a JS composition; the resolved English
        // must equal the old concatenation in EVERY branch, plural and
        // zero cases included.
        let l10n = english();
        let case = |id: &str, pairs: &[(&str, f64)], strs: &[(&str, &str)], want: &str| {
            let mut args = Args::default();
            for (k, v) in pairs {
                args.set(*k, *v);
            }
            for (k, v) in strs {
                args.set(*k, *v);
            }
            assert_eq!(l10n.resolve(id, &args), want, "{id}");
        };
        case("chrome-batch-left-out", &[("count", 1.0)], &[],
            "\u{2068}1\u{2069} tab was not shelved: ephemeral and internal tabs are skipped.");
        case("chrome-batch-left-out", &[("count", 3.0)], &[],
            "\u{2068}3\u{2069} tabs were not shelved: ephemeral and internal tabs are skipped.");
        case("chrome-shelf-left-out", &[("count", 2.0)], &[],
            " \u{2068}2\u{2069} left out: ephemeral and internal pages stay open.");
        case("chrome-leakcheck-clean", &[("count", 4.0)], &[],
            "Read \u{2068}4\u{2069} line(s) and found nothing sensitive.");
        case("chrome-leakcheck-found", &[("count", 2.0)], &[],
            "Found \u{2068}2\u{2069} thing(s) worth checking before sharing:");
        case("chrome-permissions-granted", &[], &[("who", "this site")],
            "Allowed for \u{2068}this site\u{2069} until PATANYX closes");
        case("chrome-permissions-refused", &[("count", 0.0)], &[("who", "this site")],
            "Refused for \u{2068}this site\u{2069}");
        case("chrome-permissions-refused", &[("count", 1.0)], &[("who", "example.com")],
            "Refused for \u{2068}example.com\u{2069}");
        case("chrome-permissions-refused", &[("count", 4.0)], &[("who", "example.com")],
            "Refused \u{2068}4\u{2069} times for \u{2068}example.com\u{2069}");
        case("chrome-confirm-delete-folder", &[], &[("name", "Work")],
            "Delete the folder \"\u{2068}Work\u{2069}\"? The bookmarks in it are kept, just no longer filed under this folder.");
        case("chrome-download-mark-failed-body", &[], &[("name", "a.pdf")],
            "Saved \u{2068}a.pdf\u{2069}, but Windows kept the download's source address next to the file and it could not be removed.");
        case("chrome-download-mark-unknown-body", &[], &[("name", "a.pdf")],
            "Saved \u{2068}a.pdf\u{2069}. PATANYX could not check whether Windows wrote the download's source address next to it.");
        case("chrome-update-ready-version", &[], &[("version", "1.0.0")],
            "Version \u{2068}1.0.0\u{2069} is downloaded and verified. Nothing has been installed: open Updates to see what changed and restart when it suits you.");
        case("chrome-update-ready-plain", &[], &[],
            "It is downloaded and verified. Nothing has been installed: open Updates to see what changed and restart when it suits you.");
        case("chrome-update-offered-version", &[], &[("version", "1.0.0")],
            "Version \u{2068}1.0.0\u{2069} is ready to install. Nothing has been downloaded yet. Open Updates to see what changed and decide.");
        case("chrome-update-offered-plain", &[], &[],
            "Nothing has been downloaded yet. Open Updates to see what changed and decide.");
        case("chrome-insecure-body", &[], &[("host", "example.com")],
            "PATANYX did not open \u{2068}example.com\u{2069} because the connection is plain HTTP, not encrypted. Anything you send or receive on this site can be read or changed by anyone on the path. You can continue anyway; that applies to this site in this tab only and ends when you close the tab.");
        case("chrome-site-forget-desc", &[], &[("origin", "example.com")],
            "Clears cookies for \u{2068}example.com\u{2069}. Saved passwords, local storage, and other site data are not affected.");
        case("chrome-cred-fills-subdomains", &[], &[("domain", "google.com")],
            "Fills on \u{2068}google.com\u{2069} and its subdomains");
        case("chrome-cred-fills-only", &[], &[("origin", "sso.example")],
            "Fills on \u{2068}sso.example\u{2069} only");
        case("chrome-engine-blocklist-count", &[("count", 8842.0)], &[("formatted", "8,842")],
            ", \u{2068}8,842\u{2069} sites blocked");
        case("chrome-engine-blocklist-reason", &[], &[("reason", "timeout")],
            " (\u{2068}timeout\u{2069})");
        case("chrome-engine-blocklist-ok", &[], &[("countnote", ", 8,842 sites blocked")],
            " up to date\u{2068}, 8,842 sites blocked\u{2069}");
        case("chrome-engine-blocklist-ok", &[], &[("countnote", "")],
            " up to date\u{2068}\u{2069}");
        case("chrome-engine-blocklist-failed", &[], &[("countnote", ""), ("reasonnote", " (timeout)")],
            " REFRESH FAILED. Still blocking with the list already downloaded\u{2068}\u{2069}\u{2068} (timeout)\u{2069}");
        case("chrome-compare-request-toast", &[], &[("host", "example.com")],
            "A contact asked what you downloaded from \u{2068}example.com\u{2069}. Your record's fingerprint was sent back.");
        case("chrome-recall-saved-words", &[("words", 42.0)], &[("shortfall", " The picture is the part that was on screen.")],
            "Saved. \u{2068}42\u{2069} words read from this page.\u{2068} The picture is the part that was on screen.\u{2069}");
        case("chrome-recall-saved-notext", &[], &[("shortfall", "")],
            "Saved. No text was read from this picture.\u{2068}\u{2069}");
        case("chrome-recall-short-whole", &[], &[],
            " The page was long, so the text stops partway down; the picture is complete.");
        case("chrome-recall-short-partial", &[], &[],
            " The page was long, so the text stops partway down, and the picture is the part that was on screen.");
        case("chrome-recall-screen-only", &[], &[],
            " The picture is the part that was on screen.");
        case("chrome-manager-delete-folder", &[], &[("name", "Work")],
            "Delete the folder \"\u{2068}Work\u{2069}\"? The bookmarks in it are kept, just no longer filed under it.");
    }

    #[test]
    fn the_locale_never_reaches_a_page_facing_surface() {
        // The ruling lives with the fingerprint-divergence non-goals:
        // interface language and site-visible language are two settings,
        // and only the user connects them. This test holds the door from
        // the code side, two ways.
        //
        // 1. The locale identifier must never appear in the platform layer,
        //    which is where every page-facing language surface lives
        //    (WebView2 environment creation, engine settings).
        let manifest = env!("CARGO_MANIFEST_DIR");
        let platform_dir = std::path::Path::new(manifest).join("src/platform");
        for entry in std::fs::read_dir(&platform_dir).expect("platform dir") {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read");
            for (n, line) in source.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                assert!(
                    !code.contains("ui_locale"),
                    "{}:{}: ui_locale reached the platform layer -- that is                      the road to pages learning the interface language",
                    path.display(),
                    n + 1
                );
            }
        }
        // 2. The locale plumbing itself must not name a page-facing sink.
        //    Comment lines may (to forbid them); code may not.
        for (name, source) in [
            ("i18n.rs", include_str!("i18n.rs")),
            ("chrome.js", include_str!("chrome/chrome.js")),
        ] {
            for (n, line) in source.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                // Built by concatenation so this test's own list cannot
                // trip its own scan of this file.
                let sinks = [
                    format!("navigator{}", ".language"),
                    format!("Accept{}", "-Language"),
                    format!("put_{}", "Language"),
                    format!("set_{}", "language"),
                ];
                for sink in &sinks {
                    assert!(
                        !code.contains(sink.as_str()),
                        "{name}:{}: locale plumbing names page-facing sink {sink}",
                        n + 1
                    );
                }
            }
        }
    }

    #[test]
    fn isolation_is_on_and_wraps_every_placeable() {
        // The hardening this flip buys: an interpolated value -- a filename
        // crafted to read as part of the claim around it, a bidi-control
        // hostname -- is fenced in FSI/PDI isolate marks, invisible on
        // screen and impassable for direction tricks. This is the one
        // sanctioned English byte-change after the extraction milestone,
        // landed with every affected pin updated in the same commit.
        let l10n = I18n::from_ftl("en", "m = saved { $file } here\n").unwrap();
        let mut args = Args::default();
        args.set("file", "a.txt");
        assert_eq!(
            l10n.resolve("m", &args),
            "saved \u{2068}a.txt\u{2069} here"
        );
    }

}
