//! What this program is, what it is licensed under, and what is inside it.
//!
//! THE ATTRIBUTION IS SELECTED AT COMPILE TIME, AND THAT IS THE POINT.
//!
//! `THIRD_PARTY_LICENSES.md` in the repository is the union over every feature
//! and every target -- 466 crates -- and says so about itself. Over-reporting
//! is the right call for a repository file: it cannot accidentally omit a
//! dependency.
//!
//! It is the wrong call for a panel inside the browser. The Windows public
//! build links 204 of those packages; the chat build links 229. A panel
//! rendering the union would tell someone that dozens of pieces of software
//! are running on their machine which are not. The whole reason this surface
//! exists is to answer "what am I running", so it must answer for THIS binary.
//!
//! `include_str!` under `cfg` gives that structurally: a build cannot pick up
//! another configuration's attribution, because only one of the four is
//! compiled at all. Keeping them in step with the dependency tree is
//! `scripts/shipping-licenses.py`, and `scripts/attribution-gate.sh` fails the
//! build if the checked-in files no longer match what cargo resolves.

use serde_json::{json, Value};

/// PATANYX's own terms, verbatim from the file that ships beside the binary.
const LICENSE: &str = include_str!("../../../LICENSE");

/// Attributions that must travel with a redistribution: the bundled
/// malicious-host list, the OCR models, and the platform web engines.
const NOTICE: &str = include_str!("../../../NOTICE");

// One of these four, never more, never none. A missing file is a compile
// error rather than an About panel that quietly shows nothing.
#[cfg(all(windows, feature = "chat"))]
const ATTRIBUTION: &str = include_str!("chrome/attribution/windows-chat.txt");
#[cfg(all(windows, not(feature = "chat")))]
const ATTRIBUTION: &str = include_str!("chrome/attribution/windows.txt");
#[cfg(all(not(windows), feature = "chat"))]
const ATTRIBUTION: &str = include_str!("chrome/attribution/linux-chat.txt");
#[cfg(all(not(windows), not(feature = "chat")))]
const ATTRIBUTION: &str = include_str!("chrome/attribution/linux.txt");

/// The artifact name. `PATANYX` or `PATANYX-Premium` and nothing else -- not
/// the version, not the platform, not the architecture. See
/// docs/update-channel.md. (The private build was renamed from PATANYX-chat
/// on 2026-08-05, deliberate: chat is one premium feature, not the
/// whole of them. The attribution FILES keep their `-chat` suffix because
/// they are keyed to the cargo feature's name, which is frozen.)
pub const fn product_name() -> &'static str {
    if cfg!(feature = "chat") {
        "PATANYX-Premium"
    } else {
        "PATANYX"
    }
}

/// The engine this build renders pages with. A compile-time fact, so it cannot
/// disagree with what is actually linked.
const fn engine_name() -> &'static str {
    if cfg!(windows) {
        "Microsoft Edge WebView2"
    } else {
        "WebKitGTK"
    }
}

/// What the browser is, in the words someone would use to decide whether they
/// want it.
///
/// STRUCTURED RATHER THAN PROSE, and structured rather than markdown. A
/// feature list reads better as a list, and the chrome cannot be handed
/// markdown to interpret: `innerHTML` is banned in the webview that holds the
/// vault, so any formatting the panel understands would have to be parsed and
/// turned into elements by hand. Sending the shape directly means the renderer
/// only ever calls `createElement` and sets `textContent`.
///
/// THIS COPY TRACKS THE PUBLISHED PAGE AT patanyx.edgexene.io/about/, WHICH IS
/// THE REVIEWED SOURCE. Two surfaces describing one product will drift, and
/// when they do the one nobody diffed becomes the wrong one. The site's claims
/// have been through review and, for the DNS line, through an actual packet
/// capture; re-deriving them here from first principles is how the in-app panel
/// would end up quietly contradicting the marketing.
///
/// The DNS wording earned its shape the hard way. The in-app DNS panel opens by
/// saying encrypted DNS "does NOT hide your browsing from your network provider
/// ... and no browser can prevent that", and further down the SAME panel says
/// the browser encrypts the site name inside the connection and that the
/// encrypted resolvers are what stop a network stripping it. Both cannot be
/// true. The published page settles it: the name IS hidden on Windows,
/// "measured, not assumed, though only where a site supports it". That
/// qualifier is load-bearing and travels with the claim wherever it goes.
///
/// The other lines are checked against code the same way: blocking counts only
/// where the request filter actually installed, encrypted DNS is Windows-only
/// because WebKitGTK has no support for it, and the engine disclosure says
/// "reports", not "might report", because that reporting cannot be switched off
/// by anything embedding it.
const INTRO: &str = "A desktop browser that shows you what websites are doing behind your \
back, and lets you stop it. The privacy is built in, not buried in settings \
you have to go looking for.";

/// (lead-in, body). The lead-in is emphasised; the body is a plain sentence.
///
/// FEATURES LEAD. An earlier pass put a qualifier inside every bullet and the
/// result read like a disclaimer rather than a description -- each capability
/// introduced and immediately undercut. The limits are real and they are still
/// here, gathered into the honesty section at the end where a reader meets
/// them once, deliberately, instead of tripping over them four times.
///
/// What that does NOT license is a claim the code cannot support. Each line
/// below says what the browser STOPS, which is checkable, rather than
/// promising an outcome like "you are anonymous", which is not.
/// (lead, when, body). `when` is the published page's own three-way tag, and
/// it is the most useful word on each row: it answers "do I have to do
/// anything" before the description has to.
type Feature = (&'static str, &'static str, &'static str);

// `Automatic`, not `Opt-in`. TabPolicy::default() sets block_ads: true
// (platform/privacy.rs), flipped by the project owner 2026-07-31; this tag was left
// behind and still described the old default. On the published page `Opt-in`
// means "off until you switch it on", so the tag was not merely stale, it was
// inverted -- it told a reader they had to go and enable the one protection
// that is already running. The body sentence carried the same implication and
// is reworded with it: the switch turns blocking OFF now, not on.
const F_ADS: Feature = (
    "Ad and tracker blocking",
    "Automatic",
    "Ads and trackers are blocked from the first time you open \
     PATANYX, and one switch turns it off. A blocked request never leaves \
     your computer, so nobody has a record of it.",
);
// The phishing count is NOT written here. The published page says 390,628,
// which was true when it was written; a number typed into a string is a claim
// with an expiry date on it. This body is completed at runtime from
// `blocklist::len()`, so the figure is whatever this binary actually carries.
const F_MALICIOUS: Feature = (
    "Scam sites refused",
    "Automatic",
    "PATANYX will not open a known phishing site, whatever your other \
     settings say. The list updates every hour, and you can open a blocked \
     site anyway if you think it is wrong.",
);
const F_LEDGER: Feature = (
    "See who a page talks to",
    "Automatic",
    "Open one panel to see every other company the page just contacted, and \
     how many requests were allowed or stopped. Most pages talk to more of \
     them than you would guess.",
);
const F_FREEZE: Feature = (
    "Freeze a tab",
    "On demand",
    "One click and the tab stops sending anything until you let it go \
     again. Handy when a page will not stop chattering in the background.",
);
// Windows only, and the tag says so, because WebKitGTK has no encrypted-DNS
// support of any kind -- the resolver control is hidden outright on Linux
// rather than shown and inert.
//
// "Measured, not assumed" is the project owner's packet capture, and it is why this
// says the name is hidden rather than hedging about it. The site-support
// qualifier stays: the key that makes it work is published by the SITE, so a
// site that has not set it up gets no cover from it.
const F_DNS: Feature = (
    "Pick who sees your lookups",
    "Opt-in, Windows",
    "Every site you visit starts with a lookup that normally goes \
     unencrypted to whoever runs your network. Switch it to Mullvad or Quad9 \
     and it is encrypted instead, so your provider never gets a readable list \
     of the sites you visit. On Windows the site name is hidden inside the \
     connection too, measured rather than assumed, wherever the site supports \
     it.",
);
const F_QUARANTINE: Feature = (
    "Quarantine tab",
    "On demand",
    "One click gives you a tab with blocking on, scripts off, nothing saved \
     and the freeze ready, for a link you do not trust.",
);
const F_VAULT: Feature = (
    "A vault for passwords",
    "On demand",
    "Your passwords and private notes live in one encrypted file that never \
     leaves your computer. Nothing is filled in automatically, and a secret \
     is shown only when you ask for it. You get a recovery key when you set \
     the vault up, shown once, and it is the only way in if you forget your \
     passphrase. Lost it? The Backup tab makes you a new one. The vault locks \
     itself after five minutes of nothing happening. Typing anywhere counts, \
     so it will not lock while you are working, and you get a countdown and \
     an \"I'm still here\" button a minute before. Five minutes can be 15, 30 \
     or 60, or off.",
);
const F_TUNNEL: Feature = (
    "A tunnel you supply the far end of",
    // FREE (decided 2026-08-05): the tunnel costs EdgeXene
    // nothing to provide -- the user supplies the far end -- so it does not
    // belong behind the paid tier. It was tagged "future Premium" before
    // that decision.
    "Off by default; free",
    "WireGuard is built in. Import the configuration file from your own \
     server or your provider, and PATANYX sends only this browser's traffic \
     through it, not your other apps and not the rest of the computer. Your \
     key is kept in the encrypted vault, so with the tunnel on, PATANYX opens \
     at the unlock prompt. If the tunnel goes down, pages stop loading. \
     PATANYX will not fall back to a direct connection, because a silent \
     fallback looks exactly like a working tunnel. You picked the server at \
     the far end, and it sees your traffic, so this is not an anonymity \
     feature. Switching it on or off takes effect the next time you start \
     the browser.",
);
const F_OCR: Feature = (
    "Check a photo before you send it",
    "On demand; future Premium",
    "Point it at an image and it reads the text inside, flagging e-mail \
     addresses, card numbers and keys you may not have noticed. It runs on your \
     machine and sends the picture nowhere.",
);
const F_INTEGRITY: Feature = (
    "Catch a page that changed",
    "On demand",
    "Save a page and PATANYX tells you later whether the site quietly changed \
     it.",
);
/// Wired to the photo check, so this describes something the binary does.
///
/// It rides the existing leak scan rather than adding a second button: the
/// colour of every recognised line is measured while the decoded page is still
/// in hand, and a line too close to its background comes back as one more
/// finding in the list the scan already shows. There is nothing new for anyone
/// to find in the UI, which is the point.
///
/// It is tagged future Premium from its first appearance deliberately. A
/// feature that ships free and is gated later breaks the promise in `PREMIUM`
/// below that free features always remain free; one that was never free does
/// not. That makes this tag a one-way door, which is a deliberate choice and
/// was made explicitly.
const F_HIDDEN_TEXT: Feature = (
    "Find writing that was hidden from you",
    "On demand; future Premium",
    "Text can be hidden in a picture by colouring it to match the background: \
     white on white, or a grey a shade off the paper. Sometimes that is \
     careless, and sometimes someone did not want it read. When you check a \
     photo, PATANYX finds text that is too faint to see and shows you what it \
     says. Like the rest of the photo check, this happens on your machine.",
);

fn features() -> Vec<Feature> {
    let mut out = vec![F_ADS, F_MALICIOUS, F_LEDGER, F_FREEZE];
    if cfg!(windows) {
        out.push(F_DNS);
    }
    out.extend([
        F_QUARANTINE,
        F_VAULT,
        F_TUNNEL,
        F_OCR,
        F_INTEGRITY,
        F_HIDDEN_TEXT,
    ]);
    out
}

/// The other half, and it keeps the published page's framing: a protection you
/// misunderstand is worse than one you know you do not have. Gathered in one
/// place rather than sprinkled through the features above, where an earlier
/// draft put them and made every capability read like a disclaimer.
const LIMITS_HEAD: &str = "What it cannot hide";

const LIMITS_INTRO: &str = "Privacy tools are usually sold on what they stop. Here is the \
other half.";

const LIMITS: &[(&str, &str)] = &[
    (
        "It cannot hide that you connected to something",
        "Every request has to go somewhere, and that address is the one thing \
         encryption cannot cover. Whoever carries your traffic still sees \
         which addresses you reached, when, and roughly how much data moved.",
    ),
    (
        "It is not an anonymity tool",
        "There is no onion routing, and no defence against someone watching \
         traffic patterns. The built-in tunnel moves what your local network \
         sees to a server you picked. It changes who can watch, not whether \
         anyone can. If you need nobody in the path to know you reached a \
         particular server, you want Tor.",
    ),
    (
        "The tunnel carries this browser, not your machine",
        "Every other app on your computer keeps its normal connection. The \
         server at the far end sees the traffic your local network no longer \
         does, and reaching that server is the one connection that stays \
         outside the tunnel.",
    ),
    (
        "Anti-fingerprinting is noise, not invisibility",
        "PATANYX adds small site-specific noise to the canvas, audio, and \
         graphics readouts fingerprinting scripts lean on hardest, so the \
         reading that identifies you on one site does not match the one \
         another site sees. Screen size, fonts, and plenty of other details \
         still read out exactly as they are, and code running in a worker is \
         not covered. PATANYX does not try to make you look like everyone \
         else; it tries to keep one site's picture of you from matching \
         another's.",
    ),
];

const HONESTY: &str = "PATANYX will not lie to you about your safety. If you turn a \
protection on and the engine refuses it, PATANYX tells you it was refused \
instead of showing you a tick you did not earn.";

const PREMIUM_HEAD: &str = "Free and Premium";

/// Future tense THROUGHOUT, on purpose: nothing is for sale today, and a
/// page that reads as if it were would be the exact dishonesty the rest of
/// this file exists to prevent. The one absolute sentence -- "Free features
/// always remain free." -- is the project owner's standing commitment, worded by
/// the project owner, and the test below pins it so a rewrite cannot soften it
/// into marketing. When Premium actually launches, this paragraph changes
/// to present tense IN THE SAME COMMIT as the licensing ships, never before.
const PREMIUM: &str = "PATANYX will offer a paid Premium tier. Fingerprint Divergence, private chat between PATANYX users, checking a page together with a contact, reading the text in a photo, and accent theme packs will be part of it. Nothing is behind a paywall today: Fingerprint Divergence, theme packs and the photo check are switched on for everyone in this build, and stay that way until Premium launches. Private chat and checking a page with a contact are not in this build at all -- they are compiled into a separate PATANYX-Premium build, which is also a free download. The built-in tunnel is free, and so is light and dark following your system setting. Every other protection on this page is free. Free features always remain free. Nothing is for sale yet; when Premium launches, this page will say so plainly.";

const DISCLOSURE_HEAD: &str = "What it is built from";

/// The engine caveat, in the published page's own words. "Reports a minimum of
/// component health data that no application is allowed to switch off" is the
/// accurate form: not "might send", not "a little data" -- it is required, and
/// PATANYX cannot turn it off no matter what it does.
/// THE RESOLVER PROBE IS NAMED HERE, and the published page currently does not
/// name it. That page says the only self-initiated network activity is the
/// update and blocklist checks. There is a third: `resolver_probe` sends an
/// HTTPS request to Mullvad or Quad9 to find out whether the resolver is still
/// reachable, triggered by a failed navigation rather than by the user.
///
/// It is gated -- `configured_template()` returns `None` on System DNS, so a
/// default install never does it -- and it discloses nothing new, since it
/// contacts the resolver that already sees every lookup. But the sentence says
/// "only", and someone who runs a packet capture the way this product invites
/// them to would find a third destination and be right to say the page was
/// wrong. Naming it costs one clause.
const DISCLOSURE: &str = "One Rust program, with nothing downloaded at runtime. PATANYX itself \
collects nothing about you. The only things it reaches out for on its own are \
an anonymous, signed update check and blocklist refreshes, plus an occasional \
check that the resolver is still reachable if you have chosen an encrypted \
one. Web pages are drawn by software your computer already has and updates \
itself. One caveat: on Windows, Microsoft's WebView2 engine reports a minimum \
of component health data that no application is allowed to switch off.";

fn pairs(list: &[(&str, &str)]) -> Vec<Value> {
    list.iter()
        .map(|(lead, body)| json!({ "lead": lead, "body": body }))
        .collect()
}

/// The phishing count, read off the list this binary actually carries.
///
/// Written nowhere as a literal. The published page quotes 390,628, which was
/// true the day it was written and drifts every time the list is refreshed --
/// and an over-stated protection figure is the kind of inaccuracy that gets
/// noticed by exactly the people this product is for.
fn malicious_body() -> String {
    // TWO WORDINGS CORRECTED HERE, both for the same reason -- claiming more
    // than the thing does.
    //
    // "reported as" rather than "knowing": the list is built from two public
    // sources, one community-collected and one automated, and neither
    // establishes a verified fact about whoever runs a listed site. The
    // blocked banner was reworded to match.
    //
    // "checks about once an hour" rather than "updates itself hourly": the
    // browser looks for a newer SIGNED list roughly hourly, but the list only
    // changes when a new one is published and signed offline. The old wording
    // promised a freshness the signing step cannot deliver.
    format!(
        "It ships with {} sites reported as phishing and will not open them, \
         whatever your other settings say. It checks about once an hour for a \
         newer list, and you can override any block you disagree with.",
        grouped(crate::blocklist::len())
    )
}

/// Digits grouped in threes: 390628 -> "390,628".
///
/// Rust's `{}` does not group, and six ungrouped digits in a sentence read as a
/// serial number rather than a quantity -- which loses the one thing the figure
/// is there to convey, that the list is large.
fn grouped(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Features as JSON, with the one runtime-completed body substituted in.
fn feature_json() -> Vec<Value> {
    features()
        .into_iter()
        .map(|(lead, when, body)| {
            let body = if lead == F_MALICIOUS.0 {
                malicious_body()
            } else {
                body.to_string()
            };
            json!({ "lead": lead, "when": when, "body": body })
        })
        .collect()
}

/// Everything the description is made of, as one string. Only for the tests
/// below, which scan the whole of it for claims that must not appear -- a
/// banned phrase is just as false in a bullet as in a paragraph, and splitting
/// the copy into pieces must not create somewhere for one to hide.
#[cfg(test)]
fn all_copy() -> String {
    let mut out = String::from(INTRO);
    for (lead, when, body) in features() {
        out.push(' ');
        out.push_str(lead);
        out.push(' ');
        out.push_str(when);
        out.push(' ');
        out.push_str(body);
    }
    for (lead, body) in LIMITS {
        out.push(' ');
        out.push_str(lead);
        out.push(' ');
        out.push_str(body);
    }
    out.push(' ');
    out.push_str(LIMITS_INTRO);
    out.push(' ');
    out.push_str(HONESTY);
    out.push(' ');
    out.push_str(PREMIUM);
    out.push(' ');
    out.push_str(DISCLOSURE);
    out
}

/// Identity, terms and notices. Small enough to send eagerly.
pub fn ipc_info() -> Result<Value, &'static str> {
    Ok(json!({
        "name": product_name(),
        "version": env!("CARGO_PKG_VERSION"),
        "intro": INTRO,
        "features_head": "What it does that others don't",
        "features": feature_json(),
        "honesty": HONESTY,
        "limits_head": LIMITS_HEAD,
        "limits_intro": LIMITS_INTRO,
        "limits": pairs(LIMITS),
        "premium_head": PREMIUM_HEAD,
        "premium": PREMIUM,
        "disclosure_head": DISCLOSURE_HEAD,
        "disclosure": DISCLOSURE,
        "engine": engine_name(),
        "license_spdx": "Apache-2.0",
        "license_text": LICENSE,
        "notice_text": NOTICE,
        // So the panel can offer "N third-party packages" without pulling the
        // whole inventory across the boundary to count it.
        "package_count": package_count(),
    }))
}

/// The full third-party inventory. Roughly 300 KB, so it is a SEPARATE command
/// rather than a field on `ipc_info`: it crosses the boundary only when
/// somebody actually opens the third-party section, not every time the About
/// panel is shown.
pub fn ipc_attribution() -> Result<Value, &'static str> {
    Ok(json!({ "text": ATTRIBUTION }))
}

/// Read off the generated header rather than recounted here, so this number
/// cannot drift from the list it describes.
fn package_count() -> u32 {
    for line in ATTRIBUTION.lines() {
        if let Some(rest) = line.strip_suffix(" third-party packages.") {
            if let Ok(n) = rest.trim().parse::<u32>() {
                return n;
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribution_is_compiled_in_and_describes_itself() {
        assert!(
            ATTRIBUTION.len() > 10_000,
            "the attribution file is implausibly small; it is probably a stub"
        );
        assert!(
            package_count() > 50,
            "package count parsed as {}, which means the generated header \
             changed shape and the panel would show a wrong number",
            package_count()
        );
    }

    #[test]
    fn attribution_matches_this_build() {
        // The header names the configuration it was generated for. A build that
        // picked up the wrong file via a cfg mistake would still work, still
        // render, and quietly attribute the wrong set of software -- which is
        // the failure this whole module is arranged to prevent, so it is worth
        // one assertion.
        let head = ATTRIBUTION.lines().next().unwrap_or_default();
        assert!(
            head.contains(product_name()),
            "attribution header {head:?} does not name {}",
            product_name()
        );
        let want_os = if cfg!(windows) { "Windows" } else { "Linux" };
        assert!(
            head.contains(want_os),
            "attribution header {head:?} is not the {want_os} inventory"
        );
    }

    #[test]
    fn licence_and_notice_travel_with_the_binary() {
        assert!(LICENSE.contains("Apache License"));
        assert!(LICENSE.contains("Version 2.0"));
        assert!(NOTICE.contains("EdgeXene"));
        // The bundled data has to be acknowledged wherever the binary goes; it
        // is the one attribution that a repository file alone does not satisfy.
        assert!(NOTICE.contains("Phishing.Database"));
        // Same rule, second dataset. The PSL is MPL-2.0 and is compiled into
        // the binary, so the acknowledgement has to travel with it -- and the
        // generated attribution CANNOT catch this: that inventory is built
        // from cargo metadata, and bundled DATA is invisible to it. This
        // assertion is the only thing standing between a licence obligation
        // and a file nobody remembers to edit.
        assert!(NOTICE.contains("Public Suffix List"));
        assert!(NOTICE.contains("Mozilla Public License 2.0"));
    }

    #[test]
    fn premium_copy_sells_nothing_and_keeps_the_free_promise() {
        // Two invariants, both load-bearing until launch. FIRST: nothing on
        // this page may read as purchasable today -- the tier does not exist
        // yet, and copy that invites payment for it would be a false offer.
        let lowered = all_copy().to_lowercase();
        for banned in ["buy now", "subscribe now", "purchase", "per month", "/month"] {
            assert!(
                !lowered.contains(banned),
                "premium copy reads as purchasable today: {banned:?}"
            );
        }
        // The future-tense marker: remove it only in the commit that
        // actually ships purchasable licensing.
        assert!(
            lowered.contains("nothing is for sale yet"),
            "the premium section must say nothing is for sale until it is"
        );
        // SECOND: the project owner's standing commitment, exact and brittle on
        // purpose -- a rewrite must look this sentence in the eye.
        assert!(
            lowered.contains("free features always remain free"),
            "the free-forever commitment must stay verbatim"
        );
    }

    #[test]
    fn description_makes_no_absolute_privacy_claim() {
        // Guards a standing rule rather than a preference. The engine reports
        // data no embedder can disable, so any sentence promising total
        // silence would be false. Cheap to assert, and the assertion is the
        // reason the sentence cannot be "tightened" into a lie later.
        // A substring ban cannot tell a claim from its DENIAL, and this text
        // contains the denial: "does not claim that nothing leaves your
        // machine". Banning that phrase failed the honest sentence for saying
        // the honest thing. So the list holds only phrases with no innocent
        // reading, and the positive assertion below does the real work -- it
        // requires the admission to be present, which no rewording can satisfy
        // accidentally.
        let lowered = all_copy().to_lowercase();
        for banned in [
            "sends nothing",
            "no telemetry",
            "zero telemetry",
            "completely private",
            "totally private",
            "cannot be tracked",
            // Superlatives about protection. "Maximum security" was proposed
            // for the quarantine bullet; it is a preset of four controls, and
            // naming it the maximum invites someone to stop looking.
            "maximum security",
            "completely secure",
            "fully anonymous",
        ] {
            assert!(
                !lowered.contains(banned),
                "description contains an absolute privacy claim: {banned:?}"
            );
        }
        // An EXACT phrase, and brittle on purpose. Reword the description and
        // this test fails, which forces the rewrite to look at the admission
        // and decide about it deliberately. That is the whole job: the
        // sentence must never disappear as a side effect of someone tightening
        // the prose. Update this string when the copy changes; do not relax it
        // into something a paragraph could satisfy by accident.
        assert!(
            lowered.contains("no application is allowed to switch off"),
            "the description must keep the sentence admitting the engine reports \
             data this browser cannot turn off"
        );
        // The third network destination, which the published page omits. An
        // edit that trims this clause turns a true sentence back into the false
        // "only" it replaced, and the failure would be invisible on screen.
        assert!(
            lowered.contains("check that the resolver is still reachable"),
            "the disclosure must name the resolver reachability probe. \
             resolver_probe.rs sends an HTTPS request to the chosen resolver on \
             a failed navigation, so 'the only network activity is updates and \
             blocklist refreshes' is not true once encrypted DNS is on."
        );
    }

    #[test]
    fn the_tunnel_claim_stays_scoped_and_fail_closed() {
        // The tunnel is the easiest feature on this page to oversell: "VPN"
        // reads as machine-wide and as anonymity, and it is neither. Exact
        // phrases, brittle on purpose like the admissions above: reword the
        // copy and this fails, which forces the rewrite to look at each
        // scoping clause and decide about it deliberately.
        let lowered = all_copy().to_lowercase();
        assert!(
            lowered.contains("only this browser's traffic"),
            "the tunnel copy must scope itself to this browser's traffic"
        );
        assert!(
            lowered.contains("will not fall back to a direct connection"),
            "the tunnel copy must state fail-closed: no silent direct fallback"
        );
        assert!(
            lowered.contains("it sees your traffic"),
            "the tunnel copy must say the chosen exit sees the traffic"
        );
        assert!(
            lowered.contains("not an anonymity feature"),
            "the tunnel feature must disclaim anonymity in its own body, not \
             only in the limits section"
        );
        assert!(
            lowered.contains("changes who can watch, not whether anyone can"),
            "the limits section must keep the who-not-whether sentence: it is \
             the one line that stops the tunnel reading as invisibility"
        );
    }

    /// The missing half of `a_build_only_advertises_what_it_can_do`.
    ///
    /// That test's name promises this and does not deliver it: it checks the
    /// PLATFORM filter, so a feature added to `features()` that the binary
    /// cannot actually do sails straight past it. Nothing else on this page
    /// stops an unfinished entry from reading like a shipped one.
    ///
    /// The rule is one line: if the tag says a feature is unfinished, the body
    /// has to admit it too. A tag is a chip most readers skim over; the body is
    /// what they actually read, and the two must not be allowed to drift apart.
    ///
    /// Brittle on purpose, like the claims above. When hidden-text detection is
    /// wired to the scan, its tag and its body change together in that commit
    /// and this test's second half goes with them -- which is the point, because
    /// that edit is precisely the moment someone should have to stop and decide
    /// whether the claim has become true.
    #[test]
    fn an_unfinished_feature_admits_it_in_the_tag_and_in_the_body() {
        for (lead, tag, body) in features() {
            if !tag.to_lowercase().contains("in progress") {
                continue;
            }
            assert!(
                body.to_lowercase().contains("not finished yet"),
                "{lead:?} is tagged in progress, so its body must say so as \
                 well -- a reader who skims tags would otherwise be told the \
                 browser already does this"
            );
        }

        // Hidden-text detection was wired to the leak scan in the same change
        // that flipped its tag, so the "In progress" assertion that used to sit
        // here is gone rather than left passing vacuously. What survives is the
        // half that is still load-bearing.
        assert!(
            F_HIDDEN_TEXT.1.contains("future Premium"),
            "it is tagged future Premium from first appearance on purpose: a \
             feature that ships free and is gated later breaks the free-stays-\
             free promise, one that was never free does not"
        );
        assert!(
            !F_HIDDEN_TEXT.2.contains("will measure"),
            "the body must describe what the browser does, not what it intends \
             to do -- this entry is wired now"
        );
    }

    #[test]
    fn the_dns_claim_keeps_the_qualifiers_it_was_measured_with() {
        // The strongest claim on this page, and the one with a real evidence
        // trail: an encrypted resolver stops the network reading your lookups,
        // and it stops a network stripping the key that keeps the site name
        // encrypted inside the connection. A packet capture of a browsing
        // session backs it -- what stayed visible was a list of CDN addresses,
        // not the sites.
        //
        // Two words carry that claim and neither may be dropped by a later
        // edit. "Measured" is why it is stated instead of hedged. "Wherever the
        // site supports it" is the boundary: the key is published by the SITE,
        // so a site that never set it up gets no cover from this and PATANYX
        // has no readback telling you which you got.
        let dns = F_DNS.2.to_lowercase();
        assert!(
            dns.contains("measured rather than assumed"),
            "the site-name claim must keep saying it was measured; it is stated \
             plainly BECAUSE there is a capture behind it, and unmarked it reads \
             like the assumption this product refuses to make"
        );
        assert!(
            dns.contains("wherever the site supports it"),
            "the site-name protection must stay bounded to sites that publish \
             the key. Unqualified it promises cover on every connection, which \
             is not what was measured and not what the engine does."
        );
        assert!(
            F_DNS.1.contains("Windows"),
            "the DNS feature must be tagged Windows: WebKitGTK has no encrypted \
             DNS at all, which is why the control is hidden outright on Linux"
        );
    }

    #[test]
    fn a_build_only_advertises_what_it_can_do() {
        // features() is filtered by platform, so this is the assertion that the
        // filter is actually load-bearing rather than decorative.
        let leads: Vec<&str> = features().iter().map(|(lead, _, _)| *lead).collect();
        if cfg!(windows) {
            assert!(
                leads.contains(&F_DNS.0),
                "the Windows build must advertise encrypted DNS"
            );
        } else {
            assert!(
                !leads.contains(&F_DNS.0),
                "a non-Windows build must NOT advertise encrypted DNS -- \
                 WebKitGTK cannot do it, and a marketing bullet is a claim like \
                 any other"
            );
        }
    }

    #[test]
    fn the_phishing_count_is_read_from_the_list_not_typed_in() {
        // The published page quotes a figure that was true the day it was
        // written. In here it is read off the list this binary carries, so it
        // cannot drift. Asserting the body contains the LIVE number is what
        // stops someone "simplifying" it back into a literal.
        let body = malicious_body();
        assert!(
            body.contains(&grouped(crate::blocklist::len())),
            "the phishing-site count must come from blocklist::len(), not from \
             a number typed into the copy"
        );
    }

    #[test]
    fn thousands_are_grouped() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(7), "7");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(390_628), "390,628");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }
}
