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
// (platform/privacy.rs), flipped 2026-07-31; this tag was left
// behind and still described the old default. On the published page `Opt-in`
// means "off until you switch it on", so the tag was not merely stale, it was
// inverted -- it told a reader they had to go and enable the one protection
// that is already running. The body sentence carried the same implication and
// is reworded with it: the switch turns blocking OFF now, not on.
const F_ADS: Feature = (
    "Ads & Tracker Blocker",
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
    "Reported Host List",
    "Automatic",
    "PATANYX will not open a known phishing site, whatever your other \
     settings say. The list updates every hour, and you can open a blocked \
     site anyway if you think it is wrong.",
);
// Beside the reported-host list on purpose: both are the navigation handler
// holding a page back and asking, and the answer has the same shape (this
// tab, this host, gone when the tab closes). "Warns" is the whole claim: the
// page is still reachable, on the user's say-so, and local addresses typed
// as numbers are not warned about at all. LITERAL ADDRESSES ONLY: the
// exemption is `is_private_host`, which matches numeric loopback, RFC1918,
// link-local and CGNAT plus `localhost`, and NOT a router or printer
// reached by name (fritz.box, printer.local) -- those still get the
// warning, and the copy must not promise otherwise. A compliance audit
// caught the earlier wording ("like a router") saying exactly that.
const F_INSECURE: Feature = (
    "Plain-HTTP Warning",
    "Automatic",
    "A site that is not encrypted is held back with a warning first, since \
     anyone on the path could read or change what you send it. You can \
     continue anyway; that applies to the site in that tab only and ends when \
     you close it. An address on your own network typed as a number, like \
     192.168.1.1, opens without the warning, and so does localhost or any \
     name under it; a device you reach by any other name still gets it.",
);
const F_LEDGER: Feature = (
    "Page Connections",
    "Automatic",
    "Open one panel to see every other company the page just contacted, and \
     how many requests were allowed or stopped. Most pages talk to more of \
     them than you would guess.",
);
const F_FREEZE: Feature = (
    "Tab Freeze",
    "On demand",
    "One click and the tab stops sending anything until you let it go \
     again. Handy when a page will not stop chattering in the background.",
);
// Windows only, and the tag says so, because WebKitGTK has no encrypted-DNS
// support of any kind -- the resolver control is hidden outright on Linux
// rather than shown and inert.
//
// "Measured, not assumed" refers to a packet capture on real hardware; it is why this
// says the name is hidden rather than hedging about it. The site-support
// qualifier stays: the key that makes it work is published by the SITE, so a
// site that has not set it up gets no cover from it.
const F_DNS: Feature = (
    "Encrypted DNS",
    "Opt-in, Windows",
    "Every site you visit starts with a lookup that normally goes \
     unencrypted to whoever runs your network. Switch it to Mullvad or Quad9 \
     and it is encrypted instead, so your provider never gets a readable list \
     of the sites you visit. On Windows the site name is hidden inside the \
     connection too, measured rather than assumed, wherever the site supports \
     it.",
);
// HELD OUT OF 0.9.64, and NOT because the row is badly worded. The behaviour
// it describes does not happen on real Windows. Hardware re-check 2026-08-19,
// reproduced twice, downloading from our own host straight into PATANYX: the
// zone half worked -- Explorer still shows "came from another computer" -- but
// `HostUrl` was STILL ON DISK afterwards, which is the entire point of the
// feature. Worse for a claim, the browser did not notice: the toast said only
// "Saved", because Outcome::Clean is silent and a missing stream reads as
// nothing to remove. So both sentences below were false on hardware, including
// the one promising the browser would say so.
//
// The code is deliberately unchanged (see /root/patanyx-motw-recheck-20260819/
// FINDING.md; leading theory is a race with Windows writing the stream a beat
// after the download-completed handler). Every mainstream browser leaves the
// mark too, so the severity is low and the fix can wait for a release that can
// prove it. What could NOT wait was the About page asserting it.
//
// TO RESTORE: land the fix, re-run the hardware check, then re-add the single
// `out.push(F_DOWNLOAD_MARK)` in the cfg!(windows) block below. Do not restore
// it because the tests pass -- the tests passed the day this was written, and
// rewrite()'s 8 tests never saw the input that failed.
#[allow(dead_code)]
const F_DOWNLOAD_MARK: Feature = (
    "Download Address Removed",
    "Automatic",
    "Windows marks each downloaded file with the address it came from, \
     written on your disk next to the file where any program can read it. \
     PATANYX removes the address and keeps the mark itself, so Windows still \
     warns you that the file came from another computer. If the address \
     cannot be removed, the browser says so.",
);
const F_QUARANTINE: Feature = (
    "Strict Tab",
    "On demand",
    "One click gives you a tab with blocking on, scripts off, nothing saved \
     and the freeze ready, for a link you do not trust.",
);
const F_VAULT: Feature = (
    "PATANYX Vault",
    // NOT "On demand" any more, and the tag had to move with the behaviour:
    // the legend defines that as a tool you reach for, and since the vault
    // started opening itself at launch it reaches for you. Same tag-inversion
    // the ad-blocking entry above was already caught by once.
    "Automatic",
    "Your passwords and private notes live in one encrypted file that never \
     leaves your computer. Nothing is filled in automatically, and a secret \
     is shown only when you ask for it. PATANYX offers the vault when you \
     open it, because your bookmarks and download records unlock with it too. \
     It does not when another app hands PATANYX a link, and it never takes \
     the keyboard, so you can just type an address instead. You get a \
     recovery key when you set \
     the vault up, shown once, and it is the only way in if you forget your \
     passphrase. Keep it safe: a lost recovery key cannot be reissued. \
     If your vault has no recovery key at all, the Backup tab makes you one. The vault locks \
     itself after five minutes of nothing happening. Typing anywhere counts, \
     so it will not lock while you are working, and you get a countdown and \
     an \"I'm still here\" button a minute before. Five minutes can be 15, 30 \
     or 60, or off.",
);
// Bookmarks are table stakes and the do-not-list rule would normally keep
// them off this page. This entry earns its place on ONE thing a browser's
// bookmarks usually are not -- encrypted at rest, opened with the vault --
// plus the one control people actually want from a manager, which is the
// pinned row.
//
// Deliberately two sentences. An earlier draft also covered folders, the
// absence of icon fetching and the page-change check; all true, and all cut,
// because a feature list entry that runs five sentences stops being read.
// Say plainly what happened to them: folders are visible in the manager, but
// the other two are CUT, not relocated -- nothing in the UI tells a user that
// no icon is ever fetched or that a bookmark can notice its page changed.
// Worth stating so this comment cannot be read as licence for the next cut.
//
// Both claims are checkable against code: the store is encrypted
// (crates/store), and Quick Access is a flag read outside the search and
// folder filters, which is what makes "whatever you search for" true.
const F_BOOKMARKS: Feature = (
    "Bookmark Manager",
    "On demand",
    "Your bookmarks are encrypted on your computer and open with the vault, \
     so a saved page is not a list anyone can read off your disk. Pin the \
     ones you use most to Quick Access and they stay at the top, whatever \
     you search for. You can also empty the whole manager in one go, which \
     asks first and cannot be undone.",
);
const F_TUNNEL: Feature = (
    "Private Tunnel",
    // FREE (decided 2026-08-05): the tunnel costs EdgeXene
    // nothing to provide -- the user supplies the far end -- so it does not
    // belong behind the paid tier. It was tagged "future Premium" before
    // that decision.
    "Off by default; free",
    "WireGuard is built in. Import the configuration file from your own \
     server or your provider, and PATANYX sends only this browser's traffic \
     through it, not your other apps and not the rest of the computer. Your \
     key is kept in the encrypted vault. If the tunnel goes down, pages stop \
     loading. \
     PATANYX will not fall back to a direct connection, because a silent \
     fallback looks exactly like a working tunnel. You picked the server at \
     the far end, and it sees your traffic, so this is not an anonymity \
     feature. Switching it on or off takes effect the next time you start \
     the browser, and the panel can do that restart for you: it reopens the \
     tabs you had once you unlock the vault. Because the configuration lives \
     in the vault, a tunnel switched on with the vault locked stops pages \
     loading until you unlock it.",
);
const F_OCR: Feature = (
    "Image Text Review",
    "On demand; future Premium",
    "Point it at an image and it reads the text inside, then looks for seven \
     things worth catching before you share it: an e-mail address, a card \
     number, a long number, an API key or token, a private key header, an IP \
     address, and text too faint for a person to see. It shows you what it \
     read as well as what it matched, so its answer can be checked rather \
     than taken on trust. It runs on your machine and sends the picture \
     nowhere.",
);
const F_INTEGRITY: Feature = (
    "Page Snapshot",
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
    "Text Capture",
    "On demand; future Premium",
    "Text can be hidden in a picture by coloring it to match the background: \
     white on white, or a gray a shade off the paper. Sometimes that is \
     careless, and sometimes someone did not want it read. When you check a \
     photo, PATANYX finds text that is too faint to see and shows you what it \
     says. Like the rest of the photo check, this happens on your machine.",
);

/// The personal archive. Premium-gated from its first appearance, same
/// one-way reasoning as `F_HIDDEN_TEXT` above, and genuinely enforced rather
/// than merely intended: `archive_save` and `archive_search` both call
/// `cross_tab_gate(premium_active())` before touching the store.
///
/// THE FIRST SENTENCE IS THE HONESTY GUARD, not decoration. A personal
/// archive in a privacy browser is only defensible because the user fills it
/// deliberately, and "History remembers where you went. Deep Recall remembers
/// what you chose to keep." says that in the same breath as the pitch. Keep it
/// first. Nothing here may imply PATANYX records browsing on its own, and the
/// archive is bounded to a few hundred records, so nothing may imply an
/// unlimited history either.
const F_ARCHIVE: Feature = (
    "Deep Recall",
    "On demand; future Premium",
    "History remembers where you went. Deep Recall remembers what you chose \
     to keep. Save a page and PATANYX stores a private snapshot alongside the \
     text its on-device reader finds inside it, so months later you can type a \
     word you remember and get the page back, even if that word only appeared \
     inside an image. The picture covers the WHOLE page rather than the part \
     that happened to be on screen, and you can open it again and zoom in on \
     it. On a Windows engine too old to render past the visible area the \
     picture is only what was on screen, and the message when you save says \
     so rather than leaving you to assume otherwise. It holds only the pages \
     you chose to save, in one encrypted file on your machine that opens \
     with your vault. Nothing is uploaded.",
);

/// Comparing a downloaded file with a contact. Premium-gated from its first
/// appearance, same one-way reasoning as `F_HIDDEN_TEXT`, and it only exists
/// in the chat build, so `features()` adds it under the same cfg the chat
/// feature itself rides.
///
/// THE INNOCENT EXPLANATIONS ARE PART OF THE FEATURE, not a hedge appended to
/// it. A hash that differs is evidence, and the honest reading of that
/// evidence includes a publisher reissuing a file and a content network
/// serving a regional build. Copy that let a user walk away believing they had
/// caught an attack, when the ordinary cause is far likelier, would be selling
/// alarm. Keep the "look closer, not a verdict" sentence and keep it near the
/// claim, not at the end.
const F_DOWNLOAD_COMPARE: Feature = (
    "Copy Compare",
    "On demand; future Premium",
    "Download an installer and a contact who took the same file from the same \
     address can tell you whether their copy comes out to the same hash as \
     yours. The case this is built for is the targeted swap: the file everyone \
     else receives is clean, and the one served to you is not. A difference is \
     a reason to look closer, not a verdict. Publishers reissue files and \
     content networks serve regional builds, so compare version numbers and \
     publisher signatures before you conclude anything.",
);

/// Asking a contact whether a page changed for them too. Chat build only,
/// Premium-gated, same reasoning as `F_DOWNLOAD_COMPARE` above.
///
/// THE FIRST TWO SENTENCES ARE THE HONESTY GUARD. Page Snapshot on its own
/// cannot distinguish a site editing a page for everyone from a site editing
/// it for one reader, and that limit is exactly what this feature addresses.
/// Stating the limit before the capability is what keeps the capability from
/// reading like a claim the snapshot alone could already make.
const F_CHANGE_COMPARE: Feature = (
    "Change Cross-Check",
    "On demand; future Premium",
    "PATANYX can tell you a saved page changed since you last looked at it. It \
     cannot tell you on its own whether it changed for everyone or only for \
     you. Ask a contact with the same page open and you get the other half: \
     whether their copy matches yours now, whether the two of you started from \
     the same page, and whether theirs changed as well. The comparison goes to \
     the one contact you asked and nowhere else.",
);

/// Turning Fingerprint Divergence off for named sites.
///
/// TWO LIMITS BELONG IN THE COPY AND ARE LOAD-BEARING. A choice made here
/// reaches the NEXT tab for that site, because neither engine can re-register
/// scripts on a view that is already open; and the proof line reports what a
/// tab was given, which is registration and not a measurement that any site
/// was fooled. The in-app panel is gated on both by
/// scripts/divergence-site-gate.js. This entry may not imply either one away.
///
/// Note the split: the per-site CHOICE asks for a licence from day one,
/// while Fingerprint Divergence itself is a Premium SEED -- switched on for
/// everyone until launch and gated from then on (design preamble
/// 2026-08-06, reaffirmed 2026-08-16 after a 2026-08-14 About rewrite had
/// briefly called it "stays free"). Its own entry so the two are not read
/// as one thing.
const F_DIVERGENCE_SITES: Feature = (
    "Divergence Exceptions",
    // FREE PERMANENTLY, 2026-08-19. It was "On demand; future Premium" and
    // the three IPC arms genuinely refused without a licence; both went with
    // the decision that Fingerprint Divergence is free, exceptions included.
    "On demand",
    "Fingerprint Divergence adds noise for every site, and a few sites break \
     under it. Turn it off for just those, named one full hostname at a time, \
     and leave it on everywhere else. The panel also reports what the tab in \
     front of you actually received, which is worth knowing because a tab \
     keeps whatever it started with: a change here reaches the next tab you \
     open for that site.",
);

fn features() -> Vec<Feature> {
    let mut out = vec![F_ADS, F_MALICIOUS, F_INSECURE, F_LEDGER, F_FREEZE];
    if cfg!(windows) {
        out.push(F_DNS);
        // out.push(F_DOWNLOAD_MARK) -- held; see the const above.
    }
    out.extend([
        F_QUARANTINE,
        F_VAULT,
        // Beside the vault deliberately: bookmarks are encrypted in the same
        // custody model and unlock with it, so the two belong together
        // rather than the manager sitting among the protections.
        F_BOOKMARKS,
        F_TUNNEL,
        F_OCR,
        F_INTEGRITY,
        F_HIDDEN_TEXT,
        F_ARCHIVE,
        F_DIVERGENCE_SITES,
    ]);
    // Both of these talk to a contact, so they exist only where chat does.
    // Listing them in the public build would describe a panel that build has
    // no code for.
    if cfg!(feature = "chat") {
        out.extend([F_DOWNLOAD_COMPARE, F_CHANGE_COMPARE]);
    }
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
        "There is no onion routing, and no defense against someone watching \
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
/// this file exists to prevent. The one standing commitment -- "Features
/// designated as part of the free tier will remain free forever." -- has
/// deliberate wording, and the test below pins it so a rewrite cannot soften
/// it into marketing.
///
/// REWORDED 2026-08-14 from "Free features always remain free." The promise is now SCOPED to the free tier rather
/// than to whatever happens to be free in a given build. The one-way tiering
/// rule below is unchanged and still binding: a feature that ships free is
/// not gated later. What the new wording drops is the accidental reading
/// that a Premium feature temporarily switched on for everyone (Fingerprint
/// Divergence and the photo check) had thereby become free
/// forever. Do not soften it further: it is a published commitment, not
/// copy. When Premium actually launches, this paragraph changes to present
/// tense IN THE SAME COMMIT as the licensing ships, never before.
///
/// THEME PACKS LEFT THE PREMIUM LIST 2026-08-16, and that is a ONE-WAY DOOR
/// taken deliberately.
///
/// They had been the designated paid extra since 2026-08-04: nine accents
/// and three chrome schemes, shipped unlocked as the pack's seed, with the
/// split recorded as a choice to be made the day the gate was flipped. The
/// question came up because the accent stopped being a highlight -- it now
/// tints the tab strip, the toolbar and the address bar -- so gating it
/// later would have reverted a user's whole browser to blue rather than
/// costing them a detail. Between a loud retraction, grandfathering, and
/// giving the pack away, giving it away is the only one of the three that
/// keeps faith with the free-features-stay-free note the public About page
/// already carried.
///
/// The sentence above puts them in the free tier, and the free-tier promise
/// is what makes this permanent: theme packs can never be sold. That is the
/// point of writing it here rather than only in a changelog. If the pack is
/// ever to earn money, it has to be NEW accents and NEW schemes on top of
/// these, which the wording deliberately leaves room for -- "all nine" and
/// "all three" are counts of what ships today, not a promise about a tenth.
const PREMIUM: &str = "PATANYX will offer a paid Premium tier. Private chat between PATANYX users, checking a page together with a contact, reading the text in a photo, the tab pack (searching across every open tab, the tab switcher, and batch tab actions), reading the text you drag a box around, the archive of pages you chose to keep, and comparing a downloaded file with a contact will be part of it. Fingerprint Divergence is FREE PERMANENTLY, on by default, and does not join Premium; turning its noise off for named sites is free with it. The photo check is switched on for everyone in this build and stays that way until Premium launches. The tab pack works differently, and so do the newer features: reading the text you drag a box around, the archive of pages you chose to keep, and comparing a downloaded file with a contact all ask for a Premium license from day one, and they unlock when Premium launches. Private chat and checking a page with a contact are not in this build at all -- they are compiled into a separate PATANYX-Premium build, which is also a free download. The built-in tunnel is free, and so is light and dark following your system setting. How this browser looks is free: all nine accent colors, all three chrome color schemes, and where the toolbar sits. Every other protection on this page is free. Features designated as part of the free tier will remain free forever. A Premium license will activate on up to five devices: the first time your vault opens after you paste the token, PATANYX makes one request to EdgeXene to activate that device, trying again at the next unlock if it could not reach us, and every unlock after that is checked offline by your own copy of the browser. Releasing a device frees its slot; a license allows a limited number of activations in all, and the Vault panel says so if you reach it. Nothing is for sale yet; when Premium launches, this page will say so plainly.";


/// One sentence more on the accent, ON WINDOWS ONLY: there the accent is
/// handed to the scrollbars of pages (privacy.rs, page_scrollbar_css), and
/// a page can read the colour it was given -- a few bits a site can learn
/// about this visitor, accepted knowingly on 2026-08-17 as the price of the
/// feature and said here beside the choice that causes it. WebKitGTK does not implement
/// `scrollbar-color` at all, so on Linux the sentence would describe a thing
/// that does not happen, and it is compiled out rather than hedged: the
/// same rule as `engine_name` -- each build tells its own truth.
#[cfg(windows)]
const ACCENT_REACH: &str = "The accent also reaches the scrollbars of the pages you open, and a page can read that color, so the accent you choose is something a site can tell.";
#[cfg(not(windows))]
const ACCENT_REACH: &str = "";

/// `PREMIUM` with the platform's accent sentence, for the two places that
/// present it. Empty sentence, no trailing space.
fn premium_text() -> String {
    if ACCENT_REACH.is_empty() {
        PREMIUM.to_string()
    } else {
        format!("{PREMIUM} {ACCENT_REACH}")
    }
}
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
///
/// THE LAUNCH PAGE IS THE FOURTH, since 0.9.63: started without a page, the
/// browser opens PATANYX Search at patanyx.com (main.rs, HOME_URL), a site we
/// operate. Same reasoning: it is self-initiated, a capture finds it, and the
/// sentence says "only". Named as what it is -- a page you can see open, not
/// a check -- and with the fact that lets it be harmless: the server writes
/// no log line for that page or what it loads.
const DISCLOSURE: &str = "One Rust program, with nothing downloaded at runtime. PATANYX itself \
collects nothing about you. The only things it reaches out for on its own are \
an anonymous, signed update check and blocklist refreshes, plus an occasional \
check that the resolver is still reachable if you have chosen an encrypted \
one. Started without a page, it opens PATANYX Search at patanyx.com, which \
we run and which keeps no log of that page or what it loads. Web pages are \
drawn by software your computer already has and updates itself. One caveat: \
on Windows, Microsoft's WebView2 engine reports a minimum of component health \
data that no application is allowed to switch off.";

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
    out.push_str(&premium_text());
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
        "premium": premium_text(),
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
        // SECOND: the standing free-forever commitment, exact and brittle on
        // purpose -- a rewrite must look this sentence in the eye.
        assert!(
            lowered.contains(
                "features designated as part of the free tier will remain free forever"
            ),
            "the free-tier commitment must stay verbatim"
        );
        // THIRD (Phase 4, 2026-08-17): the device count and the one
        // activation request are stated, because the browser now makes
        // that request and a page that hid it would be describing an
        // older browser. "up to five devices", never "at most" (releasing
        // a slot does not switch off the device that had it).
        assert!(
            lowered.contains("up to five devices")
                && lowered.contains("one request to edgexene"),
            "the premium section must state the five-device activation honestly"
        );
        assert!(
            !lowered.contains("at most five devices") && !lowered.contains("at most 5 devices"),
            "the honest claim is 'up to', never 'at most'"
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
        // The fourth: the page a plain launch opens. main.rs HOME_URL is
        // patanyx.com, so a launch contacts a server we run before the user
        // has done anything; leave it unnamed and "only" is false again.
        assert!(
            lowered.contains("opens patanyx search at patanyx.com"),
            "the disclosure must name the launch page. main.rs opens \
             https://patanyx.com/ in the first tab of a plain launch, so a \
             sentence listing what the browser reaches out for on its own has \
             to include it."
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
