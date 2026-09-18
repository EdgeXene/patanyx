//! Shared application state. All mutation happens on the event-loop thread.


use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use patanyx_store::Store;
use patanyx_vault::Vault;
use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;
use wry::{PageLoadEvent, WebView};

use crate::platform;
use crate::UserEvent;

/// Whether this backend's ledger records BLOCKED requests, not merely
/// contacted hosts.
///
/// WebKitGTK's content blocker reports no per-request matches, so on unix the
/// blocked column is structurally always zero and the UI must say "contacted"
/// rather than imply a block count. WebView2 answers 403 from its own
/// callback and can count them.
pub(crate) const LEDGER_COUNTS_BLOCKED: bool = cfg!(windows);

/// How long before the lock the user is warned.
///
/// The warning is what makes a short timeout liveable. Keypresses inside a page
/// now count as activity, but reading a long article or watching a video
/// involves no input at all -- and for a chat build, an auto-lock tears down
/// the transport, so someone reading a conversation would drop off the LAN
/// mid-sentence with no notice. A minute is enough to notice and act without
/// being so early that it becomes background noise.
pub const AUTO_LOCK_WARN_BEFORE: Duration = Duration::from_secs(60);

/// Hard ceiling on open tabs, for both page-driven and IPC-driven creation.
pub const MAX_TABS: usize = 32;

/// How many recently-picked file paths stay redeemable.
///
/// Small on purpose. A token is handed out per dialog and consumed by the one
/// command that uses it; more than a handful outstanding means something is
/// picking files and never redeeming them, and the oldest should go rather
/// than accumulate.
pub const MAX_PICKED_PATHS: usize = 8;

/// Scheme allowlist for content webviews, shared by the navigation handler and
/// the `tab_new` IPC command (a new webview's initial `with_url` never passes
/// through the navigation handler).
///
/// The chrome origin is excluded explicitly because on Windows it IS an http
/// URL — WebView2 cannot register custom schemes, so wry serves the chrome UI
/// at `http://rbchrome.localhost/`. Without this exclusion a plain scheme check
/// would let an untrusted page put itself on the trusted origin. On unix the
/// chrome scheme is not http and the exclusion costs nothing.
/// This is an ORIGIN test, not a string-prefix test, and the difference is the
/// whole point. `!url.starts_with("http://rbchrome.localhost/")` is trivially
/// evaded by every spelling of the same origin that does not happen to be that
/// byte sequence: no trailing slash, an explicit `:80`, a `user@` prefix, a `?`
/// straight after the host, or capital letters (hosts are case-insensitive).
/// All of those load the trusted chrome document. The predicate now extracts
/// the host and compares it, so a spelling it has never seen still fails.
///
/// It is reachable remotely: a contact can send a tab over chat, and
/// `chat_panel` validates with this same function.
pub fn is_allowed_content_url(url: &str) -> bool {
    if url == "about:blank" {
        return true;
    }
    // TWO PARSERS, AND EITHER ONE MAY VETO (security audit 2026-08-18, F19).
    //
    // `host_of` compares the host it extracts LITERALLY. That is correct for
    // the normalizations it was written for -- stripped tabs, a backslash
    // authority, userinfo, case -- and blind to the ones that happen INSIDE
    // the host component: percent-decoding and IDNA mapping. So
    // `http://%72bchrome%2elocalhost/` and `http://rbchrome\u{3002}localhost/`
    // read as unrelated names here and resolve to the chrome origin in the
    // engine. Five such spellings passed before this arm existed; they are
    // pinned in `ipc.rs`'s bypass table.
    //
    // The fix is not to teach `host_of` percent-decoding and a Unicode
    // mapping table by hand -- that is the same class of work that produced
    // the gap, and a mapping table is never finished. It is to ask the
    // question a second time with the parser the engines actually implement,
    // and let EITHER answer deny. A bypass now has to be a host that this
    // parser resolves somewhere harmless AND `host_of` reads as harmless,
    // while the engine reads it as chrome.
    //
    // Deliberately additive: `host_of` still decides everything else,
    // including which non-http schemes are refused, so nothing that was
    // denied before becomes allowed now.
    match url::Url::parse(url) {
        Ok(parsed) => {
            // Normalised the same way `host_of` normalises, because this parser
            // preserves a trailing dot verbatim and the constant has none.
            let parsed_host = parsed
                .host_str()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
            if parsed_host.as_deref() == Some(platform::CHROME_RESERVED_HOST) {
                return false;
            }
        }
        // FAIL CLOSED, and this arm is the point. It used to be absent: a URL the
        // strict parser REJECTED skipped the veto entirely and left `host_of` to
        // decide alone -- so the way past the second parser was not to satisfy it
        // but to break it. An input the two parsers cannot even agree is a URL is
        // not one to resolve in the attacker's favour.
        //
        // This can only DENY more than before. Non-http schemes do not reach it
        // (`host_of` returns None for them and they are refused below either way),
        // so what it refuses is a malformed http(s) URL -- which no engine should
        // be loading as the trusted origin regardless.
        Err(_) => return false,
    }
    match host_of(url) {
        // Compared case-insensitively; `host_of` has already lowercased.
        Some(host) => host != platform::CHROME_RESERVED_HOST,
        // No http(s) authority: file://, data:, javascript:, rbchrome://, or
        // something malformed. All denied.
        None => false,
    }
}

/// Host of an http(s) URL, lowercased, with userinfo and port removed.
/// `None` for any other scheme or a missing authority.
///
/// Deliberately mirrors two browser normalisations that a naive split misses,
/// because a parser that disagrees with the engine about where the host ends
/// is a bypass rather than a bug:
///
///   * ASCII tab, LF and CR are STRIPPED from URLs entirely, so
///     `http://rbchrome.loc\talhost/` is the chrome origin to the engine
///     while a naive parser reads an unrelated name;
///   * a backslash terminates the authority exactly as `/` does, so
///     `http://rbchrome.localhost\.evil.com/` is likewise the chrome origin
///     to the engine and an unrelated name to a naive parser.
///
/// Both of those are false-ALLOW directions, which is why they are handled
/// here rather than left to fail closed.
pub(crate) fn host_of(url: &str) -> Option<String> {
    // Tab, LF and CR are stripped because the engines strip them. The REST of the
    // C0 range and DEL are stripped for a different reason: they are not legal in a
    // host at all, so an engine either rejects the URL or drops them, and either way
    // a name that differs from the reserved one only by a control character must not
    // read here as an unrelated host. Collapsing toward the reserved name is the safe
    // direction -- it can only cause a DENY.
    let cleaned: String = url.chars().filter(|c| !c.is_ascii_control()).collect();
    let lower = cleaned.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    // The LAST '@' separates userinfo from host: userinfo may itself contain
    // an encoded '@', and taking the first one would read the attacker's half.
    let host_port = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    // An IPv6 literal keeps its brackets and its colons; the port, if any,
    // follows the closing bracket.
    let host = match host_port.find(']') {
        Some(end) => &host_port[..=end],
        None => host_port.split(':').next().unwrap_or(""),
    };
    // A TRAILING DOT NAMES THE SAME HOST. `rbchrome.localhost.` is the
    // root-anchored spelling of `rbchrome.localhost` and the engines resolve it to
    // that origin, but every comparison in this file is against the undotted
    // constant, so the dotted spelling read as an unrelated name and was ALLOWED
    // (security assessment 2026-08-28). It defeated two layers at once, which is
    // why the trim belongs here rather than at either call site: the content
    // predicate, `classify_uri`'s reserved-origin request filter (the subframe
    // backstop, which exists precisely because subframes skip the navigation
    // allowlist), the blocklist matcher and the ledger all derive their host from
    // this one function, so one spelling in means one spelling everywhere.
    //
    // An IPv6 literal keeps its brackets and never ends in a dot, so the trim is a
    // no-op there. A bare `.` trims to empty and is refused below, as it should be.
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Whether a credential-save offer may be shown for a submission, and the
/// site name the banner is allowed to use.
///
/// Pure, and separated from `note_login_submitted` for the reason the rest of
/// this file separates decisions from I/O: the interesting cases are about two
/// URLs disagreeing, and an `AppState` full of live webviews is not needed to
/// state them.
///
/// `sender` is the engine's answer to "which document sent this"
/// (`ICoreWebView2WebMessageReceivedEventArgs::Source`), NEVER the `origin`
/// field the page puts in its own JSON. The page's field used to reach the
/// save banner, which let a hostile page make the trusted chrome name a site
/// the user was not on (security audit 2026-08-18, F20).
///
/// `tab` is what this side believes the tab is showing. The two disagree in
/// exactly the case worth refusing: a page posts a submission and then
/// navigates. Web messages and navigation events are not ordered against each
/// other, so the message can arrive after the move, and the offer would
/// otherwise bind to whichever site is loaded by then -- with
/// `cred_save_confirm` dutifully re-deriving the host from THAT url and filing
/// the password under it.
///
/// Hosts are compared, not whole URLs: an in-page fragment or a query change
/// is not a different site and must not throw an honest offer away.
pub(crate) fn login_offer_origin(sender: &str, tab: Option<&str>) -> Option<String> {
    let sender_host = host_of(sender)?;
    let tab_host = host_of(tab?)?;
    if sender_host != tab_host {
        return None;
    }
    Some(sender_host)
}

/// What a login submission should produce, once the tab and origin checks
/// have passed.
///
/// Pure, and separated from `note_login_submitted` for the same reason
/// `login_offer_origin` above is: `AppState` owns live webviews, so no unit
/// test can build one, and a decision left inside it is a decision nothing can
/// drive. The dispatcher that calls this stays deliberately trivial.
///
/// THE CASE THIS EXISTS FOR is `NoticeLocked`. Before it, a submission with a
/// locked vault returned early and told the user NOTHING -- the doc comment
/// said "silently drops the submission" -- so a person logged in, no save
/// offer appeared, and there was no way to learn why. The vault auto-locks on
/// a timer, so this is reachable without the user doing anything at all.
///
/// `Silent` keeps its silence on purpose in the no-vault case. Someone who has
/// never created a vault has not opted into password saving, and telling them
/// to unlock something that does not exist is the exact mistake a copy review
/// caught in the autofill row a day earlier. `vault.is_none()` alone cannot
/// tell "locked" from "never created"; that is why `vault_exists` is a
/// separate input here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginSubmitOutcome {
    /// The vault is open and does not already hold this: stash the pending
    /// save and raise the save banner.
    Offer,
    /// The vault ALREADY holds this exact credential, which is what happens
    /// every time a saved password is autofilled and submitted. Asking to
    /// save it again is asking a question whose answer is already on disk.
    AlreadySaved,
    /// A vault exists and is LOCKED. Save nothing, tell the user why.
    NoticeLocked,
    /// Nothing happened and nothing is said.
    Silent,
}

/// Whether the vault already holds the credential being submitted.
///
/// Split out of the dispatcher so the JOIN is testable. Both halves of this
/// question were covered before it existed -- the vault's comparison and the
/// outcome table -- and the line connecting them was covered by nothing, so
/// passing a literal `false` here would have restored the bug with every test
/// still green. That exact shape has been the most common defect in this
/// work, so it gets a function rather than a line.
///
/// `None` (a locked vault) is false: nothing was compared, and the locked
/// case is decided before this matters.
pub(crate) fn already_stored(
    vault: Option<&Vault>,
    origin: &str,
    username: &str,
    password: &str,
) -> bool {
    vault.is_some_and(|vault| {
        vault.has_matching_credential(username, password, |stored| {
            crate::psl::same_site(stored, origin)
        })
    })
}

pub(crate) fn login_submit_outcome(
    unlocked: bool,
    vault_exists: bool,
    already_saved: bool,
) -> LoginSubmitOutcome {
    if unlocked {
        // Checked before anything else about the vault, because an open vault
        // that already holds this has nothing to ask.
        if already_saved {
            return LoginSubmitOutcome::AlreadySaved;
        }
        return LoginSubmitOutcome::Offer;
    }
    if !vault_exists {
        return LoginSubmitOutcome::Silent;
    }
    LoginSubmitOutcome::NoticeLocked
}

/// How long after one locked-vault notice before another may be shown.
///
/// MUST EXCEED THE NOTIFICATION'S OWN LIFETIME (`TOAST_MS` in chrome.js). That is
/// the whole property: a cooldown longer than the toast means two of these can
/// never be on screen at once, however many submissions arrive.
///
/// It has to be time-based, and nothing page-driven may reset it. An earlier
/// draft cleared the suppression on navigation, and a review pointed out that
/// a hostile page can simply submit, reload the same host, and submit again --
/// `document.addEventListener("submit", ...)` in autofill.js has no
/// `isTrusted` check, and the native bridge can be called directly regardless,
/// so the page controls how often this code runs. It does not control the
/// clock.
pub(crate) const LOCKED_SAVE_NOTICE_COOLDOWN: Duration = Duration::from_secs(30);

/// Whether enough time has passed since the last locked-vault notice.
pub(crate) fn locked_save_notice_due(last: Option<Instant>, now: Instant) -> bool {
    match last {
        None => true,
        Some(last) => now.duration_since(last) >= LOCKED_SAVE_NOTICE_COOLDOWN,
    }
}

/// Claim the notice slot if it is due, STAMPING it in the same step.
///
/// The decision and the write have to live together. When they did not -- a
/// `due()` predicate here and the assignment up in the dispatcher -- deleting
/// the assignment made every submission emit a notice while all three tests
/// stayed green, because each tested one half and nothing tested the join.
/// Passing the slot in by reference is what lets a test drive the real
/// sequence instead of two predicates that never meet.
pub(crate) fn take_locked_save_notice(last: &mut Option<Instant>, now: Instant) -> bool {
    if !locked_save_notice_due(*last, now) {
        return false;
    }
    *last = Some(now);
    true
}

/// One page-translation session, owned by the tab it belongs to.
///
/// LIVES IN RUST, NOT IN THE PAGE. The chrome UI never names a tab or a URL
/// when it asks for a translation; it sends a language and Rust acts on the
/// ACTIVE tab, holding the URL itself. That is the argument-less command
/// discipline the insecure-continue arms already use, and it is why a
/// compromised chrome origin cannot point translation at a page of its
/// choosing.
#[derive(Debug, Clone, PartialEq)]
pub struct TranslationSession {
    /// The pair the user picked, already validated against the shipped set.
    /// Never a free-form string: it reaches a model path later, and a
    /// validated enum-like value is what keeps that from becoming an
    /// injection point.
    pub pair: &'static str,
    /// The SOURCE language code (the pair's `from`), held so the corruption
    /// guard can check the page's actual script against it. Registry-owned
    /// `&'static str`, like `pair`.
    pub source: &'static str,
    /// The cumulative script tally of every batch seen this run, for the
    /// corruption guard. Judged as a whole, not per batch.
    pub script_counts: crate::detect::ScriptCounts,
    pub phase: TranslationPhase,
    /// When this session last visibly ADVANCED: created, an extract arrived,
    /// a patch landed, a pack finished. The stall deadline measures from
    /// here, not from the start -- a long page is many batches of honest
    /// work, and a deadline on total age would kill exactly the pages the
    /// batching exists to serve.
    pub last_progress: std::time::Instant,
    /// For each string actually SENT, where it sat in the batch the page
    /// delivered. A mixed-language page has nodes the source model must not
    /// see, so the batch is filtered -- and the engine numbers its output
    /// against what it was GIVEN, while the page numbers its nodes against
    /// the document. Without this map the two disagree by however many nodes
    /// were skipped, and a patch lands on the wrong paragraph.
    pub batch_map: Vec<usize>,
    /// How many document nodes this batch COVERED, filtered or not. The next
    /// offset advances by this, never by the sent length.
    pub batch_span: usize,
    /// Translatable nodes in the whole document, as the page counted them.
    /// The denominator for the panel's percentage; None until the page says.
    pub doc_total: Option<usize>,
    /// What the RUNNING translator document says it is: the asset revision it
    /// was served with, and the linear memory the engine actually got.
    /// Diagnostic only -- nothing branches on either.
    pub engine_asset_rev: Option<String>,
    pub engine_heap_bytes: Option<u64>,
    /// Script census of the last batch the engine was handed. Counts only.
    pub engine_last_input: Option<Value>,
    /// Identifies THIS run of the session to the page.
    ///
    /// The page keeps a node map per extraction, and a patch names indices
    /// into it. If the user cancels and clicks again on the same page, the URL
    /// has not changed -- so the URL alone cannot tell the second run's
    /// patches from the first's, and a late reply from run 1 could address
    /// nodes run 2 collected. The token makes the runs distinguishable, and
    /// the page drops anything that does not match its current one.
    pub token: u64,
    /// What the page sent up, held until the engine has taken it.
    ///
    /// PAGE TEXT LIVES HERE AND NOWHERE ELSE ON THE HOST, and it is cleared
    /// the moment the translation is handed back. It is not logged, not
    /// written to disk, and not carried into any other structure -- the whole
    /// point of on-device translation is that this text never becomes a record
    /// of what the user was reading.
    pub batch: Vec<String>,
    /// Whether this batch has been submitted to the engine, so a tick does not
    /// submit it twice.
    pub submitted: bool,
    /// Index the CURRENT batch starts at, as the page reported it.
    ///
    /// The page indexes its node map absolutely and this is where the batch in
    /// hand sits inside it, so a patch built here addresses the right nodes
    /// even though the host only ever holds one batch at a time.
    pub offset: usize,
    /// Whether the page said it has more text after this batch.
    pub more: bool,
    /// Running total of nodes actually put back across every batch of this
    /// run. `translation_patched` reports it; a per-batch count would reset to
    /// a small number at the end of a long page and read as a failure.
    pub patched_total: usize,
    /// THE PAGE THIS CONSENT WAS GIVEN FOR.
    ///
    /// Consent attaches to the page the user was reading when they clicked,
    /// so a session is only meaningful while the tab still shows that page.
    /// Recording the URL here makes a stale session INERT rather than merely
    /// unlikely: `session_is_current` refuses it, so forgetting to clear one
    /// on navigation is a leak of memory, not a translation of a page nobody
    /// asked about.
    ///
    /// That distinction is the whole reason this field exists. The explicit
    /// clear in `on_url_changed` is hygiene; correctness must not depend on
    /// remembering to write it, because nothing in the test suite can
    /// construct a Tab to check that it is still there.
    pub page: String,
}

/// Whether a session still belongs to what the tab is showing.
///
/// Pure, and separated out precisely so it CAN be tested: `Tab` owns a live
/// `WebView`, so no unit test can build one, and any rule expressed only
/// inside a method on Tab is a rule nothing verifies.
/// Whether one extractor message may be accepted.
///
/// PURE, and separated out for the same reason `session_is_current` is: `Tab`
/// owns a live `WebView`, so a rule expressed only inside a method on it is a
/// rule nothing verifies. This is where "never automatic" is actually
/// enforced -- not in the UI, which a compromised page cannot reach anyway,
/// but here, where text arriving from a page with no session is dropped.
///
/// `session_page` is what the user consented to; `tab_url` is where the tab is
/// NOW; `href` is where the page CLAIMS to be. All three must agree. The page
/// supplies only the last one, which is exactly why it is checked against the
/// two it does not control rather than trusted.
pub fn extract_is_acceptable(
    session_page: Option<&str>,
    tab_url: &str,
    kind: &str,
    href: &str,
) -> bool {
    if kind != "extract" {
        return false;
    }
    let Some(page) = session_page else {
        // No session: nobody asked. A page may post whenever it likes; this
        // is the line that makes that pointless.
        return false;
    };
    session_is_current(page, tab_url) && page == href
}

/// Whether an extraction belongs to the session run that is currently live.
///
/// SEPARATE FROM THE URL CHECK because they answer different questions. The
/// URL asks "is this the page consent was given for"; this asks "is this THIS
/// run". A user who cancels and clicks Translate again on the same page passes
/// the first and must fail the second for run 1's late reply -- otherwise a
/// stale batch is filed against run 2's node map, and the indices in it mean
/// something else entirely.
///
/// The token is compared AS THE PAGE SENT IT, a string, with no parsing. A
/// page can put any string in that field; the only one that gets anywhere is
/// the exact decimal the host chose, and refusing to parse means there is no
/// "42abc" or " 42" or "+42" to be lenient about.
pub fn extract_token_matches(session_token: Option<u64>, claimed: Option<&str>) -> bool {
    match (session_token, claimed) {
        (Some(token), Some(claimed)) => claimed == token.to_string(),
        // No session, or a message that names no run: refused. Both are the
        // shape of a page posting unprompted.
        _ => false,
    }
}

/// Encodes a string as a JavaScript string LITERAL for a fixed call wrapper.
///
/// THE RULE THIS ENFORCES: untrusted text never rides as code. Page text
/// crosses into the translator document exactly once, as the argument of
/// `window.__translator.translate(...)`, and it must arrive as a string that
/// the engine parses -- never as source that it runs.
///
/// `serde_json` already escapes quotes, backslashes and control characters, so
/// the output is a valid JS string literal on every engine we ship. The two
/// extra characters handled here are U+2028 LINE SEPARATOR and U+2029
/// PARAGRAPH SEPARATOR: both are legal unescaped inside a JSON string and were
/// illegal inside a JavaScript string literal before ES2019. WebKitGTK 2.50 and
/// current WebView2 are both far past that, so this is not fixing a live bug --
/// it is refusing to make correctness here depend on a language revision, when
/// the input is text scraped from a hostile page and the cost is two
/// replacements.
pub fn js_string(json: &str) -> String {
    // QUOTED, not merely escaped. An earlier version returned the payload
    // unchanged, which made the call site read
    // `translate({"id":"1","texts":[...]})` -- a JS OBJECT LITERAL, not a
    // string. The document's `JSON.parse` then received an object, coerced it
    // to "[object Object]" and threw. The engine probe caught it on the first
    // run against a real pack.
    //
    // That was also the security bug hiding behind the cosmetic one: the whole
    // point of this function is that page text arrives as DATA. Interpolating
    // it into an object literal puts it in source position, where the only
    // thing standing between a hostile page and this document is how well
    // serde_json happens to escape. Quoting makes it a string literal, which
    // is what the doc comment above always claimed.
    let quoted = serde_json::to_string(json).unwrap_or_else(|_| "\"\"".to_string());
    quoted
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Maps a failure key reported by the translator document onto one this
/// product knows.
///
/// AN ALLOWLIST, NOT A PASS-THROUGH. The key reaches the panel and is looked up
/// in the message catalog, so an unrecognised one would render as a missing
/// string in front of the user. Matching against the set the document is known
/// to produce means a document that ever reported something else -- a future
/// edit, a partially-loaded script -- degrades to a generic failure the panel
/// can actually say, instead of a blank.
///
/// It is also the narrower door: the translator document is ours, but it is the
/// one place in this feature that has touched a language pack's bytes, and
/// nothing it says needs to be taken on trust when a fixed list will do.
fn translation_failure_key(reported: &str) -> &'static str {
    match reported {
        "translate-engine-failed" => "translate-engine-failed",
        "translate-engine-aborted" => "translate-engine-aborted",
        "translate-pack-failed" => "translate-pack-failed",
        "translate-timeout" => "translate-timeout",
        "translate-no-pack" => "translate-no-pack",
        "translate-patch-failed" => "translate-patch-failed",
        // Pack delivery. Three outcomes a user can act on differently: the
        // network was unreachable (try later), the bytes could not be trusted
        // (something is wrong, and it is not their fault), or the disk refused
        // (free some space). `langpack::PackError::key` produces exactly these.
        "translate-pack-unreachable" => "translate-pack-unreachable",
        "translate-pack-untrusted" => "translate-pack-untrusted",
        "translate-pack-storage" => "translate-pack-storage",
        // Detection outcomes. Script mismatch is the corruption guard firing;
        // source-unknown is "we could not tell and you gave no source";
        // pair-unavailable is "no model exists for that direction"; busy is
        // "another translation is running".
        "translate-script-mismatch" => "translate-script-mismatch",
        "translate-source-unknown" => "translate-source-unknown",
        "translate-pair-unavailable" => "translate-pair-unavailable",
        "translate-busy" => "translate-busy",
        _ => "translate-failed",
    }
}

/// Whether the corruption guard refuses this batch for the chosen source.
///
/// PURE so it can be proved without a browser: given the source language and
/// the page's first batch, does the page's script POSITIVELY contradict the
/// source? Only a clear mismatch refuses (the Greek-into-an-en-model incident);
/// an ambiguous or same-script page proceeds on the user's explicit choice.
/// The whole safety property of this cluster lives in this one boolean.
/// Whether the CUMULATIVE script tally of a session so far is a clear mismatch
/// with the chosen source.
///
/// Cumulative, not per-batch, because a red-team pass showed a per-batch check
/// is defeated by chopping incompatible text into sub-threshold batches. The
/// caller folds each batch into `counts` and asks this after every one; the
/// verdict is about the whole page seen so far, so tiny batches accumulate and
/// a late foreign quote on an otherwise-clean page does not false-refuse.
/// Whether a pair may be fetched or used at this entitlement level.
///
/// THE WHOLE TIER RULE, in one pure function, because the three places that
/// need it cannot themselves be unit-tested: they hang off an `AppState` that
/// owns live WebViews. Extracting the decision means the RULE is covered
/// exhaustively against the real registry (see the tests below) even though
/// its call sites are not, and the three sites cannot drift apart.
///
/// An unknown token is permitted here: it has already failed
/// `validate_translation_pair` at every caller, and answering "denied" for a
/// token that does not exist would confuse a real refusal with a typo.
pub(crate) fn tier_allows(pair: &str, premium_active: bool) -> bool {
    match crate::languages::pair_by_token(pair) {
        Some(row) => tier_allows_row(row.tier, premium_active),
        // An unknown token is not the tier gate's business: every caller has
        // already refused it, and answering "denied" would report a typo as a
        // licensing problem.
        None => true,
    }
}

/// The gate itself, over a tier rather than a token.
///
/// SPLIT OUT SO IT STAYS TESTED WITH ZERO PREMIUM LANGUAGES IN THE PRODUCT.
/// Both gate tests used to prove themselves non-vacuous by finding a real
/// tier-2 row, so the moment OPUS-MT became free (2026-09-01) they failed --
/// not because the gate broke, but because the product stopped carrying
/// anything for it to refuse. A security boundary that is only tested while
/// some product decision happens to exercise it is one bad quarter from being
/// untested, so the rule is proven here, exhaustively, on its own.
pub(crate) fn tier_allows_row(tier: u8, premium_active: bool) -> bool {
    tier < 2 || premium_active
}

/// Where an engine result lands in the PAGE's node map.
///
/// Three coordinate systems meet here and getting them wrong scrambles a page
/// into itself, so the arithmetic is a pure function with tests rather than a
/// line buried in a handler:
///   * `i` numbers what was SENT to the engine (post-filter),
///   * `map` gives each sent item its index in the batch the page delivered,
///   * `offset` is where that batch starts in the document.
///
/// Returns None for an index the map cannot name -- dropped, never clamped: a
/// patch aimed at a node we cannot identify is not a patch.
fn patch_index(i: usize, map: &[usize], offset: usize) -> Option<u64> {
    let in_batch = *map.get(i)?;
    u64::try_from(in_batch.checked_add(offset)?).ok()
}

fn script_refuses(counts: &crate::detect::ScriptCounts) -> bool {
    crate::detect::verify(counts) == crate::detect::Verdict::ScriptMismatch
}

/// How often an in-flight translation is polled.
///
/// The engine reports no progress, so this is the resolution at which the
/// panel can change. Fast enough that a short page feels immediate, slow
/// enough that it is not waking the event loop for nothing during the seconds
/// a long batch actually takes.
const TRANSLATE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// How long a session may sit with NOTHING advancing before it is failed.
///
/// Measured against `last_progress`, not session age, and suspended while a
/// pack download for the session's pair is in flight (the download has its
/// own progress feed and its own failure path). Without this, a page that
/// never answered the extract request left "Getting ready" on screen forever,
/// with no path out but navigating away -- it was found on hardware
/// before any test did. Sized for a cold WebView2 boot plus a large pack
/// loading from disk on a slow laptop, with margin.
const TRANSLATE_STALL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether a page-supplied language string is a plausible BCP-47 tag.
///
/// Page-controlled, so it is validated as data before it can reach the badge:
/// 2..=32 chars, ASCII letters/digits/hyphen only. This refuses bidi controls,
/// zero-width characters and homoglyph attacks a red-team pass flagged -- not
/// by stripping them, but by refusing anything that is not tag-shaped, because
/// a value that needs stripping was never a language tag.
fn is_plausible_lang_tag(s: &str) -> bool {
    (2..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub fn session_is_current(session_page: &str, tab_url: &str) -> bool {
    !session_page.is_empty() && session_page == tab_url
}

#[derive(Debug, Clone, PartialEq)]
pub enum TranslationPhase {
    /// Asked for; the engine and pack are not ready yet.
    Preparing,
    /// Engine ready, text moving.
    Translating,
    /// Finished for the page as it stood.
    Done,
    /// Fail CLOSED: the page is left untranslated and readable, never
    /// half-patched. The string is a catalog key, not prose.
    Failed(&'static str),
}

/// The pairs the CURRENT chrome offers.
///
/// TEMPORARY, and narrower on purpose than what this build can validate: the
/// legacy panel knows one label ("Spanish") and offering a token it cannot
/// name would put a raw identifier in front of the user. The Translation-tab
/// rework replaces this with `packs_status` built from installed languages;
/// until then this list is what `translation_status` advertises, while
/// validation below accepts the whole PUBLISHED registry.
pub const TRANSLATION_PAIRS: &[&str] = &["en-es"];

/// Resolves an incoming pair token to the PUBLISHED registry, returning the
/// STATIC token so nothing downstream can be holding a borrowed
/// attacker-shaped value.
///
/// An allowlist rather than a parse, exactly as before -- only the list grew:
/// it is now `languages::PAIRS`, generated from Mozilla's published model
/// records (a pair enters it only with a complete stable model set), instead
/// of a hand-kept one-element array. The token still ends up selecting a URL
/// path and a directory name, so membership -- never shape -- is the test.
///
/// PUBLISHED is not INSTALLED: this answers "does such a model exist to
/// fetch", and the pack directory answers "is it on this machine". The two
/// predicates carry different failure keys.
pub fn validate_translation_pair(candidate: &str) -> Option<&'static str> {
    crate::languages::pair_by_token(candidate).map(|p| p.token)
}

/// One of the four coarse fingerprint surfaces shown in Tab Activity.
/// Nothing below this granularity crosses the content boundary: no method
/// name, pixel, sample, rectangle, or WebGL parameter value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FingerprintSurface {
    Audio,
    Canvas,
    WebGl,
    ElementMeasurement,
}

impl FingerprintSurface {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "audio" => Some(Self::Audio),
            "canvas" => Some(Self::Canvas),
            "webgl" => Some(Self::WebGl),
            "element_measurement" => Some(Self::ElementMeasurement),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FingerprintProbeCounts {
    pub(crate) audio: u64,
    pub(crate) canvas: u64,
    pub(crate) webgl: u64,
    pub(crate) element_measurement: u64,
}

impl FingerprintProbeCounts {
    fn add(&mut self, surface: FingerprintSurface, count: u64) {
        let slot = match surface {
            FingerprintSurface::Audio => &mut self.audio,
            FingerprintSurface::Canvas => &mut self.canvas,
            FingerprintSurface::WebGl => &mut self.webgl,
            FingerprintSurface::ElementMeasurement => &mut self.element_measurement,
        };
        *slot = slot.saturating_add(count);
    }
}

/// Strict decoder shared by both engine channels.
///
/// `deny_unknown_fields` is load-bearing: a hostile page can post anything,
/// but the event loop will only ever receive a fixed surface name and an
/// integer delta. Four entries is the complete legitimate batch and the JS
/// safe-integer ceiling prevents a lossy number becoming an exact Rust claim.
pub(crate) fn fingerprint_probe_report(
    value: &serde_json::Value,
) -> Option<Vec<(FingerprintSurface, u64)>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Report {
        kind: String,
        counts: Vec<Delta>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Delta {
        surface: String,
        count: u64,
    }

    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    let report: Report = serde_json::from_value(value.clone()).ok()?;
    if report.kind != "fingerprint_probe_counts"
        || report.counts.is_empty()
        || report.counts.len() > 4
    {
        return None;
    }
    let mut seen = [false; 4];
    let mut out = Vec::with_capacity(report.counts.len());
    for delta in report.counts {
        if delta.count == 0 || delta.count > MAX_SAFE_INTEGER {
            return None;
        }
        let surface = FingerprintSurface::parse(&delta.surface)?;
        let index = match surface {
            FingerprintSurface::Audio => 0,
            FingerprintSurface::Canvas => 1,
            FingerprintSurface::WebGl => 2,
            FingerprintSurface::ElementMeasurement => 3,
        };
        if seen[index] {
            return None;
        }
        seen[index] = true;
        out.push((surface, delta.count));
    }
    Some(out)
}

#[cfg(test)]
mod fingerprint_probe_report_tests {
    use super::{fingerprint_probe_report, FingerprintSurface};
    use serde_json::json;

    #[test]
    fn accepts_only_fixed_surface_names_and_integer_deltas() {
        let report = fingerprint_probe_report(&json!({
            "kind": "fingerprint_probe_counts",
            "counts": [
                { "surface": "audio", "count": 14 },
                { "surface": "canvas", "count": 3 },
                { "surface": "webgl", "count": 1 },
                { "surface": "element_measurement", "count": 40 }
            ]
        }))
        .expect("valid report");
        assert_eq!(
            report,
            vec![
                (FingerprintSurface::Audio, 14),
                (FingerprintSurface::Canvas, 3),
                (FingerprintSurface::WebGl, 1),
                (FingerprintSurface::ElementMeasurement, 40),
            ]
        );
    }

    #[test]
    fn rejects_content_unknown_surfaces_and_non_integer_counts() {
        for bad in [
            json!({
                "kind": "fingerprint_probe_counts",
                "counts": [{ "surface": "canvas", "count": 1, "pixels": [1, 2] }]
            }),
            json!({
                "kind": "fingerprint_probe_counts",
                "counts": [{ "surface": "canvas", "count": 1.5 }]
            }),
            json!({
                "kind": "fingerprint_probe_counts",
                "counts": [{ "surface": "webgl_parameter", "count": 1 }]
            }),
            json!({
                "kind": "fingerprint_probe_counts",
                "counts": [
                    { "surface": "audio", "count": 1 },
                    { "surface": "audio", "count": 1 }
                ]
            }),
        ] {
            assert!(fingerprint_probe_report(&bad).is_none(), "accepted {bad}");
        }
    }
}

pub struct Tab {
    pub id: u64,
    /// Platform handle for the tab's view: the GTK container on unix, a
    /// placeholder on Windows where the WebView itself is the only handle.
    view: platform::TabView,
    /// Content webview — untrusted web pages; `load_url` only, never
    /// `evaluate_script`.
    pub webview: WebView,
    pub url: String,
    pub title: String,
    /// Whether this tab was BUILT ephemeral (quarantine profile). Recorded
    /// at construction because the policy is fixed once the WebContext
    /// exists, and features that must respect the ephemeral contract (a
    /// shelf must never remember one) need the per-tab fact, not
    /// the browser-wide policy of the moment.
    pub ephemeral: bool,
    /// The malicious-list host this tab was last blocked on, set when the
    /// host emits navigation_blocked for it and consumed by blocklist_allow.
    /// The override must name the tab AND match this, so a banner raised by
    /// one tab cannot be spent on another (pentest F-006).
    pub blocked_pending: std::cell::RefCell<Option<(u64, String)>>,
    /// Whether the ad and tracker list is applied to THIS tab: the preset it
    /// was built with (private and quarantine tabs block regardless of the
    /// browser-wide switch), then whatever set_privacy last applied to every
    /// tab. Read where a held-page event is consumed: the browser-wide value
    /// was wrong for a private tab opened while blocking was off, and the
    /// hold was silently dropped (review R-002, round 6).
    pub block_ads: bool,
    /// Whether a Fingerprint Divergence script was actually built for this
    /// tab, recorded at construction.
    ///
    /// OBSERVED, not configured, and the difference is the whole point of
    /// the proof panel: this is false when the pref was off, when the
    /// randomness source failed (which yields no script rather than a fixed
    /// token), and when the site is set to Off. Reading the pref at display
    /// time would answer a different question and would be wrong for every
    /// tab opened before the pref last changed, since neither engine can
    /// re-register a live view's scripts.
    pub divergence_registered: bool,
    /// The tab's translation session, if the user started one.
    ///
    /// Per TAB and not per browser: two tabs can be mid-translation in
    /// different languages, and the consent the user gave attached to one
    /// page. Cleared on navigation -- see `on_url_changed`.
    pub translation: Option<TranslationSession>,
    /// How many text nodes the page's extractor has handed up for the CURRENT
    /// session. Observed, not predicted: it counts what actually arrived and
    /// was accepted, which is the only number worth showing a user.
    pub translation_extracted: usize,
    /// How many nodes the last translation actually put back.
    ///
    /// SEPARATE FROM `translation_extracted` because the two differ for real
    /// reasons and the difference is the interesting number: the engine drops
    /// blank strings, and the page skips any node it changed since it was
    /// read. A gap between them is a page that moved underneath the
    /// translation, not an error.
    pub translation_patched: usize,
    /// The page's DECLARED language (html lang attr), reported by the content
    /// script's tier-1 signal. Drives the badge only; never page text. `None`
    /// until a page declares one, and it never gates translation -- it is a
    /// hint, and the source dropdown overrides it.
    pub detected_lang: Option<String>,
    /// The pair this tab keeps translating as the user browses.
    ///
    /// SET BY A FINISHED TRANSLATION, never by the browser's own initiative:
    /// the user's click on Translate is the consent, and this carries that
    /// consent to the NEXT page in the same tab when that page declares the
    /// same source language. Cleared by Show original and by Cancel, because
    /// both are the user saying stop. It never downloads anything: a page
    /// whose pack is missing is simply not translated, since a network
    /// contact still requires a click.
    pub translate_continue: Option<&'static str>,
    /// True while this tab's first navigation is held behind the process-wide
    /// saved-profile wipe. More than the first tab can be waiting: a second
    /// tab opened while the asynchronous clear runs must not race past it and
    /// recreate exactly the half-wiped session this gate exists to prevent.
    initial_navigation_pending: bool,
    /// A close requested while the startup wipe owns this WebView is delayed
    /// until its completion callback runs. WebView2 is allowed to omit that
    /// callback if the WebView is closed, which would otherwise strand every
    /// other pending tab behind the process-wide gate forever.
    close_after_session_wipe: bool,
    /// Counts claimed by the document-start divergence wrappers in this tab.
    /// These are deliberately kept apart from the engine-owned request
    /// ledger: page code can reach the same message channel and forge them.
    fingerprint_probes: FingerprintProbeCounts,
    history: Vec<String>,
    history_index: Option<usize>,
    /// Set when `load_url` originates from back/forward/reload so the
    /// resulting UrlChanged event is not recorded as a new history entry.
    suppress_history: bool,
    /// Page zoom, as a scale factor. Per TAB, like every mainstream browser:
    /// a global level would resize a page the user never asked about, and a
    /// per-site one needs storage this browser deliberately does not keep for
    /// unvisited sites.
    zoom: f64,
    /// Hosts the user chose to visit despite the malicious-host list. Shared
    /// with the navigation handler's closure; dropped with the tab, which is
    /// the point -- an override that outlived its tab would be a hole nobody
    /// remembers opening.
    malicious_override: Rc<RefCell<BTreeSet<String>>>,
    /// Hosts the user chose to reach over plain HTTP after being warned.
    /// Same shape and the same lifetime rule as `malicious_override`: per
    /// tab, shared with the navigation handler's closure, gone with the tab.
    /// Kept as a SEPARATE set on purpose -- "I accept this site is
    /// unencrypted" and "I accept this site is on a phishing list" are two
    /// decisions, and one set for both would let either answer the other.
    insecure_override: Rc<RefCell<BTreeSet<String>>>,
    /// The plain-HTTP URL the navigation handler held back, waiting on the
    /// user's answer. `tab_status` carries it so the chrome shows the
    /// warning for THIS tab and only while it is the active one; cleared by
    /// Continue, Dismiss, and any navigation that does go through.
    insecure_pending: Option<String>,
    /// When `insecure_pending` was last set. The banner's subject may not be
    /// rewritten faster than a person can read it -- see
    /// `INSECURE_BANNER_STABILITY` and `note_insecure_navigation`.
    insecure_pending_at: Option<Instant>,
    /// The held-page banner and the per-tab ad-list consent behind it.
    ///
    /// Per tab and gone with the tab, like the two override sets above. The
    /// state machine is pure and lives in `adlist_consent`; this is where it
    /// is kept and the engines reach it.
    adlist: crate::adlist_consent::AdlistConsent,
}

impl Tab {
    /// Release a first navigation held behind the startup profile wipe.
    ///
    /// The URL is read at release time. If the publisher typed a different
    /// address while the engine was clearing, `queue_or_navigate` replaced
    /// the original value and this opens the address they most recently
    /// asked for; it never starts an early navigation merely because the UI
    /// was already responsive.
    fn finish_initial_navigation(&mut self) {
        if !self.initial_navigation_pending {
            return;
        }
        self.initial_navigation_pending = false;
        if self.close_after_session_wipe {
            return;
        }
        let _ = platform::load_initial_url(&self.webview, self.id, &self.url);
    }

    fn queue_or_navigate(&mut self, url: &str) -> Result<(), &'static str> {
        if self.initial_navigation_pending {
            self.url.clear();
            self.url.push_str(url);
            return Ok(());
        }
        self.webview.load_url(url).map_err(|_| "io")
    }

    pub fn record_history(&mut self, url: String) {
        if self.suppress_history {
            self.suppress_history = false;
            return;
        }
        let next = self.history_index.map_or(0, |i| i + 1);
        self.history.truncate(next);
        if self.history.last() != Some(&url) {
            self.history.push(url);
        }
        self.history_index = Some(self.history.len().saturating_sub(1));
    }

    // wry 0.55 exposes no native back/forward/reload API on its
    // WebView, and evaluating `history.back()` on the content webview is
    // forbidden by the security rules, so navigation history is kept here
    // and replayed with `load_url()`. "reload" is a re-fetch of the current
    // URL.
    pub fn history_back(&mut self) -> Result<(), &'static str> {
        let index = match self.history_index {
            Some(i) if i > 0 => i,
            _ => return Ok(()),
        };
        let url = self.history[index - 1].clone();
        self.history_index = Some(index - 1);
        self.suppress_history = true;
        self.webview.load_url(&url).map_err(|_| "io")
    }

    pub fn history_forward(&mut self) -> Result<(), &'static str> {
        let index = match self.history_index {
            Some(i) if i + 1 < self.history.len() => i,
            _ => return Ok(()),
        };
        let url = self.history[index + 1].clone();
        self.history_index = Some(index + 1);
        self.suppress_history = true;
        self.webview.load_url(&url).map_err(|_| "io")
    }

    pub fn history_reload(&mut self) -> Result<(), &'static str> {
        if self.url.is_empty() {
            return Ok(());
        }
        self.suppress_history = true;
        // A real reload, not a re-navigation. `load_url` to the current
        // address is a fresh navigation, and a navigation is allowed to be
        // answered entirely from the HTTP cache: a page inside its heuristic
        // freshness window is served with NO network traffic, so the button
        // could not pick up a changed page -- observed 2026-07-29 against a
        // server that had demonstrably changed. `reload()` carries browser
        // reload semantics on every engine (Chromium revalidates the main
        // document; WebKitGTK likewise), which is what a button drawn as a
        // circular arrow promises.
        self.webview.reload().map_err(|_| "io")
    }
}

/// The zoom steps, matching what mainstream browsers offer. Multiplicative
/// steps rather than fixed increments, so each press is the same perceived
/// change at any level.
const ZOOM_STEPS: &[f64] = &[
    0.5, 0.67, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0,
];

/// The nearest entry in [`ZOOM_STEPS`] to a factor the engine reports.
///
/// Ctrl+scroll produces levels that are not in the table -- 1.03, 1.4 -- and
/// `zoom_index` matches on exact equality, so an unsnapped value makes the
/// next Ctrl+`+` jump back to 110% from wherever the user had scrolled to
/// instead of stepping up from there.
fn snap_to_step(factor: f64) -> f64 {
    ZOOM_STEPS
        .iter()
        .copied()
        .min_by(|a, b| {
            (a - factor)
                .abs()
                .partial_cmp(&(b - factor).abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap_or(factor)
}

/// What to tell the user after a right-click copy: the message, and whether it
/// is an error.
///
/// Pure, so the three outcomes are testable without a clipboard or a display.
/// `stripped` is true ONLY when the URL actually changed -- saying tracking
/// parameters were removed from a URL that had none claims work that was not
/// done, which is the same reason the chrome drew this distinction before the
/// write moved into the process.
fn copy_result_message(wrote: bool, change: crate::ipc::LinkChange) -> (&'static str, bool) {
    use crate::ipc::LinkChange;
    if !wrote {
        return ("Could not copy that link", true);
    }
    // Says exactly which of the two things happened, never the more impressive
    // one. "Redirect skipped" on a link that only lost a utm_ would claim a
    // wrapper was found where there was none.
    let message = match change {
        LinkChange::Unchanged => "Link copied",
        LinkChange::Stripped => "Link copied, tracking parameters removed",
        LinkChange::Unwrapped => "Link copied, redirect skipped",
        LinkChange::UnwrappedAndStripped => {
            "Link copied, redirect skipped and tracking parameters removed"
        }
    };
    (message, false)
}

#[cfg(test)]
mod copy_message_tests {
    use super::copy_result_message;
    use crate::ipc::LinkChange;

    const EVERY_CHANGE: [LinkChange; 4] = [
        LinkChange::Unchanged,
        LinkChange::Stripped,
        LinkChange::Unwrapped,
        LinkChange::UnwrappedAndStripped,
    ];

    #[test]
    fn a_failed_write_is_reported_as_an_error_and_never_claims_a_copy() {
        for change in EVERY_CHANGE {
            let (message, error) = copy_result_message(false, change);
            assert!(error, "a failed clipboard write must be flagged as an error");
            assert!(
                !message.contains("copied"),
                "failure copy must not say the link was copied: {message}"
            );
        }
    }

    #[test]
    fn each_outcome_claims_exactly_what_happened_and_no_more() {
        assert_eq!(
            copy_result_message(true, LinkChange::Unchanged),
            ("Link copied", false)
        );
        assert_eq!(
            copy_result_message(true, LinkChange::Stripped),
            ("Link copied, tracking parameters removed", false)
        );
        assert_eq!(
            copy_result_message(true, LinkChange::Unwrapped),
            ("Link copied, redirect skipped", false)
        );
        assert_eq!(
            copy_result_message(true, LinkChange::UnwrappedAndStripped),
            (
                "Link copied, redirect skipped and tracking parameters removed",
                false
            )
        );
    }

    /// The failure this pins: a message that mentions a redirect when none was
    /// unwrapped, or parameters when none were removed. Either would report a
    /// protection the user did not receive.
    #[test]
    fn no_outcome_claims_a_change_it_did_not_make() {
        for change in EVERY_CHANGE {
            let (message, _) = copy_result_message(true, change);
            let says_redirect = message.contains("redirect");
            let says_params = message.contains("parameters");
            let did_unwrap = matches!(
                change,
                LinkChange::Unwrapped | LinkChange::UnwrappedAndStripped
            );
            let did_strip = matches!(
                change,
                LinkChange::Stripped | LinkChange::UnwrappedAndStripped
            );
            assert_eq!(says_redirect, did_unwrap, "{change:?}: {message}");
            assert_eq!(says_params, did_strip, "{change:?}: {message}");
        }
    }
}

#[cfg(test)]
mod zoom_snap_tests {
    use super::*;

    #[test]
    fn an_exact_step_is_left_alone() {
        for step in ZOOM_STEPS {
            assert_eq!(snap_to_step(*step), *step);
        }
    }

    #[test]
    fn a_scrolled_level_snaps_to_the_nearest_step() {
        // Ctrl+scroll lands between steps; these are the values the next
        // keypress has to continue sensibly from.
        assert_eq!(snap_to_step(1.03), 1.0);
        assert_eq!(snap_to_step(1.4), 1.5);
        assert_eq!(snap_to_step(0.72), 0.67);
        assert_eq!(snap_to_step(2.3), 2.5);
    }

    #[test]
    fn levels_beyond_the_table_clamp_to_its_ends() {
        assert_eq!(snap_to_step(0.1), 0.5);
        assert_eq!(snap_to_step(9.0), 3.0);
    }

    #[test]
    fn a_snapped_level_is_findable_again() {
        // The point of snapping: `zoom_index` matches on exact equality, so a
        // value that snapped must be one the step walk can find, or the next
        // keypress restarts from the default instead of continuing.
        for probe in [1.03, 1.4, 0.72, 2.3, 9.0] {
            let snapped = snap_to_step(probe);
            assert!(
                ZOOM_STEPS.iter().any(|z| (z - snapped).abs() < f64::EPSILON),
                "{probe} snapped to {snapped}, which is not a step"
            );
        }
    }
}

impl Tab {
    /// Step the zoom and apply it. `dir` is +1 to enlarge, -1 to shrink, 0 to
    /// reset.
    ///
    /// Clamped to the ends of the table rather than wrapping or growing
    /// without bound: a page at 20x is not a feature, and neither is one the
    /// user cannot read their way back from.
    pub fn zoom_step(&mut self, dir: i32) -> f64 {
        let current = self
            .zoom_index()
            .unwrap_or(ZOOM_STEPS.iter().position(|z| *z == 1.0).unwrap_or(4));
        self.zoom = match dir {
            0 => 1.0,
            d if d > 0 => ZOOM_STEPS[(current + 1).min(ZOOM_STEPS.len() - 1)],
            _ => ZOOM_STEPS[current.saturating_sub(1)],
        };
        // A failure here is not worth interrupting the user for: the zoom
        // simply did not change, which they can see.
        let _ = self.webview.zoom(self.zoom);
        self.zoom
    }

    fn zoom_index(&self) -> Option<usize> {
        ZOOM_STEPS
            .iter()
            .position(|z| (z - self.zoom).abs() < f64::EPSILON)
    }

    pub fn zoom_level(&self) -> f64 {
        self.zoom
    }

    /// Record a zoom the ENGINE applied. Does not call back into the engine:
    /// it already did the work, and re-applying would fight whatever the user
    /// is doing with Ctrl+scroll.
    ///
    /// Snapped to the nearest step so the next Ctrl+`+` continues from where
    /// the user actually is. Ctrl+scroll produces levels that are not in the
    /// table at all, and without snapping `zoom_index` returns None and the
    /// next keypress would jump back to 110% from wherever they had scrolled.
    fn note_engine_zoom(&mut self, factor: f64) {
        self.zoom = snap_to_step(factor);
    }

    /// Let this tab reach `host` despite the malicious-host list.
    ///
    /// Takes effect on the NEXT navigation; the caller reloads. Scoped to this
    /// tab and gone when it closes -- there is deliberately no way to make it
    /// permanent, because "allow forever" is how a one-off decision becomes a
    /// standing exemption the user cannot remember granting.
    pub fn allow_malicious_host(&self, host: &str) {
        self.malicious_override
            .borrow_mut()
            .insert(host.to_ascii_lowercase());
    }

    /// Let this tab reach `host` over plain HTTP. Same contract as
    /// `allow_malicious_host`: next navigation, this tab only, no permanent
    /// form.
    pub fn allow_insecure_host(&self, host: &str) {
        self.insecure_override
            .borrow_mut()
            .insert(host.to_ascii_lowercase());
    }
}

/// How long a plain-HTTP banner's subject is held still before a different
/// held-back URL may replace it.
///
/// A PAGE CHOOSES WHEN THIS FIRES AND WHAT IT NAMES. `location.href` in a
/// loop raises a fresh held navigation every few milliseconds, each one
/// rewriting the banner, so the host a person reads need not be the host
/// that was pending when their click landed: the browser's own trusted UI
/// becomes the delivery mechanism. The click is separately protected --
/// Continue names the host it displayed and Rust refuses a mismatch -- but a
/// banner flickering through attacker-chosen names is its own defect, and
/// rewriting it at 20 Hz also drives a dozen COM round-trips per frame
/// through `emit_tab_status` on the event-loop thread.
///
/// So a replacement is ignored while the current subject is younger than
/// this. The navigation is still held back either way; only the banner's
/// text is steadied. 750ms is long enough to defeat a tight loop and short
/// enough that a real second navigation is not left describing a stale one.
const INSECURE_BANNER_STABILITY: Duration = Duration::from_millis(750);

/// What a newly held-back plain-HTTP URL does to the banner already on
/// screen. Pure so `cargo test` can prove the rule without an engine.
#[derive(Debug, PartialEq, Eq)]
pub enum BannerUpdate {
    /// Nothing changed; emit nothing. A page retrying the same URL must not
    /// drive a status sweep per attempt.
    Unchanged,
    /// The current subject is younger than the stability window, so it keeps
    /// the banner. The navigation is still held back; only the relabel is
    /// refused.
    HoldSteady,
    /// Show the new subject.
    Replace,
}

pub fn banner_subject_update(
    current: Option<&str>,
    current_at: Option<Instant>,
    incoming: &str,
    now: Instant,
) -> BannerUpdate {
    match current {
        Some(pending) if pending == incoming => BannerUpdate::Unchanged,
        Some(_)
            if current_at.is_some_and(|at| now.duration_since(at) < INSECURE_BANNER_STABILITY) =>
        {
            BannerUpdate::HoldSteady
        }
        _ => BannerUpdate::Replace,
    }
}

/// Whether a Continue click belongs to the banner the user actually read.
///
/// The chrome echoes the host it DISPLAYED. If the held-back URL moved on
/// between the paint and the click -- the window above bounds how often that
/// can happen, it does not make it impossible -- the two disagree and the
/// click is refused. A confirmation, never a selection: this can only ever
/// agree or disagree with a URL that is already pending, so no value passed
/// here can name a destination of its own.
pub fn continue_matches_shown_banner(pending_url: &str, shown_host: &str) -> bool {
    host_of(pending_url).is_some_and(|host| shown_host.eq_ignore_ascii_case(&host))
}

/// Whether a navigation to `url` must be held back for the plain-HTTP
/// warning. `http:` only, and NOT for the user's own network: loopback,
/// `localhost`, RFC1918, link-local and CGNAT literals are exempt, the way
/// every shipping HTTPS-only mode exempts local addresses -- a router's admin page
/// or a device on the LAN is plain HTTP by construction, and a warning that
/// fires on every one of those teaches the user to click through it. Every
/// other http:// destination is warned about once per tab per host.
pub fn needs_insecure_warning(url: &str) -> bool {
    if !platform::privacy::is_insecure_page_url(url) {
        return false;
    }
    match host_of(url) {
        Some(host) => !platform::privacy::is_private_host(&host),
        // No parseable authority: not something the warning can name, and
        // `is_allowed_content_url` has already refused it upstream.
        None => false,
    }
}

impl Drop for Tab {
    fn drop(&mut self) {
        // unix: removes the container from its GTK parent. Windows: drops
        // this tab's cached main-resource bytes (up to the integrity cap),
        // which would otherwise outlive the tab in a process-lived map --
        // dropping the `webview` field below is what destroys the WebView2
        // itself.
        platform::remove_tab(&self.view, &self.webview);
    }
}

/// Builds one content tab through the platform layer (a hidden gtk::Box on
/// unix, a hidden WebView2 child window on Windows) holding a content
/// webview with all content security handlers. Every handler closure
/// captures the tab id and only sends `EventLoopProxy` events. The view
/// starts hidden; the caller decides visibility.
///
/// Fallible on purpose: see the comment at the `build_content` call below.
fn build_tab(
    hosts: &platform::Hosts,
    proxy: &EventLoopProxy<UserEvent>,
    id: u64,
    url: &str,
    policy: &platform::TabPolicy,
    // The session permission table, cloned into this tab's engine callback.
    // Passed rather than reached for: build_tab is a free function precisely
    // so it cannot touch AppState while AppState is mutably borrowed.
    permissions: crate::state::PermissionBook,
) -> Result<Tab, wry::Error> {
    let nav_proxy = proxy.clone();
    // Hosts this tab may visit despite the blocklist, because the user chose
    // to. PER TAB and dies with the tab: an override that outlived the tab
    // would be a permanent hole nobody remembers opening. Deliberately NOT
    // `allowed_hosts` (the freeze exemption) -- overloading one word for two
    // security decisions is how one of them ends up wrong.
    let malicious_override: Rc<RefCell<BTreeSet<String>>> = Rc::new(RefCell::new(BTreeSet::new()));
    let nav_allowed = malicious_override.clone();
    let insecure_override: Rc<RefCell<BTreeSet<String>>> = Rc::new(RefCell::new(BTreeSet::new()));
    let nav_insecure_allowed = insecure_override.clone();
    let load_proxy = proxy.clone();
    let title_proxy = proxy.clone();
    let new_window_proxy = proxy.clone();
    let download_start_proxy = proxy.clone();
    let download_done_proxy = proxy.clone();

    // ---- content webview: no custom protocol, no IPC, no script eval ----
    //
    // The initial URL is NOT set here. It travels to `build_content` and
    // each backend applies it only after its handlers are in place and the
    // asynchronous saved-profile wipe has completed. Giving either builder a
    // URL would let its construction start a navigation before those gates.
    // Built through the platform factory, not `WebViewBuilder::new()`: on
    // Windows that is where the WebView2 user-data directory is attached, and
    // it has to be attached at CONSTRUCTION (wry 0.55.1 has no
    // `with_web_context` setter). See platform::new_webview_builder.
    let builder = platform::new_webview_builder()
        // Developer tools, and ONLY on content. Set here rather than in the
        // shared factory so it can never depend on which builder call comes
        // last: the privileged chrome is built from the same factory and sets
        // its own `false` (release) in main.rs, and a reader should not have
        // to reason about ordering to know the boundary holds. Nothing
        // private lives in a page, and every browser lets a user inspect the
        // page in front of them.
        .with_devtools(true)
        // PURE ALLOWLIST. This must not be the source of the displayed URL.
        //
        // wry's navigation handler carries no frame information and is never
        // filtered to the main frame, so on WebKitGTK it fires for iframe
        // navigations too. Reporting those as the tab's URL let any page put an
        // arbitrary address in the URL bar by embedding an iframe, which is
        // straightforward spoofing, and polluted history with subframe URLs
        // that back/forward would then load as top-level pages. The displayed
        // URL now comes from the page-load handler below, which is main-frame
        // only on both engines.
        .with_navigation_handler(move |url: String| {
            // DEBUG BUILDS ONLY. Answers the one question reading the code
            // cannot: does NavigationStarting fire at all on WebView2 for a
            // given navigation, and if it does, what verdict does this closure
            // reach? Every link in this chain verifies on paper and the block
            // still does not happen on Windows, which is the point at which
            // guessing stops being worth anything.
            #[cfg(debug_assertions)]
            {
                let host = host_of(&url);
                let matched = host
                    .as_deref()
                    .and_then(crate::blocklist::matched_rule);
                println!(
                    "NAV url={url} host={host:?} matched={matched:?} set_len={}",
                    crate::blocklist::len()
                );
            }
            // Anything else (file://, the chrome origin, data:, ...) is denied.
            if !is_allowed_content_url(&url) {
                return false;
            }
            // KNOWN-MALICIOUS HOSTS. Refused here rather than in the content
            // filter -- see blocklist.rs for why -- and independently of
            // `block_ads`, so turning off ad blocking cannot silently turn off
            // malware blocking.
            //
            // The per-tab override is checked FIRST and lives in an Rc the
            // tab owns, so it dies with the tab. wry's handler bound is
            // `Fn(String) -> bool + 'static` with no `Send`, which is what
            // makes an Rc legal here.
            if let Some(host) = host_of(&url) {
                if !nav_allowed.borrow().contains(&host) {
                    if let Some(rule) = crate::blocklist::matched_rule(&host) {
                        // Reported, not silently dropped: a page that simply
                        // fails to load teaches the user the browser is
                        // broken. The chrome names the host and offers the
                        // override. No frame information is available here,
                        // so this fires for subframes too on WebKitGTK --
                        // which is right for BLOCKING and is why the report
                        // is a banner rather than a full-page interstitial
                        // that would replace a page the user is reading.
                        let _ = nav_proxy.send_event(UserEvent::NavigationBlocked {
                            tab_id: id,
                            host,
                            rule: rule.to_string(),
                        });
                        return false;
                    }
                }
            }
            // PLAIN HTTP, after the blocklist: a listed host gets the
            // stronger warning, not this one. Held back rather than loaded,
            // and the chrome asks; Continue puts the host in the per-tab
            // override and re-issues the SAME url, which passes here. Local
            // and private addresses never reach this arm (see
            // `needs_insecure_warning`). Same subframe caveat as the block
            // above on WebKitGTK; on WebView2 NavigationStarting is top-level
            // only.
            if needs_insecure_warning(&url) {
                let held = host_of(&url)
                    .is_some_and(|host| !nav_insecure_allowed.borrow().contains(&host));
                if held {
                    let _ = nav_proxy.send_event(UserEvent::InsecureNavigation { tab_id: id, url });
                    return false;
                }
            }
            true
        })
        .with_new_window_req_handler(move |url, _features| {
            // New windows stay denied; allowed targets get a background tab.
            //
            // This MUST be the same predicate the navigation handler uses. It
            // used to be a bare scheme test, which on Windows was a hole
            // straight through the trust boundary: the chrome document is
            // served at http://rbchrome.localhost/ there, so a page calling
            // window.open() on it passed the scheme test, and the tab that
            // opened bypassed the navigation handler entirely because a new
            // webview's initial with_url is not a navigation. An untrusted
            // page ended up on the origin that holds IPC and the vault.
            if is_allowed_content_url(&url) {
                let _ = new_window_proxy.send_event(UserEvent::OpenInNewTab(url));
            }
            wry::NewWindowResponse::Deny
        })
        // Main-frame only on both engines (WebKitGTK load-changed reports
        // webview.uri(), WebView2 ContentLoading reports the top-level Source),
        // which is why the displayed URL and history are driven from here
        // rather than from the navigation handler.
        .with_on_page_load_handler(move |event, url| {
            let loading = matches!(event, PageLoadEvent::Started);
            if loading {
                let _ = load_proxy.send_event(UserEvent::UrlChanged(id, url));
            }
            let _ = load_proxy.send_event(UserEvent::LoadState(id, loading));
        })
        .with_document_title_changed_handler(move |title| {
            let _ = title_proxy.send_event(UserEvent::TitleChanged(id, title));
        })
        .with_download_started_handler(move |url, destination| {
            *destination = unique_download_path(&url, destination);
            let _ = download_start_proxy.send_event(UserEvent::DownloadStarted(url));
            true
        })
        .with_download_completed_handler(move |url, path, success| {
            let _ = download_done_proxy.send_event(UserEvent::DownloadDone {
                url,
                path: path.map(|p| p.to_string_lossy().into_owned()),
                success,
            });
        })
        .with_devtools(cfg!(debug_assertions));

    // A CONSTRUCTION FAILURE IS A VALUE, NOT A PANIC.
    //
    // This was `.expect("failed to build content webview")`, and it was
    // reachable from web content: a page calling `window.open()` raises
    // `UserEvent::OpenInNewTab`, which lands here after the origin and
    // MAX_TABS checks. There is no `catch_unwind` anywhere in the workspace
    // and this runs inside the tao event-loop closure, so any engine-side
    // failure -- GPU process loss, a COM error, memory pressure -- took the
    // whole browser down: every tab gone, the vault dropped mid-session, and
    // on Windows a panic crossing the `extern "system"` message pump aborts
    // rather than unwinds. A page could reach that on purpose.
    //
    // The caller decides what to do instead; nothing here can.
    let (webview, view, initial_navigation_pending) =
        platform::build_content(
            hosts,
            builder,
            policy,
            proxy,
            url,
            malicious_override.clone(),
            id,
            permissions.clone(),
        )?;
    // The engine zooms on keys this process never sees; this is how the
    // indicator learns about it.
    platform::connect_zoom_changed(&webview, proxy, id);
    // Download plumbing wry cannot express on its own: the webkit2gtk
    // Response-policy workaround on unix, a no-op on Windows where wry's
    // download handlers are implemented natively.
    platform::fix_downloads(&webview);
    // What the platform layer just did, captured from the same inputs it
    // used rather than re-derived later.
    let divergence_built = platform::privacy::divergence_script(policy.ephemeral).is_some();

    Ok(Tab {
        id,
        view,
        webview,
        url: url.to_string(),
        title: String::new(),
        ephemeral: policy.ephemeral,
        blocked_pending: std::cell::RefCell::new(None),
        block_ads: policy.block_ads,
        divergence_registered: divergence_built,
        translation: None,
        translation_extracted: 0,
        translation_patched: 0,
        detected_lang: None,
        translate_continue: None,
        initial_navigation_pending,
        close_after_session_wipe: false,
        fingerprint_probes: FingerprintProbeCounts::default(),
        history: Vec::new(),
        history_index: None,
        suppress_history: false,
        zoom: 1.0,
        malicious_override,
        insecure_override,
        insecure_pending: None,
        insecure_pending_at: None,
        adlist: crate::adlist_consent::AdlistConsent::default(),
    })
}

/// Directory downloads are written to; created if missing.
pub fn download_dir() -> PathBuf {
    // unix follows XDG; Windows uses the per-user Downloads folder. (The
    // FOLDERID_Downloads "known folder" API would need a WinAPI dependency;
    // %USERPROFILE%\Downloads matches the default location.)
    #[cfg(unix)]
    let dir = std::env::var_os("XDG_DOWNLOAD_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Downloads")))
        .unwrap_or_else(|| PathBuf::from("./Downloads"));
    #[cfg(windows)]
    let dir = std::env::var_os("USERPROFILE")
        .filter(|value| !value.is_empty())
        .map(|profile| PathBuf::from(profile).join("Downloads"))
        .unwrap_or_else(|| PathBuf::from("./Downloads"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Destination for an incoming download: `download_dir()` plus a sanitized,
/// collision-free file name derived from the suggested path (falling back to
/// the URL's last path segment, then to `download`).
/// A filename for a page saved as PDF, derived from its host and path.
///
/// The HOST leads, because a folder full of "index.pdf" is useless. Falls back
/// to a fixed name rather than to anything derived from a URL that did not
/// parse; `sanitize_filename` then does the platform-specific work, and
/// `unique_download_path` handles collisions.
pub(crate) fn pdf_name_for(url: &str) -> String {
    let host = host_of(url).unwrap_or_else(|| "page".to_string());
    let slug: String = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .chars()
        .take(48)
        .collect();
    if slug.is_empty() || slug == host {
        format!("{host}.pdf")
    } else {
        format!("{host}-{slug}.pdf")
    }
}

fn unique_download_path(url: &str, suggested: &Path) -> PathBuf {
    let raw = suggested
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .or_else(|| {
            url.split(|c| c == '?' || c == '#')
                .next()
                .and_then(|base| base.rsplit('/').next())
                .filter(|segment| !segment.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "download".to_string());
    let name = sanitize_filename(&raw);
    let dir = download_dir();
    let candidate = dir.join(&name);
    if !candidate.exists() {
        return candidate;
    }
    // Collision: insert " (n)" before the (last) extension.
    let (stem, ext) = match name.rfind('.') {
        Some(pos) if pos > 0 => (&name[..pos], &name[pos..]),
        _ => (&name[..], ""),
    };
    let mut n = 1u32;
    loop {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

// Filename sanitization is platform-aware: a hostile Content-Disposition
// name must not be able to escape the download directory (path separators,
// leading dots) nor, on Windows, use characters or device names the OS
// treats specially in every directory.

#[cfg(unix)]
fn sanitize_filename(name: &str) -> String {
    // Direction overrides and zero-width characters go FIRST, on both
    // platforms (security audit 2026-08-18, Phase 6). A file name is a
    // display surface: `invoice\u{202E}gpj.exe` renders in a file manager as
    // `invoiceexe.jpg`, so a user who has been taught to check the extension
    // checks it and is told the wrong answer. The predicate is the same one
    // `hover.rs` uses to stop a link text lying about its target -- one
    // definition, because the two problems are the same problem.
    let stripped: String = name
        .chars()
        .filter(|c| !crate::hover::is_deceptive(*c))
        .filter(|c| *c != '/' && *c != '\\')
        .collect();
    let stripped = stripped.trim_start_matches('.');
    if stripped.is_empty() {
        "download".to_string()
    } else {
        stripped.to_string()
    }
}

#[cfg(windows)]
fn sanitize_filename(name: &str) -> String {
    // Win32 forbids < > : " / \ | ? * and ASCII control characters in file
    // names; replace them (rather than remove, so a crafted name cannot
    // collapse into a traversal like ".." or an alternate-data-stream ":").
    let mapped: String = name
        .chars()
        // Direction overrides and zero-width characters first: see the unix
        // arm above. `invoice\u{202E}gpj.exe` displays as `invoiceexe.jpg`,
        // and Explorer is exactly where a user checks an extension before
        // double-clicking. Same predicate as the hover readout uses.
        .filter(|c| !crate::hover::is_deceptive(*c))
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    // Leading dots hide files (same as unix); trailing dots/spaces are
    // silently stripped by Win32, which would change the name AFTER the
    // collision check in unique_download_path ran.
    let trimmed = mapped
        .trim_start_matches('.')
        .trim_end_matches(|c| c == '.' || c == ' ');
    // DOS device names are reserved in every directory, with any extension
    // (CON.txt still opens the console), so neutralize them by prefix.
    const DEVICES: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = trimmed.split('.').next().unwrap_or_default();
    if trimmed.is_empty() {
        "download".to_string()
    } else if DEVICES.iter().any(|dev| stem.eq_ignore_ascii_case(dev)) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// Outcome of re-checking a downloaded file against the fingerprint recorded
/// at completion. `as_str` is the IPC vocabulary the downloads view speaks.
pub enum FileVerdict {
    Match,
    Differs,
    Missing,
    Unreadable,
}

impl FileVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileVerdict::Match => "match",
            FileVerdict::Differs => "differs",
            FileVerdict::Missing => "missing",
            FileVerdict::Unreadable => "unreadable",
        }
    }
}

/// SHA-256 of a file, streamed in 64 KiB reads — downloads can be far larger
/// than a single in-memory read should assume. Returns the digest and the
/// exact number of bytes that went into it (which is what the stored record's
/// `byte_len` must describe).
pub fn hash_file(path: &Path) -> std::io::Result<([u8; 32], u64)> {
    use sha2::Digest;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = std::io::Read::read(&mut file, &mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        total += read as u64;
    }
    Ok((hasher.finalize().into(), total))
}

/// Re-check a recorded download: the bare file name is looked up in the
/// current download directory and re-hashed against the record.
pub fn check_download_file(filename: &str, sha256: &[u8; 32]) -> FileVerdict {
    check_download_file_in(&download_dir(), filename, sha256)
}

fn check_download_file_in(dir: &Path, filename: &str, sha256: &[u8; 32]) -> FileVerdict {
    // `filename` comes out of an HMAC-verified record and was sanitized when
    // the download landed. A separator here therefore means something is
    // deeply wrong, so refuse rather than follow it out of the download
    // directory — defense in depth behind the HMAC gate.
    if filename.is_empty()
        || Path::new(filename).file_name().and_then(|n| n.to_str()) != Some(filename)
    {
        return FileVerdict::Unreadable;
    }
    match hash_file(&dir.join(filename)) {
        Ok((hash, _)) => {
            if &hash == sha256 {
                FileVerdict::Match
            } else {
                FileVerdict::Differs
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => FileVerdict::Missing,
        Err(_) => FileVerdict::Unreadable,
    }
}

pub struct AppState {
    /// The string catalog. English-only until the locale setting exists;
    /// lives here because resolution is per-call on the UI thread and a
    /// locale change must repaint everything (see i18n.rs on why there is
    /// no cache anywhere).
    pub i18n: crate::i18n::I18n,
    /// Bumped on every accepted locale change; rides every fill snapshot so
    /// the chrome can refuse a stale one instead of painting a mixed-language
    /// UI out of a race.
    pub locale_generation: u64,
    /// Bumped on every translation START, and never reused.
    ///
    /// PER BROWSER RATHER THAN PER TAB, deliberately: a token that restarted
    /// at 1 in each tab would collide across tabs, and the value's whole job
    /// is to be unmistakable. Wrapping is not a concern at one per user click.
    translation_seq: u64,
    /// The hidden translator webview, built on first use and kept afterwards.
    /// `None` until somebody translates something; see `translator()`.
    translator: Option<WebView>,
    /// Live while a translation is in flight. Dropping it stops the poll
    /// thread, which is what keeps an idle browser from ticking.
    translate_polling: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// The last batch a page sent up, kept for the debug self-test only.
    ///
    /// DEBUG BUILDS ONLY, and this is not a formality: it is a copy of what
    /// the user was reading, and a release binary must not hold one for a
    /// moment longer than translating it requires. The live path clears
    /// `session.batch` the instant the translation is handed back; this field
    /// exists so a self-test can SEE what came up, and it is compiled out of
    /// anything that ships.
    #[cfg(debug_assertions)]
    last_extracted: Vec<String>,
    /// The pair currently downloading, if any. One at a time: two concurrent
    /// 36 MB downloads for the same profile would be the same bytes twice.
    /// Packs currently downloading, keyed by token, each with (bytes_so_far,
    /// total). Generalised from a single Option when explicit Install arrived:
    /// installing a language fetches BOTH directions, and a translate-triggered
    /// download can run beside a user-initiated one. Single-flight is now
    /// per-token, not global.
    pack_downloads: std::collections::BTreeMap<&'static str, (u64, Option<u64>)>,
    /// Why a pack download STOPPED, per pair, kept until that pair is tried
    /// again.
    ///
    /// Without this the key died at `on_pack_installed`: only a translation
    /// waiting on that exact pair consumed it, and every other route -- a
    /// user's Install click above all -- dropped it on the floor. A download
    /// that failed and one still running then rendered identically, which is
    /// to say not at all. Reported, not swallowed.
    pack_failures: std::collections::BTreeMap<&'static str, &'static str>,
    pub vault: Option<Vault>,
    pub vault_path: PathBuf,
    /// Bookmark/provenance store. Session-lifetime BY DESIGN: it opens
    /// alongside the vault (same passphrase, separate file, separate key via
    /// domain separation) and is NOT dropped when the vault locks. See the
    /// Notes in `lock_vault`/`check_autolock` — the brief asked for
    /// lock-step behavior and this deliberately deviates, for the reasons
    /// the store crate's own docs give.
    pub store: Option<Store>,
    pub store_path: PathBuf,
    /// Why the store failed to open alongside the vault, if it did. Surfaced
    /// through `store_status` so the UI can say what happened instead of
    /// showing a silently empty panel.
    store_error: Option<&'static str>,
    pub last_activity: Instant,
    /// Idle timeout in seconds, 0 meaning never. Cached from prefs rather than
    /// re-read from disk: this is consulted on every pass of the event loop.
    pub autolock_secs: u64,
    /// Whether the "about to lock" warning has already been raised for the
    /// current idle stretch. Cleared by `touch`, so acting on the warning --
    /// which is itself activity -- re-arms it for next time.
    lock_warning_sent: bool,
    pub tabs: Vec<Tab>,
    pub active: usize,
    /// Find session of the ACTIVE tab, per-tab by construction: the
    /// tab-switch path stops it and tab teardown unwires it, so one slot
    /// never has to describe two tabs. The query lives only here and inside
    /// the engine; nothing is persisted, for any tab kind.
    pub find: crate::find::FindSession,
    /// THE one source of find generations in the process (see find.rs):
    /// find-in-page and the cross-tab scan both draw from it, so a number
    /// can never describe two different searches of any kind.
    pub find_gen: crate::find::GenSeq,
    /// The live cross-tab search, if any: one row per scanned tab, in tab
    /// strip order, filled as the engine's byte reads answer. Replaced
    /// wholesale by each new find_tabs_search and dropped by lock_vault --
    /// never cancelled row by row (TabScan's id, drawn from find_gen, is
    /// what makes a dropped scan's late reads harmless).
    pub tab_scan: Option<crate::tab_search::TabScan>,
    /// Quarantine tabs skipped when the live scan was started. Snapshots
    /// word this number long after start, so it is stored with the scan
    /// rather than recomputed against tabs that may have opened or closed
    /// since; meaningless, unread and reset while tab_scan is None.
    tab_scan_skipped_quarantine: usize,
    /// Monotonically increasing; never reused even after tabs close.
    next_tab_id: u64,
    /// Ids for blocked-navigation banners (see note_navigation_blocked).
    blocked_pending_seq: u64,
    /// Platform host areas (chrome/content containers on unix, the parent
    /// window on Windows).
    pub hosts: platform::Hosts,
    /// Cloned into every tab's webview handlers.
    proxy: EventLoopProxy<UserEvent>,
    /// Chrome webview — the ONLY webview we may call `evaluate_script` on.
    chrome: WebView,
    /// Current chrome strip height in logical pixels. Stored here (not only
    /// on the GTK widget) because Windows must re-apply it on every resize.
    chrome_height: i32,
    /// Width the chrome is using down the LEFT edge, in logical pixels.
    ///
    /// Zero in the Top layout, which is every build before the sidebar
    /// existed. A second number rather than a signed height because the two
    /// axes are independent: a panel opening grows the top inset and must
    /// not disturb the left one, and the sidebar is present whether or not a
    /// panel is open.
    chrome_left: i32,
    /// Width the chrome is using down the RIGHT edge, in logical pixels.
    /// The independent mirror of `chrome_left`: panels can change the top
    /// inset without disturbing either side, and only one toolbar strip is
    /// normally non-zero.
    chrome_right: i32,
    /// The top inset of the CLOSED chrome, remembered across a panel.
    ///
    /// `chrome_height` holds whatever the chrome last asked for, which while
    /// a panel is open is the panel's height. Coming back to a strip needs
    /// the closed number, and it used to be read from `CHROME_HEIGHT_PX` --
    /// correct only by luck, and only for one layout. The sidebar's closed
    /// strip is ~88 and the constant is 120, so the frame between the
    /// arrangement message and the height message would have shoved the page
    /// down by 32px on every panel close. This is that constant, made honest.
    closed_chrome_height: i32,
    /// The chrome's resolved colours as last reported (or as persisted, until
    /// the chrome speaks). Kept here because the Windows title bar FORGETS
    /// them across a maximize/restore -- seen 2026-08-17: the caption went
    /// back to the system colour on maximize while an outside call painted
    /// it fine in that state -- so `relayout` re-applies them on every
    /// layout pass. Reading prefs there would be a file read per resize.
    chrome_palette: platform::ChromePalette,
    /// Whether the window was maximized the last time `relayout` looked.
    /// A change here is what triggers the full title-bar re-apply WITH the
    /// frame refresh: DWM repaints the maximized frame in the system colour
    /// and only a refresh brings ours back (writing the same value again is
    /// a no-op to it -- seen 2026-08-17). A `Cell` because `relayout` is
    /// `&self`; `None` until the first layout so boot counts as a change.
    window_maximized_seen: std::cell::Cell<Option<bool>>,
    /// Whether the chrome is covering the window instead of sitting in a strip.
    ///
    /// SEPARATE FROM `chrome_height`, and deliberately not just a taller
    /// height. The clamp on `set_chrome_height` exists to stop a stray number
    /// swallowing the window -- the panel that once grew this strip by 300px
    /// of empty band is why -- and folding "cover" into that number would
    /// delete the guard to gain the feature. A panel that wants the whole
    /// window has to ASK for it by name, through a command that carries no
    /// arithmetic to get wrong.
    /// How the chrome and the page currently share the window.
    chrome_arrangement: platform::ChromeLayout,
    /// Browser-wide privacy policy. Applied to every existing tab when it
    /// changes and inherited by new ones, so "block ads" means the browser
    /// rather than whichever tab happened to be focused when it was toggled.
    /// `ephemeral` is the exception: a WebContext is fixed once its view
    /// exists, so it only affects tabs opened afterwards.
    pub privacy: platform::TabPolicy,
    /// Whether this launch was handed a URL to open, rather than being started
    /// on its own.
    ///
    /// The difference is INTENT, and the vault's startup behaviour turns on
    /// it. Someone who opened PATANYX from their desktop meant to use the
    /// browser, so being offered the vault is what they came for. Someone who
    /// clicked a link in another application meant to read THAT PAGE, and the
    /// browser they had set as default is incidental -- covering the page they
    /// asked for with a passphrase prompt would be an interruption, not a
    /// service. Set from the positional argument in `main`, which is how a
    /// default browser is handed a link on both platforms.
    pub opened_with_url: bool,
    pub smoke_mode: bool,
    /// Set once the behavioural blocking probe has navigated, so the smoke
    /// exit does not fire before the page has had a chance to make requests.
    pub probe_started: bool,
    /// Pings seen from chrome.js. In smoke mode the first ping proves the
    /// JS->Rust IPC path; a second, requested via `evaluate_script`, proves
    /// the Rust->JS path as well.
    pub ping_count: u32,
    /// Files the USER picked through a native dialog, keyed by a one-shot
    /// token.
    ///
    /// WHY A TOKEN RATHER THAN THE PATH. `ocr_scan` used to take a path
    /// straight from IPC under a comment describing it as "a path the user
    /// just chose" -- nothing connected the two. The chrome could name any
    /// file on disk, and the reply distinguishes "read it" from "could not",
    /// which is a file-existence and size oracle on top of a bounded
    /// arbitrary-file read. The path now never travels back across the
    /// boundary: the dialog records it here and hands out a token.
    ///
    /// Bounded and one-shot: redeeming removes the entry, and the oldest is
    /// dropped past `MAX_PICKED_PATHS`, so this cannot grow and a token cannot
    /// be replayed.
    pub picked_paths: std::collections::VecDeque<(u64, PathBuf)>,
    pub next_pick_token: u64,
    /// An activation or release result that arrived while the vault was
    /// LOCKED. It used to be dropped, which for a release meant the server
    /// had freed the slot while this vault kept its receipt: Premium came
    /// back at the next unlock on a device the server no longer counted.
    /// Replayed by `activation::replay_pending` right after the next unlock
    /// evaluation. In memory only: a process exit in between still loses it.
    pub pending_activation_event: Option<crate::activation::ActivationEvent>,
    /// What the capture currently in flight is FOR. Written by the IPC arm
    /// that set `CAPTURE_IN_FLIGHT`, read once by `on_capture_done`. A single
    /// value is enough because the in-flight flag admits one capture at a
    /// time; see `capture::CaptureIntent`.
    pub capture_intent: crate::capture::CaptureIntent,
    /// Smoke only: the second ping has been ASKED for. Distinguishes "the
    /// webview never came up" from "the reply is still in flight", which the
    /// single deadline used to conflate.
    pub smoke_second_ping_requested: bool,
    /// Smoke only: deadline ticks seen. Bounds the reprieve so a second ping
    /// that never arrives still fails instead of re-arming forever.
    pub smoke_deadline_ticks: u32,
    pub smoke_vault_done: bool,
    /// In-flight page-byte reads and corroboration requests. Memory only.
    pub integrity: crate::page_integrity::IntegrityState,
    /// Outstanding download comparisons we asked for. Memory only, like the
    /// page-corroboration map beside it.
    #[cfg(feature = "chat")]
    pub download_compare: crate::download_compare::DownloadCompareState,
    /// A password a content tab just submitted, waiting on the user's Save/
    /// Never. NEVER PERSISTED: this field is the entire lifetime of that
    /// password outside the vault -- it exists here only from the moment the
    /// content script posts a submission to the moment `cred_save_confirm`
    /// writes it (dropping this) or `cred_save_dismiss`/a navigation/a tab
    /// switch clears it unwritten. See `note_login_submitted`.
    pending_save: Option<PendingSave>,
    /// When the locked-vault save notice was last shown, for the cooldown.
    /// A single global timestamp, NOT a per-tab or per-origin map: the notice
    /// names no site, so there is nothing to key it by, and a review showed a
    /// remembered (tab, origin) pair cannot enforce "once per pair" anyway
    /// once submissions from two tabs interleave.
    last_locked_save_notice: Option<Instant>,
    /// PDF renders in flight, keyed by destination path, valued by the URL
    /// they were started from. The engine answers asynchronously and the tab
    /// may have navigated by then, so the source URL cannot be re-read at
    /// completion time -- it has to be remembered here.
    pending_pdf: std::collections::HashMap<String, String>,
    /// Chat transport handle and session mirror. Absent from the default build.
    #[cfg(feature = "chat")]
    pub chat: crate::chat_panel::ChatState,
    /// Site permission grants and denials for THIS SESSION.
    ///
    /// Session-only by construction, which is a product promise rather than an
    /// implementation detail: this is process memory, nothing ever serialises
    /// it, and it dies with the browser. Nothing here touches prefs (which
    /// forbids secrets anyway) or the vault. The engine callback holds a clone
    /// of the same handle, so the decision is made against one table on
    /// whatever thread the engine picks.
    pub permissions: PermissionBook,
}

/// The permission kinds this product polices.
///
/// Deliberately four. Clipboard read, autoplay, local fonts and the rest are
/// out of scope: their events are left to the engine default and nothing here
/// records them, so the UI never implies a control it does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermKind {
    Camera,
    Microphone,
    Geolocation,
    Notifications,
}

impl PermKind {
    pub fn from_ipc(name: &str) -> Option<Self> {
        match name {
            "camera" => Some(Self::Camera),
            "microphone" => Some(Self::Microphone),
            "geolocation" => Some(Self::Geolocation),
            "notifications" => Some(Self::Notifications),
            _ => None,
        }
    }

    pub fn as_ipc(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Microphone => "microphone",
            Self::Geolocation => "geolocation",
            Self::Notifications => "notifications",
        }
    }

    pub const ALL: [Self; 4] = [
        Self::Camera,
        Self::Microphone,
        Self::Geolocation,
        Self::Notifications,
    ];
}

/// A site permission key: the origin that ASKED, which is not always the site
/// in the address bar.
///
/// An embedded frame gets its own entry rather than inheriting the top-level
/// grant. Allowing example.com must never hand the camera to an advertising
/// iframe it happens to embed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PermKey {
    pub origin: String,
    pub kind: PermKind,
}

/// A denied request, kept so the privacy panel can offer it back as a toggle.
#[derive(Debug, Clone, Default)]
pub struct DeniedRecord {
    pub count: u64,
    /// Top-level origins this frame asked from, so the panel can show a
    /// frame's request on the tab where it happened.
    pub seen_under: std::collections::BTreeSet<String>,
}

/// The largest number of distinct denied keys retained.
///
/// Page content chooses these origins, so without a cap a hostile page can
/// mint subdomains until the process runs out of memory. Session-only bounds
/// the DURATION of the growth, not its peak. On overflow the table stops
/// accepting NEW keys and keeps counting existing ones: dropping an entry a
/// user might be about to allow is worse than declining to remember one more.
const MAX_DENIED_KEYS: usize = 512;

#[derive(Debug, Default)]
struct PermTable {
    grants: std::collections::BTreeSet<PermKey>,
    denied: std::collections::BTreeMap<PermKey, DeniedRecord>,
}

/// Session-only site permission ledger. Cheap to clone; every clone is the
/// same table.
#[derive(Debug, Clone, Default)]
pub struct PermissionBook(std::sync::Arc<std::sync::Mutex<PermTable>>);

impl PermissionBook {
    /// The one question the engine asks, on whatever thread it likes.
    ///
    /// True ONLY on an explicit session grant for the origin that actually
    /// asked. Every other path denies and is counted: never asked, revoked,
    /// an unusable origin, or a poisoned lock. Fail closed, always -- a
    /// permission check that cannot reach its table must not answer yes.
    pub fn decide(&self, requesting_origin: &str, top_origin: &str, kind: PermKind) -> bool {
        let Some(origin) = normalize_origin(requesting_origin) else {
            return false;
        };
        let key = PermKey { origin, kind };
        let Ok(mut table) = self.0.lock() else {
            return false;
        };
        if table.grants.contains(&key) {
            return true;
        }
        let at_cap = table.denied.len() >= MAX_DENIED_KEYS;
        if let Some(record) = table.denied.get_mut(&key) {
            record.count = record.count.saturating_add(1);
            if let Some(top) = normalize_origin(top_origin) {
                record.seen_under.insert(top);
            }
        } else if !at_cap {
            let mut record = DeniedRecord {
                count: 1,
                ..Default::default()
            };
            if let Some(top) = normalize_origin(top_origin) {
                record.seen_under.insert(top);
            }
            table.denied.insert(key, record);
        }
        false
    }

    /// Grants for the session. False when the origin is unusable.
    pub fn grant(&self, origin: &str, kind: PermKind) -> bool {
        let Some(origin) = normalize_origin(origin) else {
            return false;
        };
        let key = PermKey { origin, kind };
        let Ok(mut table) = self.0.lock() else {
            return false;
        };
        // The denial RECORD IS NOT REMOVED, only its count reset. That record
        // is the only thing remembering which tabs this origin asked from, and
        // for an embedded frame the frame's origin is not the tab's, so
        // dropping it here would make a just-granted frame permission vanish
        // from the panel of the very tab the user granted it on -- leaving no
        // way to revoke it from the context where it matters.
        if let Some(record) = table.denied.get_mut(&key) {
            record.count = 0;
        }
        table.grants.insert(key);
        true
    }

    pub fn revoke(&self, origin: &str, kind: PermKind) -> bool {
        let Some(origin) = normalize_origin(origin) else {
            return false;
        };
        let Ok(mut table) = self.0.lock() else {
            return false;
        };
        table.grants.remove(&PermKey { origin, kind });
        true
    }

    /// What the panel shows for the tab currently on `top_origin`: everything
    /// granted to that origin, plus anything denied while the user was there,
    /// including frames whose own origin differs.
    pub fn status_for(&self, top_origin: &str) -> Vec<(PermKey, bool, u64)> {
        let Some(top) = normalize_origin(top_origin) else {
            return Vec::new();
        };
        let Ok(table) = self.0.lock() else {
            return Vec::new();
        };
        let mut out: std::collections::BTreeMap<PermKey, (bool, u64)> =
            std::collections::BTreeMap::new();
        for (key, record) in &table.denied {
            if record.seen_under.contains(&top) {
                out.insert(key.clone(), (false, record.count));
            }
        }
        // A grant stays visible on the tab it is active under even if it was
        // first granted elsewhere, so it can always be revoked from context.
        for key in &table.grants {
            if key.origin == top || out.contains_key(key) {
                out.insert(key.clone(), (true, 0));
            }
        }
        out.into_iter()
            .map(|(key, (granted, count))| (key, granted, count))
            .collect()
    }
}

/// Reduces a URL or origin to a comparable `scheme://host[:port]`, or None
/// when it cannot be a permission subject.
///
/// REJECTS opaque and malformed origins outright rather than turning them into
/// keys. "null", "about:blank" and a bare "https://" are not sites; accepting
/// them would collapse unrelated sandboxed documents onto one grant, so a
/// single allow could speak for all of them. Default ports are dropped so
/// `https://example.com` and `https://example.com:443` cannot become two
/// entries the user has to allow twice.
pub fn normalize_origin(input: &str) -> Option<String> {
    let input = input.trim();
    let (scheme, rest) = if let Some(rest) = input.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = input.strip_prefix("http://") {
        ("http", rest)
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rfind(':') {
        Some(at) if !authority[at..].contains(']') => {
            let port = &authority[at + 1..];
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (&authority[..at], Some(port))
        }
        _ => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    let host_lower = host.to_ascii_lowercase();
    if host_lower.starts_with('[') {
        if !host_lower.ends_with(']') || host_lower.len() <= 2 {
            return None;
        }
    } else {
        let ok = !host_lower.starts_with('.')
            && !host_lower.ends_with('.')
            && !host_lower.contains("..")
            && host_lower
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
        if !ok {
            return None;
        }
    }
    let default_port = if scheme == "https" { "443" } else { "80" };
    match port {
        Some(p) if p != default_port => Some(format!("{scheme}://{host_lower}:{p}")),
        _ => Some(format!("{scheme}://{host_lower}")),
    }
}

/// See `AppState::pending_save`. `origin` is what the content script itself
/// reported (`location.origin`) -- trusted no further than any other content
/// input, which is why `cred_save_confirm` re-derives the ORIGIN IT ACTUALLY
/// SAVES UNDER from `Tab.url` (the same tracked field `forget_active_tab_
/// cookies` and `active_tab_status`'s `origin` use), not from this struct.
/// This copy exists only to show the user which site the offer is for.
pub(crate) struct PendingSave {
    pub(crate) tab_id: u64,
    origin: String,
    pub(crate) username: String,
    pub(crate) password: String,
}

impl AppState {
    pub fn new(
        chrome: WebView,
        hosts: platform::Hosts,
        proxy: EventLoopProxy<UserEvent>,
        smoke_mode: bool,
    ) -> Self {
        Self {
            // The stored locale, with the two failure modes kept apart on
            // purpose (BootstrapError's docs carry the ruling): an UNKNOWN
            // tag -- a prefs file from a build that carried more locales --
            // falls back to English with an id-free log, while a compiled
            // catalog failing validation is a build defect and panics, in a
            // build the i18n tests already fail.
            i18n: match crate::i18n::I18n::bootstrap(&crate::prefs::load().ui_locale) {
                Ok(l10n) => l10n,
                Err(crate::i18n::BootstrapError::UnknownLocale) => {
                    // The tag itself stays out of the log: it is a stored
                    // user preference, and ids-not-values applies to it too.
                    eprintln!("i18n: stored locale unknown to this build; using en");
                    crate::i18n::I18n::bootstrap("en")
                        .expect("the embedded English catalog is valid")
                }
                Err(crate::i18n::BootstrapError::InvalidCatalog(why)) => {
                    panic!("compiled catalog invalid: {why}")
                }
            },
            locale_generation: 1,
            translation_seq: 0,
            translator: None,
            translate_polling: None,
            #[cfg(debug_assertions)]
            last_extracted: Vec::new(),
            pack_downloads: std::collections::BTreeMap::new(),
            pack_failures: std::collections::BTreeMap::new(),
            vault: None,
            vault_path: Vault::default_path(),
            store: None,
            store_path: Store::default_path(),
            store_error: None,
            last_activity: Instant::now(),
            autolock_secs: crate::prefs::load().vault_autolock_secs,
            lock_warning_sent: false,
            tabs: Vec::new(),
            active: 0,
            find: crate::find::FindSession::default(),
            find_gen: crate::find::GenSeq::default(),
            tab_scan: None,
            tab_scan_skipped_quarantine: 0,
            next_tab_id: 1,
            blocked_pending_seq: 0,
            hosts,
            proxy,
            chrome,
            chrome_height: platform::CHROME_HEIGHT_PX,
            closed_chrome_height: platform::CHROME_HEIGHT_PX,
            chrome_palette: crate::prefs::load().chrome_palette,
            window_maximized_seen: std::cell::Cell::new(None),
            // Zero until the chrome reports otherwise, in BOTH layouts. The
            // saved placement is a chrome-side fact; Rust learns the sidebar
            // exists when the chrome measures it, one round trip after boot,
            // the same way it learns the strip's height.
            chrome_left: 0,
            chrome_right: 0,
            chrome_arrangement: platform::ChromeLayout::Strip,
            privacy: platform::TabPolicy::default(),
            // Defaults to "opened on its own"; `main` sets it from the
            // positional argument once that has been parsed.
            opened_with_url: false,
            smoke_mode,
            probe_started: false,
            ping_count: 0,
            picked_paths: std::collections::VecDeque::new(),
            pending_activation_event: None,
            next_pick_token: 1,
            capture_intent: crate::capture::CaptureIntent::SaveFile,
            smoke_second_ping_requested: false,
            smoke_deadline_ticks: 0,
            smoke_vault_done: false,
            integrity: crate::page_integrity::IntegrityState::default(),
            #[cfg(feature = "chat")]
            download_compare: crate::download_compare::DownloadCompareState::default(),
            pending_save: None,
            last_locked_save_notice: None,
            pending_pdf: std::collections::HashMap::new(),
            #[cfg(feature = "chat")]
            chat: crate::chat_panel::ChatState::default(),
            permissions: PermissionBook::default(),
        }
    }

    /// The chrome webview, for platform calls that need any live webview to
    /// reach process-wide engine state (the profile, for instance).
    ///
    /// Returned as `&WebView` rather than exposing the field: this is the one
    /// webview `evaluate_script` may target, and that invariant is easier to
    /// keep when the field itself stays private.
    pub fn chrome(&self) -> &WebView {
        &self.chrome
    }

    /// What the privacy panel shows for the ACTIVE tab's site.
    ///
    /// `supported` is the honest half: on a tab whose permission handler never
    /// registered, and on every unix build, the browser is not policing these
    /// requests at all. The panel disables its controls on that answer rather
    /// than showing switches that would do nothing.
    pub fn permission_status(&self) -> serde_json::Value {
        let origin = self
            .tabs
            .get(self.active)
            .map(|t| t.url.as_str())
            .unwrap_or_default();
        let supported = self
            .tabs
            .get(self.active)
            .map(|t| platform::engine_settings(&t.view).permissions_registered == "applied")
            .unwrap_or(false);
        let site = normalize_origin(origin);
        // ALL FOUR KINDS, ALWAYS, for whatever site the tab is on -- not just
        // the ones that happen to have asked.
        //
        // The panel used to list only what a site had already requested, so a
        // user who opened it before any request found the four kinds
        // DESCRIBED in prose and no control anywhere, which reads as "this
        // browser has no permission settings". Worse, a site whose request we
        // silently denied gives no prompt, so the only way to reach a control
        // was to already know a row would appear once you triggered the
        // refusal a second time. Reported as a defect on 2026-08-06 hardware
        // testing, in exactly those words: "No option to allow or deny
        // cameras, mics, etc."
        //
        // Seeding here rather than in chrome.js keeps the rule in one place
        // and testable: the renderer stays a renderer.
        let mut entries: Vec<serde_json::Value> = Vec::new();
        if let Some(s) = site.as_deref() {
            let recorded = self.permissions.status_for(s);
            // The site's own four, in a fixed order so the list never
            // reshuffles under the pointer as requests arrive.
            for kind in PermKind::ALL {
                let found = recorded
                    .iter()
                    .find(|(key, _, _)| key.origin == s && key.kind == kind);
                let (granted, count) = found.map_or((false, 0), |(_, g, c)| (*g, *c));
                entries.push(json!({
                    "origin": s,
                    "kind": kind.as_ipc(),
                    "granted": granted,
                    "deniedCount": count,
                }));
            }
            // Then anything belonging to an EMBEDDED frame, which is a
            // different origin from the tab's and cannot be pre-seeded: we
            // only learn such an origin exists when it asks.
            for (key, granted, count) in &recorded {
                if key.origin != s {
                    entries.push(json!({
                        "origin": key.origin,
                        "kind": key.kind.as_ipc(),
                        "granted": granted,
                        "deniedCount": count,
                    }));
                }
            }
        }
        json!({
            "supported": supported,
            "site": site,
            "entries": entries,
        })
    }

    /// Runs a script in the chrome webview — the ONE surface where script
    /// evaluation is permitted. Used to install the chat panel's JS, which is
    /// not referenced from index.html so that a non-chat build does not ask
    /// for an asset it never serves.
    #[cfg(feature = "chat")]
    pub fn eval_chrome(&self, script: &str) {
        let _ = self.chrome.evaluate_script(script);
    }

    /// Smoke mode only: ask chrome.js to send a second ping. The eval itself
    /// exercises the Rust->JS direction; the resulting IPC message exercises
    /// JS->Rust again.
    pub fn request_second_ping(&self) {
        let _ = self.chrome.evaluate_script(
            r#"window.ipc.postMessage(JSON.stringify({id: 9999, cmd: "ping", args: {}}));"#,
        );
    }

    /// A proxy clone for code that must hand the event loop to a background
    /// thread's callback. The field stays private: handing out `&mut` access to
    /// it would let a caller replace the loop's only channel.
    pub fn proxy(&self) -> EventLoopProxy<UserEvent> {
        self.proxy.clone()
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        // A fresh idle stretch gets a fresh warning. Without this the notice
        // would fire once per session and every later approach to the deadline
        // would be silent.
        self.lock_warning_sent = false;
    }

    /// The configured idle timeout, or `None` when the user chose never.
    pub fn autolock_after(&self) -> Option<Duration> {
        (self.autolock_secs > 0).then(|| Duration::from_secs(self.autolock_secs))
    }

    /// When the event loop next needs to wake for the vault: the warning if it
    /// has not been raised yet, otherwise the lock itself.
    ///
    /// `None` whenever nothing is pending -- no vault open, or auto-lock
    /// disabled -- so the loop can go back to waiting indefinitely instead of
    /// spinning on a deadline that will never do anything.
    pub fn autolock_deadline(&self) -> Option<Instant> {
        let after = self.autolock_after()?;
        self.vault.as_ref()?;
        Some(if self.lock_warning_sent {
            self.last_activity + after
        } else {
            // saturating: a timeout shorter than the warning window means the
            // warning is due immediately rather than in the past.
            self.last_activity + after.saturating_sub(AUTO_LOCK_WARN_BEFORE)
        })
    }

    /// Reply to a chrome IPC request. Evaluates on the chrome webview only —
    /// never on the content webview.
    pub fn reply(&self, id: u64, result: Result<Value, &'static str>) {
        let payload = match result {
            Ok(data) => json!({ "id": id, "ok": true, "data": data }),
            Err(code) => json!({ "id": id, "ok": false, "error": code }),
        };
        let _ = self
            .chrome
            .evaluate_script(&format!("window.__rb_reply({payload});"));
    }

    /// Push an unsolicited event to the chrome UI.
    /// Resolve every chrome marker key in the CURRENT locale and push one
    /// fill snapshot, tagged with the generation. One event, all 450-odd
    /// strings: atomic by construction, so a race between two switches can
    /// only ever paint one locale, never a mixture -- the chrome refuses
    /// any snapshot that is not strictly newer than the last it applied.
    ///
    /// English pushes too when asked (a switch BACK to en is a normal fill
    /// whose content equals the golden markup; the sync gate guarantees
    /// that equality). What never happens is a push on an ENGLISH STARTUP:
    /// the caller gates that, and zero-runtime-fill for English stays true.
    pub fn push_locale_fill(&self, locale: &str) {
        let mut messages = serde_json::Map::new();
        for key in crate::i18n::CHROME_MSG_KEYS {
            messages.insert((*key).to_string(), Value::from(self.i18n.text(key)));
        }
        self.emit(
            "ui_locale_fill",
            json!({
                "generation": self.locale_generation,
                "locale": locale,
                "messages": messages,
            }),
        );
    }

    pub fn emit(&self, event: &str, data: Value) {
        let payload = json!({ "event": event, "data": data });
        let _ = self
            .chrome
            .evaluate_script(&format!("window.__rb_event({payload});"));
    }

    /// A page capture finished (or failed) in the engine. Validate cheaply,
    /// let the user choose where it goes, write it, and say what happened.
    /// Windows full-page parse/decode/validation ran on its capture worker;
    /// picker and state changes remain here. A cancelled picker is a
    /// changed mind, not an error: no file, no toast.
    pub fn on_capture_done(&mut self, ev: crate::capture::CaptureEvent) {
        let intent = self.capture_intent;
        self.capture_intent = crate::capture::CaptureIntent::SaveFile;
        // Snapshot pictures still have to pass through the row-streaming
        // 8 MP bound. Keep the shared capture slot busy until that worker
        // returns so a second snapshot cannot replace its one pending draft.
        if intent != crate::capture::CaptureIntent::Snapshot {
            crate::capture::CAPTURE_IN_FLIGHT
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
        // The scope the capture ACTUALLY had, from the path that produced
        // it -- not a compile-time guess about the platform. On Windows those
        // differ whenever the full-page call could not be issued.
        let scope = ev.scope;
        let bytes = match ev
            .png
            .and_then(|bytes| crate::capture::validate_capture_bytes(&bytes).map(|()| bytes))
        {
            Ok(bytes) => bytes,
            Err(code) => {
                match intent {
                    crate::capture::CaptureIntent::SaveFile => {
                        let text = match code {
                            "no_capture_page" => "Nothing to capture on this page.".to_string(),
                            // MARKETING PASS (WP-AH): new engine-failure copy.
                            "capture_engine_failed" => {
                                "The page could not be captured; nothing was saved.".to_string()
                            }
                            // MARKETING PASS (WP-AH): new decode/format copy.
                            "capture_decode_failed" => {
                                "The capture was not a readable PNG; nothing was saved.".to_string()
                            }
                            // MARKETING PASS (WP-AH): changed actionable size-refusal copy.
                            "capture_too_large" => "This page is too large to capture whole. Try a smaller window or a zoomed-in selection.".to_string(),
                            _ => "The capture failed; nothing was saved.".to_string(),
                        };
                        self.emit("toast", json!({ "text": text, "error": true }));
                    }
                    crate::capture::CaptureIntent::Region => {
                        // The region panel is sitting in a "capturing" state
                        // and needs a settled event, not a toast it may not
                        // connect to the mode it opened.
                        self.emit(
                            "region_capture_ready",
                            json!({ "ok": false, "error": code }),
                        );
                    }
                    crate::capture::CaptureIntent::Archive => {
                        self.emit("archive_saved", json!({ "ok": false, "error": code }));
                    }
                    crate::capture::CaptureIntent::Snapshot => {
                        crate::page_integrity::finish_snapshot_picture(self, Err(code), scope);
                    }
                }
                return;
            }
        };
        if intent == crate::capture::CaptureIntent::Region {
            // A long-page decode and resize would merely replace the old UI
            // parse stall with a new one. Prepare the bounded preview on a
            // worker and return only its token and dimensions to this loop.
            let proxy = self.proxy();
            std::thread::spawn(move || {
                let result = crate::capture::stash_region(bytes);
                let _ = proxy.send_event(UserEvent::RegionCapturePrepared { result, scope });
            });
            return;
        }
        if intent == crate::capture::CaptureIntent::Snapshot {
            let proxy = self.proxy();
            std::thread::spawn(move || {
                let result = crate::capture::bounded_picture_png(&bytes);
                let _ = proxy.send_event(UserEvent::SnapshotPicturePrepared { result, scope });
            });
            return;
        }
        if intent == crate::capture::CaptureIntent::Archive {
            self.archive_captured_page(bytes, crate::capture::scope_label(scope));
            return;
        }
        let title = format!(
            "Save capture ({})",
            crate::capture::scope_label(scope)
        );
        let Some(path) = platform::pick_file_to_save(
            &self.hosts,
            &title,
            crate::capture::default_save_name(scope),
        ) else {
            return;
        };
        match std::fs::write(&path, &bytes) {
            Ok(()) => {
                self.emit(
                    "toast",
                    json!({
                        "text": format!(
                            "Saved a picture of the {}.",
                            crate::capture::scope_label(scope)
                        ),
                    }),
                );
            }
            Err(_) => {
                self.emit(
                    "toast",
                    json!({
                        "text": "Could not write the capture to that location.",
                        "error": true,
                    }),
                );
            }
        }
    }

    /// Publishes a bounded region preview prepared off the UI thread. Source
    /// dimensions deliberately keep the original `w`/`h` wire names; the
    /// preview dimensions are additional mapping inputs, never OCR bounds.
    pub fn on_region_capture_prepared(
        &mut self,
        result: Result<(u64, u32, u32, u32, u32), &'static str>,
        scope: crate::capture::CaptureScope,
    ) {
        match result {
            Ok((token, width, height, preview_width, preview_height)) => {
                self.emit(
                    "region_capture_ready",
                    json!({
                        "ok": true,
                        "token": crate::capture::token_wire(token),
                        "w": width,
                        "h": height,
                        "preview_w": preview_width,
                        "preview_h": preview_height,
                        "scope": crate::capture::scope_label(scope),
                    }),
                );
            }
            Err(code) => {
                self.emit(
                    "region_capture_ready",
                    json!({ "ok": false, "error": code }),
                );
            }
        }
    }

    /// Forward an engine find-count callback to the chrome, if it still
    /// belongs to the search the user is looking at. Two stale-event drops
    /// protect that paint, neither trusting delivery order: the generation
    /// must be the session's current one (a callback from an abandoned
    /// query or a stopped session quotes a dead one), and the webview key
    /// must be the active tab's (a callback already in flight across a tab
    /// switch must not paint counts onto another tab's bar).
    pub fn on_find_event(&self, ev: crate::find::FindEvent) {
        if !self.find.is_active() {
            return;
        }
        // The webview-key check below cannot catch a stale count from the
        // SAME tab: a stop followed by a new start leaves the key intact
        // while the old count is already meaningless.
        if ev.generation != self.find.generation() {
            return;
        }
        let Some(webview) = self.active_webview() else {
            return;
        };
        if platform::find_key(webview) != ev.key {
            return;
        }
        self.emit(
            "find_state",
            json!({ "text": crate::find::format_count(ev.active, ev.total, ev.capped) }),
        );
    }

    pub fn check_autolock(&mut self) {
        let Some(after) = self.autolock_after() else {
            return; // the user chose never
        };
        if self.vault.is_none() {
            return;
        }
        let idle = self.last_activity.elapsed();

        // The warning, one minute out. Raised before the lock check so a very
        // short configured timeout still gets one, and only once per idle
        // stretch -- `touch` clears the flag, so acting on it re-arms it.
        if !self.lock_warning_sent && idle >= after.saturating_sub(AUTO_LOCK_WARN_BEFORE) {
            self.lock_warning_sent = true;
            if idle < after {
                let seconds = (after - idle).as_secs().max(1);
                self.emit("vault_lock_warning", json!({ "seconds": seconds }));
            }
        }

        if self.last_activity.elapsed() >= after {
            // ONE LOCK PATH, and this call is the whole point of it.
            //
            // This branch used to inline the lock -- `vault = None`, the chat
            // teardown, the `vault_locked` emit -- a byte-for-byte copy of
            // `lock_vault`, while ipc.rs's `vault_lock` arm carried a comment
            // claiming an explicit lock takes the SAME path as the auto-lock.
            // It did not. The copies even shared a note reading "to flip this
            // decision, add `self.store = None;` here (and in `lock_vault`)",
            // which is the hazard stated out loud: two sites, one of which
            // will eventually be edited alone. Adding a third trigger
            // (workstation lock) on top of that is how one of them silently
            // stops zeroizing or stops telling the chrome.
            self.lock_vault();
        }
    }

    // ---- layout ----------------------------------------------------------

    /// Windows: (re-)apply bounds for the chrome strip and the active tab —
    /// needed after resize, scale-factor change, tab switch, and chrome
    /// height change. unix: no-op, GTK packing owns layout there.
    pub fn relayout(&self) {
        // Before the geometry: the title bar comes back in the system colour
        // after a maximize or a restore, and every such transition arrives
        // here as a resize. Writing the same colours again does not repaint
        // it; the frame refresh does. So: on a maximized-state CHANGE, the
        // full apply with the refresh; on an ordinary resize, the bare
        // re-write, which costs nothing and cannot flicker.
        let maximized = platform::window_is_maximized(&self.hosts);
        if self.window_maximized_seen.get() != Some(maximized) {
            self.window_maximized_seen.set(Some(maximized));
            let _ = platform::set_window_accent(&self.hosts, &self.chrome_palette);
            // And once more AFTER the transition. The apply above runs inside
            // the resize that announces the maximize, and Windows repaints
            // the frame in the system colour after it -- a call from another
            // process a moment later painted the maximized caption fine, so
            // it is timing, not state. A short timer, then a loop event, so
            // the re-apply lands when Windows is done; the loop event is
            // where the window lives, and the timer thread only sends it.
            // Twice: the maximize animation runs a few hundred milliseconds
            // and Windows repaints the frame at its END, so a re-apply that
            // lands inside the animation is repainted over (80 ms was, seen
            // on hardware 2026-08-17). One after the animation, one more
            // well after for a slow machine.
            let proxy = self.proxy.clone();
            std::thread::spawn(move || {
                for delay_ms in [400u64, 1500] {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    if proxy.send_event(crate::UserEvent::WindowFrameSettled).is_err() {
                        return;
                    }
                }
            });
        } else {
            platform::reapply_window_accent(&self.hosts, &self.chrome_palette);
        }
        let active = self.tabs.get(self.active).map(|tab| &tab.webview);
        platform::layout(
            &self.hosts,
            &self.chrome,
            active,
            self.chrome_height,
            // What the chrome measures with no panel open. The Windows
            // Overlay branch lays the page out against THIS rather than
            // against `chrome_height`, so a modal neither moves the page nor
            // leaves a band when the strip changes underneath it.
            self.closed_chrome_height,
            self.chrome_left,
            self.chrome_right,
            self.chrome_arrangement,
        );
    }

    /// Cover the window with the chrome, or give it back to the page.
    ///
    /// This is what a modal panel opens into. The content webview is given a
    /// zero rect rather than being painted over, because the two are SIBLING
    /// child windows on Windows and siblings do not composite: whichever was
    /// created last draws on top, and the content webviews are all created
    /// after the chrome. Overlapping them would be a z-order fight that looks
    /// fine on one machine and wrong on another. Nothing overlaps if nothing
    /// has size.
    pub fn set_chrome_arrangement(&mut self, next: platform::ChromeLayout) {
        if self.chrome_arrangement == next {
            return;
        }
        let leaving_cover = !matches!(self.chrome_arrangement, platform::ChromeLayout::Strip)
            && matches!(next, platform::ChromeLayout::Strip);
        self.chrome_arrangement = next;
        // COMING BACK TO A STRIP, THE HEIGHT IS STALE FOR ONE FRAME.
        //
        // Closing a panel sends two messages: the arrangement first, the height
        // second. Between them `chrome_height` still holds the PANEL's height,
        // and the Strip arm believes it -- a diagnostic log from real hardware
        // caught it:
        //
        //   arrangement=Strip chrome_height=500
        //     STRIP chrome_rect top=0 h=500
        //     STRIP content top=500 h=329      <- page shoved down 352px
        //   arrangement=Strip chrome_height=148
        //     STRIP content top=148 h=681      <- and back
        //
        // One frame of the page jumping a third of the window down, every time
        // a panel closes. The strip cannot be 500 tall, so the stale value is
        // dropped rather than laid out: the height message arriving directly
        // behind this one relayouts with the real number.
        //
        // The value restored is the CLOSED height this chrome last reported,
        // not the build-time constant it used to be. The constant is 120 and
        // the sidebar layout's closed strip is ~88, so on that layout the
        // "fix" would itself have been a 32px jump -- the same defect, one
        // third the size, and harder to see.
        if leaving_cover {
            self.chrome_height = self.chrome_insets().leaving_cover().top;
            platform::set_chrome_height(&self.hosts, self.chrome_height);
        }
        self.relayout();
    }

    /// Whether a docked pane is currently laid out.
    pub fn is_split(&self) -> bool {
        matches!(self.chrome_arrangement, platform::ChromeLayout::Split { .. })
    }

    /// What the chrome is currently using along the top, in logical pixels.
    ///
    /// For a caller that wants to change ONE axis and leave the other where
    /// the chrome put it, rather than inventing a number for it.
    pub fn chrome_height(&self) -> i32 {
        self.chrome_height
    }

    /// All three chrome insets at once: top, left and right.
    ///
    /// One entry point rather than three setters, because the values describe
    /// one rectangle and applying them separately means laying out repeatedly
    /// -- once with a top that matches and a side that does not. That
    /// intermediate frame is exactly the class of defect the stale-height
    /// guard above exists to stop, and it would be back the first time
    /// switching layout changed multiple insets together.
    pub fn set_chrome_insets(&mut self, top: i32, left: i32, right: i32) {
        // KEEPS the closed strip it already had. A caller with only three
        // numbers is changing the sides or restoring a height, not telling us
        // what a closed strip measures, and treating its `top` as the strip
        // was a real regression: `toolbar_placement_set` calls this with
        // `chrome_height()`, which is the PANEL's height while a modal is
        // open, so switching placement back to Top mid-modal wrote the panel
        // height into the closed strip and pushed the page down until the
        // chrome remeasured. Only the chrome states a strip, and it does that
        // through `set_chrome_insets_with_strip`.
        //
        // `None` is the whole point of this method. It is not shorthand for
        // `Some(top)`, and `platform::chrome_inset_tests` fails if it ever
        // becomes that again.
        self.apply_chrome_insets(top, left, right, None);
    }

    /// The same, with the closed strip's height stated rather than inferred.
    ///
    /// The chrome sends both numbers because only it knows which is which:
    /// `top` is whatever must be given room right now, `strip` is what the
    /// chrome measures when no panel is open. Inferring the second from the
    /// arrangement was an ordering bug, because a panel's height can arrive
    /// before the arrangement that explains it.
    pub fn set_chrome_insets_with_strip(&mut self, top: i32, left: i32, right: i32, strip: i32) {
        self.apply_chrome_insets(top, left, right, Some(strip));
    }

    /// The four numbers as they are currently held.
    fn chrome_insets(&self) -> platform::ChromeInsets {
        platform::ChromeInsets {
            top: self.chrome_height,
            left: self.chrome_left,
            right: self.chrome_right,
            strip: self.closed_chrome_height,
        }
    }

    /// The one body both setters share.
    ///
    /// The decision about what `stated: None` means lives in
    /// `platform::ChromeInsets::applied`, where it can be tested as a sequence
    /// without a window. This method is only the plumbing that follows it.
    fn apply_chrome_insets(&mut self, top: i32, left: i32, right: i32, stated: Option<i32>) {
        let next = self.chrome_insets().applied(top, left, right, stated);
        self.chrome_height = next.top;
        self.chrome_left = next.left;
        self.chrome_right = next.right;
        self.closed_chrome_height = next.strip;
        // unix: moves the content overlay's insets (GTK repacks itself).
        // Windows: no-op, the relayout() below applies all three values.
        platform::set_chrome_height(&self.hosts, next.top);
        platform::set_chrome_strip(&self.hosts, next.strip);
        platform::set_chrome_left(&self.hosts, next.left);
        platform::set_chrome_right(&self.hosts, next.right);
        self.relayout();
    }

    /// The chrome's resolved colours, everywhere the chrome document itself
    /// cannot paint: the OS title bar and border, and every open tab's page
    /// scrollbar (live on Windows; installed but not honoured by WebKitGTK
    /// -- see each backend's `set_page_scrollbar`). Persisted
    /// first, so a tab created
    /// before the chrome next speaks -- including the first tab of the next
    /// launch -- reads the same colours from prefs.
    /// Returns whether the OS caption tint is in effect (Windows 11 accepted
    /// the attributes); the chrome keys its inner top line off it.
    pub fn set_chrome_palette(&mut self, palette: platform::ChromePalette) -> bool {
        let mut p = crate::prefs::load();
        if p.chrome_palette != palette {
            p.chrome_palette = palette;
            // A prefs write that fails leaves the live window correct and
            // only the NEXT launch on the old colours; not worth refusing
            // the whole change over.
            let _ = crate::prefs::save(&p);
        }
        self.chrome_palette = palette;
        let caption_tinted = platform::set_window_accent(&self.hosts, &palette);
        for tab in &self.tabs {
            platform::set_page_scrollbar(&tab.webview, &tab.view, palette.scrollbar);
        }
        caption_tinted
    }

    /// The deferred half of the maximize/restore re-apply (see `relayout`):
    /// nudge the colours to a value DWM will treat as a change, then the real
    /// ones with the frame refresh. Windows only does anything with it.
    pub fn refresh_window_accent(&self) {
        platform::refresh_window_accent(&self.hosts, &self.chrome_palette);
    }

    // ---- tabs ---------------------------------------------------------------

    /// Records a path the user picked and returns the token that redeems it.
    pub fn remember_picked_path(&mut self, path: PathBuf) -> u64 {
        let token = self.next_pick_token;
        self.next_pick_token += 1;
        self.picked_paths.push_back((token, path));
        while self.picked_paths.len() > MAX_PICKED_PATHS {
            self.picked_paths.pop_front();
        }
        token
    }

    /// Redeems a token for the path it names, consuming it.
    ///
    /// One-shot: a token cannot be replayed, so a leaked one is worth a single
    /// read of a file the user themselves selected, and only until the next
    /// eight picks push it out.
    pub fn take_picked_path(&mut self, token: u64) -> Option<PathBuf> {
        let at = self.picked_paths.iter().position(|(t, _)| *t == token)?;
        self.picked_paths.remove(at).map(|(_, path)| path)
    }

    /// Creates a tab and returns its id. `switch` selects and shows it;
    /// otherwise it stays hidden in the background.
    ///
    /// `Err("tab_failed")` when the engine could not build the webview. The
    /// caller must handle it: this is reachable from web content via
    /// `window.open`, and it used to be a process-wide panic.
    pub fn new_tab(&mut self, url: &str, switch: bool) -> Result<u64, &'static str> {
        let id = self.next_tab_id;
        let tab = build_tab(
            &self.hosts,
            &self.proxy,
            id,
            url,
            &self.privacy,
            self.permissions.clone(),
        )
        .map_err(|_| "tab_failed")?;
        // Bumped only AFTER the build succeeds, so a failed attempt does not
        // burn an id and leave a gap in the sequence.
        self.next_tab_id += 1;
        let was_empty = self.tabs.is_empty();
        self.tabs.push(tab);
        if was_empty {
            self.active = 0;
            platform::show_tab(&self.tabs[0].view, &self.tabs[0].webview);
            self.relayout();
        } else if switch {
            let index = self.tabs.len() - 1;
            self.set_active(index);
        }
        self.emit_tabs_changed();
        self.focus_url_bar_for_blank_tab(switch, url);
        Ok(id)
    }

    pub fn close_tab(&mut self, id: u64) -> Result<(), &'static str> {
        if let Some(tab) = self.tabs.iter().find(|t| t.id == id) {
            if tab.blocked_pending.borrow().is_some() {
                self.emit("navigation_blocked_retired", json!({ "tab_id": id }));
            }
        }
        let index = self
            .tabs
            .iter()
            .position(|tab| tab.id == id)
            .ok_or("not_found")?;
        crate::page_integrity::on_tab_closed(self, id);

        // Keep the WebView that owns the asynchronous engine clear alive.
        // Closing it can suppress the completion callback, leaving the
        // process gate in Running and every newer tab permanently blank.
        // The event-loop remains responsive; only destruction of this blank
        // pending tab waits for the clear's result.
        if self.tabs[index].initial_navigation_pending {
            self.tabs[index].close_after_session_wipe = true;
            return Ok(());
        }
        let was_active = index == self.active;

        // A live cross-tab scan keeps the closing tab's row: a still-pending
        // row becomes "tab_closed", a done row keeps its result -- the text
        // was read while the tab lived, and the UI shows the row as
        // gone-but-counted. This runs BEFORE the last-tab branch below,
        // which returns early after building a replacement; both exits
        // close the same tab and the scan must hear about it either way.
        let scan_changed = match self.tab_scan.as_mut() {
            Some(scan) => scan.on_tab_closed(id),
            None => false,
        };
        if scan_changed {
            self.emit_tab_scan_state();
        }

        // CLOSING THE LAST TAB: build the replacement BEFORE removing.
        //
        // The invariant is "never zero tabs", and several accessors below and
        // in set_active index `self.tabs[self.active]` directly -- so an empty
        // list does not degrade, it panics somewhere else instead. The old
        // order (remove, then build, then `.expect`) had no way to keep the
        // invariant when the engine refused to build: it took the process
        // down. Building first means a refusal leaves the browser exactly as
        // it was and the user is told, which is the only outcome here that is
        // both honest and survivable.
        if self.tabs.len() == 1 {
            let fresh = build_tab(
                &self.hosts,
                &self.proxy,
                self.next_tab_id,
                "about:blank",
                &self.privacy,
                self.permissions.clone(),
            )
            .map_err(|_| "tab_failed")?;
            self.next_tab_id += 1;
            drop(self.tabs.remove(index)); // detaches (unix) / destroys (windows)
            self.tabs.push(fresh);
            self.active = 0;
            platform::show_tab(&self.tabs[0].view, &self.tabs[0].webview);
            self.relayout();
            self.emit_tabs_changed();
            let url = self.tabs[0].url.clone();
            self.emit("url_changed", json!({ "url": url }));
            self.emit_tab_status();
            self.focus_url_bar_for_blank_tab(true, "about:blank");
            return Ok(());
        }

        let tab = self.tabs.remove(index);
        drop(tab); // Tab::drop detaches the view (unix) / destroys the WebView2 (windows)

        // At least one tab remains -- the single-tab case returned above -- so
        // every index below is in range.
        if index < self.active {
            self.active -= 1;
        } else if was_active {
            // Right neighbor (shifted into `index`) if any, else left.
            self.active = index.min(self.tabs.len() - 1);
        }
        if was_active {
            platform::show_tab(
                &self.tabs[self.active].view,
                &self.tabs[self.active].webview,
            );
            self.relayout();
        }
        self.emit_tabs_changed();
        if was_active {
            let url = self.tabs[self.active].url.clone();
            self.emit("url_changed", json!({ "url": url }));
            self.emit_tab_status();
        }
        Ok(())
    }

    pub fn switch_tab(&mut self, id: u64) -> Result<(), &'static str> {
        let index = self
            .tabs
            .iter()
            .position(|tab| tab.id == id)
            .ok_or("not_found")?;
        self.set_active(index);
        self.emit_tabs_changed();
        Ok(())
    }

    /// Reorders the strip by stable tab id while preserving the active tab's
    /// identity. The complete-permutation check happens before the Vec is
    /// touched, so a stale or malformed chrome snapshot cannot partly move
    /// tabs or make a later id name a different page.
    pub fn reorder_tabs(&mut self, ids: &[u64]) -> Result<Vec<u64>, &'static str> {
        let active_id = self
            .tabs
            .get(self.active)
            .map(|tab| tab.id)
            .ok_or("bad_args")?;
        let current: BTreeSet<u64> = self.tabs.iter().map(|tab| tab.id).collect();
        let requested: BTreeSet<u64> = ids.iter().copied().collect();
        if ids.len() != self.tabs.len() || requested.len() != ids.len() || requested != current {
            return Err("bad_args");
        }

        // Validation above proves every lookup in this loop succeeds exactly
        // once. MAX_TABS is 32, so the simple removal pass is clearer than an
        // auxiliary ownership map and its quadratic bound is immaterial.
        let mut old = std::mem::take(&mut self.tabs);
        let mut reordered = Vec::with_capacity(old.len());
        for id in ids {
            let index = old
                .iter()
                .position(|tab| tab.id == *id)
                .expect("validated tab permutation lost an id");
            reordered.push(old.remove(index));
        }
        self.tabs = reordered;
        self.active = self
            .tabs
            .iter()
            .position(|tab| tab.id == active_id)
            .expect("validated tab permutation lost the active tab");
        self.emit_tabs_changed();
        Ok(self.tabs.iter().map(|tab| tab.id).collect())
    }

    /// Selects a tab by position, ignoring an out-of-range index.
    ///
    /// Out of range is normal rather than exceptional here: Ctrl+5 with three
    /// tabs open should do nothing, not error.
    pub fn select_tab_index(&mut self, index: usize) {
        if index < self.tabs.len() {
            self.set_active(index);
            self.emit_tabs_changed();
        }
    }

    pub fn select_last_tab(&mut self) {
        if !self.tabs.is_empty() {
            self.select_tab_index(self.tabs.len() - 1);
        }
    }

    /// Moves `delta` tabs forward or backward, wrapping at both ends the way
    /// Ctrl+Tab does in every other browser.
    pub fn cycle_tab(&mut self, delta: i32) {
        let count = self.tabs.len();
        if count < 2 {
            return;
        }
        let count_i = count as i32;
        let next = (self.active as i32 + delta).rem_euclid(count_i) as usize;
        self.select_tab_index(next);
    }

    /// Closes the active tab. Ctrl+W has no id to work with, unlike the IPC
    /// command which is driven by a click on a specific tab.
    pub fn close_active_tab(&mut self) {
        if let Some(id) = self.tabs.get(self.active).map(|tab| tab.id) {
            let _ = self.close_tab(id);
        }
    }

    /// Asks the chrome UI to focus and select the URL bar.
    ///
    /// Evaluated on the chrome webview only, which is the one surface where
    /// script evaluation is permitted.
    pub fn focus_url_bar(&self) {
        // Two focuses, and both are needed. The chrome webview is one widget
        // (GTK) / one HWND (WebView2) among several: `element.focus()` inside
        // it places the caret, but does not by itself take keyboard focus
        // away from a content webview that holds it -- so first the WIDGET is
        // focused (grab_focus / MoveFocus), then the script places the caret.
        // Best-effort: a refused widget focus is not worth more than the
        // script that follows it.
        let _ = self.chrome.focus();
        self.emit("focus_url_bar", json!({}));
    }

    /// Ctrl+F: open the find bar with the cursor already in it.
    ///
    /// TWO FOCUSES, for exactly the reason `focus_url_bar` documents above.
    /// The chrome already called `findInput.focus()` when it opened the bar,
    /// and that was not enough: the shortcut is resolved in Rust precisely
    /// BECAUSE a content webview has keyboard focus, and `element.focus()`
    /// inside the chrome document places a caret without taking that focus
    /// away from the page. So the bar opened, looked ready, and swallowed
    /// nothing -- every keystroke still went to the page behind it. The
    /// widget is focused first, then the chrome opens the bar and puts the
    /// caret in it.
    ///
    /// Same best-effort rule: a refused widget focus is not worth more than
    /// the event that follows it.
    pub fn open_find_bar(&self) {
        let _ = self.chrome.focus();
        self.emit("find_open", json!({}));
    }

    /// A BLANK tab the user is now looking at has nothing to focus but the
    /// address bar, so the cursor lands there: Ctrl+T, the "+" button, and
    /// the fresh tab left behind when the last one closes.
    ///
    /// Called AFTER `show_tab`, which on Windows moves keyboard focus to the
    /// content webview (each WebView2 child is its own HWND, focused
    /// explicitly when shown). The chrome's "+" click handler used to focus
    /// the bar BEFORE its `tab_new` round trip and lost to exactly that; the
    /// Ctrl+T path never focused it at all. A tab opened on a real URL keeps
    /// focus on the page, as every browser does; a background tab changes
    /// nothing.
    fn focus_url_bar_for_blank_tab(&self, switch: bool, url: &str) {
        if switch && url == "about:blank" {
            self.focus_url_bar();
        }
    }

    /// Ctrl+K. Pushed to the chrome rather than acted on here: which actions
    /// exist and how they are matched is a chrome-JS concern, same reasoning
    /// as `UpdateChecked` deferring the install decision to the UI.
    pub fn open_command_palette(&self) {
        self.emit("open_command_palette", json!({}));
    }

    /// Print the ACTIVE TAB, never the chrome.
    ///
    /// The whole reason Ctrl+P is intercepted: unbound, the engine handled it
    /// on whichever webview had focus and printed the browser's own toolbar.
    /// Naming the active tab here removes focus from the question entirely.
    pub fn print_active_tab(&self) {
        let Some(tab) = self.tabs.get(self.active) else {
            return;
        };
        if !platform::show_print_ui(&tab.webview) {
            // Say so rather than appear to do nothing -- an unexplained no-op
            // is the failure this whole path replaced.
            self.emit(
                "print_unavailable",
                json!({ "reason": "this runtime cannot open a print preview" }),
            );
        }
    }

    /// Opens the engine's developer tools on the ACTIVE CONTENT TAB.
    ///
    /// Aimed explicitly rather than left to the engine's own F12 handling:
    /// the key is resolved natively (see `shortcuts`), so whichever webview
    /// held focus, the inspector opens on the page the user is looking at.
    /// The privileged chrome webview is built with devtools disabled in
    /// release builds and stays that way -- this method has no way to reach
    /// it, which is the point.
    pub fn open_active_devtools(&self) {
        let Some(webview) = self.active_webview() else {
            return;
        };
        platform::open_devtools(webview);
    }

    /// Replaces the browser-wide privacy policy and applies it to every open
    /// tab, so a toggle takes effect on what the user is already looking at
    /// rather than only on the next tab they open.
    ///
    /// `ephemeral` is deliberately NOT retroactive: a WebContext is fixed when
    /// its view is built, and pretending otherwise would claim a tab had no
    /// on-disk profile when it still did.
    pub fn set_privacy(&mut self, policy: platform::TabPolicy) {
        // Turning ad blocking OFF dismisses every held page. The banner tells
        // the user to do exactly this, and with the filters gone the hold's
        // reason is gone: leaving the pending up meant the real page loaded
        // under a banner still saying it did not open, with instructions to
        // disable blocking that was already disabled (review R-004, round 2).
        if !policy.block_ads {
            for tab in &mut self.tabs {
                tab.adlist.clear_pending();
            }
        }
        self.privacy = policy;
        for tab in &mut self.tabs {
            tab.block_ads = self.privacy.block_ads;
            platform::apply_policy(&tab.webview, &tab.view, &self.privacy);
        }
    }

    /// Applies WebView2's profile-level tracking-prevention choice to every
    /// profile represented by an open tab. Ordinary tabs share one profile;
    /// ephemeral tabs may not, so walking the live tabs is deliberate rather
    /// than assuming the active tab's profile is the only one in use.
    ///
    /// Returns true only when every live profile read back the requested
    /// level. New tabs independently apply the persisted preference during
    /// hardening, so this runtime path and the next-tab path converge.
    pub fn set_tracking_prevention(
        &mut self,
        level: crate::prefs::TrackingPreventionLevel,
    ) -> bool {
        use crate::platform::TrackingPreventionState;

        let mut attempted = false;
        let mut all_confirmed = true;
        for tab in &self.tabs {
            attempted = true;
            let confirmed = platform::set_tracking_prevention(&tab.webview, &tab.view, level);
            let matches = matches!(
                (level, confirmed),
                (
                    crate::prefs::TrackingPreventionLevel::Strict,
                    TrackingPreventionState::Strict
                ) | (
                    crate::prefs::TrackingPreventionLevel::Balanced,
                    TrackingPreventionState::Balanced
                )
            );
            all_confirmed &= matches;
        }
        self.emit_tab_status();
        attempted && all_confirmed
    }

    /// The policy plus what this ENGINE can actually enforce. The UI needs
    /// both: a checkbox that silently does nothing is worse than one that
    /// says it is unavailable here.
    pub fn privacy_status(&self) -> Value {
        // The browser-wide cookie control's static wording rides along here
        // rather than living in the markup: the chrome writes what Rust says,
        // and the sentence that keeps this feature honest ("cookies, not your
        // saved passwords") is then pinned by cookie_control's own tests
        // instead of by nobody. Assembled, not phrased -- see that module.
        let copy = crate::cookie_control::forget_all_copy();
        json!({
            // Whether the cookie-clearing controls can do anything on this
            // backend. False on WebKitGTK in 1.0.0, where the platform calls
            // are stubs; the chrome disables both controls and shows
            // `cookie_clear_unavailable_intro` instead of the enabled copy.
            "cookie_clear_available": crate::cookie_control::available(),
            "cookie_clear_unavailable_intro": crate::cookie_control::unavailable_intro(),
            "block_ads": self.privacy.block_ads,
            "freeze_after_load": self.privacy.freeze_after_load,
            "javascript": self.privacy.javascript,
            "ephemeral": self.privacy.ephemeral,
            "network_blocking_supported": platform::network_blocking_supported(),
            "freeze_enforced": platform::freeze_enforced(),
            "forget_all": {
                "intro": copy.intro,
                "warning": copy.warning,
                "button": copy.button,
                "confirm": copy.confirm,
                "cancel": copy.cancel,
            },
        })
    }

    /// JSON snapshot of the active tab's privacy posture. This is both the
    /// `tab_status` reply and the payload of the `tab_status` event pushed on
    /// tab switch, navigation and load-state change, so the always-visible
    /// indicators (freeze chip, TLS warning) never go stale.
    pub fn active_tab_status(&self) -> Value {
        let Some(tab) = self.tabs.get(self.active) else {
            // Unreachable in practice (the app never runs with zero tabs),
            // but a status endpoint degrades rather than panicking. The
            // string literals are the serde wire names locked by the
            // wire-names test in privacy.rs.
            return json!({
                "freeze_phase": "loaded",
                "freeze_enforcement": "inactive",
                "profile": "persistent",
                "origin": Value::Null,
                "tls": "unknown",
                "freeze_enforced": platform::freeze_enforced(),
                "network_blocking_supported": platform::network_blocking_supported(),
                "ledger_counts_blocked": LEDGER_COUNTS_BLOCKED,
                "blocked_total": 0,
                "interception": "not_attempted",
                "script_setting": "not_attempted",
                "smartscreen_off": "not_attempted",
                "tracking_prevention": "not_attempted",
                "navigation_tracking": "not_attempted",
                // Drift fix: this key and session_lock_registered (below)
                // are carried by the tab arm but were absent here. A key
                // present in one arm and absent in the other renders as a
                // missing row only in the zero-tab state, which is why
                // nobody noticed.
                "autofill_off": "not_attempted",
                "ephemeral_confirmed": "not_attempted",
                "hardened_environment": "not_attempted",
                "session_lock_registered": "not_attempted",
                "translation": { "active": false },
                // Same degraded default as everything else in this
                // unreachable arm; the measured value lives in the tab arm.
                "tunnel": "not_attempted",
                "content_script_registered": "not_attempted",
                "pending_save": Value::Null,
                "insecure_pending": Value::Null,
            });
        };
        let engine_settings = platform::engine_settings(&tab.view);
        json!({
            "freeze_phase": platform::freeze_phase(&tab.view),
            // What the user ASKED for is `freeze_phase`; what the ENGINE did
            // about it is this. They differ on WebKitGTK, where the blocking
            // filter compiles asynchronously and can fail — so the UI must
            // read this before claiming the tab is making no requests.
            "freeze_enforcement": platform::freeze_enforcement(&tab.view).as_str(),
            "profile": platform::profile_mode(&tab.view),
            // The host of the page actually loaded, not the address-bar text
            // (which may be mid-edit or a search string that never
            // navigated). `null` for a page with no http(s) authority --
            // about:blank, an internal page, or a malformed URL -- so the
            // site-info popover can say "no site" rather than showing an
            // empty label with nothing behind it.
            "origin": host_of(&tab.url),
            "tls": platform::tls_state(&tab.webview, &tab.view),
            // The certificate issuer, DISPLAY ONLY, for the Info tab's "Issued
            // by" row. Null when there is no TLS or the engine cannot read one
            // (every Windows build, honestly). Never an input to a decision.
            "tls_issuer": platform::tls_issuer(&tab.webview, &tab.view),
            // Whether THIS page was loaded over plain HTTP -- a fact a privacy
            // browser should state plainly in the Info tab ("not encrypted"),
            // distinct from `insecure_pending`, which is the mid-navigation
            // interstitial rather than a settled property of the loaded page.
            "page_insecure": platform::page_insecure(&tab.view),
            // The declared-language badge hint. Null unless the page declared a
            // language; a hint the source dropdown overrides, never a gate.
            "detected_lang": tab.detected_lang,
            // The active tab's translation state rides WITH tab status, so
            // the panel and the toolbar chip repaint on navigation and on
            // every phase change. Before this, renderTranslate ran only from
            // the user's own three clicks: navigate off a translated page and
            // the panel kept claiming "This page is translated" about a page
            // that was never touched -- the host knew, and the page was
            // never told. Third instance of that defect class in this file.
            "translation": self.translation_status().unwrap_or_else(|_| json!({ "active": false })),
            // Capability flags ride along so the UI can disable (and
            // explain) a control the running platform cannot honour, instead
            // of offering a switch that does nothing.
            "freeze_enforced": platform::freeze_enforced(),
            "network_blocking_supported": platform::network_blocking_supported(),
            "ledger_counts_blocked": LEDGER_COUNTS_BLOCKED,
            // Requests this tab has had blocked. Rides here rather than on
            // `tab_ledger` because the shield shows it without any panel being
            // open, and this is the payload that arrives on navigation and tab
            // switch. Read it ONLY together with `ledger_counts_blocked`: on a
            // backend that cannot observe blocking this is zero because nothing
            // was counted, not because nothing was stopped.
            "blocked_total": platform::blocked_total(&tab.view),
            // Which blocking mechanism this tab actually holds. Diagnostic,
            // not a control: it separates "no handler was ever registered"
            // from "registered, but the block is not sticking" — identical
            // from outside, and needing opposite fixes.
            "interception": platform::interception_state(&tab.view),
            // Whether the ENGINE confirmed the JavaScript setting, as opposed
            // to whether the user asked for it. "failed" means the tab is
            // still running script no matter what `javascript` above says.
            "script_setting": platform::script_setting(&tab.view),
            // Four more engine answers, same rule: what was CONFIRMED, not
            // what was requested. "failed" on smartscreen means reputation
            // checking is still on; on navigation it means this tab can never
            // auto-freeze.
            "smartscreen_off": engine_settings.smartscreen_off,
            "tracking_prevention": engine_settings.tracking_prevention,
            "navigation_tracking": engine_settings.navigation_tracking,
            "autofill_off": engine_settings.autofill_off,
            // Whether the engine confirmed this tab's STORAGE mode. Anything
            // other than "applied" on an ephemeral tab means the cookies and
            // cache may be landing on disk after all -- which is why "profile"
            // above already refuses to say "ephemeral" without it.
            "ephemeral_confirmed": engine_settings.ephemeral_confirmed,
            // Process-wide. "failed" means the browser is running on the
            // engine's default environment, having lost its hardened browser
            // arguments and crash-report suppression -- which used to be
            // reported only to a debug-build log nobody shipping ever sees.
            "hardened_environment": engine_settings.hardened_environment,
            // Process-wide, and the only MEASURED row: "applied" means the
            // probe thread's latest cycle completed a real SOCKS5 greeting
            // against the loopback tunnel front AND the tunnel reported Up.
            // Before the vault unlocks this reads "failed" on purpose --
            // the port is refusing every connection, so the tunnel is not
            // carrying traffic, and the row says so.
            "tunnel": engine_settings.tunnel,
            // Process-wide, like `hardened_environment`. "failed" means the OS
            // refused to tell us about workstation locks, so the vault will
            // NOT close when the screen does and only the inactivity timer is
            // guarding it. The user is told that rather than left with a
            // setting that reads as on.
            "session_lock_registered": engine_settings.session_lock_registered,
            // Whether the content-script + message-handler registration this
            // tab's autofill save/fill flow depends on actually succeeded.
            // The fill/save affordance must never be offered on the strength
            // of an unconfirmed capability -- same discipline as every other
            // field above.
            "content_script_registered": engine_settings.content_script_registered,
            // Set only if the ACTIVE tab is the one that submitted it -- see
            // `note_login_submitted` and `PendingSave`'s own doc. Never the
            // password: chrome.js gets enough to render "Save password for
            // X (Y)?" and nothing that would let the raw value sit in this
            // webview's own DOM.
            "pending_save": self.pending_save.as_ref().and_then(|p| {
                (self.tabs.get(self.active).map(|t| t.id) == Some(p.tab_id))
                    .then(|| json!({ "origin": p.origin, "username": p.username }))
            }),
            // The plain-HTTP URL the navigation handler is holding for THIS
            // tab, or null. The chrome renders the warning from this field
            // alone, so it follows the active tab and never a stale event.
            // The held page, or null. Carries the pending id because this
            // banner survives a tab switch and a click must name the banner
            // it answers; and `can_allow`, because a backend with no way to
            // except a host must not be offered a button it cannot honour.
            // THE TAB'S ID, because the held-page banner is answered by tab AND
            // pending id, and the chrome takes the tab id from here. It was
            // absent: the chrome sent `undefined`, JSON dropped the field, and
            // both IPC arms rejected every click as bad_args, so Open anyway
            // never worked. The DOM gate's fixture had invented the field and
            // passed thirteen checks over a button that could not (review R-001,
            // round 2). Pinned by the smoke run, which reads the real status.
            "id": tab.id,
            "adlist_pending": tab.adlist.pending().map(|p| serde_json::json!({
                "id": p.id,
                "host": p.host,
                "method": p.method,
                "can_allow": crate::adlist_consent::CAN_ALLOW,
            })),
            "adlist_override_host": tab.adlist.override_host(),
            // The blocked-site notice this tab is showing, if any: the chrome
            // keeps its notice up exactly while this matches the id it was
            // given, and takes it down when Rust has cleared or replaced it.
            "blocked_pending": tab.blocked_pending.borrow().as_ref().map(|(id, _)| *id),
            "insecure_pending": tab.insecure_pending.as_deref(),
            // THE HOST, COMPUTED HERE, because the chrome computing its own
            // put two parsers on the same string and they disagreed. The
            // chrome's regex kept the whole authority; host_of strips the
            // port and the userinfo. continue_matches_shown_banner demands
            // the two agree, so Continue was refused for every URL carrying
            // a port -- http://example.com:8080/ warned normally, then said
            // "That does not look right" whichever way the user answered,
            // with no path forward at all.
            //
            // Worse for a banner whose whole job is naming the right site:
            // the authority includes userinfo, so
            // http://www.paypal.com@attacker.example/ RENDERED as
            // "www.paypal.com@attacker.example". An attacker-chosen string
            // in the subject line of the warning about that attacker. This
            // is the relabelling class the banner was rewritten to prevent,
            // arriving through the parser rather than through a race.
            //
            // The blocklist banner one screen away already did it this way.
            "insecure_pending_host": tab
                .insecure_pending
                .as_deref()
                .and_then(host_of)
                .map(Value::from)
                .unwrap_or(Value::Null),
        })
    }

    /// Pushes the active tab's status to the chrome UI. Called from every
    /// transition that can change it without an IPC round trip: tab switch,
    /// navigation, load-state change, tab close.
    /// Apply any due auto-freeze transitions and report the next deadline.
    ///
    /// Called from the event loop's timer arm. Exists because the WINDOWS
    /// backend has no engine timer -- its transition happens lazily on the next
    /// request, which enforces correctly but leaves the toolbar reporting
    /// "Live" on a tab that is armed to freeze. Unix returns None here; its GTK
    /// timeout already did the work.
    pub fn tick_auto_freeze(&mut self, now: Instant) -> Option<Instant> {
        let mut changed = false;
        let mut next: Option<Instant> = None;
        for tab in &self.tabs {
            let (did, deadline) = platform::tick_auto_freeze(&tab.view, now);
            changed |= did;
            next = match (next, deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        if changed {
            self.emit_tab_status();
        }
        next
    }

    /// Zoom the active tab and tell the chrome, so the level is visible
    /// rather than something the user has to infer from the page.
    pub fn zoom_active(&mut self, dir: i32) {
        // With a MODAL open, the zoom keys belong to the PANEL, and this is
        // the only place that can honour them. Our own accelerator handler
        // runs on the chrome webview too and marks Ctrl+= / Ctrl+- / Ctrl+0
        // handled (connect_shortcuts), so a keydown listener in chrome.js
        // would never fire -- one shipped, looked exactly like the feature,
        // and did nothing on real hardware (decided 2026-07-31). Routing
        // the event back across the IPC is the one spelling that works, and
        // it also stops the old failure of rescaling a page nobody can see.
        if matches!(
            self.chrome_arrangement,
            crate::platform::ChromeLayout::Overlay
        ) {
            self.emit("panel_zoom", json!({ "dir": dir }));
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else {
            return;
        };
        let level = tab.zoom_step(dir);
        self.emit(
            "zoom_changed",
            json!({ "percent": (level * 100.0).round() }),
        );
    }

    /// The engine zoomed a tab by itself -- a keypad shortcut, or Ctrl+scroll.
    ///
    /// Reported for the tab it happened to, but only shown when that tab is
    /// the visible one: a background tab's level is not what the chip is
    /// describing.
    pub fn on_zoom_factor_changed(&mut self, id: u64, factor: f64) {
        let Some(index) = self.tabs.iter().position(|t| t.id == id) else {
            return;
        };
        self.tabs[index].note_engine_zoom(factor);
        if index == self.active {
            let level = self.tabs[index].zoom_level();
            self.emit(
                "zoom_changed",
                json!({ "percent": (level * 100.0).round() }),
            );
        }
    }

    pub fn emit_tab_status(&self) {
        let status = self.active_tab_status();
        self.emit("tab_status", status);
    }

    /// Manual freeze of the active tab. Per-tab and reversible; the reply is
    /// the refreshed status so the toolbar chip and panel update in one
    /// round trip. Honoured even mid-load: a load finishing does not undo a
    /// manual freeze (see FreezeController::on_load_finished).
    pub fn freeze_active_tab(&self) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("not_found")?;
        platform::freeze(&tab.webview, &tab.view);
        Ok(self.active_tab_status())
    }

    /// One-call unfreeze of the active tab.
    pub fn unfreeze_active_tab(&self) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("not_found")?;
        platform::unfreeze(&tab.webview, &tab.view);
        Ok(self.active_tab_status())
    }

    /// Per-site override on the active tab: `host` keeps working even while
    /// the tab is frozen. Survives navigation, dies with the tab (the
    /// override is the user's exception, not the page's).
    pub fn allow_site_active_tab(&self, host: &str) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("not_found")?;
        platform::allow_site(&tab.webview, &tab.view, host);
        Ok(self.active_tab_status())
    }

    /// Receives one extractor message from a content page.
    ///
    /// EVERYTHING HERE IS UNTRUSTED. It was assembled by a script running in a
    /// hostile document, so this is the one place it is parsed, and it is
    /// parsed against a shape rather than trusted to be one.
    ///
    /// Four things are refused outright, and each has a reason rather than
    /// being defensive habit:
    ///   - a tab that no longer exists (a late message from a closed tab);
    ///   - a tab with no live translation session (nobody asked, so nothing
    ///     is accepted -- this is where "never automatic" is actually
    ///     enforced, not in the UI);
    ///   - a message whose `href` is not the page the session was consented
    ///     for (the page navigated, so the consent died with it);
    ///   - anything that is not the one shape this path accepts.
    pub fn on_content_translate(&mut self, id: u64, raw: &str) {
        let Some(index) = self.tabs.iter().position(|t| t.id == id) else {
            return;
        };
        let Ok(value) = serde_json::from_str::<Value>(raw) else {
            return;
        };
        let href = value.get("href").and_then(Value::as_str).unwrap_or_default();
        let kind = value.get("kind").and_then(Value::as_str).unwrap_or_default();

        // TIER-1 DETECTION: the page declared its language. This carries NO
        // page text -- only the html lang attribute -- so it needs no session
        // and no consent: it is the same class of fact as the URL, which the
        // host already has. Stored for the badge; it never gates translation.
        // A late or repeated signal simply overwrites, which is correct: a page
        // that changes its lang attribute has changed its answer.
        if kind == "detected" {
            let lang = value.get("lang").and_then(Value::as_str).unwrap_or_default();
            // Only when the signalling page is still the one on screen, so a
            // stale message from a navigated-away page cannot relabel this tab.
            // AND only if it is a plausible language tag: a page controls this
            // string, so bidi overrides, zero-width characters and other
            // control junk must never reach the badge UI. A BCP-47 tag is ASCII
            // letters, digits and hyphens; anything else is refused rather than
            // sanitised, because a tag that needs sanitising is not a tag.
            // Declared attribute first; failing that, the page-side letter
            // count's script name, resolved only where it names exactly one
            // supported language (see language_for_script_name). Both are
            // page-controlled hints: the dropdown overrides them and the
            // cumulative script guard still judges the real text.
            // Resolved HERE, once, to a registry code -- "el-GR" becomes
            // "el", "zh-CN" becomes "zh-Hans" -- so every consumer (the
            // prefill, the hint, continuation) compares codes and none of
            // them re-derives a primary subtag. The old split-the-tag
            // approach cut "zh-CN" to "zh", which names NO registry language
            // (Chinese is two: zh-Hans and zh-Hant), so a Chinese page that
            // declared itself perfectly was treated as undetected.
            let resolved: Option<String> = if !lang.is_empty() && is_plausible_lang_tag(lang) {
                crate::detect::registry_code_for_tag(lang)
            } else {
                None
            }
            .or_else(|| {
                value
                    .get("script")
                    .and_then(Value::as_str)
                    .and_then(crate::detect::language_for_script_name)
            })
            .map(str::to_string);
            let (Some(resolved), true) =
                (resolved, session_is_current(href, &self.tabs[index].url))
            else {
                return;
            };
            let lang = resolved.as_str();
            {
                self.tabs[index].detected_lang = Some(lang.to_string());
                self.emit_tab_status();
                // CONTINUATION, triggered by the page's own declaration and
                // nothing else. The user translated a page in this language
                // in this tab; the new page says it is the same language; so
                // the standing choice applies. Declared-lang only -- a page
                // that declares nothing waits for a click, which is stated in
                // the panel as an honest limit rather than worked around by
                // reading page text unasked.
                if index == self.active {
                    let code = lang.to_string();
                    self.maybe_continue_translation(index, &code);
                }
            }
            return;
        }

        let tab = &self.tabs[index];
        // A session is required, and it must be for THIS page. A page that
        // posts unprompted -- which any page can, since this runs in its own
        // JS context -- gets its text dropped here.
        if !extract_is_acceptable(
            tab.translation.as_ref().map(|s| s.page.as_str()),
            &tab.url,
            kind,
            href,
        ) {
            return;
        }
        // THE TOKEN, checked separately from the URL because they answer
        // different questions. The URL says "is this the page consent was
        // given for"; the token says "is this THIS run of the session". A user
        // who cancels and clicks again on the same page passes the first check
        // and must still fail the second for run 1's late reply.
        if !extract_token_matches(
            tab.translation.as_ref().map(|s| s.token),
            value.get("session").and_then(Value::as_str),
        ) {
            return;
        }
        let batch: Vec<&str> = match value.get("batch").and_then(Value::as_array) {
            Some(items) => items.iter().filter_map(Value::as_str).collect(),
            None => return,
        };
        let batch: Vec<String> = batch.into_iter().map(str::to_string).collect();
        #[cfg(debug_assertions)]
        {
            self.last_extracted = batch.clone();
        }
        let offset_u64 = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let more = value.get("more").and_then(Value::as_bool).unwrap_or(false);
        // Page-supplied and therefore bounded: a document cannot have more
        // translatable nodes than the extractor's own ceiling allows, and a
        // wild value would only distort a percentage, never a patch.
        let doc_total = value
            .get("total")
            .and_then(Value::as_u64)
            .filter(|t| *t > 0 && *t <= 1_000_000)
            .map(|t| t as usize);

        // OFFSET ORDERING, ENFORCED, AND COMPARED AS u64. The offset is
        // attacker-controlled JSON. A red-team pass showed that trusting it lets
        // a page skip the guard (a non-zero offset first) or corrupt accounting
        // (a huge offset). A reconciliation pass added the 32-bit note: casting
        // to usize BEFORE comparing lets a value congruent mod 2^32 pass on a
        // 32-bit target, so the comparison is done in u64. The offset MUST equal
        // what the host has accepted so far -- first batch 0, each continuation
        // exactly where the last left off -- else the message is dropped.
        let expected_offset = self.tabs[index].translation_extracted as u64;
        if offset_u64 != expected_offset {
            return;
        }
        let offset = offset_u64 as usize; // safe: equals translation_extracted
        self.tabs[index].translation_extracted = offset.saturating_add(batch.len());

        // THE CORRUPTION GUARD, ON EVERY BATCH -- not just the first.
        //
        // The whole reason the rework exists: an en-source model fed Greek
        // emitted mangled Greek that got written into a live page. Checking only
        // the first batch was a red-team CRITICAL: a page could send a tiny or
        // mixed probe that returned Unknown, then send incompatible text in a
        // LATER batch that reached the engine unchecked. Now every batch is
        // checked before it is queued for translation, so wrong-script text
        // never reaches the engine no matter how the page splits it.
        //
        // ONLY A POSITIVE SCRIPT MISMATCH REFUSES. "Unknown" -- too little text,
        // or a Latin page against a Latin source that script cannot
        // disambiguate -- proceeds on the user's explicit source choice, which
        // the dropdown exists to resolve. A clear incompatible script, or a
        // substantial incompatible SHARE across several scripts, is refused.
        // The check runs before any pack is fetched on the first batch, so the
        // common case costs no download and leaves the page untouched; a
        // refusal on a later batch stops further translation (earlier batches
        // stay as translated -- readable, never corrupted).
        // Fold this batch into the session's running tally, then judge the
        // WHOLE page seen so far. A clear mismatch refuses the session; the
        // first batch catches the common case before any pack is fetched, and a
        // later batch that tips the cumulative tally into mismatch stops
        // further translation (earlier batches stay as translated -- readable,
        // never corrupted).
        if let Some(session) = self.tabs[index].translation.as_mut() {
            session.script_counts.add_batch(&batch);
            // The document's translatable-node count, as the page counted it.
            // Kept from whichever batch reports it; a page that rewrites
            // itself mid-run can revise it upward and the panel follows.
            if let Some(t) = doc_total {
                session.doc_total = Some(t);
            }
        }
        // PER NODE, NOT PER PAGE. The cumulative verdict answers "may this
        // page be translated at all"; it cannot answer "may this NODE be
        // sent", and a real page often needs the second question. A language
        // reader prints Macedonian and its English translation in one
        // document: the page tally lands near half foreign, trips the
        // incompatible-share ceiling, and the whole page is refused -- so the
        // reader gets nothing, on a page that is half exactly what they asked
        // for. Filtering instead sends the Macedonian and leaves the English
        // alone, which is what a reader of that page wants.
        //
        // The corruption guard is NOT weakened by this. The incident it exists
        // for -- an en-source model fed Greek -- has every node fail the same
        // check, so the filtered batch comes out empty and the refusal below
        // still fires. What changed is that "some of this page is foreign" and
        // "this page is the wrong language" are no longer the same answer.
        let (sent, map): (Vec<String>, Vec<usize>) = {
            let Some(session) = self.tabs[index].translation.as_ref() else {
                return;
            };
            let mut sent = Vec::new();
            let mut map = Vec::new();
            for (i, text) in batch.iter().enumerate() {
                if session.script_counts.text_is_expected(text) {
                    sent.push(text.clone());
                    map.push(i);
                }
            }
            (sent, map)
        };
        // Nothing on this page belongs to the source the user chose. THAT is a
        // script mismatch; a page merely containing some foreign text is not.
        if sent.is_empty() {
            let refuses = self.tabs[index]
                .translation
                .as_ref()
                .map(|ssn| script_refuses(&ssn.script_counts))
                .unwrap_or(false);
            if refuses {
                self.fail_translation(index, "translate-script-mismatch");
                return;
            }
            // Too little text to judge and nothing to send: ask for the next
            // batch rather than ending the run on an inconclusive one.
            if let Some(session) = self.tabs[index].translation.as_mut() {
                session.batch = Vec::new();
                session.batch_map = Vec::new();
                session.batch_span = batch.len();
                session.offset = offset;
                session.more = more;
                session.last_progress = std::time::Instant::now();
            }
            self.request_next_batch(index);
            return;
        }

        if let Some(session) = self.tabs[index].translation.as_mut() {
            session.batch_span = batch.len();
            session.batch = sent;
            session.batch_map = map;
            session.submitted = false;
            session.offset = offset;
            session.more = more;
            session.phase = TranslationPhase::Translating;
            session.last_progress = std::time::Instant::now();
        }
        self.emit_tab_status();
        // From here it is the engine's turn. The tick drives boot, pack load
        // and translation in that order, reading the translator document
        // rather than assuming any of them finished.
        self.start_translate_poller();
    }

    /// Builds the hidden translator webview, once, on first use.
    ///
    /// LAZY ON PURPOSE. It costs a WebView2/WebKitGTK instance and, once a
    /// pack is loaded, a couple of hundred megabytes of wasm heap. A user who
    /// never translates anything must never pay that, which means it cannot be
    /// created at startup no matter how much simpler that would be.
    ///
    /// OWN ORIGIN, OWN DATA STORE, OWN PROTOCOL HANDLER -- `build_translator`
    /// and `serve_translator`, never `serve_chrome`. Phase 0 measured what a
    /// shared origin leaks (storage both ways on WebView2, IndexedDB and
    /// cross-session localStorage on WebKitGTK, and `serve_chrome` answering
    /// screen captures and decrypted archive pages), which is why this is a
    /// separate arrangement rather than another chrome window.
    fn translator(&mut self) -> Option<&WebView> {
        if self.translator.is_none() {
            let builder = platform::new_translator_webview_builder()
                // THE DOCUMENT URL CARRIES THE REVISION TOO, and that is the
                // whole point rather than a flourish. Versioning only the
                // SCRIPT urls cannot bootstrap: the document that carries the
                // new script urls is itself cached, so a stale copy is served,
                // it references the old unversioned scripts, and they are
                // served from cache as well. The eviction never begins.
                //
                // Four builds reached a tester and produced byte-identical
                // wrong output while the code changed underneath them, because
                // the entry point never changed. Changing it is what makes
                // every asset below it reachable again.
                .with_url(&format!(
                    "{}?v={}",
                    platform::TRANSLATE_URL,
                    crate::asset_revision()
                ))
                .with_custom_protocol(
                    platform::TRANSLATE_SCHEME.to_string(),
                    move |_id, request: wry::http::Request<Vec<u8>>| {
                        crate::serve_translator(&request)
                    },
                );
            match platform::build_translator(&self.hosts, builder) {
                Ok(view) => self.translator = Some(view),
                Err(_) => {
                    // Degrade, never crash. The session fails with a named
                    // reason on the next tick and the panel says so.
                    return None;
                }
            }
        }
        self.translator.as_ref()
    }

    /// Starts the poll loop if it is not already running.
    ///
    /// RUNS ONLY WHILE THERE IS WORK. The flag it shares with the thread is
    /// cleared by the first tick that finds nothing in flight, and the thread
    /// exits on seeing that. A browser sitting idle does not tick, which
    /// matters more than it sounds: this wakes the event loop, and a permanent
    /// timer in a privacy browser is a permanent reason for the machine not to
    /// sleep.
    /// Asks the page for the batch AFTER the one just handled.
    ///
    /// Its own method because two callers need it and they must not drift: the
    /// normal continuation after a patch lands, and the case where an entire
    /// batch was filtered out as foreign -- a mixed page can easily produce a
    /// run of English nodes between two Macedonian ones, and stopping there
    /// would translate the top of the page and quietly abandon the rest.
    fn request_next_batch(&mut self, index: usize) {
        let Some((token, next_offset, more)) = self.tabs[index]
            .translation
            .as_ref()
            .map(|s| (s.token, s.offset + s.batch_span, s.more))
        else {
            return;
        };
        if !more {
            if let Some(session) = self.tabs[index].translation.as_mut() {
                session.phase = TranslationPhase::Done;
            }
            self.emit_tab_status();
            return;
        }
        let cmd = json!({
            "cmd": "extract",
            "session": token.to_string(),
            "offset": next_offset,
            "limitNodes": EXTRACT_MAX_NODES,
            "limitChars": EXTRACT_MAX_CHARS,
        });
        let tab = &self.tabs[index];
        if platform::deliver_translation(&tab.webview, &tab.view, cmd.to_string()) {
            if let Some(session) = self.tabs[index].translation.as_mut() {
                session.phase = TranslationPhase::Translating;
                session.last_progress = std::time::Instant::now();
            }
        } else {
            self.fail_translation(index, "translate-patch-failed");
        }
        self.emit_tab_status();
    }

    fn start_translate_poller(&mut self) {
        if self.translate_polling.is_some() {
            return;
        }
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        self.translate_polling = Some(alive.clone());
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            while alive.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(TRANSLATE_POLL_INTERVAL);
                if proxy.send_event(UserEvent::TranslateTick).is_err() {
                    // The event loop is gone; so is the browser.
                    break;
                }
            }
        });
    }

    fn stop_translate_poller(&mut self) {
        if let Some(alive) = self.translate_polling.take() {
            alive.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Finds the one session currently waiting on the engine.
    ///
    /// ONE AT A TIME. The engine is a single hidden document with one loaded
    /// pack, so two tabs translating at once would have them fighting over
    /// which pack is resident. The second tab waits; it does not fail, and it
    /// does not silently swap the pack out from under the first.
    fn translating_tab(&self) -> Option<usize> {
        self.tabs
            .iter()
            .position(|t| {
                matches!(
                    t.translation.as_ref().map(|s| &s.phase),
                    // Preparing is IN FLIGHT: a session waiting for the page
                    // to answer its extract request must be ticked too, or
                    // the stall deadline below can never fire for exactly the
                    // stuck state it exists to end.
                    Some(TranslationPhase::Preparing) | Some(TranslationPhase::Translating)
                )
            })
    }

    /// One step. Reads the translator rather than assuming its state.
    pub fn on_translate_tick(&mut self) {
        let Some(index) = self.translating_tab() else {
            // Nothing in flight: stop ticking rather than spinning forever.
            self.stop_translate_poller();
            return;
        };
        let Some(session) = self.tabs[index].translation.as_ref() else {
            self.stop_translate_poller();
            return;
        };
        let (token, submitted) = (session.token, session.submitted);
        let pair = session.pair;
        let preparing = matches!(session.phase, TranslationPhase::Preparing);
        let stalled = session.last_progress.elapsed() >= TRANSLATE_STALL_DEADLINE;
        // THE STALL DEADLINE. Not while a pack for this pair is downloading:
        // that wait has its own progress feed, and its failure already fails
        // the session through on_pack_installed.
        if stalled && !self.pack_downloads.contains_key(pair) {
            self.fail_translation(index, "translate-timeout");
            return;
        }
        // Waiting on the page's extract reply: nothing to ask the engine yet.
        if preparing {
            return;
        }
        let proxy = self.proxy.clone();
        let Some(view) = self.translator() else {
            self.fail_translation(index, "translate-engine-failed");
            return;
        };
        // A job already with the engine: ask for its result. Otherwise ask
        // what the document is ready for.
        let script = if submitted {
            format!(
                "window.__translator.result({})",
                js_string(&json!({ "id": token.to_string() }).to_string())
            )
        } else {
            "window.__translator.status()".to_string()
        };
        let _ = view.evaluate_script_with_callback(&script, move |raw| {
            // `raw` is the JSON-encoded return value, so it is a JSON STRING
            // containing our JSON. Unwrapped once here and parsed in the
            // handler, which is the single place that reads this shape.
            let inner = serde_json::from_str::<String>(&raw).unwrap_or(raw);
            let _ = if submitted {
                proxy.send_event(UserEvent::TranslateResult(token, inner))
            } else {
                proxy.send_event(UserEvent::TranslateEngine(inner))
            };
        });
    }

    /// The translator document said what it is ready for. Advance it.
    pub fn on_translate_engine(&mut self, json: &str) {
        let Some(index) = self.translating_tab() else {
            return;
        };
        let Ok(value) = serde_json::from_str::<Value>(json) else {
            return;
        };
        let phase = value.get("phase").and_then(Value::as_str).unwrap_or("");
        let loaded_pair = value.get("pair").and_then(Value::as_str).unwrap_or("");
        // THE INSTRUMENT. Which copy of translator.js is running, and how much
        // linear memory it got. Four builds produced byte-identical wrong
        // output while the code changed underneath them, and nothing could
        // distinguish a stale script from a correct one computing a wrong
        // answer. Recorded on the session so the panel can show it: a fact a
        // person can read beats another round of inference.
        {
            let rev = value
                .get("assetRev")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let heap = value.get("heapBytes").and_then(Value::as_u64);
            // The census of what crossed into the engine. Counts only -- the
            // text itself never leaves the translator document.
            let census = value.get("lastInput").cloned();
            if let Some(session) = self.tabs[index].translation.as_mut() {
                if !rev.is_empty() {
                    session.engine_asset_rev = Some(rev);
                }
                if heap.is_some() {
                    session.engine_heap_bytes = heap;
                }
                if let Some(c) = census {
                    if !c.is_null() {
                        session.engine_last_input = Some(c);
                    }
                }
            }
        }
        let (pair, token) = {
            let Some(session) = self.tabs[index].translation.as_mut() else {
                return;
            };
            // AN ENGINE THAT ANSWERS IS ALIVE, and that is what the stall
            // deadline is entitled to measure. Booting, loading a 74 MiB
            // tier-2 pack, or grinding through a batch are all SLOW, not
            // stuck, and every one of them answers this poll. Marking only on
            // finished batches made the deadline a work-rate limit: it killed
            // correct Latin translations at sixty seconds because OPUS-MT is
            // about eleven times slower than the Mozilla students and a
            // 200-node batch simply takes longer than that. Silence is the
            // only symptom worth failing on.
            session.last_progress = std::time::Instant::now();
            (session.pair, session.token)
        };

        if phase == "failed" {
            // The document's own error KEY, forwarded as-is: it is a catalog
            // key by construction (see translator.js), never prose, so it can
            // reach the panel and be rendered in the user's language.
            let key = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("translate-engine-failed")
                .to_string();
            self.fail_translation(index, &key);
            return;
        }
        // Still booting or still loading: nothing to do but wait for the next
        // tick. Reporting progress here would mean guessing at a percentage
        // the engine does not provide.
        if phase == "boot" || phase == "loading-engine" || phase == "loading-pack" {
            return;
        }
        if phase == "engine-ready" || (phase == "ready" && loaded_pair != pair) {
            // THE PACK HAS TO EXIST BEFORE THE ENGINE IS ASKED FOR IT. A
            // missing one is the NORMAL first-run state, not an error: no
            // language model ships in the installer, by ruling, so the first
            // translation into any language downloads one.
            let root = crate::pack_root().to_path_buf();
            if !crate::langpack::installed(&root, pair) {
                self.start_pack_download(pair);
                return;
            }
            // FROM AND TO RIDE ALONGSIDE THE TOKEN, from the registry row.
            // The translator document used to derive them by byte-slicing the
            // token (slice(0,2)/(3,5)), which is silently wrong for any
            // longer subtag: "en-zh-Hans" sliced to from="en", to="h-". A
            // token is not self-delimiting, so components travel as data and
            // nothing anywhere splits one.
            let Some(row) = crate::languages::pair_by_token(pair) else {
                // Unreachable while sessions are built from validated pairs;
                // refuse rather than slice if that ever changes.
                self.fail_translation(index, "translate-failed");
                return;
            };
            // ONE PRECISION FOR EVERY PACK, AND IT IS THE ONE THAT WORKS ON
            // THE PLATFORM MOST USERS RUN.
            //
            // OPUS-MT packs used int8shiftAlphaAll, on the spike's finding
            // that uncalibrated int8 turned the ine-eng model into word
            // salad. That was measured on WebKitGTK. On WebView2 the SAME
            // pack, over the same channel, produced fluent English with no
            // relation to the input -- a Macedonian article rendered as
            // invented sentences, while a French page through a Mozilla pack
            // (int8shiftAll) on that same build was near-perfect. Valid
            // tokens, wrong arithmetic: the alphas path does not compute the
            // same thing on the two engines, and the test hardware is
            // the one that counts.
            //
            // Re-measured both ways on every converted pack after the vocab
            // rebuild, and the premise no longer holds anyway: plain int8 is
            // equal or BETTER on all of them. On Latin it keeps "Gallia",
            // which the alphas path turned into "Galileo". So the calibration
            // is not carrying quality here -- it was compensating for the
            // misaligned vocabulary that has since been fixed.
            //
            // Alphas remain in the model files, ignored by this path. A pack
            // that genuinely needs them would need its precision recorded
            // per-pack in the catalog rather than inferred from `source`;
            // nothing does today, and inferring it is what shipped a broken
            // path to Windows.
            let _ = row.source;
            let gemm = "int8shiftAll";
            let script = format!(
                "window.__translator.loadPack({})",
                js_string(
                    &json!({
                        "pair": pair, "from": row.from, "to": row.to,
                        "gemm": gemm, "vocab": row.vocab,
                    })
                    .to_string()
                )
            );
            if let Some(view) = self.translator() {
                let _ = view.evaluate_script(&script);
            }
            return;
        }
        if phase == "ready" && loaded_pair == pair {
            let Some(session) = self.tabs[index].translation.as_ref() else {
                return;
            };
            if session.batch.is_empty() {
                return;
            }
            // THE ONE CROSSING THAT CARRIES PAGE TEXT INTO THE ENGINE. A FIXED
            // wrapper with a serde_json-encoded argument: the text is a string
            // literal, never source. `js_string` additionally escapes U+2028
            // and U+2029, which are legal in JSON and were illegal in JS string
            // literals before ES2019 -- both engines are far past that, and it
            // costs nothing to not depend on it.
            let payload = json!({
                "id": token.to_string(),
                // The pair this text is FOR. The document checks it against
                // what it actually has loaded -- this side's own check reads a
                // status polled earlier and cannot see a pack swapped in
                // since. Cheap, and being wrong means a page goes through
                // another language's model.
                "pair": pair,
                "texts": session.batch,
            })
            .to_string();
            let script = format!("window.__translator.translate({})", js_string(&payload));
            if let Some(view) = self.translator() {
                let _ = view.evaluate_script(&script);
            }
            if let Some(session) = self.tabs[index].translation.as_mut() {
                session.submitted = true;
            }
        }
    }

    /// A job came back. Patch the page, or fail visibly.
    pub fn on_translate_result(&mut self, job: u64, json: &str) {
        let Some(index) = self.translating_tab() else {
            return;
        };
        {
            let Some(live) = self.tabs[index].translation.as_mut() else {
                return;
            };
            // A result for a session that has been replaced or cancelled is
            // dropped: the indices in it address a node map that no longer
            // exists.
            if live.token != job {
                return;
            }
            // Liveness, for the same reason as the status handler above: the
            // `pending` answer below returns early, and while a job is with
            // the engine that is the ONLY answer arriving. Without this mark a
            // translation that is running perfectly looks identical to one
            // that died, and the deadline picked the wrong one.
            live.last_progress = std::time::Instant::now();
        }
        let Some(session) = self.tabs[index].translation.as_ref() else {
            return;
        };
        // THE PAGE MUST STILL BE THE ONE THIS TEXT CAME FROM.
        //
        // Navigation deliberately leaves the session alive -- that is hygiene,
        // and `session_is_current` is what actually refuses stale work -- and
        // EXTRACTION checks the url. Delivery did not: it validated the job
        // token and posted the patch to the tab's CURRENT webview. A
        // translation still in flight when the user navigated was therefore
        // handed to whatever origin the tab now showed.
        //
        // Our own content script drops it, because the session id no longer
        // matches. But any page can register the same native message listener
        // and read the strings: that is the PREVIOUS page's translated text,
        // its content, disclosed to an unrelated origin. Found by an
        // independent audit on 2026-09-01 and reproduced against this handler
        // before it was changed.
        //
        // The session is ended rather than deferred: it was consented for a
        // page that is gone.
        if !session_is_current(&session.page, &self.tabs[index].url) {
            self.tabs[index].translation = None;
            self.emit_tab_status();
            return;
        }
        let Ok(value) = serde_json::from_str::<Value>(json) else {
            return;
        };
        if value.get("pending").and_then(Value::as_bool) == Some(true) {
            return;
        }
        if let Some(key) = value.get("error").and_then(Value::as_str) {
            let key = key.to_string();
            self.fail_translation(index, &key);
            return;
        }
        let Some(items) = value.get("items").and_then(Value::as_array) else {
            self.fail_translation(index, "translate-failed");
            return;
        };
        // Rebuilt rather than forwarded. The document returns {i, t} and the
        // page expects {i, t}, but passing the engine's array straight through
        // would let a future change in one shape reach the other without
        // anybody noticing.
        // ABSOLUTE INDICES. The engine numbers its output from zero within the
        // batch it was given; the page numbers its node map across the whole
        // document. Adding the batch's offset is what joins the two, and
        // getting it wrong would patch run 2's translations onto run 1's
        // paragraphs -- a page scrambled into itself, which is far worse than
        // a page left untranslated.
        let offset = session.offset;
        let patch: Vec<Value> = items
            .iter()
            .filter_map(|item| {
                let i = item.get("i").and_then(Value::as_u64)?;
                let t = item.get("t").and_then(Value::as_str)?;
                // Through the filter map FIRST, then into document space. An
                // engine index addresses what was SENT; the page's node map
                // addresses what was EXTRACTED, and skipped nodes sit between
                // them. An out-of-range index is dropped rather than clamped:
                // a patch aimed at a node we cannot name is not a patch.
                let at = patch_index(i as usize, &session.batch_map, offset)?;
                Some(json!({ "i": at, "t": t }))
            })
            .collect();
        let count = patch.len();
        let token = session.token;
        let more = session.more;
        // The SPAN, not the sent length: the next batch starts after every
        // node this one covered, including the ones filtered out. Advancing by
        // the sent length would re-extract the skipped nodes forever.
        let next_offset = session.offset + session.batch_span;
        let message = json!({
            "cmd": "patch",
            "session": token.to_string(),
            "items": patch,
        })
        .to_string();
        // SELF-TEST ONLY, debug builds only: the translated text itself, so a
        // harness can judge a pack's OUTPUT rather than only that a patch
        // landed. Release builds never log page text (the privacy promise);
        // this is compiled out of them entirely.
        #[cfg(all(debug_assertions, unix))]
        if crate::translate_channel_probe::selftest_enabled() {
            let texts: Vec<String> = patch
                .iter()
                .filter_map(|p| p.get("t").and_then(|t| t.as_str()).map(str::to_string))
                .collect();
            println!(
                "{}",
                json!({ "selftest_translations": texts.join(" | ") })
            );
        }
        let tab = &self.tabs[index];
        let delivered = platform::deliver_translation(&tab.webview, &tab.view, message);
        if let Some(session) = self.tabs[index].translation.as_mut() {
            // PAGE TEXT IS DROPPED THE MOMENT IT IS NO LONGER NEEDED. The
            // batch has been translated and sent back; keeping it would mean
            // the host holding a copy of what the user was reading for as long
            // as the tab lives.
            session.batch = Vec::new();
            session.submitted = false;
            session.patched_total += count;
            session.last_progress = std::time::Instant::now();
            session.phase = if delivered {
                TranslationPhase::Done
            } else {
                TranslationPhase::Failed("translate-patch-failed")
            };
        }
        // A page that finished translating is this tab's standing choice:
        // the SAME language keeps translating as the user browses on, until
        // Show original or Cancel says stop. Recorded only on success --
        // a failed run must not become a standing order.
        if delivered {
            if let Some(pair) = self.tabs[index].translation.as_ref().map(|s| s.pair) {
                self.tabs[index].translate_continue = Some(pair);
            }
        }
        let total = self
            .tabs[index]
            .translation
            .as_ref()
            .map(|s| s.patched_total)
            .unwrap_or(count);
        self.tabs[index].translation_patched = total;

        // MORE OF THE PAGE TO GO, so ask for it. A cap of 200 nodes was never
        // meant to be where translation STOPS -- it is how much is read at a
        // time, so a long article fills in progressively instead of freezing
        // the panel for a minute. Without this the feature translated the top
        // of a page and left the rest in English, which is not what the button
        // says it does.
        //
        // Only when the last batch actually landed: continuing after a failed
        // patch would read more of a page nobody is going to see.
        if delivered && more {
            let cmd = json!({
                "cmd": "extract",
                "session": token.to_string(),
                "offset": next_offset,
                "limitNodes": EXTRACT_MAX_NODES,
                "limitChars": EXTRACT_MAX_CHARS,
            });
            let tab = &self.tabs[index];
            if platform::deliver_translation(&tab.webview, &tab.view, cmd.to_string()) {
                if let Some(session) = self.tabs[index].translation.as_mut() {
                    session.phase = TranslationPhase::Translating;
                }
                self.emit_tab_status();
                // The poller is already running; the next extraction arrives
                // as a ContentTranslate and the machine turns again.
                return;
            }
        }
        self.stop_translate_poller();
        self.emit_tab_status();
    }

    /// What the self-test needs to see, in one call.
    ///
    /// Debug builds only. Returns the active tab's translation phase, how many
    /// nodes the last run patched, and the last batch a page sent up.
    #[cfg(debug_assertions)]
    pub fn selftest_snapshot(&self) -> (String, usize, Vec<String>) {
        let phase = self
            .tabs
            .get(self.active)
            .and_then(|t| t.translation.as_ref())
            .map(|s| match &s.phase {
                TranslationPhase::Preparing => "preparing".to_string(),
                TranslationPhase::Translating => "translating".to_string(),
                TranslationPhase::Done => "done".to_string(),
                TranslationPhase::Failed(k) => format!("failed:{k}"),
            })
            .unwrap_or_else(|| "none".to_string());
        let patched = self
            .tabs
            .get(self.active)
            .map(|t| t.translation_patched)
            .unwrap_or(0);
        (phase, patched, self.last_extracted.clone())
    }

    /// Starts one pack download, on a thread, if one is not already running.
    ///
    /// OFF THE UI THREAD, because it is tens of megabytes over a network and
    /// the event loop draws the window. The thread does the whole
    /// fetch-verify-install and reports one result; nothing partial crosses
    /// back, so there is no state here that can be half-updated.
    ///
    /// THE USER ALREADY CONSENTED. This runs only inside a session the user
    /// started by clicking Translate and picking a language, and the panel says
    /// a pack may download. Nothing here fetches speculatively or in advance.
    fn start_pack_download(&mut self, pair: &'static str) {
        // THE TIER GATE'S CHOKE POINT. Every pack download in the product
        // starts here -- the user's Install, and the fetch a translation makes
        // when its pack is missing -- so the entitlement check lives here
        // rather than in each caller. A future third caller is gated by
        // construction instead of by remembering. `install_language` still
        // checks separately, because it must REPORT the refusal; this is the
        // wall behind that door.
        if !tier_allows(pair, crate::licence_control::premium_active()) {
            return;
        }
        // Per-token single-flight: already fetching THIS pair, nothing to do.
        // A different pair may fetch in parallel (the two directions of a
        // language install, or a translate download beside a user install).
        if self.pack_downloads.contains_key(pair) {
            return;
        }
        // A fresh attempt is not the old attempt's failure.
        self.pack_failures.remove(pair);
        self.pack_downloads.insert(pair, (0, None));
        let root = crate::pack_root().to_path_buf();
        let proxy = self.proxy.clone();
        let progress_proxy = self.proxy.clone();
        std::thread::spawn(move || {
            // THROTTLED AT THE SOURCE. The reader reports every 64 KiB, which
            // is ~1,600 events for one large pack -- and each event costs a
            // full packs_status rebuild (a disk stat per registry pair) plus
            // a script evaluation into the chrome, which then re-renders the
            // whole panel. Two simultaneous installs produced events faster
            // than the main thread drained them and the BROWSER froze; it
            // was found by not being able to click anything. Four
            // updates a second is indistinguishable to a person reading a
            // percentage, and the completion event below is unconditional,
            // so the final state can never be missed.
            let mut last_sent: Option<std::time::Instant> = None;
            let failure = crate::langpack::install_with_progress(&root, pair, |got, total| {
                let now = std::time::Instant::now();
                let due = last_sent
                    .is_none_or(|at| now.duration_since(at) >= std::time::Duration::from_millis(250));
                if !due {
                    return;
                }
                last_sent = Some(now);
                let _ = progress_proxy.send_event(UserEvent::PackProgress(pair, got, total));
            })
            .err()
            .map(|e| e.key());
            let _ = proxy.send_event(UserEvent::PackInstalled(pair, failure));
        });
    }

    /// Progress on an in-flight pack. Recorded for the panel; no logic hangs
    /// off it, so a late or out-of-order event is harmless.
    pub fn on_pack_progress(&mut self, pair: &'static str, got: u64, total: Option<u64>) {
        if let Some(slot) = self.pack_downloads.get_mut(pair) {
            *slot = (got, total);
            self.emit_packs_status();
        }
    }

    /// A pack download finished. Clears the in-flight slot, then either lets a
    /// waiting translation proceed or just refreshes the packs panel.
    pub fn on_pack_installed(&mut self, pair: &'static str, failure: Option<&'static str>) {
        self.pack_downloads.remove(pair);
        match failure {
            Some(key) => self.pack_failures.insert(pair, key),
            None => self.pack_failures.remove(pair),
        };
        self.emit_packs_status();
        // A translation waiting on THIS pack: advance or fail it. A translation
        // waiting on a DIFFERENT pack (the mapping hazard) must not be
        // disturbed -- check the waiting session's pair before touching it.
        if let Some(index) = self.translating_tab() {
            let waiting_on = self.tabs[index]
                .translation
                .as_ref()
                .map(|ssn| ssn.pair == pair)
                .unwrap_or(false);
            if waiting_on {
                if let Some(key) = failure {
                    self.fail_translation(index, key);
                } else {
                    if let Some(session) = self.tabs[index].translation.as_mut() {
                        session.last_progress = std::time::Instant::now();
                    }
                    self.start_translate_poller();
                }
            }
        }
    }

    /// Installs a language the user chose: BOTH directions that the registry
    /// publishes (X-en and en-X), because a language is useful for reading
    /// pages in it AND writing pages into it, and the UI offers it as one
    /// choice. A one-directional language installs the one direction that
    /// exists and the packs panel reports which directions it got.
    pub fn install_language(&mut self, code: &str) -> Result<Value, &'static str> {
        let code = crate::languages::LANGUAGES
            .iter()
            .find(|l| l.code == code)
            .map(|l| l.code)
            .ok_or("unknown_language")?;
        // The pivot has no pack of its own: every pair is English-anchored, so
        // "install English" would match the ENTIRE registry and start several
        // gigabytes of downloads. English arrives with each language instead.
        if code == "en" {
            return Err("pivot_language");
        }
        // THE PREMIUM GATE, client-side by decision: the server serves
        // anyone (the bytes are public upstream anyway, and gating there would
        // attach an identity to a request that today discloses only a pair);
        // the browser is where the tier is enforced. A tier-2 pair installs
        // only while a Premium licence is ACTIVE on this device --
        // licence_control::premium_active is the entire rule, same as every
        // other premium feature.
        let entitled = crate::licence_control::premium_active();
        let mut started = 0;
        let mut premium_blocked = 0;
        for pair in crate::languages::PAIRS.iter() {
            if pair.from == code || pair.to == code {
                if !tier_allows(pair.token, entitled) {
                    premium_blocked += 1;
                    continue;
                }
                if crate::langpack::installed(&crate::pack_root(), pair.token) {
                    continue;
                }
                self.start_pack_download(pair.token);
                started += 1;
            }
        }
        // Nothing started and something was withheld: the user asked for a
        // language they are not entitled to, and silence would read as a bug.
        if started == 0 && premium_blocked > 0 {
            return Err("premium_language_required");
        }
        self.emit_packs_status();
        self.packs_status()
    }

    /// Removes a language: both directions, from disk. A pack mid-download is
    /// left to finish rather than racing its own writer; removing it then is a
    /// second click.
    pub fn remove_language(&mut self, code: &str) -> Result<Value, &'static str> {
        let code = crate::languages::LANGUAGES
            .iter()
            .find(|l| l.code == code)
            .map(|l| l.code)
            .ok_or("unknown_language")?;
        // Same reason as install: "remove English" would strip every pack.
        if code == "en" {
            return Err("pivot_language");
        }
        let root = crate::pack_root();
        for pair in crate::languages::PAIRS.iter() {
            if (pair.from == code || pair.to == code)
                && !self.pack_downloads.contains_key(pair.token)
            {
                let _ = crate::langpack::remove(&root, pair.token);
            }
        }
        self.emit_packs_status();
        self.packs_status()
    }

    /// The packs panel's data: one row per language, with what is installed,
    /// what is downloading (and how far), and the approximate size.
    ///
    /// NAMES ARE HOST-SUPPLIED DATA here, like ledger hostnames -- English
    /// until a second locale exists, which is stated honestly in the UI rather
    /// than pretended otherwise. Everything else is a fact about disk or the
    /// registry.
    pub fn packs_status(&self) -> Result<Value, &'static str> {
        let root = crate::pack_root();
        let entitled = crate::licence_control::premium_active();
        let rows: Vec<Value> = crate::languages::LANGUAGES
            .iter()
            .map(|lang| {
                // The two directions this language could have, and their state.
                let mut directions = Vec::new();
                let mut approx = 0u64;
                for pair in crate::languages::PAIRS.iter() {
                    if pair.from != lang.code && pair.to != lang.code {
                        continue;
                    }
                    approx += pair.approx_bytes;
                    let downloading = self.pack_downloads.get(pair.token).copied();
                    directions.push(json!({
                        "token": pair.token,
                        "from": pair.from,
                        "to": pair.to,
                        "tier": pair.tier,
                        "source": pair.source,
                        "installed": crate::langpack::installed(&root, pair.token),
                        "downloading": downloading.is_some(),
                        "got": downloading.map(|(g, _)| g),
                        "total": downloading.and_then(|(_, t)| t),
                        "failed": self.pack_failures.get(pair.token).copied(),
                    }));
                }
                // INSTALLED MEANS EVERY DIRECTION, not one of them.
                //
                // `any` was wrong in a way that stranded a language with no way
                // out: a user with en-es from the old single-pair build saw
                // Spanish marked Installed, so the row offered REMOVE and
                // nothing else -- while es-en had never been fetched, leaving
                // Spanish->English with no target and no control to fix it. The
                // language looked complete and could not be used in the
                // direction most people want.
                //
                // `partial` is reported alongside so the panel can say so and
                // offer to finish the job; install_language already skips the
                // directions that are present, so completing costs only what is
                // missing.
                let installed_count = directions
                    .iter()
                    .filter(|d| d["installed"].as_bool().unwrap_or(false))
                    .count();
                let all_installed = installed_count > 0 && installed_count == directions.len();
                let partly_installed = installed_count > 0 && !all_installed;
                let any_downloading = directions
                    .iter()
                    .any(|d| d["downloading"].as_bool().unwrap_or(false));
                // FIRST failure, not a count: the row has space for one reason
                // and every reason is actionable on its own.
                let failed = directions
                    .iter()
                    .find_map(|d| d["failed"].as_str())
                    .map(str::to_owned);
                // A language is Premium when ANY direction it has is tier 2.
                // The registry generator REFUSES to emit a mixed-tier language
                // (a hard invariant, tested), so today every language is wholly
                // one tier and `any` == `all`. `any` is nonetheless the correct
                // reading: if that invariant were ever broken, this fails SAFE
                // -- the row says Premium and the gate holds -- instead of
                // presenting an ordinary Install that silently does half the
                // job.
                let premium = directions
                    .iter()
                    .any(|d| d["tier"].as_u64().unwrap_or(1) >= 2);
                json!({
                    "code": lang.code,
                    "name": lang.name,
                    "approx_bytes": approx,
                    "installed": all_installed,
                    "partial": partly_installed,
                    "downloading": any_downloading,
                    "failed": failed,
                    "premium": premium,
                    "directions": directions,
                })
            })
            // A FREE INSTALL NEVER LEARNS THESE LANGUAGES EXIST. Filtered
            // HERE rather than in the panel, so the rows do not cross to the
            // chrome at all: a locked row advertising something that cannot be
            // bought is an advert, not a feature, and a UI-only filter would
            // still put the list one devtools inspection away.
            //
            // ONE EXCEPTION, and it is about not stranding data rather than
            // about selling: a premium language that is ALREADY INSTALLED
            // stays listed even unentitled, because a licence that lapses
            // otherwise leaves tens of megabytes on disk with no control to
            // remove them. It still cannot be USED -- translate_active_tab
            // refuses tier 2 without a licence -- so what remains visible is
            // a Remove button, not a feature.
            .filter(|row| {
                let premium = row["premium"].as_bool().unwrap_or(false);
                let installed = row["installed"].as_bool().unwrap_or(false);
                !premium || entitled || installed
            })
            .collect();
        Ok(json!({
            "languages": rows,
            // The CLIENT-SIDE premium gate's current answer, so the panel can
            // render a locked Install honestly instead of failing on click.
            "premium_active": crate::licence_control::premium_active(),
        }))
    }

    /// Remembers the target language for next time. Accepts only a code the
    /// registry knows, so a stray value can never be written to prefs.
    pub fn set_translate_target(&mut self, code: &str) -> Result<Value, &'static str> {
        let code = crate::languages::LANGUAGES
            .iter()
            .find(|l| l.code == code)
            .ok_or("unknown_language")?
            .code;
        let mut prefs = crate::prefs::load();
        prefs.translate_target = code.to_string();
        // A failed save is worth reporting: the user picked a default and it
        // silently did not stick otherwise.
        crate::prefs::save(&prefs).map_err(|_| "prefs_write_failed")?;
        Ok(json!({ "target": code }))
    }

    /// Pushes packs_status to the chrome. Called whenever the set changes.
    fn emit_packs_status(&self) {
        if let Ok(status) = self.packs_status() {
            self.emit("packs_status", status);
        }
    }

    /// Ends a session with a named, renderable reason.
    ///
    /// FAIL CLOSED TO UNTRANSLATED. The page keeps whatever it already has and
    /// nothing further is sent; a page stuck between two languages is worse
    /// than one that was never touched.
    fn fail_translation(&mut self, index: usize, key: &str) {
        if let Some(session) = self.tabs[index].translation.as_mut() {
            session.batch = Vec::new();
            session.submitted = false;
            session.phase = TranslationPhase::Failed(translation_failure_key(key));
        }
        self.stop_translate_poller();
        self.emit_tab_status();
    }

    /// Applies this tab's standing translate-this-language choice to a page
    /// that just DECLARED that language.
    ///
    /// Every refusal here is SILENT by design: this path was not asked for by
    /// a click, so it must never put a failure banner on a page the user did
    /// not ask to translate. The guards, in order: a standing choice exists;
    /// the declared primary subtag matches the pair's source; no session is
    /// already live for this page; and the pack is ON DISK -- an automatic
    /// run must never start a network fetch, because a network contact still
    /// requires a click. Whatever passes those runs through the same entry
    /// path as a click, so the premium gate, the URL check and the script
    /// guard all apply unchanged.
    fn maybe_continue_translation(&mut self, index: usize, declared_primary: &str) {
        let Some(pair) = self.tabs[index].translate_continue else {
            return;
        };
        let Some(row) = crate::languages::pair_by_token(pair) else {
            return;
        };
        if !declared_primary.eq_ignore_ascii_case(row.from) {
            return;
        }
        // (The argument is a REGISTRY CODE now, resolved at the detected
        // handler; the name survives from when it was a bare primary subtag.)
        if let Some(session) = self.tabs[index].translation.as_ref() {
            if session_is_current(&session.page, &self.tabs[index].url) {
                return;
            }
        }
        if !crate::langpack::installed(&crate::pack_root(), pair) {
            return;
        }
        let _ = self.translate_active_tab(pair);
    }

    /// Starts a translation session on the ACTIVE tab.
    ///
    /// Takes a language pair and NOTHING ELSE, for the same reason
    /// `forget_active_tab_cookies` takes no domain: the chrome UI has no
    /// legitimate reason to name which page to translate, and refusing to
    /// accept one stops this becoming a translate-any-tab primitive if the
    /// chrome origin were ever compromised. The tab is whichever one the user
    /// is looking at, and the URL is read here, not supplied.
    pub fn translate_active_tab(&mut self, pair: &str) -> Result<Value, &'static str> {
        // Validated to a STATIC token before it is stored. This value selects
        // a model to load later; a free-form string reaching that path is the
        // shape of an injection, so it is rejected here rather than sanitised
        // downstream.
        let pair = validate_translation_pair(pair).ok_or("unsupported_pair")?;
        // THE PREMIUM GATE AT USE, not only at install. Install-gating alone
        // let a lapsed licence keep translating with a tier-2 pack that is
        // still on disk -- the one premium feature that would survive a lapse,
        // when "LAPSED gates exactly like FREE" is the rule everywhere else.
        // A tier-2 pair translates only while the licence is ACTIVE; the pack
        // stays installed (removing someone's download on a lapse would be
        // hostile), it simply cannot be USED until the licence is.
        //
        // This is also what bounds the one staleness the download path has:
        // entitlement is sampled when a download STARTS, so a licence that
        // lapses mid-download leaves the bytes on disk. They are unusable
        // until the licence returns, which is the same place a lapse leaves
        // every other premium feature.
        if !tier_allows(pair, crate::licence_control::premium_active()) {
            return Err("premium_language_required");
        }
        let tab = self.tabs.get_mut(self.active).ok_or("no_tab")?;
        // Internal pages have nothing a user asked to read in another
        // language, and translating one would mean pointing the machinery at
        // our own UI.
        if !is_translatable_url(&tab.url) {
            return Err("not_translatable");
        }
        // NOTHING IS ASKED OF A PAGE THAT IS NOT LISTENING. On WebKitGTK this
        // means a poll is parked; on Windows, that a document announced
        // itself. Either way it is OBSERVED, not assumed, so a tab showing a
        // PDF or an error page refuses here instead of appearing to start and
        // then never finishing.
        if !platform::translate_page_ready(&tab.view) {
            return Err("page_not_ready");
        }
        self.translation_seq = self.translation_seq.wrapping_add(1);
        let token = self.translation_seq;
        let tab = self.tabs.get_mut(self.active).ok_or("no_tab")?;
        // Source language for the script guard, from the registry row. A pair
        // that resolved through validation always has a row; the fallback is
        // "en" only so this cannot panic, and an unknown source degrades to
        // "ask" in the detector rather than to a wrong verdict.
        let source = crate::languages::pair_by_token(pair)
            .map(|row| row.from)
            .unwrap_or("en");
        // Reset the per-page progress counters for the NEW run. The offset
        // ordering check keys on translation_extracted, so a fresh session must
        // start it at zero or its first batch (offset 0) would be rejected
        // against a previous run's total.
        tab.translation_extracted = 0;
        tab.translation_patched = 0;
        tab.translation = Some(TranslationSession {
            pair,
            source,
            script_counts: crate::detect::ScriptCounts::new(source),
            phase: TranslationPhase::Preparing,
            last_progress: std::time::Instant::now(),
            batch_map: Vec::new(),
            batch_span: 0,
            doc_total: None,
            engine_asset_rev: None,
            engine_heap_bytes: None,
            engine_last_input: None,
            page: tab.url.clone(),
            token,
            batch: Vec::new(),
            submitted: false,
            offset: 0,
            more: false,
            patched_total: 0,
        });
        // THE ONLY PLACE A PAGE IS EVER ASKED TO READ ITSELF. Reached only
        // from a user's click on the tab they are looking at, with a URL this
        // side read rather than accepted. The content script does nothing at
        // all until this arrives.
        let asked = platform::deliver_translation(
            &tab.webview,
            &tab.view,
            json!({
                "cmd": "extract",
                "session": token.to_string(),
                "limitNodes": EXTRACT_MAX_NODES,
                "limitChars": EXTRACT_MAX_CHARS,
            })
            .to_string(),
        );
        if !asked {
            // Fail CLOSED and fail VISIBLY: no session left behind, and a
            // named failure the panel can render, rather than a spinner in
            // front of a process that never started.
            self.tabs[self.active].translation = None;
            self.emit_tab_status();
            return Err("page_not_ready");
        }
        // Tick from the very start: the poller is what carries the stall
        // deadline, and a page that never answers the extract request is
        // exactly the case that needs it.
        self.start_translate_poller();
        let status = self.translation_status();
        self.emit_tab_status();
        status
    }
}

/// How much of a page is read in one extraction.
///
/// A FIRST BATCH, not a whole document. Phase 0 measured 40 sentences at
/// between 2.2 s and 10.4 s on the test laptop depending on whether
/// WebView2 was warm, so a 400-node page translated in one go is somewhere
/// between twenty seconds and two minutes of nothing happening. Visible-first
/// batching is the answer and it is not built yet; until it is, the cap is
/// what stops the first honest attempt being an unresponsive one.
const EXTRACT_MAX_NODES: usize = 200;
/// Companion cap in characters, for a page of few but enormous nodes.
const EXTRACT_MAX_CHARS: usize = 20_000;

impl AppState {

    /// What the panel renders. Reports the ACTIVE tab's session or none.
    pub fn translation_status(&self) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("no_tab")?;
        // A session whose page is no longer the one on screen is treated as
        // absent, whether or not anything remembered to clear it.
        let live = tab
            .translation
            .as_ref()
            .filter(|s| session_is_current(&s.page, &tab.url));
        Ok(match live {
            None => json!({
                "active": false,
                "translatable": is_translatable_url(&tab.url),
                "pairs": TRANSLATION_PAIRS,
            }),
            Some(session) => json!({
                "active": true,
                "translatable": true,
                "pairs": TRANSLATION_PAIRS,
                "pair": session.pair,
                "phase": match &session.phase {
                    TranslationPhase::Preparing => "preparing",
                    TranslationPhase::Translating => "translating",
                    TranslationPhase::Done => "done",
                    TranslationPhase::Failed(_) => "failed",
                },
                "failure": match &session.phase {
                    TranslationPhase::Failed(key) => json!(key),
                    _ => Value::Null,
                },
                // How far through the DOCUMENT this run is: nodes patched
                // against nodes the page says exist. Real progress, not a
                // phase word -- a long page spends minutes in "Translating"
                // and said nothing about how much was left.
                "done_nodes": session.patched_total,
                "total_nodes": session.doc_total,
                "engine_asset_rev": session.engine_asset_rev,
                "engine_heap_bytes": session.engine_heap_bytes,
                "engine_last_input": session.engine_last_input,
                // What the BUILD expects, so the panel can show agreement or
                // disagreement rather than a number nobody can check.
                "expected_asset_rev": crate::asset_revision(),
                // A pack download for THIS session, so the panel can say
                // "downloading, N%" instead of a phase word that names the
                // wrong wait. Advisory, same feed as the packs list.
                "downloading": self.pack_downloads.contains_key(session.pair),
                "dl_got": self.pack_downloads.get(session.pair).map(|(g, _)| g),
                "dl_total": self.pack_downloads.get(session.pair).and_then(|(_, t)| *t),
            }),
        })
    }

    /// Ends the active tab's session. Takes no argument, like the arms above.
    ///
    /// Cancelling must leave the page READABLE. Fail-closed for this feature
    /// means untranslated, never half-patched -- a page stuck between two
    /// languages is worse than one that was never touched.
    /// Show original: put the page back to what it was before translation.
    ///
    /// Sends the page a `restore` command -- which walks its own retained
    /// originals back into the nodes, engine-free and network-free, because
    /// the originals never left the page -- and then ends the session. A later
    /// re-translate is a fresh run: the host deliberately keeps no copy of the
    /// page's text or its translations, so re-showing the translation means
    /// re-doing it, which is the honest cost of not lingering user text.
    ///
    /// Only meaningful on a translated page; on anything else it is a no-op
    /// that still answers with the current status so the UI stays in step.
    pub fn restore_active_tab(&mut self) -> Result<Value, &'static str> {
        let tab = self.tabs.get_mut(self.active).ok_or("no_tab")?;
        // Show original is the user saying STOP for this tab, so the standing
        // continue-in-this-language choice ends here too.
        tab.translate_continue = None;
        let was_translated = matches!(
            tab.translation.as_ref().map(|s| &s.phase),
            Some(TranslationPhase::Done)
        );
        if was_translated {
            let _ = platform::deliver_translation(
                &tab.webview,
                &tab.view,
                json!({
                    "cmd": "restore",
                    "session": tab.translation.as_ref().map(|s| s.token).unwrap_or(0).to_string(),
                })
                .to_string(),
            );
            tab.translation = None;
        }
        let status = self.translation_status();
        self.emit_tab_status();
        status
    }

    pub fn translation_cancel(&mut self) -> Result<Value, &'static str> {
        let tab = self.tabs.get_mut(self.active).ok_or("no_tab")?;
        tab.translate_continue = None;
        tab.translation = None;
        // Tell the page to drop its node map. Best effort by design: the host
        // has ALREADY forgotten the session on the line above, so a page that
        // never hears this can achieve nothing with what it kept -- every
        // later extraction from it is refused, and no patch will ever be sent.
        // Asking is still right, because holding references to every text node
        // of a page nobody is translating any more is a waste the user did not
        // ask for.
        let _ = platform::deliver_translation(
            &tab.webview,
            &tab.view,
            json!({"cmd": "reset"}).to_string(),
        );
        let status = self.translation_status();
        self.emit_tab_status();
        status
    }

    /// Deletes cookies for the active tab's own host -- and ONLY cookies.
    ///
    /// The host is read fresh from `Tab.url` at the moment of the call, never
    /// taken as an argument: the chrome UI has no legitimate reason to name a
    /// domain other than the one it is currently showing, and refusing to
    /// accept one closes off this becoming a delete-any-domain primitive if
    /// the chrome origin were ever compromised.
    ///
    /// There is no origin-scoped API for localStorage or IndexedDB on
    /// `ICoreWebView2Profile` -- only a profile-WIDE clear exists, and using
    /// it here would erase every other open site's data along with this
    /// one's. So this clears cookies alone, and the UI copy must say exactly
    /// that; see `forget_site_cookies`'s own doc for why.
    pub fn forget_active_tab_cookies(&self) -> Result<Value, &'static str> {
        // Checked BEFORE the platform call, so a backend whose stub refuses
        // without asking the engine can never reach `cookie_delete_failed`.
        // That code's sentence blames the engine, and on this path the engine
        // was never called.
        if !crate::cookie_control::available() {
            return Err("cookie_clear_unavailable");
        }
        let tab = self.tabs.get(self.active).ok_or("no_tab")?;
        let host = host_of(&tab.url).ok_or("no_site")?;
        if platform::forget_site_cookies(&tab.webview, &host) {
            Ok(json!({ "origin": host }))
        } else {
            Err("cookie_delete_failed")
        }
    }

    /// Deletes cookies for EVERY site -- and, exactly like the per-site call
    /// above, only cookies.
    ///
    /// Takes no argument for the same reason `forget_active_tab_cookies`
    /// takes none: there is nothing for a caller to name. The scope is all of
    /// it, which is precisely why the chrome puts a confirmation in front of
    /// it and words that confirmation from `cookie_control` rather than
    /// inventing a sentence at the call site.
    ///
    /// COOKIES ALONE, and the UI copy must keep saying so. The reasoning is
    /// unchanged from the per-site case: `ClearBrowsingData` would take a
    /// data-kind mask and reach history, cache and site data the user did not
    /// ask about. `DeleteAllCookies` is the whole of what this does.
    ///
    /// WHY IT PICKS A PERSISTENT TAB RATHER THAN THE ACTIVE ONE. The engine
    /// call runs against the profile of whichever webview it is handed, and a
    /// quarantine tab is in-private: its cookies are a separate, in-memory
    /// store that dies with the tab anyway. Running this from a quarantine tab
    /// would clear that store, leave every saved cookie untouched, and return
    /// success -- a false claim on exactly the surface where a false claim
    /// matters most. So it looks for a tab on the saved profile and refuses
    /// with `no_persistent_tab` when every open tab is a quarantine one, which
    /// is an honest "there is nothing saved here to clear".
    pub fn forget_all_cookies(&self) -> Result<Value, &'static str> {
        // Same order as the per-site call above, and for the same reason: the
        // unavailable backend is not an engine refusal.
        if !crate::cookie_control::available() {
            return Err("cookie_clear_unavailable");
        }
        let tab = self
            .tabs
            .iter()
            .find(|tab| !tab.ephemeral)
            .ok_or("no_persistent_tab")?;
        if platform::forget_all_cookies(&tab.webview) {
            Ok(json!({ "message": crate::cookie_control::cleared_line() }))
        } else {
            // Its OWN code, not the per-site `cookie_delete_failed`. The two
            // failures need different sentences ("for this site" is false
            // here), and one code cannot carry two messages -- sharing it is
            // how the chrome would end up telling a user the wrong thing
            // about what was left untouched.
            Err("cookie_delete_all_failed")
        }
    }

    /// A content tab's password form was submitted. Only stashed if the tab
    /// is the ACTIVE one -- a background tab submitting a form must not pop
    /// a save offer for a page the user is not looking at, and there is
    /// nowhere else in this browser a save-password prompt could sensibly
    /// appear.
    ///
    /// A LOCKED vault no longer drops the submission in silence. It saves
    /// nothing -- the password is still never stored while the vault is shut,
    /// and this function still ends without keeping it -- but it now says so,
    /// because a user who logs in and sees nothing happen has no way to tell a
    /// locked vault from a broken browser. A tester reported exactly that.
    ///
    /// The ORIGIN IS DERIVED BEFORE the vault is considered, and the order is
    /// load-bearing: a submission with no recognizable origin would not have
    /// produced a save offer even with the vault open, so the lock is not the
    /// reason it failed and saying so would be wrong. The active-tab check
    /// stays first for the reason it always had -- a background tab must not
    /// raise UI for a page the user is not looking at.
    pub fn note_login_submitted(
        &mut self,
        tab_id: u64,
        source_url: String,
        username: String,
        password: String,
    ) {
        self.note_login_submitted_at(tab_id, source_url, username, password, Instant::now())
    }

    /// The clock is a parameter so the notice cooldown is testable without
    /// sleeping, the same shape as `note_insecure_navigation_at`.
    pub fn note_login_submitted_at(
        &mut self,
        tab_id: u64,
        source_url: String,
        username: String,
        password: String,
        now: Instant,
    ) {
        if self.tabs.get(self.active).map(|t| t.id) != Some(tab_id) {
            return;
        }
        let tab_url = self.tabs.iter().find(|t| t.id == tab_id).map(|t| t.url.clone());
        let Some(origin) = login_offer_origin(&source_url, tab_url.as_deref()) else {
            return;
        };
        // Asked of the vault, which compares without handing the stored
        // password out. A locked vault answers false and never reaches the
        // question: `already_saved` only decides the unlocked case.
        let already_saved = already_stored(self.vault.as_ref(), &origin, &username, &password);
        match login_submit_outcome(
            self.vault.is_some(),
            Vault::exists(&self.vault_path),
            already_saved,
        ) {
            LoginSubmitOutcome::AlreadySaved | LoginSubmitOutcome::Silent => return,
            LoginSubmitOutcome::NoticeLocked => {
                // `password` is dropped with this scope, exactly as it was
                // when this path returned early and said nothing. Nothing is
                // stored, and the event below carries no password, no
                // username and no origin -- the sentence names no site, so
                // the chrome needs none of it.
                if take_locked_save_notice(&mut self.last_locked_save_notice, now) {
                    self.emit("vault_locked_no_save", json!({}));
                }
                return;
            }
            LoginSubmitOutcome::Offer => {}
        }
        self.pending_save = Some(PendingSave {
            tab_id,
            origin: origin.clone(),
            username: username.clone(),
            password,
        });
        // Never the password: this event only tells chrome.js a save offer
        // exists, so the save banner can render without the raw password
        // ever entering the chrome webview's own DOM.
        self.emit(
            "login_submit_detected",
            json!({ "origin": origin, "username": username }),
        );
    }

    /// Takes and clears the pending save, for `cred_save_confirm` and
    /// `cred_save_dismiss` -- both consume it, neither peeks without taking.
    pub(crate) fn take_pending_save(&mut self) -> Option<PendingSave> {
        self.pending_save.take()
    }

    /// Drops the pending save if it belongs to the tab that just navigated --
    /// the DOM state that produced it is gone, so the offer must go with it.
    /// Called from `on_url_changed` regardless of which tab navigated: a
    /// pending save is tied to a specific tab, not only the active one.
    fn clear_pending_save_for(&mut self, tab_id: u64) {
        if self.pending_save.as_ref().map(|p| p.tab_id) == Some(tab_id) {
            self.pending_save = None;
        }
    }

    /// A snapshot for the diagnostics export: build/version, the active
    /// tab's engine-confirmed status, DNS mode, vault auto-lock setting, the
    /// last update check, and the recent in-memory diagnostic log.
    ///
    /// EXCLUDED ON PURPOSE, and this is the constraint the export exists
    /// under, not an afterthought: no browsing history, no page content, no
    /// URL beyond the one field `tab_status` already carries for the
    /// CURRENT tab, and nothing from the vault. `panel-audit.js` asserts the
    /// rendered template never grows a field shaped like one of those.
    pub fn diagnostics_snapshot(&self) -> Value {
        let prefs = crate::prefs::load();
        let mut recent_log = platform::recent_diagnostics();
        recent_log.extend(crate::capture::recent_diagnostics());
        json!({
            "build": crate::about::ipc_info().unwrap_or_else(|_| json!({})),
            "tab_status": self.active_tab_status(),
            // The resolver IN FORCE (what the engine was given at startup),
            // and separately what the file says. On Linux nothing records
            // one, so the first is System there, which is the truth: a
            // report saying "quad9" would claim a protection never applied.
            "dns_mode": crate::prefs::applied_dns().as_str(),
            "dns_preference": prefs.dns.as_str(),
            "vault_autolock_secs": prefs.vault_autolock_secs,
            "update_status": crate::updater::status(),
            "ocr": crate::ocr_support::diagnostics(),
            "recent_log": recent_log,
        })
    }

    /// Writes the same snapshot `diagnostics_get` returns, as plain text, to
    /// `dest`. No confirmation sentence like the vault's plaintext export --
    /// there is nothing destructive here, only information the user already
    /// has on screen, and no vault content is ever included.
    pub fn export_diagnostics(&self, dest: &Path) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(&self.diagnostics_snapshot())
            .unwrap_or_else(|_| "{}".to_string());
        std::fs::write(dest, text)
    }

    /// The active tab's per-host ledger. `counts_blocked` tells the UI
    /// whether the blocked column is observed (Windows) or structurally
    /// zero (WebKitGTK — see LEDGER_COUNTS_BLOCKED), so the ledger is
    /// labelled as what was STOPPED only where that is true.
    pub fn active_ledger(&self) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("not_found")?;
        Ok(json!({
            "items": platform::ledger(&tab.view),
            "counts_blocked": LEDGER_COUNTS_BLOCKED,
        }))
    }

    /// One command, full paranoid preset: ephemeral profile, JavaScript off,
    /// ad/tracker blocking on, freeze right after load (privacy.rs documents
    /// the policy). Always opens on about:blank and always switches to it —
    /// the point is that the user immediately types the suspicious URL into
    /// a tab that keeps nothing and runs nothing.
    pub fn new_quarantine_tab(&mut self) -> Result<u64, &'static str> {
        self.new_tab_with_policy("about:blank", true, &platform::TabPolicy::quarantine())
    }

    /// Renders the active tab to a PDF in the downloads folder.
    ///
    /// Returns the destination so the chrome can say where it went. The write
    /// itself is asynchronous; `on_pdf_saved` finishes the job when the engine
    /// reports back.
    pub fn save_active_page_as_pdf(&mut self) -> Result<String, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("no_tab")?;
        let url = tab.url.clone();
        // A page that never loaded has nothing to render, and `about:blank`
        // would produce a blank sheet with a provenance record pointing at
        // nothing.
        if !is_allowed_content_url(&url) {
            return Err("no_page");
        }
        // Named from the URL and de-duplicated exactly like a real download,
        // so two saves of the same page do not overwrite each other.
        let suggested = download_dir().join(pdf_name_for(&url));
        let dest = unique_download_path(&url, &suggested);
        if !platform::save_page_as_pdf(&tab.webview, &dest, &self.proxy) {
            return Err("unsupported");
        }
        // Remembered so the completion handler can attribute the file to the
        // page it came from: by the time the engine answers, the tab may have
        // navigated somewhere else entirely.
        self.pending_pdf
            .insert(dest.to_string_lossy().into_owned(), url);
        Ok(dest.to_string_lossy().into_owned())
    }

    /// The engine finished (or failed) a PDF render.
    pub fn on_pdf_saved(&mut self, path: &str, success: bool) {
        let Some(source_url) = self.pending_pdf.remove(path) else {
            return; // not ours, or already handled
        };
        if !success {
            self.emit(
                "toast",
                json!({ "text": "Could not save that page as a PDF.", "error": true }),
            );
            return;
        }
        // The SAME call an ordinary download makes, so the PDF is hashed and
        // recorded identically and the Library's Verify button works on it
        // with no special case.
        self.record_download_provenance(&source_url, Some(path), true);
        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        self.emit("toast", json!({ "text": format!("Saved {name}") }));
    }

    /// Writes one of the right-click menu's copy actions to the clipboard and
    /// says what happened.
    fn copy_to_clipboard(&mut self, text: &str, change: crate::ipc::LinkChange) {
        let (message, error) = copy_result_message(platform::set_clipboard_text(text), change);
        self.emit("toast", json!({ "text": message, "error": error }));
    }

    /// Image addresses take the same path but never the link vocabulary, and
    /// are never unwrapped or stripped: an image src is not a click target.
    fn copy_image_to_clipboard(&mut self, text: &str) {
        let (message, error) = if platform::set_clipboard_text(text) {
            ("Image address copied", false)
        } else {
            ("Could not copy that image address", true)
        };
        self.emit("toast", json!({ "text": message, "error": error }));
    }

    /// Acts on a right-click menu choice.
    ///
    /// The ids come from `platform::windows`'s MENU_* constants, and this is
    /// the only place they are interpreted. Every URL is re-validated by the
    /// path it takes (`new_tab_with_policy` -> `is_allowed_content_url`)
    /// rather than trusted because a menu produced it: the target originated
    /// in an untrusted page.
    pub fn on_context_menu_action(&mut self, action: u32, target: Option<&str>) {
        use crate::platform::menu_ids;

        // Cloned BEFORE the closure below, which needs `&mut self`: reading
        // `self.privacy` inside a match arm while that closure is alive is a
        // borrow conflict, and the value is four bools.
        let browser_policy = self.privacy.clone();

        // A failure here is reported the way every other user-initiated
        // failure is -- a toast -- rather than silently doing nothing, which
        // is indistinguishable from a menu that is broken.
        let mut open = |url: &str, background: bool, policy: platform::TabPolicy| {
            if !is_allowed_content_url(url) {
                self.emit(
                    "toast",
                    json!({ "text": "That link cannot be opened.", "error": true }),
                );
                return;
            }
            if self.new_tab_with_policy(url, !background, &policy).is_err() {
                self.emit(
                    "toast",
                    json!({ "text": "Could not open that link.", "error": true }),
                );
            }
        };

        match (action, target) {
            (menu_ids::OPEN_NEW_TAB, Some(url)) => {
                open(url, false, browser_policy.clone());
            }
            (menu_ids::OPEN_BACKGROUND, Some(url)) => {
                open(url, true, browser_policy.clone());
            }
            (menu_ids::OPEN_EPHEMERAL, Some(url)) => {
                open(url, false, platform::TabPolicy::ephemeral());
            }
            (menu_ids::OPEN_QUARANTINE, Some(url)) => {
                open(url, false, platform::TabPolicy::quarantine());
            }
            // Image open reuses the browser policy and the same allow-list
            // gate: the image source is untrusted page data like every other
            // menu URL.
            (menu_ids::OPEN_IMAGE_NEW_TAB, Some(url)) => {
                open(url, false, browser_policy.clone());
            }
            // Copying is done by THIS PROCESS, not by handing the text to the
            // chrome webview to write with `navigator.clipboard`. That is what
            // it used to do, and it could not work: the Clipboard API refuses
            // to write from a document that is not focused, and the focus is
            // in the page the user just right-clicked, never in the chrome.
            // See platform::set_clipboard_text. Nothing is evaluated in the
            // content webview either way.
            // SPLIT, not one arm for both. These used to share an arm, and
            // folding the image case in with the link case meant "Copy image
            // address" reported "Link copied". Same call, different noun.
            (menu_ids::COPY_LINK, Some(url)) => {
                self.copy_to_clipboard(url, crate::ipc::LinkChange::Unchanged);
            }
            (menu_ids::COPY_IMAGE, Some(url)) => {
                self.copy_image_to_clipboard(url);
            }
            (menu_ids::COPY_LINK_CLEAN, Some(url)) => {
                // Unwrap the redirect wrapper first, then strip tracking
                // parameters off whatever came out: a recovered destination
                // usually carries its own. `clean_link` pins that order.
                let (cleaned, change) = crate::ipc::clean_link(url);
                self.copy_to_clipboard(&cleaned, change);
            }
            // Navigation acts on the active tab and carries no URL. A failure
            // (nothing to go back to) is a normal state, not an error to
            // surface, so it is swallowed like the Back/Forward shortcuts.
            (menu_ids::HISTORY_BACK, _) => {
                let _ = self.history_back();
            }
            (menu_ids::HISTORY_FORWARD, _) => {
                let _ = self.history_forward();
            }
            (menu_ids::HISTORY_RELOAD, _) => {
                let _ = self.history_reload();
            }
            // Includes every id this build does not know and every action
            // whose target is missing. Doing nothing is correct: the menu is
            // built from the same constants, so a mismatch means a bug, not a
            // user request to guess at.
            _ => {}
        }
    }

    /// THE ONLY PLACE THE VAULT LOCKS. Every trigger routes here: the
    /// inactivity timer (`check_autolock`), the explicit `vault_lock` IPC
    /// command, the Ctrl+Shift+L shortcut, and workstation lock/suspend. Add
    /// a new trigger by calling this, never by repeating what it does -- a
    /// second copy is what let the auto-lock and the explicit lock drift
    /// apart once already.
    pub fn lock_vault(&mut self) {
        crate::page_integrity::on_vault_locked(self);
        self.vault = None; // dropping Vault zeroizes key material
        // The store deliberately stays resident for internal download
        // provenance. It is NOT publicly open: `store_status` reports closed
        // and every Library command routes through `ipc::store_open`, which
        // refuses while `vault` is None. Keeping the domain-separated key
        // here lets a download already in flight retain its provenance
        // without leaving bookmarks or snapshot text readable; process exit
        // drops it through Zeroizing regardless.
        //
        // The transport holds identities derived from the vault, so it has to
        // go down with it -- otherwise a locked vault keeps announcing the
        // user's addresses on the LAN.
        #[cfg(feature = "chat")]
        crate::chat_panel::on_vault_locked(self);
        // Premium output must not outlive the licence session: the scan is
        // dropped BEFORE the licence session is told, and the chrome hears
        // it (locked: true) so an open panel clears. Byte reads already in
        // flight die naturally -- their answers quote a dead scan id.
        self.tab_scan = None;
        self.tab_scan_skipped_quarantine = 0;
        self.emit_tab_scan_state();
        // The licence session state derives from the vault the same way:
        // nothing licence-related survives a lock, and the next unlock
        // re-verifies from the stored record. Ungated, like the tunnel.
        crate::licence_control::on_vault_locked();
        // The staged Deep Recall picture dies with the vault too. The STORE
        // stays open (above), so the archive's ciphertext remains readable --
        // but the staged slot holds a DECRYPTED page screenshot, servable
        // over the chrome protocol, and the panel's published copy says the
        // feature "requires an unlocked vault". A locked browser with a
        // decrypted page still on offer would make that sentence false, so
        // the promise wins over the loophole.
        crate::archive::clear_staged();
        // The per-site divergence table dies with the vault for the same
        // reason: it was read out of the encrypted store, and a tab opened
        // after the lock must not carry choices this browser can no longer
        // read. Cleared BEFORE the event, so nothing can observe the lock
        // and still be handed the old table.
        set_divergence_overrides_snapshot(String::new());
        self.emit("vault_locked", json!({}));
    }

    // ---- bookmark/provenance store -------------------------------------------

    /// Opens the store with the vault's passphrase, creating it on first use
    /// (existing vaults from before the store was wired get one silently, at
    /// the moment of unlock — no second prompt, no passphrase reuse nudge).
    ///
    /// Failure is recorded rather than propagated: a damaged bookmark file
    /// must not make the vault unusable, and the next unlock retries.
    /// Beside the Library file while a profile import could not remove the
    /// previous profile's Library. While it exists AND the old file exists,
    /// no Store is opened: the marker outlives lock, unlock and restart, so
    /// a matching passphrase cannot quietly reattach the old profile (review
    /// round 3, R-002). It is cleared when the old file is gone.
    pub fn library_replace_marker(&self) -> std::path::PathBuf {
        let mut p = self.store_path.clone().into_os_string();
        p.push(".replace-pending");
        std::path::PathBuf::from(p)
    }

    pub fn open_store(&mut self, passphrase: &str) {
        let marker = self.library_replace_marker();
        if marker.exists() {
            if Store::exists(&self.store_path) {
                self.detach_store_unreplaced();
                return;
            }
            let _ = std::fs::remove_file(&marker);
        }
        let opened = if Store::exists(&self.store_path) {
            Store::unlock(&self.store_path, passphrase)
        } else {
            Store::create(&self.store_path, passphrase)
        };
        match opened {
            Ok(store) => {
                self.store = Some(store);
                self.store_error = None;
            }
            Err(err) => {
                self.store = None;
                self.store_error = Some(crate::ipc::store_code(err));
            }
        }
        // Per-site divergence choices live in the store, and the script that
        // needs them is built by platform code with no AppState in reach, so
        // the table is snapshotted into a process-level cache here.
        self.refresh_divergence_snapshot();
        // Sweep archive pictures no record names. Debris is possible
        // whenever a write was interrupted between the two stores, and a
        // picture with no way to see or delete it should not sit on disk.
        if let Some(store) = self.store.as_ref() {
            let _ = store.reconcile_archive();
        }
    }

    /// Rebuilds the injected per-site table from the open store.
    ///
    /// Called at unlock and after every change. With no store open the table
    /// is EMPTY, which is the honest pre-unlock answer: the choices are
    /// encrypted with the vault, so before it opens this browser genuinely
    /// does not know them, and every tab gets the global behaviour.
    pub fn refresh_divergence_snapshot(&self) {
        let entries: Vec<(String, bool)> = self
            .store
            .as_ref()
            .map(|store| {
                store
                    .divergence_overrides()
                    .iter()
                    .map(|o| {
                        (
                            o.host.clone(),
                            matches!(o.level, patanyx_store::DivergenceLevel::Off),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        set_divergence_overrides_snapshot(crate::platform::privacy::divergence_overrides_json(
            &entries,
        ));
    }

    pub fn store_status(&self) -> Value {
        json!({
            // The encrypted store stays resident for internal download
            // provenance, but the Library is vault-gated: its public status
            // is closed whenever the vault is closed.
            "open": self.vault.is_some() && self.store.is_some(),
            "error": self.store_error,
            // Whether this build can digest a page is one question with one
            // answer, and it lives with the code that does the digesting:
            // `integrity_status` reports `platform::page_bytes_supported()`.
            // There used to be a second answer here — a hardcoded `false`
            // beside a seam that always returned None — so the bookmarks UI
            // said "this build cannot read page content yet" on a build that
            // demonstrably could, while the integrity panel on the same page
            // read it and produced verdicts.
            "digests_ready": crate::platform::page_bytes_supported(),
        })
    }

    /// Marks the bookmarks/downloads store as unavailable for this session.
    ///
    /// Used after a recovery-key unlock: the store is encrypted under the
    /// vault PASSPHRASE, and a recovery unlock legitimately does not have it.
    /// The library is therefore genuinely unreadable until the user unlocks
    /// with their passphrase again — which is a true statement about the
    /// encryption, not a bug, and the UI says exactly that instead of showing
    /// an empty list that reads as "you have no bookmarks".
    pub fn mark_store_unavailable(&mut self) {
        self.store = None;
        self.store_error = Some("store_needs_passphrase");
    }

    pub fn store_error(&self) -> Option<&'static str> {
        self.store_error
    }

    /// Called from the event loop's `UserEvent::DownloadDone` arm — BEFORE
    /// the `download_finished` emit there, so a downloads-view refresh
    /// triggered by that event already sees the record (or the explicit
    /// failure event). On a successful completion, hashes the saved file and
    /// records it in the store: "this is exactly what arrived".
    ///
    /// What happens when recording is impossible is a decision, not a silent
    /// drop:
    ///   * failed download, or no destination path: nothing to fingerprint;
    ///     the download toast already covered the download itself.
    ///   * store never opened this session (vault never unlocked, a
    ///     recovery-key unlock, or the store failed to open): the file is
    ///     fine on disk, but the downloads view promises a fingerprint for
    ///     every finished download, so `download_record_failed` is emitted
    ///     with reason `store_unavailable` and the UI names the exception.
    ///     The store remains resident across a vault lock for this internal
    ///     write only; public Library IPC is still refused by `store_open`.
    ///     Therefore "locked" alone does NOT land here — recording still
    ///     happens without making bookmark or snapshot data readable.
    ///   * save failure: same event, reason `io` — otherwise the panel would
    ///     imply every download is fingerprinted when this one is not.
    ///
    /// Note: this hashes on the event-loop thread. Fine for typical
    /// downloads; a multi-GB file stalls the UI for seconds. The threaded
    /// fix needs one new `UserEvent` variant in main.rs (hash on a worker,
    /// post the result back, record here) — flagged for the reviewer rather
    /// than done blind, because main.rs was not in my context.
    pub fn record_download_provenance(&mut self, url: &str, path: Option<&str>, success: bool) {
        if !success {
            return;
        }
        let path = match path {
            Some(path) => path,
            None => return,
        };
        let filename = match Path::new(path).file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => return,
        };
        let (sha256, byte_len) = match hash_file(Path::new(path)) {
            Ok(result) => result,
            // The file vanished or became unreadable between completion and
            // hashing; there is nothing truthful left to record.
            Err(_) => return,
        };
        if self.store.is_none() {
            self.emit(
                "download_record_failed",
                json!({ "reason": "store_unavailable" }),
            );
            return;
        }
        let result = match self.store.as_mut() {
            Some(store) => store.record_download(url, &filename, byte_len, sha256),
            None => return, // unreachable: checked above
        };
        match result {
            Ok(_) => self.emit("downloads_changed", json!({})),
            // A save failure means the record is gone; the panel would
            // otherwise imply every download is fingerprinted.
            Err(_) => self.emit("download_record_failed", json!({ "reason": "io" })),
        }
    }

    fn set_active(&mut self, index: usize) {
        if index >= self.tabs.len() || index == self.active {
            return;
        }
        // Find sessions are per-tab: highlights must not stay lit on a tab
        // the user is leaving, and a count arriving late must find nothing
        // to describe. The chrome closes its bar off the url_changed this
        // switch emits below.
        if self.find.stop(&mut self.find_gen) {
            platform::find_stop(&self.tabs[self.active].webview);
        }
        platform::hide_tab(
            &self.tabs[self.active].view,
            &self.tabs[self.active].webview,
        );
        self.active = index;
        platform::show_tab(&self.tabs[index].view, &self.tabs[index].webview);
        // A freshly shown Windows tab may have stale bounds (created hidden,
        // or hidden during a resize); re-apply geometry for it and chrome.
        self.relayout();
        let url = self.tabs[index].url.clone();
        self.emit("url_changed", json!({ "url": url }));
        // The status is PER TAB and `emit_tab_status`'s own doc has always
        // listed "tab switch" among the transitions that push it -- but no
        // switch path did. Everything rendered from tab_status (freeze chip,
        // TLS banner, save-password offer, the plain-HTTP warning) described
        // the tab the user just LEFT until something else happened to
        // re-emit it. Found when the HTTP warning stayed up on a tab that had
        // already continued.
        self.emit_tab_status();
    }

    pub fn tab_list(&self) -> Value {
        let items: Vec<Value> = self
            .tabs
            .iter()
            .enumerate()
            .map(|(i, tab)| {
                json!({
                    "id": tab.id,
                    "url": tab.url,
                    "title": tab.title,
                    "active": i == self.active,
                })
            })
            .collect();
        json!({ "items": items })
    }

    pub fn emit_tabs_changed(&self) {
        let list = self.tab_list();
        self.emit("tabs_changed", list);
    }

    /// The cross-tab scan's target list: every non-quarantine tab, in strip
    /// order. Quarantine tabs are NEVER scanned -- their contract is that
    /// nothing outlives them, and a search row is a memory -- so they are
    /// skipped and counted, and the count is what the UI states.
    pub fn tab_scan_candidates(&self) -> (Vec<u64>, usize) {
        let mut ids = Vec::with_capacity(self.tabs.len());
        let mut skipped = 0usize;
        for tab in &self.tabs {
            if tab.ephemeral {
                skipped += 1;
            } else {
                ids.push(tab.id);
            }
        }
        (ids, skipped)
    }

    /// Start (or wholesale replace) the cross-tab scan and remember how
    /// many quarantine tabs were left out, so every later snapshot words
    /// the same number the search reply did. A replaced scan needs no
    /// per-row cancel: its in-flight reads quote its dead id and
    /// TabScan::record refuses them.
    pub fn start_tab_scan(&mut self, scan: crate::tab_search::TabScan, skipped_quarantine: usize) {
        self.tab_scan = Some(scan);
        self.tab_scan_skipped_quarantine = skipped_quarantine;
    }

    /// A tab's content webview by id, for per-tab engine asks that are not
    /// about the active tab (the scan's byte reads).
    pub fn tab_webview(&self, id: u64) -> Option<&WebView> {
        self.tabs
            .iter()
            .find(|tab| tab.id == id)
            .map(|tab| &tab.webview)
    }

    /// Whether a goto target is one the scan could have listed: it exists
    /// and is not a quarantine tab.
    pub fn tab_is_searchable(&self, id: u64) -> bool {
        self.tabs.iter().any(|tab| tab.id == id && !tab.ephemeral)
    }

    /// The ONE place the find_tabs_state shape is built -- the search reply
    /// and every later event share it, so the chrome renders one shape.
    /// Rows join the scan with LIVE tab titles/urls; a tab that closed
    /// mid-scan keeps its row but reads "Closed tab". Counts are worded by
    /// find::format_count and reasons by reason_copy: the chrome renders
    /// strings, it never words anything.
    pub fn find_tabs_state(&self) -> Value {
        use crate::tab_search::ScanRow;
        let rows = match &self.tab_scan {
            Some(scan) => scan
                .rows()
                .iter()
                .map(|(id, row)| {
                    let live = self.tabs.iter().find(|tab| tab.id == *id);
                    let title = live.map(|tab| tab.title.as_str()).unwrap_or("Closed tab");
                    let url = live.map(|tab| tab.url.as_str()).unwrap_or("");
                    match row {
                        ScanRow::Pending => json!({
                            "id": id,
                            "title": title,
                            "url": url,
                            "state": "pending",
                            "reason": null,
                        }),
                        ScanRow::Done(set) => json!({
                            "id": id,
                            "title": title,
                            "url": url,
                            "state": "done",
                            "reason": null,
                            "count": set.total,
                            "capped": set.capped,
                            "text": crate::find::format_count(None, set.total, set.capped),
                            "snippets": set
                                .snippets
                                .iter()
                                .map(|s| json!({
                                    "text": s.text,
                                    "start": s.match_start,
                                    "end": s.match_end,
                                    "cut_start": s.cut_start,
                                    "cut_end": s.cut_end,
                                }))
                                .collect::<Vec<Value>>(),
                        }),
                        ScanRow::Unsearchable(reason) => json!({
                            "id": id,
                            "title": title,
                            "url": url,
                            "state": "unsearchable",
                            "reason": crate::tab_search::reason_copy(reason),
                        }),
                    }
                })
                .collect::<Vec<Value>>(),
            None => Vec::new(),
        };
        json!({
            "scanning": self
                .tab_scan
                .as_ref()
                .map_or(false, |scan| !scan.is_complete()),
            // An absence of information must never read as unlocked.
            "locked": self.vault.is_none(),
            "query": self.tab_scan.as_ref().map(|scan| scan.query()).unwrap_or(""),
            "skipped_quarantine": if self.tab_scan.is_some() {
                self.tab_scan_skipped_quarantine
            } else {
                0
            },
            "rows": rows,
        })
    }

    /// Every scan state change funnels here: row answers (page_integrity),
    /// tab closes, and the vault lock.
    pub fn emit_tab_scan_state(&self) {
        let state = self.find_tabs_state();
        self.emit("find_tabs_state", state);
    }

    /// The active tab's webview, for engine reads that must go through the
    /// real page (never through evaluating script in it).
    pub fn active_webview(&self) -> Option<&WebView> {
        self.tabs.get(self.active).map(|tab| &tab.webview)
    }

    /// Per-tab refused-request totals for every OPEN tab, for the session
    /// receipt. The same per-tab source `tab_status` reads -- never a
    /// second ledger walk maintained for the receipt.
    pub fn live_blocked_totals(&self) -> impl Iterator<Item = u64> + '_ {
        self.tabs.iter().map(|tab| platform::blocked_total(&tab.view))
    }

    /// The ACTIVE tab's refused-request total ("on this page").
    pub fn active_blocked_total(&self) -> u64 {
        self.tabs
            .get(self.active)
            .map(|tab| platform::blocked_total(&tab.view))
            .unwrap_or(0)
    }

    /// Accept a validated batch for one live tab. Validation happens before
    /// the event is constructed on both platforms; this layer only performs
    /// saturating aggregation so even a forged flood cannot wrap to a small
    /// and reassuring number.
    pub fn note_fingerprint_probes(&mut self, tab_id: u64, deltas: &[(FingerprintSurface, u64)]) {
        let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == tab_id) else {
            return;
        };
        for (surface, count) in deltas {
            tab.fingerprint_probes.add(*surface, *count);
        }
    }

    /// The separate, explicitly untrusted Tab Activity reading. These words
    /// live in Rust with the panel's other factual copy so the UI renderer
    /// cannot accidentally collapse it into the privacy receipt.
    pub fn fingerprint_probe_activity(&self) -> serde_json::Value {
        const LABEL: &str = "Page-reported fingerprint probes";
        const CAVEAT: &str = "Page-reported, not browser-observed. These counts describe probe calls reported by this page's main-world scripts; the page can omit or forge them, and worker probes are not included.";
        const DISABLED: &str = "Fingerprint Divergence is not active in this tab.";
        const CHANNEL_FAILED: &str =
            "Probe reports are unavailable because the page-reporting channel did not register.";

        let Some(tab) = self.tabs.get(self.active) else {
            return json!({
                "label": LABEL,
                "caveat": CAVEAT,
                "status": "unavailable",
                "status_text": CHANNEL_FAILED,
                "surface_labels": {
                    "audio": "Audio",
                    "canvas": "Canvas",
                    "webgl": "WebGL/Graphics",
                    "element_measurement": "Element measurement",
                },
                "counts": {
                    "audio": 0,
                    "canvas": 0,
                    "webgl": 0,
                    "element_measurement": 0,
                },
            });
        };
        let channel = platform::fingerprint_probe_reporting(&tab.view);
        let (status, status_text) = if !tab.divergence_registered {
            ("disabled", DISABLED)
        } else if channel != "applied" {
            ("unavailable", CHANNEL_FAILED)
        } else {
            ("active", "")
        };
        let counts = tab.fingerprint_probes;
        json!({
            "label": LABEL,
            "caveat": CAVEAT,
            "status": status,
            "status_text": status_text,
            "surface_labels": {
                "audio": "Audio",
                "canvas": "Canvas",
                "webgl": "WebGL/Graphics",
                "element_measurement": "Element measurement",
            },
            "counts": {
                "audio": counts.audio,
                "canvas": counts.canvas,
                "webgl": counts.webgl,
                "element_measurement": counts.element_measurement,
            },
        })
    }

    /// Builds a tab under an explicit policy rather than the browser-wide one.
    /// A quarantine tab is the reason this exists: `ephemeral` and the initial
    /// JavaScript setting are fixed at construction, so they cannot be applied
    /// to a tab that already exists.
    pub fn new_tab_with_policy(
        &mut self,
        url: &str,
        switch: bool,
        policy: &platform::TabPolicy,
    ) -> Result<u64, &'static str> {
        let id = self.next_tab_id;
        let tab = build_tab(
            &self.hosts,
            &self.proxy,
            id,
            url,
            policy,
            self.permissions.clone(),
        )
        .map_err(|_| "tab_failed")?;
        // As in `new_tab`: the id is consumed only once the tab exists.
        self.next_tab_id += 1;
        let was_empty = self.tabs.is_empty();
        self.tabs.push(tab);
        if was_empty {
            self.active = 0;
            platform::show_tab(&self.tabs[0].view, &self.tabs[0].webview);
            self.relayout();
        } else if switch {
            let index = self.tabs.len() - 1;
            self.set_active(index);
        }
        self.emit_tabs_changed();
        self.focus_url_bar_for_blank_tab(switch, url);
        Ok(id)
    }

    pub fn active_url(&self) -> String {
        self.tabs
            .get(self.active)
            .map(|tab| tab.url.clone())
            .unwrap_or_default()
    }

    pub fn active_title(&self) -> String {
        self.tabs
            .get(self.active)
            .map(|tab| tab.title.clone())
            .unwrap_or_default()
    }

    /// A capture on its way into Deep Recall: read it for text, then store
    /// the record and the encrypted picture together.
    ///
    /// The READ happens on a worker, like every other scan, because it takes
    /// about a second on a real page and this runs on the event loop. So
    /// this method hands the bytes off and returns; `finish_archive` does
    /// the storing when the text comes back.
    ///
    /// The url and title are captured NOW rather than when the text arrives.
    /// A second is long enough for the user to navigate, and archiving a
    /// picture of one page under the address of another would be a quiet
    /// lie about where it came from.
    fn archive_captured_page(&mut self, png: Vec<u8>, scope: &'static str) {
        let url = self.active_url();
        let title = self.active_title();
        if self.store.is_none() {
            self.emit(
                "archive_saved",
                json!({ "ok": false, "error": "not_unlocked" }),
            );
            return;
        }
        crate::ocr_support::read_for_archive(self, png, url, title, scope);
    }

    /// The text came back: write the record and the picture.
    pub fn finish_archive(
        &mut self,
        png: Vec<u8>,
        url: String,
        title: String,
        scope: &'static str,
        text: String,
    ) {
        let Some(store) = self.store.as_mut() else {
            self.emit(
                "archive_saved",
                json!({ "ok": false, "error": "not_unlocked" }),
            );
            return;
        };
        match store.add_archive(&url, &title, scope, &text, Some(&png)) {
            Ok(id) => {
                // The reader stops at MAX_BOXES and says so with a marker
                // region. Deep Recall is the surface that actually reaches
                // that cap -- a long page is exactly what it saves -- and
                // reporting a word count as if it were the whole page is the
                // "read 2 lines" failure in a politer costume. The marker is
                // not a word the user wrote, so it comes out of the count as
                // well as being announced.
                let truncated = text.contains(patanyx_ocr::TRUNCATED_MARKER);
                let words = text
                    .replace(patanyx_ocr::TRUNCATED_MARKER, " ")
                    .split_whitespace()
                    .count();
                // The scope travels with the event because the picture can
                // be a viewport on the Windows fallback path, and the save
                // message is the only place the user is told which they got.
                self.emit(
                    "archive_saved",
                    json!({ "ok": true, "id": id, "words": words, "truncated": truncated, "scope": scope }),
                );
            }
            Err(e) => {
                let code = crate::ipc::store_code(e);
                self.emit("archive_saved", json!({ "ok": false, "error": code }));
            }
        }
    }

    // ---- navigation (always the active tab) ----------------------------------

    pub fn navigate(&mut self, url: &str) -> Result<(), &'static str> {
        match self.tabs.get_mut(self.active) {
            Some(tab) => tab.queue_or_navigate(url),
            None => Err("not_found"),
        }
    }

    /// Releases every tab built while the asynchronous once-per-process wipe
    /// was running. Tabs built after the platform gate reaches Ready navigate
    /// immediately and have `initial_navigation_pending == false`, so this is
    /// idempotent and can never reload a live tab.
    pub fn finish_session_wipe(&mut self) {
        for tab in &mut self.tabs {
            tab.finish_initial_navigation();
        }
        let delayed_closes = self
            .tabs
            .iter()
            .filter(|tab| tab.close_after_session_wipe)
            .map(|tab| tab.id)
            .collect::<Vec<_>>();
        for id in delayed_closes {
            let _ = self.close_tab(id);
        }
    }

    pub fn history_back(&mut self) -> Result<(), &'static str> {
        match self.tabs.get_mut(self.active) {
            Some(tab) => tab.history_back(),
            None => Ok(()),
        }
    }

    pub fn history_forward(&mut self) -> Result<(), &'static str> {
        match self.tabs.get_mut(self.active) {
            Some(tab) => tab.history_forward(),
            None => Ok(()),
        }
    }

    pub fn history_reload(&mut self) -> Result<(), &'static str> {
        match self.tabs.get_mut(self.active) {
            Some(tab) => tab.history_reload(),
            None => Ok(()),
        }
    }

    // ---- tab events (routed by tab id) ----------------------------------------

    pub fn on_url_changed(&mut self, id: u64, url: String) {
        let is_active = self.tabs.get(self.active).map(|t| t.id) == Some(id);
        let index = match self.tabs.iter().position(|tab| tab.id == id) {
            Some(index) => index,
            None => return, // late event from a closed tab
        };
        self.tabs[index].url = url.clone();
        self.tabs[index].record_history(url.clone());
        // The declared-language badge is a fact about the page that just left,
        // so it clears on navigation. The new page re-declares (or does not),
        // and a stale badge from the previous page must not linger.
        self.tabs[index].detected_lang = None;
        // A navigation that went THROUGH answers any held-back one: the user
        // went somewhere else, or clicked Continue and this is that load.
        self.tabs[index].insecure_pending = None;
        self.tabs[index].insecure_pending_at = None;
        // A blocked-site notice is about the navigation that was blocked.
        // Once this tab has gone somewhere else, its id must spend nothing
        // (review of pentest F-006): the click is refused as stale.
        if self.tabs[index].blocked_pending.borrow_mut().take().is_some() {
            // Background tabs get no tab_status on navigation, so the chrome
            // is told outright (review round 3, R-005).
            let tab_id = self.tabs[index].id;
            self.emit("navigation_blocked_retired", json!({ "tab_id": tab_id }));
        }
        // THE HELD-PAGE LIFECYCLE, both halves, here because this is the
        // main-frame navigation signal on both engines. The banner clears on a
        // navigation away (a load of the held URL itself is the placeholder
        // and is kept: see on_top_level_navigation). And the override ENDS
        // when the top-level host changes -- the sentence the banner puts in
        // front of the user -- which means the native side must be told to
        // drop it too, or the request handler keeps exempting the host from a
        // consent that is over. Neither hook had a caller until a review
        // found that "Open anyway" never ended (R-001, R-004).
        self.tabs[index].adlist.on_top_level_navigation(&url);
        // A navigation with NO host -- about:blank is allowlisted and has none
        // -- is still leaving the consented host, and was a hole: revocation
        // only ran when a host could be parsed, so about:blank kept the
        // override alive and a return to the listed host needed no new consent
        // (review R-003, round 2).
        let ended = match host_of(&url) {
            Some(host) => self.tabs[index].adlist.on_committed_host(&host),
            None => self.tabs[index].adlist.end_override(),
        };
        if ended {
            platform::set_adlist_override(&self.tabs[index].view, None);
        }
        // Translation consent attaches to the PAGE the user asked about, so it
        // dies here with the page. A new page is a new click; "never
        // automatic" means never untriggered, and carrying a session across a
        // navigation would translate something nobody asked about.
        //
        // THIS LINE IS HYGIENE, NOT CORRECTNESS, and that is deliberate.
        //
        // It used to be the only thing standing between a navigation and a
        // session outliving the page it was consented for -- and nothing in
        // the suite could verify it, because `Tab` owns a live `WebView` so no
        // unit test can build one to drive a navigation. Deleting it broke
        // nothing; I planted that defect and the whole battery stayed green.
        //
        // So the rule moved into the data. A session records the page it was
        // given for, and `session_is_current` refuses one whose page is not
        // what the tab now shows. Removing this line today leaks a struct
        // until the tab closes; it does NOT translate a page nobody asked
        // about. Both halves are proven by planted defect -- see
        // `a_session_does_not_survive_the_page_it_was_given_for`.
        // The DOM state that produced any pending save offer for THIS tab is
        // gone the moment it navigates -- confirming it now would save under
        // whatever origin the tab happens to show next.
        self.clear_pending_save_for(id);
        // url_changed is emitted for the active tab only; the strip learns
        // about every URL change through tabs_changed.
        if index == self.active {
            self.emit("url_changed", json!({ "url": url }));
        }
        self.emit_tabs_changed();
        if is_active {
            self.emit_tab_status();
        }
    }

    /// The navigation handler held back a plain-HTTP load on tab `id`.
    /// Recorded on the tab, so a background tab's warning is waiting when the
    /// user switches to it, and pushed to the chrome now if the tab is the
    /// active one. Nothing loaded; the refusal already happened.
    pub fn note_insecure_navigation(&mut self, id: u64, url: String) {
        self.note_insecure_navigation_at(id, url, Instant::now())
    }

    /// The clock is a parameter so the stability rule is testable without
    /// sleeping.
    pub fn note_insecure_navigation_at(&mut self, id: u64, url: String, now: Instant) {
        let is_active = self.tabs.get(self.active).map(|t| t.id) == Some(id);
        let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == id) else {
            return; // late event from a closed tab
        };
        if banner_subject_update(
            tab.insecure_pending.as_deref(),
            tab.insecure_pending_at,
            &url,
            now,
        ) != BannerUpdate::Replace
        {
            return;
        }
        tab.insecure_pending = Some(url);
        tab.insecure_pending_at = Some(now);
        if is_active {
            self.emit_tab_status();
        }
    }

    /// "Continue" on the plain-HTTP warning: the held-back URL's host joins
    /// the active tab's override and the SAME URL is loaded again, this time
    /// passing the navigation handler. Refuses when nothing is pending, so a
    /// compromised chrome cannot use this to seed an override for a host the
    /// user was never asked about.
    pub fn insecure_allow(&mut self, shown_host: &str) -> Result<Value, &'static str> {
        let tab = self.tabs.get_mut(self.active).ok_or("no_tab")?;
        // BORROWED, NOT TAKEN, until every check has passed. Taking first
        // meant a rejected request still cleared the pending, so the banner
        // vanished and the user could not retry.
        let url = tab.insecure_pending.clone().ok_or("bad_args")?;
        // Re-checked at the point of use, not trusted from when it was
        // recorded: only a URL this warning would hold back may be allowed
        // through it.
        if !needs_insecure_warning(&url) || !is_allowed_content_url(&url) {
            return Err("bad_args");
        }
        let host = host_of(&url).ok_or("bad_args")?;
        // THE HOST THE USER READ MUST BE THE HOST THAT LOADS. The chrome
        // sends back the host it displayed; if the pending URL changed
        // between the render and the click, these differ and the click is
        // refused rather than loading something the user never agreed to.
        // This is a CONFIRMATION, not a selection: a mismatch refuses, and
        // no value here can ever name a URL that was not already pending, so
        // it cannot become an open-anything primitive.
        if !continue_matches_shown_banner(&url, shown_host) {
            return Err("bad_args");
        }
        tab.insecure_pending = None;
        tab.insecure_pending_at = None;
        tab.allow_insecure_host(&host);
        tab.webview.load_url(&url).ok();
        let status = self.active_tab_status();
        Ok(json!({ "allowed": host, "status": status }))
    }

    /// "Dismiss" on the plain-HTTP warning: the held-back URL is dropped and
    /// nothing is allowed. The tab stays where it was.
    /// "Open anyway" on the held-page banner.
    ///
    /// Named by tab and by pending id rather than acting on the active tab,
    /// because this banner is rendered per tab from an async push and a switch
    /// can land between the paint and the click. Every value the chrome sends
    /// CONFIRMS what it displayed; none of them selects anything, so no call
    /// here can name a URL that was not already pending.
    pub fn adlist_allow(
        &mut self,
        tab_id: u64,
        pending_id: u64,
        shown_host: &str,
    ) -> Result<Value, &'static str> {
        if !crate::adlist_consent::CAN_ALLOW {
            return Err("adlist_no_exception");
        }
        let rules = platform::privacy::bundled_rules();
        let idx = self
            .tabs
            .iter()
            .position(|t| t.id == tab_id)
            .ok_or("no_tab")?;
        // Re-checked at the moment of use, never trusted from when the banner
        // was raised: a list refresh in between must not leave an override
        // standing for a host nothing would block.
        let still_listed = self.tabs[idx]
            .adlist
            .pending()
            .is_some_and(|p| rules.blocks_host(&p.host));
        // Cloned BEFORE allow consumes it, so a navigation that fails to
        // start can put back the exact record (id and method) the banner is
        // still showing (review R-003, round 4).
        let record = self.tabs[idx].adlist.pending().cloned();
        let url = self.tabs[idx]
            .adlist
            .allow(pending_id, shown_host, still_listed)
            .map_err(crate::adlist_consent::refusal_code)?;
        let host = shown_host.to_ascii_lowercase();
        platform::set_adlist_override(&self.tabs[idx].view, Some(host.clone()));
        // If the navigation cannot even START, the consent was consumed for
        // nothing: the user stays on the placeholder, the banner is gone, and
        // the exception stands. The first draft discarded this Result and
        // reported success (review R-005, round 3). Undo the grant, put the
        // banner back so the click can be retried, and say what happened.
        // A held URL WITH a fragment is resumed by reload, not by load_url.
        // The placeholder already sits at that address, and Microsoft
        // documents that Navigate to the current URL differing only in the
        // fragment is a fragment navigation: no request, no document, the
        // placeholder stays and the banner is gone (review R-002, round 5;
        // engine behaviour not reproduced here, taken from the vendor
        // documentation). history_reload re-requests the document; the
        // request handler sees the override and lets the real page through,
        // and the engine keeps the fragment. A tab whose first navigation
        // has not happened yet has no placeholder to reload, so it queues.
        //
        // ONLY FOR A HELD GET. A reload re-issues the request that produced
        // the current document, and for a held POST that is the POST, body
        // and all, which the banner promised would not be sent (review
        // R-001, round 6). A held POST with a fragment therefore resumes as
        // a plain GET to the address WITHOUT its fragment: the address then
        // differs from the placeholder's, so it is a real navigation, and
        // a fragment is the lesser loss on a form action next to the body.
        let was_post = record.as_ref().is_some_and(|r| r.method.eq_ignore_ascii_case("POST"));
        let has_fragment = url.contains('#');
        let resumed = if has_fragment && was_post {
            let bare = url.split('#').next().unwrap_or(&url).to_string();
            self.tabs[idx].queue_or_navigate(&bare)
        } else if has_fragment && !self.tabs[idx].initial_navigation_pending {
            self.tabs[idx].history_reload()
        } else {
            self.tabs[idx].queue_or_navigate(&url)
        };
        if let Err(reason) = resumed {
            self.tabs[idx].adlist.end_override();
            platform::set_adlist_override(&self.tabs[idx].view, None);
            if let Some(record) = record {
                self.tabs[idx].adlist.restore(record);
            }
            return Err(reason);
        }
        // The SAME shape insecure_allow returns, because the chrome reads
        // `res.status` and treats anything else as "hide the banner". A bare
        // status here made every successful allow take the hide branch, and a
        // late reply from one tab could take down another tab's banner (R-007).
        Ok(json!({ "allowed": host, "status": self.active_tab_status() }))
    }

    /// "Dismiss". Same id discipline: a stale click must not clear a banner
    /// raised for something else.
    pub fn adlist_dismiss(&mut self, tab_id: u64, pending_id: u64) -> Result<Value, &'static str> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|t| t.id == tab_id)
            .ok_or("no_tab")?;
        tab.adlist
            .dismiss(pending_id)
            .map_err(crate::adlist_consent::refusal_code)?;
        Ok(self.active_tab_status())
    }

    /// Raised by the engine adapters when a top-level navigation to a listed
    /// host was refused. Returns the pending id so the adapter can tag the
    /// placeholder load it is about to start.
    /// An import could not remove the previous profile's Library file. No
    /// Store is attached and the error names why, so store_open refuses
    /// until the file is dealt with rather than reattaching the old profile.
    pub fn detach_store_unreplaced(&mut self) {
        self.store = None;
        self.store_error = Some("library_not_replaced");
    }

    /// Records which host a tab was just blocked on and mints the id the
    /// banner must hand back. A NEW blocked attempt replaces the id, so a
    /// banner from an earlier attempt, even to the same host in the same
    /// tab, spends nothing (design review of pentest F-006).
    pub fn note_navigation_blocked(&mut self, tab_id: u64, host: &str) -> Option<u64> {
        let tab = self.tabs.iter().find(|t| t.id == tab_id)?;
        self.blocked_pending_seq = self.blocked_pending_seq.wrapping_add(1);
        let id = self.blocked_pending_seq;
        *tab.blocked_pending.borrow_mut() = Some((id, host.to_ascii_lowercase()));
        Some(id)
    }

    pub fn adlist_hold(&mut self, tab_id: u64, url: &str, host: &str, method: &str) -> Option<u64> {
        // Checked against the policy NOW, not when the engine queued the
        // hold. Switching blocking off clears every pending (round 2), but a
        // hold already queued behind that switch would raise a fresh banner
        // telling the user to disable protection that was just disabled
        // (review R-001, round 5). With blocking off there is no reason to
        // hold anything. THIS TAB's policy, not the browser-wide one: a
        // private tab blocks under its own preset while the switch is off,
        // and its hold is real (review R-002, round 6).
        let tab = self.tabs.iter_mut().find(|t| t.id == tab_id)?;
        if !tab.block_ads {
            return None;
        }
        Some(tab.adlist.raise(url, host, method))
    }

    pub fn insecure_dismiss(&mut self) -> Result<Value, &'static str> {
        let tab = self.tabs.get_mut(self.active).ok_or("no_tab")?;
        tab.insecure_pending = None;
        tab.insecure_pending_at = None;
        Ok(self.active_tab_status())
    }

    pub fn on_title_changed(&mut self, id: u64, title: String) {
        if let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == id) {
            tab.title = title;
            self.emit_tabs_changed();
        }
    }

    /// The URL bar's loading indicator tracks the active tab only.
    pub fn on_load_state(&mut self, id: u64, loading: bool) {
        // Probe deltas describe one document, never a tab's lifetime. A real
        // load start is the host-owned boundary; URL changes alone include
        // same-document fragment navigation and must not erase the reading.
        if loading {
            if let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == id) {
                tab.fingerprint_probes = FingerprintProbeCounts::default();
            }
        }
        // Freeze phase and TLS state both change across a load, and the
        // banner that warns about an intercepted connection is driven from
        // here. Without this the whole per-tab feed was silent.
        if self.tabs.get(self.active).map(|t| t.id) == Some(id) {
            self.emit_tab_status();
        }
        if self.tabs.get(self.active).map(|tab| tab.id) == Some(id) {
            self.emit("load_state", json!({ "loading": loading }));
        }
        crate::page_integrity::on_tab_load_state(self, id, loading);
    }
}

#[cfg(test)]
mod tests {
    use super::{check_download_file_in, hash_file, sanitize_filename, FileVerdict};
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    #[test]
    fn unix_strips_separators_and_leading_dots() {
        assert_eq!(sanitize_filename("/etc/passwd"), "etcpasswd");
        assert_eq!(sanitize_filename("..\\..\\evil.exe"), "evil.exe");
        assert_eq!(sanitize_filename(".hidden"), "hidden");
        assert_eq!(sanitize_filename(""), "download");
    }

    /// A FILE NAME IS A DISPLAY SURFACE, and the same characters that let a
    /// link text lie about its target let a name lie about its type.
    ///
    /// `invoice\u{202E}gpj.exe` renders in a file manager as `invoiceexe.jpg`,
    /// because the override reverses everything after it. A user who has been
    /// taught to check the extension before opening something checks it, and
    /// is told the wrong answer. Zero-width characters are the quieter half:
    /// they let two downloads look identical while being different files.
    ///
    /// Runs on both platforms because both file managers honour the override.
    #[test]
    fn deceptive_characters_never_survive_into_a_file_name() {
        // The classic: reads as ".jpg", actually ".exe".
        let disguised = sanitize_filename("invoice\u{202E}gpj.exe");
        assert!(
            !disguised.contains('\u{202E}'),
            "a direction override survived into a file name: {disguised:?}"
        );
        assert!(
            disguised.ends_with(".exe"),
            "the real extension must remain visible: {disguised:?}"
        );
        // Every character the hover readout refuses, refused here too.
        for c in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}',
            '\u{2067}', '\u{2068}', '\u{2069}', '\u{200B}', '\u{200E}', '\u{200F}',
            '\u{00AD}', '\u{FEFF}',
        ] {
            let name = format!("a{c}b.txt");
            let out = sanitize_filename(&name);
            assert!(
                !out.chars().any(crate::hover::is_deceptive),
                "{c:?} survived sanitizing: {out:?}"
            );
        }
        // A name made only of them is not a name.
        assert_eq!(sanitize_filename("\u{202E}\u{200B}"), "download");
        // And ordinary names are untouched.
        assert_eq!(sanitize_filename("report.pdf"), "report.pdf");
    }

    #[cfg(windows)]
    #[test]
    fn windows_replaces_reserved_chars() {
        assert_eq!(sanitize_filename("report?.pdf"), "report_.pdf");
        assert_eq!(sanitize_filename("a\\b/c:d"), "a_b_c_d");
        // Trailing dots/spaces would be silently stripped by Win32.
        assert_eq!(sanitize_filename("file."), "file");
        assert_eq!(sanitize_filename("file "), "file");
    }

    #[cfg(windows)]
    #[test]
    fn windows_blocks_device_names() {
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("con.txt"), "_con.txt");
        assert_eq!(sanitize_filename("COM1"), "_COM1");
        assert_eq!(sanitize_filename("lpt9.png"), "_lpt9.png");
        assert_eq!(sanitize_filename("company.txt"), "company.txt");
        assert_eq!(sanitize_filename("..."), "download");
    }

    fn temp_file(tag: &str, bytes: &[u8]) -> PathBuf {
        let unique = format!(
            "patanyx-app-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn hash_file_matches_the_sha256_test_vector_for_abc() {
        let path = temp_file("abc", b"abc");
        let (hash, len) = hash_file(&path).unwrap();
        assert_eq!(len, 3);
        assert_eq!(
            hash,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn check_download_file_distinguishes_match_differs_and_missing() {
        let dir = std::env::temp_dir();
        let path = temp_file("content", b"some downloaded bytes");
        let filename = path.file_name().unwrap().to_str().unwrap().to_string();
        let (sha256, _) = hash_file(&path).unwrap();

        assert!(matches!(
            check_download_file_in(&dir, &filename, &sha256),
            FileVerdict::Match
        ));

        let mut wrong = sha256;
        wrong[0] ^= 0x01;
        assert!(matches!(
            check_download_file_in(&dir, &filename, &wrong),
            FileVerdict::Differs
        ));

        assert!(matches!(
            check_download_file_in(&dir, "definitely-not-here.bin", &sha256),
            FileVerdict::Missing
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn check_download_file_refuses_names_with_separators() {
        // A record's filename must be a bare file name; anything else is
        // rejected before the filesystem is followed anywhere.
        assert!(matches!(
            check_download_file_in(Path::new("/tmp"), "../escape", &[0u8; 32]),
            FileVerdict::Unreadable
        ));
        assert!(matches!(
            check_download_file_in(Path::new("/tmp"), "a/b", &[0u8; 32]),
            FileVerdict::Unreadable
        ));
        assert!(matches!(
            check_download_file_in(Path::new("/tmp"), "", &[0u8; 32]),
            FileVerdict::Unreadable
        ));
    }

    /// `diagnostics_snapshot` cannot be exercised end-to-end here: `AppState`
    /// needs a real `WebView`/`Hosts` pair, which needs a display this test
    /// runner does not have. So this checks the constraint the function's own
    /// doc states -- reading its SOURCE, the same way `every_error_code_has_
    /// user_facing_text` in ipc.rs checks a claim by scanning text rather
    /// than by constructing what would be needed to observe it directly.
    ///
    /// Deliberately conservative: fails if the substring appears ANYWHERE in
    /// the function body, not just in an obviously-dangerous position. A
    /// diagnostics export composing a field named `history`/`credential`/
    /// `password`/`browsing_url` is the exact class of scope-creep this
    /// guards against, whatever form adding it took.
    #[test]
    fn diagnostics_snapshot_never_names_a_forbidden_field() {
        let source = include_str!("state.rs");
        let start = source
            .find("pub fn diagnostics_snapshot(&self) -> Value {")
            .expect("diagnostics_snapshot not found; this test's anchor was renamed");
        let end = source[start..]
            .find("\n    }\n")
            .map(|i| start + i)
            .expect("diagnostics_snapshot has no terminator");
        let body = &source[start..end];

        // Non-vacuity: the function must actually have grown past a stub, or
        // this test would pass by examining nothing.
        assert!(
            body.len() > 100,
            "diagnostics_snapshot's body is suspiciously short ({} bytes) -- \
             check the anchors above still bound the real function",
            body.len()
        );

        for forbidden in [
            "history",
            "credential",
            "password",
            "browsing_url",
            "self.vault",
            "self.store",
            "\"url\"",
        ] {
            assert!(
                !body.to_ascii_lowercase().contains(&forbidden.to_ascii_lowercase()),
                "diagnostics_snapshot's body mentions \"{forbidden}\" -- the \
                 diagnostics export must never carry history, credentials, or \
                 vault content",
            );
        }
    }
}

#[cfg(test)]
mod insecure_warning_tests {
    use super::{
        banner_subject_update, continue_matches_shown_banner, needs_insecure_warning, BannerUpdate,
        INSECURE_BANNER_STABILITY,
    };
    use std::time::Instant;

    /// THE ATTACK THIS BOUNDS. A page already continued-through runs
    /// `location.href = "http://" + rand() + ".attacker.example/"` every
    /// 50ms. Each attempt is held back and would have relabelled the banner,
    /// so the host a person reads need not be the host that is pending when
    /// their click lands. The subject is now frozen for the stability
    /// window, which makes a tight loop unable to move it at all.
    #[test]
    fn a_redirect_loop_cannot_relabel_the_banner_under_the_reader() {
        let t0 = Instant::now();
        let shown = "http://first.example/";
        for i in 0..20 {
            let attempt = format!("http://a{i}.attacker.example/");
            let step = t0 + INSECURE_BANNER_STABILITY / 40 * (i as u32 + 1);
            assert_eq!(
                banner_subject_update(Some(shown), Some(t0), &attempt, step),
                BannerUpdate::HoldSteady,
                "attempt {i} moved the banner inside the stability window"
            );
        }
    }

    #[test]
    fn the_same_url_again_changes_nothing_and_emits_nothing() {
        // A page retrying one URL must not drive a status sweep per attempt:
        // active_tab_status is a dozen COM round-trips on the event loop.
        let t0 = Instant::now();
        assert_eq!(
            banner_subject_update(Some("http://x.example/"), Some(t0), "http://x.example/", t0),
            BannerUpdate::Unchanged
        );
    }

    #[test]
    fn a_genuinely_later_navigation_does_replace_the_subject() {
        // The window steadies the banner; it must not freeze it forever, or
        // a real second navigation would be described by a stale one.
        let t0 = Instant::now();
        let later = t0 + INSECURE_BANNER_STABILITY + std::time::Duration::from_millis(1);
        assert_eq!(
            banner_subject_update(
                Some("http://a.example/"),
                Some(t0),
                "http://b.example/",
                later
            ),
            BannerUpdate::Replace
        );
        // And the first banner of all is never held back.
        assert_eq!(
            banner_subject_update(None, None, "http://a.example/", t0),
            BannerUpdate::Replace
        );
    }

    /// The second half of the defence: the window bounds how often the
    /// subject can move, and this catches the remaining race where it moved
    /// after the chrome painted but before the click was processed.
    #[test]
    fn continue_is_refused_when_the_pending_url_moved_after_the_paint() {
        // The user read "good.example" and clicked it.
        assert!(continue_matches_shown_banner(
            "http://good.example/path?q=1",
            "good.example"
        ));
        assert!(continue_matches_shown_banner(
            "http://GOOD.example/",
            "good.example"
        ));
        // Pending has since become the attacker's. The click names what was
        // on screen, the two disagree, and it is refused rather than loading
        // a full attacker-chosen URL as the top-level document.
        assert!(!continue_matches_shown_banner(
            "http://attacker.example/deep/path",
            "good.example"
        ));
        // A host that cannot be parsed can never match.
        assert!(!continue_matches_shown_banner("not a url", ""));
        assert!(!continue_matches_shown_banner("http://good.example/", ""));
    }

    #[test]
    fn the_echoed_host_cannot_name_a_destination_of_its_own() {
        // The property that keeps this a confirmation rather than a
        // selection: agreement is only ever possible with the URL already
        // pending, so no value passed in can introduce a new one.
        for attempt in [
            "evil.example",
            "good.example.evil.example",
            "good.example:80",
            "good.example/",
            "",
        ] {
            let allowed = continue_matches_shown_banner("http://good.example/", attempt);
            assert_eq!(
                allowed,
                attempt == "good.example",
                "{attempt:?} must not be accepted for good.example"
            );
        }
    }

    /// The case the feature exists for: a public site over plain HTTP is
    /// held back; the same site over HTTPS is not.
    #[test]
    fn public_http_is_warned_https_is_not() {
        assert!(needs_insecure_warning("http://example.com/"));
        assert!(needs_insecure_warning("HTTP://Example.COM/path?q=1"));
        assert!(needs_insecure_warning("http://user@example.com:8080/"));
        assert!(!needs_insecure_warning("https://example.com/"));
        assert!(!needs_insecure_warning("about:blank"));
    }

    /// The user's own network is exempt: routers, printers and LAN devices
    /// are plain HTTP by construction, and a warning that fires on every one
    /// of them teaches the user to click through it.
    #[test]
    fn local_and_private_addresses_are_exempt() {
        for url in [
            "http://localhost/",
            "http://localhost:8080/admin",
            "http://router.localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://192.168.1.1/",
            "http://10.0.0.5:9000/",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            assert!(!needs_insecure_warning(url), "{url} must not be warned about");
        }
    }

    /// A public address that merely LOOKS local is not exempt: only literal
    /// private ranges and the localhost name are, never a hostname that might
    /// resolve there.
    #[test]
    fn a_public_name_is_not_exempt_for_sounding_local() {
        assert!(needs_insecure_warning("http://router.example.com/"));
        assert!(needs_insecure_warning("http://8.8.8.8/"));
        assert!(needs_insecure_warning("http://192.168.1.1.example.com/"));
    }

    /// Anything the allowlist upstream would already refuse is not this
    /// warning's business: no authority, no warning.
    #[test]
    fn unparseable_urls_are_not_warned() {
        assert!(!needs_insecure_warning("http://"));
        assert!(!needs_insecure_warning("http:///path"));
        assert!(!needs_insecure_warning("file:///etc/passwd"));
        assert!(!needs_insecure_warning("javascript:alert(1)"));
    }
}

#[cfg(test)]
mod permission_book_tests {
    use super::{normalize_origin, PermKind, PermissionBook};

    const SITE: &str = "https://example.com";
    const FRAME: &str = "https://ads.other.example";

    /// The whole premise. Nothing is allowed until a human allows it.
    #[test]
    fn everything_is_denied_before_anyone_grants_anything() {
        let book = PermissionBook::default();
        for kind in PermKind::ALL {
            assert!(!book.decide(SITE, SITE, kind), "{kind:?} must start denied");
        }
    }

    #[test]
    fn a_granted_origin_is_allowed_and_a_revoked_one_is_not() {
        let book = PermissionBook::default();
        assert!(book.grant(SITE, PermKind::Camera));
        assert!(book.decide(SITE, SITE, PermKind::Camera));
        // The grant is per KIND, never a blanket allow for the site.
        assert!(!book.decide(SITE, SITE, PermKind::Microphone));
        assert!(book.revoke(SITE, PermKind::Camera));
        assert!(!book.decide(SITE, SITE, PermKind::Camera));
    }

    /// A non-negotiable rule. Allowing the page must never hand
    /// the camera to an advertising iframe the page embeds.
    #[test]
    fn an_embedded_frame_does_not_inherit_the_pages_grant() {
        let book = PermissionBook::default();
        book.grant(SITE, PermKind::Camera);
        assert!(book.decide(SITE, SITE, PermKind::Camera));
        assert!(
            !book.decide(FRAME, SITE, PermKind::Camera),
            "a frame with its own origin must ask for itself"
        );
    }

    /// A frame's denial has to surface on the tab where it happened, or the
    /// user cannot allow it from the only context they have.
    #[test]
    fn a_frames_denial_is_visible_on_the_tab_it_happened_under() {
        let book = PermissionBook::default();
        book.decide(FRAME, SITE, PermKind::Camera);
        let rows = book.status_for(SITE);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.origin, FRAME);
        assert!(!rows[0].1, "it was denied");
        assert_eq!(rows[0].2, 1, "and counted");
    }

    /// A grant made under one site stays revocable from wherever it is active.
    #[test]
    fn an_active_frame_grant_stays_visible_for_revocation() {
        let book = PermissionBook::default();
        book.decide(FRAME, SITE, PermKind::Camera);
        book.grant(FRAME, PermKind::Camera);
        let rows = book.status_for(SITE);
        assert_eq!(rows.len(), 1, "still listed after being granted");
        assert!(rows[0].1, "now shown as granted");
    }

    #[test]
    fn repeated_denials_are_counted_not_duplicated() {
        let book = PermissionBook::default();
        for _ in 0..5 {
            book.decide(SITE, SITE, PermKind::Geolocation);
        }
        let rows = book.status_for(SITE);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].2, 5);
    }

    /// Page content picks these origins, so the table must not grow forever.
    #[test]
    fn the_denied_table_is_bounded_against_hostile_content() {
        let book = PermissionBook::default();
        for i in 0..2000 {
            book.decide(
                &format!("https://n{i}.attacker.example"),
                SITE,
                PermKind::Camera,
            );
        }
        let rows = book.status_for(SITE);
        assert!(
            rows.len() <= super::MAX_DENIED_KEYS,
            "denied table grew to {} entries",
            rows.len()
        );
    }

    /// Opaque and malformed origins are not sites. Accepting them would let
    /// unrelated sandboxed documents share one grant.
    #[test]
    fn an_unusable_origin_can_never_be_granted() {
        let book = PermissionBook::default();
        for bad in [
            "null",
            "about:blank",
            "https://",
            "http://",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,x",
            "https://@",
            "https://:443",
            "https://exa mple.com",
            "https://..",
            "",
        ] {
            assert!(normalize_origin(bad).is_none(), "must reject {bad:?}");
            assert!(!book.grant(bad, PermKind::Camera), "must not grant {bad:?}");
            assert!(
                !book.decide(bad, SITE, PermKind::Camera),
                "must not allow {bad:?}"
            );
        }
    }

    /// Two spellings of one site must not need allowing twice.
    #[test]
    fn origins_normalise_so_one_grant_is_one_site() {
        let book = PermissionBook::default();
        book.grant(
            "https://Example.COM:443/some/path?q=1#frag",
            PermKind::Camera,
        );
        for spelling in [
            "https://example.com",
            "https://EXAMPLE.com",
            "https://example.com:443",
            "https://example.com/other/page",
        ] {
            assert!(
                book.decide(spelling, SITE, PermKind::Camera),
                "{spelling} is the same site"
            );
        }
        // A different port IS a different origin, and a different scheme too.
        assert!(!book.decide("https://example.com:8443", SITE, PermKind::Camera));
        assert!(!book.decide("http://example.com", SITE, PermKind::Camera));
    }

    /// Fail closed. A table that cannot be reached must not answer yes.
    #[test]
    fn a_poisoned_table_denies_rather_than_allowing() {
        let book = PermissionBook::default();
        book.grant(SITE, PermKind::Camera);
        assert!(book.decide(SITE, SITE, PermKind::Camera), "granted first");

        let poisoner = book.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.0.lock().unwrap();
            panic!("poison the mutex on purpose");
        })
        .join();

        assert!(
            !book.decide(SITE, SITE, PermKind::Camera),
            "an unreachable table must deny even a granted permission"
        );
        assert!(book.status_for(SITE).is_empty(), "and show nothing");
    }
}

/// The per-site divergence table, as a JSON object literal ready to inject.
///
/// A process-level cache rather than a field, because the script is built in
/// `platform::privacy::divergence_script` during tab construction, where no
/// `AppState` is in scope. Starts EMPTY and returns to empty at vault lock:
/// the choices are encrypted with the vault, so a locked browser does not
/// know them, and pretending otherwise would apply a stale table to a tab
/// opened after the vault closed.
static DIVERGENCE_OVERRIDES_JSON: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

pub fn divergence_overrides_snapshot() -> String {
    DIVERGENCE_OVERRIDES_JSON
        .lock()
        .map(|held| {
            if held.is_empty() {
                "{}".to_string()
            } else {
                held.clone()
            }
        })
        // A poisoned lock means a panic happened while the table was being
        // written. The safe answer is the global behaviour, never a
        // half-written table.
        .unwrap_or_else(|_| "{}".to_string())
}

fn set_divergence_overrides_snapshot(json: String) {
    if let Ok(mut held) = DIVERGENCE_OVERRIDES_JSON.lock() {
        *held = json;
    }
}

impl AppState {
    /// Whether the active tab actually got a divergence script.
    pub fn active_divergence_registered(&self) -> bool {
        self.tabs
            .get(self.active)
            .map(|tab| tab.divergence_registered)
            .unwrap_or(false)
    }
}

/// Whether a URL is a page a user could have asked to read in another
/// language. Excludes our own chrome and the translator origin explicitly:
/// pointing the machinery at the privileged UI is exactly what the origin
/// split exists to prevent, and it should be impossible by policy here too,
/// not only by construction over there.
pub fn is_translatable_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with(platform::CHROME_ORIGIN_PREFIX)
        || lower.starts_with(platform::TRANSLATE_ORIGIN_PREFIX)
        || lower.starts_with("about:")
        || lower.starts_with("data:")
        || lower.starts_with("file:")
        || lower.is_empty()
    {
        return false;
    }
    lower.starts_with("http://") || lower.starts_with("https://")
}


#[cfg(test)]
mod login_submit_tests {
    use super::*;

    /// THE TESTER'S SIDE OF THE STORY. A locked vault used to drop a
    /// submission in silence; the only outcome that may stay silent now is the
    /// one where there is nothing to unlock.
    #[test]
    fn a_locked_vault_is_no_longer_silent() {
        use super::{login_submit_outcome, LoginSubmitOutcome};
        // (vault unlocked, a vault file exists, already stored) -> outcome
        let cases = [
            ((true, true, false), LoginSubmitOutcome::Offer),
            // AUTOFILL THEN SUBMIT. Reported from Windows hardware: filling a
            // saved password and signing in immediately asked whether to save
            // the password the browser had just typed. The vault already holds
            // it, so there is no question to ask.
            ((true, true, true), LoginSubmitOutcome::AlreadySaved),
            // Unlocked implies a vault exists; kept to pin that the open vault
            // wins regardless of what the second input says.
            ((true, false, false), LoginSubmitOutcome::Offer),
            // A LOCKED vault cannot have compared anything, so already_saved
            // is false there by construction -- but pin that it would not
            // change the answer even if something set it.
            ((false, true, false), LoginSubmitOutcome::NoticeLocked),
            ((false, true, true), LoginSubmitOutcome::NoticeLocked),
            // Never created a vault: saying "unlock it" would name something
            // that does not exist.
            ((false, false, false), LoginSubmitOutcome::Silent),
        ];
        for ((unlocked, exists, saved), want) in cases {
            assert_eq!(
                login_submit_outcome(unlocked, exists, saved),
                want,
                "unlocked={unlocked} exists={exists} already_saved={saved}"
            );
        }
    }

    /// The cooldown is what keeps a page from stacking these up the side of
    /// the chrome. It is time-based BECAUSE the page controls how often the
    /// code runs (no isTrusted check on the submit listener, and the native
    /// bridge is reachable directly) but does not control the clock.
    #[test]
    fn the_notice_cooldown_outlives_the_toast_it_rate_limits() {
        use super::{locked_save_notice_due, LOCKED_SAVE_NOTICE_COOLDOWN};
        // The property, not the number, and the number is READ FROM THE
        // CHROME rather than restated here. Restating it is how this test
        // would keep passing while measuring a lifetime the product no longer
        // uses: the notification moved from 6s to 15s, and a hardcoded 6000
        // would still have been satisfied by a cooldown too short to prevent
        // two notices overlapping.
        const CHROME_JS: &str = include_str!("chrome/chrome.js");
        let at = CHROME_JS
            .find("const TOAST_MS = ")
            .expect("chrome.js no longer declares TOAST_MS");
        let rest = &CHROME_JS[at + "const TOAST_MS = ".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        // REFUSE what this cannot read, rather than reading part of it.
        // Taking leading digits alone turns JavaScript's `60_000` -- sixty
        // thousand milliseconds -- into 60, and a cooldown comparison against
        // 60ms would pass while two notices overlapped on screen. A parser
        // that silently returns a smaller number is worse than no parser.
        let after = &rest[digits.len()..];
        assert!(
            after.starts_with(';'),
            "TOAST_MS is not a plain decimal literal ({:?}...); this test can \
             only compare a number it fully understands",
            &rest[..digits.len() + 4.min(after.len())]
        );
        let toast_ms: u64 = digits.parse().expect("TOAST_MS is not a plain number");
        assert!(
            LOCKED_SAVE_NOTICE_COOLDOWN > Duration::from_millis(toast_ms),
            "the cooldown ({LOCKED_SAVE_NOTICE_COOLDOWN:?}) must outlast a \
             notification ({toast_ms}ms), or two can be on screen at once"
        );

        let t0 = Instant::now();
        // Nothing shown yet: the first submission always speaks.
        assert!(locked_save_notice_due(None, t0));
        // A flood inside the window is refused, however many arrive.
        for after in [0, 1, 5, 29] {
            assert!(
                !locked_save_notice_due(Some(t0), t0 + Duration::from_secs(after)),
                "a second notice {after}s later must be suppressed"
            );
        }
        // And it re-arms, so a genuine later login is still told.
        assert!(locked_save_notice_due(Some(t0), t0 + LOCKED_SAVE_NOTICE_COOLDOWN));
        assert!(locked_save_notice_due(Some(t0), t0 + Duration::from_secs(31)));
    }



    /// The JOIN, driven against a real vault.
    ///
    /// `has_matching_credential` had a test and `login_submit_outcome` had a
    /// test; the line between them had none, so passing a literal `false`
    /// would have put the autofill-then-asked-to-save bug straight back with
    /// every test still passing.
    #[test]
    fn a_stored_credential_is_recognised_through_the_join() {
        use super::already_stored;
        let dir = std::env::temp_dir().join(format!("patanyx-join-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.json");
        let _ = std::fs::remove_file(&path);
        let mut vault = Vault::create_with_params(&path, "test passphrase", 8192, 1, 1)
            .unwrap()
            .0;
        vault
            .add_credential(
                "accounts.example.com",
                Some("accounts.example.com"),
                "dora",
                "hunter2",
                "",
            )
            .unwrap();

        // The reported case: filled from the vault, submitted, already stored.
        assert!(
            already_stored(Some(&vault), "accounts.example.com", "dora", "hunter2"),
            "the credential the vault just stored was not recognised"
        );
        // Across subdomains, because that is how the FILL offer matches too.
        assert!(
            already_stored(Some(&vault), "mail.example.com", "dora", "hunter2"),
            "a sibling subdomain must recognise it, or a second copy is saved"
        );
        // A changed password is a password change and must still be offered.
        assert!(!already_stored(Some(&vault), "accounts.example.com", "dora", "hunter3"));
        // A different site must never suppress another site's save offer.
        assert!(!already_stored(Some(&vault), "evil.example.net", "dora", "hunter2"));
        // A LOCKED vault compares nothing.
        assert!(!already_stored(None, "accounts.example.com", "dora", "hunter2"));

        // AND THE DISPATCHER MUST ACTUALLY ASK.
        //
        // Everything above drives `already_stored` directly. What no unit test
        // here can reach is `note_login_submitted_at`, because AppState owns
        // live webviews and cannot be built -- so replacing its call with a
        // literal `false` restores the reported bug with every assertion above
        // still green. Proven by planting exactly that.
        //
        // Checked as source text, which is weak, and recorded as weak rather
        // than left implied. The strong version needs an AppState this crate
        // cannot construct.
        const SELF_SRC: &str = include_str!("state.rs");
        // SPLIT so the needle cannot match ITSELF. Written whole, this literal
        // appears in this very file, so the assertion stayed green after the
        // call it guards was deleted -- it was finding its own text. `concat!`
        // rebuilds it at compile time while leaving the source split.
        let needle = concat!("already_stored(self.vault", ".as_ref()");
        assert!(
            SELF_SRC.contains(needle),
            "note_login_submitted_at no longer asks whether the credential is \
             already stored, so an autofilled password would be offered for \
             saving again"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    /// The suppression AS IT ACTUALLY RUNS: decision and stamp together,
    /// driving the same state the dispatcher owns.
    ///
    /// This is the test whose absence let the stamp be deleted with every
    /// other test here still passing.
    #[test]
    fn the_notice_stamps_itself_so_the_next_one_is_suppressed() {
        use super::{take_locked_save_notice, LOCKED_SAVE_NOTICE_COOLDOWN};
        let t0 = Instant::now();
        let mut slot: Option<Instant> = None;

        assert!(take_locked_save_notice(&mut slot, t0), "the first must speak");
        assert_eq!(slot, Some(t0), "it must record that it spoke");

        // A page can call this as often as it likes; the clock is what says no.
        for after in [0, 1, 5, 29] {
            let t = t0 + Duration::from_secs(after);
            assert!(
                !take_locked_save_notice(&mut slot, t),
                "a notice {after}s later must be suppressed"
            );
            assert_eq!(slot, Some(t0), "a suppressed notice must not re-stamp");
        }

        // And it re-arms, so a genuine later login is still told.
        let later = t0 + LOCKED_SAVE_NOTICE_COOLDOWN;
        assert!(take_locked_save_notice(&mut slot, later));
        assert_eq!(slot, Some(later), "speaking again must move the stamp");
        assert!(
            !take_locked_save_notice(&mut slot, later + Duration::from_secs(1)),
            "the second notice must start its own cooldown"
        );
    }

    /// The sentence and its catalog id have to agree, and the id has to exist.
    /// This is the seam a JavaScript gate cannot see from the Rust side and
    /// the Rust tests cannot see from the chrome side, so it is checked as
    /// text, the way `every_error_code_has_user_facing_text` already does.
    ///
    /// KNOWN LIMIT, recorded rather than implied: this proves the id is
    /// present in both files and that the chrome asks for it. It cannot prove
    /// that the Rust arm actually emits `vault_locked_no_save` on a real
    /// submission -- the capture path is Windows-only (`unix.rs` has no
    /// `login_submit` handler at all), so that step is owed a Windows run.
    #[test]
    fn the_locked_notice_string_reaches_the_chrome() {
        const CHROME_JS: &str = include_str!("chrome/chrome.js");
        const EN_FTL: &str = include_str!("chrome/i18n/locales/en.ftl");
        assert!(
            CHROME_JS.contains("\"vault_locked_no_save\""),
            "chrome.js does not handle the event this arm emits"
        );
        assert!(
            CHROME_JS.contains("chrome-js-toast-locked-no-save"),
            "chrome.js does not ask for the notice string"
        );
        assert!(
            EN_FTL.contains("chrome-js-toast-locked-no-save = "),
            "the catalog has no entry for the notice string"
        );
    }

    /// Notifications are CENTRED AND BOLD, by decision: "I want all
    /// notifications to show like that. Forget the upper right hand corner
    /// notifications." They used to sit top-right in a 320px box, which is
    /// easily missed, and a notification nobody reads is not a notification.
    ///
    /// Pinned as text because the shape of the surface is a decision, not an
    /// accident, and the next person to tidy this CSS should have to change a
    /// test that says so. The rendered result -- centre offset, weight, and no
    /// truncation -- is measured in a real browser; this only guards the
    /// intent.
    #[test]
    fn notifications_are_centred_and_bold() {
        const CSS: &str = include_str!("chrome/chrome.css");
        const CHROME_JS: &str = include_str!("chrome/chrome.js");
        // Each rule is sliced to its own closing brace rather than a fixed
        // number of characters. A fixed window silently stops covering the
        // declarations it was written to check the moment someone adds a
        // comment inside the rule -- which is exactly how this test started
        // failing on a property that had not changed.
        let rule = |name: &str| -> &str {
            let at = CSS
                .find(name)
                .unwrap_or_else(|| panic!("{name} rule is gone"));
            let end = CSS[at..]
                .find("\n}")
                .unwrap_or_else(|| panic!("{name} rule has no terminator"));
            &CSS[at..at + end]
        };
        let block = rule("#toasts {");
        assert!(
            block.contains("left: 50%") && block.contains("translateX(-50%)"),
            "the notification surface is no longer centred"
        );
        assert!(
            !block.contains("right: 8px"),
            "the notification surface went back to the corner"
        );
        let tblock = rule("\n.toast {");
        assert!(
            tblock.contains("font-weight: 600"),
            "notifications are no longer bold"
        );
        assert!(
            !tblock.contains("white-space: nowrap"),
            "nowrap is back, so a long notification is silently truncated"
        );

        // CLICK-THROUGH. Notices sit centred, over the address bar, so the
        // surface must not take clicks -- except the dismiss button, which is
        // useless if it does not. Both halves matter and each has been wrong
        // in a draft: a notice that eats clicks makes a six-second dead zone
        // across the toolbar, and a button that does not take them is a
        // control the user cannot press.
        assert!(
            block.contains("pointer-events: none"),
            "the notification surface takes clicks; it would swallow clicks \
             meant for the toolbar underneath it"
        );
        // ABOVE THE MODAL SCRIM. At z-index 20 the surface sat UNDER the
        // scrim (30), so with any panel open a notification was dimmed and its
        // dismiss button could not be clicked -- a control the user is told to
        // use and cannot reach.
        let z = block
            .find("z-index: ")
            .map(|i| {
                block[i + "z-index: ".len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
            })
            .and_then(|d| d.parse::<u32>().ok())
            .expect("#toasts declares no z-index");
        // THE WHOLE ORDERING, not just "above the scrim". `z > 30` accepted
        // 35, which still sits under the panels at 40 and under the strip at
        // 50 while a modal is open, and accepted 65, which covers the accent
        // frame at 60. Both would have passed this test while undoing what it
        // exists to protect.
        assert!(
            z > 50,
            "notifications sit at z-index {z}: above the scrim (30) is not \
             enough, they must also clear the panels (40) and the strip (50) \
             or the dismiss button is still unreachable with a panel open"
        );
        assert!(
            z < 60,
            "notifications sit at z-index {z}, at or above the accent frame \
             (60), which is meant to be the outermost thing drawn"
        );

        // DISMISSING A NOTICE MUST NOT CLOSE THE PANEL UNDER IT.
        //
        // Lifting this surface above the modal scrim is what made the X
        // clickable with a panel open, and the first thing that made possible
        // was a mousedown bubbling to the document's outside-click handler,
        // which ran `closeOpenPanel()` -- whose onClose wipes a chat
        // transcript and its unsent draft. Pressing X to clear a notice
        // destroyed the conversation behind it. Reproduced in a browser, fixed
        // by adding #toasts to the handler's exemption list.
        //
        // Checked as TEXT because the DOM harness cannot model it: `_fire`
        // does not bubble to a document-level listener, so a gate check there
        // passed whether the exemption was present or not. The real
        // interaction is verified in a browser; this pins the contract so it
        // cannot be silently removed.
        let at = CHROME_JS
            .find("!ev.target.closest(")
            .expect("the outside-click handler no longer guards on closest()");
        // The SELECTOR ITSELF, split the way the browser reads it.
        //
        // Checking that a window of text merely CONTAINS "#toasts" is not the
        // same claim: delete the comma before it and the list becomes
        // `#confirm-overlay #toasts`, a valid DESCENDANT selector matching
        // nothing, because those two containers are siblings. The exemption
        // dies, the chat-wiping regression comes back, and a contains() check
        // sails straight through it.
        let open_q = CHROME_JS[at..]
            .find('"')
            .expect("the closest() guard has no selector literal")
            + at;
        let close_q = CHROME_JS[open_q + 1..]
            .find('"')
            .expect("the selector literal is unterminated")
            + open_q
            + 1;
        let selector = &CHROME_JS[open_q + 1..close_q];
        assert!(
            selector.split(',').any(|part| part.trim() == "#toasts"),
            "#toasts is not its own entry in the outside-click exemption list \
             ({selector:?}), so pressing a notification's X would close the \
             open panel and run its onClose, wiping a chat transcript"
        );

        let cblock = rule(".toast-close {");
        assert!(
            cblock.contains("pointer-events: auto"),
            "the dismiss button does not take clicks, so it cannot be pressed"
        );
    }
}

#[cfg(test)]
mod translation_session_tests {
    use super::*;

    /// THE TIER GATE, exhaustively against the real registry.
    ///
    /// Its three call sites (install, the download choke point, and translate)
    /// hang off an AppState owning live WebViews and cannot be unit-tested;
    /// the DECISION they all share can be, and is. If a tier-2 pair ever
    /// became reachable without a licence, this fails.
    #[test]
    fn tier_two_pairs_need_premium_and_tier_one_never_does() {
        let mut saw_tier_two = 0;
        for p in crate::languages::PAIRS {
            match p.tier {
                1 => {
                    assert!(tier_allows(p.token, false), "{} must be free", p.token);
                    assert!(tier_allows(p.token, true), "{} must stay free", p.token);
                }
                2 => {
                    saw_tier_two += 1;
                    assert!(
                        !tier_allows(p.token, false),
                        "{} is tier 2 and must be REFUSED without a licence",
                        p.token
                    );
                    assert!(
                        tier_allows(p.token, true),
                        "{} is tier 2 and must be allowed WITH a licence",
                        p.token
                    );
                }
                other => panic!("{}: unexpected tier {other}", p.token),
            }
        }
        // NOT an anti-vacuity assert on the registry any more: since OPUS-MT
        // became free there is no tier-2 row, and `saw_tier_two` is expected
        // to be zero. The gate is proven directly instead, so it stays under
        // test no matter what the product tiers today.
        let _ = saw_tier_two;
        assert!(tier_allows_row(1, false), "tier 1 is free");
        assert!(tier_allows_row(1, true), "tier 1 stays free");
        assert!(!tier_allows_row(2, false), "tier 2 without a licence is REFUSED");
        assert!(tier_allows_row(2, true), "tier 2 with a licence is allowed");
        // A tier above 2 is not a loophole: anything that is not tier 1 needs
        // a licence.
        assert!(!tier_allows_row(3, false), "an unknown high tier must not be free");
    }

    /// A FREE INSTALL IS NEVER TOLD THE PREMIUM LANGUAGES EXIST.
    ///
    /// `packs_status` is what the panel renders from, so the rule is enforced
    /// where the data is made: an unentitled session receives no row for a
    /// premium language it has not installed. This pins the shape of that
    /// filter against the real registry (the AppState it hangs off owns live
    /// WebViews and cannot be built in a test, so the predicate is checked
    /// directly, the same way the tier gate is).
    /// A language is installed when EVERY published direction is.
    ///
    /// `any` stranded a language with no way out: a user carrying en-es from
    /// the old single-pair build saw Spanish marked Installed, so the row
    /// offered Remove and nothing else -- while es-en had never been fetched,
    /// leaving Spanish->English with no target and no control to fix it.
    ///
    /// The rule: every language translates to English and back,
    /// unless the reverse pair does not exist upstream -- and then the single
    /// direction IS the whole language. So this is a count against what the
    /// registry publishes, never a fixed expectation of two.
    #[test]
    fn a_language_is_installed_only_when_all_its_directions_are() {
        // The predicate as packs_status computes it.
        let state = |present: usize, published: usize| {
            let all = present > 0 && present == published;
            let partial = present > 0 && !all;
            (all, partial)
        };
        // Two-way language, one direction on disk: NOT installed, and partial
        // so the panel can offer to finish it.
        assert_eq!(state(1, 2), (false, true));
        assert_eq!(state(2, 2), (true, false));
        assert_eq!(state(0, 2), (false, false));
        // One-way language (no reverse model upstream): the single direction
        // is the whole language and must read as fully installed, never as
        // half of something.
        assert_eq!(state(1, 1), (true, false));
        assert_eq!(state(0, 1), (false, false));

        // The registry really does carry one-way languages, or the case above
        // is hypothetical: Georgian, Hausa, Igbo and Kinyarwanda have no
        // en-X model, and Azerbaijani and Albanian are one-way upstream.
        let mut one_way = 0;
        for lang in crate::languages::LANGUAGES {
            if lang.code == "en" {
                continue;
            }
            let n = crate::languages::PAIRS
                .iter()
                .filter(|p| p.from == lang.code || p.to == lang.code)
                .count();
            if n == 1 {
                one_way += 1;
            }
        }
        assert!(
            one_way > 0,
            "no one-way language in the registry: the single-direction case \
             above would be untested"
        );
    }

    #[test]
    fn the_premium_row_filter_hides_unowned_languages_from_free_installs() {
        // (premium, entitled, installed) -> is the row sent?
        let sent = |premium: bool, entitled: bool, installed: bool| {
            !premium || entitled || installed
        };
        // A free install sees every free language and no premium one.
        assert!(sent(false, false, false), "free languages are always listed");
        assert!(!sent(true, false, false), "a premium language must be hidden");
        // Entitled sees them.
        assert!(sent(true, true, false), "a licence reveals them");
        // And the one exception: already installed stays listed even after a
        // lapse, so the pack can still be REMOVED rather than stranded.
        assert!(sent(true, false, true), "an installed pack keeps its Remove");

        // No registry dependency: there is no premium language today (OPUS-MT
        // became free on 2026-09-01), and the filter's RULE is what this pins.
        // Tying it to a real row is what made it fail when the product
        // retiered, which is the opposite of what a rule test should do.
        assert!(
            crate::languages::PAIRS.iter().all(|p| p.tier == 1),
            "a premium language reappeared: re-check the panel copy and the \
             gate tests, both of which assume nothing is gated today"
        );
    }

    /// A token the registry does not carry is not the tier gate's business:
    /// every caller has already refused it. Answering "denied" here would
    /// report a typo as a licensing problem.
    #[test]
    fn an_unknown_token_is_not_a_licensing_refusal() {
        for miss in ["", "zz-zz", "en", "en-es-fr", "LA-EN"] {
            assert!(tier_allows(miss, false), "{miss:?} is not a tier refusal");
        }
    }

    /// The pivot cannot be installed or removed as a language: every pair
    /// contains English, so "install English" would mean the whole registry.
    #[test]
    fn english_is_not_an_installable_language() {
        assert!(
            crate::languages::PAIRS.iter().all(|p| p.from == "en" || p.to == "en"),
            "the pivot assumption behind the en refusal no longer holds"
        );
    }

    /// The pair is an allowlist against the PUBLISHED registry, not a parse.
    /// This value selects a model to fetch and load, so anything the chrome
    /// sends is either a token the registry publishes or it is refused --
    /// nothing sanitised, nothing escaped.
    #[test]
    fn only_published_pairs_are_accepted() {
        // Published tokens resolve to themselves (the 'static registry copy).
        // en-fr is a REAL published pair now, where it used to be a stand-in
        // for "not offered"; the hostile cases below carry that weight instead.
        for good in ["en-es", "el-en", "es-en", "en-fr"] {
            assert_eq!(validate_translation_pair(good), Some(good), "accept {good}");
        }
        for hostile in [
            "en-es/../../etc/passwd",
            "../en-es",
            "en-es\0",
            "EN-ES",            // registry tokens are lowercase
            "en_es",            // wrong separator
            "",
            "en-es ",           // trailing space
            "https://evil.example/model.bin",
            "en-zz",            // shaped like a token, not published
            "en-es-fr",         // three subtags
            "xx-yy",            // valid shape, absent from the registry
        ] {
            assert_eq!(
                validate_translation_pair(hostile),
                None,
                "must refuse {hostile:?}"
            );
        }
    }

    /// The registry lookup NEVER splits a token. A script-tagged code would be
    /// unsplittable ("en-zh-Hans"), and although such tokens are excluded from
    /// the registry, the resolver must not depend on that: it matches whole
    /// tokens and returns the row's own components.
    #[test]
    fn pair_resolution_is_lookup_not_split() {
        let row = crate::languages::pair_by_token("en-es").expect("published");
        assert_eq!(row.token, "en-es");
        assert_eq!(row.from, "en");
        assert_eq!(row.to, "es");
        // A THREE-SUBTAG token resolves to its true components, which is the
        // whole reason resolution is a lookup: "en-zh-hans" cannot be split
        // unambiguously, and nothing tries -- the row carries `from`/`to`,
        // and `from` keeps the real casing the engine needs.
        let row = crate::languages::pair_by_token("en-zh-hans").expect("published");
        assert_eq!(row.from, "en");
        assert_eq!(row.to, "zh-Hans");
        // A token absent from the registry yields nothing, never a guessed split.
        assert!(crate::languages::pair_by_token("en-zz-hans").is_none());
        assert!(crate::languages::pair_by_token("en-zh-Hans").is_none(), "tokens are lowercase");
    }

    /// Page-controlled language strings are refused unless tag-shaped, so
    /// bidi/control/homoglyph junk never reaches the badge.
    #[test]
    fn detected_lang_rejects_non_tags() {
        for good in ["en", "el", "zh-hans", "pt-BR", "de"] {
            assert!(is_plausible_lang_tag(good), "should accept {good}");
        }
        for bad in [
            "",
            "e",                       // too short
            "\u{202E}evil",            // RTL override
            "en\u{200B}",              // zero-width
            "en es",                   // space
            "en/es",
            "en\0",
            "语言",                     // non-ASCII
            &"a".repeat(33),           // too long
        ] {
            assert!(!is_plausible_lang_tag(bad), "should refuse {bad:?}");
        }
    }

    /// THE CORRUPTION GUARD, proved at the state layer: a Greek page against
    /// an English source is refused, and the incident cannot recur.
    ///
    /// This is the planted-defect proof for the whole cluster. If
    /// `script_refuses` ever returned false for the Greek-into-en case, the
    /// mangled-Greek-written-into-the-page bug is back, and this test goes red.
    #[test]
    fn a_greek_page_against_an_english_source_is_refused() {
        let greek: Vec<String> = [
            "Καλώς ήλθατε στην εφαρμογή",
            "Επιλέξτε Ενεργώ για τον εαυτό μου εφόσον έχετε ΑΦΜ και Κλειδάριθμο",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // The incident: refused.
        let counts = |source: &str, texts: &[String]| {
            let mut c = crate::detect::ScriptCounts::new(source);
            c.add_batch(texts);
            c
        };
        assert!(script_refuses(&counts("en", &greek)), "Greek into en MUST refuse");
        // Greek into a Greek source: allowed.
        assert!(!script_refuses(&counts("el", &greek)), "Greek into el must proceed");

        // A clean English page against en: allowed.
        let english: Vec<String> = ["Welcome to the application, please choose an option below"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(!script_refuses(&counts("en", &english)), "English into en must proceed");
        // English against a Greek source: refused (the mirror of the incident).
        assert!(script_refuses(&counts("el", &english)), "English into el must refuse");
    }

    /// Every detection failure key the guard can produce has a panel case, so
    /// a refusal renders a real message rather than degrading to the generic
    /// one. Mirrors the langpack test for PackError keys.
    #[test]
    fn detection_failure_keys_reach_a_panel_case() {
        const CHROME_JS: &str = include_str!("chrome/chrome.js");
        for key in [
            "translate-script-mismatch",
            "translate-source-unknown",
            "translate-pair-unavailable",
            "translate-busy",
        ] {
            assert_eq!(translation_failure_key(key), key, "{key} must survive the allowlist");
            assert!(
                CHROME_JS.contains(&format!("case \"{key}\":")),
                "{key} has no panel case; it would render the generic failure"
            );
        }
    }

    /// THE LINE THAT ENFORCES "NEVER AUTOMATIC".
    ///
    /// The extractor lives in a hostile page's own JS context, so the page can
    /// call it whenever it likes -- pretending otherwise would be theatre.
    /// What stops unprompted text being accepted is not the UI, which a page
    /// cannot reach, but this refusal.
    #[test]
    fn text_from_a_page_with_no_session_is_refused() {
        let page = "https://example.com/a";
        assert!(!extract_is_acceptable(None, page, "extract", page));
    }

    /// THE BUG THE ENGINE PROBE CAUGHT, pinned so it cannot come back.
    ///
    /// `js_string` must produce a JavaScript STRING LITERAL. An earlier version
    /// escaped without quoting, so the call site read
    /// `translate({"id":"1",...})` -- an object literal. The document's
    /// JSON.parse got an object and threw, and page text was sitting in source
    /// position rather than data position, which is the thing this function
    /// exists to prevent.
    #[test]
    fn a_payload_becomes_a_quoted_string_literal_not_an_object() {
        let payload = r#"{"id":"1","texts":["hi"]}"#;
        let out = js_string(payload);
        assert!(out.starts_with('"'), "must be quoted: {out}");
        assert!(out.ends_with('"'), "must be quoted: {out}");
        // What the engine will see after JSON.parse: the original payload.
        assert_eq!(serde_json::from_str::<String>(&out).unwrap(), payload);
    }

    /// Page text is hostile input and rides through this function. Each of
    /// these is a character that ends a string, ends a statement, or opens a
    /// comment if it survives unescaped into source position.
    #[test]
    fn hostile_page_text_cannot_escape_the_literal() {
        for hostile in [
            r#"");alert(1);(""#,
            "\\\\\"",
            "</script>",
            "\n\r\t",
            "\u{2028}break\u{2029}",
            "\0",
            "`${process}`",
        ] {
            let payload = serde_json::json!({ "texts": [hostile] }).to_string();
            let out = js_string(&payload);
            // It survives as DATA: parsing the literal returns exactly the
            // payload, so nothing was lost and nothing was added.
            assert_eq!(
                serde_json::from_str::<String>(&out).unwrap(),
                payload,
                "round trip failed for {hostile:?}"
            );
            // And the two characters JSON permits raw but older JS did not
            // never appear literally in the emitted source.
            assert!(!out.contains('\u{2028}'), "raw U+2028 emitted");
            assert!(!out.contains('\u{2029}'), "raw U+2029 emitted");
        }
    }

    /// A document may only report a failure this product can render. Anything
    /// else becomes a generic one rather than a blank line in the panel.
    #[test]
    fn an_unknown_failure_key_degrades_to_a_renderable_one() {
        assert_eq!(
            translation_failure_key("translate-pack-failed"),
            "translate-pack-failed"
        );
        // Every key langpack can produce must survive the allowlist, or a
        // real failure would render as a generic one.
        for e in [
            crate::langpack::PackError::Unreachable("network"),
            crate::langpack::PackError::Manifest,
            crate::langpack::PackError::Body,
            crate::langpack::PackError::Malformed,
            crate::langpack::PackError::Storage,
        ] {
            assert_eq!(
                translation_failure_key(e.key()),
                e.key(),
                "{e:?} must survive the allowlist"
            );
        }
        for unknown in ["", "something-else", "<script>", "translate-"] {
            assert_eq!(translation_failure_key(unknown), "translate-failed");
        }
    }

    /// A late reply from a CANCELLED run must not be filed against the run
    /// that replaced it. Same page, same URL, same everything the URL check
    /// looks at -- only the token tells them apart.
    #[test]
    fn a_stale_run_cannot_be_filed_against_the_run_that_replaced_it() {
        assert!(extract_token_matches(Some(7), Some("7")));
        assert!(!extract_token_matches(Some(8), Some("7")));
        // No session at all: nobody asked, so nothing is acceptable.
        assert!(!extract_token_matches(None, Some("7")));
        // A message that names no run.
        assert!(!extract_token_matches(Some(7), None));
    }

    /// The token is compared as a string and never parsed, so there is no
    /// leniency to exploit. Every one of these is a value that a parse-then-
    /// compare would have had to make a judgement about.
    #[test]
    fn the_token_is_matched_exactly_not_parsed() {
        for hostile in ["07", " 7", "7 ", "+7", "7.0", "0x7", "7\0", "", "7a"] {
            assert!(
                !extract_token_matches(Some(7), Some(hostile)),
                "must refuse {hostile:?}"
            );
        }
    }

    /// The page supplies `href`. It does not supply the session's page or the
    /// tab's URL, which is precisely why it is checked against those two.
    #[test]
    fn a_page_cannot_lie_about_which_page_it_is() {
        let consented = "https://example.com/article";
        assert!(extract_is_acceptable(
            Some(consented),
            consented,
            "extract",
            consented
        ));
        // Claims to be the consented page while the tab is elsewhere.
        assert!(!extract_is_acceptable(
            Some(consented),
            "https://example.com/other",
            "extract",
            consented
        ));
        // Tab is on the consented page, but the message claims another.
        assert!(!extract_is_acceptable(
            Some(consented),
            consented,
            "extract",
            "https://evil.example/x"
        ));
    }

    /// One shape, and only one. Anything else is dropped rather than
    /// interpreted -- a message path that grows shapes by accident is how a
    /// page ends up talking to something that was never meant to hear it.
    #[test]
    fn only_the_extract_shape_is_accepted() {
        let p = "https://example.com/a";
        for kind in ["", "fill_credential", "Extract", "extract ", "login_submit"] {
            assert!(
                !extract_is_acceptable(Some(p), p, kind, p),
                "must refuse kind {kind:?}"
            );
        }
        assert!(extract_is_acceptable(Some(p), p, "extract", p));
    }

    /// The gap this closes. Consent attaches to the PAGE the user was reading
    /// when they clicked, and the explicit clear in `on_url_changed` is a line
    /// of code nothing in this suite can verify still exists -- `Tab` owns a
    /// live `WebView`, so no unit test can build one to drive a navigation.
    ///
    /// So correctness does not rest on that line. A session records the URL it
    /// was given for, and a session whose page is not what the tab now shows
    /// is treated as absent. Deleting the clear leaks memory; it does not
    /// translate a page nobody asked about.

    #[test]
    fn a_session_does_not_survive_the_page_it_was_given_for() {
        let consented = "https://example.com/article";
        assert!(session_is_current(consented, consented));
        for moved_to in [
            "https://example.com/other",
            "https://example.com/article/",
            "https://evil.example/article",
            "https://example.com/article?utm=1",
            "about:blank",
            "",
        ] {
            assert!(
                !session_is_current(consented, moved_to),
                "a session for {consented} must not apply on {moved_to}"
            );
        }
    }

    /// An empty recorded page must never match, or a session constructed
    /// before a URL was known would apply to every page at once.
    #[test]
    fn an_empty_recorded_page_matches_nothing() {
        assert!(!session_is_current("", ""));
        assert!(!session_is_current("", "https://example.com/"));
    }

    // NOT TESTED, deliberately: that a validated pair is 'static and not the
    // caller's slice. The signature `-> Option<&'static str>` already makes it
    // impossible to return a borrow of the argument, so a test can only assert
    // an implementation detail. The first version of this test compared
    // pointers and failed on const inlining -- an accurate report about the
    // compiler and nothing at all about safety.

    /// The privileged UI and the translator origin are not pages a user asked
    /// to read in another language. The origin split already makes pointing
    /// the machinery at chrome impossible by construction; this makes it
    /// impossible by policy as well, which is the half that survives someone
    /// changing the construction.
    #[test]
    fn our_own_origins_are_never_translatable() {
        assert!(!is_translatable_url(platform::CHROME_URL));
        assert!(!is_translatable_url(platform::TRANSLATE_URL));
        for internal in [
            "about:blank",
            "data:text/html,<b>x</b>",
            "file:///etc/passwd",
            "",
        ] {
            assert!(!is_translatable_url(internal), "{internal}");
        }
    }

    /// Case must not be a way around the origin check.
    #[test]
    fn the_origin_check_is_case_insensitive() {
        let shouty = platform::CHROME_URL.to_ascii_uppercase();
        assert!(
            !is_translatable_url(&shouty),
            "uppercasing must not smuggle the chrome origin past the check: {shouty}"
        );
    }

    /// Ordinary web pages are translatable; that is the point.
    #[test]
    fn real_pages_are_translatable() {
        for page in [
            "https://example.com/article",
            "http://example.com/",
            "https://example.com/a?b=c#d",
        ] {
            assert!(is_translatable_url(page), "{page}");
        }
    }
    /// Every event the host PUSHES must have a listener on the page.
    ///
    /// THIS HAS NOW GONE WRONG TWICE, and both times a person found it by
    /// staring at a screen. `tab_status` was emitted and handled by nothing,
    /// freezing every per-tab indicator -- including the TLS-interception
    /// banner, which could therefore never appear. Then `packs_status` was
    /// emitted on every download progress tick and handled by nothing, so the
    /// packs panel showed a percentage that never moved and rendered a FAILED
    /// download identically to a running one.
    ///
    /// Neither was a hard failure: the host did its half correctly and the
    /// page simply never heard. That is precisely the shape a test catches
    /// and review does not, so an emitted event with no `case` is now a
    /// failing test rather than a bug report.
    ///
    /// The needle is built at run time; spelling it literally would make this
    /// scan match its own source.
    /// Every kind the page-side script posts must be routed on Windows.
    ///
    /// The Windows backend shares one WebMessageReceived stream across
    /// autofill, probes and translation, and tells translation messages apart
    /// by an ALLOWLIST of kinds. That allowlist was written when the script
    /// posted two kinds and never revisited: "detected" was added to the
    /// script, flowed on WebKitGTK (whose channel forwards everything), and
    /// was silently dropped on Windows -- so language detection, its panel
    /// hint, and translate-as-you-browse all shipped dead on the platform
    /// most users run, while every test on the other backend passed. The
    /// list is now derived from what the script actually posts.
    #[test]
    fn every_kind_the_translate_script_posts_is_routed_on_windows() {
        const SCRIPT: &str = include_str!("content_scripts/translate_extract.js");
        const WINDOWS_RS: &str = include_str!("platform/windows.rs");
        let mut kinds = Vec::new();
        let needle = "kind: \"";
        for (at, _) in SCRIPT.match_indices(needle) {
            let rest = &SCRIPT[at + needle.len()..];
            let end = rest.find('"').expect("unterminated kind");
            let kind = &rest[..end];
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        assert!(
            kinds.len() >= 3,
            "found only {kinds:?} -- the scan itself broke"
        );
        for kind in kinds {
            assert!(
                WINDOWS_RS.contains(&format!("kind == \"{kind}\"")),
                "the content script posts kind {kind:?} and the Windows \
                 message router never mentions it: on WebView2 that message \
                 is dropped before the host sees it, while WebKitGTK forwards \
                 it -- the exact platform split that shipped language \
                 detection dead on Windows"
            );
        }
    }

    /// The stall deadline's key must survive the mapper and reach copy.
    ///
    /// `translation_failure_key` funnels unknown keys to a generic case, so a
    /// key added on the Rust side and forgotten in the mapper silently loses
    /// its specific message -- the timeout would render as plain "failed",
    /// which tells a user nothing about what to do differently.
    #[test]
    fn the_timeout_key_survives_the_mapper_and_reaches_a_panel_case() {
        assert_eq!(translation_failure_key("translate-timeout"), "translate-timeout");
        const CHROME_JS: &str = include_str!("chrome/chrome.js");
        assert!(
            CHROME_JS.contains("case \"translate-timeout\":"),
            "the timeout produces a key the panel has no case for"
        );
    }

    /// The three coordinate systems, pinned.
    ///
    /// A mixed page filters nodes out, so engine index != batch index !=
    /// document index. Getting this wrong puts a correct translation on the
    /// WRONG paragraph, which reads as the model having produced nonsense --
    /// far harder to diagnose than a plain failure, and the reason the
    /// arithmetic is a tested function rather than an inline expression.
    /// ONE precision reaches the engine, for every pack.
    ///
    /// The two-path version inferred precision from a pack's SOURCE, and the
    /// OPUS-MT branch selected a path that computes correctly on WebKitGTK and
    /// wrongly on WebView2 -- so every converted language shipped word salad
    /// to the platform most users run, while the Mozilla languages beside them
    /// were fine. The split was invisible on the machine that built it.
    ///
    /// Precision is not something to infer from provenance. If a pack ever
    /// genuinely needs a different one, it records that itself.
    /// The engine REPORTS its heap, so a heap claim can be measured.
    ///
    /// A previous version of this test asserted the heap must exceed twice
    /// the largest pack plus the workspace, and the code raised it to 1.5 GiB
    /// to satisfy that. The premise was wrong: the same converted pack
    /// translates correctly at the original 223 MiB, so nothing was ever
    /// starved. Asserting a number derived from a disproven model of the
    /// engine would pin a fiction -- and would have blocked putting the heap
    /// back.
    ///
    /// What IS worth pinning is the instrument: status() must keep reporting
    /// `heapBytes`, so the next person with a memory theory can read the

    #[test]
    fn the_engine_is_asked_for_one_precision_and_it_is_the_portable_one() {
        const STATE_RS: &str = include_str!("state.rs");
        let asked = STATE_RS.matches("let gemm = \"int8shiftAll\";").count();
        assert_eq!(asked, 1, "the GEMM path should be chosen in exactly one place");
        // The alphas path must not be selectable from product code again
        // without this test being revisited. The probe may still force it --
        // comparing the two is how this was found -- so only THIS file counts.
        assert!(
            !STATE_RS.contains("\"int8shiftAlphaAll\""),
            "state.rs selects int8shiftAlphaAll again: it is measurably wrong \
             on WebView2, which is the platform most users run"
        );
    }

    #[test]
    fn a_patch_lands_on_the_node_its_text_came_from() {
        // Batch of 6 at document offset 100; nodes 1, 3 and 4 survived the
        // filter, so the engine was sent 3 items numbered 0,1,2.
        let map = vec![1usize, 3, 4];
        assert_eq!(patch_index(0, &map, 100), Some(101));
        assert_eq!(patch_index(1, &map, 100), Some(103));
        assert_eq!(patch_index(2, &map, 100), Some(104));
        // An index the engine invented is dropped, not clamped.
        assert_eq!(patch_index(3, &map, 100), None);
        assert_eq!(patch_index(usize::MAX, &map, 100), None);
        // Unfiltered batches are the identity case and must be unaffected.
        let all: Vec<usize> = (0..5).collect();
        for i in 0..5 {
            assert_eq!(patch_index(i, &all, 0), Some(i as u64));
            assert_eq!(patch_index(i, &all, 42), Some(i as u64 + 42));
        }
        // An empty map names nothing.
        assert_eq!(patch_index(0, &[], 0), None);
    }

    #[test]
    fn every_emitted_event_reaches_a_dispatcher_case() {
        const STATE_RS: &str = include_str!("state.rs");
        const CHROME_JS: &str = include_str!("chrome/chrome.js");
        let needle = format!(".{}(\"", "emit");
        let mut checked = 0;
        for (at, _) in STATE_RS.match_indices(&needle) {
            let rest = &STATE_RS[at + needle.len()..];
            let end = rest.find('"').expect("unterminated event name");
            let event = &rest[..end];
            assert!(
                CHROME_JS.contains(&format!("case \"{event}\":")),
                "state.rs emits {event:?}, and chrome.js has no `case \"{event}\":` \
                 for it. The event is pushed into nothing and whatever it was \
                 meant to update stays frozen at its last value."
            );
            checked += 1;
        }
        assert!(
            checked >= 10,
            "scanned only {checked} emit sites -- the scan itself broke, and a \
             scan that finds nothing passes vacuously"
        );
    }

}
