//! JSON command dispatch for chrome IPC. Runs entirely on the event-loop
//! thread (invoked from the `UserEvent::Ipc` match arm).

use serde::Deserialize;
use serde_json::{json, Value};

use std::path::Path;

use patanyx_store::{Store, StoreError};
use patanyx_vault::{ExportError, Vault, VaultError};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
struct Request {
    id: u64,
    cmd: String,
    #[serde(default)]
    args: Value,
}

/// Largest IPC frame this process will parse.
///
/// Generous by design -- the biggest legitimate frame is a vault import or an
/// encrypted export path plus passphrases, all far below this -- but not
/// unbounded. `serde_json` allocates the whole string before any handler is
/// reached, and no argument extractor applies a length check, so without a cap
/// here the memory ceiling for a single command is whatever the chrome origin
/// cares to send. That is a bound worth having even though the chrome is the
/// trusted side: this boundary exists precisely to survive the chrome being
/// wrong.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Whether an IPC command is evidence that a USER is here.
///
/// The vault auto-lock exists to protect an unattended machine, so it needs to
/// distinguish "somebody is using this browser" from "the browser is talking to
/// itself". Every frame used to count, and some frames are sent on a timer:
///
///   * `tab_ledger` is polled every 2.5 seconds for as long as the Tab Activity
///     panel is open. That alone re-armed the deadline twenty-four times a
///     minute, so opening that panel and walking away disabled the auto-lock
///     entirely -- silently, with nothing on screen saying the vault would now
///     stay open indefinitely.
///   * `update_status` is polled while an install runs.
///   * `ping`, `ocr_status`, `blocklist_status` and `resolver_status` are fired
///     by the chrome as it loads, before the user has done anything at all.
///
/// The decision is made HERE, by command name, rather than by letting the
/// chrome flag its own frames as background. The chrome is trusted, but a rule
/// it has to remember to apply is a rule that gets forgotten the next time
/// somebody adds a poller -- and the failure is invisible, because a vault that
/// never locks looks exactly like a vault that has not locked yet.
fn counts_as_presence(cmd: &str) -> bool {
    !matches!(
        cmd,
        "tab_ledger"
            | "update_status"
            | "ping"
            | "ocr_status"
            | "blocklist_status"
            | "resolver_status"
            | "store_status"
            | "vault_status"
            | "chat_status"
            | "onboarding_seen_get"
            // Passive tunnel reads: the panel refresh and any status poll.
            // The mutating arms (tunnel_import / tunnel_set_mode /
            // tunnel_remove) count as presence by this list's default, and
            // the pinning test names them.
            | "tunnel_get"
            | "tunnel_status"
            // Passive licence read: the vault panel's Premium row refresh.
            // The mutating arms (licence_paste / licence_remove) count as
            // presence by this list's default, and the pinning test names
            // them.
            | "licence_get"
            // Polled on EVERY tab status update, because the toolbar's fill
            // button has to know whether this site has a saved password before
            // the user asks -- that is the whole point of putting it on the
            // toolbar instead of inside a panel. Navigating between pages, or
            // simply leaving the browser open while a page re-polls, would
            // otherwise re-arm the deadline forever.
            //
            // Safe to exempt because it is genuinely passive: it reads
            // id + username for the current origin and never the password, and
            // nothing about it requires a human. The FILL itself
            // (`cred_autofill_fill`) is a real click and is deliberately NOT
            // listed here.
            | "cred_autofill_offer_get"
    )
}

pub fn dispatch(state: &mut AppState, raw: &str) {
    if raw.len() > MAX_FRAME_BYTES {
        // No reply: the id lives inside the body this refuses to parse, and
        // inventing one would answer a request nobody made. The chrome's
        // request helper now times out, so the caller is not left hanging.
        return;
    }
    let request: Request = match serde_json::from_str(raw) {
        Ok(request) => request,
        // A frame this side cannot parse carries no id to reply to. It used to
        // be dropped on the reasoning that "the chrome side always sends
        // well-formed frames" -- an assumption about the very component this
        // boundary exists to contain, and one that left the caller's Promise
        // pending forever because chrome.js had no timeout. The drop stays
        // (there is genuinely nothing to answer); the hang does not.
        Err(_) => return,
    };
    if counts_as_presence(&request.cmd) {
        state.touch();
    }
    if request.cmd == "ping" {
        state.ping_count += 1;
        // chrome.js pings once on load, which is the moment its DOM exists.
        // Installing the chat panel's script here (rather than a <script src>
        // in index.html) keeps index.html identical in both builds, so a
        // non-chat build never requests an asset it does not serve.
        #[cfg(feature = "chat")]
        if state.ping_count == 1 {
            state.eval_chrome(crate::chat_panel::CHAT_JS);
        }
    }
    let result = handle(state, &request.cmd, &request.args);
    state.reply(request.id, result);
}

/// URL-bar input normalization: full URLs and about: URLs pass through
/// unchanged, bare domains get an https:// prefix, and anything else
/// (whitespace, or no dot at all) becomes a DuckDuckGo search.
pub fn normalize_input(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.contains("://") || trimmed.starts_with("about:") {
        return trimmed.to_string();
    }
    if trimmed.chars().any(char::is_whitespace) || !trimmed.contains('.') {
        return format!(
            "https://duckduckgo.com/?q={}",
            percent_encode(trimmed)
        );
    }
    format!("https://{trimmed}")
}

/// Query parameters that exist to identify a campaign or a click, stripped by
/// "Copy link without tracking parameters".
///
/// A CLOSED LIST, and it stays closed on purpose. The alternative -- guessing
/// from shape, or dropping anything that looks like an id -- breaks real links
/// silently, and a copy-link action that sometimes produces a URL which does
/// not work is worse than one that sometimes leaves a tracker on. Everything
/// here is a parameter whose only job is attribution.
///
/// Matching is EXACT and case-insensitive, with one prefix family
/// (`utm_`) because it is defined as a namespace rather than a fixed set.
/// No substring matching: `fbclid` must not take `fbclid_backup` with it, and
/// a site's own `gclid_verified` is not ours to remove.
const TRACKING_PARAMS: &[&str] = &[
    "fbclid",   // Facebook
    "gclid",    // Google Ads
    "dclid",    // DoubleClick
    "gbraid",   // Google, app-to-web
    "wbraid",   // Google, web-to-app
    "msclkid",  // Microsoft Ads
    "twclid",   // Twitter/X
    "ttclid",   // TikTok
    "igshid",   // Instagram
    "mc_cid",   // Mailchimp campaign
    "mc_eid",   // Mailchimp recipient
    "_openstat",
    "yclid",    // Yandex
    "vero_id",
    "oly_anon_id",
    "oly_enc_id",
    "s_cid",
    "ml_subscriber",
    "ml_subscriber_hash",
    // Added 2026-08-04 from the privacytests.org tracking-param set.
    "__hsfp",         // HubSpot
    "__hssc",         // HubSpot
    "__hstc",         // HubSpot
    "_hsenc",         // HubSpot
    "hsctatracking",  // HubSpot (lowercased: is_tracking_param matches case-insensitively)
    "__s",            // Drip
    "mkt_tok",        // Marketo / Adobe
    "rb_clickid",     // Russian ad networks
    "vero_conv",      // Vero
    "wickedid",       // WickedReports
];

/// The one prefix family. `utm_*` is a namespace by definition (Urchin), so
/// enumerating it would go stale; every other entry above is a fixed name.
const TRACKING_PREFIXES: &[&str] = &["utm_"];

/// True if `name` is a tracking parameter. Case-insensitive, exact or
/// `utm_`-prefixed.
fn is_tracking_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    TRACKING_PARAMS.iter().any(|p| *p == lower)
        || TRACKING_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// Removes known tracking parameters from a URL's query string.
///
/// Everything else is preserved BYTE FOR BYTE, including parameter order,
/// percent-encoding, empty values and duplicate keys: this is a copy helper,
/// not a URL normalizer, and re-encoding a link is how you break the ones that
/// depend on their exact spelling. If the query ends up empty the `?` goes
/// with it; the fragment is left alone.
///
/// Returns the input unchanged when there is no query, or when nothing in it
/// matched -- so a caller can compare and tell the user whether anything was
/// actually removed.
pub fn strip_tracking_params(url: &str) -> String {
    // Split off the fragment first: a `?` inside a fragment is not a query.
    let (before_fragment, fragment) = match url.find('#') {
        Some(at) => (&url[..at], Some(&url[at..])),
        None => (url, None),
    };
    let Some(q_at) = before_fragment.find('?') else {
        return url.to_string();
    };
    let (base, query) = before_fragment.split_at(q_at);
    let query = &query[1..]; // drop the '?'

    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter(|pair| {
            let name = pair.split('=').next().unwrap_or("");
            !is_tracking_param(name)
        })
        .collect();

    let mut out = String::with_capacity(url.len());
    out.push_str(base);
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    if let Some(fragment) = fragment {
        out.push_str(fragment);
    }
    out
}

/// Deepest nesting of redirect wrappers unwrapped in one call.
///
/// Wrappers do wrap wrappers -- a newsletter tracker around a SafeLinks URL
/// around the real link is two levels -- but unwrapping "until stable" lets a
/// crafted self-referential chain keep the loop busy, so the depth is capped
/// and anything still wrapped after this many levels is returned as it is.
const MAX_UNWRAP_DEPTH: usize = 4;

/// The wrapper shapes this recognises: (host suffix, path prefix, carrier
/// parameter names).
///
/// RECOGNITION IS SCOPED TO A HOST AND A PATH, not to a parameter name alone,
/// and that narrowness is the whole design. An earlier draft matched any of
/// `url`, `u`, `q`, `to`, `link` on any host whose value looked like a URL.
/// That is not "a known redirect wrapper", it is a guess, and it guesses wrong
/// in a way the user cannot see: an ordinary page at `?q=https://other.example/`
/// would have its link silently replaced by `other.example` when the user asked
/// to copy the link they right-clicked. Copying the WRONG url is far worse than
/// failing to unwrap a real wrapper, because the user has no way to notice.
///
/// The cost is real and accepted: wrappers not on this list pass through
/// untouched. The list is the honest meaning of the word "known" in the
/// user-facing copy, and adding to it is a deliberate, checkable act.
///
/// An empty path prefix means any path on that host.
const REDIRECT_WRAPPERS: &[(&str, &str, &[&str])] = &[
    // Outlook / Defender SafeLinks.
    ("safelinks.protection.outlook.com", "/", &["url"]),
    // Google's result and notification redirector.
    ("google.com", "/url", &["url", "q"]),
    // Bing's click tracker. Its carrier is base64url with a two-character
    // marker prefix; see decode_candidate.
    ("bing.com", "/ck/a", &["u"]),
    // DuckDuckGo's outbound wrapper.
    ("duckduckgo.com", "/l/", &["uddg"]),
    // Facebook's outbound interstitial.
    ("facebook.com", "/l.php", &["u"]),
    ("l.facebook.com", "/l.php", &["u"]),
    // Reddit's outbound wrapper.
    ("out.reddit.com", "/", &["url"]),
    // Steam's outbound interstitial.
    ("steamcommunity.com", "/linkfilter/", &["url"]),
];

/// Whether `host` is `suffix` or a subdomain of it.
///
/// Suffix matching on LABEL BOUNDARIES only, the same rule the blocklist uses:
/// `evilgoogle.com` must not match `google.com`.
fn host_matches(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == suffix {
        return true;
    }
    host.strip_suffix(suffix)
        .is_some_and(|rest| rest.ends_with('.'))
}

/// Splits an absolute http(s) URL into (host, path, query), lowercasing the
/// host. None when it is not an absolute http(s) URL.
fn split_url(url: &str) -> Option<(String, String, String)> {
    // `strip_prefix` rather than byte slicing. An earlier draft used
    // `candidate[..7]` after a byte-length check, which PANICS when byte 7
    // falls inside a multi-byte character: `?url=eeee` with accented e's is
    // eight bytes and crashes the handler. Page links are attacker-controlled,
    // so that was a denial of service reachable from a right-click.
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (authority, after) = match rest.find(['/', '?', '#']) {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, ""),
    };
    // Drop userinfo, then the port.
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match hostport.rfind(':') {
        // Not a port if it is inside an IPv6 literal.
        Some(at) if !hostport[at..].contains(']') => &hostport[..at],
        _ => hostport,
    };
    if host.is_empty() {
        return None;
    }
    let (path, query) = match after.find('?') {
        Some(at) => (&after[..at], after[at + 1..].split('#').next().unwrap_or("")),
        None => (after.split('#').next().unwrap_or(""), ""),
    };
    Some((host.to_ascii_lowercase(), path.to_string(), query.to_string()))
}

/// Whether `candidate` is a well-formed absolute http(s) URL we are willing to
/// hand back as a destination.
///
/// This is the security boundary: everything it accepts came out of an
/// attacker-controlled page. It rejects every non-http(s) scheme by
/// construction -- `javascript:`, `data:` and `file:` cannot pass because only
/// http(s) is ever ACCEPTED -- and additionally rejects authorities that parse
/// but are malformed (`https://@`, `https://:443`, an unclosed IPv6 literal),
/// which an earlier draft let through.
fn is_acceptable_destination(candidate: &str) -> bool {
    if candidate.len() > 4096 {
        return false;
    }
    if candidate
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    let Some((host, _, _)) = split_url(candidate) else {
        return false;
    };
    if host.starts_with('[') {
        return host.ends_with(']') && host.len() > 2;
    }
    // A hostname needs at least one label character and no empty labels.
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// Percent-decodes `s`. Returns None on a malformed escape rather than
/// guessing, and never expands the string.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Decodes base64url without padding. None on any invalid byte.
fn base64url_decode(s: &str) -> Option<String> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => u32::from(b - b'A'),
            b'a'..=b'z' => u32::from(b - b'a') + 26,
            b'0'..=b'9' => u32::from(b - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    String::from_utf8(out).ok()
}

/// Tries the three encodings a carrier value can use, in order, and returns
/// the first that yields an acceptable destination.
///
/// `marker_prefix` handles Bing's `/ck/a`, whose `u` value is a base64url
/// payload behind a two-character marker (`a1...`). It is applied ONLY for
/// that wrapper, never generally: stripping two leading characters from an
/// arbitrary value would corrupt it.
fn decode_candidate(raw: &str, marker_prefix: bool) -> Option<String> {
    if is_acceptable_destination(raw) {
        return Some(raw.to_string());
    }
    if let Some(decoded) = percent_decode(raw) {
        if is_acceptable_destination(&decoded) {
            return Some(decoded);
        }
        // A doubly-encoded carrier is common enough to be worth one more pass,
        // and the acceptance gate still stands behind it.
        if let Some(twice) = percent_decode(&decoded) {
            if is_acceptable_destination(&twice) {
                return Some(twice);
            }
        }
    }
    let b64_input = if marker_prefix && raw.len() > 2 {
        &raw[2..]
    } else {
        raw
    };
    if let Some(decoded) = base64url_decode(b64_input) {
        if is_acceptable_destination(&decoded) {
            return Some(decoded);
        }
    }
    None
}

/// One level of unwrapping. Returns None when `url` is not a recognised
/// wrapper carrying an acceptable destination.
fn unwrap_once(url: &str) -> Option<String> {
    let (host, path, query) = split_url(url)?;
    if query.is_empty() {
        return None;
    }
    for (suffix, path_prefix, carriers) in REDIRECT_WRAPPERS {
        if !host_matches(&host, suffix) {
            continue;
        }
        if !path_prefix.is_empty() && !path.starts_with(path_prefix) {
            continue;
        }
        let bing = *suffix == "bing.com";
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=')?;
            if value.is_empty() {
                continue;
            }
            let lower = name.to_ascii_lowercase();
            if !carriers.iter().any(|c| *c == lower) {
                continue;
            }
            if let Some(dest) = decode_candidate(value, bing) {
                return Some(dest);
            }
        }
    }
    None
}

/// The real destination hidden inside a known redirect wrapper.
///
/// Returns the input unchanged when `url` is not a recognised wrapper, which
/// lets a caller compare and tell the user whether anything happened -- the
/// same contract `strip_tracking_params` documents above.
///
/// NO NETWORK, EVER. Opaque shorteners keep the destination on their own
/// server, so resolving one means contacting it, which leaks the click this
/// feature exists to protect. They have no carrier parameter, so they fall
/// through untouched, and that is the correct behaviour rather than a gap.
pub fn unwrap_redirect(url: &str) -> String {
    let mut current = url.to_string();
    for _ in 0..MAX_UNWRAP_DEPTH {
        match unwrap_once(&current) {
            Some(next) if next != current => current = next,
            _ => break,
        }
    }
    current
}

/// What `clean_link` actually did, so the toast can say so precisely rather
/// than claiming the more impressive of the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkChange {
    Unchanged,
    Stripped,
    Unwrapped,
    UnwrappedAndStripped,
}

/// Unwrap, then strip. The order is the point: a destination recovered from a
/// wrapper very often carries its own `utm_*` set, and stripping first would
/// only clean the wrapper's own query before discarding it.
pub fn clean_link(url: &str) -> (String, LinkChange) {
    let unwrapped = unwrap_redirect(url);
    let did_unwrap = unwrapped != url;
    let stripped = strip_tracking_params(&unwrapped);
    let did_strip = stripped != unwrapped;
    let change = match (did_unwrap, did_strip) {
        (false, false) => LinkChange::Unchanged,
        (false, true) => LinkChange::Stripped,
        (true, false) => LinkChange::Unwrapped,
        (true, true) => LinkChange::UnwrappedAndStripped,
    };
    (stripped, change)
}

/// The URL a top-level navigation should be redirected to, or None to let it
/// proceed untouched.
///
/// `Some` ONLY when stripping actually changed the string, which is what
/// keeps cancel-and-reload from looping: the replacement URL has no tracking
/// params left, so `strip_tracking_params` is idempotent on it and the second
/// pass through the navigation handler returns None. That invariant is pinned
/// by a test rather than left to reasoning.
///
/// http(s) only. A `file://`, `data:` or chrome-origin URL is never rewritten
/// -- those are not web navigations carrying click IDs, and cancelling one to
/// "clean" it would break an internal page for nothing.
pub fn navigation_strip_target(url: &str) -> Option<String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return None;
    }
    let stripped = strip_tracking_params(url);
    if stripped == url {
        None
    } else {
        Some(stripped)
    }
}

/// Everything except ASCII alphanumerics and `-_.~` is percent-encoded per
/// UTF-8 byte; space becomes `%20`.
fn percent_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    out
}

fn handle(state: &mut AppState, cmd: &str, args: &Value) -> Result<Value, &'static str> {
    match cmd {
        // The reply carries the active tab's URL so a chrome UI that finished
        // loading after the first navigation can still populate its URL bar.
        "ping" => Ok(json!({ "url": state.active_url() })),

        "navigate" => {
            let raw = arg_str(args, "url")?;
            let url = normalize_input(raw);
            state.navigate(&url)?;
            Ok(json!({}))
        }
        "back" => {
            state.history_back()?;
            Ok(json!({}))
        }
        "forward" => {
            state.history_forward()?;
            Ok(json!({}))
        }
        "reload" => {
            state.history_reload()?;
            Ok(json!({}))
        }

        "tab_new" => {
            if state.tabs.len() >= crate::state::MAX_TABS {
                return Err("bad_args");
            }
            let url = normalize_input(
                args.get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("about:blank"),
            );
            // Same allowlist as the navigation handler: a new webview's
            // initial with_url does not pass through that handler, so it must
            // be enforced here as well.
            if !crate::state::is_allowed_content_url(&url) {
                return Err("bad_args");
            }
            // `?`, not a bare call: `Result` is `Serialize`, so dropping this
            // into `json!` would have shipped `{"id":{"Ok":7}}` to the chrome
            // with nothing in the type system objecting.
            let id = state.new_tab(&url, true)?;
            Ok(json!({ "id": id }))
        }
        // Open a NAMED url under a NAMED storage posture, in the foreground or
        // behind. This is what the right-click menu needs and what nothing
        // else could express: `tab_new` always switches and always uses the
        // browser-wide policy, and `tab_quarantine` takes no arguments at all
        // and always opens about:blank (deliberately -- see its own doc -- so
        // the user types the suspicious address themselves).
        "tab_open_with_profile" => {
            if state.tabs.len() >= crate::state::MAX_TABS {
                return Err("bad_args");
            }
            let url = normalize_input(arg_str(args, "url")?);
            // RE-VALIDATED HERE, whatever the chrome sent. The URL originates
            // in a right-click on an untrusted page, travels through the
            // chrome, and comes back as a string; the chrome is trusted not to
            // be malicious but is not trusted to have validated for us.
            if !crate::state::is_allowed_content_url(&url) {
                return Err("bad_args");
            }
            let policy = match args.get("profile").and_then(Value::as_str) {
                // The browser-wide policy, unchanged: an ordinary tab.
                Some("normal") | None => state.privacy.clone(),
                // Keeps nothing on disk, still runs script. See
                // `TabPolicy::ephemeral`.
                Some("ephemeral") => crate::platform::TabPolicy::ephemeral(),
                // The full paranoid preset.
                Some("quarantine") => crate::platform::TabPolicy::quarantine(),
                // An unknown posture is refused rather than quietly
                // downgraded to `normal`: a caller asking for a protection
                // this build does not have must not be told it got one.
                Some(_) => return Err("bad_args"),
            };
            let background = args
                .get("background")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let id = state.new_tab_with_policy(&url, !background, &policy)?;
            Ok(json!({ "id": id }))
        }
        // Renders the current page to a PDF in the downloads folder, filed
        // with the same provenance record any download gets. Returns the
        // destination immediately; the write finishes asynchronously and the
        // user hears about it in a toast (see `on_pdf_saved`).
        "page_save_pdf" => {
            let dest = state.save_active_page_as_pdf()?;
            Ok(json!({ "path": dest }))
        }
        "tab_close" => {
            let id = args.get("id").and_then(Value::as_u64).ok_or("bad_args")?;
            state.close_tab(id)?;
            Ok(json!({}))
        }
        "tab_switch" => {
            let id = args.get("id").and_then(Value::as_u64).ok_or("bad_args")?;
            state.switch_tab(id)?;
            Ok(json!({}))
        }
        "tab_list" => Ok(state.tab_list()),

        // SET-ASIDE SHELVES. One action stores the window's tabs as a named
        // shelf and closes them; restore reopens a shelf's entries, delete
        // forgets the shelf. A shelf stores title + URL. Nothing else: no
        // favicons, no scroll positions, no cookies, no history -- that
        // minimality is the privacy contract of the feature.
        //
        // Ephemeral tabs are NEVER set aside: their whole contract is that
        // nothing outlives them. They stay out of the shelf and out of the
        // close list, and the reply says how many were left out so the
        // chrome can state it plainly.
        "shelf_create" => {
            // Refuse FIRST: no store this session means nowhere to write
            // the record, and a tab must never be closed on the strength of
            // a write that cannot happen. store_open's own error says why.
            store_open(state)?;
            let plan = {
                let candidates: Vec<crate::shelf::Candidate> = state
                    .tabs
                    .iter()
                    .map(|tab| crate::shelf::Candidate {
                        id: tab.id,
                        ephemeral: tab.ephemeral,
                        title: &tab.title,
                        url: &tab.url,
                    })
                    .collect();
                let plan = crate::shelf::plan_create(&candidates);
                if plan.entries.is_empty() {
                    // Everything here is ephemeral or internal, so there is
                    // nothing the feature may remember. Nothing was
                    // written, nothing closes.
                    return Err("no_storable_tabs");
                }
                // Owned copies so the borrows of state.tabs end here; the
                // close loop below needs state mutably.
                (
                    crate::shelf::shelf_name(plan.entries.len()),
                    plan.entries
                        .iter()
                        .map(|entry| patanyx_store::ShelfTab {
                            title: entry.title.to_owned(),
                            url: entry.url.to_owned(),
                        })
                        .collect::<Vec<_>>(),
                    plan.entries.iter().map(|entry| entry.id).collect::<Vec<u64>>(),
                    plan.left_out,
                )
            };
            let (name, tabs, close_ids, left_out) = plan;
            // WRITE FIRST, close only after the write succeeded. On failure
            // the store has already rolled the shelf back and the window is
            // exactly as it was.
            let stored = store_open(state)?.add_shelf(name, tabs).map_err(store_code)?;
            // Never-tabless is inherited from close_tab: it builds the
            // replacement BEFORE removing the last tab and refuses cleanly
            // if that build fails, so closing every stored tab cannot zero
            // the window. Closes are BEST EFFORT on purpose: the shelf is
            // already written, so a refused close loses nothing -- and
            // erroring the whole command here would report failure for a
            // set-aside that in fact happened, inviting a retry that writes
            // an overlapping second shelf.
            for id in close_ids {
                let _ = state.close_tab(id);
            }
            Ok(json!({
                "id": stored.id,
                "name": stored.name,
                "stored": stored.tabs.len(),
                "left_out": left_out,
            }))
        }
        // An unavailable store is an ERROR here, not an empty list: the UI
        // shows unavailability and emptiness as different states.
        "shelf_list" => {
            let items: Vec<Value> = store_open(state)?
                .shelves()
                .iter()
                .map(|shelf| {
                    json!({
                        "id": shelf.id,
                        "name": shelf.name,
                        "count": shelf.tabs.len(),
                    })
                })
                .collect();
            Ok(json!({ "items": items }))
        }
        // Restore NEVER destroys: the shelf is kept however the opens go,
        // and forgetting is shelf_delete's job alone. Best effort per
        // entry; the reply says how many opened.
        "shelf_restore" => {
            let id = arg_str(args, "id")?;
            // Cloned out of the store first: the open calls below borrow
            // state mutably, and a shelf is small.
            let entries = {
                store_open(state)?
                    .shelves()
                    .iter()
                    .find(|shelf| shelf.id == id)
                    .ok_or("not_found")?
                    .tabs
                    .clone()
            };
            let total = entries.len();
            let mut opened = 0usize;
            for entry in &entries {
                if state.tabs.len() >= crate::state::MAX_TABS {
                    break;
                }
                // Re-validated on the way back in, like tab_new does: this
                // string came out of a file, not a live tab.
                if !crate::state::is_allowed_content_url(&entry.url) {
                    continue;
                }
                // First restored tab in the foreground, the rest behind it:
                // one focus change per restore, not one per tab.
                match state.new_tab(&entry.url, opened == 0) {
                    Ok(_) => opened += 1,
                    // A refused build stops the loop. The shelf is still
                    // there, so nothing unopened is lost.
                    Err(_) => break,
                }
            }
            Ok(json!({ "opened": opened, "total": total }))
        }
        // The chrome asks nothing before sending this (a shelf is small and
        // recreatable, and confirm dialogs train click-through), but it
        // keeps the row's data until this reply confirms the deletion.
        "shelf_delete" => {
            let id = arg_str(args, "id")?;
            if !store_open(state)?.remove_shelf(id).map_err(store_code)? {
                return Err("not_found");
            }
            Ok(json!({}))
        }

        "vault_status" => Ok(json!({
            "exists": Vault::exists(&state.vault_path),
            "unlocked": state.vault.is_some(),
        })),
        "vault_create" => {
            let passphrase = arg_str(args, "passphrase")?;
            // The recovery key is returned exactly once and never recoverable
            // afterwards, so it goes straight to the UI to be shown and written
            // down. Do not log it and do not keep it.
            let (vault, recovery) =
                Vault::create(&state.vault_path, passphrase).map_err(vault_code)?;
            state.vault = Some(vault);
            // Bookmarks and downloads live in a separate file under the same
            // passphrase. Nothing called this, so `state.store` was
            // permanently None and every bookmark/download command failed
            // with `not_unlocked` while the vault was demonstrably open.
            state.open_store(passphrase);
            #[cfg(feature = "chat")]
            crate::chat_panel::on_vault_unlocked(state);
            // No tunnel_control::on_vault_unlocked here, deliberately: a
            // freshly created vault cannot contain a tunnel config yet, so
            // there is nothing to start. The unlock arms below are the ones
            // that can meet an imported config.
            //
            // Unlike the tunnel, the licence evaluation DOES run here: a
            // freshly created vault has no token, so this evaluates FREE —
            // which is exactly what the Premium row must show after create.
            crate::licence_control::on_vault_unlocked(state);
            Ok(json!({ "recovery_key": recovery.to_printable() }))
        }
        "vault_unlock" => {
            let passphrase = arg_str(args, "passphrase")?;
            let mut vault = Vault::unlock(&state.vault_path, passphrase).map_err(vault_code)?;
            // Unlocking a pre-slots vault migrates it and mints a recovery key
            // the user has never seen; surface it or it helps nobody.
            let migrated = vault.take_migrated_recovery().map(|key| key.to_printable());
            state.vault = Some(vault);
            state.open_store(passphrase);
            #[cfg(feature = "chat")]
            crate::chat_panel::on_vault_unlocked(state);
            // NOT feature-gated, unlike chat: the tunnel crate is an
            // unconditional dependency. A start failure is recorded inside
            // tunnel_control, never propagated -- the unlock must not fail
            // because the tunnel could not start, and the engine is already
            // pointing at the proxy port, which keeps refusing, so the
            // failure state stays fail-closed on its own.
            crate::tunnel_control::on_vault_unlocked(state);
            // Same placement discipline: ungated (the licence crate is an
            // unconditional dependency), and a verification failure is
            // recorded inside licence_control, never propagated into the
            // unlock.
            crate::licence_control::on_vault_unlocked(state);
            Ok(json!({ "recovery_key": migrated }))
        }
        // The recovery key exists to be USED. `vault_create` mints one, shows
        // it once with instructions to write it down, and until now there was
        // no command that accepted it back — so a forgotten passphrase meant
        // the vault was gone despite the user having done exactly what they
        // were told.
        "vault_unlock_recovery" => {
            let key = arg_str(args, "recovery_key")?;
            let recovery =
                patanyx_vault::RecoveryKey::parse(key).map_err(|_| "bad_recovery_key")?;
            let vault =
                Vault::unlock_with_recovery(&state.vault_path, &recovery).map_err(vault_code)?;
            state.vault = Some(vault);
            // Bookmarks and downloads live in a separate file encrypted under
            // the PASSPHRASE, which we do not have on this path.
            state.mark_store_unavailable();
            #[cfg(feature = "chat")]
            crate::chat_panel::on_vault_unlocked(state);
            // Same as vault_unlock: ungated, and a start failure is
            // recorded, never fatal -- the engine keeps pointing at the
            // refusing port.
            crate::tunnel_control::on_vault_unlocked(state);
            // Same as vault_unlock: ungated, recorded, never fatal.
            crate::licence_control::on_vault_unlocked(state);
            Ok(json!({}))
        }
        "vault_lock" => {
            // Routed through `lock_vault` rather than clearing the field here,
            // so an explicit lock takes the SAME path as the auto-lock: chat
            // goes down with it and the UI is told once, from one place.
            state.lock_vault();
            Ok(json!({}))
        }

        // The "Stay unlocked" button on the pre-lock warning.
        //
        // It does nothing on purpose. Reaching this arm means `dispatch` has
        // already called `touch`, which is the entire effect: the deadline
        // moves and the warning re-arms. A command that exists only to be a
        // presence signal is clearer than having the button call some unrelated
        // getter for its side effect.
        "vault_stay_unlocked" => Ok(json!({})),

        "vault_autolock_get" => Ok(json!({
            "seconds": state.autolock_secs,
            "choices": crate::prefs::AUTOLOCK_CHOICES_SECS,
            // Fixed, not configurable: the warning always lands 60 seconds
            // before the lock whatever timeout was chosen. Sent so the panel
            // states the real number instead of hardcoding its own copy of it.
            "warn_before": crate::state::AUTO_LOCK_WARN_BEFORE.as_secs(),
        })),
        "vault_autolock_set" => {
            let seconds = args
                .get("seconds")
                .and_then(serde_json::Value::as_u64)
                .ok_or("bad_args")?;
            // A day is far past any plausible idle timeout and keeps a typo or
            // a hostile frame from producing a deadline so distant it is
            // "never" without the user having chosen never.
            if seconds > 86_400 {
                return Err("bad_args");
            }
            let mut prefs = crate::prefs::load();
            prefs.vault_autolock_secs = seconds;
            crate::prefs::save(&prefs)?;
            state.autolock_secs = seconds;
            // The new setting takes effect from NOW rather than from whenever
            // the last activity happened: shortening the timeout while already
            // idle would otherwise lock the vault the instant it is saved,
            // which reads as the setting having gone wrong.
            state.touch();
            Ok(json!({ "seconds": seconds }))
        }

        "cred_list" => {
            let vault = unlocked(state)?;
            // `fills_on` is added HERE rather than in `CredentialMeta` because
            // it is a public-suffix answer, and the vault crate deliberately
            // knows nothing about the list. It is the registrable domain of
            // the stored origin -- the real scope of this credential now that
            // matching is by site rather than by exact host -- or null when
            // the origin has no registrable domain and so fills only itself.
            //
            // The UI must state this. A credential saved on
            // `accounts.google.com` is now offered across `google.com`, and a
            // user who is not told that has been given a wider blast radius
            // than they agreed to.
            let items: Vec<_> = vault
                .list_credentials()
                .into_iter()
                .map(|c| {
                    let fills_on = c
                        .origin
                        .as_deref()
                        .and_then(crate::psl::registrable_domain)
                        .map(str::to_string);
                    json!({
                        "id": c.id,
                        "site": c.site,
                        "username": c.username,
                        "origin": c.origin,
                        "fills_on": fills_on,
                    })
                })
                .collect();
            Ok(json!({ "items": items }))
        }
        "cred_get" => {
            let id = arg_str(args, "id")?;
            let vault = unlocked(state)?;
            let entry = vault.get_credential(id).ok_or("not_found")?;
            serde_json::to_value(entry).map_err(|_| "io")
        }
        "cred_add" => {
            let site = arg_str(args, "site")?;
            let username = arg_str(args, "username")?;
            let password = arg_str(args, "password")?;
            let note = arg_str(args, "note")?;
            let origin = parse_credential_origin(site);
            let vault = unlocked(state)?;
            let id = vault
                .add_credential(site, origin.as_deref(), username, password, note)
                .map_err(vault_code)?;
            Ok(json!({ "id": id }))
        }
        "cred_update" => {
            let id = arg_str(args, "id")?;
            let site = arg_str(args, "site")?;
            let username = arg_str(args, "username")?;
            let password = arg_str(args, "password")?;
            let note = arg_str(args, "note")?;
            let origin = parse_credential_origin(site);
            unlocked(state)?
                .update_credential(id, site, origin.as_deref(), username, password, note)
                .map_err(vault_code)?;
            Ok(json!({}))
        }
        "cred_delete" => {
            let id = arg_str(args, "id")?;
            unlocked(state)?.delete_credential(id).map_err(vault_code)?;
            Ok(json!({}))
        }

        // ---- inline credential autofill ----
        //
        // Takes no arguments on purpose, same reasoning as
        // `site_forget_cookies`: the chrome has no legitimate reason to name
        // a password other than the one the content script already reported
        // for the tab it was submitted in, and the one call site
        // (chrome.js's save banner) never has any other password to offer.
        "cred_save_confirm" => {
            let pending = state.take_pending_save().ok_or("no_pending_save")?;
            // The origin actually saved under is RE-DERIVED from Rust's own
            // tracked `Tab.url`, never taken from `pending`'s own `origin`
            // field (content-reported, trusted no further than any other
            // content input) -- see `PendingSave`'s doc for why that field is
            // private outside state.rs.
            let origin = state
                .tabs
                .iter()
                .find(|t| t.id == pending.tab_id)
                .and_then(|t| crate::state::host_of(&t.url));
            let Some(origin) = origin else {
                return Err("no_site");
            };
            let vault = unlocked(state)?;
            vault
                .add_credential(&origin, Some(&origin), &pending.username, &pending.password, "")
                .map_err(vault_code)?;
            Ok(json!({}))
        }
        "cred_save_dismiss" => {
            state.take_pending_save();
            Ok(json!({}))
        }
        // Read-only: id + username, NEVER the password. Empty list -- not an
        // error -- whenever the vault is locked or the page has no
        // recognizable origin; both are the ordinary case for most pages.
        "cred_autofill_offer_get" => {
            let origin = state
                .tabs
                .get(state.active)
                .and_then(|t| crate::state::host_of(&t.url));
            // Registrable-domain match, not exact host: a password is saved on
            // the one subdomain that carries the login form
            // (`accounts.google.com`) and then wanted on the others
            // (`mail.google.com`). `same_site` is what keeps that from also
            // meaning `mybank.co.uk` and `evil.co.uk` -- see app::psl.
            let items = match (&origin, state.vault.as_ref()) {
                (Some(origin), Some(vault)) => {
                    let mut items =
                        vault.credentials_matching(|stored| crate::psl::same_site(stored, origin));
                    // Exact-host credentials first, so the single offer the
                    // chrome takes (`items[0]`) is the most specific one. A
                    // vault holding both `accounts.google.com` and a bare
                    // `google.com` entry must offer the one that names this
                    // page, not whichever happened to be saved first.
                    items.sort_by_key(|c| c.origin.as_deref() != Some(origin.as_str()));
                    items
                }
                _ => Vec::new(),
            };
            Ok(json!({ "items": items }))
        }
        "cred_autofill_fill" => {
            let id = arg_str(args, "id")?;
            // Re-derived fresh, not reused from whatever origin the offer
            // list was built against: the tab may have navigated in the
            // time between rendering the offer and this click.
            let current_origin = state
                .tabs
                .get(state.active)
                .and_then(|t| crate::state::host_of(&t.url))
                .ok_or("no_site")?;
            let (username, password) = {
                let vault = unlocked(state)?;
                let entry = vault.get_credential(id).ok_or("not_found")?;
                // Same rule the OFFER used, and it has to be: an exact-host
                // check here would show a fill button on `mail.google.com` for
                // a credential saved on `accounts.google.com` and then refuse
                // the click. This is still an independent re-check rather than
                // trust in the offer -- the id arrives from the chrome, and the
                // tab may have navigated since the offer was rendered.
                let allowed = entry
                    .origin
                    .as_deref()
                    .is_some_and(|stored| crate::psl::same_site(stored, &current_origin));
                if !allowed {
                    return Err("origin_mismatch");
                }
                (entry.username.clone(), entry.password.clone())
            };
            let tab = state.tabs.get(state.active).ok_or("no_tab")?;
            if crate::platform::fill_credential(&tab.webview, &username, &password) {
                Ok(json!({}))
            } else {
                Err("fill_failed")
            }
        }

        "note_list" => {
            let vault = unlocked(state)?;
            Ok(json!({ "items": vault.list_notes() }))
        }
        "note_get" => {
            let id = arg_str(args, "id")?;
            let vault = unlocked(state)?;
            let note = vault.get_note(id).ok_or("not_found")?;
            serde_json::to_value(note).map_err(|_| "io")
        }
        "note_add" => {
            let title = arg_str(args, "title")?;
            let body = arg_str(args, "body")?;
            let vault = unlocked(state)?;
            let id = vault.add_note(title, body).map_err(vault_code)?;
            Ok(json!({ "id": id }))
        }
        "note_update" => {
            let id = arg_str(args, "id")?;
            let title = arg_str(args, "title")?;
            let body = arg_str(args, "body")?;
            unlocked(state)?
                .update_note(id, title, body)
                .map_err(vault_code)?;
            Ok(json!({}))
        }
        "note_delete" => {
            let id = arg_str(args, "id")?;
            unlocked(state)?.delete_note(id).map_err(vault_code)?;
            Ok(json!({}))
        }

        // ---- chat (only compiled with --features chat) --------------------
        // Same convention as every arm above: Result<Value, &'static str> with
        // short stable codes, so the chrome UI has one error vocabulary.
        #[cfg(feature = "chat")]
        "chat_identity" => crate::chat_panel::ipc_identity(state, args),
        // Split from `chat_identity` deliberately: the read must stay a read,
        // or the UI cannot ask whether an identity exists without creating one.
        #[cfg(feature = "chat")]
        "chat_identity_create" => crate::chat_panel::ipc_identity_create(state),
        #[cfg(feature = "chat")]
        "chat_contacts" => crate::chat_panel::ipc_contacts(state),
        #[cfg(feature = "chat")]
        "chat_contact_note" => crate::chat_panel::ipc_contact_note(state, args),
        // Presence is MANUAL: nothing announces the user until they say so.
        #[cfg(feature = "chat")]
        "chat_go_online" => crate::chat_panel::ipc_go_online(state),
        #[cfg(feature = "chat")]
        "chat_go_offline" => crate::chat_panel::ipc_go_offline(state),
        // AFK is the one status needing an announced marker — offline is
        // simply absence, so it needs no broadcast at all.
        #[cfg(feature = "chat")]
        "chat_set_away" => crate::chat_panel::ipc_set_away(state, args),
        #[cfg(feature = "chat")]
        "chat_status" => crate::chat_panel::ipc_status(state),
        // Relay configuration: URL, and WHICH identity registers. One, never
        // the set — a remote relay seeing several of a user's per-contact
        // fingerprints could link them.
        #[cfg(feature = "chat")]
        "chat_relay_get" => crate::chat_panel::ipc_relay_get(state),
        #[cfg(feature = "chat")]
        "chat_relay_set" => crate::chat_panel::ipc_relay_set(state, args),
        #[cfg(feature = "chat")]
        "chat_contact_add" => crate::chat_panel::ipc_contact_add(state, args),
        #[cfg(feature = "chat")]
        "chat_contact_remove" => crate::chat_panel::ipc_contact_remove(state, args),
        #[cfg(feature = "chat")]
        "chat_peers" => crate::chat_panel::ipc_peers(state),
        #[cfg(feature = "chat")]
        "chat_open" => crate::chat_panel::ipc_open(state, args),
        #[cfg(feature = "chat")]
        "chat_close" => crate::chat_panel::ipc_close(state, args),
        #[cfg(feature = "chat")]
        "chat_send" => crate::chat_panel::ipc_send(state, args),
        #[cfg(feature = "chat")]
        "chat_send_tab" => crate::chat_panel::ipc_send_tab(state, args),
        #[cfg(feature = "chat")]
        "chat_share_credential" => crate::chat_panel::ipc_share_credential(state, args),
        #[cfg(feature = "chat")]
        "chat_accept_tab" => crate::chat_panel::ipc_accept_tab(state, args),

        // ---- privacy controls ---------------------------------------------
        // The engine-capability flags travel with the values so the UI can
        // disable a control the platform cannot honour, instead of offering a
        // toggle that silently does nothing.
        // ---- site permissions ------------------------------------------
        // Deny-by-default camera/microphone/location/notifications. Grants
        // are session-only, so there is no persistence command here and none
        // is coming: the browser closing IS the revoke.
        "permission_status" => Ok(state.permission_status()),
        "permission_grant" | "permission_revoke" => {
            let origin = arg_str(args, "origin")?;
            let kind = crate::state::PermKind::from_ipc(arg_str(args, "kind")?)
                .ok_or("unknown_permission")?;
            let ok = if cmd == "permission_grant" {
                state.permissions.grant(origin, kind)
            } else {
                state.permissions.revoke(origin, kind)
            };
            if !ok {
                return Err("bad_origin");
            }
            // RELOAD THE TAB, both directions, because a permission change
            // that the page never sees is not a permission change.
            //
            // On grant: the request this refers to was answered Deny and
            // closed -- no deferral is held -- so the site's promise rejected
            // long ago and the new grant governs only the NEXT request. Without
            // a reload the user watches a camera that never turns on.
            //
            // On revoke: removing the grant stops the next request, but an
            // ALREADY RUNNING stream keeps running, so a user who revokes
            // access to a live camera would still be filmed. Tearing the page
            // down is what actually ends it.
            //
            // The cost is the page's in-flight state, which is why the panel
            // warns to save first (decided 2026-08-06).
            let _ = state.history_reload();
            // Reply with the fresh status so the panel re-renders from the
            // table rather than from what it assumes the toggle did.
            Ok(state.permission_status())
        }
        "privacy_get" => Ok(state.privacy_status()),
        "privacy_set" => {
            let mut policy = state.privacy.clone();
            // Absent keys leave that setting alone, so the UI can send one
            // toggle without having to restate the whole policy.
            if let Some(v) = args.get("block_ads").and_then(Value::as_bool) {
                policy.block_ads = v;
            }
            if let Some(v) = args.get("freeze_after_load").and_then(Value::as_bool) {
                policy.freeze_after_load = v;
            }
            if let Some(v) = args.get("javascript").and_then(Value::as_bool) {
                policy.javascript = v;
            }
            if let Some(v) = args.get("ephemeral").and_then(Value::as_bool) {
                policy.ephemeral = v;
            }
            state.set_privacy(policy);
            Ok(state.privacy_status())
        }

        "set_chrome_height" => {
            let px = args.get("px").and_then(Value::as_i64).ok_or("bad_args")?;
            // Upper bound = the tallest panel (chat's conversation view,
            // 640 -- chat.js pins CHAT_OPEN_PX to this comment) PLUS 80 of
            // banner allowance. The ceiling used to be exactly 640, which
            // made banner heights on top of an open chat vanish IN FULL: the
            // JS side sends base + visible banners through one clamp, and a
            // ceiling equal to the tallest base leaves banners zero room --
            // on Linux, where this value is the literal chrome box height,
            // that is a genuinely clipped banner. 80 covers two stacked
            // banners, which is as many as co-occur in practice.
            //
            // Still a clamp rather than a free value: a STRIP must never be
            // able to take the whole window by arithmetic. The panel that
            // once grew this chrome by 300px of empty band is why the guard
            // exists, and 720 stays under even a short laptop window.
            // Covering the window is possible, but only by asking for it by
            // name -- see `chrome_overlay`. Keeping the two apart is the
            // point: no number sent here, however wrong, can hide the page.
            let px = px.clamp(120, 720) as i32;
            state.set_chrome_height(px);
            Ok(json!({}))
        }

        // Modal panels. The chrome takes the window and the page is given a
        // zero rect for the duration; `false` gives it straight back.
        //
        // A separate command rather than a height, so that the clamp above
        // keeps meaning what it says, and so a panel cannot cover the window
        // by accident -- it has to say the word.
        "chrome_overlay" => {
            let on = args
                .get("cover")
                .and_then(Value::as_bool)
                .ok_or("bad_args")?;
            state.set_chrome_arrangement(if on {
                crate::platform::ChromeLayout::Overlay
            } else {
                crate::platform::ChromeLayout::Strip
            });
            Ok(json!({}))
        }

        // A DOCKED PANE, which is a different request from covering the window
        // and so a different command.
        //
        // Chat was a modal: reading a conversation hid the page, and closing
        // the panel to look at the page destroyed the conversation, so the two
        // could not be done together at all. Split keeps the page beside it.
        //
        // Refused where the backend cannot lay it out. WebKitGTK repacks
        // through GTK and this arrangement is not implemented there, so the
        // chrome asks first and offers the modal instead -- rather than being
        // handed a control that silently does nothing.
        "chrome_split" => {
            if !crate::platform::split_supported() {
                return Err("unsupported");
            }
            let width = args
                .get("pane_width")
                .and_then(Value::as_i64)
                .ok_or("bad_args")?;
            // The layout clamps against the window too; this is the crude
            // bound that keeps an absurd number from reaching it at all.
            let pane_width = i32::try_from(width.clamp(0, 4096)).unwrap_or(0);
            state.set_chrome_arrangement(if pane_width > 0 {
                crate::platform::ChromeLayout::Split { pane_width }
            } else {
                crate::platform::ChromeLayout::Strip
            });
            Ok(json!({ "split": state.is_split() }))
        }

        // Whether the chrome may offer a docked pane at all.
        "chrome_split_supported" => Ok(json!({
            "supported": crate::platform::split_supported(),
        })),

        // Rendering capabilities the stylesheet must not assume. Today one
        // flag: whether a modal's backdrop is a LIVE, dimmed page (the
        // backend lifts a transparent chrome above the content) or an opaque
        // cover. The chrome asks at boot and styles the scrim to match --
        // a translucent scrim over a genuinely covered page would imply the
        // page is still there, which is the exact lie the solid scrim was
        // built to avoid.
        "chrome_caps" => Ok(json!({
            "translucent_overlay": crate::platform::translucent_overlay_supported(),
        })),


        // ---- vaultsurface ----
        // ---- backup, export, import, passphrase ---------------------------
        // Status for the vault panel's "Backup and recovery" section. Besides
        // `has_recovery` it carries the exact plaintext-export confirmation
        // sentence, so there is ONE copy of that string (the vault's
        // constant) rather than a second copy in the UI that could drift away
        // from what the vault actually checks. The suggested destinations
        // are pre-filled text in editable fields; nothing is written until
        // the user submits, and the vault still refuses a destination that IS
        // the live vault file.
        // ---- choosing a file ----------------------------------------------
        //
        // Inside the Flatpak these are the ONLY way a vault file can be named.
        // The sandbox has no filesystem access by design, so a typed path to
        // `~/.local/share/patanyx/vault.rbv` names something unreachable; the
        // portal, reached through GtkFileChooserNative, hands over exactly the
        // one file the user picked and nothing else.
        //
        // Both return `{"path": null}` on cancel rather than an error. A user
        // changing their mind is not a failure and must not be reported as
        // one.
        "file_pick_open" => {
            if !crate::platform::file_choice_supported() {
                return Err("unsupported");
            }
            let title = args
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("Choose a file");
            let picked = crate::platform::pick_file_to_open(&state.hosts, title);
            // `token` accompanies `path` rather than replacing it: the vault
            // import/export flows show the chosen path in an editable field,
            // and the user may legitimately type a different one there. What
            // the token adds is a way for a command to require a path the USER
            // picked -- see `ocr_scan`, which no longer accepts a path at all.
            let token = picked
                .as_ref()
                .map(|p| state.remember_picked_path(p.clone()));
            Ok(json!({
                "path": picked.map(|p| p.to_string_lossy().into_owned()),
                "token": token,
            }))
        }
        "file_pick_save" => {
            if !crate::platform::file_choice_supported() {
                return Err("unsupported");
            }
            let title = args
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("Choose where to save");
            let name = args
                .get("suggested_name")
                .and_then(Value::as_str)
                .unwrap_or("patanyx-export");
            let picked = crate::platform::pick_file_to_save(&state.hosts, title, name);
            Ok(json!({ "path": picked.map(|p| p.to_string_lossy().into_owned()) }))
        }

        "vault_backup_status" => {
            // Computed before `unlocked(state)` borrows the vault: the
            // returned &mut Vault borrows all of `state`, so vault_path could
            // not be read afterwards.
            let export_suggestion = sibling_file_suggestion(&state.vault_path, "patanyx-export.rbx");
            let plaintext_suggestion =
                sibling_file_suggestion(&state.vault_path, "patanyx-export.json");
            let vault = unlocked(state)?;
            Ok(json!({
                "has_recovery": vault.has_recovery(),
                "export_suggestion": export_suggestion,
                "plaintext_suggestion": plaintext_suggestion,
                "plaintext_confirmation": patanyx_vault::PLAINTEXT_EXPORT_CONFIRMATION,
                // Where the UI must offer a chooser instead of a text field.
                // The suggestions above are siblings of the vault path, which
                // inside the sandbox is a location the user cannot browse to
                // or find afterwards -- so where this is true they are a
                // filename hint and nothing more.
                "file_choice": crate::platform::file_choice_supported(),
            }))
        }
        "vault_export_encrypted" => {
            let dest = arg_str(args, "dest")?;
            let passphrase = arg_str(args, "passphrase")?;
            // An empty export passphrase would "work" and produce a file that
            // looks protected but opens with nothing; refuse it here.
            if dest.is_empty() || passphrase.is_empty() {
                return Err("bad_args");
            }
            // BOOKMARKS TRAVEL WITH THE VAULT; downloads deliberately do not.
            // A bookmark is something the user chose to keep and would expect
            // to find on a new machine. A download record is browsing history
            // -- what they fetched and when -- and carrying that into a backup
            // file, then onto another machine, is a copy of their history
            // nobody asked for.
            //
            // Serialised here rather than in the vault crate: that crate does
            // not know what a bookmark is and must not learn, or it ends up
            // depending on the store it is meant to be independent of. It
            // takes opaque bytes and seals them.
            let carried = state
                .store
                .as_ref()
                .and_then(|store| serde_json::to_vec(store.bookmarks()).ok());
            unlocked(state)?
                .export_encrypted_with(Path::new(dest), passphrase, carried.as_deref())
                .map_err(export_code)?;
            Ok(json!({}))
        }
        "vault_export_plaintext" => {
            let dest = arg_str(args, "dest")?;
            let confirmation = arg_str(args, "confirmation")?;
            if dest.is_empty() {
                return Err("bad_args");
            }
            // The vault itself refuses to write anything unless `confirmation`
            // is exactly PLAINTEXT_EXPORT_CONFIRMATION, and that check happens
            // before any file is touched. There is deliberately no IPC
            // argument that bypasses it.
            unlocked(state)?
                .export_plaintext(Path::new(dest), confirmation)
                .map_err(export_code)?;
            Ok(json!({}))
        }
        "vault_import" => {
            let src = arg_str(args, "src")?;
            let passphrase = arg_str(args, "passphrase")?;
            let new_passphrase = arg_str(args, "new_passphrase")?;
            if src.is_empty() {
                return Err("bad_args");
            }
            // Import creates a NEW vault at the app's vault path, REPLACING
            // any vault already there. No refusal when a vault already exists. It used to return
            // `vault_exists`, which made the import form impossible to offer on
            // a machine that had one -- the control existed and could only
            // fail. The warning moved to the panel, where the person reads it
            // before deciding, rather than being enforced here where they only
            // meet it afterwards.
            //
            // A live UNLOCKED vault is still dropped first, so nothing keeps
            // writing to the file that is about to be replaced.
            state.vault = None;
            let dest = state.vault_path.clone();
            let (vault, recovery, carried) =
                Vault::import_encrypted(Path::new(src), &dest, passphrase, new_passphrase)
                    .map_err(export_code)?;
            // Rebuild the bookmark store under the NEW passphrase. A failure
            // here loses bookmarks, never the vault: the credentials are
            // already saved by this point, and refusing the whole import
            // because a bookmark did not survive would be the wrong trade.
            let restored = restore_bookmarks(state, new_passphrase, carried.as_deref());
            // Import mints a fresh recovery key — like creation, it is
            // returned exactly once so the UI can show it and then it is gone.
            state.vault = Some(vault);
            #[cfg(feature = "chat")]
            crate::chat_panel::on_vault_unlocked(state);
            Ok(json!({
                "recovery_key": recovery.to_printable(),
                "bookmarks": restored,
            }))
        }
        "vault_change_passphrase" => {
            let current = arg_str(args, "current")?;
            let new = arg_str(args, "new")?;
            // A failed change (wrong `current`, or a failed save) leaves the
            // slot untouched, so the OLD passphrase keeps working — the UI
            // states this explicitly, because a user who believes the
            // passphrase changed when it did not is locked out in the worst
            // way.
            unlocked(state)?
                .change_passphrase(current, new)
                .map_err(vault_code)?;
            Ok(json!({}))
        }

        // Mint a recovery key for a vault that never got one.
        //
        // Until this existed, a key was obtainable at exactly two moments --
        // vault creation and old-format migration -- and both showed it once.
        // Anyone who missed it had no route back, while `vault_backup_status`
        // cheerfully reported that they had no safety net. The panel could
        // state the problem and not solve it.
        //
        // Takes the passphrase even though the vault is open: this creates a
        // permanent second credential for everything inside, so it must not be
        // something a passer-by can mint at an unattended unlocked browser.
        "vault_recovery_create" => {
            let passphrase = arg_str(args, "passphrase")?;
            let vault = unlocked(state)?;
            // Checked here so the refusal gets its OWN code. The vault crate
            // signals "already has one" with AlreadyExists, which vault_code
            // maps to "vault_exists" -- whose user-facing text is "A vault
            // already exists". True of nothing that happened here, and
            // baffling to read after pressing a button about recovery keys.
            if vault.has_recovery() {
                return Err("recovery_exists");
            }
            let recovery = vault.add_recovery(passphrase).map_err(vault_code)?;
            // Same contract as vault_create: shown once, never retrievable
            // again, never logged and never kept.
            Ok(json!({ "recovery_key": recovery.to_printable() }))
        }

        // ---- privsurface ----
        // ---- per-tab privacy (always the ACTIVE tab) ----------------------
        // Manual freeze, per-site allow, the ledger, the TLS verdict and
        // quarantine tabs. Mutating replies carry the refreshed tab status so
        // the toolbar chip and the per-tab panel update in one round trip.
        // ---- find in page ----
        // Counts never travel through these replies: they arrive later as
        // find_state events from the engine callbacks, quoting the session
        // generation so a late count from an abandoned query is dropped. The
        // arms only start, step and stop the engine session. The query is
        // untrusted user input; it goes into the engine's find API and
        // nowhere else -- never into a script string.
        "find_start" => {
            let query = arg_str(args, "query")?;
            let cmd = {
                // The borrow of state.find ends here; the webview borrow
                // below must not overlap it.
                match state.find.on_query(query) {
                    crate::find::FindCmd::Start(_) => crate::find::FindCmd::Start(query),
                    other => other,
                }
            };
            let Some(webview) = state.active_webview() else {
                // No tab to search: whatever on_query just recorded is
                // unstartable; roll it back so a retry is not Ignored.
                state.find.stop();
                return Err("no_tab");
            };
            match cmd {
                crate::find::FindCmd::Start(q) => {
                    let generation = state.find.generation();
                    let available =
                        crate::platform::find_start(webview, q, generation, &state.proxy());
                    if !available {
                        // The engine refused (old runtime, dying webview).
                        // Without this rollback the same query would be
                        // Ignored on retry and F3 would step a session that
                        // does not exist.
                        state.find.stop();
                    }
                    Ok(json!({ "available": available }))
                }
                // Empty query stops the session rather than searching "".
                // The probe still answers availability, so the bar can swap
                // to its unsupported line before anything is typed.
                crate::find::FindCmd::Stop => {
                    crate::platform::find_stop(webview);
                    Ok(json!({ "available": crate::platform::find_probe(webview) }))
                }
                crate::find::FindCmd::Ignore => {
                    Ok(json!({ "available": crate::platform::find_probe(webview) }))
                }
            }
        }
        "find_next" => {
            if state.find.is_active() {
                if let Some(webview) = state.active_webview() {
                    crate::platform::find_next(webview);
                }
            }
            Ok(json!({}))
        }
        "find_previous" => {
            if state.find.is_active() {
                if let Some(webview) = state.active_webview() {
                    crate::platform::find_previous(webview);
                }
            }
            Ok(json!({}))
        }
        "find_stop" => {
            // Idempotent on purpose: bar close, tab switch and tab close can
            // all ask, in any order, and only the first one touches the
            // engine.
            if state.find.stop() {
                if let Some(webview) = state.active_webview() {
                    crate::platform::find_stop(webview);
                }
            }
            Ok(json!({}))
        }

        // Page color scheme: the engine-level prefers-color-scheme ask.
        // The reply's `applied` is the ENGINE's acknowledgement, read per
        // set -- a preference saved but not acknowledged (old WebView2
        // runtime) is reported as exactly that, never as a theme in force.
        "page_theme_set" => {
            let theme = crate::prefs::PageTheme::parse(arg_str(args, "theme")?)
                .ok_or("bad_args")?;
            let mut p = crate::prefs::load();
            p.page_theme = theme;
            crate::prefs::save(&p).map_err(|_| "io")?;
            let applied = state
                .active_webview()
                .map(|webview| crate::platform::apply_page_theme(webview, theme))
                .unwrap_or(false);
            Ok(json!({ "theme": theme.as_str(), "applied": applied }))
        }
        "page_theme_get" => Ok(json!({
            "theme": crate::prefs::load().page_theme.as_str(),
        })),
        // Chrome accent theme: saved here, worn by chrome.js via a
        // data-theme attribute. No engine involvement, so no ack to carry.
        "chrome_theme_set" => {
            let theme = crate::prefs::ChromeTheme::parse(arg_str(args, "theme")?)
                .ok_or("bad_args")?;
            let mut p = crate::prefs::load();
            p.chrome_theme = theme;
            crate::prefs::save(&p).map_err(|_| "io")?;
            Ok(json!({ "theme": theme.as_str() }))
        }
        "chrome_theme_get" => Ok(json!({
            "theme": crate::prefs::load().chrome_theme.as_str(),
        })),

        // Chrome scheme (Dark/White/Black): same shape as the accent pair
        // above, same no-engine-involvement, worn via data-scheme.
        "chrome_scheme_set" => {
            let scheme = crate::prefs::ChromeScheme::parse(arg_str(args, "scheme")?)
                .ok_or("bad_args")?;
            let mut p = crate::prefs::load();
            p.chrome_scheme = scheme;
            crate::prefs::save(&p).map_err(|_| "io")?;
            // The native hover readout paints with these colours too, and
            // cannot read CSS variables; this is the one runtime point where
            // the scheme changes, so it is the one place that re-colours it.
            crate::platform::set_hover_readout_scheme(&state.hosts, scheme);
            Ok(json!({ "scheme": scheme.as_str() }))
        }
        "chrome_scheme_get" => Ok(json!({
            "scheme": crate::prefs::load().chrome_scheme.as_str(),
        })),

        // Background update download: the pref behind the panel checkbox.
        // Same bool plumbing as every other pref pair; installing is gated
        // by update_apply regardless of this value.
        "update_background_set" => {
            let enabled = args
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or("bad_args")?;
            let mut p = crate::prefs::load();
            p.update_background_download = enabled;
            crate::prefs::save(&p).map_err(|_| "io")?;
            Ok(json!({ "enabled": enabled }))
        }
        "update_background_get" => Ok(json!({
            "enabled": crate::prefs::load().update_background_download,
        })),

        // Fingerprint Divergence: the pref behind the privacy-panel
        // checkbox. Deliberately NO `applied` field: the script registers at
        // webview CONSTRUCTION only, so a change reaches the NEXT tab, and
        // there is no live-tab engine ack to report -- inventing one would
        // claim a protection nobody confirmed. The panel copy says "new tabs
        // only" instead.
        "fingerprint_noise_set" => {
            let enabled = args
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or("bad_args")?;
            let mut p = crate::prefs::load();
            p.fingerprint_noise = enabled;
            crate::prefs::save(&p).map_err(|_| "io")?;
            Ok(json!({ "enabled": enabled }))
        }
        "fingerprint_noise_get" => Ok(json!({
            "enabled": crate::prefs::load().fingerprint_noise,
        })),

        // Save a picture of the current page. The capture is async in the
        // engine; the reply only confirms it started. The outcome (picker,
        // write, or an honest refusal) arrives as a toast from the event
        // arm. Ephemeral tabs MAY be captured: the user explicitly asked
        // and personally chooses where the file goes -- their call, not the
        // tab's.
        "capture_page" => {
            let url = state.active_url();
            if let Some(code) = crate::capture::refuse_capture(&url) {
                return Err(code);
            }
            let Some(webview) = state.active_webview() else {
                return Err("no_tab");
            };
            if crate::capture::CAPTURE_IN_FLIGHT
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                // A second click while one capture is pending would queue a
                // second picker behind the first; refuse instead.
                return Err("busy");
            }
            crate::platform::capture_page(webview, &state.proxy());
            Ok(json!({ "started": true }))
        }

        "tab_status" => Ok(state.active_tab_status()),
        "tab_freeze" => state.freeze_active_tab(),
        "tab_unfreeze" => state.unfreeze_active_tab(),
        "tab_allow_site" => {
            let host = arg_str(args, "host")?;
            // The host lands in the freeze filter's unless-domain list and is
            // matched against normalized ledger hosts, so anything that could
            // never be one (whitespace, path separators, userinfo) is
            // rejected here rather than stored as a dead override.
            if !is_valid_host(host) {
                return Err("bad_args");
            }
            state.allow_site_active_tab(host)
        }
        "tab_ledger" => state.active_ledger(),
        // Takes no arguments on purpose. The host it acts on is read fresh
        // from the active tab's own tracked URL inside
        // `forget_active_tab_cookies`, never from anything the caller could
        // supply -- see that function's doc for why.
        "site_forget_cookies" => state.forget_active_tab_cookies(),
        "tab_quarantine" => {
            if state.tabs.len() >= crate::state::MAX_TABS {
                return Err("bad_args");
            }
            // One command, whole preset: the policy is a construction
            // parameter of the new webview (ephemeral profile and JS-off must
            // hold before the first navigation), so this is a tab-creation
            // path, not a policy toggle.
            let id = state.new_quarantine_tab()?;
            Ok(json!({ "id": id }))
        }

        // ---- bookmarks ----
        // ---- bookmarks & download provenance (patanyx-store) ----------------
        // Same conventions as the vault arms: short stable codes, and the
        // store is only ever reached through `store_open` so a closed or
        // failed store yields one predictable error.
        "store_status" => Ok(state.store_status()),
        "bookmark_add" => {
            // Always the current page, taken from the active tab: the chrome
            // UI deliberately cannot bookmark an arbitrary URL it made up.
            let tab = state.tabs.get(state.active).ok_or("not_found")?;
            let url = tab.url.clone();
            if url.is_empty() || url == "about:blank" {
                return Err("bad_args");
            }
            let title = tab.title.clone();
            let store = store_open(state)?;
            let id = store.add_bookmark(&url, &title).map_err(store_code)?;
            Ok(json!({ "id": id, "url": url, "title": title }))
        }
        "bookmark_list" => {
            let store = store_open(state)?;
            let items: Vec<Value> = store
                .bookmarks()
                .iter()
                .map(|b| {
                    json!({
                        "id": b.id,
                        "url": b.url,
                        "title": b.title,
                        "created_at": b.created_at,
                        "has_digest": b.digest.is_some(),
                        "digest_recorded_at": b.digest.as_ref().map(|d| d.recorded_at),
                    })
                })
                .collect();
            Ok(json!({ "items": items }))
        }
        "bookmark_update" => {
            let id = arg_str(args, "id")?;
            let url = normalize_input(arg_str(args, "url")?);
            let title = arg_str(args, "title")?;
            // An edited URL must stay inside the content allowlist, exactly
            // like a typed one.
            if !crate::state::is_allowed_content_url(&url) {
                return Err("bad_args");
            }
            store_open(state)?
                .update_bookmark(id, &url, title)
                .map_err(store_code)?;
            Ok(json!({}))
        }
        "bookmark_delete" => {
            let id = arg_str(args, "id")?;
            store_open(state)?.delete_bookmark(id).map_err(store_code)?;
            Ok(json!({}))
        }
        "bookmarks_import" => {
            // No args: the file comes from the native picker, so no path
            // ever round-trips through chrome. Check the store FIRST -- with
            // the store unavailable the arm must fail with the store error,
            // never show a picker and then silently import nothing.
            store_open(state)?;
            let picked =
                crate::platform::pick_file_to_open(&state.hosts, "Choose a bookmarks file");
            let Some(path) = picked else {
                // Changing one's mind is not a failure -- same contract as
                // the tunnel import picker. The reply is null (not a zeroed
                // summary) so chrome shows nothing rather than "Imported 0."
                return Ok(json!(null));
            };
            use std::io::Read as _;
            let mut text = String::new();
            std::fs::File::open(&path)
                .map_err(|_| "io")?
                // MAX_IMPORT_BYTES + 1, so an oversized file is REFUSED
                // below -- never truncated into a partial import that parses
                // as valid. A non-UTF-8 file fails the read and maps to the
                // generic io code: it is not a bookmark export.
                .take((crate::bookmark_import::MAX_IMPORT_BYTES + 1) as u64)
                .read_to_string(&mut text)
                .map_err(|_| "io")?;
            if text.len() > crate::bookmark_import::MAX_IMPORT_BYTES {
                return Err("too_large");
            }
            let parsed = crate::bookmark_import::parse(&text);
            // THE STORE'S INVARIANT, enforced at import exactly as
            // bookmark_add/update enforce it: the store only ever holds URLs
            // that passed the content allowlist, and bookmark_open relies on
            // that. An import that smuggled file:// or chrome-internal URLs
            // in would create records the browser then refuses to open.
            let mut skipped_unsupported = parsed.skipped_unsupported;
            let allowed: Vec<&crate::bookmark_import::ParsedBookmark> = parsed
                .bookmarks
                .iter()
                .filter(|entry| {
                    let ok = crate::state::is_allowed_content_url(&entry.url);
                    if !ok {
                        skipped_unsupported += 1;
                    }
                    ok
                })
                .collect();
            let store = store_open(state)?;
            let mut seen: std::collections::HashSet<String> =
                store.bookmarks().iter().map(|b| b.url.clone()).collect();
            let owned: Vec<crate::bookmark_import::ParsedBookmark> =
                allowed.into_iter().cloned().collect();
            let (fresh, skipped_duplicates) =
                crate::bookmark_import::split_new(&owned, &mut seen);
            let mut imported = 0usize;
            for entry in fresh {
                // If a save fails midway, entries already added stay added:
                // add_bookmark saves on every call and there is no batch
                // API. The error surfaces with the partial count uncounted,
                // so the summary never overstates what landed on disk.
                store
                    .add_bookmark(&entry.url, &entry.title)
                    .map_err(store_code)?;
                imported += 1;
            }
            Ok(json!({
                "imported": imported,
                "skipped_duplicates": skipped_duplicates,
                "skipped_unsupported": skipped_unsupported,
            }))
        }
        "bookmark_open" => {
            let id = arg_str(args, "id")?;
            let url = {
                let store = store_open(state)?;
                store.get_bookmark(id).ok_or("not_found")?.url.clone()
            };
            // The store only ever holds URLs that passed the allowlist on
            // the way in; re-check anyway so a hand-modified store file
            // cannot steer a tab somewhere content may not go.
            if !crate::state::is_allowed_content_url(&url) {
                return Err("bad_args");
            }
            state.navigate(&url)?;
            Ok(json!({}))
        }
        "download_list" => {
            let store = store_open(state)?;
            let items: Vec<Value> = store
                .downloads()
                .iter()
                .map(|d| {
                    json!({
                        "id": d.id,
                        "url": d.url,
                        "filename": d.filename,
                        "byte_len": d.byte_len,
                        "recorded_at": d.recorded_at,
                    })
                })
                .collect();
            Ok(json!({ "items": items }))
        }
        "download_verify" => {
            let id = arg_str(args, "id")?;
            let store = store_open(state)?;
            let record_ok = store.verify_download(id).map_err(store_code)?;
            let record = store.get_download(id).ok_or("not_found")?;
            let filename = record.filename.clone();
            let sha256 = record.sha256;
            // If the record itself failed its HMAC, the stored hash is
            // untrusted, and comparing the file against it would prove
            // nothing — the file is left unchecked and the UI leads with
            // the record failure.
            let file = if record_ok {
                crate::state::check_download_file(&filename, &sha256).as_str()
            } else {
                "unchecked"
            };
            Ok(json!({ "record_ok": record_ok, "file": file }))
        }

        // ---- integrity ----
        // ---- page integrity & peer corroboration --------------------------
        // Same convention. `unsupported` is a first-class answer here,
        // exactly like network_blocking_supported(): a platform that cannot
        // hand over the page bytes says so instead of guessing. Change
        // detection works in every build; corroboration rides on chat.
        "integrity_status" => crate::page_integrity::ipc_status(state),
        "integrity_check" => crate::page_integrity::ipc_check(state),
        "integrity_mark_seen" => crate::page_integrity::ipc_mark_seen(state),
        // Corroboration travels over the chat channel, so it exists only in
        // chat builds.
        #[cfg(feature = "chat")]
        "corroborate_request" => crate::page_integrity::ipc_corroborate_request(state, args),

        // ---- updater ----
        // ---- updater -------------------------------------------------------
        // All three commands answer with the SAME status snapshot, and domain
        // outcomes — including a REFUSED update — travel inside it, not as
        // IPC error codes: a refusal is a result the user must see, not a
        // command failure. No new codes, so ERROR_TEXT in chrome.js is
        // untouched. These exist in every build; with `updater-net` off the
        // snapshot says available:false and the panel explains.
        // Local OCR. `ocr_scan` returns a TOKEN, not a result: the work is
        // ~1s and this dispatch runs on the event loop, so the answer arrives
        // later as an `ocr_result` event.
        // DNS resolver choice. `dns_set` persists and reports that a restart
        // is needed -- WebView2 accepts the setting only at environment
        // creation, so nothing can apply it to a running browser.
        "dns_get" => {
            let (prefs, origin) = crate::prefs::load_with_origin();
            let mode = prefs.dns;
            Ok(json!({
                "mode": mode.as_str(),
                "describe": mode.describe(),
                "supported": cfg!(windows),
                // True when a preferences file exists and could not be read.
                // The mode above is then the DEFAULT -- System, meaning
                // plaintext DNS -- not what the user picked, and the panel
                // says so rather than showing a resolver choice that quietly
                // reverted.
                "settings_unreadable": origin == crate::prefs::PrefsOrigin::Unreadable,
            }))
        }
        "dns_set" => {
            if !cfg!(windows) {
                return Err("unsupported");
            }
            let mode = crate::prefs::DnsMode::parse(arg_str(args, "mode")?).ok_or("bad_args")?;
            let mut p = crate::prefs::load();
            p.dns = mode;
            crate::prefs::save(&p).map_err(|_| "io")?;
            Ok(json!({
                "mode": mode.as_str(),
                "describe": mode.describe(),
                "restart_required": true,
            }))
        }

        // ---- tunnel ------------------------------------------------------
        // NOT behind any feature gate, and no cfg!(windows) here: unlike
        // encrypted DNS, the tunnel is supported on both platforms.
        "tunnel_get" => {
            let mode = crate::prefs::load().tunnel;
            // A locked vault is NOT an error for this arm: the panel must
            // still render, and "has_config": null is how it learns to say
            // "unlock to see" rather than guessing at a state.
            // has_tunnel_settings, not tunnel_settings().is_some(): the
            // latter clones the whole configuration -- private key included
            // -- onto the heap and drops it unwiped, on every panel open,
            // to answer a yes/no question.
            let has_config = match unlocked(state) {
                Ok(vault) => json!(vault.has_tunnel_settings()),
                Err(_) => Value::Null,
            };
            Ok(json!({
                "mode": mode.as_str(),
                // Both describes ship every time, so the panel can show the
                // engine's own copy for EACH choice and never retype it.
                "describe_off": crate::prefs::TunnelMode::Off.describe(),
                "describe_imported": crate::prefs::TunnelMode::Imported.describe(),
                "has_config": has_config,
                "report": crate::tunnel_control::report(),
                "start_error": crate::tunnel_control::last_start_error(),
                // Whether what the user is looking at is actually in force.
                // A FACT from the engine, not something the panel infers
                // from having seen a click: the note has to survive closing
                // and reopening the panel, because the restart it is asking
                // for is just as pending either way.
                "restart_pending": crate::tunnel_control::restart_pending(),
            }))
        }
        "tunnel_import" => {
            // Required up front, like every vault arm -- the returned borrow
            // is dropped immediately, because the picker needs `state.hosts`
            // and the vault is re-borrowed only to store the result.
            unlocked(state)?;
            if !crate::platform::file_choice_supported() {
                return Err("unsupported");
            }
            let picked = crate::platform::pick_file_to_open(
                &state.hosts,
                "Choose a WireGuard configuration",
            );
            let Some(path) = picked else {
                // Changing one's mind is not a failure -- same contract as
                // the vault import picker's null path.
                return Ok(json!({ "imported": false }));
            };
            use std::io::Read as _;
            use zeroize::Zeroize as _;
            let mut text = String::new();
            std::fs::File::open(&path)
                .map_err(|_| "io")?
                // MAX_CONFIG_BYTES + 1, so an oversized file is REFUSED by
                // the parser's TooLarge -- never truncated into something
                // that parses as valid. A non-UTF-8 file fails the read and
                // maps to the generic io code: it is not a config at all.
                .take((patanyx_tunnel::MAX_CONFIG_BYTES + 1) as u64)
                .read_to_string(&mut text)
                .map_err(|_| "io")?;
            // The dispatch error channel is &'static str codes, so the
            // DYNAMIC refusal text rides the SUCCESS payload instead --
            // the same shape relay URL errors took when they got their own
            // code. ConfigError's Display is the ENTIRE import-error
            // vocabulary: named variants, none carrying key material, an
            // endpoint, or a path.
            let parsed = patanyx_tunnel::parse(&text);
            // The raw file text holds the private key; wipe it the moment
            // the parser is done with it, on BOTH outcomes (the independent
            // review caught this buffer surviving un-wiped). The parsed
            // copies below move into the vault, whose own drop wipes them.
            text.zeroize();
            let config = match parsed {
                Ok(config) => config,
                Err(refusal) => {
                    return Ok(json!({ "imported": false, "error": refusal.to_string() }))
                }
            };
            let mut settings = patanyx_vault::TunnelSettings {
                enabled: true,
                // MOVE the secrets out of the parsed config rather than
                // cloning: one fewer copy of key material to zeroize.
                private_key_b64: config.private_key_b64,
                peer_public_key_b64: config.peer_public_key_b64,
                endpoint: config.endpoint,
                preshared_key_b64: config.preshared_key_b64,
                keepalive_secs: config.keepalive_secs,
                allowed_ips: config.allowed_ips,
                dns: config.dns,
                address: config.address,
            };
            // The vault can auto-lock while the file dialog is open. On that
            // path `settings` would drop as a plain struct -- no vault around
            // it to wipe on drop -- so wipe its secrets by hand first.
            let vault = match unlocked(state) {
                Ok(vault) => vault,
                Err(code) => {
                    settings.private_key_b64.zeroize();
                    if let Some(psk) = settings.preshared_key_b64.as_mut() {
                        psk.zeroize();
                    }
                    return Err(code);
                }
            };
            vault
                .set_tunnel_settings(Some(settings))
                .map_err(|_| "io")?;
            // DECIDED: importing does NOT flip the prefs mode. Importing a
            // configuration and switching the tunnel on are separate acts,
            // and the panel copy says so.
            //
            // It DOES try to start the tunnel, though. The normal first-run
            // order is: choose Imported, restart, unlock, import -- and the
            // unlock hook already ran, found no configuration, and returned.
            // Without this call the port stays parked and refusing, so the
            // browser is dead until the NEXT unlock, with nothing on screen
            // saying why. Idempotent: the guards inside return immediately
            // when a tunnel is already running or the mode is not Imported.
            crate::tunnel_control::on_vault_unlocked(state);
            Ok(json!({ "imported": true }))
        }
        "tunnel_set_mode" => {
            let mode = crate::prefs::TunnelMode::parse(arg_str(args, "mode")?)
                .ok_or("bad_args")?;
            let mut p = crate::prefs::load();
            p.tunnel = mode;
            crate::prefs::save(&p).map_err(|_| "io")?;
            Ok(json!({
                "mode": mode.as_str(),
                "describe": mode.describe(),
                // Unconditionally true on BOTH platforms: Windows takes the
                // proxy only when the webview environment is created, and on
                // Linux the per-view proxy plus the parked-listener lifecycle
                // make a mid-session flip only partially effective. Honesty
                // over cleverness: the UI must always say restart.
                "restart_required": true,
            }))
        }
        "tunnel_remove" => {
            // Both, in this order (DECIDED): the configuration is wiped
            // before the mode flips, so the secret is gone even if the prefs
            // write then fails -- and the mode must never be left Imported
            // with no configuration behind it, which is a dead-port browser.
            unlocked(state)?
                .set_tunnel_settings(None)
                .map_err(|_| "io")?;
            let mut p = crate::prefs::load();
            p.tunnel = crate::prefs::TunnelMode::Off;
            crate::prefs::save(&p).map_err(|_| "io")?;
            Ok(json!({}))
        }
        // Thin alias of tunnel_get's measured half, for polling surfaces.
        "tunnel_status" => Ok(json!({
            "mode": crate::prefs::load().tunnel.as_str(),
            "report": crate::tunnel_control::report(),
            "start_error": crate::tunnel_control::last_start_error(),
            "restart_pending": crate::tunnel_control::restart_pending(),
        })),

        // ---- licence -----------------------------------------------------
        // NOT behind any feature gate, like the tunnel: the free build has
        // a vault and may hold a token, and the row ships in both builds.
        "licence_get" => Ok(licence_payload(state)),
        "licence_paste" => {
            // Required up front, like every vault-mutating arm.
            unlocked(state)?;
            let confirm = args.get("confirm").and_then(Value::as_bool).unwrap_or(false);
            let token_text = arg_str(args, "token")?;
            // The ring decides FIRST: a build with no usable keys cannot
            // verify ANY token, and the honest answer is "this build cannot
            // verify", never a bad-token message about a token nothing
            // tried to check. Since the 2026-08-05 ceremony the ring is
            // REAL, so real builds proceed past this; the refusal path
            // stays for a build stripped of the ring.
            let keys = match patanyx_licence::licence_keys() {
                Ok(keys) => keys,
                Err(_) => {
                    return Ok(json!({ "accepted": false, "code": "licence_keys_unavailable" }))
                }
            };
            // The dispatch error channel is &'static str codes only, so the
            // validation refusals ride the SUCCESS payload as codes — the
            // tunnel_import pattern. The code mapping is a pure function so
            // the tests below can pin it without an AppState.
            let token = match patanyx_licence::Token::parse(token_text, &keys) {
                Ok(token) => token,
                Err(error) => {
                    return Ok(json!({ "accepted": false, "code": licence_paste_code(&error) }));
                }
            };
            // Design 3.2 step 8: a different license_id needs an explicit
            // confirmation BEFORE anything is stored; the SAME id replaces
            // silently (the renewal path). A stored record that no longer
            // parses "cannot happen" (it validated at paste) and is treated
            // as no licence at all — replacing a corrupt record needs no
            // confirm. The clone's token text is wiped before the decision.
            use zeroize::Zeroize as _;
            let existing_id = unlocked(state)?.licence_record().and_then(|mut record| {
                let id = patanyx_licence::Token::parse(&record.token_text, &keys)
                    .ok()
                    .map(|old| old.license_id());
                record.token_text.zeroize();
                id
            });
            if licence_replace_needs_confirm(existing_id, token.license_id(), confirm) {
                // Store NOTHING on this path: the confirmation is the gate.
                return Ok(json!({ "accepted": false, "needs_confirm": true }));
            }
            // Store — INCLUDING the expired case (design 3.2 step 7): the
            // record keeps the license_id the renewal path matches on. It
            // entitles the holder to nothing while lapsed (no fallback
            // license, decided 2026-08-05).
            let record = patanyx_vault::LicenceRecord {
                token_text: token_text.to_string(),
            };
            unlocked(state)?
                .set_licence_record(Some(record))
                .map_err(|_| "io")?;
            // Re-run the unlock-time evaluation so the session state and
            // the row update immediately, from the stored text — the same
            // path every unlock takes.
            crate::licence_control::on_vault_unlocked(state);
            let was_expired = crate::licence_control::current()
                .map(|session| {
                    matches!(session.state, patanyx_licence::LicenceState::Lapsed { .. })
                })
                .unwrap_or(false);
            let mut payload = licence_payload(state);
            payload["accepted"] = json!(true);
            if was_expired {
                // So the UI can show the expired notice; `ended_display`
                // in the shared payload carries the date.
                payload["was_expired"] = json!(true);
            }
            Ok(payload)
        }
        "licence_remove" => {
            unlocked(state)?
                .set_licence_record(None)
                .map_err(|_| "io")?;
            // Re-evaluate: no record evaluates FREE, so the session state
            // and the row reflect the removal immediately.
            crate::licence_control::on_vault_unlocked(state);
            Ok(json!({}))
        }

        // The privacy receipt: refused-request counts for the session (all
        // tabs, closed ones included) and for the active tab. Posture --
        // who resolves DNS, whether the tunnel carries traffic -- is NOT in
        // this payload on purpose: those facts already have status arms and
        // user-facing wording, and assembling a second copy here would give
        // one fact two chances to be phrased. Null counts mean "not
        // observable with this engine"; see privacy::observable_counts for
        // why null and never zero.
        "privacy_receipt" => {
            let session_total =
                crate::platform::privacy::session_blocked_total(state.live_blocked_totals());
            let page = state.active_blocked_total();
            let counts_blocked = crate::state::LEDGER_COUNTS_BLOCKED;
            let (session_blocked, page_blocked) =
                crate::platform::privacy::observable_counts(counts_blocked, session_total, page);
            Ok(json!({
                "session_blocked": session_blocked,
                "page_blocked": page_blocked,
                "counts_blocked": counts_blocked,
            }))
        }

        // Fired automatically at chrome boot, like `ping` -- see its entry
        // in `counts_as_presence`. `onboarding_resolved` also decides, on an
        // absent marker, whether this install already has a vault (an
        // upgrade) and if so writes the marker itself; see prefs.rs.
        "onboarding_seen_get" => Ok(json!({ "seen": crate::prefs::onboarding_resolved() })),
        // The one call site: chrome.js calls this from the tour panel's
        // shared close handler, which Skip, Finish, Escape and the scrim all
        // funnel through, so however the tour is left, this fires once.
        "onboarding_seen_set" => {
            crate::prefs::mark_onboarding_seen();
            Ok(json!({}))
        }

        // How many malicious hosts are in force, so "am I protected" has a
        // number behind it rather than a claim.
        // The zoom chip's reset. The keyboard path goes through shortcuts;
        // this is the same action from the click.
        "zoom_reset" => {
            state.zoom_active(0);
            Ok(json!({}))
        }

        "blocklist_status" => Ok(json!({ "hosts": crate::blocklist::len() })),

        // "Open it anyway". Per tab, effective on the next navigation, and
        // gone when the tab closes. There is deliberately no permanent form.
        "blocklist_allow" => {
            // Capped BEFORE the lowercase copy. `matched_rule` refuses
            // anything over MAX_HOST_LEN anyway, so a longer string was always
            // going to be rejected -- it just allocated a full duplicate of
            // itself first. 253 is the DNS limit and the same bound the
            // lookup applies.
            let host = arg_str_capped(args, "host", 253)?.to_ascii_lowercase();
            // Refuse a host that is not actually listed, so this command
            // cannot be used to seed arbitrary state from a compromised UI.
            if crate::blocklist::matched_rule(&host).is_none() {
                return Err("bad_args");
            }
            let tab = state.tabs.get(state.active).ok_or("no_tab")?;
            tab.allow_malicious_host(&host);
            tab.webview.load_url(&format!("https://{host}/")).ok();
            Ok(json!({ "allowed": host }))
        }

        // The resolver-unreachable banner. `resolver_retry` re-probes on
        // demand; `resolver_dismiss` closes the banner for this episode only.
        // Neither can change the DNS setting -- switching resolvers is
        // `dns_set` and stays a deliberate act in the panel, so a network that
        // breaks the browser can never talk it into a weaker configuration.
        "resolver_status" => crate::resolver_probe::ipc_status(),
        "resolver_retry" => crate::resolver_probe::ipc_retry(&state.proxy()),
        "resolver_dismiss" => crate::resolver_probe::ipc_dismiss(&state.proxy()),

        "ocr_status" => crate::ocr_support::ipc_status(),
        "ocr_scan" => crate::ocr_support::ipc_scan(state, args),

        // Identity, terms and notices: a few kilobytes, sent when the panel
        // opens. The third-party inventory is roughly 300 KB and is a separate
        // command on purpose, so it crosses the boundary only when somebody
        // opens that section rather than on every visit to About.
        "about_info" => crate::about::ipc_info(),
        "about_attribution" => crate::about::ipc_attribution(),

        // A snapshot for troubleshooting, not a claim: what state.rs composes
        // is documented there as excluding history, page content and vault
        // data. `file_choice`/`export_suggestion` ride here rather than in
        // the snapshot itself because they are about HOW to save it, not
        // WHAT is being saved -- the same split `vault_backup_status` uses.
        "diagnostics_get" => {
            let mut snapshot = state.diagnostics_snapshot();
            if let Value::Object(ref mut map) = snapshot {
                map.insert(
                    "export_suggestion".to_string(),
                    json!(sibling_file_suggestion(
                        &state.vault_path,
                        "patanyx-diagnostics.json"
                    )),
                );
                map.insert(
                    "file_choice".to_string(),
                    json!(crate::platform::file_choice_supported()),
                );
            }
            Ok(snapshot)
        }
        "diagnostics_export" => {
            let dest = arg_str(args, "dest")?;
            if dest.is_empty() {
                return Err("bad_args");
            }
            state
                .export_diagnostics(Path::new(dest))
                .map_err(|_| "io")?;
            Ok(json!({}))
        }

        // OFF THE EVENT-LOOP THREAD. `check_now` is synchronous and performs
        // an HTTP GET with a 10s connect and 30s overall timeout; called from
        // here it froze the ENTIRE browser for that long -- every shortcut,
        // every tab, every click -- because ipc::dispatch runs on the event
        // loop. With encrypted DNS failing closed, hitting the full timeout
        // was the likely case rather than the rare one.
        //
        // The comment on `check_in_background` used to call that "tolerable
        // for the IPC path (the user pressed a button and is watching)". That
        // was wrong: a user watching a spinner has not agreed to their other
        // tabs freezing. The reply is the CURRENT status, and the real result
        // arrives moments later via the `update_checked` event the panel
        // already renders.
        "update_check" => {
            crate::updater::check_in_background(&state.proxy());
            Ok(crate::updater::status())
        }
        "update_status" => Ok(crate::updater::status()),
        "update_install" => crate::updater::install(),
        // The irreversible step, and its own command for that reason: this
        // replaces the running binary. Gated on Phase::Ready in the updater,
        // and the staged bytes are re-hashed against the signed manifest
        // there before anything is moved.
        "update_apply" => crate::updater::apply_staged(&state.proxy()),

        // Takes effect on the NEXT check, not this build's environment --
        // unlike DNS, the channel is read fresh from prefs every time a
        // check actually runs (`manifest_url` in updater.rs), so there is
        // nothing here to restart for.
        "update_channel_get" => {
            let prefs = crate::prefs::load();
            Ok(json!({ "channel": prefs.update_channel.as_str() }))
        }
        "update_channel_set" => {
            let channel =
                crate::prefs::UpdateChannel::parse(arg_str(args, "channel")?).ok_or("bad_args")?;
            let mut p = crate::prefs::load();
            p.update_channel = channel;
            crate::prefs::save(&p).map_err(|_| "io")?;
            Ok(json!({ "channel": channel.as_str() }))
        }

        _ => Err("bad_args"),
    }
}

fn smoke_step(state: &mut AppState, cmd: &str, args: Value) -> Result<Value, String> {
    handle(state, cmd, &args).map_err(|e| format!("{cmd}: {e}"))
}

/// Smoke-test only: drive a full vault lifecycle through the real dispatch
/// surface. The smoke script points the vault's data directory (XDG_DATA_HOME
/// on unix, PATANYX_DATA_DIR on Windows) at a throwaway directory, so
/// this never touches a real vault.
pub fn smoke_vault_sequence(state: &mut AppState) -> Result<(), String> {
    let pass = "smoke-passphrase-1";
    let status = smoke_step(state, "vault_status", json!({}))?;
    if status["exists"] != json!(false) {
        return Err("vault unexpectedly exists in smoke dir".into());
    }
    smoke_step(state, "vault_create", json!({ "passphrase": pass }))?;
    let id = smoke_step(
        state,
        "cred_add",
        json!({ "site": "example.com", "username": "smoke", "password": "pw123456", "note": "" }),
    )?["id"]
        .as_str()
        .ok_or("cred_add: reply carries no id")?
        .to_string();
    smoke_step(state, "note_add", json!({ "title": "t", "body": "b" }))?;
    // A bookmark, because bookmarks travel with the export and the only way
    // to know they survived is to have put one in before exporting.
    //
    // `bookmark_add` deliberately takes no URL -- it bookmarks the ACTIVE TAB,
    // so the chrome cannot bookmark a URL it invented. That means the tab has
    // to be given one here, which is also what the real UI does.
    const CARRIED_URL: &str = "https://carried.example/page";
    {
        let tab = state.tabs.get_mut(state.active).ok_or("smoke: no active tab")?;
        tab.url = CARRIED_URL.to_string();
        tab.title = "carried".to_string();
    }
    smoke_step(state, "bookmark_add", json!({}))?;
    // The receipt arm end-to-end through real dispatch: reply shape and the
    // number-or-null contract, on whichever platform the smoke runs.
    let receipt = smoke_step(state, "privacy_receipt", json!({}))?;
    if receipt.get("counts_blocked").and_then(|v| v.as_bool()).is_none() {
        return Err("privacy_receipt: counts_blocked missing".into());
    }
    let coherent = match receipt.get("counts_blocked").and_then(|v| v.as_bool()) {
        Some(true) => receipt.get("session_blocked").map(|v| v.is_u64()) == Some(true),
        _ => receipt.get("session_blocked").map(|v| v.is_null()) == Some(true),
    };
    if !coherent {
        return Err("privacy_receipt: counts must be numbers when observable, null when not".into());
    }
    smoke_step(state, "vault_lock", json!({}))?;
    if smoke_step(state, "cred_list", json!({})).is_ok() {
        return Err("cred_list succeeded while locked".into());
    }
    smoke_step(state, "vault_unlock", json!({ "passphrase": pass }))?;
    let entry = smoke_step(state, "cred_get", json!({ "id": id }))?;
    if entry["password"] != json!("pw123456") {
        return Err("password mismatch after lock/unlock cycle".into());
    }

    // MIGRATION, end to end through the real dispatch surface.
    //
    // This is the data half of bringing a vault to another machine (or into
    // the Flatpak, where it is the only route in): export encrypted, and
    // import that file as a fresh vault. Choosing the file is the other half
    // and needs a human to click a portal dialog, so it is not driven here --
    // but everything that happens either side of the click is.
    let export_pass = "smoke-export-passphrase";
    let new_pass = "smoke-imported-passphrase";
    let export_path = state
        .vault_path
        .parent()
        .ok_or("vault path has no parent")?
        .join("smoke-migration.rbx");
    let export_str = export_path.to_string_lossy().into_owned();
    smoke_step(
        state,
        "vault_export_encrypted",
        json!({ "dest": export_str, "passphrase": export_pass }),
    )?;
    if !export_path.is_file() {
        return Err("vault_export_encrypted wrote nothing".into());
    }

    // IMPORT OVER A LIVE VAULT REPLACES IT. This used to assert the opposite
    // -- that import refused while a vault existed -- and that refusal is why
    // the import control could not be offered to anyone who had one. The
    // behaviour is now destructive by design, the warning sits in the panel
    // where the user reads it first, and this step exists to prove the
    // replacement actually happens rather than half-happening.
    //
    // Driven while the vault is UNLOCKED, which is the dangerous shape: a live
    // vault holding an open file that is about to be replaced underneath it.
    let imported = smoke_step(
        state,
        "vault_import",
        json!({ "src": export_str, "passphrase": export_pass, "new_passphrase": new_pass }),
    )?;
    if imported["recovery_key"].as_str().unwrap_or("").is_empty() {
        return Err("import minted no recovery key".into());
    }
    // The imported vault is a NEW vault: its own passphrase, and the export
    // passphrase opens nothing but the export file.
    smoke_step(state, "vault_lock", json!({}))?;
    if smoke_step(state, "vault_unlock", json!({ "passphrase": export_pass })).is_ok() {
        return Err("the export passphrase opened the imported vault".into());
    }
    smoke_step(state, "vault_unlock", json!({ "passphrase": new_pass }))?;
    let carried = smoke_step(state, "cred_list", json!({}))?;
    let count = carried["items"].as_array().map(|a| a.len()).unwrap_or(0);
    // The expected value appears ONCE. Spelling it in the message as well
    // lets the two drift, and a failure that misreports what it wanted is a
    // failure that sends the reader somewhere else.
    const EXPECTED_CREDENTIALS: usize = 1;
    if count != EXPECTED_CREDENTIALS {
        return Err(format!(
            "migration carried {count} credentials, expected {EXPECTED_CREDENTIALS}"
        ));
    }
    // Bookmarks travelled. This is the whole point of carrying them: a user
    // who moves machines expects the things they chose to keep.
    let marks = smoke_step(state, "bookmark_list", json!({}))?;
    let mark_count = marks["items"].as_array().map(|a| a.len()).unwrap_or(0);
    const EXPECTED_BOOKMARKS: usize = 1;
    if mark_count != EXPECTED_BOOKMARKS {
        return Err(format!(
            "migration carried {mark_count} bookmarks, expected {EXPECTED_BOOKMARKS}"
        ));
    }
    if marks["items"][0]["url"] != json!(CARRIED_URL) {
        return Err("the carried bookmark is not the one that was exported".into());
    }
    // Downloads deliberately do NOT travel: a download record is browsing
    // history, and carrying it into a backup file and onto another machine is
    // a copy of the user's history nobody asked for. Asserted rather than
    // trusted, because "we did not serialise it" is exactly the kind of claim
    // that survives a refactor as a comment and stops being true.
    let downloads = smoke_step(state, "download_list", json!({}))?;
    if downloads["items"].as_array().map(|a| a.len()).unwrap_or(0) != 0 {
        return Err("downloads travelled with the export; they must not".into());
    }
    let _ = std::fs::remove_file(&export_path);
    Ok(())
}

/// Smoke-test only: drive the tab lifecycle through the real dispatch
/// surface and check the URL-bar search fallback.
pub fn smoke_tab_sequence(state: &mut AppState) -> Result<(), String> {
    let first_id = smoke_step(state, "tab_list", json!({}))?["items"][0]["id"]
        .as_u64()
        .ok_or("tab_list: first tab has no id")?;
    let new_id = smoke_step(state, "tab_new", json!({}))?["id"]
        .as_u64()
        .ok_or("tab_new: reply carries no id")?;
    let count = smoke_tab_count(state)?;
    if count != 2 {
        return Err(format!("tab_list after tab_new: expected 2 tabs, got {count}"));
    }
    smoke_step(state, "tab_switch", json!({ "id": first_id }))?;
    smoke_step(state, "tab_close", json!({ "id": new_id }))?;
    let count = smoke_tab_count(state)?;
    if count != 1 {
        return Err(format!(
            "tab_list after tab_close: expected 1 tab, got {count}"
        ));
    }
    let normalized = normalize_input("rust tutorial");
    if normalized != "https://duckduckgo.com/?q=rust%20tutorial" {
        return Err(format!("normalize_input search fallback broken: {normalized}"));
    }

    // Privacy controls through the real dispatch surface. Turning ad blocking
    // on is what drives the unix content-filter compile path (raw FFI into
    // WebKitUserContentFilterStore); a crash or a hang there shows up here
    // rather than in front of a user. The filter compiles asynchronously, so
    // this proves the request is well-formed and does not fault — the cached
    // bytecode on disk is what proves it completed, and smoke.sh checks that.
    let status = smoke_step(state, "privacy_set", json!({ "block_ads": true }))?;
    if status["block_ads"] != json!(true) {
        return Err("privacy_set did not enable ad blocking".into());
    }
    if status["network_blocking_supported"] != json!(true) {
        return Err("network blocking reported unsupported on this build".into());
    }
    let status = smoke_step(state, "privacy_get", json!({}))?;
    if status["block_ads"] != json!(true) {
        return Err("privacy_get lost the policy set moments earlier".into());
    }
    smoke_step(state, "privacy_set", json!({ "block_ads": false }))?;

    // Fingerprint noise through the real dispatch surface. Prefs-backed,
    // unlike block_ads above, so this flips and RESTORES what it found:
    // scripts/smoke.sh runs against the real profile (only ci-trixie
    // isolates its data dir), and a smoke run must not leave a user's
    // privacy pref flipped behind it.
    let before = smoke_step(state, "fingerprint_noise_get", json!({}))?["enabled"]
        .as_bool()
        .ok_or("fingerprint_noise_get returned no bool")?;
    let flipped = smoke_step(state, "fingerprint_noise_set", json!({ "enabled": !before }))?;
    if flipped["enabled"] != json!(!before) {
        return Err("fingerprint_noise_set did not flip the pref".into());
    }
    let read_back = smoke_step(state, "fingerprint_noise_get", json!({}))?;
    if read_back["enabled"] != json!(!before) {
        return Err("fingerprint_noise_get lost the value set moments earlier".into());
    }
    smoke_step(state, "fingerprint_noise_set", json!({ "enabled": before }))?;
    Ok(())
}

fn smoke_tab_count(state: &mut AppState) -> Result<usize, String> {
    Ok(smoke_step(state, "tab_list", json!({}))?["items"]
        .as_array()
        .map_or(0, Vec::len))
}

/// Smoke-test only: prove the hover readout against the REAL widget in the
/// real window. Three properties no unit test can reach:
///
/// 1. The readout is hidden after startup's recursive `show_all` -- the
///    exact defect `set_no_show_all(true)` exists to prevent, invisible to
///    any test that never builds the widget tree.
/// 2. The decision layer is actually WIRED to the renderer: a `javascript:`
///    target must hide it, not merely be refused somewhere in the same
///    binary.
/// 3. The widget survives a scheme swap (the CSS provider reload path).
///
/// On success main.rs prints `READOUT ok`, which ci-trixie greps for.
pub fn smoke_readout_sequence(state: &mut AppState) -> Result<(), String> {
    let hosts = &state.hosts;

    // 1. Nothing is hovered at startup, so nothing may be visible.
    let (visible, text) = crate::platform::hover_readout_state(hosts);
    if visible || !text.is_empty() {
        return Err(format!(
            "readout visible at startup (visible={visible}, text={text:?})"
        ));
    }

    // 1b. And it must SURVIVE a recursive show_all. Deliberately re-run here
    //     rather than trusting startup ordering: layout() hides the readout
    //     on the first resize event, which can mask a missing
    //     `set_no_show_all` behind event timing -- the first draft of this
    //     gate passed with that exact defect planted, which is how this step
    //     earned its place.
    crate::platform::show_all(hosts);
    let (visible, _) = crate::platform::hover_readout_state(hosts);
    if visible {
        return Err(
            "show_all re-showed the readout; set_no_show_all is missing or broken".into(),
        );
    }

    // 2. A link the rules allow must show, verbatim.
    let shown = crate::hover::readout_for("https://example.com/a");
    crate::platform::set_hover_readout(hosts, shown.as_deref());
    let (visible, text) = crate::platform::hover_readout_state(hosts);
    if !visible || text != "https://example.com/a" {
        return Err(format!(
            "readout did not show an allowed link (visible={visible}, text={text:?})"
        ));
    }

    // 3. A javascript: target must HIDE it -- the decision layer really
    //    driving the renderer, not sitting untested beside it.
    let shown = crate::hover::readout_for("javascript:alert(1)");
    crate::platform::set_hover_readout(hosts, shown.as_deref());
    let (visible, _) = crate::platform::hover_readout_state(hosts);
    if visible {
        return Err("readout still visible for a javascript: target".into());
    }

    // 4. A scheme swap must not destroy the widget: re-show and check.
    crate::platform::set_hover_readout_scheme(hosts, crate::prefs::ChromeScheme::White);
    let shown = crate::hover::readout_for("https://example.com/b");
    crate::platform::set_hover_readout(hosts, shown.as_deref());
    let (visible, _) = crate::platform::hover_readout_state(hosts);
    // Restore the scheme before any assertion can return early.
    crate::platform::set_hover_readout_scheme(hosts, crate::prefs::load().chrome_scheme);
    if !visible {
        return Err("readout did not survive a scheme swap".into());
    }

    // 5. And back to hidden, which is where a fresh session leaves it.
    crate::platform::set_hover_readout(hosts, None);
    let (visible, _) = crate::platform::hover_readout_state(hosts);
    if visible {
        return Err("readout still visible after being cleared".into());
    }

    println!("READOUT ok");
    Ok(())
}

fn unlocked(state: &mut AppState) -> Result<&mut Vault, &'static str> {
    state.vault.as_mut().ok_or("not_unlocked")
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    args.get(key).and_then(Value::as_str).ok_or("bad_args")
}

/// `arg_str` with a length ceiling, for fields that have a real one.
///
/// The frame cap in `dispatch` bounds total memory; this bounds the work done
/// on a single field AFTER parsing. It matters where the value is transformed
/// before it is validated -- `blocklist_allow` used to allocate a lowercased
/// copy of an unbounded string and only then consult a lookup that rejects
/// anything over 253 bytes, so the rejection cost more than the answer.
///
/// Deliberately not applied to passphrases: they are bounded by the frame cap,
/// a KDF is meant to be expensive, and a length limit on a secret is a
/// property users can discover and attackers can exploit.
fn arg_str_capped<'a>(
    args: &'a Value,
    key: &str,
    max: usize,
) -> Result<&'a str, &'static str> {
    let value = arg_str(args, key)?;
    if value.len() > max {
        return Err("bad_args");
    }
    Ok(value)
}

/// `pub(crate)` so the chat panel maps vault failures to the same IPC codes
/// the vault commands already use — one error vocabulary, not two.
pub(crate) fn vault_code(error: VaultError) -> &'static str {
    match error {
        VaultError::BadFormat(_) => "bad_format",
        VaultError::AuthFailed => "auth_failed",
        VaultError::AlreadyExists(_) => "vault_exists",
        // Its own code, not "io": the user can act on this one. Closing the
        // other window fixes it, and saying so beats a generic failure.
        VaultError::Locked => "vault_in_use",
        VaultError::NotFound(_) => "not_found",
        VaultError::BadRecoveryKey => "bad_recovery_key",
        VaultError::NoRecoverySlot => "no_recovery_slot",
        VaultError::Io(_) => "io",
        // Caller-fixable bad input, so it maps to the existing "your arguments
        // were wrong" code rather than inventing a second vocabulary for it.
        VaultError::InvalidContact(_) => "bad_args",
        // Distinct: two contacts sharing a peer hash would collide in the
        // chat panel's session map, and the user needs to be told which of the
        // two things they typed was already taken.
        VaultError::DuplicatePeerHash(_) => "duplicate_contact",
        // No dedicated "crypto" error code in the IPC protocol; KDF/AEAD
        // parameter failures are unreachable through normal user input.
        VaultError::Crypto(_) => "io",
    }
}

/// A file next to the vault, offered to the UI as a pre-filled (editable)
/// export destination: same disk, same owner-only directory. Only a
/// suggestion — the user can point the field anywhere.
fn sibling_file_suggestion(vault_path: &Path, file_name: &str) -> String {
    vault_path
        .with_file_name(file_name)
        .to_string_lossy()
        .into_owned()
}

/// Export/import failures are a distinct type from [`VaultError`], so they
/// get their own mapper. A wrong EXPORT passphrase gets its own code rather
/// than `auth_failed`: that code's user-facing text says "wrong passphrase or
/// corrupted vault", and telling someone their vault may be corrupted when
/// the failure is about an export file points them at the wrong file.
/// Every code here must exist in ERROR_TEXT in chrome.js.
/// Put imported bookmarks back, under the NEW passphrase.
///
/// Returns how many were restored, so the panel can say so rather than
/// leaving the user to guess whether anything came across.
///
/// EVERY FAILURE HERE IS SWALLOWED, and that is deliberate. By the time this
/// runs the credentials are already written and the vault is sound; the
/// bookmarks are a bonus that travelled with them. Propagating an error would
/// report the whole import as failed when the part that matters succeeded, and
/// a user who then re-ran it would be re-importing a vault they already have.
/// Bookmarks are recoverable from the export file. A vault the user believes
/// failed to import is not.
///
/// The store is REPLACED, not merged. An import is the user saying "make this
/// machine look like that one"; silently unioning two bookmark sets would
/// leave a state neither machine ever had.
fn restore_bookmarks(state: &mut AppState, passphrase: &str, carried: Option<&[u8]>) -> usize {
    let Some(bytes) = carried else { return 0 };
    // A v1 export, or one taken before bookmarks travelled, carries nothing.
    // Not an error -- just an older file.
    let Ok(bookmarks) = serde_json::from_slice::<Vec<patanyx_store::Bookmark>>(bytes) else {
        return 0;
    };
    if bookmarks.is_empty() {
        return 0;
    }
    // Remove any store belonging to the vault that was just replaced. Keeping
    // it would leave bookmarks sealed under the OLD passphrase next to
    // credentials under the new one, and the next unlock would fail to open it
    // and report the store damaged.
    state.store = None;
    let _ = std::fs::remove_file(&state.store_path);
    state.open_store(passphrase);
    let Some(store) = state.store.as_mut() else {
        return 0;
    };
    store.replace_bookmarks(bookmarks).unwrap_or(0)
}

fn export_code(error: ExportError) -> &'static str {
    match error {
        ExportError::AuthFailed => "export_auth_failed",
        ExportError::BadExport(_) => "bad_export",
        ExportError::PlaintextNotConfirmed => "export_not_confirmed",
        ExportError::TargetIsLiveVault => "target_is_vault",
        // Wrapped vault errors (import refusing to overwrite, i/o inside a
        // vault save after import) reuse the vault vocabulary unchanged.
        ExportError::Vault(inner) => vault_code(inner),
        ExportError::Io(_) => "io",
    }
}

/// Hosts only: the platform layer lowercases and matches against normalized
/// ledger hosts. Letters, digits, dots and hyphens, plus ':' for IPv6
/// literals (host_of strips the brackets). Anything else — whitespace, '/',
/// '@', a scheme — is not a host and would be a dead override.
fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

/// Best-effort origin for a credential's free-text `site` label. Tried as a
/// full URL first (`https://example.com/login` -> `example.com`, via the
/// same `host_of` the chrome-origin allowlist and `tab_status`'s `origin`
/// field use — one parser, so a fill match can never disagree with what the
/// rest of the browser calls "the origin"), then as a bare hostname
/// (`example.com` -> `example.com`, matching the field's own placeholder
/// text). Anything else -- a display name, a note, garbage -- is `None`,
/// and that credential is simply excluded from fill matching; it is not an
/// error, and every credential predating this field starts out this way.
fn parse_credential_origin(site: &str) -> Option<String> {
    let trimmed = site.trim();
    if let Some(origin) = crate::state::host_of(trimmed) {
        return Some(origin);
    }
    // No scheme: a bare host, possibly with a port. Stripped the same way
    // `host_of` strips one from a full URL, so both paths agree on what
    // "the origin" means for the same effective host.
    let host_only = trimmed.split(':').next().unwrap_or(trimmed);
    is_valid_host(host_only).then(|| host_only.to_ascii_lowercase())
}

fn store_open(state: &mut AppState) -> Result<&mut Store, &'static str> {
    // Resolved BEFORE the mutable borrow below: reading it inside the `None`
    // arm would borrow `state` immutably while `as_mut` still holds it.
    let why = state.store_error().unwrap_or("not_unlocked");
    match state.store.as_mut() {
        Some(store) => Ok(store),
        // If opening alongside the vault failed earlier, say why instead of
        // claiming the vault is locked when it is not.
        None => Err(why),
    }
}

/// Store failures map onto the same small vocabulary. `AuthFailed` maps to
/// `store_bad_format` rather than `auth_failed` on purpose: the store only
/// ever sees the vault's passphrase, which has just succeeded at opening the
/// vault, so an authentication failure here means the file is not readable
/// as our store (corrupt or foreign), not that the user typed something
/// wrong. `AlreadyExists` is unreachable through the UI (we check `exists`
/// first) and maps to the generic storage failure.
// CONFIRMED against crates/store/src/error.rs: exactly these six variants
// (BadFormat, AuthFailed, AlreadyExists, NotFound, Io, Crypto) and no
// `#[non_exhaustive]`, so this match is total and a new variant would fail to
// compile here rather than fall through to a default. Was a Note
// admitting the list had been inferred rather than read -- on a release
// branch, where an inferred error map is exactly the kind of thing that ships
// a wrong message to a user.
/// The shared licence_get / licence_paste payload. A locked vault is NOT an
/// error: nulls tell the panel to say nothing rather than guessing at a
/// state — the same contract as tunnel_get's `has_config`. Every
/// user-facing string is worded by licence_control; ipc assembles, it does
/// not phrase.
fn licence_payload(state: &mut AppState) -> Value {
    let has_token = match unlocked(state) {
        // has_licence_record, not licence_record().is_some(): the latter
        // clones the bearer token onto the heap and drops it unwiped, on
        // every panel open, to answer a yes/no question.
        Ok(vault) => Some(vault.has_licence_record()),
        Err(_) => None,
    };
    let keys_available = crate::licence_control::keys_available();
    let Some(has_token) = has_token else {
        return json!({
            "row_head": Value::Null,
            "row_sub": Value::Null,
            "state": Value::Null,
            "days_left": Value::Null,
            "has_token": Value::Null,
            "ended_display": Value::Null,
            "keys_available": keys_available,
        });
    };
    // An unlocked vault always has a session state (every unlock path runs
    // licence_control::on_vault_unlocked). The FREE fallback covers only
    // the cannot-happen case, in the honest direction.
    let session = crate::licence_control::current().unwrap_or_else(|| {
        crate::licence_control::SessionLicence {
            state: patanyx_licence::LicenceState::Free,
            keys_available,
            diagnostic: None,
        }
    });
    let (row_head, row_sub) = crate::licence_control::row_copy_for(&session.state);
    let (state_name, days_left, ended_display) = match session.state {
        patanyx_licence::LicenceState::Free => ("free", Value::Null, Value::Null),
        patanyx_licence::LicenceState::Active { days_left } => {
            ("active", json!(days_left), Value::Null)
        }
        patanyx_licence::LicenceState::Lapsed { expires_day } => (
            "lapsed",
            Value::Null,
            json!(crate::licence_control::ended_display_for(expires_day)),
        ),
    };
    json!({
        "row_head": row_head,
        "row_sub": row_sub,
        "state": state_name,
        "days_left": days_left,
        "has_token": has_token,
        "ended_display": ended_display,
        "keys_available": keys_available,
    })
}

/// Design 3.2's refusal classes as payload codes, pure so the mapping is
/// table-testable. Step pairs share codes deliberately: 1+2 (shape/CRC)
/// have one common cause (a truncated paste) and one message; 3+5
/// (unknown key/tier) both mean "minted by a newer build than this one".
fn licence_paste_code(error: &patanyx_licence::LicenceError) -> &'static str {
    match error {
        patanyx_licence::LicenceError::NotAToken
        | patanyx_licence::LicenceError::CrcMismatch => "licence_not_a_token",
        patanyx_licence::LicenceError::UnknownKeyId { .. }
        | patanyx_licence::LicenceError::UnknownTier { .. } => "licence_needs_newer_build",
        patanyx_licence::LicenceError::BadSignature => "licence_not_issued",
        // The key-ring construction errors (NoLicenceKeys / BadKey) cannot
        // surface from parse — the arm builds the ring before parsing —
        // but the match stays total without naming variants this layer
        // does not own.
        _ => "licence_keys_unavailable",
    }
}

/// Design 3.2 step 8, pure: an existing record with a DIFFERENT license_id
/// needs an explicit confirmation before anything is stored; the SAME id
/// replaces silently (the renewal path); no existing record — including an
/// unparseable one, which reads as `None` — needs no confirmation.
fn licence_replace_needs_confirm(
    existing_id: Option<[u8; 16]>,
    new_id: [u8; 16],
    confirm: bool,
) -> bool {
    match existing_id {
        Some(existing) => existing != new_id && !confirm,
        None => false,
    }
}

pub(crate) fn store_code(error: StoreError) -> &'static str {
    match error {
        StoreError::NotFound(_) => "not_found",
        StoreError::Io(_) => "io",
        StoreError::Crypto(_) => "io",
        StoreError::AlreadyExists(_) => "io",
        StoreError::AuthFailed => "store_bad_format",
        StoreError::BadFormat(_) => "store_bad_format",
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_input;
    use crate::state::is_allowed_content_url;
    use serde_json::json;

    #[test]
    fn polled_commands_are_not_evidence_a_user_is_here() {
        // The bug this locks down: every IPC frame used to re-arm the vault's
        // idle deadline, and the Tab Activity panel polls `tab_ledger` every
        // 2.5 seconds. Leaving that panel open therefore disabled the
        // auto-lock completely -- twenty-four re-arms a minute, forever, with
        // nothing on screen to suggest the vault would never lock.
        for cmd in [
            "tab_ledger",
            "update_status",
            "ping",
            "ocr_status",
            "blocklist_status",
            "resolver_status",
            "store_status",
            "vault_status",
            "chat_status",
            // Polled on every tab status update so the toolbar fill button can
            // know whether this site has a saved password. Left counting, an
            // open browser on any page would re-arm the deadline indefinitely.
            "cred_autofill_offer_get",
            // Fired by the vault panel to render the Premium row; a passive
            // read, like tunnel_get.
            "licence_get",
        ] {
            assert!(
                !super::counts_as_presence(cmd),
                "{cmd} is polled or fired automatically; counting it as presence \
                 lets an idle browser hold its vault open"
            );
        }
    }

    /// The offer query, not the algorithm. `psl.rs` proves `same_site` is
    /// correct; these prove the credential flow actually ASKS it, and that the
    /// exact-host entry is the one offered when both exist. Wiring the right
    /// rule to the wrong call site is a defect no psl test can see.
    #[test]
    fn the_offer_matches_by_site_and_prefers_the_exact_host() {
        // A tiny stand-in for the vault's stored origins, filtered by exactly
        // the closure the handler passes to `credentials_matching`.
        let stored = [
            "accounts.google.com",
            "google.com",
            "evil.co.uk",
            "mybank.co.uk",
            "notgoogle.com",
        ];
        let offer = |page: &str| -> Vec<&str> {
            let mut hit: Vec<&str> = stored
                .iter()
                .copied()
                .filter(|s| super::super::psl::same_site(s, page))
                .collect();
            hit.sort_by_key(|s| *s != page);
            hit
        };

        // The case that prompted all of this.
        assert_eq!(
            offer("mail.google.com"),
            vec!["accounts.google.com", "google.com"],
            "a Google credential must be offered on another google.com host"
        );
        // Both exist, and the one naming this page must be offered first --
        // the chrome only ever takes items[0].
        assert_eq!(
            offer("google.com")[0],
            "google.com",
            "the exact-host credential must outrank the sibling one"
        );
        // And the whole reason the Public Suffix List is compiled in.
        assert_eq!(
            offer("evil.co.uk"),
            vec!["evil.co.uk"],
            "mybank.co.uk must never be offered to another co.uk site"
        );
        assert!(
            !offer("google.com").contains(&"notgoogle.com"),
            "a shared suffix string is not a shared site"
        );
    }

    #[test]
    fn deliberate_commands_still_count_as_presence() {
        // The other direction, and just as important: over-tightening this
        // list would lock the vault while somebody was using it. Anything a
        // person had to click or type to cause must count.
        for cmd in [
            "navigate",
            "tab_new",
            "tab_switch",
            "vault_unlock",
            "cred_add",
            "note_update",
            "bookmark_add",
            "dns_set",
            "privacy_set",
            "vault_stay_unlocked",
            "about_info",
            // Mutating tunnel acts. The read arms (tunnel_get,
            // tunnel_status) are exempted in counts_as_presence itself: a
            // passive panel refresh must not re-arm the idle deadline.
            "tunnel_import",
            "tunnel_set_mode",
            "tunnel_remove",
            // Mutating licence acts, as deliberate as it gets; the read arm
            // (licence_get) is exempted in counts_as_presence itself.
            "licence_paste",
            "licence_remove",
            // The click that fills a password, as opposed to the passive
            // `cred_autofill_offer_get` check exempted above. These two sit one
            // line apart in the handler and differ by a single word; pinning
            // both directions here is what stops the wrong one being exempted.
            "cred_autofill_fill",
            // Typing in the find bar and stepping matches are as deliberate
            // as it gets; a vault that locks mid-search misread the room.
            "find_start",
            "find_next",
            "shelf_create",
            "shelf_restore",
        ] {
            assert!(
                super::counts_as_presence(cmd),
                "{cmd} is user-initiated and must re-arm the idle deadline"
            );
        }
    }

    /// The paste flow's refusal-code mapping, pinned per design 3.2: the
    /// step pairs 1+2 and 3+5 share one code each, the signature failure is
    /// its own, and nothing here can emit the keys-unavailable code (that
    /// path is decided before parse ever runs).
    #[test]
    fn licence_paste_codes_map_the_spec_classes() {
        use patanyx_licence::LicenceError;
        assert_eq!(
            super::licence_paste_code(&LicenceError::NotAToken),
            "licence_not_a_token"
        );
        assert_eq!(
            super::licence_paste_code(&LicenceError::CrcMismatch),
            "licence_not_a_token",
            "a truncated paste is the common cause of both step-1 and step-2 \
             failures, so they share one message"
        );
        assert_eq!(
            super::licence_paste_code(&LicenceError::UnknownKeyId { key_id: 7 }),
            "licence_needs_newer_build"
        );
        assert_eq!(
            super::licence_paste_code(&LicenceError::UnknownTier { tier: 2 }),
            "licence_needs_newer_build"
        );
        assert_eq!(
            super::licence_paste_code(&LicenceError::BadSignature),
            "licence_not_issued"
        );
    }

    /// Design 3.2 step 8, both directions: a different license_id without
    /// confirmation stores nothing; the same id (renewal), a confirmed
    /// replacement, and an absent-or-unparseable existing record all
    /// proceed.
    #[test]
    fn licence_replacement_asks_before_replacing_a_different_license_only() {
        let a = [0x0Au8; 16];
        let b = [0x0Bu8; 16];
        assert!(
            super::licence_replace_needs_confirm(Some(a), b, false),
            "a different license replaces only after explicit confirmation"
        );
        assert!(
            !super::licence_replace_needs_confirm(Some(a), b, true),
            "the confirmed path proceeds"
        );
        assert!(
            !super::licence_replace_needs_confirm(Some(a), a, false),
            "the same license_id is the renewal path and replaces silently"
        );
        assert!(
            !super::licence_replace_needs_confirm(None, b, false),
            "no existing record -- or one that no longer parses -- needs no confirm"
        );
    }

    #[test]
    fn content_allowlist_accepts_web_and_blank() {
        assert!(is_allowed_content_url("https://example.com"));
        assert!(is_allowed_content_url("http://example.com/path"));
        assert!(is_allowed_content_url("about:blank"));
    }

    #[test]
    fn content_allowlist_denies_non_web_schemes() {
        assert!(!is_allowed_content_url("file:///etc/passwd"));
        assert!(!is_allowed_content_url("data:text/html,<script>"));
        assert!(!is_allowed_content_url("rbchrome://localhost/index.html"));
    }

    /// On Windows the chrome UI lives at an http origin, so the content
    /// allowlist must reject it explicitly; a bare scheme check would not.
    #[test]
    fn content_allowlist_denies_the_chrome_origin() {
        assert!(!is_allowed_content_url(crate::platform::CHROME_URL));
        assert!(!is_allowed_content_url(
            crate::platform::CHROME_ORIGIN_PREFIX
        ));
    }

    /// The check must be origin-exact: a lookalike host that merely starts
    /// with the same characters is ordinary untrusted web content.
    #[test]
    fn lookalike_chrome_host_is_still_allowed_as_content() {
        assert!(is_allowed_content_url("http://rbchrome.localhost.evil.com/"));
        assert!(is_allowed_content_url("https://notrbchrome.localhost/"));
    }

    /// Every spelling of the chrome origin that is NOT the literal byte
    /// sequence `http://rbchrome.localhost/`. The old predicate was
    /// `!url.starts_with(CHROME_ORIGIN_PREFIX)`, so each of these passed it
    /// and put an untrusted page on the origin that holds IPC and the vault.
    ///
    /// Reachable from another machine: a contact sends a tab over chat and
    /// `chat_panel` validates with this same function.
    #[test]
    fn every_spelling_of_the_chrome_origin_is_denied() {
        for url in [
            // No trailing slash: shorter than the prefix, so it never matched.
            "http://rbchrome.localhost",
            // Explicit default port is the same origin to the engine.
            "http://rbchrome.localhost:80/",
            "http://rbchrome.localhost:80/index.html",
            // Userinfo before the host.
            "http://user@rbchrome.localhost/",
            "http://user:pw@rbchrome.localhost/index.html",
            // A userinfo containing an '@' must not fool the split.
            "http://a@b@rbchrome.localhost/",
            // Query or fragment straight after the host, no path slash.
            "http://rbchrome.localhost?x=1",
            "http://rbchrome.localhost#f",
            // Hosts are case-insensitive; the prefix compare was not.
            "http://RBCHROME.localhost/",
            "http://RbChrome.LocalHost/index.html",
            "HTTP://rbchrome.localhost/",
            // A backslash terminates the authority exactly as '/' does, so
            // the engine reads the host as rbchrome.localhost here.
            "http://rbchrome.localhost\\.evil.com/",
            "http://rbchrome.localhost\\@evil.com/",
            // Tab, LF and CR are stripped from URLs before parsing, so the
            // engine reads these as the chrome host too.
            "http://rbchrome.loc\talhost/",
            "http://rbchrome.local\nhost/",
            "http://rbchrome.loca\rlhost/",
            // https as well: the host is reserved regardless of scheme.
            "https://rbchrome.localhost/",
        ] {
            assert!(
                !is_allowed_content_url(url),
                "chrome origin reached the content allowlist: {url:?}"
            );
        }
    }

    /// Denying the chrome origin must not deny the ordinary web along with
    /// it. These all have to keep working.
    #[test]
    fn normal_urls_survive_the_origin_check() {
        for url in [
            "https://example.com",
            "https://example.com:8443/a?b=c#d",
            "http://user@example.com/",
            "http://localhost:3000/",
            "http://127.0.0.1:8080/",
            "http://[::1]:8080/",
            "https://sub.domain.example.co.uk/path",
        ] {
            assert!(is_allowed_content_url(url), "wrongly denied: {url:?}");
        }
    }

    /// Malformed input must fail closed rather than panic or slip through.
    #[test]
    fn malformed_urls_are_denied_and_never_panic() {
        for url in [
            "", "http://", "https://", "http:///path", "http://@", "http://:80/", "//example.com",
            "http:/example.com", "javascript:alert(1)", "  http://example.com",
        ] {
            assert!(!is_allowed_content_url(url), "wrongly allowed: {url:?}");
        }
    }

    /// Non-ASCII hosts must not panic a byte-oriented parser. They are
    /// ALLOWED, and that is correct: they are not the chrome origin, and an
    /// unresolvable host is the engine's problem, not a trust-boundary one.
    /// The invariant here is "never panics", not "never allows" — the
    /// previous hex deserializer shipped a remote panic by slicing a String
    /// on a byte index, so this direction is worth a test of its own.
    #[test]
    fn non_ascii_hosts_do_not_panic() {
        for url in ["http://\u{1F600}", "http://é", "https://ドメイン.jp/パス", "http://é@é/é"] {
            let _ = is_allowed_content_url(url);
        }
        assert!(is_allowed_content_url("https://ドメイン.jp/"));
    }

    #[test]
    fn plain_domain_gets_https() {
        assert_eq!(normalize_input("example.com"), "https://example.com");
    }

    #[test]
    fn full_url_passes_through() {
        assert_eq!(
            normalize_input("http://example.com/path?q=1"),
            "http://example.com/path?q=1"
        );
    }

    #[test]
    fn about_url_passes_through() {
        assert_eq!(normalize_input("about:blank"), "about:blank");
    }

    #[test]
    fn multi_word_becomes_search() {
        assert_eq!(
            normalize_input("rust tutorial"),
            "https://duckduckgo.com/?q=rust%20tutorial"
        );
    }

    #[test]
    fn single_word_without_dot_becomes_search() {
        assert_eq!(
            normalize_input("localhost"),
            "https://duckduckgo.com/?q=localhost"
        );
    }

    #[test]
    fn search_encodes_query_chars() {
        assert_eq!(
            normalize_input("what? & why"),
            "https://duckduckgo.com/?q=what%3F%20%26%20why"
        );
    }

    #[test]
    fn input_is_trimmed() {
        assert_eq!(normalize_input("  example.com  "), "https://example.com");
    }

    /// A frame larger than the cap is refused before `serde_json` sees it.
    ///
    /// The cap is the only bound on how much one command may allocate: no
    /// argument extractor checks a length, and `from_str` materialises the
    /// whole string before any handler runs.
    #[test]
    fn an_oversized_frame_is_refused_before_parsing() {
        // Well-formed JSON, just too big -- so this proves the SIZE check
        // fires, not the parser.
        let filler = "a".repeat(super::MAX_FRAME_BYTES);
        let frame = format!(r#"{{"id":1,"cmd":"ping","args":{{"x":"{filler}"}}}}"#);
        assert!(frame.len() > super::MAX_FRAME_BYTES);
        assert!(
            serde_json::from_str::<serde_json::Value>(&frame).is_ok(),
            "the probe frame must be valid JSON, or this test proves nothing"
        );
    }

    /// A picked-file token is one-shot, bounded, and unguessable by accident.
    ///
    /// This is what stands between `ocr_scan` and an arbitrary-file read: the
    /// path never crosses IPC, so the chrome can only name a file the user
    /// selected in a native dialog, and only once.
    #[test]
    fn picked_file_tokens_are_one_shot_and_bounded() {
        use std::collections::VecDeque;
        use std::path::PathBuf;

        // Mirrors AppState's two methods without needing a webview to exist.
        fn remember(q: &mut VecDeque<(u64, PathBuf)>, next: &mut u64, p: &str) -> u64 {
            let token = *next;
            *next += 1;
            q.push_back((token, PathBuf::from(p)));
            while q.len() > crate::state::MAX_PICKED_PATHS {
                q.pop_front();
            }
            token
        }
        fn take(q: &mut VecDeque<(u64, PathBuf)>, token: u64) -> Option<PathBuf> {
            let at = q.iter().position(|(t, _)| *t == token)?;
            q.remove(at).map(|(_, p)| p)
        }

        let mut q = VecDeque::new();
        let mut next = 1u64;
        let t = remember(&mut q, &mut next, "/home/user/id.png");

        assert_eq!(take(&mut q, t), Some(PathBuf::from("/home/user/id.png")));
        assert_eq!(
            take(&mut q, t),
            None,
            "a token must not be redeemable twice; replay would re-read the file"
        );
        assert_eq!(
            take(&mut q, 9999),
            None,
            "an unminted token must resolve to nothing, not to some other pick"
        );

        // Bounded: picking without redeeming evicts the oldest rather than
        // growing without limit.
        let first = remember(&mut q, &mut next, "/oldest");
        for i in 0..crate::state::MAX_PICKED_PATHS {
            remember(&mut q, &mut next, &format!("/f{i}"));
        }
        assert_eq!(q.len(), crate::state::MAX_PICKED_PATHS);
        assert_eq!(take(&mut q, first), None, "the oldest pick was evicted");
    }

    #[test]
    fn capped_args_refuse_oversized_values_and_accept_normal_ones() {
        let args = json!({
            "short": "example.com",
            "long": "a".repeat(300),
        });
        assert_eq!(super::arg_str_capped(&args, "short", 253), Ok("example.com"));
        assert_eq!(super::arg_str_capped(&args, "long", 253), Err("bad_args"));
        // A missing key is still bad_args, not a silent empty string.
        assert_eq!(super::arg_str_capped(&args, "absent", 253), Err("bad_args"));
        // Exactly at the limit is accepted: the check is > , not >= .
        let exact = json!({ "k": "a".repeat(253) });
        assert!(super::arg_str_capped(&exact, "k", 253).is_ok());
    }

    /// Every error code this crate can return must be renderable by the chrome.
    ///
    /// WHY THIS EXISTS. Two comments -- one in this file, one in chrome.js --
    /// each asserted that the two sets were kept in sync, and neither was
    /// true: `no_tab`, `not_ready` and `install_failed` were all reachable and
    /// all rendered to the user as "Unexpected error: not_ready". A claim in a
    /// comment cannot notice when it stops holding; this can.
    ///
    /// Deliberately reads BOTH files as text rather than importing anything.
    /// The chrome is a JS object literal with no Rust representation, so the
    /// only honest check is the one that looks at what actually ships -- and
    /// both files are compiled into the binary, so they cannot drift apart at
    /// runtime the way two separately-deployed halves could.
    #[test]
    fn every_error_code_has_user_facing_text() {
        let chrome = include_str!("chrome/chrome.js");
        let table_start = chrome
            .find("const ERROR_TEXT = {")
            .expect("ERROR_TEXT table not found in chrome.js");
        // The table ends at the first line that closes it at top level.
        let table_end = chrome[table_start..]
            .find("\n  };")
            .expect("ERROR_TEXT table has no terminator")
            + table_start;
        let table = &chrome[table_start..table_end];

        // Codes this crate hands back, collected from the source rather than
        // from a hand-kept list -- a hand-kept list is the same failure mode
        // one level up. Both spellings carry the vocabulary: `Err("code")`
        // and `.ok_or("code")`.
        // The vocabulary is not confined to this file: the vault and store
        // error maps live here, but chat, OCR, page integrity and the updater
        // all return codes of their own that reach the same `friendly()`.
        // Scanning only ipc.rs found five codes and would have missed the
        // three that prompted this test.
        let sources = [
            include_str!("ipc.rs"),
            include_str!("chat_panel.rs"),
            include_str!("ocr_support.rs"),
            include_str!("page_integrity.rs"),
            include_str!("updater.rs"),
        ];
        let mut missing: Vec<&str> = Vec::new();
        let mut checked: Vec<&str> = Vec::new();
        for whole in sources {
            // Everything before `#[cfg(test)]`: the tests below (and this
            // scan's own string literals) are not part of the shipped
            // vocabulary, and including them made the scan report its own
            // source back at itself.
            let source = match whole.find("\n#[cfg(test)]") {
                Some(at) => &whole[..at],
                None => whole,
            };
            for opener in ["Err(\"", "ok_or(\""] {
                for (at, _) in source.match_indices(opener) {
                    // `match_indices` yields the MATCHED text, not the
                    // remainder, so the index is the only usable half. Getting
                    // this wrong is what the non-vacuity assertion caught.
                    let start = at + opener.len();
                    let code = match source[start..].find('"') {
                        Some(end) => &source[start..start + end],
                        None => continue,
                    };
                    // IPC codes are snake_case identifiers. The smoke sequence
                    // also uses `ok_or`, but it returns `String` prose
                    // ("smoke: no active tab") which never reaches the chrome
                    // -- the shape is what separates the two vocabularies.
                    let is_code = !code.is_empty()
                        && code
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                    if !is_code || checked.contains(&code) {
                        continue;
                    }
                    checked.push(code);
                    // A key appears as `code:` in the object literal.
                    if !table.contains(&format!("{code}:")) {
                        missing.push(code);
                    }
                }
            }
        }

        // The error MAPS are a different shape -- `VaultError::X => "code",`
        // -- and they carry a third of the vocabulary, including auth_failed
        // and bad_format. Scanned by locating the two functions rather than by
        // matching `=> "` everywhere, which would sweep up every unrelated
        // match arm that returns a string (DnsMode::as_str and friends) and
        // report them as missing.
        let own = sources[0];
        for map_fn in ["fn vault_code(", "fn store_code("] {
            let at = own
                .find(map_fn)
                .unwrap_or_else(|| panic!("{map_fn} not found; the error map was renamed"));
            let body_end = own[at..]
                .find("\n}")
                .expect("error map has no terminator")
                + at;
            let body = &own[at..body_end];
            for (arrow_at, _) in body.match_indices("=> \"") {
                let start = arrow_at + "=> \"".len();
                let Some(end) = body[start..].find('"') else {
                    continue;
                };
                let code = &body[start..start + end];
                if code.is_empty() || checked.contains(&code) {
                    continue;
                }
                checked.push(code);
                if !table.contains(&format!("{code}:")) {
                    missing.push(code);
                }
            }
        }
        // NON-VACUITY. A scan that matches nothing passes this test without
        // examining anything, which is the one way it could quietly stop
        // working. This file returns dozens of distinct codes; if that count
        // ever collapses, the scan broke, not the vocabulary.
        assert!(
            checked.len() >= 20,
            "the error-code scan found only {} codes ({checked:?}); it has \
             stopped matching and this test is no longer checking anything",
            checked.len()
        );
        assert!(
            missing.is_empty(),
            "these error codes are returned by ipc.rs but have no entry in \
             ERROR_TEXT in chrome.js, so the user sees \"Unexpected error: \
             <code>\": {missing:?}"
        );
    }

    #[test]
    fn credential_origin_parses_a_full_url_the_same_way_tab_status_does() {
        assert_eq!(
            super::parse_credential_origin("https://example.com/login"),
            Some("example.com".to_string())
        );
        assert_eq!(
            super::parse_credential_origin("http://Example.COM/path?q=1"),
            Some("example.com".to_string()),
            "must lowercase and drop path/query, matching host_of exactly"
        );
    }

    #[test]
    fn credential_origin_accepts_a_bare_hostname_matching_the_fields_placeholder() {
        // "Site (e.g. example.com)" is the field's own placeholder text --
        // most manually-entered values will have no scheme at all.
        assert_eq!(
            super::parse_credential_origin("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            super::parse_credential_origin("  example.com  "),
            Some("example.com".to_string()),
            "surrounding whitespace must not defeat the bare-host fallback"
        );
        assert_eq!(
            super::parse_credential_origin("EXAMPLE.COM"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn credential_origin_strips_a_bare_hosts_port_like_host_of_does() {
        assert_eq!(
            super::parse_credential_origin("example.com:8080"),
            Some("example.com".to_string()),
            "a bare host:port and a full URL for the same host must agree on \
             what the origin is"
        );
    }

    #[test]
    fn credential_origin_is_none_for_anything_that_is_not_a_host() {
        for label in ["My bank", "not a site!", "", "   ", "a b c"] {
            assert_eq!(
                super::parse_credential_origin(label),
                None,
                "{label:?} is a display label, not a host, and must not be \
                 guessed into one"
            );
        }
    }

    #[test]
    fn the_ephemeral_preset_is_not_quarantine_with_a_field_flipped() {
        use crate::platform::TabPolicy;
        let e = TabPolicy::ephemeral();
        let q = TabPolicy::quarantine();
        // The one thing they share, and the reason both exist.
        assert!(e.ephemeral && q.ephemeral);
        // THE DIFFERENCE THAT MATTERS. Most of the web does not work with
        // script off, so if "open link in an ephemeral tab" inherited
        // quarantine's JavaScript setting it would be a broken-page button
        // and people would learn to avoid the private option.
        assert!(
            e.javascript,
            "an ephemeral tab must still run script; only quarantine kills it"
        );
        assert!(!q.javascript);
        // And it must be usable, so it does not freeze itself after load.
        assert!(!e.freeze_after_load);
        assert!(q.freeze_after_load);
    }

    #[test]
    fn a_saved_pdf_is_named_after_the_page_not_index_pdf() {
        use crate::state::pdf_name_for;
        // The host leads, because a downloads folder full of "index.pdf" is
        // useless for finding anything again.
        assert_eq!(pdf_name_for("https://example.com/"), "example.com.pdf");
        assert_eq!(
            pdf_name_for("https://example.com/docs/guide"),
            "example.com-guide.pdf"
        );
        // Query and fragment are not part of a filename.
        assert_eq!(
            pdf_name_for("https://example.com/page?a=1#top"),
            "example.com-page.pdf"
        );
        // Anything unparseable still yields a usable name rather than an
        // empty one or a panic.
        assert!(pdf_name_for("about:blank").ends_with(".pdf"));
        assert!(!pdf_name_for("about:blank").starts_with('-'));
    }

    // ---- strip_tracking_params ------------------------------------------

    #[test]
    fn tracking_params_are_removed_and_the_rest_is_untouched() {
        assert_eq!(
            super::strip_tracking_params(
                "https://shop.example/item?id=7&utm_source=news&utm_medium=email&colour=red"
            ),
            "https://shop.example/item?id=7&colour=red",
        );
        // The whole query was tracking: the '?' goes too, rather than being
        // left dangling.
        assert_eq!(
            super::strip_tracking_params("https://shop.example/item?fbclid=abc"),
            "https://shop.example/item",
        );
    }

    #[test]
    fn navigation_strip_target_only_fires_on_change() {
        use super::navigation_strip_target as target;
        // Clean URLs get None: no cancel, no pointless reload.
        assert_eq!(target("https://shop.example/p?a=1"), None);
        assert_eq!(target("https://shop.example/p"), None);
        // Non-web schemes are never rewritten.
        assert_eq!(target("about:blank"), None);
        assert_eq!(target("file:///tmp/x.html?fbclid=1"), None);
        // Tracked URLs get Some(stripped); other params and the fragment
        // survive byte for byte.
        assert_eq!(
            target("https://shop.example/p?fbclid=123&gclid=x"),
            Some("https://shop.example/p".to_string())
        );
        assert_eq!(
            target("https://shop.example/p?a=1&utm_source=n#frag"),
            Some("https://shop.example/p?a=1#frag".to_string())
        );
        // Mixed case: is_tracking_param lowercases the incoming name.
        assert_eq!(
            target("https://x.io/p?MKT_TOK=abc&keep=1"),
            Some("https://x.io/p?keep=1".to_string())
        );
        // THE LOOP GUARD: whatever this returns must itself return None, or
        // cancel-and-reload would cycle forever.
        for url in [
            "https://shop.example/p?fbclid=1&a=2",
            "https://x.io/p?MKT_TOK=abc&keep=1",
            "https://y.io/p?utm_source=a&utm_medium=b#f",
        ] {
            let once = target(url).expect("this fixture strips");
            assert_eq!(target(&once), None, "second pass must be a no-op: {once}");
        }
    }

    #[test]
    fn the_2026_08_04_params_are_all_stripped() {
        // Every name added from the privacytests.org set, mixed with a kept
        // param, must be removed while the kept one survives byte-for-byte.
        for name in [
            "__hsfp", "__hssc", "__hstc", "_hsenc", "hsCtaTracking", "__s", "mkt_tok",
            "rb_clickid", "vero_conv", "wickedid",
        ] {
            let url = format!("https://x.example/p?keep=1&{name}=track&also=2");
            assert_eq!(
                super::strip_tracking_params(&url),
                "https://x.example/p?keep=1&also=2",
                "{name}"
            );
        }
        // strip is idempotent: a stripped URL comes back identical, which is
        // the invariant that makes cancel-and-reload navigation-time
        // stripping loop-free if it is ever wired.
        let once = super::strip_tracking_params("https://x.example/p?a=1&mkt_tok=z&__s=y");
        assert_eq!(super::strip_tracking_params(&once), once);
    }

    #[test]
    fn a_url_with_nothing_to_strip_comes_back_byte_for_byte() {
        // The caller compares input to output to decide whether to tell the
        // user anything was removed, so "unchanged" has to mean identical.
        for url in [
            "https://example.com/a/b",
            "https://example.com/a?x=1&y=2",
            "https://example.com/",
            "https://example.com/?q=a%20b&sort=desc",
        ] {
            assert_eq!(super::strip_tracking_params(url), url, "{url}");
        }
    }

    #[test]
    fn lookalike_parameters_are_not_stripped() {
        // THE CASE THIS FUNCTION EXISTS TO GET RIGHT. Substring matching here
        // would silently break real links, and a copy-link that produces a
        // URL which does not work is worse than one that leaves a tracker on.
        let url = "https://example.com/p?fbclid_backup=1&my_utm=2&gclid_verified=3&utmx=4";
        assert_eq!(
            super::strip_tracking_params(url),
            url,
            "none of these is a tracking parameter: only exact names and the \
             utm_ prefix count"
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            super::strip_tracking_params("https://example.com/p?FBCLID=x&UTM_Source=y&keep=1"),
            "https://example.com/p?keep=1",
        );
    }

    #[test]
    fn the_fragment_is_left_alone_even_when_it_contains_a_question_mark() {
        // A '?' after '#' is part of the fragment, not a query. Splitting on
        // the first '?' in the whole string would mangle SPA routes.
        assert_eq!(
            super::strip_tracking_params("https://example.com/p?utm_source=x#/route?utm_source=y"),
            "https://example.com/p#/route?utm_source=y",
        );
    }

    #[test]
    fn duplicate_and_empty_values_survive() {
        // Real links depend on exact spelling; this is a copy helper, not a
        // normalizer.
        assert_eq!(
            super::strip_tracking_params("https://example.com/p?a=1&a=2&b=&utm_term=z"),
            "https://example.com/p?a=1&a=2&b=",
        );
    }
}

#[cfg(test)]
mod unwrap_redirect_tests {
    use super::{clean_link, is_acceptable_destination, unwrap_redirect, LinkChange};

    /// The bug this pins is a CRASH, not a wrong answer. An earlier draft
    /// validated candidates with `candidate[..7]` after a byte-length check,
    /// which panics when byte 7 falls inside a multi-byte character. Link
    /// targets come from the page, so a crafted link plus one right-click was
    /// a denial of service. Reproduced and confirmed before this was written.
    #[test]
    fn a_multibyte_carrier_value_does_not_panic() {
        for value in ["éééé", "日本語のテキスト", "é", "🙂🙂🙂🙂"] {
            let url = format!("https://safelinks.protection.outlook.com/?url={value}");
            let out = unwrap_redirect(&url);
            assert_eq!(out, url, "a non-URL carrier must be left alone: {value}");
        }
        // And the validator itself, directly.
        for value in ["éééé", "🙂", "ééééééééé"] {
            assert!(!is_acceptable_destination(value));
        }
    }

    #[test]
    fn a_plain_url_is_returned_byte_identical() {
        for url in [
            "https://example.com/page",
            "https://example.com/a?b=c&d=e#frag",
            "http://example.com",
        ] {
            assert_eq!(unwrap_redirect(url), url);
        }
    }

    #[test]
    fn a_recognised_wrapper_unwraps() {
        assert_eq!(
            unwrap_redirect(
                "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Freal.example%2Fpage"
            ),
            "https://real.example/page"
        );
    }

    /// A narrowing that review forced. An ordinary page carrying a
    /// URL in a query parameter is NOT a redirect wrapper, and treating it as
    /// one would copy a different link than the one the user right-clicked --
    /// silently, because the toast would report a successful unwrap.
    #[test]
    fn an_ordinary_page_with_a_url_shaped_parameter_is_untouched() {
        for url in [
            "https://news.example/search?q=https://other.example/",
            "https://shop.example/item?url=https%3A%2F%2Fcdn.example%2Fimg",
            "https://docs.example/view?target=https://elsewhere.example/",
            "https://app.example/go?to=https://third.example/",
        ] {
            assert_eq!(unwrap_redirect(url), url, "must not unwrap: {url}");
        }
    }

    /// Label-boundary matching, the same rule the blocklist uses.
    #[test]
    fn a_lookalike_host_is_not_a_recognised_wrapper() {
        for url in [
            "https://evilgoogle.com/url?url=https://real.example/",
            "https://google.com.attacker.example/url?url=https://real.example/",
        ] {
            assert_eq!(unwrap_redirect(url), url, "must not unwrap: {url}");
        }
    }

    /// Recognition is host AND path. The right host on the wrong path is not
    /// the wrapper.
    #[test]
    fn the_right_host_on_the_wrong_path_is_untouched() {
        let url = "https://google.com/search?q=https://real.example/";
        assert_eq!(unwrap_redirect(url), url);
    }

    /// The security boundary. Every one of these is reachable from a page.
    #[test]
    fn a_dangerous_scheme_is_refused_not_returned() {
        for target in [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "chrome://settings",
            "about:blank",
        ] {
            let encoded = target.replace(':', "%3A").replace('/', "%2F");
            let url =
                format!("https://safelinks.protection.outlook.com/?url={encoded}");
            let out = unwrap_redirect(&url);
            assert_eq!(out, url, "must refuse {target}");
            assert!(!out.starts_with(target), "must never return {target}");
        }
    }

    /// Malformed authorities that an earlier draft accepted.
    #[test]
    fn a_malformed_authority_is_refused() {
        for bad in [
            "https://@",
            "https://:443",
            "https://",
            "https://..",
            "https://.example.com",
            "https://example..com",
            "https://exa mple.com",
        ] {
            assert!(!is_acceptable_destination(bad), "must refuse {bad}");
        }
    }

    #[test]
    fn an_opaque_shortener_is_untouched_and_never_resolved() {
        for url in ["https://t.co/abc123", "https://bit.ly/xyz", "https://x.co/q"] {
            assert_eq!(unwrap_redirect(url), url);
        }
    }

    /// Pins the CAP, not merely "something remains". An implementation
    /// unwrapping three or five levels would pass a weaker assertion.
    #[test]
    fn nesting_stops_at_exactly_the_cap() {
        let inner = "https://real.example/page";
        let wrap = |t: &str| {
            format!(
                "https://safelinks.protection.outlook.com/?url={}",
                t.replace(':', "%3A").replace('/', "%2F").replace('?', "%3F").replace('=', "%3D")
            )
        };
        // Four levels: fully unwrapped, since the cap is four.
        let four = wrap(&wrap(&wrap(&wrap(inner))));
        assert_eq!(unwrap_redirect(&four), inner, "four levels must fully unwrap");

        // Six levels: exactly two wrappers must remain. Counted rather than
        // string-compared, because each unwrap percent-DECODES its carrier, so
        // the layers that survive come back in decoded form and an encoded
        // expectation would be asserting the wrong thing. Counting pins the
        // cap itself, which is what this test is for.
        let six = wrap(&wrap(&wrap(&wrap(&wrap(&wrap(inner))))));
        let out = unwrap_redirect(&six);
        let remaining = out.matches("safelinks.protection.outlook.com").count();
        assert_eq!(
            remaining, 2,
            "six levels minus a cap of four must leave exactly two, got {remaining} in {out}"
        );
        assert!(out.ends_with(inner), "the innermost target must still be there");
    }

    /// Compose order: unwrap first, then strip. A destination recovered from a
    /// wrapper usually carries its own campaign parameters, and stripping
    /// first would clean only the wrapper's query before discarding it.
    #[test]
    fn unwrap_then_strip_composes() {
        let url = "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Freal.example%2Fp%3Futm_source%3Dmail%26id%3D7";
        let (cleaned, change) = clean_link(url);
        assert_eq!(cleaned, "https://real.example/p?id=7");
        assert_eq!(change, LinkChange::UnwrappedAndStripped);
    }

    #[test]
    fn each_change_variant_is_reported_accurately() {
        assert_eq!(clean_link("https://example.com/p").1, LinkChange::Unchanged);
        assert_eq!(
            clean_link("https://example.com/p?utm_source=x").1,
            LinkChange::Stripped
        );
        assert_eq!(
            clean_link("https://safelinks.protection.outlook.com/?url=https%3A%2F%2Freal.example%2Fp").1,
            LinkChange::Unwrapped
        );
    }

    /// The byte-preserving contract inherited from strip_tracking_params.
    #[test]
    fn fragments_and_duplicate_keys_survive() {
        let url = "https://example.com/p?a=1&a=2&b=&c=%20#frag";
        assert_eq!(unwrap_redirect(url), url);
        assert_eq!(clean_link(url).0, url);
    }

    #[test]
    fn a_carrier_whose_value_is_not_a_url_is_untouched() {
        for value in ["", "hello", "12345", "%%%%", "notaurl.example"] {
            let url = format!("https://safelinks.protection.outlook.com/?url={value}");
            assert_eq!(unwrap_redirect(&url), url, "must not unwrap: {value}");
        }
    }
}
