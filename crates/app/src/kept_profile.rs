//! Kept sites live in their own WebView2 profile (Windows, 1.0.7).
//!
//! WHY. PATANYX clears every site's data at each start. The keep-list lets a
//! person name sites that should survive (Messenger keeps its end-to-end keys
//! in IndexedDB, and loses minutes re-downloading its history otherwise). The
//! first keep-list (1.0.1) kept those sites by switching the whole start-up
//! clear to a site-by-site one, and that could not be complete: the engine has
//! no "clear everything except" and no list of origins with storage, so data
//! stored at www. while the cookie named the parent domain, on a port, or
//! without a cookie survived for sites nobody kept (measured on Windows,
//! release-108-notes/messenger-keep/FINDINGS.md).
//!
//! THE SHAPE NOW. Two user-data folders. MAIN holds everything else and is
//! always cleared in full, with the engine's own complete clear. KEPT holds
//! only kept sites, and only kept sites ever load as a tab's page there:
//! everything in it was put there by a site the person chose to keep, or by
//! something those sites embed. This module holds the rules; windows.rs and
//! state.rs apply them. Everything here is pure, so every rule is tested on
//! every platform.

use std::sync::RwLock;

/// Which of the two profiles a tab's pages live in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileKind {
    /// Cleared in full at every start. The default.
    Main,
    /// Kept sites only. Survives starts.
    Kept,
}

/// The keep-list as the request handlers see it, updated by AppState at start
/// and whenever the list changes. A handler cannot read prefs from disk per
/// request; this is the in-memory copy, and the only one.
static KEPT_HOSTS: RwLock<Vec<String>> = RwLock::new(Vec::new());

pub fn set_kept_hosts(hosts: &[String]) {
    if let Ok(mut current) = KEPT_HOSTS.write() {
        *current = hosts.to_vec();
    }
}

pub fn kept_hosts() -> Vec<String> {
    KEPT_HOSTS.read().map(|h| h.clone()).unwrap_or_default()
}

/// Whether `host` belongs to a kept site (the host or a subdomain of a kept
/// entry, dot boundaries: the keep-list's own rule).
pub fn is_kept_host(kept: &[String], host: &str) -> bool {
    crate::prefs::wipe_exempts(kept, host)
}

/// The profile a page at `url` belongs in. Only http(s) pages on a kept host,
/// in a tab that keeps data at all (not private), and only where this platform
/// has the second profile.
pub fn kind_for_url(url: &str, kept: &[String], ephemeral: bool, supported: bool) -> ProfileKind {
    if !supported || ephemeral {
        return ProfileKind::Main;
    }
    match host_of_page(url) {
        Some(host) if is_kept_host(kept, &host) => ProfileKind::Kept,
        _ => ProfileKind::Main,
    }
}

/// The host of an http(s) page URL, lowercased, or None.
pub fn host_of_page(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Whether the KEPT profile's start cleanup keeps a cookie set for `domain`.
///
/// Kept: a cookie on a kept host or one of its subdomains, and a cookie on an
/// ANCESTOR of a kept host that is still inside that host's registrable domain
/// (a login cookie on `.example.test` serves kept `app.example.test`; plan
/// review 2026-10-13, R-020). Never a cookie on a bare public suffix.
/// Everything else in KEPT came from something a kept site embedded, and goes.
pub fn retain_kept_cookie(kept: &[String], domain: &str) -> bool {
    let domain = domain.trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    if is_kept_host(kept, &domain) {
        return true;
    }
    kept.iter().any(|keep| {
        let Some(registrable) = crate::psl::registrable_domain(keep) else {
            return false;
        };
        let inside_registrable =
            domain == registrable || domain.ends_with(&format!(".{registrable}"));
        let ancestor_of_keep = keep.ends_with(&format!(".{domain}"));
        inside_registrable && ancestor_of_keep
    })
}

/// What the KEPT profile needs at this start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeptStart {
    /// Delete cookies that `retain_kept_cookie` does not keep, and the HTTP
    /// cache. Storage stays: only kept sites wrote it as a page.
    Cleanup,
    /// Clear the whole profile: a site that was kept is not kept any more,
    /// and its storage cannot be found reliably on its own.
    FullClear,
}

/// `admitted` is every host added to the keep-list since KEPT was last
/// cleared in full (the ledger below); `kept` is the list now. A host
/// admitted and since removed -- even removed in the same session it was
/// added -- forces the full clear (plan review 2026-10-13, R-016).
pub fn kept_start(admitted: &[String], kept: &[String]) -> KeptStart {
    if admitted.iter().all(|a| kept.iter().any(|k| k == a)) {
        KeptStart::Cleanup
    } else {
        KeptStart::FullClear
    }
}

// ---- THE LEDGER --------------------------------------------------------
//
// What the kept profile owes, in its own file beside it (WebView2-kept.ledger),
// one entry per line: every site admitted since the profile was last cleared
// in full, and `!` markers for things that could not be enforced or cleared.
// NOT in prefs: another running PATANYX, a failed save or a damaged settings
// file could each lose it there (code review round 2, R-037, R-040). Written
// only by the process holding the kept profile's lock: appended with a sync
// before a site can load there, rewritten (temp file, sync, rename) only after
// a full clear.

/// What reading the ledger found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerRead {
    /// No ledger file.
    Missing,
    /// A ledger that could not be read. Owed: nobody can prove what it held.
    Unreadable,
    Entries(Vec<String>),
}

/// The ledger's entries from its text. A line that is neither a plausible
/// host nor a `!marker` reads as `!malformed`, which no keep-list holds.
pub fn parse_ledger(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            if let Some(name) = line.strip_prefix('!') {
                if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    return line.to_string();
                }
                return "!malformed".to_string();
            }
            crate::prefs::normalize_wipe_exempt_host(line).unwrap_or_else(|| "!malformed".to_string())
        })
        .collect()
}

pub fn read_ledger_at(path: &std::path::Path) -> LedgerRead {
    match std::fs::read(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LedgerRead::Missing,
        Err(_) => LedgerRead::Unreadable,
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => LedgerRead::Entries(parse_ledger(&text)),
            Err(_) => LedgerRead::Unreadable,
        },
    }
}

pub fn write_ledger_at(path: &std::path::Path, entries: &[String]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("ledger-new");
    {
        let mut file = std::fs::File::create(&tmp)?;
        for entry in entries {
            file.write_all(format!("{entry}\n").as_bytes())?;
        }
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// What the kept profile needs at this start, from the ledger. A missing
/// ledger beside an existing kept folder, or an unreadable one, is owed the
/// full clear (R-040).
pub fn kept_start_from(read: &LedgerRead, folder_exists: bool, kept: &[String]) -> KeptStart {
    match read {
        LedgerRead::Missing if folder_exists => KeptStart::FullClear,
        LedgerRead::Missing => KeptStart::Cleanup,
        LedgerRead::Unreadable => KeptStart::FullClear,
        LedgerRead::Entries(entries) => kept_start(entries, kept),
    }
}

pub fn entries_of(read: &LedgerRead) -> Vec<String> {
    match read {
        LedgerRead::Entries(entries) => entries.clone(),
        _ => Vec::new(),
    }
}

/// The ledger after a full clear that this process's start decided on: the
/// sites kept now, plus every marker raised SINCE that start. A marker that
/// was already there was the reason for this clear and is retired; one raised
/// after (a tab whose enforcement failed while the clear ran) is not
/// (R-038).
pub fn after_clear(kept: &[String], current: &[String], markers_at_start: &[String]) -> Vec<String> {
    let mut entries: Vec<String> = kept.to_vec();
    for entry in current {
        if entry.starts_with('!') && !markers_at_start.contains(entry) && !entries.contains(entry) {
            entries.push(entry.clone());
        }
    }
    entries
}

static LEDGER_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
static MARKERS_AT_START: RwLock<Vec<String>> = RwLock::new(Vec::new());

pub fn set_ledger_path(path: std::path::PathBuf) {
    let _ = LEDGER_PATH.set(path);
}

pub fn set_markers_at_start(markers: Vec<String>) {
    if let Ok(mut current) = MARKERS_AT_START.write() {
        *current = markers;
    }
}

pub fn markers_at_start() -> Vec<String> {
    MARKERS_AT_START.read().map(|m| m.clone()).unwrap_or_default()
}

pub fn read_ledger() -> LedgerRead {
    match LEDGER_PATH.get() {
        Some(path) => read_ledger_at(path),
        None => LedgerRead::Missing,
    }
}

/// Adds one entry (a host, or a `!marker`) by rewriting the whole ledger
/// at once (temp file, sync, rename): a write that fails leaves the old
/// ledger exactly as it was, never a shorter one that reads as clean (code
/// review round 4). What could not be read is carried forward as a marker.
/// An error when there is no ledger path: nothing can be recorded, so
/// nothing may rely on it.
pub fn record(entry: &str) -> std::io::Result<()> {
    match LEDGER_PATH.get() {
        Some(path) => record_at(path, entry),
        None => Err(std::io::Error::other("no kept ledger")),
    }
}

pub fn record_at(path: &std::path::Path, entry: &str) -> std::io::Result<()> {
    let mut entries = match read_ledger_at(path) {
        LedgerRead::Entries(entries) => entries,
        LedgerRead::Unreadable => vec!["!unreadable-ledger".to_string()],
        LedgerRead::Missing if path.with_extension("").exists() => vec!["!missing-ledger".to_string()],
        LedgerRead::Missing => Vec::new(),
    };
    if !entries.iter().any(|e| e == entry) {
        entries.push(entry.to_string());
    }
    write_ledger_at(path, &entries)
}

/// When a marker cannot be written: the ledger is removed instead, and a
/// missing ledger beside the kept folder is owed the full clear
/// (`kept_start_from`), so the obligation outlives the process either way
/// (code review round 5). True when it is on disk; with no folder there
/// is nothing to clear.
pub fn forfeit_ledger() -> bool {
    LEDGER_PATH.get().is_some_and(|path| forfeit_ledger_at(path))
}

pub fn forfeit_ledger_at(path: &std::path::Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Whether the ledger can be written, tried with the write it really gets
/// (its own entries again: temp file, sync, rename): one that cannot be
/// may hold no record of an obligation raised while it could be neither
/// written nor removed, so the start that finds it so owes the full clear
/// (code review rounds 7 and 8). An absent ledger is decided by
/// `kept_start_from`; an unreadable one is not writable.
pub fn ledger_writable_at(path: &std::path::Path) -> bool {
    match read_ledger_at(path) {
        LedgerRead::Missing => true,
        LedgerRead::Unreadable => false,
        LedgerRead::Entries(entries) => write_ledger_at(path, &entries).is_ok(),
    }
}

pub fn ledger_writable() -> bool {
    LEDGER_PATH.get().is_none_or(|path| ledger_writable_at(path))
}

pub fn kept_folder_exists() -> bool {
    LEDGER_PATH.get().is_some_and(|path| path.with_extension("").exists())
}

/// The ledger to write once a full clear this start decided on completes:
/// `after_clear`, plus every marker raised this session that is not on
/// disk. From a ledger that cannot be read, or one missing beside the
/// folder, the clear is not credited: the result stays owed (code review
/// round 5).
pub fn ledger_after_clear(
    kept: &[String],
    read: &LedgerRead,
    folder_exists: bool,
    markers_at_start: &[String],
    unrecorded: &[String],
) -> Vec<String> {
    let mut entries = match read {
        LedgerRead::Entries(current) => after_clear(kept, current, markers_at_start),
        LedgerRead::Unreadable => after_clear(kept, &["!unreadable-ledger".to_string()], &[]),
        LedgerRead::Missing if folder_exists => after_clear(kept, &["!missing-ledger".to_string()], &[]),
        LedgerRead::Missing => kept.to_vec(),
    };
    for marker in unrecorded {
        if !entries.contains(marker) {
            entries.push(marker.clone());
        }
    }
    entries
}

pub fn write_ledger(entries: &[String]) -> std::io::Result<()> {
    match LEDGER_PATH.get() {
        Some(path) => write_ledger_at(path, entries),
        None => Err(std::io::Error::other("no kept ledger")),
    }
}

/// Whether the kept profile may hold anything: the ledger has an entry. What
/// "clear cookies for every site" leaves out follows this, not the current
/// keep-list (R-041).
///
/// Conservative: a ledger that cannot be read, or none beside an existing
/// kept folder, counts as holding something (code review round 3).
pub fn holds_kept_data() -> bool {
    let Some(path) = LEDGER_PATH.get() else {
        return false;
    };
    match read_ledger_at(path) {
        LedgerRead::Entries(entries) => !entries.is_empty(),
        LedgerRead::Unreadable => true,
        LedgerRead::Missing => path.with_extension("").exists(),
    }
}

/// Every host in `hosts` recorded in the ledger before it is used
/// (admission before use, code review round 3, R-046): the list another
/// PATANYX wrote included. Returns the hosts that ARE recorded; one that
/// could not be is left out, so it is never treated as kept.
pub fn admit(hosts: &[String]) -> Vec<String> {
    let recorded = entries_of(&read_ledger());
    hosts
        .iter()
        .filter(|host| recorded.contains(host) || record(host).is_ok())
        .cloned()
        .collect()
}

/// Whether the page at `url` is on the site just added to the keep list,
/// the only page Keep reopens at once: a page on a site kept earlier and
/// still in an ordinary tab moves at its own next navigation, not because
/// another site was added (code review round 10).
pub fn added_covers(url: &str, added: &str) -> bool {
    kind_for_url(url, &[added.to_string()], false, true) == ProfileKind::Kept
}

/// How a KEPT tab answers a DOCUMENT request (page or frame) for `host`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeptDocument {
    /// A kept host, or provably a subframe: load it.
    Allow,
    /// Not kept and possibly the tab's own page: refuse, and (first time for
    /// this navigation) open the page in a MAIN tab.
    RefuseAndMove,
    /// Not kept and not provably a subframe: refuse, nothing else. Unknown is
    /// never allowed (plan review 2026-10-13, R-015).
    Refuse,
}

/// The rule for KEPT tabs, which FAILS CLOSED. `matches_top_level` is whether
/// the request's host equals the host of any top-level navigation in flight
/// in this tab (consumed by an earlier request or not: an old frame can win
/// the race for the slot); `provably_frame` is whether frame tracking is on,
/// no frame navigation is unreadable, and a frame navigation to this URL is
/// in flight.
pub fn kept_document(kept: &[String], host: &str, matches_top_level: bool, provably_frame: bool) -> KeptDocument {
    if is_kept_host(kept, host) {
        KeptDocument::Allow
    } else if matches_top_level {
        KeptDocument::RefuseAndMove
    } else if provably_frame {
        KeptDocument::Allow
    } else {
        KeptDocument::Refuse
    }
}

/// What a tab shows where a page was moved to the other profile: plainly not
/// the site, with no copy (the chrome's notice says where the page went) and a
/// policy that runs nothing. Served with the held page's per-process marker,
/// so no capture can take it for the site's own document.
pub const MOVED_PLACEHOLDER_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\">\
<title>PATANYX moved this page</title>\
<style>html,body{margin:0;height:100%;background:#1c1c1e}</style>\
</head><body></body></html>";

/// How long a tab opened by a crossing may not itself cross again (R-019):
/// long enough to stop a redirect loop between a kept site and another site
/// from opening tab after tab, short enough not to get in the way of a person
/// following links.
pub const CROSSING_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether a crossing requested by a tab may open a new tab now.
pub fn crossing_allowed(opened_by_crossing_at: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    opened_by_crossing_at.is_none_or(|at| now.saturating_duration_since(at) >= CROSSING_COOLDOWN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn list(hosts: &[&str]) -> Vec<String> {
        hosts.iter().map(|h| h.to_string()).collect()
    }

    #[test]
    fn a_page_is_kept_only_on_a_kept_host_in_a_saving_tab_where_supported() {
        let kept = list(&["messenger.com", "facebook.com"]);
        for url in [
            "https://www.messenger.com/t/1",
            "https://messenger.com/",
            "https://www.facebook.com/messages/",
            "http://facebook.com/",
        ] {
            assert_eq!(kind_for_url(url, &kept, false, true), ProfileKind::Kept, "{url}");
            assert_eq!(kind_for_url(url, &kept, true, true), ProfileKind::Main, "private tab: {url}");
            assert_eq!(kind_for_url(url, &kept, false, false), ProfileKind::Main, "unsupported: {url}");
        }
        for url in [
            "https://notfacebook.com/",
            "https://facebook.com.evil.example/",
            "https://www.google.com/",
            "about:blank",
            "file:///C:/x.html",
            "not a url",
        ] {
            assert_eq!(kind_for_url(url, &kept, false, true), ProfileKind::Main, "{url}");
        }
        assert_eq!(kind_for_url("https://www.messenger.com/", &[], false, true), ProfileKind::Main);
    }

    #[test]
    fn kept_cookies_are_the_kept_sites_and_their_parent_domains_only() {
        let kept = list(&["app.example.test", "messenger.com"]);
        for domain in [
            "app.example.test",
            ".app.example.test",
            "x.app.example.test",
            ".example.test",
            "example.test",
            "messenger.com",
            ".messenger.com",
            "www.messenger.com",
        ] {
            assert!(retain_kept_cookie(&kept, domain), "{domain} should stay");
        }
        for domain in [
            "other.example.test",
            ".test",
            "test",
            "facebook.com",
            "notmessenger.com",
            "tracker.example",
            "",
            ".",
        ] {
            assert!(!retain_kept_cookie(&kept, domain), "{domain} should go");
        }
    }

    #[test]
    fn a_removed_site_forces_the_full_clear_even_if_added_and_removed_in_one_session() {
        assert_eq!(kept_start(&[], &[]), KeptStart::Cleanup);
        assert_eq!(kept_start(&list(&["a.test"]), &list(&["a.test"])), KeptStart::Cleanup);
        assert_eq!(kept_start(&list(&["a.test"]), &list(&["a.test", "b.test"])), KeptStart::Cleanup);
        // b.test was added and removed since the last full clear.
        assert_eq!(kept_start(&list(&["a.test", "b.test"]), &list(&["a.test"])), KeptStart::FullClear);
        // The last kept site removed.
        assert_eq!(kept_start(&list(&["a.test"]), &[]), KeptStart::FullClear);
    }

    #[test]
    fn the_ledger_reads_hosts_and_markers_and_nothing_else() {
        assert_eq!(
            parse_ledger("messenger.com\n\n  Facebook.com \n!cache\n"),
            list(&["messenger.com", "facebook.com", "!cache"])
        );
        assert_eq!(parse_ledger("not a host\n!\n!bad marker\n"), list(&["!malformed", "!malformed", "!malformed"]));
    }

    #[test]
    fn a_ledger_that_cannot_be_trusted_owes_the_full_clear() {
        let kept = list(&["messenger.com"]);
        assert_eq!(kept_start_from(&LedgerRead::Unreadable, false, &kept), KeptStart::FullClear);
        assert_eq!(kept_start_from(&LedgerRead::Missing, true, &kept), KeptStart::FullClear);
        assert_eq!(kept_start_from(&LedgerRead::Missing, false, &kept), KeptStart::Cleanup);
        let ok = LedgerRead::Entries(list(&["messenger.com"]));
        assert_eq!(kept_start_from(&ok, true, &kept), KeptStart::Cleanup);
        let marked = LedgerRead::Entries(list(&["messenger.com", "!enforcement"]));
        assert_eq!(kept_start_from(&marked, true, &kept), KeptStart::FullClear);
        let removed = LedgerRead::Entries(list(&["messenger.com", "old.test"]));
        assert_eq!(kept_start_from(&removed, true, &kept), KeptStart::FullClear);
    }

    #[test]
    fn a_clear_retires_only_the_markers_that_caused_it() {
        let kept = list(&["messenger.com"]);
        let current = list(&["messenger.com", "old.test", "!cache", "!interception"]);
        let at_start = list(&["!cache"]);
        assert_eq!(after_clear(&kept, &current, &at_start), list(&["messenger.com", "!interception"]));
    }

    #[test]
    fn keep_reopens_only_the_site_just_added() {
        assert!(added_covers("https://www.messenger.com/t/1", "messenger.com"));
        assert!(added_covers("https://messenger.com/", "messenger.com"));
        // Another site, kept earlier or not, is not reopened by this Keep.
        assert!(!added_covers("https://www.facebook.com/", "messenger.com"));
        assert!(!added_covers("https://notmessenger.com/", "messenger.com"));
        assert!(!added_covers("about:blank", "messenger.com"));
    }

    #[test]
    fn a_clear_is_not_credited_from_a_ledger_it_cannot_read() {
        let kept = list(&["messenger.com"]);
        let unrecorded = list(&["!enforcement"]);
        // Readable: retired as before, plus what is only in memory.
        let read = LedgerRead::Entries(list(&["messenger.com", "!cache"]));
        let after = ledger_after_clear(&kept, &read, true, &list(&["!cache"]), &unrecorded);
        assert_eq!(after, list(&["messenger.com", "!enforcement"]));
        assert_eq!(kept_start_from(&LedgerRead::Entries(after), true, &kept), KeptStart::FullClear);
        // Removed or unreadable since the start: still owed.
        for read in [LedgerRead::Missing, LedgerRead::Unreadable] {
            let after = ledger_after_clear(&kept, &read, true, &list(&["!missing-ledger"]), &[]);
            assert_eq!(kept_start_from(&LedgerRead::Entries(after), true, &kept), KeptStart::FullClear);
        }
        // A trusted ledger with nothing raised since: clean.
        let read = LedgerRead::Entries(list(&["messenger.com", "!owed-clear"]));
        let after = ledger_after_clear(&kept, &read, true, &list(&["!owed-clear"]), &[]);
        assert_eq!(kept_start_from(&LedgerRead::Entries(after), true, &kept), KeptStart::Cleanup);
    }

    #[test]
    fn a_ledger_is_writable_when_absent_or_openable() {
        let dir = std::env::temp_dir().join(format!("kept-ledger-writable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("WebView2-kept.ledger");
        assert!(ledger_writable_at(&path), "absent");
        write_ledger_at(&path, &list(&["messenger.com"])).unwrap();
        assert!(ledger_writable_at(&path), "present");
        // A directory where the ledger should be cannot be opened for
        // writing on any platform, whatever the user's privileges.
        let blocked = dir.join("blocked.ledger");
        std::fs::create_dir_all(&blocked).unwrap();
        assert!(!ledger_writable_at(&blocked), "unwritable");
        assert_eq!(read_ledger_at(&path), LedgerRead::Entries(list(&["messenger.com"])), "probing changes nothing");
        // Appendable, but the rewrite the ledger really gets cannot happen
        // (its temp file's path is taken): not writable, and untouched
        // (code review round 9).
        std::fs::create_dir_all(path.with_extension("ledger-new")).unwrap();
        assert!(std::fs::OpenOptions::new().append(true).open(&path).is_ok(), "still appendable");
        assert!(!ledger_writable_at(&path), "a rewrite that cannot happen");
        assert_eq!(read_ledger_at(&path), LedgerRead::Entries(list(&["messenger.com"])), "left as it was");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_forfeited_ledger_is_owed_the_full_clear() {
        let dir = std::env::temp_dir().join(format!("kept-ledger-forfeit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("WebView2-kept")).unwrap();
        let path = dir.join("WebView2-kept.ledger");
        write_ledger_at(&path, &list(&["messenger.com"])).unwrap();
        assert!(forfeit_ledger_at(&path));
        assert_eq!(kept_start_from(&read_ledger_at(&path), true, &list(&["messenger.com"])), KeptStart::FullClear);
        assert!(forfeit_ledger_at(&path), "already gone counts");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recording_into_an_untrusted_ledger_keeps_it_owed() {
        let dir = std::env::temp_dir().join(format!("kept-ledger-owed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("WebView2-kept")).unwrap();
        let path = dir.join("WebView2-kept.ledger");
        // Missing beside an existing kept folder: the first write keeps
        // the obligation.
        record_at(&path, "!owed-clear").unwrap();
        let read = read_ledger_at(&path);
        assert_eq!(read, LedgerRead::Entries(list(&["!missing-ledger", "!owed-clear"])));
        assert_eq!(kept_start_from(&read, true, &[]), KeptStart::FullClear);
        // Unreadable: same.
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        record_at(&path, "a.test").unwrap();
        assert_eq!(read_ledger_at(&path), LedgerRead::Entries(list(&["!unreadable-ledger", "a.test"])));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_ledger_file_round_trips_and_records_durably() {
        let dir = std::env::temp_dir().join(format!("kept-ledger-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("WebView2-kept.ledger");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_ledger_at(&path), LedgerRead::Missing);
        record_at(&path, "messenger.com").unwrap();
        record_at(&path, "!cache").unwrap();
        record_at(&path, "messenger.com").unwrap();
        assert!(!path.with_extension("ledger-new").exists(), "no temp file left behind");
        assert_eq!(read_ledger_at(&path), LedgerRead::Entries(list(&["messenger.com", "!cache"])));
        write_ledger_at(&path, &list(&["facebook.com"])).unwrap();
        assert_eq!(read_ledger_at(&path), LedgerRead::Entries(list(&["facebook.com"])));
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(read_ledger_at(&path), LedgerRead::Unreadable);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_kept_tab_fails_closed_on_documents() {
        let kept = list(&["messenger.com"]);
        // Kept hosts load, page or frame.
        assert_eq!(kept_document(&kept, "www.messenger.com", true, false), KeptDocument::Allow);
        assert_eq!(kept_document(&kept, "messenger.com", false, false), KeptDocument::Allow);
        // A non-kept host matching the tab's navigation is refused and moved,
        // EVEN IF a frame to it is also in flight (the race).
        assert_eq!(kept_document(&kept, "news.example", true, false), KeptDocument::RefuseAndMove);
        assert_eq!(kept_document(&kept, "news.example", true, true), KeptDocument::RefuseAndMove);
        // A provable frame loads.
        assert_eq!(kept_document(&kept, "captcha.example", false, true), KeptDocument::Allow);
        // Unknown never loads.
        assert_eq!(kept_document(&kept, "news.example", false, false), KeptDocument::Refuse);
    }

    #[test]
    fn a_tab_opened_by_a_crossing_cannot_cross_again_at_once() {
        let now = Instant::now();
        assert!(crossing_allowed(None, now));
        assert!(!crossing_allowed(Some(now), now));
        assert!(!crossing_allowed(Some(now), now + Duration::from_secs(9)));
        assert!(crossing_allowed(Some(now), now + CROSSING_COOLDOWN));
    }

    #[test]
    fn the_placeholder_runs_nothing_and_says_nothing() {
        let h = MOVED_PLACEHOLDER_HTML.to_ascii_lowercase();
        assert!(h.contains("default-src 'none'"));
        assert!(!h.contains("<script"));
        assert!(h.contains("<body></body>"));
    }

    #[test]
    fn the_in_memory_list_is_what_handlers_read() {
        set_kept_hosts(&list(&["a.test"]));
        assert_eq!(kept_hosts(), list(&["a.test"]));
        set_kept_hosts(&[]);
        assert!(kept_hosts().is_empty());
    }
}
