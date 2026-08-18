//! Cross-tab text search, pure.
//!
//! What this module is: the matching, snippet shaping and refusal wording
//! for searching the visible text of every open tab at once. What it is
//! not: it touches no platform type, no clock, no file, no socket. The
//! visible text arrives as a `&str` already produced by
//! `patanyx_integrity::visible_text`, so "what the text search reads" is
//! byte-for-byte "what the text digest covers" -- the two can never drift
//! apart, and this module never re-derives text from HTML itself.
//!
//! Everything is decided identically on every platform, including a
//! headless test runner, for the same reason find.rs keeps its wording
//! pure: the engines differ, the honesty rules must not.
//!
//! Every offset handed out is a BYTE offset into plain text -- original
//! casing, no markup. The UI bolds a match by composing text nodes around
//! the range; nothing here is ever spliced into HTML, so a hostile page
//! cannot smuggle markup into the chrome through a snippet.

/// Snippets per tab, hard stop. The panel renders one row per snippet; past
/// this many the rows stop informing and start costing, and the count line
/// already says the tab has more.
pub const MAX_SNIPPETS_PER_TAB: usize = 100;

/// Match-count cap per tab, mirroring the engine cap find.rs words with a
/// "+". Counting stops here and `capped` goes true, so the UI never
/// presents a stopped counter as an exact total.
pub const MAX_MATCH_COUNT: u32 = 1000;

/// Query length cap in CHARS, not bytes: the limit exists to bound the
/// folded-query allocation, and a byte limit would be a stricter limit for
/// exactly the scripts whose characters take several bytes (a 256-byte cap
/// is about 85 CJK characters).
pub const MAX_QUERY_CHARS: usize = 256;

/// Target context each side of a match, in chars of the visible text. The
/// window snaps outward to a space within `WORD_SNAP_SLACK_CHARS`, so a
/// snippet can be a little wider; only the target is fixed, and the window
/// is bounded by target + slack either way.
const SNIPPET_CONTEXT_CHARS: usize = 60;

/// How far past the target window edge a space may be and still be snapped
/// to. Small on purpose: the window exists to bound row height, and a large
/// slack would reintroduce unbounded rows one word at a time.
const WORD_SNAP_SLACK_CHARS: usize = 12;

// The non-ASCII fold map stores byte offsets as u32 (see find_snippets):
// the integrity crate's input cap bounds every offset it can hold, and this
// is the line that turns a silent truncation into a compile error if that
// cap ever outgrows u32.
const _: () = assert!(patanyx_integrity::MAX_INPUT_BYTES <= u32::MAX as usize);

/// One rendered row: a window of the tab's visible text around one match.
#[derive(Debug, Clone, PartialEq)]
pub struct Snippet {
    /// Plain text, original casing, no markup, no added ellipsis marks.
    pub text: String,
    /// Byte range of the matched query WITHIN `text` (char-boundary safe,
    /// case of the page, not of the query). The UI bolds this range by
    /// composing text nodes; nothing here is HTML.
    pub match_start: usize,
    pub match_end: usize,
    /// Whether text was cut off before/after the window, so the UI can
    /// render its own ellipsis marks.
    pub cut_start: bool,
    pub cut_end: bool,
}

/// The search result for one tab.
pub struct SnippetSet {
    /// At most `MAX_SNIPPETS_PER_TAB`, the first ones in document order.
    pub snippets: Vec<Snippet>,
    /// Matches counted, up to `MAX_MATCH_COUNT`.
    pub total: u32,
    /// True when `total` hit `MAX_MATCH_COUNT`. The real total may be
    /// higher, so the UI words it as a floor ("1000+"), never as an exact
    /// count -- the honesty rule find.rs::format_count already applies to
    /// engine counts.
    pub capped: bool,
}

/// Validate and normalize a query from the search box.
///
/// Three refusals and one rewrite:
///
/// * Empty and whitespace-only queries are `Err("bad_args")` -- searching
///   nothing would highlight everything or nothing depending on nothing.
/// * Over `MAX_QUERY_CHARS` CHARS (not bytes) is refused. The cap is
///   measured on the collapsed query -- the thing actually searched -- so
///   runs of whitespace never push a real query over the limit. The
///   resource bound on the RAW input is the IPC frame cap (ipc.rs's
///   MAX_FRAME_BYTES, enforced before dispatch), so the collapse below can
///   never be fed more than one frame's worth of bytes.
/// * The surviving query is whitespace-collapsed with the SAME collapse the
///   visible text underwent (every run of HTML whitespace becomes one
///   single space): the text is stored collapsed, so an uncollapsed
///   multi-word query could never match it.
///
/// There is deliberately NO minimum length. A single CJK character is a
/// complete, meaningful query, and a silent minimum would fall entirely on
/// users of scripts this product has no grounds to second-guess. The
/// rejected alternative was a one-or-two-character minimum copied from
/// Latin-centric search boxes; it saves nothing (matching is linear in the
/// text either way) and costs exactly the wrong users.
///
/// Returns an owned String because a collapsed query is a NEW string
/// whenever the input contained runs of whitespace. The error string for an
/// over-length query is "bad_args", matching the empty and whitespace
/// refusals and the IPC layer's argument-error wording.
pub fn check_query(query: &str) -> Result<String, &'static str> {
    let collapsed = collapse_query_ws(query);
    if collapsed.is_empty() {
        return Err("bad_args");
    }
    if collapsed.chars().count() > MAX_QUERY_CHARS {
        return Err("bad_args");
    }
    Ok(collapsed)
}

/// Search one tab's visible text for `query` and shape the result for the
/// panel.
///
/// `query` is expected to be the Ok of `check_query` (collapsed, within
/// caps). The function is still total: an empty query finds nothing,
/// because an empty needle at best highlights everything -- the same reason
/// find.rs stops on "".
///
/// Matching is case-insensitive and Unicode-aware via `to_lowercase` on
/// BOTH sides. The hazard that shapes the implementation: folding can
/// change byte lengths and char counts (İ folds to i + a combining dot, one
/// char becoming two), so offsets into a folded string are WRONG in the
/// original. The folded haystack is built together with, for every folded
/// char, the byte offset of the original char it came from, and every
/// reported range is translated back through that map -- it always lands on
/// original char boundaries, in the page's casing.
///
/// ASCII text takes a separate path with no map at all: an ASCII fold is
/// one byte to one byte, so folded offsets ARE original offsets. This is
/// not only speed -- the map costs 4 bytes per folded char, and the pages
/// large enough for that to matter (the integrity cap admits 16 MiB) are
/// exactly the pages most likely to be pure ASCII.
///
/// Stable std has no full casefold, and under `to_lowercase` 'ß' stays 'ß'
/// (its casefold "ss" exists only behind a nightly API, and a
/// hand-maintained fold table would be Unicode data nobody re-checks). So
/// "ss" does not match "ß" here; the test
/// `ss_does_not_match_a_sharp_s_without_a_casefold` pins that as a
/// decision, not an accident. The engines' own find-in-page uses a full
/// casefold, so after a jump the engine may highlight matches this panel
/// did not list -- more highlights than rows, never fewer kinds of honesty.
/// Unlike the integrity digests, search results are ephemeral, so the
/// Unicode-table drift the integrity crate avoids is acceptable here.
pub fn find_snippets(visible_text: &str, query: &str) -> SnippetSet {
    let mut set = SnippetSet {
        snippets: Vec::new(),
        total: 0,
        capped: false,
    };
    let folded_query = query.to_lowercase();
    if folded_query.is_empty() || visible_text.is_empty() {
        return set;
    }

    if visible_text.is_ascii() {
        // One byte per char and the fold is 1:1, so folded offsets are
        // original offsets and the match's original length is the folded
        // needle's length. No map is built.
        let folded = visible_text.to_ascii_lowercase();
        let mut pos = 0usize;
        while pos < folded.len() {
            let Some(rel) = folded[pos..].find(&folded_query) else {
                break;
            };
            let m0 = pos + rel;
            let m1 = m0 + folded_query.len();
            if set.snippets.len() < MAX_SNIPPETS_PER_TAB {
                set.snippets.push(make_snippet(visible_text, m0, m1));
            }
            set.total += 1;
            if set.total == MAX_MATCH_COUNT {
                set.capped = true;
                return set;
            }
            // One byte IS one char here; see the general path's advance
            // comment for why overlaps are counted.
            pos = m0 + 1;
        }
        return set;
    }

    let query_chars = folded_query.chars().count();

    // Fold the haystack, remembering for each folded char the START byte of
    // the original char it came from; the original char's length is re-read
    // from the text when a range is closed. u32, not usize: the offsets are
    // bounded by the integrity input cap (const-asserted above), and the
    // map is the dominant transient cost of this function.
    let mut folded = String::with_capacity(visible_text.len());
    let mut orig_starts: Vec<u32> = Vec::new();
    for (b, c) in visible_text.char_indices() {
        for fc in c.to_lowercase() {
            folded.push(fc);
            orig_starts.push(b as u32);
        }
    }

    let mut pos = 0usize; // byte offset into `folded`; only moves forward
    let mut cpos = 0usize; // folded char index of `pos`
    while pos < folded.len() {
        let Some(rel) = folded[pos..].find(&folded_query) else {
            break;
        };
        let m0 = pos + rel;
        let c0 = cpos + folded[pos..m0].chars().count();
        // The match covers exactly `query_chars` folded chars; both folded
        // offsets are char boundaries because the needle is a valid str.
        let c1 = c0 + query_chars;
        let oms = orig_starts[c0] as usize;
        let last = orig_starts[c1 - 1] as usize;
        let ome = last
            + visible_text[last..]
                .chars()
                .next()
                .expect("orig_starts point at original char starts")
                .len_utf8();
        if set.snippets.len() < MAX_SNIPPETS_PER_TAB {
            set.snippets.push(make_snippet(visible_text, oms, ome));
        }
        set.total += 1;
        if set.total == MAX_MATCH_COUNT {
            // Counting stops here whether or not the text does: a total at
            // the cap is a floor, and `capped` tells the UI to word it with
            // a "+" rather than present the stopped counter as exact.
            set.capped = true;
            return set;
        }
        // Advance ONE folded char past the match START, not past the whole
        // match: overlapping matches each count and each get a snippet
        // ("aa" in "aaa" is two matches), because a user selecting the run
        // sees them overlap too, and a count that skipped them would
        // contradict the page.
        pos = m0
            + folded[m0..]
                .chars()
                .next()
                .expect("a match starts inside the folded text")
                .len_utf8();
        cpos = c0 + 1;
    }
    set
}

/// The window around one match, in the ORIGINAL text. Each edge targets
/// `SNIPPET_CONTEXT_CHARS` chars of context and then snaps OUTWARD to a
/// space when one lies within `WORD_SNAP_SLACK_CHARS`: a row that opens or
/// closes mid-word reads as broken, while a slightly wider row does not.
/// All arithmetic walks `char_indices`, never byte guesses, and the window
/// always contains the full match by construction -- the edges are computed
/// outward from it. The only space looked for is ' ': the visible text was
/// whitespace-collapsed before it got here, so single spaces are the only
/// word boundaries it contains.
fn make_snippet(text: &str, match_start: usize, match_end: usize) -> Snippet {
    let mut start = 0usize;
    let mut back = 0usize;
    let mut target = None;
    for (b, c) in text[..match_start].char_indices().rev() {
        back += 1;
        if back == SNIPPET_CONTEXT_CHARS {
            target = Some(b);
        }
        if back >= SNIPPET_CONTEXT_CHARS && c == ' ' {
            // Open the row after the space, on a whole word.
            start = b + c.len_utf8();
            break;
        }
        if back == SNIPPET_CONTEXT_CHARS + WORD_SNAP_SLACK_CHARS {
            // No space within slack: accept the mid-word cut at the target.
            start = target.expect("target is set once back reaches the target");
            break;
        }
    }
    // If the walk reached the start of the text without breaking, start
    // stays 0: nothing was dropped, so nothing is marked cut.
    let mut end = text.len();
    let mut fwd = 0usize;
    let mut target = None;
    for (b, c) in text[match_end..].char_indices() {
        fwd += 1;
        if fwd == SNIPPET_CONTEXT_CHARS {
            target = Some(match_end + b + c.len_utf8());
        }
        if fwd >= SNIPPET_CONTEXT_CHARS && c == ' ' {
            // Close the row before the space, on the last whole word.
            end = match_end + b;
            break;
        }
        if fwd == SNIPPET_CONTEXT_CHARS + WORD_SNAP_SLACK_CHARS {
            end = target.expect("target is set once fwd reaches the target");
            break;
        }
    }
    Snippet {
        text: text[start..end].to_string(),
        match_start: match_start - start,
        match_end: match_end - start,
        // The cut flags mean exactly "text was dropped on this side".
        cut_start: start > 0,
        cut_end: end < text.len(),
    }
}

/// Whitespace-collapse a query with the SAME table the visible text was
/// collapsed with: HTML's five ASCII whitespace chars plus U+00A0, every
/// run becoming one single space, ends trimmed. The table is duplicated
/// from patanyx-integrity rather than imported because that crate exposes
/// the collapse only as an internal step of `visible_text`, and widening
/// its public surface for one helper is worse than pinning the agreement
/// with a test (`queries_and_pages_agree_on_what_a_space_is`).
///
/// Deliberately NOT `char::is_whitespace`: the text was collapsed with
/// exactly this table, so a query containing, say, U+2003 must keep it --
/// the text kept it too, and collapsing it here would send the query
/// hunting for a character the page never folded away.
fn collapse_query_ws(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let mut pending_space = false;
    for c in query.chars() {
        if is_query_space(c) {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    out
}

fn is_query_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{0C}' | '\r' | '\u{00A0}')
}

/// Why a tab cannot be searched right now, as a stable reason string -- or
/// None when there is nothing to complain about.
///
/// `outcome` is the tab's captured page bytes: None while the async capture
/// has not delivered yet, Some(Err(..)) when it never will, Some(Ok(..))
/// when the bytes exist -- which is not this function's business, so the
/// answer is None and the caller proceeds to `find_snippets`.
///
/// The strings are keys, not copy: `reason_copy` is the ONE place they
/// become user-visible sentences, so the wording can be tuned without
/// touching the mapping, and the mapping can be tested without approving
/// sentences.
pub fn unsearchable_reason(
    outcome: Option<&Result<Vec<u8>, crate::page_integrity::PageBytesError>>,
) -> Option<&'static str> {
    use crate::page_integrity::PageBytesError as E;
    match outcome {
        None => Some("loading"),
        Some(Err(E::NoMainResource)) => Some("not_a_web_page"),
        // A failed read usually means the page is still loading; saying so
        // is honest and recoverable, unlike "error".
        Some(Err(E::FetchFailed)) => Some("loading"),
        Some(Err(E::TooLarge)) => Some("too_large"),
        Some(Ok(_)) => None,
    }
}

/// The ONE place reason strings become user-visible sentences. American
/// English, plain, no exclamation marks. An unknown reason gets a generic
/// sentence rather than a panic: a reason travels across module boundaries
/// as a bare &str, and a wording hiccup must never take the chrome down.
pub fn reason_copy(reason: &'static str) -> &'static str {
    match reason {
        "loading" => "Still loading; search again in a moment.",
        "not_a_web_page" => "Not a web page.",
        "too_large" => "This page is too large to search.",
        "tab_closed" => "This tab was closed.",
        _ => "This tab cannot be searched right now.",
    }
}

/// The cross-tab search premium gate.
///
/// This is the first real premium feature gate in the browser, so the rule
/// lives in a pure function: the caller passes
/// `licence_control::premium_active()`, and the refusal rule stays
/// unit-testable without standing up a licence session. Keeping the gate
/// here rather than inlined at a call site means the refusal string has
/// exactly one author.
pub fn cross_tab_gate(premium: bool) -> Result<(), &'static str> {
    if premium {
        Ok(())
    } else {
        Err("premium_required")
    }
}

// ---------------------------------------------------------------------------
// Scan bookkeeping
// ---------------------------------------------------------------------------

/// One tab's row in a cross-tab scan.
pub enum ScanRow {
    /// Bytes requested, no answer yet. There is deliberately NO timeout: a
    /// Pending row that never answers stays Pending until the tab closes or
    /// the next search replaces the scan, and the UI words it as "Still
    /// loading". Safe because nothing blocks on a row and nothing leaks --
    /// the in-flight read owns only a registry token, and an answer quoting
    /// a dead scan id is refused by `record`.
    Pending,
    /// The tab's visible text was searched; the result is final.
    Done(SnippetSet),
    /// The tab could not be searched. The key is worded by `reason_copy`,
    /// the one place reasons become sentences.
    Unsearchable(&'static str),
}

/// The bookkeeping for one cross-tab search, fixed at start: an identity
/// drawn from the SAME GenSeq every find generation comes from, the
/// checked, collapsed query, and one row per scanned tab in tab strip
/// order.
///
/// A scan is REPLACED wholesale by the next search and DROPPED on vault
/// lock; there is no per-row cancel. The id is what makes that safe: every
/// in-flight byte read quotes the id of the scan that asked for it, and
/// `record` refuses an answer quoting any other id -- so a replaced scan's
/// late read can never plant bytes captured under the OLD scan (or a
/// pre-lock licence session) into the live panel, even when both scans
/// cover the same tab.
pub struct TabScan {
    id: u64,
    query: String,
    rows: Vec<(u64, ScanRow)>,
}

impl TabScan {
    /// A fresh scan: every row Pending, in the given (tab strip) order.
    /// `id` comes from the shared find GenSeq, so no scan and no find
    /// session can ever share a number.
    pub fn start(id: u64, query: String, tab_ids: &[u64]) -> TabScan {
        TabScan {
            id,
            query,
            rows: tab_ids
                .iter()
                .map(|&tab_id| (tab_id, ScanRow::Pending))
                .collect(),
        }
    }

    /// The identity in-flight byte reads must quote back.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Fill a Pending row; returns whether anything changed. Three refusals,
    /// each load-bearing: an answer quoting another scan's id (a replaced
    /// scan's late read -- the stale-bytes hazard), a tab with no row, and
    /// a row already filled (a late duplicate must never overwrite the
    /// answer already on screen).
    pub fn record(&mut self, scan_id: u64, tab_id: u64, row: ScanRow) -> bool {
        if scan_id != self.id {
            return false;
        }
        let Some((_, slot)) = self.rows.iter_mut().find(|(id, _)| *id == tab_id) else {
            return false;
        };
        if !matches!(slot, ScanRow::Pending) {
            return false;
        }
        *slot = row;
        true
    }

    /// Mark a tab closed. A Pending row becomes Unsearchable("tab_closed");
    /// a Done row KEEPS its result -- the text was read while the tab
    /// lived, and the UI shows the row as gone-but-counted.
    pub fn on_tab_closed(&mut self, tab_id: u64) -> bool {
        let Some((_, slot)) = self.rows.iter_mut().find(|(id, _)| *id == tab_id) else {
            return false;
        };
        if !matches!(slot, ScanRow::Pending) {
            return false;
        }
        *slot = ScanRow::Unsearchable("tab_closed");
        true
    }

    /// Whether no row is still waiting on the engine. (The IPC arm refuses
    /// an empty tab list, so the vacuous case never exists over IPC.)
    pub fn is_complete(&self) -> bool {
        self.rows
            .iter()
            .all(|(_, row)| !matches!(row, ScanRow::Pending))
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn rows(&self) -> &[(u64, ScanRow)] {
        &self.rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn only_snippet(text: &str, query: &str) -> Snippet {
        let set = find_snippets(text, query);
        assert_eq!(set.snippets.len(), 1, "expected exactly one snippet");
        set.snippets.into_iter().next().unwrap()
    }

    /// The matched range, sliced out of each snippet. Slicing panics on a
    /// non-char-boundary offset, so every use of this helper quietly pins
    /// boundary safety too.
    fn matched(set: &SnippetSet) -> Vec<&str> {
        set.snippets
            .iter()
            .map(|s| &s.text[s.match_start..s.match_end])
            .collect()
    }

    #[test]
    fn an_empty_or_blank_query_is_refused() {
        assert_eq!(check_query(""), Err("bad_args"));
        assert_eq!(check_query("   "), Err("bad_args"));
        // Every HTML whitespace char, including the non-breaking space.
        assert_eq!(check_query("\t\n\u{0C}\r\u{00A0}"), Err("bad_args"));
    }

    #[test]
    fn overlong_queries_are_refused_by_chars_not_bytes() {
        let ok = "a".repeat(MAX_QUERY_CHARS);
        assert!(check_query(&ok).is_ok());
        let too_many = "a".repeat(MAX_QUERY_CHARS + 1);
        assert_eq!(check_query(&too_many), Err("bad_args"));
        // 256 CJK chars are 768 bytes and LEGAL: the cap counts chars, or it
        // would be a stricter limit for exactly the scripts that need
        // several bytes per character.
        let cjk_ok = "東".repeat(MAX_QUERY_CHARS);
        assert!(check_query(&cjk_ok).is_ok());
        let cjk_too_many = "東".repeat(MAX_QUERY_CHARS + 1);
        assert_eq!(check_query(&cjk_too_many), Err("bad_args"));
    }

    #[test]
    fn queries_are_collapsed_like_the_text_they_search() {
        assert_eq!(
            check_query("  hello   world\t"),
            Ok("hello world".to_string())
        );
        // A non-breaking space is a space in the page collapse, so it is a
        // space in the query collapse.
        assert_eq!(check_query("a\u{00A0}\u{00A0}b"), Ok("a b".to_string()));
    }

    #[test]
    fn a_single_cjk_character_is_a_legitimate_query() {
        // No minimum length, on purpose; see check_query's docs.
        assert_eq!(check_query("東").as_deref(), Ok("東"));
        let set = find_snippets("彼は東京に行った", "東");
        assert_eq!(set.total, 1);
        let s = &set.snippets[0];
        assert_eq!(&s.text[s.match_start..s.match_end], "東");
        assert_eq!((s.match_start, s.match_end), (6, 9));
    }

    #[test]
    fn matching_is_case_insensitive_but_reports_the_pages_casing() {
        let set = find_snippets("I love Rust.", "rust");
        assert_eq!(set.total, 1);
        assert_eq!(matched(&set), vec!["Rust"]);
        assert_eq!(
            (set.snippets[0].match_start, set.snippets[0].match_end),
            (7, 11)
        );
        // The fold runs on both sides, so an uppercase query matches too.
        let set = find_snippets("rust is nice", "RUST");
        assert_eq!(matched(&set), vec!["rust"]);
        // Same-script casing folds as expected.
        let set = find_snippets("Straße", "straße");
        assert_eq!(matched(&set), vec!["Straße"]);
    }

    #[test]
    fn case_folding_never_shifts_the_reported_offsets() {
        // İ folds to two chars and ß is a two-byte char; both sit BEFORE the
        // match, so any offset computed in the folded string is wrong here.
        // Reported offsets must be original byte offsets on original char
        // boundaries.
        for text in ["İstanbul Rust", "Straße, Rust"] {
            let set = find_snippets(text, "rust");
            assert_eq!(set.total, 1, "{text:?}");
            let s = &set.snippets[0];
            let want = text.find("Rust").unwrap();
            assert_eq!((s.match_start, s.match_end), (want, want + 4), "{text:?}");
            assert_eq!(&s.text[s.match_start..s.match_end], "Rust");
        }
    }

    #[test]
    fn the_ascii_fast_path_agrees_with_the_general_path() {
        // The same ASCII prefix must report the same offsets whichever path
        // ran; a trailing non-ASCII char forces the general path without
        // moving anything before it.
        let ascii = "one Needle two needle three";
        let forced_general = format!("{ascii} é");
        let a = find_snippets(ascii, "needle");
        let b = find_snippets(&forced_general, "needle");
        assert_eq!(a.total, b.total);
        let sa: Vec<usize> = a.snippets.iter().map(|s| s.match_start).collect();
        let sb: Vec<usize> = b.snippets.iter().map(|s| s.match_start).collect();
        assert_eq!(sa, sb);
        assert_eq!(matched(&a), matched(&b));
    }

    #[test]
    fn ss_does_not_match_a_sharp_s_without_a_casefold() {
        // Stable std's to_lowercase leaves 'ß' as 'ß'; the casefold to "ss"
        // is nightly-only. Pinning the non-match makes the limitation a
        // decision with a doc comment, not a silent gap.
        assert_eq!(find_snippets("Straße", "ss").total, 0);
        assert_eq!(find_snippets("Straße", "STRASSE").total, 0);
    }

    #[test]
    fn overlapping_matches_each_get_their_own_snippet() {
        // The scan advances one folded char past each match START, so "aa"
        // in "aaaa" is three matches, and each is its own row.
        let set = find_snippets("aaaa", "aa");
        assert_eq!(set.total, 3);
        assert_eq!(set.snippets.len(), 3);
        assert_eq!(matched(&set), vec!["aa", "aa", "aa"]);
        let starts: Vec<usize> = set.snippets.iter().map(|s| s.match_start).collect();
        assert_eq!(starts, vec![0, 1, 2]);
    }

    #[test]
    fn snippets_are_in_document_order() {
        let text = "one needle two needle three needle";
        let set = find_snippets(text, "needle");
        let want: Vec<usize> = text.match_indices("needle").map(|(i, _)| i).collect();
        let got: Vec<usize> = set.snippets.iter().map(|s| s.match_start).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn the_window_contains_the_match_and_marks_what_it_cut() {
        // A match deep inside a long single line, no spaces anywhere.
        let text = format!("{}needle{}", "x".repeat(500), "y".repeat(500));
        let s = only_snippet(&text, "needle");
        assert!(s.cut_start && s.cut_end, "both sides dropped text");
        assert_eq!(&s.text[s.match_start..s.match_end], "needle");
        // No space within slack, so both edges cut mid-word at the target.
        assert_eq!(s.match_start, SNIPPET_CONTEXT_CHARS);
        // The window is bounded: target + slack + match, never the line.
        assert!(
            s.text.chars().count() <= 2 * (SNIPPET_CONTEXT_CHARS + WORD_SNAP_SLACK_CHARS) + 6
        );
    }

    #[test]
    fn a_match_at_the_text_edges_cuts_nothing() {
        let s = only_snippet("needle at the start", "needle");
        assert!(!s.cut_start && !s.cut_end, "the whole short text fits");
        let text = format!("{}needle", "z".repeat(500));
        let s = only_snippet(&text, "needle");
        assert!(s.cut_start, "five hundred chars were dropped on the left");
        assert!(!s.cut_end, "the match reaches the end of the text");
    }

    #[test]
    fn the_left_edge_snaps_outward_to_a_space_within_slack() {
        // A space exactly AT the target edge: the row opens after it, on a
        // whole word, instead of on the space itself.
        let text = format!("{} {}needle", "a".repeat(20), "b".repeat(59));
        let s = only_snippet(&text, "needle");
        assert_eq!(s.match_start, 59);
        assert!(s.text.starts_with('b'));
        assert!(s.cut_start);
        // A space six chars past the target: still snapped to, so the row
        // keeps the whole word at the price of a slightly wider window.
        let text = format!("{} {}needle", "a".repeat(15), "b".repeat(65));
        let s = only_snippet(&text, "needle");
        assert_eq!(s.match_start, 65);
        // A space beyond the slack: no snap, mid-word cut at the target.
        let text = format!("{} {}needle", "a".repeat(1), "b".repeat(75));
        let s = only_snippet(&text, "needle");
        assert_eq!(s.match_start, SNIPPET_CONTEXT_CHARS);
        assert!(s.cut_start);
    }

    #[test]
    fn the_right_edge_snaps_outward_to_a_space_within_slack() {
        let text = format!("needle{} {}", "b".repeat(59), "a".repeat(20));
        let s = only_snippet(&text, "needle");
        assert!(!s.cut_start);
        assert!(s.cut_end, "the trailing word was dropped");
        assert!(s.text.ends_with('b'), "the row closes on a whole word");
        assert!(!s.text.contains('a'));
    }

    #[test]
    fn the_window_always_contains_the_whole_match() {
        // A match longer than both contexts together is still shown whole:
        // the edges are computed outward from the match, never across it.
        let needle = "n".repeat(200);
        let text = format!("{}{}{}", "a".repeat(300), needle, "b".repeat(300));
        let s = only_snippet(&text, &needle);
        assert_eq!(&s.text[s.match_start..s.match_end], needle.as_str());
        assert!(s.cut_start && s.cut_end);
        assert_eq!(
            s.text.chars().count(),
            2 * SNIPPET_CONTEXT_CHARS + 200,
            "no spaces, so both edges cut at the exact target"
        );
    }

    #[test]
    fn snippets_stop_at_the_cap_but_counting_goes_on() {
        let text = "ab ".repeat(MAX_SNIPPETS_PER_TAB + 50);
        let set = find_snippets(&text, "ab");
        assert_eq!(set.snippets.len(), MAX_SNIPPETS_PER_TAB);
        assert_eq!(set.total as usize, MAX_SNIPPETS_PER_TAB + 50);
        assert!(!set.capped, "the count cap was never reached");
    }

    #[test]
    fn the_count_cap_is_worded_as_a_floor_never_an_exact_total() {
        let text = "ab ".repeat(MAX_MATCH_COUNT as usize + 1);
        let set = find_snippets(&text, "ab");
        assert_eq!(set.total, MAX_MATCH_COUNT);
        assert!(set.capped, "more matches exist than were counted");
        // A text holding exactly the cap still reports capped: counting
        // stopped at the cap, so the total is a floor either way -- the same
        // rule find.rs applies to engine counts that reach their cap.
        let text = "ab ".repeat(MAX_MATCH_COUNT as usize);
        let set = find_snippets(&text, "ab");
        assert_eq!(set.total, MAX_MATCH_COUNT);
        assert!(set.capped);
    }

    #[test]
    fn no_match_is_an_empty_set_not_an_error() {
        let set = find_snippets("nothing here", "needle");
        assert_eq!(set.total, 0);
        assert!(set.snippets.is_empty());
        assert!(!set.capped);
        // The function is total: an unchecked empty query finds nothing
        // rather than panicking or highlighting everything.
        let set = find_snippets("anything", "");
        assert_eq!(set.total, 0);
    }

    #[test]
    fn queries_and_pages_agree_on_what_a_space_is() {
        // The query collapse MUST be the visible-text collapse, or a
        // multi-word query could never match the collapsed text. Pinned
        // through patanyx-integrity's public surface rather than by
        // importing its internals.
        let text = patanyx_integrity::visible_text("<p>alpha\u{00A0} \t beta</p>".as_bytes())
            .expect("small input");
        assert_eq!(text, "alpha beta");
        let query = check_query("alpha\u{00A0}  beta").unwrap();
        assert_eq!(query, "alpha beta");
        assert_eq!(find_snippets(&text, &query).total, 1);
    }

    #[test]
    fn unsearchable_reason_maps_every_outcome() {
        use crate::page_integrity::PageBytesError as E;
        assert_eq!(unsearchable_reason(None), Some("loading"));
        assert_eq!(
            unsearchable_reason(Some(&Err(E::NoMainResource))),
            Some("not_a_web_page")
        );
        assert_eq!(
            unsearchable_reason(Some(&Err(E::FetchFailed))),
            Some("loading")
        );
        assert_eq!(
            unsearchable_reason(Some(&Err(E::TooLarge))),
            Some("too_large")
        );
        // Captured bytes are not this function's business.
        let bytes = b"<p>hi</p>".to_vec();
        assert_eq!(unsearchable_reason(Some(&Ok(bytes))), None);
    }

    #[test]
    fn every_reason_has_exactly_one_sentence() {
        assert_eq!(
            reason_copy("loading"),
            "Still loading; search again in a moment."
        );
        assert_eq!(reason_copy("not_a_web_page"), "Not a web page.");
        assert_eq!(reason_copy("too_large"), "This page is too large to search.");
        assert_eq!(reason_copy("tab_closed"), "This tab was closed.");
    }

    // ---- scan bookkeeping ----

    fn scan_of(tab_ids: &[u64]) -> TabScan {
        TabScan::start(1, "needle".to_string(), tab_ids)
    }

    fn row_at(scan: &TabScan, index: usize) -> &ScanRow {
        &scan.rows()[index].1
    }

    #[test]
    fn a_fresh_scan_is_all_pending_in_tab_strip_order() {
        let scan = scan_of(&[7, 3, 9]);
        assert_eq!(scan.query(), "needle");
        let ids: Vec<u64> = scan.rows().iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![7, 3, 9], "row order is the tab strip order");
        assert!(
            scan.rows()
                .iter()
                .all(|(_, row)| matches!(row, ScanRow::Pending)),
            "every row starts waiting on the engine"
        );
        assert!(!scan.is_complete());
    }

    #[test]
    fn recording_fills_a_pending_row_once_and_reports_the_change() {
        let mut scan = scan_of(&[1, 2]);
        assert!(scan.record(1, 2, ScanRow::Done(find_snippets("a needle", "needle"))));
        assert!(matches!(row_at(&scan, 1), ScanRow::Done(_)));
        assert!(!scan.is_complete(), "row 1 is still waiting");
        assert!(scan.record(1, 1, ScanRow::Unsearchable("loading")));
        assert!(scan.is_complete());
    }

    #[test]
    fn an_answer_quoting_a_replaced_scans_id_never_records() {
        // THE stale-bytes hazard: two scans in a row cover the same tab, and
        // the first scan's byte read lands after the second scan started.
        // The answer quotes the dead scan's id and must be refused, or bytes
        // captured under the old scan (or a pre-lock licence session) would
        // be presented as the live tab's current content.
        let mut seq = crate::find::GenSeq::default();
        let old_id = seq.next();
        let mut live = TabScan::start(seq.next(), "needle".to_string(), &[1]);
        assert!(
            !live.record(old_id, 1, ScanRow::Done(find_snippets("needle", "needle"))),
            "an answer from the replaced scan must not fill the live row"
        );
        assert!(matches!(row_at(&live, 0), ScanRow::Pending));
        // The live scan's own read still lands normally afterwards.
        assert!(live.record(live.id(), 1, ScanRow::Done(find_snippets("needle", "needle"))));
    }

    #[test]
    fn two_scans_from_one_seq_never_share_an_id() {
        let mut seq = crate::find::GenSeq::default();
        let a = TabScan::start(seq.next(), "a".to_string(), &[1]);
        let b = TabScan::start(seq.next(), "b".to_string(), &[1]);
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn a_late_duplicate_answer_never_overwrites_a_filled_row() {
        // The engine can answer a token whose row is already filled; the
        // first answer stands.
        let mut scan = scan_of(&[1]);
        assert!(scan.record(1, 1, ScanRow::Done(find_snippets("needle", "needle"))));
        assert!(!scan.record(1, 1, ScanRow::Unsearchable("loading")));
        assert!(matches!(row_at(&scan, 0), ScanRow::Done(_)));
    }

    #[test]
    fn answers_from_tabs_outside_the_scan_are_ignored() {
        let mut scan = scan_of(&[1]);
        assert!(!scan.record(1, 999, ScanRow::Done(find_snippets("needle", "needle"))));
        assert!(matches!(row_at(&scan, 0), ScanRow::Pending));
    }

    #[test]
    fn closing_a_tab_fails_its_pending_row_but_keeps_a_done_one() {
        let mut scan = scan_of(&[1, 2]);
        assert!(scan.record(1, 1, ScanRow::Done(find_snippets("needle", "needle"))));
        assert!(scan.on_tab_closed(2));
        assert!(
            matches!(row_at(&scan, 1), ScanRow::Unsearchable("tab_closed")),
            "a pending row has no answer to keep"
        );
        assert!(!scan.on_tab_closed(1), "a done row is gone but counted");
        assert!(matches!(row_at(&scan, 0), ScanRow::Done(_)));
        assert!(scan.is_complete());
    }

    #[test]
    fn closing_a_tab_outside_the_scan_changes_nothing() {
        let mut scan = scan_of(&[1]);
        assert!(!scan.on_tab_closed(999));
        assert!(matches!(row_at(&scan, 0), ScanRow::Pending));
    }

    #[test]
    fn an_unknown_reason_gets_a_plain_fallback_not_a_panic() {
        // Reason strings cross module boundaries as bare &str; a stale or
        // future caller must meet a sentence, not a crash.
        let copy = reason_copy("some_future_reason");
        assert!(!copy.is_empty());
        assert!(copy.ends_with('.'));
    }

    #[test]
    fn cross_tab_search_requires_premium() {
        assert_eq!(cross_tab_gate(true), Ok(()));
        assert_eq!(cross_tab_gate(false), Err("premium_required"));
    }
}
