//! Netscape bookmark-file import.
//!
//! Chrome, Edge, Firefox, Brave and Vivaldi all export the same
//! "NETSCAPE-Bookmark-file-1" HTML. This module is a hand-rolled,
//! dependency-free scanner for that format -- deliberately NOT an HTML
//! parser, because the exports are only tag-shaped: `</DT>` close tags are
//! usually missing, attribute case and order vary, and Firefox sprinkles
//! in `<HR>` separators and SHORTCUTURL / TAGS attributes. Tolerance is
//! the whole job here; a strict parser would refuse every real export.
//!
//! Folder structure is DELIBERATELY not preserved: the store has no folder
//! concept, so a captured name would be dead weight -- and worse, a
//! memory-amplification hazard (one multi-megabyte <H3> cloned onto every
//! following bookmark). Folder tags parse as ordinary ignored markup.
//!
//! The parser is PURE: no I/O, no network, no platform calls. The IPC arm
//! owns the picker, the size cap and the store; this file owns bytes in,
//! structured entries out. Nothing here ever fetches anything -- the
//! picked file is the entire input.

/// Refusal cap for the picked file, enforced by the IPC arm before parsing
/// (the parser itself is pure and never sees I/O). 16 MiB: Firefox exports
/// embed base64 ICON attributes that inflate files into the low
/// single-digit MiB even for a few thousand bookmarks, so this leaves
/// generous headroom while keeping a hostile or mistaken pick bounded --
/// parser output is strictly smaller than parser input.
pub const MAX_IMPORT_BYTES: usize = 16 * 1024 * 1024;

/// One import-ready entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBookmark {
    pub url: String,
    /// Entity-decoded and whitespace-trimmed. Falls back to the URL when
    /// the exported title is empty, which is what the existing add path
    /// displays for a titleless entry.
    pub title: String,
}

/// The result of scanning one export file.
#[derive(Debug, Default)]
pub struct ImportParse {
    pub bookmarks: Vec<ParsedBookmark>,
    /// Entries that looked like bookmarks (an `<A>` with an HREF) but were
    /// refused: `place:` smart folders, `javascript:` / `data:` URLs, and
    /// empty HREFs. Counted so the chrome summary can be honest. An `<A>`
    /// with no HREF at all is page debris, not a failed bookmark, and is
    /// neither imported nor counted; an entry lost to file truncation is
    /// likewise uncounted (nothing was refused -- the file simply ended).
    pub skipped_unsupported: usize,
}

/// Scan a Netscape bookmark file. Infallible by design: any input parses,
/// a 0-byte or garbage file simply yields an empty outcome.
pub fn parse(text: &str) -> ImportParse {
    let mut out = ImportParse::default();
    let mut pos = 0usize;
    let mut anchor: Option<Anchor<'_>> = None;

    while let Some(event) = next_event(text, &mut pos) {
        match event {
            Event::Text(t) => {
                if let Some(a) = anchor.as_mut() {
                    a.text.push_str(t);
                }
            }
            Event::Start { name, attrs } if name.eq_ignore_ascii_case("a") => {
                // Exports never nest anchors, so an <A> that arrives while
                // one is open means the earlier one is debris; the new one
                // replaces it. Only HREF is read. ADD_DATE is dropped
                // because an exported timestamp is unverifiable input --
                // the store stamps its own created_at on every add. ICON
                // and ICON_URI are dropped because imported favicons are a
                // fingerprint and disk-bloat hazard, and the browser
                // renders its own.
                let href = attrs
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("href"))
                    .map(|(_, v)| *v);
                anchor = Some(Anchor { href, text: String::new() });
            }
            Event::Start { .. } => {}
            Event::End { name } if name.eq_ignore_ascii_case("a") => {
                if let Some(a) = anchor.take() {
                    finish_anchor(a, &mut out);
                }
            }
            Event::End { .. } => {}
        }
    }
    // An anchor or H3 left open by a truncated file is dropped, not
    // half-imported: a cut-off tail is damage, not data.
    out
}

/// An `<A>` capture in progress: the raw HREF (None if the tag has none)
/// plus the raw inner text accumulated so far.
struct Anchor<'a> {
    href: Option<&'a str>,
    text: String,
}

fn finish_anchor(anchor: Anchor<'_>, out: &mut ImportParse) {
    // No HREF at all: page debris (named anchors and the like), not a
    // failed bookmark -- neither imported nor counted.
    let Some(href) = anchor.href else {
        return;
    };
    let url = decode_entities(href).trim().to_string();
    if url.is_empty() || is_unsupported_scheme(&url) {
        out.skipped_unsupported += 1;
        return;
    }
    let title = decode_entities(&anchor.text).trim().to_string();
    let title = if title.is_empty() { url.clone() } else { title };
    out.bookmarks.push(ParsedBookmark { url, title });
}

/// Scheme compare is case-insensitive because HTML scheme names are -- a
/// "JavaScript:" spelling must not slip past the same refusal that a
/// lowercase one gets.
fn is_unsupported_scheme(url: &str) -> bool {
    let Some(colon) = url.find(':') else {
        return false;
    };
    let scheme = &url[..colon];
    scheme.eq_ignore_ascii_case("place")
        || scheme.eq_ignore_ascii_case("javascript")
        || scheme.eq_ignore_ascii_case("data")
}

/// Decode the entities real exports actually contain: the four named ones
/// plus numeric decimal/hex. Anything else stays literal -- an unknown
/// entity is data, not an error.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after_amp = &rest[amp + 1..];
        let mut consumed = false;
        if let Some(semi) = after_amp.find(';') {
            let body = &after_amp[..semi];
            // Bounded window: the longest real body is "#x10FFFF" (8).
            // Past this it was never an entity, just prose with a ';'.
            if !body.is_empty() && body.len() <= 10 {
                if let Some(decoded) = decode_entity_body(body) {
                    out.push_str(&decoded);
                    rest = &after_amp[semi + 1..];
                    consumed = true;
                }
            }
        }
        if !consumed {
            out.push('&');
            rest = after_amp;
        }
    }
    out.push_str(rest);
    out
}

fn decode_entity_body(body: &str) -> Option<String> {
    match body {
        "amp" => return Some("&".to_string()),
        "lt" => return Some("<".to_string()),
        "gt" => return Some(">".to_string()),
        "quot" => return Some("\"".to_string()),
        _ => {}
    }
    let digits = body.strip_prefix('#')?;
    let value = match digits.strip_prefix('x').or_else(|| digits.strip_prefix('X')) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    // char::from_u32 refuses surrogates and values past U+10FFFF; those
    // entities stay literal instead of decoding to replacement mush.
    char::from_u32(value).map(|c| c.to_string())
}

/// One scanner step: the text up to the next tag, or the tag itself.
enum Event<'a> {
    Text(&'a str),
    Start { name: &'a str, attrs: Vec<(&'a str, &'a str)> },
    End { name: &'a str },
}

/// Text runs up to the next PLAUSIBLE tag start: a '<' followed by an
/// ASCII letter, '/', '!' or '?'. Anything else ("a < b", "I <3 you")
/// stays literal text -- exports entity-encode real markup, and being
/// liberal here keeps stray prose from eating entries.
fn is_tag_opener(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'/' || b == b'!' || b == b'?'
}

/// Tag and attribute names: exports use ASCII plus '-' (HTTP-EQUIV) and
/// '_' (ADD_DATE, LAST_MODIFIED).
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn find_byte(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    bytes
        .get(from..)?
        .iter()
        .position(|&b| b == needle)
        .map(|rel| from + rel)
}

fn read_name(s: &str, from: usize) -> (&str, usize) {
    let bytes = s.as_bytes();
    let mut i = from;
    while i < bytes.len() && is_name_byte(bytes[i]) {
        i += 1;
    }
    (&s[from..i], i)
}

fn next_event<'a>(text: &'a str, pos: &mut usize) -> Option<Event<'a>> {
    let bytes = text.as_bytes();
    loop {
        let start = *pos;
        let mut i = start;
        while i < bytes.len() {
            if bytes[i] == b'<' && i + 1 < bytes.len() && is_tag_opener(bytes[i + 1]) {
                break;
            }
            i += 1;
        }
        if i > start {
            *pos = i;
            return Some(Event::Text(&text[start..i]));
        }
        if i >= bytes.len() {
            return None;
        }
        match bytes[i + 1] {
            b'!' | b'?' => {
                // DOCTYPE / comment / PI: skipped to the next '>'. Full
                // comment scanning is deliberately not implemented --
                // exports carry at most the NETSCAPE doctype, and a
                // pathological comment merely leaks harmless text.
                match find_byte(bytes, i + 2, b'>') {
                    Some(gt) => *pos = gt + 1,
                    None => *pos = bytes.len(),
                }
            }
            b'/' => {
                let (name, after) = read_name(text, i + 2);
                match find_byte(bytes, after, b'>') {
                    Some(gt) => {
                        *pos = gt + 1;
                        return Some(Event::End { name });
                    }
                    None => {
                        *pos = bytes.len();
                        return None;
                    }
                }
            }
            _ => return read_start_tag(text, pos, i),
        }
    }
}

fn read_start_tag<'a>(text: &'a str, pos: &mut usize, lt: usize) -> Option<Event<'a>> {
    let bytes = text.as_bytes();
    let (name, mut i) = read_name(text, lt + 1);
    let mut attrs: Vec<(&'a str, &'a str)> = Vec::new();
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            // Ran out of file inside a tag: the partial tag is dropped, so
            // a truncated tail cannot half-import an entry.
            *pos = bytes.len();
            return None;
        }
        match bytes[i] {
            b'>' => {
                *pos = i + 1;
                return Some(Event::Start { name, attrs });
            }
            b'/' => match find_byte(bytes, i + 1, b'>') {
                Some(gt) => {
                    *pos = gt + 1;
                    return Some(Event::Start { name, attrs });
                }
                None => {
                    *pos = bytes.len();
                    return None;
                }
            },
            _ => {
                let (attr_name, after) = read_name(text, i);
                if after == i {
                    // A stray byte that is none of name / '=' / '>': step
                    // over one whole char, so forward progress is
                    // guaranteed without ever slicing mid-codepoint.
                    i += 1;
                    while i < bytes.len() && !text.is_char_boundary(i) {
                        i += 1;
                    }
                    continue;
                }
                i = after;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                let mut value: &'a str = "";
                if i < bytes.len() && bytes[i] == b'=' {
                    i += 1;
                    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= bytes.len() {
                        *pos = bytes.len();
                        return None;
                    }
                    if bytes[i] == b'"' || bytes[i] == b'\'' {
                        let quote = bytes[i];
                        let vstart = i + 1;
                        match find_byte(bytes, vstart, quote) {
                            Some(vend) => {
                                value = &text[vstart..vend];
                                i = vend + 1;
                            }
                            None => {
                                // Unterminated quote: truncated file.
                                *pos = bytes.len();
                                return None;
                            }
                        }
                    } else {
                        let vstart = i;
                        while i < bytes.len()
                            && !bytes[i].is_ascii_whitespace()
                            && bytes[i] != b'>'
                        {
                            i += 1;
                        }
                        value = &text[vstart..i];
                    }
                }
                attrs.push((attr_name, value));
            }
        }
    }
}

/// Split parsed entries into the ones to add (order preserved, first
/// occurrence wins) and the count of duplicates, against `seen` -- which
/// the caller seeds with the store's existing URLs. Case-sensitive exact
/// match: a case fold or normalisation could merge two genuinely different
/// bookmarks. Pure so the arm's dedup decision is testable without a store.
pub fn split_new<'a>(
    parsed: &'a [ParsedBookmark],
    seen: &mut std::collections::HashSet<String>,
) -> (Vec<&'a ParsedBookmark>, usize) {
    let mut fresh = Vec::new();
    let mut duplicates = 0usize;
    for entry in parsed {
        if seen.insert(entry.url.clone()) {
            fresh.push(entry);
        } else {
            duplicates += 1;
        }
    }
    (fresh, duplicates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls(out: &ImportParse) -> Vec<&str> {
        out.bookmarks.iter().map(|b| b.url.as_str()).collect()
    }

    #[test]
    fn happy_path_firefox_style_export() {
        let input = r#"<!DOCTYPE NETSCAPE-Bookmark-file-1>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>
    <DT><H3 ADD_DATE="1690000000" LAST_MODIFIED="1690000001">Folder name</H3>
    <DL><p>
        <DT><A HREF="https://example.com/" ADD_DATE="1690000000"
               ICON="data:image/png;base64,iVBORw0KGgo=">Page title</A>
    </DL><p>
    <DT><A HREF="https://other.example/">Top-level bookmark</A>
</DL><p>
"#;
        let out = parse(input);
        assert_eq!(out.skipped_unsupported, 0);
        assert_eq!(out.bookmarks.len(), 2);
        assert_eq!(out.bookmarks[0].url, "https://example.com/");
        assert_eq!(out.bookmarks[0].title, "Page title");
        assert_eq!(out.bookmarks[1].url, "https://other.example/");
        assert_eq!(out.bookmarks[1].title, "Top-level bookmark");
    }

    #[test]
    fn missing_close_tags_are_tolerated() {
        // </DT> is routinely absent in real exports; here </H3> and every
        // </DL> are missing too. The DL implicitly closes the open H3.
        let input = r#"<DL><p>
<DT><H3>Folder A
<DL><p>
<DT><A HREF="https://a1.example/">First</A>
<DT><A HREF="https://a2.example/">Second</A>
"#;
        let out = parse(input);
        assert_eq!(urls(&out), ["https://a1.example/", "https://a2.example/"]);
        assert_eq!(out.skipped_unsupported, 0);
    }

    #[test]
    fn tag_and_attribute_case_and_order_do_not_matter() {
        let input = r#"<dL><P><Dt><h3 LAST_MODIFIED="1" ADD_DATE="2">Mixed</H3><Dl><p>
<Dt><a add_date="3" HrEf="https://mixed.example/" ICON='data:x'>T</A>
<DT><A ICON="data:y" HREF='https://single.example/'>Single quotes</A>
<DT><A HREF=https://unquoted.example/>Unquoted</A>
"#;
        let out = parse(input);
        assert_eq!(
            urls(&out),
            [
                "https://mixed.example/",
                "https://single.example/",
                "https://unquoted.example/"
            ]
        );
        assert_eq!(
            out.bookmarks
                .iter()
                .map(|b| b.title.as_str())
                .collect::<Vec<_>>(),
            ["T", "Single quotes", "Unquoted"]
        );
    }

    #[test]
    fn entities_decode_in_titles_and_urls() {
        let input = r#"<DL><p><DT><H3>F&#246;lder</H3><DL><p>
<DT><A HREF="https://e.example/?a=1&amp;b=2">A &amp; B &lt;tag&gt; &quot;q&quot; &#39;ap&#39; &#65;&#x42;&#X43; &#x1F600;</A>
<DT><A HREF="https://e.example/literal?x=&bogus;&amp">kept</A>
"#;
        let out = parse(input);
        assert_eq!(out.bookmarks.len(), 2);
        assert_eq!(out.bookmarks[0].url, "https://e.example/?a=1&b=2");
        assert_eq!(
            out.bookmarks[0].title,
            r#"A & B <tag> "q" 'ap' ABC 😀"#
        );
        // Unknown entities and a trailing '&' without ';' stay literal.
        assert_eq!(
            out.bookmarks[1].url,
            "https://e.example/literal?x=&bogus;&amp"
        );
        assert_eq!(out.skipped_unsupported, 0);
    }

    #[test]
    fn unsupported_and_empty_hrefs_are_skipped_and_counted() {
        let input = r#"<DL><p><DT><A HREF="place:folder=BOOKMARKS_MENU">Smart folder</A>
<DT><A HREF="javascript:alert(1)">Scriptlet</A>
<DT><A HREF="JavaScript:alert(2)">Case variant</A>
<DT><A HREF="data:text/html;base64,AAAA">Data</A>
<DT><A HREF="">Empty</A>
<DT><A HREF="   ">Blank</A>
<DT><A>No href at all</A>
<DT><A HREF="https://keep.example/">Keep</A>"#;
        let out = parse(input);
        assert_eq!(urls(&out), ["https://keep.example/"]);
        // The no-HREF anchor is page junk, not a failed bookmark, so it is
        // not counted: 6 refusals, not 7.
        assert_eq!(out.skipped_unsupported, 6);
    }

    #[test]
    fn truncated_file_mid_tag_keeps_what_was_complete() {
        let input = r#"<DL><p><DT><A HREF="https://a.example/">First</A><DT><A HREF="https://b.example/"#;
        let out = parse(input);
        assert_eq!(urls(&out), ["https://a.example/"]);
        // The cut-off entry is dropped, not refused, so nothing is counted.
        assert_eq!(out.skipped_unsupported, 0);
    }

    #[test]
    fn truncated_file_mid_text_keeps_what_was_complete() {
        let input = r#"<DL><p><DT><A HREF="https://a.example/">First</A><DT><A HREF="https://b.example/">Sec"#;
        let out = parse(input);
        assert_eq!(urls(&out), ["https://a.example/"]);
    }

    #[test]
    fn empty_input_is_an_empty_parse_not_an_error() {
        let out = parse("");
        assert!(out.bookmarks.is_empty());
        assert_eq!(out.skipped_unsupported, 0);
    }

    #[test]
    fn empty_title_falls_back_to_url() {
        let input = r#"<DL><p><DT><A HREF="https://notitle.example/"></A>
<DT><A HREF="https://blank.example/">   </A>
<DT><A HREF="https://spaceent.example/"> &#32; </A>
<DT><A HREF="https://pad.example/">  Padded  </A>"#;
        let out = parse(input);
        assert_eq!(
            out.bookmarks
                .iter()
                .map(|b| b.title.as_str())
                .collect::<Vec<_>>(),
            [
                "https://notitle.example/",
                "https://blank.example/",
                "https://spaceent.example/",
                "Padded"
            ]
        );
    }

    #[test]
    fn firefox_separators_and_extra_attributes_are_ignored() {
        let input = r#"<DL><p><HR><DT><A HREF="https://a.example/" SHORTCUTURL="kw" TAGS="one,two" ICON_URI="https://a.example/favicon.ico" LAST_CHARSET="UTF-8">A</A>
<HR CLASS="sidebar-ruler">
<DT><A HREF="https://b.example/">B</A>"#;
        let out = parse(input);
        assert_eq!(urls(&out), ["https://a.example/", "https://b.example/"]);
        assert_eq!(out.skipped_unsupported, 0);
    }

    #[test]
    fn stray_less_than_in_text_is_literal() {
        let input = r#"<DL><p><DT><A HREF="https://x.example/">1 &lt; 2 and I <3 it</A>"#;
        let out = parse(input);
        assert_eq!(out.bookmarks[0].title, "1 < 2 and I <3 it");
    }

    #[test]
    fn multibyte_utf8_and_truncation_do_not_panic() {
        let input = r#"<DL><p><DT><A tést="1" HREF="https://w.example/">日本語 タイトル 🦀</A><DT><A HREF="https://v.example/">"#;
        let out = parse(input);
        assert_eq!(out.bookmarks.len(), 1);
        assert_eq!(out.bookmarks[0].url, "https://w.example/");
        assert_eq!(out.bookmarks[0].title, "日本語 タイトル 🦀");
    }

    #[test]
    fn duplicates_are_kept_by_the_parser() {
        // Dedup lives in the import arm (it must also dedup against the
        // existing store), so the parser reports every entry verbatim and
        // the arm decides what is a duplicate.
        let input = r#"<DL><p><DT><A HREF="https://dup.example/">One</A><DT><A HREF="https://dup.example/">Two</A>"#;
        let out = parse(input);
        assert_eq!(out.bookmarks.len(), 2);
    }

    #[test]
    fn mismatched_dl_close_is_tolerated() {
        let input = r#"<DL><p></DL><DT><A HREF="https://x.example/">X</A>"#;
        let out = parse(input);
        assert_eq!(out.bookmarks.len(), 1);
    }

    // --- Dedup plan --------------------------------------------------------

    fn entry(url: &str) -> ParsedBookmark {
        ParsedBookmark {
            url: url.to_string(),
            title: url.to_string(),
        }
    }

    #[test]
    fn split_new_dedups_against_the_store_and_within_the_file() {
        let parsed = vec![
            entry("https://in-store.example/"),
            entry("https://fresh.example/"),
            entry("https://fresh.example/"),
            entry("https://also-fresh.example/"),
        ];
        let mut seen: std::collections::HashSet<String> =
            std::iter::once("https://in-store.example/".to_string()).collect();
        let (fresh, duplicates) = split_new(&parsed, &mut seen);
        assert_eq!(
            fresh.iter().map(|b| b.url.as_str()).collect::<Vec<_>>(),
            ["https://fresh.example/", "https://also-fresh.example/"],
            "first occurrence wins, order preserved"
        );
        assert_eq!(duplicates, 2, "one store duplicate + one in-file duplicate");
    }

    #[test]
    fn split_new_is_case_sensitive_on_purpose() {
        // /Path and /path can be two different pages; merging them would
        // silently drop a bookmark the user chose to keep.
        let parsed = vec![entry("https://x.example/Path"), entry("https://x.example/path")];
        let mut seen = std::collections::HashSet::new();
        let (fresh, duplicates) = split_new(&parsed, &mut seen);
        assert_eq!(fresh.len(), 2);
        assert_eq!(duplicates, 0);
    }
}
