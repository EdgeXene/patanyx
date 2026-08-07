//! A small, total, deterministic HTML tokenizer.
//!
//! Why hand-written: the design forbids `html5ever`/`scraper`, and we do
//! not need spec-correct parsing — we need a *stable, deterministic* event
//! stream. The output is a flat token stream, not a tree: unclosed tags and
//! malformed nesting therefore cannot break anything, they just appear
//! as-is. Divergences from the HTML5 spec are deliberate and documented
//! inline; every rule here is fixed forever, because the structure hash is
//! only meaningful if the tokenizer never changes its mind.
//!
//! Supported: start/end tags, attributes (quoted, unquoted, boolean),
//! comments (dropped), doctype, CDATA/processing-instruction bogus comments
//! (dropped), raw-text mode for `<script>` and `<style>` (bodies dropped),
//! and a deliberately tiny entity table (ten named references plus numeric
//! references) — not the full HTML5 named-reference table, which would be
//! 2000+ entries of attack surface for zero digest-relevant benefit.

/// One token of the flat stream. Text is entity-decoded but NOT yet
/// whitespace-collapsed (that happens in `normalize`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    StartTag {
        /// ASCII-lowercased tag name.
        name: String,
        /// (name, value) pairs in document order; names ASCII-lowercased,
        /// values entity-decoded. Sorting/filtering happens in `normalize`.
        attrs: Vec<(String, String)>,
        self_closing: bool,
    },
    EndTag {
        name: String,
    },
    Text(String),
    /// ASCII-lowercased doctype name ("" if absent).
    Doctype(String),
}

enum Markup {
    Event(Event),
    /// Comments, CDATA, processing instructions, bogus comments: consumed
    /// but producing no event.
    Skipped,
}

pub fn tokenize(input: &str) -> Vec<Event> {
    Tokenizer {
        b: input.as_bytes(),
        pos: 0,
        events: Vec::new(),
    }
    .run()
}

struct Tokenizer<'a> {
    b: &'a [u8],
    pos: usize,
    events: Vec<Event>,
}

/// HTML's ASCII whitespace, as an explicit fixed table. Deliberately not
/// `u8::is_ascii_whitespace`, which includes vertical tab (0x0B) that the
/// HTML spec excludes — the table must match the spec, not the stdlib.
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0C | b'\r')
}

fn is_raw_text_tag(name: &str) -> bool {
    name == "script" || name == "style"
}

/// Byte length of the UTF-8 char starting with lead byte `b`; 1 for
/// continuation bytes (defensive — the input was already lossy-decoded, so
/// every slice point below is a genuine char boundary, and the from_utf8
/// checks are belt-and-braces rather than load-bearing).
fn utf8_width(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b < 0xC0 {
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

impl<'a> Tokenizer<'a> {
    fn run(mut self) -> Vec<Event> {
        let mut text = String::new();
        while self.pos < self.b.len() {
            match self.b[self.pos] {
                b'<' => match self.parse_markup() {
                    Some(markup) => {
                        if !text.is_empty() {
                            self.events.push(Event::Text(std::mem::take(&mut text)));
                        }
                        if let Markup::Event(ev) = markup {
                            // Per the HTML spec, script/style are raw-text
                            // elements and a self-closing slash on them is
                            // ignored — so raw-text mode is entered whether
                            // or not the tag looked self-closing.
                            let raw_tag = match &ev {
                                Event::StartTag { name, .. } if is_raw_text_tag(name) => {
                                    Some(name.clone())
                                }
                                _ => None,
                            };
                            self.events.push(ev);
                            if let Some(tag) = raw_tag {
                                self.consume_raw_text(&tag);
                            }
                        }
                    }
                    // '<' not followed by markup is literal text (HTML spec).
                    None => {
                        text.push('<');
                        self.pos += 1;
                    }
                },
                b'&' => match decode_entity(self.b, self.pos) {
                    Some((decoded, consumed)) => {
                        text.push_str(&decoded);
                        self.pos += consumed;
                    }
                    None => {
                        text.push('&');
                        self.pos += 1;
                    }
                },
                byte => {
                    let end = (self.pos + utf8_width(byte)).min(self.b.len());
                    if let Ok(s) = std::str::from_utf8(&self.b[self.pos..end]) {
                        text.push_str(s);
                    }
                    self.pos = end;
                }
            }
        }
        if !text.is_empty() {
            self.events.push(Event::Text(text));
        }
        self.events
    }

    /// At '<'. Returns None if this is not markup at all (literal '<').
    fn parse_markup(&mut self) -> Option<Markup> {
        let next = *self.b.get(self.pos + 1)?;
        match next {
            b'a'..=b'z' | b'A'..=b'Z' => Some(Markup::Event(self.parse_start_tag())),
            b'/' => Some(self.parse_end_tag_or_bogus()),
            b'!' => Some(self.parse_declaration()),
            b'?' => {
                // Processing instruction: bogus comment per spec.
                self.skip_past_gt();
                Some(Markup::Skipped)
            }
            _ => None,
        }
    }

    fn parse_start_tag(&mut self) -> Event {
        self.pos += 1; // consume '<'
        let name = self.scan_tag_name();
        let mut attrs = Vec::new();
        let mut self_closing = false;
        loop {
            self.skip_ws();
            let Some(&b) = self.b.get(self.pos) else {
                break; // EOF inside a tag: emit what we have
            };
            match b {
                b'>' => {
                    self.pos += 1;
                    break;
                }
                b'/' => {
                    if self.b.get(self.pos + 1) == Some(&b'>') {
                        self.pos += 2;
                        self_closing = true;
                        break;
                    }
                    // Stray slash inside a tag: ignored per spec.
                    self.pos += 1;
                }
                _ => {
                    let attr_name = self.scan_attr_name();
                    if attr_name.is_empty() {
                        // e.g. a stray '=' where a name should be: skip one
                        // byte so the loop always makes progress.
                        self.pos += 1;
                        continue;
                    }
                    self.skip_ws();
                    let mut value = String::new();
                    if self.b.get(self.pos) == Some(&b'=') {
                        self.pos += 1;
                        self.skip_ws();
                        value = self.scan_attr_value();
                    }
                    attrs.push((attr_name, value));
                }
            }
        }
        Event::StartTag {
            name,
            attrs,
            self_closing,
        }
    }

    fn parse_end_tag_or_bogus(&mut self) -> Markup {
        match self.b.get(self.pos + 2) {
            Some(&b) if b.is_ascii_alphabetic() => {
                self.pos += 2; // consume '</'
                let name = self.scan_tag_name();
                // Attributes on end tags carry no meaning: discard them.
                self.skip_past_gt();
                Markup::Event(Event::EndTag { name })
            }
            // "</>" or "</ x>": bogus comment per spec.
            _ => {
                self.skip_past_gt();
                Markup::Skipped
            }
        }
    }

    fn parse_declaration(&mut self) -> Markup {
        let rest = &self.b[self.pos..];
        if rest.starts_with(b"<!--") {
            // Comments are dropped entirely: they are volatile by
            // convention (build markers, server stats).
            self.pos += 4;
            match find_subslice(&self.b[self.pos..], b"-->") {
                Some(off) => self.pos += off + 3,
                None => self.pos = self.b.len(), // unterminated comment eats EOF
            }
            return Markup::Skipped;
        }
        if rest.len() >= 9
            && rest[..9].eq_ignore_ascii_case(b"<!doctype")
            && self
                .b
                .get(self.pos + 9)
                .map_or(true, |&b| is_ws(b) || b == b'>')
        {
            self.pos += 9;
            self.skip_ws();
            let name = self.scan_tag_name();
            self.skip_past_gt(); // discard any public/system identifiers
            return Markup::Event(Event::Doctype(name));
        }
        // CDATA and other markup declarations: bogus comment in HTML
        // content per spec. (Real CDATA only exists in foreign content,
        // which this tokenizer deliberately does not model.)
        self.skip_past_gt();
        Markup::Skipped
    }

    /// Raw-text mode for script/style: the body is discarded entirely —
    /// both the structure level and the text level ignore it by design.
    /// Ends at the first `</tag` followed by whitespace, '/', '>' or EOF
    /// (the spec's end-tag rule); "</scriptx>" is not a closer.
    fn consume_raw_text(&mut self, tag: &str) {
        let mut needle = b"</".to_vec();
        needle.extend_from_slice(tag.as_bytes());
        let mut scan = self.pos;
        loop {
            match find_ascii_case_insensitive(self.b, scan, &needle) {
                None => {
                    // Unclosed script/style: the rest of the document is
                    // raw text and disappears.
                    self.pos = self.b.len();
                    return;
                }
                Some(at) => {
                    let after = at + needle.len();
                    match self.b.get(after) {
                        Some(&b) if is_ws(b) || b == b'/' || b == b'>' => {
                            self.pos = after;
                            self.skip_past_gt();
                            self.events.push(Event::EndTag {
                                name: tag.to_string(),
                            });
                            return;
                        }
                        None => {
                            self.pos = self.b.len();
                            self.events.push(Event::EndTag {
                                name: tag.to_string(),
                            });
                            return;
                        }
                        _ => scan = at + 1,
                    }
                }
            }
        }
    }

    /// Tag name: runs until whitespace, '/' or '>'. ('=' is a legal tag-name
    /// char per spec — it only terminates *attribute* names.)
    fn scan_tag_name(&mut self) -> String {
        let start = self.pos;
        while let Some(&b) = self.b.get(self.pos) {
            if is_ws(b) || b == b'/' || b == b'>' {
                break;
            }
            self.pos += 1;
        }
        ascii_lower(&self.b[start..self.pos])
    }

    /// Attribute name: runs until whitespace, '=', '/' or '>'.
    fn scan_attr_name(&mut self) -> String {
        let start = self.pos;
        while let Some(&b) = self.b.get(self.pos) {
            if is_ws(b) || b == b'=' || b == b'/' || b == b'>' {
                break;
            }
            self.pos += 1;
        }
        ascii_lower(&self.b[start..self.pos])
    }

    fn scan_attr_value(&mut self) -> String {
        match self.b.get(self.pos) {
            Some(&q) if q == b'"' || q == b'\'' => {
                self.pos += 1;
                let mut out = String::new();
                while let Some(&b) = self.b.get(self.pos) {
                    if b == q {
                        self.pos += 1;
                        return out;
                    }
                    if b == b'&' {
                        match decode_entity(self.b, self.pos) {
                            Some((s, n)) => {
                                out.push_str(&s);
                                self.pos += n;
                            }
                            None => {
                                out.push('&');
                                self.pos += 1;
                            }
                        }
                    } else {
                        let end = (self.pos + utf8_width(b)).min(self.b.len());
                        if let Ok(s) = std::str::from_utf8(&self.b[self.pos..end]) {
                            out.push_str(s);
                        }
                        self.pos = end;
                    }
                }
                out // EOF inside a quoted value: the rest is the value
            }
            _ => {
                // Unquoted value: runs until whitespace or '>'. A '/' is a
                // legal char here per spec. The stop bytes are ASCII, so the
                // slice never splits a multi-byte char.
                let start = self.pos;
                while let Some(&b) = self.b.get(self.pos) {
                    if is_ws(b) || b == b'>' {
                        break;
                    }
                    self.pos += 1;
                }
                decode_entities(&self.b[start..self.pos])
            }
        }
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.b.get(self.pos) {
            if !is_ws(b) {
                break;
            }
            self.pos += 1;
        }
    }

    fn skip_past_gt(&mut self) {
        while let Some(&b) = self.b.get(self.pos) {
            self.pos += 1;
            if b == b'>' {
                return;
            }
        }
    }
}

fn ascii_lower(bytes: &[u8]) -> String {
    // ASCII-only lowercasing: HTML tag/attribute names are ASCII
    // case-insensitive, and full Unicode lowercasing would tie digests to a
    // Unicode version.
    let lowered: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    String::from_utf8_lossy(&lowered).into_owned()
}

/// Decode the entity at `at` (`b[at] == b'&'`). Returns the replacement and
/// the number of input bytes consumed, or None if this is not a recognized
/// entity — unrecognized or unterminated entities stay literal, which keeps
/// the tokenizer total.
fn decode_entity(b: &[u8], at: usize) -> Option<(String, usize)> {
    let rest = b.get(at..)?;
    // The semicolon is required for every entry: that is what makes the
    // table unambiguous without the HTML5 lookahead rules.
    const NAMED: [(&[u8], &str); 10] = [
        (b"&amp;", "&"),
        (b"&AMP;", "&"),
        (b"&lt;", "<"),
        (b"&LT;", "<"),
        (b"&gt;", ">"),
        (b"&GT;", ">"),
        (b"&quot;", "\""),
        (b"&QUOT;", "\""),
        (b"&apos;", "'"),
        (b"&nbsp;", "\u{00A0}"),
    ];
    for (pat, rep) in NAMED {
        if rest.starts_with(pat) {
            return Some((rep.to_string(), pat.len()));
        }
    }
    if rest.starts_with(b"&#") {
        let mut i = at + 2;
        let hex = matches!(b.get(i), Some(b'x') | Some(b'X'));
        if hex {
            i += 1;
        }
        let start = i;
        // Saturating accumulate: a 40-digit "codepoint" must not overflow.
        let mut value: u32 = 0;
        while let Some(&d) = b.get(i) {
            let digit = match d {
                b'0'..=b'9' => (d - b'0') as u32,
                b'a'..=b'f' if hex => (d - b'a') as u32 + 10,
                b'A'..=b'F' if hex => (d - b'A') as u32 + 10,
                _ => break,
            };
            value = value
                .saturating_mul(if hex { 16 } else { 10 })
                .saturating_add(digit)
                .min(0x11_0000);
            i += 1;
        }
        if i == start || b.get(i) != Some(&b';') {
            return None; // no digits, or missing ';': literal '&'
        }
        i += 1; // consume ';'
        // The spec's windows-1252 remapping of 0x80..=0x9F is deliberately
        // not implemented (v1 simplicity); out-of-range, zero, and
        // surrogates map to U+FFFD.
        let ch = if value == 0 || value > 0x10FFFF {
            '\u{FFFD}'
        } else {
            char::from_u32(value).unwrap_or('\u{FFFD}')
        };
        return Some((ch.to_string(), i - at));
    }
    None
}

fn decode_entities(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some((s, n)) = decode_entity(bytes, i) {
                out.push_str(&s);
                i += n;
                continue;
            }
        }
        let end = (i + utf8_width(bytes[i])).min(bytes.len());
        if let Ok(s) = std::str::from_utf8(&bytes[i..end]) {
            out.push_str(s);
        }
        i = end;
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn find_ascii_case_insensitive(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let mut i = from;
    while i + needle.len() <= hay.len() {
        if hay[i] == b'<' && hay[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(i);
        }
        i += 1;
    }
    None
}
