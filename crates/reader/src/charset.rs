//! Bytes to text, for text a person will read.
//!
//! The integrity crate decodes lossily on purpose: its text is hashed, never
//! shown. Reader View shows what it decodes, so a page in a legacy encoding
//! must come out as the words the author wrote, or not at all.
//!
//! The main-resource capture hands us body bytes without the response
//! headers, so the encoding is found the way the HTML standard's prescan
//! does it without a transport label: a byte-order mark, then a `<meta>`
//! declaration near the top of the document, then a guess between UTF-8
//! and windows-1252 (the web's default legacy encoding).
//!
//! Supported: UTF-8, and the labels the Encoding Standard maps to
//! windows-1252 (which include ISO-8859-1 and US-ASCII). Anything else is
//! reported as unsupported rather than rendered as mojibake.

use crate::ReaderError;

/// How far into the document the `<meta>` prescan looks. The standard
/// uses 1024 bytes; real pages put a long `<head>` before the charset
/// often enough that a little more slack avoids a wrong guess, and the
/// scan is linear and cheap.
const PRESCAN_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Utf8,
    Windows1252,
}

/// Decode `bytes` to a String using the declared or detected encoding.
pub(crate) fn decode(bytes: &[u8]) -> Result<String, ReaderError> {
    if let Some(rest) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        return Ok(String::from_utf8_lossy(rest).into_owned());
    }
    if bytes.starts_with(b"\xFF\xFE") || bytes.starts_with(b"\xFE\xFF") {
        return Err(ReaderError::UnsupportedEncoding("utf-16".into()));
    }
    let encoding = match declared_label(&bytes[..bytes.len().min(PRESCAN_BYTES)]) {
        Some(label) => match encoding_for_label(&label) {
            Some(e) => e,
            None => return Err(ReaderError::UnsupportedEncoding(label)),
        },
        None => {
            // Undeclared in the body. The real encoding may have been in the
            // response header, which this capture does not carry, so a guess
            // here could be confidently wrong (review R-007: a
            // windows-1251 page rendered as Latin mojibake). Valid UTF-8 is
            // safe to read; anything else is refused, not guessed.
            if std::str::from_utf8(bytes).is_ok() {
                Encoding::Utf8
            } else {
                return Err(ReaderError::UnsupportedEncoding("undeclared".into()));
            }
        }
    };
    Ok(match encoding {
        // Declared UTF-8 with a stray bad byte: show U+FFFD for that byte
        // rather than refuse the whole article.
        Encoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        Encoding::Windows1252 => bytes.iter().map(|&b| windows_1252(b)).collect(),
    })
}

/// The label from the first `<meta charset=...>` or
/// `<meta http-equiv="content-type" content="...; charset=...">` whose label
/// this crate can decode, following the HTML standard's encoding prescan.
/// Lowercased and trimmed of ASCII whitespace; None when nothing usable is
/// declared.
///
/// Attributes are parsed, not searched (review R-006): a commented-out
/// `<meta>` is skipped, and the word "charset" inside some other attribute's
/// value (a description, say) is not a declaration. Review round 5 brought
/// the rest of the prescan in: a tag cut off by the end of the input aborts
/// the scan instead of deciding it (R-002); the pragma must be exactly
/// "content-type" (R-001); and a leading XML declaration's encoding is the
/// fallback (R-005). As the standard says, the first declaration naming a
/// real encoding decides, even one this crate cannot decode (the page is
/// then refused, never read as something else); a label that names no
/// encoding is skipped (round 5 R-003, final review R-002).
fn declared_label(head: &[u8]) -> Option<String> {
    let lower: Vec<u8> = head.iter().map(u8::to_ascii_lowercase).collect();
    let finish = || xml_encoding(&lower).filter(|l| is_encoding_label(l));
    let mut i = 0;
    while i < lower.len() {
        if lower[i..].starts_with(b"<!--") {
            // The opener's own hyphens may close it: `<!-->` is a whole
            // comment (the standard's prescan; review round 4, R-004).
            match find(&lower[i + 2..], b"-->") {
                Some(p) => i = i + 2 + p + 3,
                None => return finish(),
            }
            continue;
        }
        // Whitespace or "/" after the name, as the standard's prescan
        // requires: `<meta-widget charset=...>` is some other element
        // (review round 3, R-004).
        if lower[i..].starts_with(b"<meta")
            && lower.get(i + 5).is_some_and(|c| c.is_ascii_whitespace() || *c == b'/')
        {
            let (attrs, end, complete) = parse_attrs(&lower, i + 5);
            if !complete {
                return finish();
            }
            let get = |k: &str| attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            // A charset attribute decides this meta even when it is empty:
            // the content attribute is not a fallback for it (review round
            // 4, R-006).
            let label = match get("charset") {
                Some(cs) => Some(ascii_trim(&cs).to_string()).filter(|l| !l.is_empty()),
                None if get("http-equiv").as_deref() == Some("content-type") => {
                    get("content").as_deref().and_then(charset_in_content)
                }
                None => None,
            };
            if let Some(label) = label.filter(|l| is_encoding_label(l)) {
                return Some(label);
            }
            i = end;
            continue;
        }
        // Any other tag is stepped over whole, its attributes parsed like a
        // meta's, so a quoted value cannot smuggle in a declaration
        // (review round 2, R-004: <link title="<meta charset=...>">). The
        // HTML standard's encoding prescan does the same, end tags included;
        // "<!" and "<?" run to the next '>'.
        if lower[i] == b'<' {
            let next = lower.get(i + 1).copied().unwrap_or(0);
            let end_tag = next == b'/' && lower.get(i + 2).is_some_and(u8::is_ascii_alphabetic);
            if next.is_ascii_alphabetic() || end_tag {
                let mut j = i + if end_tag { 2 } else { 1 };
                while j < lower.len() && !lower[j].is_ascii_whitespace() && lower[j] != b'>' {
                    j += 1;
                }
                let (_, end, complete) = parse_attrs(&lower, j);
                if !complete {
                    return finish();
                }
                i = end;
                continue;
            }
            if matches!(next, b'!' | b'/' | b'?') {
                match find(&lower[i + 1..], b">") {
                    Some(p) => i = i + 1 + p + 1,
                    None => return finish(),
                }
                continue;
            }
        }
        i += 1;
    }
    finish()
}

/// The encoding a leading XML declaration names: the standard's "get an
/// XML encoding". `lower` is already lowercase.
fn xml_encoding(lower: &[u8]) -> Option<String> {
    if !lower.starts_with(b"<?xml") {
        return None;
    }
    let decl = &lower[..find(lower, b">")?];
    let mut j = find(decl, b"encoding")? + "encoding".len();
    while j < decl.len() && decl[j] <= 0x20 {
        j += 1;
    }
    if decl.get(j) != Some(&b'=') {
        return None;
    }
    j += 1;
    while j < decl.len() && decl[j] <= 0x20 {
        j += 1;
    }
    let quote = *decl.get(j).filter(|q| matches!(q, b'"' | b'\''))?;
    let close = j + 1 + decl[j + 1..].iter().position(|&c| c == quote)?;
    let label = ascii_trim(std::str::from_utf8(&decl[j + 1..close]).ok()?);
    (!label.is_empty()).then(|| label.to_string())
}

/// Trim ASCII whitespace only, as encoding labels are (a vertical tab is not
/// ASCII whitespace there; review round 5, R-001).
fn ascii_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_ascii_whitespace())
}

/// The standard's "extracting a character encoding from a meta element":
/// each "charset" in turn, which counts only when "=" follows it; a quoted
/// label needs its closing quote, so `charset='windows-1252` with the quote
/// left open is no declaration at all (review round 4, R-005). `content` is
/// already lowercase.
fn charset_in_content(content: &str) -> Option<String> {
    let b = content.as_bytes();
    let mut pos = 0;
    loop {
        let at = pos + content[pos..].find("charset")?;
        let mut j = at + "charset".len();
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) != Some(&b'=') {
            pos = j;
            continue;
        }
        j += 1;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        let label = match b.get(j)? {
            q @ (b'"' | b'\'') => {
                let close = content[j + 1..].find(*q as char)?;
                &content[j + 1..j + 1 + close]
            }
            _ => {
                let len = content[j..]
                    .find(|c: char| c.is_ascii_whitespace() || c == ';')
                    .unwrap_or(content.len() - j);
                &content[j..j + len]
            }
        };
        let label = ascii_trim(label);
        return (!label.is_empty()).then(|| label.to_string());
    }
}

/// Attributes of a tag starting at `from` (just past its name), as
/// (name, value) pairs, the index just past the tag's `>`, and whether that
/// `>` was found (false: the input ended inside the tag).
fn parse_attrs(b: &[u8], from: usize) -> (Vec<(String, String)>, usize, bool) {
    let mut out = Vec::new();
    let mut i = from;
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return (out, b.len(), false);
        }
        if b[i] == b'>' {
            return (out, i + 1, true);
        }
        let ns = i;
        // An "=" before any name character is part of the name, not the
        // start of a value (the standard's prescan; review round 3, R-003):
        // read as a separator, `="` opened a quoted value that ran over the
        // real declaration after it.
        if b[i] == b'=' {
            i += 1;
        }
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let name = String::from_utf8_lossy(&b[ns..i]).into_owned();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let vs = i + 1;
                i = vs;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                value = String::from_utf8_lossy(&b[vs..i.min(b.len())]).into_owned();
                i = (i + 1).min(b.len());
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                value = String::from_utf8_lossy(&b[vs..i]).into_owned();
            }
        }
        if !name.is_empty() {
            out.push((name, value));
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The labels this crate decodes, per the WHATWG Encoding Standard's label
/// table for the two encodings it supports.
fn encoding_for_label(label: &str) -> Option<Encoding> {
    match label {
        "utf-8" | "utf8" | "unicode-1-1-utf-8" | "unicode11utf8" | "unicode20utf8"
        | "x-unicode20utf8" => Some(Encoding::Utf8),
        "windows-1252" | "cp1252" | "x-cp1252" | "iso-8859-1" | "iso8859-1" | "iso88591"
        | "iso_8859-1" | "iso_8859-1:1987" | "latin1" | "l1" | "ibm819" | "cp819"
        | "csisolatin1" | "iso-ir-100" | "us-ascii" | "ascii" | "ansi_x3.4-1968"
        | "iso-8859-1:1987" => Some(Encoding::Windows1252),
        // A meta or XML declaration naming UTF-16 is read as UTF-8, and
        // x-user-defined as windows-1252: the standard's remapping for
        // declarations found by the prescan (review round 5, R-004). Real
        // UTF-16 bytes carry a BOM and are refused before this.
        "utf-16" | "utf-16le" | "utf-16be" | "unicode" | "unicodefeff" | "unicodefffe"
        | "ucs-2" | "csunicode" | "iso-10646-ucs-2" => Some(Encoding::Utf8),
        "x-user-defined" => Some(Encoding::Windows1252),
        _ => None,
    }
}

/// Every label the Encoding Standard defines (https://encoding.spec.whatwg.org/
/// "Names and labels"), lowercase and sorted for binary search: 228 labels for
/// 40 encodings. A declaration naming one of these is the page's encoding,
/// whether or not this crate can decode it; anything else is not an
/// encoding at all, and the prescan skips it (final review, R-002).
const ENCODING_LABELS: [&str; 228] = [
    "866", "ansi_x3.4-1968", "arabic", "ascii", "asmo-708", "big5", "big5-hkscs", "chinese",
    "cn-big5", "cp1250", "cp1251", "cp1252", "cp1253", "cp1254", "cp1255", "cp1256", "cp1257",
    "cp1258", "cp819", "cp866", "csbig5", "cseuckr", "cseucpkdfmtjapanese", "csgb2312",
    "csibm866", "csiso2022jp", "csiso2022kr", "csiso58gb231280", "csiso88596e", "csiso88596i",
    "csiso88598e", "csiso88598i", "csisolatin1", "csisolatin2", "csisolatin3", "csisolatin4",
    "csisolatin5", "csisolatin6", "csisolatin9", "csisolatinarabic", "csisolatincyrillic",
    "csisolatingreek", "csisolatinhebrew", "cskoi8r", "csksc56011987", "csmacintosh",
    "csshiftjis", "csunicode", "cyrillic", "dos-874", "ecma-114", "ecma-118", "elot_928",
    "euc-jp", "euc-kr", "gb18030", "gb2312", "gb_2312", "gb_2312-80", "gbk", "greek", "greek8",
    "hebrew", "hz-gb-2312", "ibm819", "ibm866", "iso-10646-ucs-2", "iso-2022-cn",
    "iso-2022-cn-ext", "iso-2022-jp", "iso-2022-kr", "iso-8859-1", "iso-8859-10", "iso-8859-11",
    "iso-8859-13", "iso-8859-14", "iso-8859-15", "iso-8859-16", "iso-8859-2", "iso-8859-3",
    "iso-8859-4", "iso-8859-5", "iso-8859-6", "iso-8859-6-e", "iso-8859-6-i", "iso-8859-7",
    "iso-8859-8", "iso-8859-8-e", "iso-8859-8-i", "iso-8859-9", "iso-ir-100", "iso-ir-101",
    "iso-ir-109", "iso-ir-110", "iso-ir-126", "iso-ir-127", "iso-ir-138", "iso-ir-144",
    "iso-ir-148", "iso-ir-149", "iso-ir-157", "iso-ir-58", "iso8859-1", "iso8859-10",
    "iso8859-11", "iso8859-13", "iso8859-14", "iso8859-15", "iso8859-2", "iso8859-3",
    "iso8859-4", "iso8859-5", "iso8859-6", "iso8859-7", "iso8859-8", "iso8859-9", "iso88591",
    "iso885910", "iso885911", "iso885913", "iso885914", "iso885915", "iso88592", "iso88593",
    "iso88594", "iso88595", "iso88596", "iso88597", "iso88598", "iso88599", "iso_8859-1",
    "iso_8859-15", "iso_8859-1:1987", "iso_8859-2", "iso_8859-2:1987", "iso_8859-3",
    "iso_8859-3:1988", "iso_8859-4", "iso_8859-4:1988", "iso_8859-5", "iso_8859-5:1988",
    "iso_8859-6", "iso_8859-6:1987", "iso_8859-7", "iso_8859-7:1987", "iso_8859-8",
    "iso_8859-8:1988", "iso_8859-9", "iso_8859-9:1989", "koi", "koi8", "koi8-r", "koi8-ru",
    "koi8-u", "koi8_r", "korean", "ks_c_5601-1987", "ks_c_5601-1989", "ksc5601", "ksc_5601",
    "l1", "l2", "l3", "l4", "l5", "l6", "l9", "latin1", "latin2", "latin3", "latin4", "latin5",
    "latin6", "logical", "mac", "macintosh", "ms932", "ms_kanji", "replacement", "shift-jis",
    "shift_jis", "sjis", "sun_eu_greek", "tis-620", "ucs-2", "unicode", "unicode-1-1-utf-8",
    "unicode11utf8", "unicode20utf8", "unicodefeff", "unicodefffe", "us-ascii", "utf-16",
    "utf-16be", "utf-16le", "utf-8", "utf8", "visual", "windows-1250", "windows-1251",
    "windows-1252", "windows-1253", "windows-1254", "windows-1255", "windows-1256",
    "windows-1257", "windows-1258", "windows-31j", "windows-874", "windows-949", "x-cp1250",
    "x-cp1251", "x-cp1252", "x-cp1253", "x-cp1254", "x-cp1255", "x-cp1256", "x-cp1257",
    "x-cp1258", "x-euc-jp", "x-gbk", "x-mac-cyrillic", "x-mac-roman", "x-mac-ukrainian",
    "x-sjis", "x-unicode20utf8", "x-user-defined", "x-x-big5",
];

fn is_encoding_label(label: &str) -> bool {
    ENCODING_LABELS.binary_search(&label).is_ok()
}

/// windows-1252: identical to Latin-1 except 0x80..=0x9F.
fn windows_1252(b: u8) -> char {
    const HIGH: [char; 32] = [
        '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}',
        '\u{017D}', '\u{008F}', '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}',
        '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}',
        '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
    ];
    match b {
        0x80..=0x9F => HIGH[(b - 0x80) as usize],
        _ => b as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r2_004_a_meta_written_inside_another_tags_attribute_is_not_a_declaration() {
        // Review round 2 (R-004), reproduced before fixing: the scan stepped
        // byte by byte through other tags and found this fake declaration.
        let page = "<link title=\"<meta charset=windows-1252>\"><meta charset=utf-8><p>caf\u{e9}</p>";
        assert_eq!(declared_label(page.as_bytes()).as_deref(), Some("utf-8"));
        assert!(decode(page.as_bytes()).unwrap().contains("caf\u{e9}"));
        let single = "<a href='x' data-x='<meta charset=windows-1252>'>a</a><meta charset=utf-8>";
        assert_eq!(declared_label(single.as_bytes()).as_deref(), Some("utf-8"));
        let end = "<p>a</p x=\"><meta charset=windows-1252>\"><meta charset=utf-8>";
        assert_eq!(declared_label(end.as_bytes()).as_deref(), Some("utf-8"));
    }

    #[test]
    fn r3_003_a_leading_equals_is_part_of_the_name_not_a_quote_opener() {
        // Review round 3 (R-003): the stray `="` opened a quoted value that
        // swallowed the real declaration after it.
        let page = b"<link =\"x><meta charset=windows-1252><p>caf\xe9</p>";
        assert_eq!(declared_label(page).as_deref(), Some("windows-1252"));
        assert!(decode(page).unwrap().contains("caf\u{e9}"));
    }

    #[test]
    fn r3_004_a_custom_element_named_meta_something_is_not_a_meta() {
        // Review round 3 (R-004): `<meta-widget charset=...>` was read as a
        // declaration; the standard needs whitespace or `/` after `<meta`.
        let page = "<meta-widget charset=windows-1252><meta charset=utf-8><p>caf\u{e9}</p>";
        assert_eq!(declared_label(page.as_bytes()).as_deref(), Some("utf-8"));
        assert_eq!(declared_label(b"<meta/charset=utf-8>").as_deref(), Some("utf-8"));
    }

    #[test]
    fn r4_004_the_comment_opener_hyphens_can_close_it() {
        // `<!-->` is a whole comment in the standard's prescan.
        let page = b"<!--><meta charset=windows-1252><p>caf\xe9</p>";
        assert_eq!(declared_label(page).as_deref(), Some("windows-1252"));
        assert_eq!(declared_label(b"<!---><meta charset=utf-8>").as_deref(), Some("utf-8"));
        assert_eq!(declared_label(b"<!-- <meta charset=windows-1252> --><meta charset=utf-8>").as_deref(), Some("utf-8"));
    }

    #[test]
    fn r4_005_an_unmatched_quote_in_content_is_no_declaration() {
        let page = "<meta http-equiv=content-type content=\"text/html; charset='windows-1252\"><meta charset=utf-8>";
        assert_eq!(declared_label(page.as_bytes()).as_deref(), Some("utf-8"));
        let good = "<meta http-equiv=content-type content=\"text/html; charset='windows-1252'\">";
        assert_eq!(declared_label(good.as_bytes()).as_deref(), Some("windows-1252"));
        let later = "<meta http-equiv=content-type content=\"text/html; charsetx; charset=windows-1252\">";
        assert_eq!(declared_label(later.as_bytes()).as_deref(), Some("windows-1252"));
    }

    #[test]
    fn r4_006_an_empty_charset_does_not_fall_back_to_content() {
        let page = "<meta charset=\"\" http-equiv=content-type content=\"text/html; charset=windows-1252\"><meta charset=utf-8>";
        assert_eq!(declared_label(page.as_bytes()).as_deref(), Some("utf-8"));
    }

    #[test]
    fn r5_001_the_pragma_is_exact_and_labels_trim_only_ascii_whitespace() {
        let spaced = "<meta http-equiv=\" content-type\" content=\"charset=windows-1252\"><meta charset=utf-8>";
        assert_eq!(declared_label(spaced.as_bytes()).as_deref(), Some("utf-8"));
        let vt = "<meta charset=\"\u{b}windows-1252\"><meta charset=utf-8>";
        assert_eq!(declared_label(vt.as_bytes()).as_deref(), Some("utf-8"));
        assert_eq!(declared_label(b"<meta charset=\" windows-1252\t\">").as_deref(), Some("windows-1252"));
    }

    #[test]
    fn r5_002_a_meta_cut_off_by_the_end_of_the_input_decides_nothing() {
        let page = "<p>caf\u{e9}</p><meta charset=\"windows-1252";
        assert_eq!(declared_label(page.as_bytes()), None);
        assert!(decode(page.as_bytes()).unwrap().contains("caf\u{e9}"));
    }

    #[test]
    fn r5_003_an_unrecognized_label_lets_a_later_declaration_count() {
        assert_eq!(declared_label(b"<meta charset=bogus><meta charset=windows-1252>").as_deref(), Some("windows-1252"));
        let content = "<meta http-equiv=content-type content=\"charset=bogus\"><meta charset=windows-1252>";
        assert_eq!(declared_label(content.as_bytes()).as_deref(), Some("windows-1252"));
        // A real encoding this crate cannot decode decides, and the page is
        // refused rather than decoded as a guess.
        assert!(matches!(decode(b"<meta charset=shift_jis><p>x</p>"), Err(ReaderError::UnsupportedEncoding(_))));
    }

    #[test]
    fn r5_004_meta_utf16_means_utf8_and_user_defined_means_windows_1252() {
        assert_eq!(decode(b"<meta charset=utf-16><p>cafe</p>").unwrap(), "<meta charset=utf-16><p>cafe</p>");
        assert!(decode(b"<meta charset=x-user-defined><p>caf\xe9</p>").unwrap().contains("caf\u{e9}"));
    }

    #[test]
    fn r5_005_the_xml_declaration_is_the_fallback() {
        let page = b"<?xml version=\"1.0\" encoding=\"windows-1252\"?><p>caf\xe9</p>";
        assert!(decode(page).unwrap().contains("caf\u{e9}"));
        let both = b"<?xml version=\"1.0\" encoding=\"windows-1252\"?><meta charset=utf-8><p>x</p>";
        assert_eq!(declared_label(both).as_deref(), Some("utf-8"));
    }

    #[test]
    fn final_002_a_real_encoding_this_crate_cannot_decode_still_decides() {
        // Final review (R-002): shift_jis was skipped as if it were not an
        // encoding, so the later windows-1252 meta decoded Shift_JIS bytes
        // as Latin text. The first real encoding decides; the page is
        // refused.
        let page = b"<meta charset=shift_jis><meta charset=windows-1252><p>\x82\xa0</p>";
        assert_eq!(declared_label(page).as_deref(), Some("shift_jis"));
        assert!(matches!(decode(page), Err(ReaderError::UnsupportedEncoding(_))));
        assert_eq!(declared_label(b"<meta charset=bogus><meta charset=windows-1252>").as_deref(), Some("windows-1252"));
    }

    #[test]
    fn the_label_table_is_sorted_lowercase_and_complete() {
        assert!(ENCODING_LABELS.windows(2).all(|w| w[0] < w[1]), "sorted, no duplicates");
        assert!(ENCODING_LABELS.iter().all(|l| *l == l.to_ascii_lowercase()));
        for l in ["utf-8", "windows-1252", "latin1", "shift_jis", "gb18030", "replacement", "x-user-defined", "iso-2022-jp"] {
            assert!(is_encoding_label(l), "{l}");
        }
        assert!(!is_encoding_label("bogus"));
    }

    #[test]
    fn utf8_bom_wins_and_is_stripped() {
        assert_eq!(decode(b"\xEF\xBB\xBFcaf\xC3\xA9").unwrap(), "caf\u{e9}");
    }

    #[test]
    fn utf16_is_refused_not_garbled() {
        assert!(matches!(
            decode(b"\xFF\xFEh\0i\0"),
            Err(ReaderError::UnsupportedEncoding(_))
        ));
    }

    #[test]
    fn meta_charset_windows_1252_decodes_smart_quotes() {
        let page = b"<meta charset=\"windows-1252\"><p>\x93caf\xe9\x94 \x97 ok</p>";
        let text = decode(page).unwrap();
        assert!(text.contains("\u{201C}caf\u{e9}\u{201D} \u{2014} ok"), "{text}");
    }

    #[test]
    fn http_equiv_declaration_is_read() {
        let page = b"<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=ISO-8859-1\"><p>na\xefve</p>";
        assert!(decode(page).unwrap().contains("na\u{ef}ve"));
    }

    #[test]
    fn unknown_declared_label_is_reported() {
        match decode(b"<meta charset=shift_jis><p>x</p>") {
            Err(ReaderError::UnsupportedEncoding(l)) => assert_eq!(l, "shift_jis"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn undeclared_valid_utf8_is_read_and_anything_else_is_refused() {
        assert_eq!(decode("na\u{ef}ve".as_bytes()).unwrap(), "na\u{ef}ve");
        assert!(matches!(decode(b"na\xefve"), Err(ReaderError::UnsupportedEncoding(_))));
    }

    #[test]
    fn unquoted_and_single_quoted_declarations_are_read() {
        assert_eq!(declared_label(b"<meta charset=UTF-8>").as_deref(), Some("utf-8"));
        assert_eq!(declared_label(b"<meta charset='windows-1252'>").as_deref(), Some("windows-1252"));
        assert_eq!(declared_label(b"<metadata charset=x>"), None);
    }
}
