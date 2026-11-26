//! What the hover readout shows, and what it refuses to show.
//!
//! The engine hands over a link target when the pointer enters a link. That
//! string is PAGE DATA and is chosen by whoever wrote the page, so everything
//! here treats it as hostile input rather than as a URL to be displayed.
//!
//! Kept engine-free so `cargo test` can prove the rules on a box with no
//! WebView2 and no display; the backends contribute only the event.

/// Longest readout rendered. Past this the middle is elided.
///
/// Elision is in the MIDDLE, never at the end. The tail is the part a person
/// most needs -- the path they are about to open -- and a readout that always
/// ends in "..." tells them the host they could already see and hides the bit
/// they could not. Chosen to fit a narrow window without wrapping.
pub(crate) const MAX_DISPLAY_CHARS: usize = 110;

/// Characters that can make a hostile URL read as a different site.
///
/// The bidi overrides are the dangerous half: RLO in a link target can make
/// `evil.example/gnp.attacker` render as though it ended in `png`, and a
/// user reading the readout would see a domain that is not where they are
/// going. Zero-width and line separators are here for the same reason at
/// lower stakes -- they let a name be split or padded invisibly.
/// Shared with `state::sanitize_filename`: a downloaded file's NAME is a
/// display surface too, and the same characters that let a link text lie
/// about where it points let a file name lie about what it is.
///
/// The second group draws as nothing, or as blank space, in common fonts
/// (SecScan S-57c229d929b0, 2026-11-24): a run of Hangul fillers between
/// `invoice.pdf` and `.exe` pushes the real extension out of sight, and the
/// Arabic letter mark is a bidi control like the ones above.
pub(crate) fn is_deceptive(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'   // LRE, RLE, PDF, LRO, RLO
            | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
            | '\u{200B}'..='\u{200F}' // zero-width, LRM, RLM
            | '\u{2028}' | '\u{2029}' // line/paragraph separators
            | '\u{00AD}'              // soft hyphen
            | '\u{FEFF}'              // zero-width no-break space
            | '\u{061C}'              // Arabic letter mark
            | '\u{2060}'..='\u{206F}' // word joiner, invisible math characters, other format controls
            | '\u{180B}'..='\u{180F}' // Mongolian variation selectors and vowel separator
            | '\u{17B4}' | '\u{17B5}' // Khmer inherent vowels
            | '\u{034F}'              // combining grapheme joiner
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // Hangul fillers
            | '\u{2800}'              // braille blank
            | '\u{FE00}'..='\u{FE0F}' // variation selectors
            | '\u{FFF0}'..='\u{FFF8}' // unassigned specials
            | '\u{1BCA0}'..='\u{1BCA3}' // shorthand format controls
            | '\u{1D173}'..='\u{1D17A}' // musical format controls
            | '\u{E0000}'..='\u{E0FFF}' // tags and supplementary variation selectors
    )
}

/// What to display for a hovered link, or None to show nothing at all.
///
/// None rather than an empty string is deliberate: the caller must HIDE the
/// overlay, not draw an empty one. An empty bar sitting over the page says
/// "something is here" when nothing is.
pub fn readout_for(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Only web destinations. `javascript:` in particular must never be
    // rendered as though it were somewhere to go, and internal schemes are
    // not the user's business.
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return None;
    }

    // Strip the deceptive characters rather than refusing the whole readout:
    // refusing would hide a link the user is genuinely pointing at, and the
    // remaining text is then exactly what it appears to be.
    let cleaned: String = trimmed
        .chars()
        .filter(|c| !is_deceptive(*c) && !c.is_control())
        .collect();
    if cleaned.is_empty() {
        return None;
    }

    Some(shorten_keeping_host(&cleaned, MAX_DISPLAY_CHARS))
}

/// Shortens a web URL without ever cutting into its host.
///
/// Plain middle elision kept the first 55 characters, so a host like
/// `accounts.google.com.<60 letters>.evil.example` lost its real ending and
/// read as Google (SecScan S-3864551c2478, 2026-11-24). The host is the one
/// part that says where the link goes: only the path is elided, and a host
/// too long to fit keeps its END, where the registrable domain is.
///
/// Userinfo is dropped for the same reason: `https://accounts.google.com@evil.example/`
/// goes to evil.example, and the readout says so.
fn shorten_keeping_host(url: &str, max: usize) -> String {
    let Some(scheme_end) = url.find("://").map(|i| i + 3) else {
        return elide_middle(url, max);
    };
    let (scheme, after) = url.split_at(scheme_end);
    // The authority ends where a web browser ends it, backslash included.
    let authority_end = after
        .find(|c| matches!(c, '/' | '?' | '#' | '\\'))
        .unwrap_or(after.len());
    let (authority, rest) = after.split_at(authority_end);
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);

    let shown = format!("{scheme}{host}{rest}");
    let total = shown.chars().count();
    if total <= max {
        return shown;
    }
    let lead = scheme.chars().count() + host.chars().count();
    // Room for the host plus a short elided path: elide the path only.
    if lead + 8 <= max {
        let rest_budget = max - lead;
        return format!("{scheme}{host}{}", elide_middle(rest, rest_budget));
    }
    // The host alone does not fit: keep its end, mark both cuts.
    let marks = if rest.is_empty() { 1 } else { 2 };
    let host_budget = max.saturating_sub(scheme.chars().count() + marks);
    let host_chars: Vec<char> = host.chars().collect();
    let tail: String = host_chars[host_chars.len().saturating_sub(host_budget)..].iter().collect();
    let mut out = format!("{scheme}\u{2026}{tail}");
    if !rest.is_empty() {
        out.push('\u{2026}');
    }
    out
}

/// Shortens by removing the MIDDLE, keeping both ends.
///
/// Counts CHARACTERS, not bytes: slicing a URL on a byte index lands inside a
/// multi-byte character and panics, and link targets are attacker-controlled.
pub fn elide_middle(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max || max < 8 {
        return s.to_string();
    }
    // One ellipsis character in the middle; the remainder splits with the
    // larger share to the FRONT, so the scheme and host stay whole.
    let budget = max - 1;
    let head = budget.div_ceil(2);
    let tail = budget - head;
    let mut out: String = chars[..head].iter().collect();
    out.push('\u{2026}');
    out.extend(chars[chars.len() - tail..].iter());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_link_is_shown_as_it_is() {
        let url = "https://example.com/some/page?q=1";
        assert_eq!(readout_for(url).as_deref(), Some(url));
    }

    /// Nothing to point at means nothing drawn, not an empty bar.
    #[test]
    fn nothing_worth_showing_yields_none() {
        for raw in ["", "   ", "\n"] {
            assert_eq!(readout_for(raw), None, "{raw:?}");
        }
    }

    /// The one that matters: a link target is page data, and these schemes
    /// must never be presented as somewhere to go.
    #[test]
    fn non_web_schemes_are_never_displayed() {
        for raw in [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "about:blank",
            "chrome://settings",
            "vbscript:msgbox",
        ] {
            assert_eq!(readout_for(raw), None, "must not display {raw}");
        }
    }

    /// A right-to-left override can make a hostile target READ as another
    /// domain. Stripping it means the readout says what it appears to say.
    #[test]
    fn bidi_and_zero_width_tricks_are_stripped() {
        let hostile = "https://evil.example/\u{202E}gnp.attacker\u{202C}/x";
        let shown = readout_for(hostile).expect("a real http link is displayable");
        assert!(
            !shown.chars().any(is_deceptive),
            "no deceptive character may survive into the readout: {shown:?}"
        );
        assert!(shown.starts_with("https://evil.example/"));

        let padded = "https://exa\u{200B}mple.com/";
        let shown = readout_for(padded).unwrap();
        assert_eq!(shown, "https://example.com/", "zero-width padding removed");
    }

    /// The tail is what the user needs, so the elision takes the middle.
    #[test]
    fn a_long_url_keeps_both_ends() {
        let url = format!("https://example.com/{}/final-segment", "a".repeat(400));
        let shown = readout_for(&url).unwrap();
        assert!(shown.chars().count() <= MAX_DISPLAY_CHARS);
        assert!(
            shown.starts_with("https://example.com/"),
            "the host must survive: {shown}"
        );
        assert!(
            shown.ends_with("final-segment"),
            "the tail is the point of the feature: {shown}"
        );
        assert!(shown.contains('\u{2026}'), "elision must be visible");
    }

    /// Slicing a URL on a byte index panics when the boundary lands inside a
    /// character, and link targets come from the page.
    #[test]
    fn multibyte_urls_do_not_panic_and_stay_bounded() {
        for filler in ["é", "日", "🙂"] {
            let url = format!("https://example.com/{}", filler.repeat(300));
            let shown = readout_for(&url).unwrap();
            assert!(shown.chars().count() <= MAX_DISPLAY_CHARS, "{shown}");
        }
    }

    #[test]
    fn a_url_at_the_limit_is_not_elided() {
        let url = format!("https://example.com/{}", "a".repeat(80));
        assert!(url.chars().count() < MAX_DISPLAY_CHARS);
        assert_eq!(readout_for(&url).as_deref(), Some(url.as_str()));
    }

    /// SecScan S-3864551c2478: the old middle cut kept a trusted-looking
    /// prefix and dropped the real host.
    #[test]
    fn a_long_host_is_never_cut_to_a_trusted_looking_prefix() {
        let url = format!(
            "https://accounts.google.com.{}.evil.example/{}",
            "a".repeat(60),
            "b".repeat(60)
        );
        let shown = readout_for(&url).unwrap();
        assert!(shown.chars().count() <= MAX_DISPLAY_CHARS, "{shown}");
        assert!(shown.contains(".evil.example/"), "the real host must stay: {shown}");
        assert!(shown.ends_with("bbbb"), "the path tail stays too: {shown}");

        // A host longer than the whole readout keeps its END.
        let huge = format!("https://accounts.google.com.{}.evil.example/x", "a".repeat(200));
        let shown = readout_for(&huge).unwrap();
        assert!(shown.chars().count() <= MAX_DISPLAY_CHARS, "{shown}");
        assert!(shown.contains("evil.example"), "{shown}");
        assert!(!shown.contains("accounts.google.com"), "{shown}");
        assert!(shown.starts_with("https://\u{2026}"), "{shown}");
    }

    /// Userinfo is not where a link goes; the host after the last @ is.
    #[test]
    fn userinfo_is_dropped_from_the_readout() {
        assert_eq!(
            readout_for("https://accounts.google.com@evil.example/login").as_deref(),
            Some("https://evil.example/login")
        );
        assert_eq!(
            readout_for("http://user:pw@a.example@b.example:8080/?q=1").as_deref(),
            Some("http://b.example:8080/?q=1")
        );
        // An @ in the path is not userinfo.
        assert_eq!(
            readout_for("https://example.com/@someone").as_deref(),
            Some("https://example.com/@someone")
        );
    }

    /// SecScan S-57c229d929b0: blank-rendering and bidi characters the first
    /// list missed.
    #[test]
    fn blank_rendering_characters_are_deceptive() {
        for c in [
            '\u{061C}', '\u{2060}', '\u{2064}', '\u{180E}', '\u{034F}', '\u{115F}', '\u{1160}',
            '\u{3164}', '\u{FFA0}', '\u{2800}', '\u{E0020}', '\u{E007F}', '\u{FE0F}',
            '\u{E0100}', '\u{180B}', '\u{17B4}', '\u{206A}', '\u{FFF0}', '\u{1BCA0}',
            '\u{1D173}',
        ] {
            assert!(is_deceptive(c), "U+{:04X}", c as u32);
        }
        for c in ['a', ' ', '.', 'é', '日', '\u{00A0}'] {
            assert!(!is_deceptive(c), "U+{:04X}", c as u32);
        }
    }

    #[test]
    fn elision_is_a_no_op_below_a_sane_budget() {
        assert_eq!(elide_middle("abcdefgh", 4), "abcdefgh");
    }

    /// The suite above proves the bidi and zero-width cases, but never the
    /// plain control characters on an otherwise-valid URL. They matter to the
    /// RENDERER: a newline makes a `GtkLabel` two lines tall and grow over the
    /// page, and under `DT_SINGLELINE` it draws as a box. The decision layer
    /// already removes them; this is what keeps that true.
    #[test]
    fn control_characters_never_reach_the_renderer() {
        let shown = readout_for("https://example.com/a\nb\tc\u{7}d").unwrap();
        assert!(
            !shown.chars().any(char::is_control),
            "no control character may survive into the readout: {shown:?}"
        );
        assert_eq!(shown, "https://example.com/abcd");
    }

    /// The readout is TEXT, not markup and not accelerator text. A query
    /// string is full of ampersands, and both backends have a way of eating
    /// them -- Pango markup on GTK, the `&`-as-underline prefix in
    /// `DrawTextW`. Nothing here may strip them, so the renderers must be the
    /// ones to opt out (`set_text` rather than `set_markup`, `DT_NOPREFIX`).
    #[test]
    fn ampersands_survive_the_readout() {
        let url = "https://example.com/search?a=1&b=2&c=3";
        let shown = readout_for(url).unwrap();
        assert_eq!(shown, url);
        assert_eq!(shown.matches('&').count(), 2);
    }
}
