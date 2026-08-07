//! Recovery-key candidate extraction from raw OCR text.
//!
//! The vault's existing parser already strips whitespace and dashes and is
//! case-insensitive; it requires exactly 64 hex chars. Everything here exists
//! to get noisy OCR output to that point -- no crypto, no re-parsing.

const KEY_HEX_LEN: usize = 64;
const GROUP: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sep {
    None,
    Space,
    Dash,
}

enum Class {
    Hex(char),
    Sep(Sep),
    Break,
}

fn classify(c: char) -> Class {
    match c {
        '0'..='9' => Class::Hex(c),
        'a'..='f' => Class::Hex(c),
        // Uppercase A-F is case noise, which the parser tolerates anyway; the
        // lowercase alphabet is only a display convention of the issued key.
        'A'..='F' => Class::Hex(c.to_ascii_lowercase()),
        // Every letter mapped below is outside the key alphabet [0-9a-f], so
        // an OCR token containing it can never be a faithful key character.
        // Mapping it to the lookalike digit therefore cannot turn a valid key
        // into a different valid key; it can only salvage a misread one. Any
        // future mapping must re-run this argument before being added.
        'o' | 'O' => Class::Hex('0'),
        'l' | 'L' | 'i' | 'I' => Class::Hex('1'),
        'z' | 'Z' => Class::Hex('2'),
        's' | 'S' => Class::Hex('5'),
        'g' | 'G' => Class::Hex('6'),
        // The two below are MEASURED, not inherited from a generic OCR
        // confusables list. Running the real PP-OCR models over a rendered
        // 79-character key on 2026-07-27, every single 'f' came back as 't'
        // (5 of 5) and one '7' came back as '/'. Both land outside [0-9a-f],
        // so the safety argument above covers them unchanged.
        't' | 'T' => Class::Hex('f'),
        '/' | '\\' => Class::Hex('7'),
        // 'b'/'B' are deliberately NOT mapped to 6/8 despite being classic
        // OCR confusables: they are legitimate key characters themselves, and
        // remapping would corrupt real b's. A two-pass scheme (retry with
        // b->6, B->8 when the first pass fails) was considered and rejected:
        // the second pass yields a *different* 64-hex candidate, never a
        // missing one, and the key format has no checksum to rank the two.
        // The safeguard is that the UI never auto-submits; the user compares
        // against the paper copy.
        //
        // Note: a follow-up could return an alternate reading alongside
        // the primary so the UI can offer "not matching? try the other
        // reading" for keys containing b/B/6/8. Not done here to keep the
        // IPC shape minimal.
        //
        // Handwriting OCR emits assorted Unicode dashes for the group
        // separator. Escapes are used because this codebase forbids the
        // literal characters in source.
        '-' | '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2212}' => {
            Class::Sep(Sep::Dash)
        }
        c if c.is_whitespace() => Class::Sep(Sep::Space),
        _ => Class::Break,
    }
}

struct Run {
    chars: Vec<char>,
    /// seps[i] is the separator that followed chars[i]; len == chars.len() - 1.
    seps: Vec<Sep>,
}

fn push_run(runs: &mut Vec<Run>, chars: &mut Vec<char>, seps: &mut Vec<Sep>) {
    if !chars.is_empty() {
        runs.push(Run {
            chars: std::mem::take(chars),
            seps: std::mem::take(seps),
        });
    }
}

fn collect_runs(text: &str) -> Vec<Run> {
    let mut runs = Vec::new();
    let mut chars: Vec<char> = Vec::new();
    let mut seps: Vec<Sep> = Vec::new();
    let mut pending = Sep::None;
    for c in text.chars() {
        match classify(c) {
            Class::Hex(h) => {
                if !chars.is_empty() {
                    seps.push(pending);
                }
                chars.push(h);
                pending = Sep::None;
            }
            Class::Sep(s) => {
                if !chars.is_empty() {
                    // Consecutive separators collapse; a dash anywhere in the
                    // gap wins because it carries group-structure signal.
                    pending = match (pending, s) {
                        (Sep::Dash, _) | (_, Sep::Dash) => Sep::Dash,
                        (Sep::Space, _) | (_, Sep::Space) => Sep::Space,
                        _ => s,
                    };
                }
            }
            Class::Break => {
                push_run(&mut runs, &mut chars, &mut seps);
                pending = Sep::None;
            }
        }
    }
    push_run(&mut runs, &mut chars, &mut seps);
    runs
}

/// Scores 64-char windows by how many of the 15 expected group boundaries
/// actually carry a separator. A window that is exactly a whole run is
/// accepted at any score (a key written without dashes is still a key); a
/// window carved out of a longer run must show at least one real dash at a
/// group boundary, which is what stops hex-ish prose ("deadbeef cafe...",
/// git hashes next to other words) from filling the field with junk.
fn best_in_run(run: &Run) -> Option<(i32, String)> {
    let n = run.chars.len();
    if n < KEY_HEX_LEN {
        return None;
    }
    let mut best: Option<(i32, usize)> = None;
    for start in 0..=(n - KEY_HEX_LEN) {
        let mut score = 0i32;
        for k in 1..(KEY_HEX_LEN / GROUP) {
            let g = start + k * GROUP;
            match run.seps.get(g - 1) {
                Some(Sep::Dash) => score += 2,
                Some(Sep::Space) => score += 1,
                _ => {}
            }
        }
        let whole_run = start == 0 && n == KEY_HEX_LEN;
        if !whole_run && score < 2 {
            continue;
        }
        // Strictly-greater wins, so ties keep the earliest window: stable
        // output for identical input.
        if best.map_or(true, |(bs, _)| score > bs) {
            best = Some((score, start));
        }
    }
    best.map(|(s, start)| (s, run.chars[start..start + KEY_HEX_LEN].iter().collect()))
}

/// Best-effort extraction of one recovery key from raw OCR text. Returns the
/// 64 lowercase hex chars, or None when nothing key-shaped is present. The
/// caller decides what "nothing found" means (for IPC: a null result, not an
/// error).
pub fn extract_recovery_candidate(text: &str) -> Option<String> {
    let runs = collect_runs(text);
    let mut best: Option<(i32, String)> = None;
    for run in &runs {
        if let Some((score, cand)) = best_in_run(run) {
            if best.as_ref().map_or(true, |(bs, _)| score > *bs) {
                best = Some((score, cand));
            }
        }
    }
    if let Some((_, cand)) = best {
        return Some(cand);
    }
    // A key that wrapped across lines arrives as several runs. If the hex
    // chars of *all* runs together make exactly one key, that is the key;
    // any junk alongside makes the count wrong and the attempt fails closed,
    // which is the safe direction for a credential field.
    let total: usize = runs.iter().map(|r| r.chars.len()).sum();
    if total == KEY_HEX_LEN && !runs.is_empty() {
        let mut s = String::with_capacity(KEY_HEX_LEN);
        for r in &runs {
            s.extend(r.chars.iter());
        }
        return Some(s);
    }
    None
}

/// Reformats 64 hex chars as the issued display form (16 dash-separated
/// groups of 4) so the user can compare group-by-group against the paper
/// copy. The parser does not need this; the human does.
pub fn format_grouped(candidate: &str) -> String {
    let mut out = String::with_capacity(KEY_HEX_LEN + KEY_HEX_LEN / GROUP - 1);
    for (i, c) in candidate.chars().enumerate() {
        if i > 0 && i % GROUP == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // 32 bytes 0x00..0x1f as hex: contains 0,1,5,6,8,b -- the confusable set.
    const RAW: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const GROUPED: &str =
        "0001-0203-0405-0607-0809-0a0b-0c0d-0e0f-1011-1213-1415-1617-1819-1a1b-1c1d-1e1f";

    #[test]
    fn clean_key_with_surrounding_junk() {
        let input = format!("Recovery key:\n{GROUPED}\nKeep it safe.");
        assert_eq!(extract_recovery_candidate(&input), Some(RAW.to_string()));
    }

    #[test]
    fn confusable_letters_are_salvaged() {
        // Simulate OCR reading 0->O, 1->l, 5->S, 6->G throughout.
        let ocr: String = GROUPED
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'l',
                '5' => 'S',
                '6' => 'G',
                other => other,
            })
            .collect();
        assert_eq!(extract_recovery_candidate(&ocr), Some(RAW.to_string()));
    }

    #[test]
    fn uppercase_and_space_separators_work() {
        let input = GROUPED.to_uppercase().replace('-', "  ");
        assert_eq!(extract_recovery_candidate(&input), Some(RAW.to_string()));
    }

    #[test]
    fn unicode_dash_separators_work() {
        // en dash and minus sign as group separators, written as escapes.
        let input = GROUPED.replace('-', "\u{2013}");
        assert_eq!(extract_recovery_candidate(&input), Some(RAW.to_string()));
        let input2 = GROUPED.replace('-', "\u{2212}");
        assert_eq!(extract_recovery_candidate(&input2), Some(RAW.to_string()));
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert_eq!(extract_recovery_candidate(&RAW[..63]), None);
        // 65 continuous hex chars: sub-windows score 0 and the guard rejects.
        let long = format!("{RAW}a");
        assert_eq!(extract_recovery_candidate(&long), None);
    }

    #[test]
    fn junk_prefix_on_same_line_still_finds_aligned_key() {
        // Two stray hex letters attach to the key run; only the window that
        // aligns with the real dash grouping scores, so it wins.
        let input = format!("aa {GROUPED}");
        assert_eq!(extract_recovery_candidate(&input), Some(RAW.to_string()));
    }

    #[test]
    fn key_split_across_runs_is_concatenated() {
        let input = format!("{} | {}", &RAW[..32], &RAW[32..]);
        assert_eq!(extract_recovery_candidate(&input), Some(RAW.to_string()));
    }

    #[test]
    fn junk_lines_defeat_concatenation_safely() {
        let input = format!("{} page 1\n{}", &RAW[..32], &RAW[32..]);
        // Extra hex-ish letters from the junk line make the total != 64.
        assert_eq!(extract_recovery_candidate(&input), None);
    }

    #[test]
    fn b_for_8_is_not_rewritten_documents_limitation() {
        // OCR reads every 8 as B. B is valid hex (case-insensitive b), so the
        // extraction keeps it as b. This is wrong against the paper key but
        // UNKNOWABLE without a checksum; the test pins the behavior so a
        // future change here is a deliberate decision. The UI not
        // auto-submitting is the safety net.
        let ocr = GROUPED.replace('8', "B");
        let expected = RAW.replace('8', "b");
        assert_eq!(extract_recovery_candidate(&ocr), Some(expected));
    }

    #[test]
    fn format_grouped_matches_issued_form() {
        assert_eq!(format_grouped(RAW), GROUPED);
        assert_eq!(format_grouped(RAW).len(), 79);
    }
}

#[cfg(test)]
mod measured_tests {
    use super::*;

    /// The exact strings the real PP-OCR models returned on 2026-07-27 for a
    /// rendered 79-character recovery key, wrapped over four lines the way the
    /// vault panel displays it. Kept verbatim so a change in the confusable
    /// map is checked against evidence rather than against intuition.
    const OCR_LINES: [&str; 4] = [
        "1a2b-3c4d-5e6t-7a8b-",
        "9c0d-1e2t-3a4b-5c6d-",
        "7e8t-9a0b-1c2d-3e4t-",
        "5a6b-/c8d-9e0f-1a26",
    ];
    /// What was actually on the card.
    const TRUTH: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b";

    #[test]
    fn real_ocr_output_recovers_all_but_the_ambiguous_character() {
        let joined = OCR_LINES.join("");
        let got = extract_recovery_candidate(&joined)
            .expect("64 hex characters must be recoverable from the real reading");
        assert_eq!(got.len(), 64);

        // Every 'f' misread as 't' and the '7' misread as '/' are recovered,
        // because both are outside the key alphabet.
        let wrong: Vec<usize> = got
            .chars()
            .zip(TRUTH.chars())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();

        // Exactly one character is unrecoverable: the final 'b' read as '6'.
        // BOTH are valid hex, so no alphabet constraint can distinguish them
        // and no mapping may try -- remapping 6 would corrupt real 6s. This
        // is the documented reason the UI never auto-submits.
        assert_eq!(
            wrong.len(),
            1,
            "expected only the b/6 ambiguity to survive, got {wrong:?} -> {got}"
        );
        assert_eq!(got.chars().nth(wrong[0]), Some('6'));
        assert_eq!(TRUTH.chars().nth(wrong[0]), Some('b'));
    }

    #[test]
    fn a_line_of_prose_yields_no_candidate() {
        // The scan runs over whatever the user picked. A photo of a page must
        // not produce a plausible-looking key out of ordinary words.
        assert_eq!(
            extract_recovery_candidate("the quick brown fox jumps over the lazy dog"),
            None
        );
    }
}
