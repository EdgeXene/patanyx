//! Page-language sanity checking, by Unicode script.
//!
//! WHY THIS EXISTS. The feature once fed a Greek page to an English->Spanish
//! model, which emitted mangled Greek that got written into the live page. The
//! model does not refuse input it cannot handle; it corrupts it. So the host
//! must refuse BEFORE any text reaches the engine, and the cheapest reliable
//! signal is the script the text is actually written in.
//!
//! WHAT THIS IS AND IS NOT. Script classification answers "is this page written
//! in the alphabet the chosen source language uses". It catches the real
//! incident -- Greek text, Latin-expecting model -- with certainty, because
//! Greek and Latin are disjoint character ranges. It does NOT distinguish
//! languages that SHARE a script: a French page and an English page are both
//! Latin, and no amount of script analysis tells them apart. That case is
//! carried by the page's declared `lang` and the user's source dropdown, and
//! the UI says so honestly rather than pretending the guard covers it.
//!
//! NOT A LANGUAGE DETECTOR. There is no word list, no n-gram model, no trained
//! data here -- nothing that is plausibly wrong and hard to falsify. Every
//! rule is a Unicode code-point range, which is a fact, not a guess.

/// A writing system, coarse enough that every registry language maps to exactly
/// one and fine enough to tell the incident case apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Script {
    Latin,
    Greek,
    Cyrillic,
    Arabic,
    Hebrew,
    Han,
    Kana,
    Hangul,
    Devanagari,
    Bengali,
    Gujarati,
    Tamil,
    Telugu,
    Kannada,
    Malayalam,
    Thai,
    Georgian,
    /// A letter that carries no script signal we act on (digits, punctuation,
    /// symbols, spaces are all excluded before we get here; this is for letters
    /// in scripts outside the set above).
    Other,
}



/// The script of a single character, or None for anything that is not a letter
/// (digit, punctuation, whitespace, symbol, control).
///
/// Only LETTERS vote. A page of Greek prose is full of ASCII spaces, commas and
/// digits; counting those as Latin would drown the Greek. So non-letters are
/// dropped here and never reach the tally.
fn script_of(c: char) -> Option<Script> {
    if !c.is_alphabetic() {
        return None;
    }
    let u = c as u32;
    // Ranges are checked most-specific first where they would otherwise be
    // shadowed. Each bound is a Unicode block edge, cited so a reviewer can
    // check it against the standard rather than trust it.
    Some(match u {
        // Basic Latin letters + Latin-1 + Extended-A/B, IPA, Latin Extended
        // Additional/C/D/E, and fullwidth Latin. Broadened after a red-team
        // pass noted that letters in the uncovered Latin blocks fell to
        // `Other`, where they diluted the tally instead of counting as Latin.
        0x0041..=0x005A | 0x0061..=0x007A => Script::Latin,
        0x00C0..=0x02AF | 0x1E00..=0x1EFF => Script::Latin, // Latin-1..IPA + Additional
        0x2C60..=0x2C7F | 0xA720..=0xA7FF | 0xAB30..=0xAB6F => Script::Latin, // Ext-C/D/E
        0xFF21..=0xFF3A | 0xFF41..=0xFF5A => Script::Latin, // fullwidth A-Z a-z
        // Greek and Coptic + Greek Extended.
        0x0370..=0x03FF | 0x1F00..=0x1FFF => Script::Greek,
        // Cyrillic + Supplement + Extended-A/B/C.
        0x0400..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F | 0x1C80..=0x1C8F => Script::Cyrillic,
        // Hebrew.
        0x0590..=0x05FF => Script::Hebrew,
        // Arabic + Arabic Supplement + Presentation Forms (Persian, Urdu use
        // this block plus a few extensions inside it).
        0x0600..=0x06FF | 0x0750..=0x077F | 0xFB50..=0xFDFF | 0xFE70..=0xFEFF => Script::Arabic,
        // Devanagari (Hindi, Marathi).
        0x0900..=0x097F => Script::Devanagari,
        // Bengali.
        0x0980..=0x09FF => Script::Bengali,
        // Gujarati.
        0x0A80..=0x0AFF => Script::Gujarati,
        // Tamil.
        0x0B80..=0x0BFF => Script::Tamil,
        // Telugu.
        0x0C00..=0x0C7F => Script::Telugu,
        // Kannada.
        0x0C80..=0x0CFF => Script::Kannada,
        // Malayalam.
        0x0D00..=0x0D7F => Script::Malayalam,
        // Thai.
        0x0E00..=0x0E7F => Script::Thai,
        // Georgian: Mkhedruli + Asomtavruli/Nuskhuri (Supplement) + Extended.
        // One language in the registry uses it, so it RESOLVES a page on its
        // own -- see language_for_script_name.
        0x10A0..=0x10FF | 0x2D00..=0x2D2F | 0x1C90..=0x1CBF => Script::Georgian,
        // Hangul (Korean): Jamo + Syllables + Compatibility Jamo + Jamo
        // Extended-A/B.
        0x1100..=0x11FF | 0xAC00..=0xD7AF | 0x3130..=0x318F | 0xA960..=0xA97F | 0xD7B0..=0xD7FF => {
            Script::Hangul
        }
        // Hiragana + Katakana + Kana Supplement/Extended (Japanese kana).
        0x3040..=0x30FF | 0x1B000..=0x1B16F => Script::Kana,
        // CJK Unified Ideographs and Extensions A-G + Compatibility (Han:
        // Chinese, and Japanese kanji). Extensions added so rare ideographs are
        // not miscounted as `Other` and used to dilute a Chinese page's Han
        // share. Checked AFTER kana so a Japanese page is scored by its kana.
        0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xF900..=0xFAFF
        | 0x20000..=0x2A6DF
        | 0x2A700..=0x2EBEF
        | 0x2F800..=0x2FA1F
        | 0x30000..=0x3134F => Script::Han,
        _ => Script::Other,
    })
}

/// The dominant script of a body of text, and what share of the letters it
/// accounts for.
///
/// SHARE MATTERS because real pages are mixed: a Greek article carries English
/// brand names and URLs, an English page quotes a Greek word. The dominant
/// script plus its share lets the caller demand a clear majority rather than a
/// bare plurality, so one English word on a Greek page does not flip the verdict
/// and one Greek word on an English page does not either.
/// The script a registry language is written in.
///
/// EXPLICIT TABLE, not derived. Every code that can be a translation SOURCE
/// appears here; a code that does not returns None and the caller fails safe.
/// Japanese maps to Kana because the presence of kana is what separates a
/// Japanese page from a Chinese one, even though Japanese also uses Han.
pub fn expected_script(code: &str) -> Option<Script> {
    Some(match code {
        "en" | "es" | "fr" | "de" | "it" | "pt" | "nl" | "sv" | "da" | "nb" | "nn" | "fi"
        | "is" | "ca" | "gl" | "eu" | "et" | "lt" | "lv" | "pl" | "cs" | "sk" | "sl" | "hr"
        | "bs" | "sq" | "hu" | "ro" | "tr" | "az" | "id" | "ms" | "vi" | "mt" | "la"
        | "tl" | "ht" | "eo" | "ga" | "af" | "ha" | "ig" | "rw" | "ny" | "mg"
        // Middle French, from the ine-eng OPUS-MT model (2026-09-16). Old
        // Norse and Middle English were measured on the same engine and held
        // back: their prose output loops (launch-sweep record).
        | "frm" => {
            Script::Latin
        }
        "el" => Script::Greek,
        // Chinese is Han. The two script variants are separate LANGUAGES to
        // the registry (Mozilla publishes different models for Simplified and
        // Traditional) but the same SCRIPT to this guard, which only asks
        // whether the page's characters could belong to the source the model
        // expects. Telling Simplified from Traditional is a job no code-point
        // range can do, and this guard never claims to.
        "zh" | "zh-Hans" | "zh-Hant" | "zh-hans" | "zh-hant" => Script::Han,
        "ru" | "uk" | "bg" | "sr" | "be" | "mk" => Script::Cyrillic,
        "ar" | "fa" | "ur" => Script::Arabic,
        "he" => Script::Hebrew,
        "hi" | "mr" => Script::Devanagari,
        "bn" => Script::Bengali,
        "gu" => Script::Gujarati,
        "ta" => Script::Tamil,
        "te" => Script::Telugu,
        "kn" => Script::Kannada,
        "ml" => Script::Malayalam,
        "th" => Script::Thai,
        "ka" => Script::Georgian,
        "ko" => Script::Hangul,
        "ja" => Script::Kana,
        _ => return None,
    })
}

/// The language a page-reported script name resolves to, when that answer is
/// UNIQUE among the languages this build supports.
///
/// The inverse of [`expected_script`], derived from the registry at call time
/// so it cannot drift from it. Greek resolves to `el` because exactly one
/// supported language is written in Greek; Cyrillic resolves to NOTHING,
/// because four are and guessing between them would prefill a wrong source
/// with confidence. The name arrives from a page and is matched against a
/// closed set -- an unknown or hostile string is simply no answer.
///
/// "kana" is the page-side classifier's word for "Han text with enough kana
/// to be Japanese"; it maps through [`Script::Kana`], which only `ja`
/// declares. Plain "han" stays ambiguous between the Chinese variants.
pub fn language_for_script_name(name: &str) -> Option<&'static str> {
    let script = match name {
        "greek" => Script::Greek,
        "cyrillic" => Script::Cyrillic,
        "arabic" => Script::Arabic,
        "hebrew" => Script::Hebrew,
        "han" => Script::Han,
        "kana" => Script::Kana,
        "hangul" => Script::Hangul,
        "devanagari" => Script::Devanagari,
        "bengali" => Script::Bengali,
        "gujarati" => Script::Gujarati,
        "tamil" => Script::Tamil,
        "telugu" => Script::Telugu,
        "kannada" => Script::Kannada,
        "malayalam" => Script::Malayalam,
        "thai" => Script::Thai,
        "georgian" => Script::Georgian,
        // "latin" is deliberately absent: dozens of languages share it and
        // the classifier sending it means only "not one of the marked
        // scripts", which is not an answer.
        _ => return None,
    };
    let mut found: Option<&'static str> = None;
    for lang in crate::languages::LANGUAGES {
        if expected_script(lang.code) == Some(script) {
            if found.is_some() {
                return None;
            }
            found = Some(lang.code);
        }
    }
    found
}

/// The registry language a declared BCP-47 tag resolves to, if any.
///
/// Most tags resolve by primary subtag: "el-GR" is el, "fr-CA" is fr. Chinese
/// is the exception the registry forces: it carries TWO Chinese languages
/// (zh-Hans and zh-Hant, separate models upstream), so a bare "zh" primary
/// names neither and the script or region subtag decides -- an explicit
/// Hans/Hant wins, then the traditional-script regions (TW, HK, MO) map to
/// Hant, and everything else -- including a bare "zh" -- to Hans, which is
/// what the overwhelming majority of undecorated zh pages are. The tag is
/// page-controlled: anything that resolves to no registry code is None, and
/// the caller treats None as "not detected", never as an error.
pub fn registry_code_for_tag(tag: &str) -> Option<&'static str> {
    // An exact (case-insensitive) match against a full registry code wins
    // outright: a page declaring "zh-Hans" said precisely what we call it.
    for lang in crate::languages::LANGUAGES {
        if lang.code.eq_ignore_ascii_case(tag) {
            return Some(lang.code);
        }
    }
    let mut subtags = tag.split(['-', '_']);
    let primary = subtags.next().unwrap_or("");
    if primary.eq_ignore_ascii_case("zh") {
        let mut hant = false;
        let mut hans = false;
        for sub in subtags {
            if sub.eq_ignore_ascii_case("hant") {
                hant = true;
            } else if sub.eq_ignore_ascii_case("hans") {
                hans = true;
            } else if sub.eq_ignore_ascii_case("tw")
                || sub.eq_ignore_ascii_case("hk")
                || sub.eq_ignore_ascii_case("mo")
            {
                hant = true;
            }
        }
        let want = if hans {
            "zh-Hans"
        } else if hant {
            "zh-Hant"
        } else {
            "zh-Hans"
        };
        return crate::languages::LANGUAGES
            .iter()
            .find(|l| l.code == want)
            .map(|l| l.code);
    }
    for lang in crate::languages::LANGUAGES {
        if lang.code.eq_ignore_ascii_case(primary) {
            return Some(lang.code);
        }
    }
    None
}

/// A running, session-wide tally of text by writing system.
///
/// CUMULATIVE ON PURPOSE. A red-team pass showed that a PER-BATCH check is
/// defeated by chopping incompatible text into sub-threshold batches (each too
/// small to judge, so each proceeds) -- and that a per-batch check false-refuses
/// a legitimate page whose one continuation batch happens to be a foreign
/// quote. Accumulating every batch into one tally and judging the WHOLE removes
/// both: a page is refused on what it is overall, not on how it was sliced.
///
/// It captures the source's expected script at creation, so `verify` needs no
/// argument and cannot be called against the wrong source by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptCounts {
    expected: Option<Script>,
    total: usize,
    /// Letters in the source's own expected script (for Japanese this is Kana;
    /// Han is added into the in-system share separately).
    expected_letters: usize,
    kana: usize,
    han: usize,
}

impl ScriptCounts {
    /// A fresh accumulator for a given source language.
    pub fn new(source_code: &str) -> Self {
        Self {
            expected: expected_script(source_code),
            total: 0,
            expected_letters: 0,
            kana: 0,
            han: 0,
        }
    }

    /// Folds one batch of strings into the tally.
    pub fn add_batch(&mut self, texts: &[String]) {
        for t in texts {
            for c in t.chars() {
                if let Some(sc) = script_of(c) {
                    self.total += 1;
                    if Some(sc) == self.expected {
                        self.expected_letters += 1;
                    }
                    match sc {
                        Script::Kana => self.kana += 1,
                        Script::Han => self.han += 1,
                        _ => {}
                    }
                }
            }
        }
    }

    /// Is THIS ONE STRING written in the expected system?
    ///
    /// The page-level verdict answers "may this page be translated at all";
    /// this answers "may this NODE be sent", which is the question a mixed
    /// page actually poses. A Macedonian reader with the English translation
    /// printed below it is one document in two languages: refusing the whole
    /// page leaves the reader nothing, and sending all of it feeds English to
    /// a Macedonian model. Per node, both halves are served.
    ///
    /// Same thresholds as the page verdict, deliberately: a node is kept when
    /// the expected system clearly dominates it, skipped when a meaningful
    /// share is foreign, and KEPT when there is too little to tell -- a short
    /// node ("2)", a date, a name) carries no signal, and dropping those would
    /// silently gap a page whose verdict already said translate.
    pub fn text_is_expected(&self, text: &str) -> bool {
        let mut total = 0usize;
        let mut in_system = 0usize;
        for c in text.chars() {
            let Some(sc) = script_of(c) else { continue };
            total += 1;
            let ok = match self.expected {
                Some(Script::Kana) => sc == Script::Kana || sc == Script::Han,
                Some(exp) => sc == exp,
                None => true,
            };
            if ok {
                in_system += 1;
            }
        }
        if self.expected.is_none() {
            return true;
        }
        // A SHORT NODE IS ONLY GIVEN THE BENEFIT OF THE DOUBT WHILE THE PAGE
        // AS A WHOLE DESERVES IT.
        //
        // Short nodes are kept unjudged because a heading or a date carries no
        // script signal, and dropping them would gap a page the verdict has
        // already approved. But a page controls how its text is SPLIT, so
        // "under eight letters is always fine" is a rule an attacker can meet:
        // chop incompatible text into six-letter nodes and every one is waved
        // through, however unequivocal the cumulative census. Found by an
        // independent audit, 2026-09-01.
        //
        // The doubt is therefore extended only while the WHOLE page has not
        // already been judged incompatible. Once it has, short nodes are held
        // to the same standard as long ones.
        if total < MIN_LETTERS_PER_NODE {
            return verify(self) != Verdict::ScriptMismatch;
        }
        (in_system as f64 / total as f64) >= CLEAR_SHARE
    }

    /// Letters counted so far (non-letters excluded).
    pub fn letters(&self) -> usize {
        self.total
    }

    /// The share written in the expected WRITING SYSTEM. For Japanese that is
    /// kana + han; for every other language it is the expected script alone.
    fn in_system_share(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let in_system = match self.expected {
            Some(Script::Kana) => self.kana + self.han,
            Some(_) => self.expected_letters,
            None => 0,
        };
        in_system as f64 / self.total as f64
    }
}

/// The minimum letters before a tally means anything at all.
///
/// Below this, `verify` returns `Unknown` rather than a false verdict on a
/// probe that is mostly punctuation and digits.
const MIN_LETTERS: usize = 20;

/// The minimum letters in ONE NODE before its script is judged.
///
/// Lower than the page floor because a node is short by nature: a heading, a
/// list item, a caption. Below this a node is KEPT rather than judged -- the
/// page verdict has already decided the document is translatable, and a
/// four-letter node is not evidence against it.
const MIN_LETTERS_PER_NODE: usize = 8;

/// The minimum share the expected writing system must reach to count as a clear
/// signal (used as the Match floor).
const CLEAR_SHARE: f64 = 0.6;

/// The outcome of checking a page against a chosen source language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The page's script matches the source language. Proceed.
    Match,
    /// The page's script is incompatible with the source language: the
    /// incident case. Refuse; do not translate.
    ScriptMismatch,
    /// Not enough signal, or a source with no known script. Ask the user
    /// rather than guess -- the source dropdown exists for exactly this.
    Unknown,
}

/// The most letters NOT in the expected writing system a page may contain
/// before it is refused, as a share of all letters.
///
/// This counts EVERYTHING that is not the expected system: known incompatible
/// scripts AND unclassified `Other` letters, because both corrupt when fed to
/// the wrong model. A red-team pass showed the earlier version, which summed
/// only an enumerated set of known scripts, let an all-Armenian page through
/// (Armenian fell to `Other` and counted as neither). 0.10 leaves room for the
/// stray brand name a real page carries and refuses a page that is
/// meaningfully in another alphabet.
const MAX_INCOMPAT_SHARE: f64 = 0.10;

/// The minimum kana a page must contain to be accepted as Japanese.
///
/// Japanese prose is heavily kana (particles and inflections alone put normal
/// text well above this); a Chinese page is at zero, and padding it with a few
/// kana characters to fake Japanese has to reach this share -- at which point
/// the page is substantially kana and no longer pure Chinese. A red-team pass
/// showed a 5% floor was trivially padded; 0.15 is not.
const MIN_KANA_SHARE_FOR_JAPANESE: f64 = 0.15;

/// The guard the incident needed: is this page's text in the script of the
/// language the user says it is in?
///
/// HARDENED across two red-team rounds. The rule, in order:
///  - no expected script for the source -> Unknown (unreachable in practice:
///    the pair is registry-validated first and every registry language is
///    mapped; a defensive Unknown, never a wrong verdict).
///  - too little text -> Unknown.
///  - Japanese without a real kana share -> a Chinese page in a Japanese
///    label; ScriptMismatch if Han dominates, else Unknown.
///  - a meaningful share NOT in the expected system -> ScriptMismatch. This
///    counts known-wrong scripts AND unclassified letters, so dilution across
///    several scripts, sub-threshold batches, and unsupported-script pages are
///    all refused once the whole page is seen.
///  - the expected system clearly dominates -> Match. A French page against an
///    English source still Matches (both Latin): the documented same-script
///    limit, carried by the dropdown, not this guard.
///  - anything else -> Unknown (proceed on the user's explicit source choice).
///
/// FAIL CLOSED: only a page that is overwhelmingly the expected script, with
/// little foreign content, proceeds without asking.
pub fn verify(counts: &ScriptCounts) -> Verdict {
    let Some(expected) = counts.expected else {
        return Verdict::Unknown;
    };
    if counts.total < MIN_LETTERS {
        return Verdict::Unknown;
    }
    if expected == Script::Kana {
        let kana_share = counts.kana as f64 / counts.total as f64;
        if kana_share < MIN_KANA_SHARE_FOR_JAPANESE {
            let han_share = counts.han as f64 / counts.total as f64;
            return if han_share >= CLEAR_SHARE {
                Verdict::ScriptMismatch
            } else {
                Verdict::Unknown
            };
        }
    }
    let in_system = counts.in_system_share();
    if 1.0 - in_system >= MAX_INCOMPAT_SHARE {
        return Verdict::ScriptMismatch;
    }
    if in_system >= CLEAR_SHARE {
        return Verdict::Match;
    }
    Verdict::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(source: &str, texts: &[&str]) -> ScriptCounts {
        let mut cc = ScriptCounts::new(source);
        cc.add_batch(&texts.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        cc
    }

    /// CHINESE AND JAPANESE SHARE HAN, AND THE GUARD USES THAT HONESTLY.
    ///
    /// Chinese is Han; Japanese is Kana, because kana is what separates a
    /// Japanese page from a Chinese one. So a Chinese page under a Chinese
    /// model passes, a Chinese page under a JAPANESE model is refused (no
    /// kana), and a Japanese page under a Chinese model is refused too --
    /// its kana are foreign to Han. What the guard does NOT claim is to tell
    /// Simplified from Traditional: no code-point range can, they share a
    /// script, and the registry treats them as separate models only because
    /// Mozilla publishes separate models.
    #[test]
    fn chinese_and_japanese_are_separated_by_kana_not_by_han() {
        // Page-length, deliberately: the guard refuses to judge on fewer than
        // MIN_LETTERS characters, and a two-clause sample sits right on that
        // floor and answers Unknown -- which is the guard being careful, not
        // a defect, but it makes for a test that proves nothing.
        let chinese = &[
            "北京是中国的首都，也是全国的政治和文化中心。",
            "这个项目的目标是保护用户的隐私和安全。",
            "我们相信每个人都应该掌控自己的数据。",
        ];
        let japanese = &[
            "このブラウザはあなたのプライバシーを守ります。",
            "日本の首都は東京です。",
            "わたしたちは、だれもが自分のデータを管理できるべきだと考えています。",
        ];
        assert_eq!(expected_script("zh-Hans"), Some(Script::Han));
        assert_eq!(expected_script("zh-Hant"), Some(Script::Han));
        assert_eq!(expected_script("ja"), Some(Script::Kana));

        assert_eq!(verify(&c("zh-Hans", chinese)), Verdict::Match);
        assert_eq!(verify(&c("zh-Hant", chinese)), Verdict::Match);
        assert_eq!(verify(&c("ja", chinese)), Verdict::ScriptMismatch);
        assert_eq!(verify(&c("ja", japanese)), Verdict::Match);
        // And neither is mistaken for a Latin-script page, which is the class
        // of error the guard exists to make impossible.
        assert_eq!(verify(&c("en", chinese)), Verdict::ScriptMismatch);
        assert_eq!(verify(&c("en", japanese)), Verdict::ScriptMismatch);
    }

    /// Middle French (added 2026-09-16) rides the same Latin-script guard as
    /// Latin: its pages match, and Greek under it is still the incident.
    #[test]
    fn middle_french_expects_latin_script_and_refuses_greek() {
        let middle_french = &["Mais où sont les neiges d'antan?", "Le roy estoit fort malade."];
        let greek = &["Η Ρώμη είναι πόλη.", "Καλημέρα κόσμε φίλε."];
        assert_eq!(expected_script("frm"), Some(Script::Latin));
        assert_eq!(verify(&c("frm", middle_french)), Verdict::Match, "a Middle French page refused itself");
        assert_eq!(verify(&c("frm", greek)), Verdict::ScriptMismatch, "frm accepted Greek");
    }

    #[test]
    fn latin_the_language_expects_latin_the_script() {
        // The tier-2 la-en pack reads Latin PAGES; the guard must know the
        // language code, or a real Latin page would count as all-foreign and
        // refuse itself. Latin and English share the script, so the guard
        // cannot tell them apart (the honest limit documented on the module);
        // what it CAN do is not mistake a Latin page for a non-Latin one.
        assert_eq!(expected_script("la"), Some(Script::Latin));
        let latin = &["Gallia est omnis divisa in partes tres.", "Senatus Populusque."];
        assert_eq!(verify(&c("la", latin)), Verdict::Match);
        // Greek text under a Latin-expecting model is still the incident, and
        // still refused, la or en on the source side alike.
        let greek = &["Η Ρώμη είναι πόλη.", "Καλημέρα κόσμε φίλε."];
        assert_eq!(verify(&c("la", greek)), Verdict::ScriptMismatch);
    }

    /// The dominant script of a body of text, for the classification checks.
    fn dominant(texts: &[&str]) -> Script {
        use std::collections::HashMap;
        let mut m: HashMap<Script, usize> = HashMap::new();
        for t in texts {
            for ch in t.chars() {
                if let Some(sc) = script_of(ch) {
                    *m.entry(sc).or_insert(0) += 1;
                }
            }
        }
        m.into_iter().max_by_key(|(_, n)| *n).map(|(s, _)| s).unwrap_or(Script::Other)
    }

    #[test]
    fn the_incident_is_refused() {
        let greek = &[
            "Καλώς ήλθατε στην εφαρμογή",
            "Επιλέξτε Ενεργώ για τον εαυτό μου εφόσον έχετε ΑΦΜ και Κλειδάριθμο",
        ];
        assert_eq!(dominant(greek), Script::Greek);
        assert_eq!(verify(&c("en", greek)), Verdict::ScriptMismatch);
        assert_eq!(verify(&c("es", greek)), Verdict::ScriptMismatch);
        assert_eq!(verify(&c("el", greek)), Verdict::Match);
    }

    #[test]
    fn a_clean_english_page_matches_english() {
        let english = &[
            "Welcome to the application",
            "Choose Active for yourself if you have a tax number and a PIN",
        ];
        assert_eq!(verify(&c("en", english)), Verdict::Match);
        assert_eq!(verify(&c("el", english)), Verdict::ScriptMismatch);
    }

    #[test]
    fn latin_versus_latin_is_not_distinguishable_and_says_so() {
        let french = &[
            "Bienvenue dans l'application",
            "Choisissez Actif pour vous-même si vous avez un numéro fiscal",
        ];
        assert_eq!(dominant(french), Script::Latin);
        assert_eq!(verify(&c("fr", french)), Verdict::Match);
        assert_eq!(verify(&c("en", french)), Verdict::Match); // the honest limit
    }

    #[test]
    fn a_few_brand_names_do_not_flip_a_greek_page() {
        // Mostly Greek with a couple of inline Latin brand words -- under the
        // 10% foreign bound, so it still translates.
        let mostly_greek = &[
            "Το άρθρο αναφέρεται στην μεγάλη εταιρεία Google και τα προϊόντα της",
            "και συνεχίζει με πολύ περισσότερο ελληνικό κείμενο εδώ κάτω από αυτό",
            "με ακόμη περισσότερες ελληνικές λέξεις για να είναι ρεαλιστικό το κείμενο",
        ];
        assert_eq!(dominant(mostly_greek), Script::Greek);
        assert_eq!(verify(&c("el", mostly_greek)), Verdict::Match);
    }

    #[test]
    fn a_genuinely_mixed_page_is_refused_not_translated() {
        // Half Latin, half Greek: whichever source, ~half is the wrong alphabet
        // and would be corrupted. Fail closed.
        let mixed = &[
            "Hello world this is english text here now",
            "Γεια σου κόσμε αυτό είναι ελληνικό κείμενο εδώ",
        ];
        assert_eq!(verify(&c("en", mixed)), Verdict::ScriptMismatch);
        assert_eq!(verify(&c("el", mixed)), Verdict::ScriptMismatch);
    }

    /// Every attack two red-team rounds found, pinned as regressions.
    #[test]
    fn red_team_bypasses_are_closed() {
        // Han-only is Chinese, not Japanese.
        let han = &["这是中文文本这里现在今天请翻译更多的中文内容在这里非常好"];
        assert_eq!(verify(&c("ja", han)), Verdict::ScriptMismatch);
        // Real Japanese (kana-rich) still passes.
        let jp = &["これはにほんごのテキストですすべてのたんごがここにあります"];
        assert_eq!(verify(&c("ja", jp)), Verdict::Match);
        // A Chinese page padded with a LITTLE kana (round 2 bypass) is still
        // refused: the kana floor is 15%, not 5%.
        let padded = &["这是中文文本这里现在今天请翻译更多的中文内容 かな"];
        assert_eq!(verify(&c("ja", padded)), Verdict::ScriptMismatch);

        // Three-script dilution against en -> refused.
        let diluted = &["αβγδεζηθικλμνξο", "абвгдежзийклм", "abcdefghi"];
        assert_eq!(verify(&c("en", diluted)), Verdict::ScriptMismatch);

        // 60/40 Latin/Greek -> refused (the 40% Greek would corrupt).
        let split = &["abcdefghijkl", "αβγδεζηθ"];
        assert_eq!(verify(&c("en", split)), Verdict::ScriptMismatch);

        // Armenian (unenumerated -> Other) against en -> refused, because
        // "incompatible" now counts everything not in the expected system.
        let arm = &["ԱԲԳԴԵԶԷԸԹԺԻԼԽԾԿՀՁՂՃՄՅՆՇՈՉ"];
        assert_eq!(verify(&c("en", arm)), Verdict::ScriptMismatch);

        // zh still works for a Chinese page.
        assert_eq!(verify(&c("zh", han)), Verdict::Match);
    }

    /// THE TINY-BATCH BYPASS the reconciliation found: incompatible text chopped
    /// into sub-threshold batches must still be caught, because the tally is
    /// CUMULATIVE across batches.
    #[test]
    fn sub_threshold_batches_accumulate_and_are_refused() {
        let mut cc = ScriptCounts::new("en");
        // Five batches of 8 Greek letters each = 40 letters, but no single
        // batch reaches MIN_LETTERS.
        for _ in 0..5 {
            cc.add_batch(&["αβγδεζηθ".to_string()]);
            // Below the minimum, the running verdict is still Unknown...
        }
        // ...but once enough has accumulated, the whole is a clear mismatch.
        assert!(cc.letters() >= MIN_LETTERS);
        assert_eq!(verify(&cc), Verdict::ScriptMismatch);
    }

    #[test]
    fn too_little_text_is_unknown() {
        let tiny = c("en", &["Hi", "123", "!!!"]);
        assert!(tiny.letters() < MIN_LETTERS);
        assert_eq!(verify(&tiny), Verdict::Unknown);
    }

    #[test]
    fn a_source_with_no_known_script_asks() {
        assert_eq!(verify(&c("xx", &["Welcome to the application here now today please"])), Verdict::Unknown);
    }

    #[test]
    fn cyrillic_arabic_hebrew_cjk_each_classify() {
        assert_eq!(dominant(&["Привет мир это русский текст здесь сейчас"]), Script::Cyrillic);
        assert_eq!(verify(&c("ru", &["Привет мир это русский текст здесь сейчас снова"])), Verdict::Match);
        assert_eq!(dominant(&["مرحبا بالعالم هذا نص عربي هنا الآن اليوم"]), Script::Arabic);
        assert_eq!(verify(&c("ar", &["مرحبا بالعالم هذا نص عربي هنا الآن اليوم مرة"])), Verdict::Match);
        assert_eq!(dominant(&["שלום עולם זהו טקסט עברי כאן עכשיו היום"]), Script::Hebrew);
    }

    /// Decomposed (NFD) text classifies the same as its composed form. Fixed
    /// after the reconciliation noted the earlier test compared non-equivalent
    /// strings. Same words, composed vs decomposed, compared on the verdict.
    #[test]
    fn decomposed_text_classifies_like_composed() {
        let composed = "élève café résumé Zürich Köln naïve àéîõü";
        let decomposed = "e\u{0301}le\u{0300}ve cafe\u{0301} re\u{0301}sume\u{0301} Zu\u{0308}rich Ko\u{0308}ln nai\u{0308}ve a\u{0300}e\u{0301}i\u{0302}o\u{0303}u\u{0308}";
        // Same words either way; both are dominantly Latin and Match for en.
        assert_eq!(dominant(&[composed]), Script::Latin);
        assert_eq!(dominant(&[decomposed]), Script::Latin);
        let cc = c("en", &[composed]);
        let dd = c("en", &[decomposed]);
        assert_eq!(verify(&cc), verify(&dd));
        assert_eq!(verify(&cc), Verdict::Match);
    }

    #[test]
    fn every_registry_language_has_an_expected_script() {
        for lang in crate::languages::LANGUAGES {
            assert!(
                expected_script(lang.code).is_some(),
                "{} ({}) has no expected script",
                lang.code,
                lang.name
            );
        }
    }
    /// The inverse mapping resolves only where the answer is unique, and the
    /// interesting cases are pinned: Greek is one language, Cyrillic is four,
    /// kana is Japanese by definition of the classifier's own word, and a
    /// hostile or unknown name is no answer at all.
    #[test]
    fn a_script_name_resolves_only_when_one_language_uses_it() {
        assert_eq!(language_for_script_name("greek"), Some("el"));
        assert_eq!(language_for_script_name("hangul"), Some("ko"));
        assert_eq!(language_for_script_name("thai"), Some("th"));
        assert_eq!(language_for_script_name("hebrew"), Some("he"));
        assert_eq!(language_for_script_name("kana"), Some("ja"));
        // Ambiguous scripts refuse rather than guess.
        assert_eq!(language_for_script_name("cyrillic"), None);
        assert_eq!(language_for_script_name("arabic"), None);
        assert_eq!(language_for_script_name("devanagari"), None);
        // Latin is deliberately not even a recognised name.
        assert_eq!(language_for_script_name("latin"), None);
        // Page-controlled input: junk is no answer, never a panic.
        assert_eq!(language_for_script_name(""), None);
        assert_eq!(language_for_script_name("GREEK"), None);
        assert_eq!(language_for_script_name("<script>"), None);
    }

    /// The tag resolver: primary subtags resolve plainly, Chinese resolves by
    /// script-or-region, and page-controlled junk resolves to nothing.
    #[test]
    fn a_declared_tag_resolves_to_a_registry_code_or_nothing() {
        assert_eq!(registry_code_for_tag("el"), Some("el"));
        assert_eq!(registry_code_for_tag("el-GR"), Some("el"));
        assert_eq!(registry_code_for_tag("fr-CA"), Some("fr"));
        assert_eq!(registry_code_for_tag("EN-us"), Some("en"));
        assert_eq!(registry_code_for_tag("pt_BR"), Some("pt"));
        // The Chinese split: explicit script wins, region decides otherwise,
        // bare zh is Simplified.
        assert_eq!(registry_code_for_tag("zh-Hans"), Some("zh-Hans"));
        assert_eq!(registry_code_for_tag("zh-hant"), Some("zh-Hant"));
        assert_eq!(registry_code_for_tag("zh-CN"), Some("zh-Hans"));
        assert_eq!(registry_code_for_tag("zh-SG"), Some("zh-Hans"));
        assert_eq!(registry_code_for_tag("zh-TW"), Some("zh-Hant"));
        assert_eq!(registry_code_for_tag("zh-HK"), Some("zh-Hant"));
        assert_eq!(registry_code_for_tag("zh"), Some("zh-Hans"));
        assert_eq!(registry_code_for_tag("zh-Hant-TW"), Some("zh-Hant"));
        // Junk, unknown, empty: no answer, no panic.
        assert_eq!(registry_code_for_tag("xx"), None);
        assert_eq!(registry_code_for_tag(""), None);
        assert_eq!(registry_code_for_tag("zzz-Hans"), None);
    }

    /// The mixed-page case, which the page-level verdict cannot serve.
    ///
    /// A language-reader page prints Macedonian and its English translation in
    /// one document. The whole-page tally lands near half foreign and trips
    /// ScriptMismatch, so the page was refused entirely -- on a document that
    /// is half exactly what the reader asked for. Per node, the Cyrillic goes
    /// to the model and the English is left alone.
    #[test]
    fn a_mixed_page_sends_its_own_language_and_skips_the_rest() {
        let counts = ScriptCounts::new("mk");
        assert!(counts.text_is_expected("Секој има право на образование."));
        assert!(!counts.text_is_expected("Everyone has the right to education."));
        // The page verdict on that same document still says mismatch -- which
        // is why the per-node check has to exist rather than the page one
        // being loosened.
        let mut page = ScriptCounts::new("mk");
        page.add_batch(&[
            "Секој има право на образование.".to_string(),
            "Everyone has the right to education.".to_string(),
        ]);
        assert_eq!(verify(&page), Verdict::ScriptMismatch);
    }

    /// THE CORRUPTION GUARD IS NOT WEAKENED BY PER-NODE FILTERING.
    ///
    /// The incident this whole seam exists for: an en-source model fed a Greek
    /// page. Every node fails the node check too, so nothing is sent and the
    /// page verdict still refuses -- the outcome is identical, which is the
    /// property that had to be preserved.
    #[test]
    fn a_wholly_foreign_page_still_sends_nothing() {
        let counts = ScriptCounts::new("en");
        for line in [
            "Καθένας έχει δικαίωμα στην εκπαίδευση.",
            "Η εκπαίδευση πρέπει να παρέχεται δωρεάν.",
        ] {
            assert!(!counts.text_is_expected(line), "{line}");
        }
    }

    /// A node too short to judge is KEPT, not dropped: the page verdict has
    /// already said this document is translatable, and "2)" or a date is not
    /// evidence against it. Dropping them would leave visible gaps.
    #[test]
    fn a_node_with_too_little_text_is_kept() {
        let counts = ScriptCounts::new("mk");
        assert!(counts.text_is_expected("2)"));
        assert!(counts.text_is_expected("1948"));
        assert!(counts.text_is_expected("UN"));
    }

    /// A page cannot split its way past the guard.
    ///
    /// Short nodes are kept unjudged so a heading or a date does not gap a
    /// page the verdict approved -- but a page controls how its text is split,
    /// and an audit found that "under eight letters is always fine" is a rule
    /// an attacker can simply meet. Once the cumulative census says the page
    /// is incompatible, short nodes stop getting the benefit of the doubt.
    #[test]
    fn short_nodes_stop_being_waved_through_once_the_page_is_refused() {
        // A Greek page against an English source: the classic incident.
        let mut counts = ScriptCounts::new("en");
        // Before any tally, a short node is kept -- there is nothing to judge.
        assert!(counts.text_is_expected("Άρθρο"));
        // Feed the page. The cumulative verdict becomes a mismatch.
        counts.add_batch(&[
            "Καθένας έχει δικαίωμα στην εκπαίδευση.".to_string(),
            "Η εκπαίδευση πρέπει να παρέχεται δωρεάν.".to_string(),
        ]);
        assert_eq!(verify(&counts), Verdict::ScriptMismatch);
        // Now the same short node is refused: chopping the rest of the page
        // into fragments buys nothing.
        assert!(!counts.text_is_expected("Άρθρο"));
        assert!(!counts.text_is_expected("δωρεάν"));
    }

    /// The tightening must not break the ordinary mixed page: a document whose
    /// verdict is fine keeps its short nodes.
    #[test]
    fn short_nodes_survive_on_a_page_whose_verdict_is_good() {
        let mut counts = ScriptCounts::new("mk");
        counts.add_batch(&[
            "Секој има право на образование.".to_string(),
            "Образованието ќе биде бесплатно.".to_string(),
        ]);
        assert_ne!(verify(&counts), Verdict::ScriptMismatch);
        assert!(counts.text_is_expected("2)"));
        assert!(counts.text_is_expected("1948"));
    }

}
