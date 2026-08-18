//! Change Cross-Check: did this page change for your contact too?
//!
//! Change detection on its own answers one question: has this page changed
//! since I last saw it. Useful, and blind in one direction. A page that
//! changed for you might have changed for everyone (an ordinary edit) or
//! only for you (something worth knowing about). One browser cannot tell
//! those apart. Two can.
//!
//! This module is the protocol layer for that exchange: message shapes and
//! the verdict matrix. Pure logic. No I/O, no transport, no clock.
//!
//! # What is actually compared, and why it is a matrix rather than a verdict
//!
//! Each side has a BASELINE (what the page looked like when they bookmarked
//! or last checked it) and possibly a CURRENT reading (what it looks like
//! now, if the page is open). Three comparisons are available, and each
//! answers a different question:
//!
//! | cell | compares | answers |
//! | --- | --- | --- |
//! | `now` | my current vs their current | are we being served the same thing right now |
//! | `baselines` | my baseline vs their baseline | did we start from the same thing |
//! | `their_change` | their baseline vs their current | did it change for them too |
//!
//! Collapsing those into one word would throw away the distinction the
//! feature exists for. A cell is `None` when the reading it needs is
//! missing, which is common and not a failure: a contact who does not have
//! the page open can still answer usefully from their baseline alone.
//!
//! # What this proves, and what it does not
//!
//! 1. **Timestamps are not synchronised.** Two baselines recorded days
//!    apart differ for the most ordinary reason there is, so
//!    `baseline_gap_seconds` travels with the verdict and any wording built
//!    on it has to account for the gap rather than hide it.
//! 2. **It assumes an honest contact.** There is no identity layer here;
//!    authentication is the transport's job, and nothing stops a peer
//!    misreporting what they saw.
//! 3. **"Changed for you and not for them" is a REASON TO LOOK, never a
//!    finding.** Caches, CDN variants, regional editions, a personalised
//!    fragment and simple timing all produce it innocently.
//! 4. **A missing cell is not evidence.** Absence of a current reading says
//!    the page was not open, nothing more.
//!
//! A feature that overclaims here is worse than no feature. Every string
//! this module produces is written to be safe to show a user verbatim.
//!
//! # The wire budget, which shapes the message
//!
//! A `ContentDigest` is 608 bytes raw (three 32-byte hashes plus 64 u64
//! minima), and the app hex-encodes a message body into a JSON envelope
//! capped at `patanyx_chat::MAX_MESSAGE_BYTES` (4096). Two digests fit;
//! THREE DOES NOT. That is why a response carries at most two, and why "no
//! current reading" is an absent field rather than a third digest.
//!
//! THE BODY IS PACKED BINARY, NOT JSON, and that is what makes two fit.
//! Serde renders `[u8; 32]` as an array of decimal numbers, which inflated
//! a 608-byte digest to roughly 1,700 bytes of text: two of those, hex
//! encoded, measured 6,946 bytes against the 4,096 cap. The first version of
//! this module was JSON and the wire-budget test at the bottom caught it.
//! Every field is read back through a bounds-checked cursor, so a truncated
//! or hostile body is an error rather than an index into peer-supplied
//! bytes.

use patanyx_integrity::{compare, ContentDigest, Verdict as IntegrityVerdict};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{normalize_url, CorroborateError, NormalizedUrl, MAX_MESSAGE_BYTES};

/// Bumped when these shapes change incompatibly. Independent of the page and
/// download protocols: the three evolve separately.
pub const CHANGE_PROTOCOL_VERSION: u32 = 1;

/// "Here is what this page looked like when I saved it, and what it looks
/// like now. What about you?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeCompareRequest {
    pub version: u32,
    pub url: String,
    pub baseline: ContentDigest,
    pub baseline_recorded_at: u64,
    /// Absent when the asker's own page is not open. The comparison still
    /// works; it simply has fewer cells.
    pub current: Option<ContentDigest>,
    pub checked_at: u64,
}

/// The other side's answer, in the same shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeCompareResponse {
    pub version: u32,
    pub url: String,
    /// Absent when the contact has no baseline for this address, which is
    /// the ordinary case for a page they never bookmarked.
    pub baseline: Option<ContentDigest>,
    pub baseline_recorded_at: Option<u64>,
    pub current: Option<ContentDigest>,
    pub checked_at: u64,
}

/// A digest packed into exactly this many bytes: three 32-byte hashes plus
/// 64 little-endian u64 minima.
const DIGEST_WIRE_LEN: usize = 32 + 32 + 32 + 64 * 8;

/// Fixed-layout binary for one digest.
///
/// NOT serde_json, and this is the difference between fitting the chat
/// envelope and not fitting it. JSON renders `[u8; 32]` as an array of
/// decimal numbers, so a 608-byte digest becomes about 1,700 bytes of text,
/// and two of them hex-encoded came to 6,946 bytes against a 4,096 cap. The
/// first version of this module used JSON and was caught by the wire-budget
/// test below, which is exactly what that test exists for.
fn digest_to_wire(digest: &ContentDigest) -> Result<Vec<u8>, CorroborateError> {
    if digest.minhash.len() != 64 {
        return Err(CorroborateError::MalformedMessage(format!(
            "digest sketch is {} words, expected 64",
            digest.minhash.len()
        )));
    }
    let mut out = Vec::with_capacity(DIGEST_WIRE_LEN);
    out.extend_from_slice(&digest.raw);
    out.extend_from_slice(&digest.structure);
    out.extend_from_slice(&digest.text);
    for word in &digest.minhash {
        out.extend_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}

fn digest_from_wire(bytes: &[u8]) -> Result<ContentDigest, CorroborateError> {
    if bytes.len() != DIGEST_WIRE_LEN {
        return Err(CorroborateError::MalformedMessage(
            "digest is the wrong length".to_string(),
        ));
    }
    let mut raw = [0u8; 32];
    let mut structure = [0u8; 32];
    let mut text = [0u8; 32];
    raw.copy_from_slice(&bytes[..32]);
    structure.copy_from_slice(&bytes[32..64]);
    text.copy_from_slice(&bytes[64..96]);
    let minhash = bytes[96..]
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().expect("chunks_exact(8)")))
        .collect();
    Ok(ContentDigest {
        raw,
        structure,
        text,
        minhash,
    })
}

/// Reader over a message body, refusing every short read rather than
/// indexing into peer-supplied bytes.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CorroborateError> {
        let end = self.at.checked_add(n).ok_or_else(|| {
            CorroborateError::MalformedMessage("length overflow".to_string())
        })?;
        if end > self.bytes.len() {
            return Err(CorroborateError::MalformedMessage(
                "message ends early".to_string(),
            ));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, CorroborateError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CorroborateError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("took 4"),
        ))
    }

    fn u64(&mut self) -> Result<u64, CorroborateError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("took 8"),
        ))
    }

    fn url(&mut self) -> Result<String, CorroborateError> {
        let len = u16::from_le_bytes(self.take(2)?.try_into().expect("took 2")) as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| CorroborateError::MalformedMessage("url is not utf-8".to_string()))
    }

    fn digest(&mut self) -> Result<ContentDigest, CorroborateError> {
        digest_from_wire(self.take(DIGEST_WIRE_LEN)?)
    }

    fn optional_digest(&mut self) -> Result<Option<ContentDigest>, CorroborateError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.digest()?)),
            other => Err(CorroborateError::MalformedMessage(format!(
                "bad presence byte {other}"
            ))),
        }
    }
}

fn push_url(out: &mut Vec<u8>, url: &str) -> Result<(), CorroborateError> {
    let len = u16::try_from(url.len())
        .map_err(|_| CorroborateError::MalformedMessage("url too long".to_string()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(url.as_bytes());
    Ok(())
}

fn push_optional_digest(
    out: &mut Vec<u8>,
    digest: &Option<ContentDigest>,
) -> Result<(), CorroborateError> {
    match digest {
        None => out.push(0),
        Some(d) => {
            out.push(1);
            out.extend_from_slice(&digest_to_wire(d)?);
        }
    }
    Ok(())
}

/// Shared tail of every decode: version, then the peer-supplied url is
/// re-normalized and required to match what arrived. Same rule the download
/// protocol applies, and for the same reason: a noncanonical spelling would
/// produce a false mismatch, and control characters have no business
/// reaching a comparison.
fn check_envelope(version: u32, url: &str) -> Result<(), CorroborateError> {
    if version != CHANGE_PROTOCOL_VERSION {
        return Err(CorroborateError::UnsupportedVersion(version));
    }
    let canonical = normalize_url(url).map_err(|e| {
        CorroborateError::MalformedMessage(format!("url does not normalize: {e}"))
    })?;
    if canonical.as_str() != url {
        return Err(CorroborateError::MalformedMessage(
            "url is not in canonical normalized form".to_string(),
        ));
    }
    Ok(())
}

fn open_cursor(bytes: &[u8]) -> Result<Cursor<'_>, CorroborateError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(CorroborateError::MessageTooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    Ok(Cursor { bytes, at: 0 })
}

impl ChangeCompareRequest {
    /// version | url | baseline | baseline_recorded_at | current? | checked_at
    pub fn to_bytes(&self) -> Result<Vec<u8>, CorroborateError> {
        let mut out = Vec::with_capacity(DIGEST_WIRE_LEN * 2 + 64);
        out.extend_from_slice(&self.version.to_le_bytes());
        push_url(&mut out, &self.url)?;
        out.extend_from_slice(&digest_to_wire(&self.baseline)?);
        out.extend_from_slice(&self.baseline_recorded_at.to_le_bytes());
        push_optional_digest(&mut out, &self.current)?;
        out.extend_from_slice(&self.checked_at.to_le_bytes());
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CorroborateError> {
        let mut cur = open_cursor(bytes)?;
        let version = cur.u32()?;
        let url = cur.url()?;
        check_envelope(version, &url)?;
        Ok(Self {
            version,
            url,
            baseline: cur.digest()?,
            baseline_recorded_at: cur.u64()?,
            current: cur.optional_digest()?,
            checked_at: cur.u64()?,
        })
    }
}

impl ChangeCompareResponse {
    /// version | url | baseline? | baseline_recorded_at? | current? | checked_at
    pub fn to_bytes(&self) -> Result<Vec<u8>, CorroborateError> {
        let mut out = Vec::with_capacity(DIGEST_WIRE_LEN * 2 + 64);
        out.extend_from_slice(&self.version.to_le_bytes());
        push_url(&mut out, &self.url)?;
        push_optional_digest(&mut out, &self.baseline)?;
        match self.baseline_recorded_at {
            None => out.push(0),
            Some(at) => {
                out.push(1);
                out.extend_from_slice(&at.to_le_bytes());
            }
        }
        push_optional_digest(&mut out, &self.current)?;
        out.extend_from_slice(&self.checked_at.to_le_bytes());
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CorroborateError> {
        let mut cur = open_cursor(bytes)?;
        let version = cur.u32()?;
        let url = cur.url()?;
        check_envelope(version, &url)?;
        let baseline = cur.optional_digest()?;
        let baseline_recorded_at = match cur.u8()? {
            0 => None,
            1 => Some(cur.u64()?),
            other => {
                return Err(CorroborateError::MalformedMessage(format!(
                    "bad presence byte {other}"
                )))
            }
        };
        Ok(Self {
            version,
            url,
            baseline,
            baseline_recorded_at,
            current: cur.optional_digest()?,
            checked_at: cur.u64()?,
        })
    }
}

impl ChangeCompareRequest {
    pub fn new(
        url: &NormalizedUrl,
        baseline: ContentDigest,
        baseline_recorded_at: u64,
        current: Option<ContentDigest>,
        checked_at: u64,
    ) -> Self {
        Self {
            version: CHANGE_PROTOCOL_VERSION,
            url: url.as_str().to_string(),
            baseline,
            baseline_recorded_at,
            current,
            checked_at,
        }
    }
}

impl ChangeCompareResponse {
    pub fn new(
        url: &NormalizedUrl,
        baseline: Option<ContentDigest>,
        baseline_recorded_at: Option<u64>,
        current: Option<ContentDigest>,
        checked_at: u64,
    ) -> Self {
        Self {
            version: CHANGE_PROTOCOL_VERSION,
            url: url.as_str().to_string(),
            baseline,
            baseline_recorded_at,
            current,
            checked_at,
        }
    }
}

/// One cell of the matrix: what two readings say about each other.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cell {
    Same,
    TextSameMarkupDiffers,
    TextDiffers { similarity: f32 },
}

fn cell(a: &ContentDigest, b: &ContentDigest) -> Cell {
    match compare(a, b) {
        IntegrityVerdict::Identical => Cell::Same,
        IntegrityVerdict::StructureDiffers => Cell::TextSameMarkupDiffers,
        IntegrityVerdict::TextDiffers { similarity } => Cell::TextDiffers { similarity },
    }
}

impl Cell {
    /// True when the two readings differ in their VISIBLE TEXT, which is the
    /// only difference this feature draws a conclusion from. Markup churn is
    /// not a change a reader experienced.
    pub fn text_differs(&self) -> bool {
        matches!(self, Cell::TextDiffers { .. })
    }
}

/// The three comparisons, plus the context needed to read them honestly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChangeVerdict {
    /// My current vs their current.
    pub now: Option<Cell>,
    /// My baseline vs their baseline.
    pub baselines: Option<Cell>,
    /// Their baseline vs their current: did it change for them.
    pub their_change: Option<Cell>,
    /// My baseline vs my current: did it change for me. Always present,
    /// since the asker cannot ask without a baseline and this is the check
    /// that prompted the question.
    pub my_change: Option<Cell>,
    /// Seconds between the two baselines, when both exist. A large gap is
    /// the most ordinary explanation for two baselines disagreeing.
    pub baseline_gap_seconds: Option<u64>,
}

/// Compare two sides' readings of the same page.
///
/// Errors only when the messages are not about the same normalized URL,
/// which cannot happen between honest peers: the response is built from the
/// request's own URL.
pub fn change_verdict(
    request: &ChangeCompareRequest,
    response: &ChangeCompareResponse,
) -> Result<ChangeVerdict, CorroborateError> {
    if request.url != response.url {
        return Err(CorroborateError::UrlMismatch {
            ours: request.url.clone(),
            theirs: response.url.clone(),
        });
    }
    let now = match (&request.current, &response.current) {
        (Some(mine), Some(theirs)) => Some(cell(mine, theirs)),
        _ => None,
    };
    let baselines = response
        .baseline
        .as_ref()
        .map(|theirs| cell(&request.baseline, theirs));
    let their_change = match (&response.baseline, &response.current) {
        (Some(base), Some(current)) => Some(cell(base, current)),
        _ => None,
    };
    let my_change = request
        .current
        .as_ref()
        .map(|current| cell(&request.baseline, current));
    let baseline_gap_seconds = response
        .baseline_recorded_at
        .map(|theirs| request.baseline_recorded_at.abs_diff(theirs));
    Ok(ChangeVerdict {
        now,
        baselines,
        their_change,
        my_change,
        baseline_gap_seconds,
    })
}

/// The one sentence a reader takes away, chosen from the cells that exist.
///
/// Written here rather than in the UI so the wording has a single author and
/// cannot drift between surfaces, exactly as the page and download verdicts
/// are worded in this crate.
///
/// NOTE ON THE STRONGEST CASE. "It changed for you and not for them" is the
/// finding the feature exists to surface, and it is also the one most easily
/// overstated. Its sentence names the observation, then names the innocent
/// causes, then says what to do. It never says targeted, never says
/// manipulated, and never tells the reader what happened to them.
impl fmt::Display for ChangeVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mine = self.my_change.map(|c| c.text_differs());
        let theirs = self.their_change.map(|c| c.text_differs());
        match (mine, theirs) {
            (Some(true), Some(true)) => f.write_str(
                "This page changed for your contact too. A change both of you \
                 see is an ordinary edit rather than something aimed at either \
                 of you.",
            ),
            (Some(true), Some(false)) => f.write_str(
                "This page changed for you, and your contact's copy still \
                 matches what they saved. Caches, regional editions and simple \
                 timing all produce that, so treat it as a reason to look \
                 closer rather than a conclusion. Comparing what each of you \
                 sees now is the next useful step.",
            ),
            (Some(false), Some(true)) => f.write_str(
                "This page changed for your contact but not for you. That is \
                 worth knowing for the same reasons the other way round would \
                 be, and it has the same innocent explanations.",
            ),
            (Some(false), Some(false)) => f.write_str(
                "Neither copy has changed since you each saved it.",
            ),
            // I have no current reading of my own, but my contact does. The
            // page was not open here, which is unusual (the ask normally
            // starts from a check) and still answerable: what they can say
            // is whether it changed for them.
            (None, Some(theirs)) => {
                if theirs {
                    f.write_str(
                        "Your own copy was not open to compare. This page has \
                         changed for your contact since they saved it.",
                    )
                } else {
                    f.write_str(
                        "Your own copy was not open to compare. Your contact's \
                         copy has not changed since they saved it.",
                    )
                }
            }
            // Their current reading is missing: the page was not open for
            // them. Their baseline may still say something useful.
            (_, None) => match self.baselines {
                Some(cellv) if cellv.text_differs() => f.write_str(
                    "Your contact did not have the page open, so only the saved \
                     copies could be compared, and those already differ. Two \
                     copies saved at different times routinely do.",
                ),
                Some(_) => f.write_str(
                    "Your contact did not have the page open. The copies you \
                     each saved match each other.",
                ),
                None => f.write_str(
                    "Your contact has nothing saved for this address and did \
                     not have it open, so there was nothing to compare.",
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patanyx_integrity::digest;

    fn page(words: &str) -> ContentDigest {
        digest(format!("<p>{words}</p>").as_bytes()).unwrap()
    }

    fn url() -> NormalizedUrl {
        normalize_url("https://news.example/story").unwrap()
    }

    fn request(baseline: &str, current: Option<&str>) -> ChangeCompareRequest {
        ChangeCompareRequest::new(&url(), page(baseline), 1000, current.map(page), 2000)
    }

    fn response(baseline: Option<&str>, current: Option<&str>) -> ChangeCompareResponse {
        ChangeCompareResponse::new(
            &url(),
            baseline.map(page),
            baseline.map(|_| 1200),
            current.map(page),
            2000,
        )
    }

    const A: &str = "the committee published the report on Tuesday after a long debate";
    const B: &str = "the committee withdrew the report on Tuesday after a long debate";

    #[test]
    fn a_change_both_sides_see_is_reported_as_ordinary() {
        let req = request(A, Some(B));
        let resp = response(Some(A), Some(B));
        let verdict = change_verdict(&req, &resp).unwrap();
        assert!(verdict.my_change.unwrap().text_differs());
        assert!(verdict.their_change.unwrap().text_differs());
        assert_eq!(verdict.now, Some(Cell::Same), "both now see the same text");
        let text = verdict.to_string();
        assert!(text.contains("ordinary edit"), "{text}");
        assert!(!text.to_lowercase().contains("targeted"), "{text}");
    }

    #[test]
    fn a_change_only_i_can_see_names_its_innocent_causes_and_no_conclusion() {
        // The finding the feature exists for, and the one most easily
        // overstated.
        let req = request(A, Some(B));
        let resp = response(Some(A), Some(A));
        let verdict = change_verdict(&req, &resp).unwrap();
        assert!(verdict.my_change.unwrap().text_differs());
        assert!(!verdict.their_change.unwrap().text_differs());
        let text = verdict.to_string().to_lowercase();
        assert!(text.contains("caches"), "innocent causes must be named");
        assert!(text.contains("reason to look"), "must not conclude");
        for banned in ["targeted", "manipulat", "attack", "tamper"] {
            assert!(!text.contains(banned), "the verdict said {banned:?}: {text}");
        }
    }

    #[test]
    fn a_contact_with_the_page_closed_still_answers_from_their_baseline() {
        let req = request(A, Some(B));
        let resp = response(Some(A), None);
        let verdict = change_verdict(&req, &resp).unwrap();
        assert_eq!(verdict.now, None, "no current reading, no now cell");
        assert_eq!(verdict.their_change, None);
        assert!(verdict.baselines.is_some(), "baselines can still compare");
        assert!(verdict.to_string().contains("did not have the page open"));
    }

    #[test]
    fn a_contact_with_nothing_saved_says_so_rather_than_implying_anything() {
        let req = request(A, Some(B));
        let resp = response(None, None);
        let verdict = change_verdict(&req, &resp).unwrap();
        assert_eq!(verdict.baselines, None);
        assert_eq!(verdict.baseline_gap_seconds, None);
        let text = verdict.to_string();
        assert!(text.contains("nothing to compare"), "{text}");
    }

    #[test]
    fn the_baseline_gap_travels_with_the_verdict() {
        // Two baselines saved days apart differ for the most ordinary reason
        // there is, so the gap must reach whoever reads the answer.
        let req = request(A, Some(A));
        let resp = response(Some(B), Some(B));
        let verdict = change_verdict(&req, &resp).unwrap();
        assert_eq!(verdict.baseline_gap_seconds, Some(200));
    }

    #[test]
    fn the_verdict_refuses_two_different_pages() {
        let req = request(A, Some(B));
        let mut resp = response(Some(A), Some(A));
        resp.url = "https://other.example/".to_string();
        assert!(matches!(
            change_verdict(&req, &resp),
            Err(CorroborateError::UrlMismatch { .. })
        ));
    }

    #[test]
    fn two_digests_fit_the_chat_envelope_and_a_third_would_not() {
        // The constraint that shaped the message. Both messages carry at
        // most TWO digests, hex-encoded into a JSON envelope capped at 4096
        // bytes of plaintext by patanyx_chat.
        const CHAT_CAP: usize = 4096;
        const ENVELOPE_SLACK: usize = 120;
        let long = format!("https://example.com/{}", "a".repeat(180));
        let url = normalize_url(&long).unwrap();
        let req = ChangeCompareRequest::new(&url, page(A), u64::MAX, Some(page(B)), u64::MAX);
        let hex_len = req.to_bytes().unwrap().len() * 2;
        assert!(
            hex_len + ENVELOPE_SLACK < CHAT_CAP,
            "a two-digest request is {hex_len} hex bytes and must fit {CHAT_CAP}"
        );
        // And the headroom really is about one digest, not three: this is
        // the measurement the "no third digest" rule rests on.
        let one_digest_hex = serde_json::to_vec(&page(A)).unwrap().len() * 2;
        assert!(
            hex_len + one_digest_hex + ENVELOPE_SLACK > CHAT_CAP,
            "a third digest would fit after all; the message shape can be \
             reconsidered, and this test's reasoning updated with it"
        );
    }

    #[test]
    fn messages_survive_a_round_trip_and_refuse_a_foreign_version() {
        let req = request(A, Some(B));
        let back = ChangeCompareRequest::from_bytes(&req.to_bytes().unwrap()).unwrap();
        assert_eq!(back.url, req.url);
        assert_eq!(back.baseline, req.baseline);
        assert!(back.current.is_some());

        let resp = response(Some(A), None);
        let back = ChangeCompareResponse::from_bytes(&resp.to_bytes().unwrap()).unwrap();
        assert!(back.baseline.is_some());
        assert!(back.current.is_none());

        // The version is the first four bytes of the body, little-endian.
        let mut newer = req.to_bytes().unwrap();
        newer[..4].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            ChangeCompareRequest::from_bytes(&newer),
            Err(CorroborateError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn a_decoded_message_must_carry_an_already_normalized_url() {
        // The url sits after the version and its own length prefix, so it
        // can be rewritten in place as long as the length does not change.
        let req = request(A, Some(B));
        let mut bytes = req.to_bytes().unwrap();
        let at = bytes
            .windows(b"news.example".len())
            .position(|w| w == b"news.example")
            .expect("the url is in the body");
        bytes[at..at + b"News.EXAMPLE".len()].copy_from_slice(b"News.EXAMPLE");
        assert!(matches!(
            ChangeCompareRequest::from_bytes(&bytes),
            Err(CorroborateError::MalformedMessage(_))
        ));
    }

    #[test]
    fn a_truncated_message_is_refused_rather_than_indexed_into() {
        // Every field is read through a bounds-checked cursor, so a body cut
        // at any point is an error and never a panic.
        let req = request(A, Some(B));
        let full = req.to_bytes().unwrap();
        for cut in [0, 1, 4, 10, 200, full.len() - 1] {
            assert!(
                ChangeCompareRequest::from_bytes(&full[..cut]).is_err(),
                "a body cut to {cut} bytes was accepted"
            );
        }
    }
}
