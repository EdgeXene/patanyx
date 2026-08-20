//! Mark-of-the-Web, without the address.
//!
//! WHAT WINDOWS DOES ON ITS OWN. When WebView2 saves a download it attaches an
//! NTFS alternate data stream named `Zone.Identifier` to the file:
//!
//! ```text
//! [ZoneTransfer]
//! ZoneId=3
//! HostUrl=https://example.org/dl/thing.bin
//! ReferrerUrl=https://example.org/downloads/
//! ```
//!
//! Observed 2026-08-18 on a real 0.9.63 install (security audit, MOTW item):
//! `ZoneId=3` AND `HostUrl` were both present on a file PATANYX had saved.
//!
//! WHY THAT IS TWO DIFFERENT THINGS. `ZoneId=3` ("Internet") is the safety
//! half: it is what makes Explorer show "This file came from another
//! computer", what the Unblock box clears, what puts Office into Protected
//! View, and what makes PowerShell treat a script as remote. It costs the
//! user nothing and it protects them. `HostUrl` and `ReferrerUrl` are the
//! record half: the address the file came from, and the page the user was
//! on, written NEXT TO THE FILE in a stream any program can read, and one
//! that survives a copy to another NTFS volume. Fifty downloads and the
//! Downloads folder is a list of fifty places the user went. That is the one
//! place this browser was quietly keeping a browsing record.
//!
//! WHAT THIS MODULE DOES. After a download completes it rewrites the stream
//! to `ZoneId` ALONE, keeping the zone Windows chose and dropping every
//! address line. Nothing is added: a file that arrived with no stream gets
//! none (writing one would be inventing provenance), and a stream that
//! already carries no address is left byte-for-byte alone.
//!
//! WHAT IT DOES NOT DO. It does not raise the zone, lower it, or invent one.
//! It does not touch SmartScreen, which stays off (it reports URL and hash to
//! Microsoft; see the audit ledger). It is a no-op on Linux, where the
//! concept does not exist.
//!
//! WHY THE DECISION IS HERE AND THE I/O IS IN `windows.rs`. `rewrite` is pure:
//! bytes in, verdict out. `cargo test` proves the property on any host --
//! the address is gone, the zone is kept, an untouched stream is untouched --
//! without needing NTFS. The Windows backend only opens the stream, calls
//! this, and writes back what it is told to.

/// What the platform did about a finished download's mark.
///
/// Reported, not swallowed: the downloads view can say what happened, and a
/// failure to strip is a fact the user is entitled to (the address is still
/// on disk), not a detail to hide behind a successful-looking save.
// `Clean`, `Scrubbed` and `Failed` are constructed only by the Windows arm
// of `scrub_download_mark`; on unix the no-op returns `NotApplicable` and
// nothing else, so rustc rightly says the others are never built there. They
// are still MATCHED there (`mark_outcome_name` in main.rs), which is the
// point: one wire vocabulary on both targets.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// This platform has no such stream (Linux).
    NotApplicable,
    /// The file arrived with no stream, or one that already carried no
    /// address. Nothing was written.
    Clean,
    /// An address was present and has been removed.
    Scrubbed,
    /// An address was present and could not be removed. The stream could not
    /// be rewritten (a permission, a lock, a filesystem that is not NTFS
    /// pretending to be). The address is STILL ON DISK.
    Failed,
    /// The stream could not be READ, so whether it holds an address is
    /// unknown. Distinct from `Clean` on purpose: "there was nothing to
    /// remove" and "I could not look" are different facts, and reporting the
    /// second as the first is the exact overclaim this module exists to
    /// avoid. Distinct from `Failed` too, which asserts an address WAS
    /// there -- unknown must not borrow that certainty in either direction.
    Unknown,
}

/// The alternate data stream name Windows uses. Appended to a path as
/// `file.bin:Zone.Identifier`; NTFS resolves that with ordinary file APIs.
/// Read only by the Windows arm; unix has no stream to name.
#[allow(dead_code)]
pub const STREAM_NAME: &str = "Zone.Identifier";

/// What to do with an existing `Zone.Identifier` stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The stream carries no address; leave it exactly as it is.
    Keep,
    /// The stream carries an address; replace it with these bytes.
    Replace(String),
}

/// Given the current contents of a `Zone.Identifier` stream, decide whether
/// it needs rewriting and, if so, to what.
///
/// The output keeps `[ZoneTransfer]` and the `ZoneId=` line as they were and
/// drops every other key. Only two keys are documented for this stream and
/// both are addresses (`HostUrl`, `ReferrerUrl`), but the drop is by
/// ALLOWLIST -- keep `ZoneId`, discard the rest -- so an undocumented address
/// key some future runtime adds is dropped too rather than kept by omission.
///
/// REFUSING IS PART OF THE CONTRACT. A rewrite that drops the `ZoneId`
/// removes the Windows warning -- the exact half this module exists to keep
/// -- so the only safe rule is: never emit a replacement whose zone this
/// function did not positively read. Three shapes reach that rule, and a
/// pre-commit audit found all three writing an empty stream before it
/// existed:
///   * a stream with no `[ZoneTransfer]` header, whose `ZoneId` this parser
///     never enters the section to see;
///   * a UTF-16 stream, whose every byte pair this parser misreads;
///   * any input where no `ZoneId` line was kept but the raw text still
///     looks like it names one.
/// All three now return `Keep`, and the caller reports `Unknown` rather than
/// claiming a clean file. The ONE case that legitimately emits without a
/// zone is an input that parsed cleanly and genuinely had none: there is no
/// zone to lose, so dropping an address-only stream to its bare header takes
/// nothing away.
pub fn rewrite(existing: &str) -> Verdict {
    // A UTF-16 stream read as bytes and lossily converted arrives here full
    // of NUL. This parser would understand none of it, decide every line was
    // droppable, and emit a replacement with no zone. Refuse instead.
    if existing.contains('\0') || existing.starts_with('\u{FEFF}') {
        return Verdict::Keep;
    }
    let mut kept = Vec::new();
    let mut dropped_any = false;
    let mut in_zone_transfer = false;
    let mut saw_header = false;
    for raw in existing.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') {
            in_zone_transfer = trimmed.eq_ignore_ascii_case("[ZoneTransfer]");
            if in_zone_transfer {
                saw_header = true;
                kept.push("[ZoneTransfer]".to_string());
            } else {
                // A section this module does not know. Nothing documented
                // lives outside [ZoneTransfer]; drop it, and say so.
                dropped_any = true;
            }
            continue;
        }
        if in_zone_transfer && key_of(trimmed).eq_ignore_ascii_case("ZoneId") {
            kept.push(trimmed.to_string());
        } else {
            dropped_any = true;
        }
    }
    if !dropped_any {
        return Verdict::Keep;
    }
    // Never write a replacement whose zone was not positively read.
    let kept_a_zone = kept
        .iter()
        .any(|line| key_of(line).eq_ignore_ascii_case("ZoneId"));
    let text_names_a_zone = existing.to_ascii_lowercase().contains("zoneid");
    if !saw_header || (!kept_a_zone && text_names_a_zone) {
        return Verdict::Keep;
    }
    let mut out = String::new();
    for line in kept {
        out.push_str(&line);
        out.push_str("\r\n");
    }
    Verdict::Replace(out)
}

fn key_of(line: &str) -> &str {
    line.split('=').next().unwrap_or("").trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVED: &str =
        "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://patanyx.net/dl/blocklist-1787094094.bin\r\n";

    #[test]
    fn the_observed_stream_loses_its_address_and_keeps_its_zone() {
        // This is the exact stream, byte for byte, read off a real 0.9.63
        // install on 2026-08-18. The file is a public blocklist snapshot.
        match rewrite(OBSERVED) {
            Verdict::Replace(out) => {
                assert_eq!(out, "[ZoneTransfer]\r\nZoneId=3\r\n");
                assert!(!out.contains("patanyx"), "address survived: {out}");
            }
            Verdict::Keep => panic!("an address-bearing stream must be rewritten"),
        }
    }

    #[test]
    fn a_referrer_goes_too() {
        let s = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a.example/page\r\nHostUrl=https://a.example/f.bin\r\n";
        assert_eq!(
            rewrite(s),
            Verdict::Replace("[ZoneTransfer]\r\nZoneId=3\r\n".into())
        );
    }

    #[test]
    fn a_stream_with_no_address_is_left_alone() {
        // Byte-for-byte: no rewrite means no write, and no write means the
        // file's timestamps and the stream itself are untouched.
        assert_eq!(rewrite("[ZoneTransfer]\r\nZoneId=3\r\n"), Verdict::Keep);
        assert_eq!(rewrite("[ZoneTransfer]\nZoneId=3\n"), Verdict::Keep);
        assert_eq!(rewrite("[ZoneTransfer]\r\nZoneId=3"), Verdict::Keep);
    }

    #[test]
    fn the_zone_number_is_preserved_whatever_it_is() {
        // Never raise, never lower. A corporate proxy that lands a file in
        // zone 1 or 2 keeps that; this module has no opinion about zones.
        for z in ["0", "1", "2", "3", "4"] {
            let s = format!("[ZoneTransfer]\r\nZoneId={z}\r\nHostUrl=https://x/\r\n");
            assert_eq!(
                rewrite(&s),
                Verdict::Replace(format!("[ZoneTransfer]\r\nZoneId={z}\r\n"))
            );
        }
    }

    #[test]
    fn unknown_keys_are_dropped_not_kept_by_omission() {
        // Allowlist, not blocklist: a key this code has never heard of is an
        // address until proven otherwise.
        let s = "[ZoneTransfer]\r\nZoneId=3\r\nSomeFutureUrl=https://x/\r\n";
        assert_eq!(
            rewrite(s),
            Verdict::Replace("[ZoneTransfer]\r\nZoneId=3\r\n".into())
        );
    }

    #[test]
    fn key_matching_is_case_insensitive_and_tolerates_spaces() {
        let s = "[zonetransfer]\r\n  zoneid = 3  \r\nhosturl=https://x/\r\n";
        assert_eq!(
            rewrite(s),
            Verdict::Replace("[ZoneTransfer]\r\nzoneid = 3\r\n".into())
        );
    }

    #[test]
    fn an_address_only_stream_collapses_to_the_bare_header() {
        // No ZoneId to keep. The result is a header with no zone, which
        // Windows treats as unmarked -- the same as if the stream were gone.
        assert_eq!(
            rewrite("[ZoneTransfer]\r\nHostUrl=https://x/\r\n"),
            Verdict::Replace("[ZoneTransfer]\r\n".into())
        );
    }

    #[test]
    fn an_empty_stream_is_kept() {
        assert_eq!(rewrite(""), Verdict::Keep);
    }

    // The three shapes below each produced Replace("") -- an empty stream, no
    // zone, no Windows warning -- before a pre-commit audit executed them.
    // Each carries a perfectly good ZoneId that this parser could not see.
    // The rule they pin: never emit a replacement whose zone was not
    // positively read.

    #[test]
    fn a_zone_with_no_header_is_not_thrown_away() {
        // No [ZoneTransfer] line: the parser never enters the section, so
        // it never keeps the ZoneId. Writing would erase the mark.
        assert_eq!(rewrite("ZoneId=3\r\n"), Verdict::Keep);
        assert_eq!(rewrite("ZoneId=3\r\nHostUrl=https://x/\r\n"), Verdict::Keep);
    }

    #[test]
    fn a_bom_prefixed_stream_is_left_alone() {
        let s = "\u{FEFF}[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://x/\r\n";
        assert_eq!(rewrite(s), Verdict::Keep);
    }

    #[test]
    fn a_utf16_stream_is_left_alone() {
        // What String::from_utf8_lossy makes of UTF-16LE bytes: every other
        // byte is NUL. Nothing here parses; nothing here may be written.
        let mut s = String::new();
        for c in "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://x/\r\n".chars() {
            s.push(c);
            s.push('\0');
        }
        assert_eq!(rewrite(&s), Verdict::Keep);
    }

    #[test]
    fn an_unknown_section_holding_the_zone_is_left_alone() {
        // [Other] is not a section this parser knows, so its ZoneId is not
        // kept -- and therefore must not be written over.
        assert_eq!(rewrite("[Other]\r\nZoneId=3\r\n"), Verdict::Keep);
    }

    #[test]
    fn a_replacement_never_lacks_a_zone_the_input_had() {
        // The property behind every case above, stated once. For any input
        // that names a ZoneId, a Replace verdict must still name one.
        let inputs = [
            "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://x/\r\n",
            "[ZoneTransfer]\nZoneId=2\nReferrerUrl=https://x/\n",
            "  [ZONETRANSFER]  \r\n zoneid=1 \r\n hosturl=https://x/ \r\n",
            "ZoneId=3\r\nHostUrl=https://x/\r\n",
            "[Other]\r\nZoneId=3\r\nHostUrl=https://x/\r\n",
        ];
        for input in inputs {
            if let Verdict::Replace(out) = rewrite(input) {
                assert!(
                    out.to_ascii_lowercase().contains("zoneid"),
                    "input {input:?} named a zone but the replacement {out:?} does not"
                );
            }
        }
    }
}
