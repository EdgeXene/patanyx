//! Searching the personal archive: pure decision logic, no store, no IPC.
//!
//! An archived page is a capture plus the text OCR read off it. That text is
//! the point of the feature: it holds words that exist ONLY inside images,
//! which no bookmark search could ever match. This module decides which
//! records answer a query and what each row shows.
//!
//! # It reuses the cross-tab searcher rather than growing a second one
//!
//! `tab_search::find_snippets` already solves this exact problem for open
//! tabs: case-insensitive matching, a window around each hit that snaps
//! outward to whole words, and arithmetic that walks `char_indices` instead
//! of guessing byte offsets. Writing a second snippet shaper here would mean
//! two implementations of the same UTF-8 edge cases, one of them untested by
//! the gate that already covers the other. So archive search is a filter and
//! a ranking over that function's output, and nothing more.
//!
//! # What it deliberately does not do
//!
//! No index, no stemming, no ranking by relevance score. The archive is
//! bounded (a few hundred records), so a linear scan is both fast enough and
//! honest: a user who searched for a word gets the records containing that
//! word, ordered by when they were archived, with no invisible judgment
//! about which ones matter more.

use patanyx_store::ArchiveRecord;

use crate::tab_search::{check_query, find_snippets, Snippet};

/// One archived page that matched, with the context to show for it.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveHit {
    pub id: String,
    pub url: String,
    pub title: String,
    pub created_at: u64,
    /// True when the query was found in the title or address rather than in
    /// the page text. Worth distinguishing: a hit in the title is something
    /// a bookmark could have found, while a hit in the text may be a word
    /// that exists only inside a picture.
    pub in_metadata: bool,
    /// Context windows from the read text. Empty when the match was in the
    /// title or address only.
    pub snippets: Vec<Snippet>,
    /// Matches found in the text, before the snippet cap applies.
    pub match_count: u32,
    /// True when `match_count` hit the searcher's ceiling, so it is a floor
    /// rather than an exact number. Carried through rather than dropped:
    /// the cross-tab search words a capped count as "1000+" and an archive
    /// row that quietly printed the cap as exact would be the same lie in
    /// a different panel.
    pub match_count_capped: bool,
}

/// Records answering `query`, newest first.
///
/// The query is validated by the same `check_query` the cross-tab search
/// uses, so an over-long or empty query is refused identically in both
/// places rather than each surface inventing its own limit.
pub fn search(records: &[ArchiveRecord], query: &str) -> Result<Vec<ArchiveHit>, &'static str> {
    let needle = check_query(query)?;
    let lowered = needle.to_lowercase();
    let mut hits: Vec<ArchiveHit> = records
        .iter()
        .filter_map(|record| {
            let set = find_snippets(&record.text, &needle);
            // Metadata is matched here rather than through find_snippets: a
            // title is short enough that a context window around the hit
            // would just be the title again.
            let in_metadata = record.title.to_lowercase().contains(&lowered)
                || record.url.to_lowercase().contains(&lowered);
            if set.total == 0 && !in_metadata {
                return None;
            }
            Some(ArchiveHit {
                id: record.id.clone(),
                url: record.url.clone(),
                title: record.title.clone(),
                created_at: record.created_at,
                in_metadata,
                snippets: set.snippets,
                match_count: set.total,
                match_count_capped: set.capped,
            })
        })
        .collect();
    // Newest first. Stable, so two records archived in the same second keep
    // their stored order rather than swapping between searches.
    hits.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, title: &str, url: &str, text: &str, created_at: u64) -> ArchiveRecord {
        ArchiveRecord {
            id: id.to_string(),
            url: url.to_string(),
            title: title.to_string(),
            created_at,
            scope: "visible area".to_string(),
            text: text.to_string(),
            picture_bytes: 0,
            has_picture: false,
        }
    }

    #[test]
    fn a_word_that_exists_only_in_the_read_text_is_found() {
        // The whole reason the feature exists: the title and address say
        // nothing about the invoice number, which was legible only in the
        // picture.
        let records = [record(
            "a",
            "Scanned paperwork",
            "https://example.com/upload",
            "Invoice 88421 dated the fourteenth of March, payable in thirty days",
            100,
        )];
        let hits = search(&records, "88421").expect("valid query");
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].in_metadata, "the hit was in the text, not the title");
        assert_eq!(hits[0].match_count, 1);
        assert!(!hits[0].snippets.is_empty(), "a text hit must carry context");
    }

    #[test]
    fn a_title_or_address_hit_is_marked_as_such_and_needs_no_snippet() {
        let records = [record("a", "Quarterly report", "https://example.com/q3", "", 100)];
        let by_title = search(&records, "quarterly").expect("valid");
        assert_eq!(by_title.len(), 1);
        assert!(by_title[0].in_metadata);
        assert!(by_title[0].snippets.is_empty());

        let by_url = search(&records, "example.com").expect("valid");
        assert_eq!(by_url.len(), 1, "the address is searchable too");
    }

    #[test]
    fn matching_ignores_case_everywhere() {
        let records = [record("a", "Mixed Case Title", "https://EXAMPLE.com/", "Body TEXT here", 1)];
        for query in ["mixed case", "MIXED CASE", "text", "TEXT", "example.com"] {
            assert_eq!(search(&records, query).expect("valid").len(), 1, "{query:?}");
        }
    }

    #[test]
    fn records_that_do_not_match_are_absent_rather_than_empty_rows() {
        let records = [
            record("a", "One", "https://a.example/", "alpha beta", 1),
            record("b", "Two", "https://b.example/", "gamma delta", 2),
        ];
        let hits = search(&records, "gamma").expect("valid");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "b");
    }

    #[test]
    fn results_are_newest_first() {
        let records = [
            record("old", "Report", "https://a.example/", "shared word", 100),
            record("new", "Report", "https://b.example/", "shared word", 300),
            record("mid", "Report", "https://c.example/", "shared word", 200),
        ];
        let hits = search(&records, "shared").expect("valid");
        let ids: Vec<&str> = hits.iter().map(|hit| hit.id.as_str()).collect();
        assert_eq!(ids, ["new", "mid", "old"]);
    }

    #[test]
    fn the_query_rules_are_the_cross_tab_searchers_rules_not_new_ones() {
        let records = [record("a", "t", "https://a.example/", "body", 1)];
        // Empty and over-long queries are refused by check_query; this test
        // exists so a future divergence between the two surfaces fails here.
        assert!(search(&records, "").is_err());
        assert!(search(&records, "   ").is_err());
        let too_long: String = "x".repeat(crate::tab_search::MAX_QUERY_CHARS + 1);
        assert!(search(&records, too_long.as_str()).is_err());
    }

    #[test]
    fn a_record_with_no_read_text_still_matches_on_its_title() {
        // OCR finding nothing is a legitimate outcome, not a broken record:
        // it must stay findable by the things that are known about it.
        let records = [record("a", "Photo of a whiteboard", "https://a.example/", "", 1)];
        let hits = search(&records, "whiteboard").expect("valid");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].match_count, 0);
    }
}
