//! Find-in-page state that must behave identically on every platform,
//! including a headless test runner: what a new query should DO, and how the
//! match count is WORDED. The engines differ (WebView2 reports an active
//! match index, WebKitGTK does not), so both platform backends reduce their
//! callbacks to one `FindEvent` and everything user-visible is decided here.

/// An engine find callback, normalised. `key` identifies the content webview
/// the callback came from (platform::find_key), so the main loop can drop
/// counts belonging to a tab the user has already left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindEvent {
    pub key: usize,
    /// The session generation this count describes (find_start hands it to
    /// the platform layer). A callback quoting an older generation arrives
    /// AFTER the query changed or the session stopped; painting it would put
    /// a stale number beside new text, so state.rs drops it.
    pub generation: u64,
    /// 1-based index of the active match where the engine reports one. None
    /// on WebKitGTK, which has no such concept -- it is never invented.
    pub active: Option<u32>,
    pub total: u32,
    /// True when total reached the cap the search was started with (unix), so
    /// the UI says "1000+" rather than presenting the cap as an exact count.
    pub capped: bool,
}

/// What a query arriving over IPC should do to the engine session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindCmd<'a> {
    Start(&'a str),
    Stop,
    Ignore,
}

/// The find session of the ACTIVE tab. Sessions are per-tab and a tab switch
/// stops them (state.rs), so one instance is enough: it never has to describe
/// two tabs at once. The query lives only here and inside the engine; nothing
/// is persisted, for any tab kind.
#[derive(Debug, Default)]
pub struct FindSession {
    /// The query the engine is currently running, if a session is live.
    query: Option<String>,
    /// Bumped on every Start and every real stop. It is what makes the
    /// ASYNC engine callbacks safe to trust: each callback quotes the
    /// generation its search was started under, and a late answer from an
    /// abandoned query is dropped instead of shown beside the new one.
    generation: u64,
}

impl FindSession {
    pub fn is_active(&self) -> bool {
        self.query.is_some()
    }

    /// The generation the platform layer must quote back with its counts.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Folds an incoming query into the session and says what the platform
    /// layer should do. Empty means stop (searching "" highlights everything
    /// or nothing depending on the engine); a repeat of the live query is
    /// ignored so reopening or refocusing the bar does not restart the
    /// engine's search and re-highlight the whole page for nothing.
    pub fn on_query<'q>(&mut self, query: &'q str) -> FindCmd<'q> {
        if query.is_empty() {
            return if self.stop() { FindCmd::Stop } else { FindCmd::Ignore };
        }
        if self.query.as_deref() == Some(query) {
            return FindCmd::Ignore;
        }
        self.query = Some(query.to_string());
        self.generation = self.generation.wrapping_add(1);
        FindCmd::Start(query)
    }

    /// Ends the session. Returns whether one was live, so callers skip the
    /// platform stop when there is nothing to stop (the common case for a
    /// find_stop that arrives after a tab switch already cleaned up).
    pub fn stop(&mut self) -> bool {
        if self.query.take().is_some() {
            // A count already in flight describes the stopped session;
            // bumping here is what makes it quote a dead generation.
            self.generation = self.generation.wrapping_add(1);
            true
        } else {
            false
        }
    }
}

/// The ONE place a match count becomes user-visible text.
///
/// Two honest shapes, chosen by what the engine reported:
///   active Some -> "3 of 17"        (WebView2)
///   active None -> "17 matches"     (WebKitGTK)
/// A capped total gets a "+" on the number, so the cap is never read as an
/// exact count. An active index that contradicts the total (engine
/// inconsistency) falls back to the plain total rather than printing
/// "9 of 2".
pub fn format_count(active: Option<u32>, total: u32, capped: bool) -> String {
    if total == 0 {
        return "no matches".to_string();
    }
    let total_s = format!("{total}{}", if capped { "+" } else { "" });
    match active {
        Some(n) if n >= 1 && n <= total => format!("{n} of {total_s}"),
        _ if total == 1 => "1 match".to_string(),
        _ => format!("{total_s} matches"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_worded_per_what_the_engine_knows() {
        // WebKitGTK has no active index; None must never grow one.
        assert_eq!(format_count(None, 17, false), "17 matches");
        assert_eq!(format_count(None, 1, false), "1 match");
        assert_eq!(format_count(None, 0, false), "no matches");
        // WebView2 reports a 1-based active index.
        assert_eq!(format_count(Some(3), 17, false), "3 of 17");
        assert_eq!(format_count(Some(1), 1, false), "1 of 1");
    }

    #[test]
    fn a_cap_is_never_shown_as_an_exact_count() {
        assert_eq!(format_count(None, 1000, true), "1000+ matches");
        assert_eq!(format_count(Some(3), 1000, true), "3 of 1000+");
    }

    #[test]
    fn an_inconsistent_active_index_falls_back_to_the_plain_total() {
        assert_eq!(format_count(Some(9), 2, false), "2 matches");
        assert_eq!(format_count(Some(0), 5, false), "5 matches");
    }

    #[test]
    fn first_query_starts_and_a_repeat_is_ignored() {
        let mut s = FindSession::default();
        assert_eq!(s.on_query("rust"), FindCmd::Start("rust"));
        assert!(s.is_active());
        // Reopening the bar re-sends the query; the engine session must not
        // restart, or every highlight on the page is rebuilt for nothing.
        assert_eq!(s.on_query("rust"), FindCmd::Ignore);
        assert_eq!(s.on_query("rustc"), FindCmd::Start("rustc"));
    }

    #[test]
    fn empty_query_stops_and_never_searches() {
        let mut s = FindSession::default();
        // Empty with nothing live: no Stop, and certainly no Start("").
        assert_eq!(s.on_query(""), FindCmd::Ignore);
        s.on_query("rust");
        assert_eq!(s.on_query(""), FindCmd::Stop);
        assert!(!s.is_active());
        assert_eq!(s.on_query(""), FindCmd::Ignore);
    }

    #[test]
    fn generations_change_on_every_start_and_stop() {
        // The whole point: a callback from an abandoned query or a stopped
        // session must be distinguishable from a current one.
        let mut s = FindSession::default();
        let g0 = s.generation();
        s.on_query("rust");
        let g1 = s.generation();
        assert_ne!(g0, g1, "a new search must open a new generation");
        s.on_query("rustc");
        let g2 = s.generation();
        assert_ne!(g1, g2, "a changed query must open a new generation");
        s.stop();
        assert_ne!(g2, s.generation(), "a stop must retire the generation");
        // A repeat query and a no-op stop change nothing, so counts from the
        // live search keep flowing.
        s.on_query("go");
        let g3 = s.generation();
        assert_eq!(s.on_query("go"), FindCmd::Ignore);
        assert_eq!(g3, s.generation());
    }

    #[test]
    fn stop_reports_whether_there_was_anything_to_stop() {
        let mut s = FindSession::default();
        assert!(!s.stop());
        s.on_query("rust");
        assert!(s.stop());
        // The second stop is the one a tab switch can produce after the bar
        // already closed; it must be a quiet no-op all the way down.
        assert!(!s.stop());
    }
}
