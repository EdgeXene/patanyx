//! The browser half of the WebSocket guard's channel (1.1.2).
//!
//! WHY. WebView2 never shows a WebSocket handshake to the request filter, so
//! before 1.1.2 a page could open a socket to a listed tracker (measured
//! 2026-11-14 on the 1.1.1 release build: an image and a fetch to the host
//! were blocked, the socket's upgrade reached the server). The page-world
//! guard (content_scripts/local_network_guard.js) now asks here before every
//! socket the private-address rule did not refuse, and waits for the answer.
//!
//! This module is the whole protocol on the browser side, kept free of COM so
//! `cargo test` can prove it on a box with no WebView2. The Windows backend
//! only carries messages in and replies out, per frame.
//!
//! WHO MAY ASK. Each webview gets a random 128-bit TOKEN, written into the
//! guard's text before the browser registers it. Page code cannot read an
//! injected script's text or the guard's closure, so a message without the
//! token is not the guard's and is dropped BEFORE any decision or side
//! effect. Each document's guard draws a GENERATION and says hello; a
//! generation belongs to the frame that announced it, and a check from any
//! other frame under that generation is dropped.
//!
//! WHAT IT ANSWERS. The malicious-site list first, then
//! `TabState::decide_websocket_check` (the local-network boundary, freeze and
//! the ad and tracker rules). An Allow is held as PENDING until the guard
//! acknowledges it, so Page Connections can say what happened rather than what
//! was decided: `constructed` keeps the allow; `timed-out` or `failed` turns it
//! into a block; `cancelled` takes it back (nothing was contacted). An Allow
//! the guard never consumed within ACK_DEADLINE is turned into a block too.
//!
//! WHAT IT DOES NOT SEE. Sockets opened inside workers, which no page script
//! reaches. That limit is the guard's and is unchanged in 1.1.2.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::platform::privacy::{host_of, RequestDecision, RuleSet, TabState};

/// The placeholder the guard script carries, replaced exactly once.
pub const TOKEN_PLACEHOLDER: &str = "__PATANYX_WS_TOKEN__";

/// Checks a single document may ask per RATE_WINDOW before the rest are
/// refused without a decision. It bounds the work a page can cause on the
/// browser's thread, not how many sockets a page may use: well above what a
/// page opens in ordinary use (a burst of feeds at load, a reconnect loop),
/// so it should only ever refuse a page that is flooding the channel.
pub const RATE_LIMIT: u32 = 100;
pub const RATE_WINDOW: Duration = Duration::from_secs(1);
/// How long an Allow may wait for the guard's acknowledgement.
pub const ACK_DEADLINE: Duration = Duration::from_secs(10);
/// Generations remembered per webview; the oldest is forgotten first.
pub const MAX_GENERATIONS: usize = 64;
/// Unacknowledged allows held per generation.
pub const MAX_PENDING: usize = 256;
const MAX_URL: usize = 8192;

struct Pending {
    host: String,
    at: Instant,
}

struct Generation {
    frame: u64,
    born: Instant,
    window_start: Instant,
    window_count: u32,
    pending: HashMap<String, Pending>,
    /// Allows the sweep turned into blocks, most recent last (at most
    /// MAX_SWEPT): a late "constructed" for one of them moves the count back.
    swept: std::collections::VecDeque<(String, String)>,
}

/// Allows remembered per generation after the sweep blocked them.
pub const MAX_SWEPT: usize = 64;

/// One webview's side of the channel.
pub struct WsGuard {
    token: String,
    generations: HashMap<String, Generation>,
    /// Internal health (R-119): never shown as UI wording, never carries a
    /// host or URL.
    health: GuardHealth,
}

/// How the channel is doing, for the diagnostic log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardHealth {
    /// Registered with a token; no document has said hello yet.
    Registered,
    /// At least one document's guard has been answered.
    Answering,
    /// A reply could not be posted to a page.
    ReplyFailed,
}

/// What the Windows side was asked to record in its diagnostic log. Never a
/// host or URL: the export of that log must stay free of browsing history.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not the guard's message (no or wrong token, unknown generation,
    /// another frame's generation, malformed). Nothing was done.
    Dropped,
    /// A reply to post back to the sending frame.
    Reply(String),
    /// Accepted; nothing to send back (an acknowledgement).
    Accepted,
}

impl WsGuard {
    /// A fresh token from the OS generator, or None when there is none: the
    /// guard is then registered WITHOUT a token and runs as before 1.1.2.
    pub fn new() -> Option<WsGuard> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).ok()?;
        Some(WsGuard::with_token(hex(&bytes)))
    }

    pub fn with_token(token: String) -> WsGuard {
        WsGuard {
            token,
            generations: HashMap::new(),
            health: GuardHealth::Registered,
        }
    }

    /// The guard's source with this webview's token written in. Refuses a
    /// template that does not carry the placeholder exactly once.
    pub fn script(&self, template: &str) -> Option<String> {
        if template.matches(TOKEN_PLACEHOLDER).count() != 1 {
            return None;
        }
        Some(template.replacen(TOKEN_PLACEHOLDER, &self.token, 1))
    }

    pub fn health(&self) -> GuardHealth {
        self.health
    }

    /// The engine refused to post a reply.
    pub fn note_reply_failed(&mut self) {
        self.health = GuardHealth::ReplyFailed;
    }

    /// Forgets every generation a frame announced (the frame is gone).
    pub fn frame_gone(&mut self, frame: u64) {
        self.generations.retain(|_, g| g.frame != frame);
    }

    /// Handles one message from `frame`.
    #[allow(clippy::too_many_arguments)]
    pub fn handle(
        &mut self,
        frame: u64,
        msg: &serde_json::Value,
        tab: &mut TabState,
        rules: &RuleSet,
        now: Instant,
        override_host: Option<&str>,
        malicious: &dyn Fn(&str) -> bool,
    ) -> Outcome {
        self.sweep(tab, now);
        let field = |key: &str| msg.get(key).and_then(|v| v.as_str());
        if field("k") != Some("pws") {
            return Outcome::Dropped;
        }
        // Before anything else, and before any side effect.
        match field("t") {
            Some(t) if same(t, &self.token) => {}
            _ => return Outcome::Dropped,
        }
        let Some(generation) = field("g").filter(|g| is_generation(g)) else {
            return Outcome::Dropped;
        };
        match field("op") {
            Some("hello") => {
                let Some(nonce) = field("n").filter(|n| is_generation(n)) else {
                    return Outcome::Dropped;
                };
                self.hello(frame, generation, nonce, now)
            }
            Some("check") => {
                let (Some(id), Some(url), Some(nonce)) = (field("id"), field("url"), field("n")) else {
                    return Outcome::Dropped;
                };
                if !is_check_id(id) || url.len() > MAX_URL || !is_generation(nonce) {
                    return Outcome::Dropped;
                }
                self.check(frame, generation, id, url, nonce, tab, rules, now, override_host, malicious)
            }
            Some("ack") => {
                let (Some(id), Some(outcome)) = (field("id"), field("outcome")) else {
                    return Outcome::Dropped;
                };
                self.ack(frame, generation, id, outcome, tab)
            }
            _ => Outcome::Dropped,
        }
    }

    fn hello(&mut self, frame: u64, generation: &str, nonce: &str, now: Instant) -> Outcome {
        match self.generations.get(generation) {
            Some(g) if g.frame != frame => return Outcome::Dropped,
            Some(_) => {}
            None => {
                if self.generations.len() >= MAX_GENERATIONS {
                    if let Some(oldest) = self
                        .generations
                        .iter()
                        .min_by_key(|(_, g)| g.born)
                        .map(|(k, _)| k.clone())
                    {
                        self.generations.remove(&oldest);
                    }
                }
                self.generations.insert(
                    generation.to_string(),
                    Generation {
                        frame,
                        born: now,
                        window_start: now,
                        window_count: 0,
                        pending: HashMap::new(),
                        swept: std::collections::VecDeque::new(),
                    },
                );
            }
        }
        if self.health == GuardHealth::Registered {
            self.health = GuardHealth::Answering;
        }
        Outcome::Reply(reply(generation, "ready", None, None, nonce))
    }

    #[allow(clippy::too_many_arguments)]
    fn check(
        &mut self,
        frame: u64,
        generation: &str,
        id: &str,
        url: &str,
        nonce: &str,
        tab: &mut TabState,
        rules: &RuleSet,
        now: Instant,
        override_host: Option<&str>,
        malicious: &dyn Fn(&str) -> bool,
    ) -> Outcome {
        let Some(g) = self.generations.get_mut(generation) else {
            return Outcome::Dropped;
        };
        if g.frame != frame {
            return Outcome::Dropped;
        }
        let host = host_of(url);
        if now.duration_since(g.window_start) >= RATE_WINDOW {
            g.window_start = now;
            g.window_count = 0;
        }
        g.window_count += 1;
        if g.window_count > RATE_LIMIT || g.pending.len() >= MAX_PENDING {
            // Refused without a policy decision, but still ledgered once:
            // a page cannot hide a socket by asking too often.
            if let Some(host) = &host {
                tab.ledger.record(host, true);
            }
            return Outcome::Reply(reply(generation, "verdict", Some(id), Some(false), nonce));
        }
        if let Some(host) = host.as_deref().filter(|h| malicious(h)) {
            tab.ledger.record(host, true);
            return Outcome::Reply(reply(generation, "verdict", Some(id), Some(false), nonce));
        }
        let allow = tab.decide_websocket_check(url, rules, now, override_host) == RequestDecision::Allow;
        if allow {
            if let Some(host) = host {
                g.pending.insert(id.to_string(), Pending { host, at: now });
            }
        }
        Outcome::Reply(reply(generation, "verdict", Some(id), Some(allow), nonce))
    }

    fn ack(&mut self, frame: u64, generation: &str, id: &str, outcome: &str, tab: &mut TabState) -> Outcome {
        let Some(g) = self.generations.get_mut(generation) else {
            return Outcome::Dropped;
        };
        if g.frame != frame {
            return Outcome::Dropped;
        }
        let Some(pending) = g.pending.remove(id) else {
            // A "constructed" that arrived after the sweep blocked this
            // allow: the socket did open, so the row goes back to allowed.
            if outcome == "constructed" {
                if let Some(i) = g.swept.iter().position(|(sid, _)| sid == id) {
                    if let Some((_, host)) = g.swept.remove(i) {
                        tab.ledger.correct_block_to_allowed(&host);
                        return Outcome::Accepted;
                    }
                }
            }
            return Outcome::Dropped; // a refusal, or already settled
        };
        match outcome {
            "constructed" => {}
            "cancelled" => tab.ledger.retract_allowed(&pending.host),
            // timed-out, failed, or a value this version does not know: the
            // socket was not opened on this verdict.
            _ => tab.ledger.correct_allowed_to_blocked(&pending.host),
        }
        Outcome::Accepted
    }

    /// An Allow the guard never acknowledged within ACK_DEADLINE: it never
    /// opened on that verdict, so the row says blocked.
    fn sweep(&mut self, tab: &mut TabState, now: Instant) {
        for g in self.generations.values_mut() {
            let late: Vec<String> = g
                .pending
                .iter()
                .filter(|(_, p)| now.duration_since(p.at) >= ACK_DEADLINE)
                .map(|(k, _)| k.clone())
                .collect();
            for id in late {
                if let Some(p) = g.pending.remove(&id) {
                    tab.ledger.correct_allowed_to_blocked(&p.host);
                    if g.swept.len() >= MAX_SWEPT {
                        g.swept.pop_front();
                    }
                    g.swept.push_back((id, p.host));
                }
            }
        }
    }
}

/// Every reply echoes the nonce the guard sent with its request, and the
/// guard accepts no reply without it: WebView2 hands these messages to page
/// script as untrusted events that a page could imitate.
fn reply(generation: &str, op: &str, id: Option<&str>, allow: Option<bool>, nonce: &str) -> String {
    let mut m = serde_json::Map::new();
    m.insert("k".into(), "pws".into());
    m.insert("g".into(), generation.into());
    m.insert("op".into(), op.into());
    m.insert("n".into(), nonce.into());
    if let Some(id) = id {
        m.insert("id".into(), id.into());
    }
    if let Some(allow) = allow {
        m.insert("allow".into(), allow.into());
    }
    serde_json::Value::Object(m).to_string()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

fn is_generation(g: &str) -> bool {
    g.len() == 32 && g.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_check_id(id: &str) -> bool {
    id.len() >= 2 && id.len() <= 16 && id.starts_with('c') && id[1..].bytes().all(|b| b.is_ascii_digit())
}

/// Token comparison that does not stop at the first difference.
fn same(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::privacy::{TabPolicy, TabState};
    use serde_json::json;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const GEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn tab() -> TabState {
        TabState::new(&TabPolicy {
            block_ads: true,
            ..TabPolicy::default()
        })
    }
    fn rules() -> RuleSet {
        RuleSet::from_lines("tracker.example\n")
    }
    fn none(_: &str) -> bool {
        false
    }
    fn msg(op: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut m = json!({ "k": "pws", "t": TOKEN, "g": GEN, "op": op, "n": NONCE });
        if let (Some(m), Some(e)) = (m.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                m.insert(k.clone(), v.clone());
            }
        }
        m
    }
    fn row(t: &TabState, host: &str) -> Option<(u64, u64)> {
        t.ledger.snapshot().into_iter().find(|r| r.host == host).map(|r| (r.allowed, r.blocked))
    }
    fn verdict(o: &Outcome) -> Option<bool> {
        match o {
            Outcome::Reply(s) => serde_json::from_str::<serde_json::Value>(s).ok()?.get("allow")?.as_bool(),
            _ => None,
        }
    }

    #[test]
    fn the_script_gets_the_token_exactly_once() {
        let g = WsGuard::with_token(TOKEN.into());
        let s = g.script("var TOKEN = \"__PATANYX_WS_TOKEN__\";").unwrap();
        assert_eq!(s, format!("var TOKEN = \"{TOKEN}\";"));
        assert!(g.script("no placeholder").is_none());
        assert!(g.script("__PATANYX_WS_TOKEN__ __PATANYX_WS_TOKEN__").is_none());
        let fresh = WsGuard::new().expect("the OS generator is there on a test box");
        assert!(is_generation(&fresh.token), "a fresh token is 32 lowercase hex");
    }

    #[test]
    fn the_shipped_guard_carries_the_placeholder_once() {
        let src = include_str!("content_scripts/local_network_guard.js");
        assert_eq!(src.matches(TOKEN_PLACEHOLDER).count(), 1);
    }

    #[test]
    fn a_message_without_the_token_does_nothing() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let now = Instant::now();
        let mut bad = msg("hello", json!({}));
        bad["t"] = json!("ffffffffffffffffffffffffffffffff");
        assert_eq!(g.handle(1, &bad, &mut t, &rules(), now, None, &none), Outcome::Dropped);
        let mut check = msg("check", json!({ "id": "c0", "url": "wss://tracker.example/" }));
        check["t"] = json!("ffffffffffffffffffffffffffffffff");
        assert_eq!(g.handle(1, &check, &mut t, &rules(), now, None, &none), Outcome::Dropped);
        assert!(t.ledger.snapshot().is_empty(), "nothing ledgered for an untokened check");
    }

    #[test]
    fn hello_then_check_blocks_a_tracker_and_allows_the_rest() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let now = Instant::now();
        assert!(matches!(g.handle(1, &msg("hello", json!({})), &mut t, &rules(), now, None, &none), Outcome::Reply(_)));
        let o = g.handle(1, &msg("check", json!({ "id": "c0", "url": "wss://tracker.example/s" })), &mut t, &rules(), now, None, &none);
        assert_eq!(verdict(&o), Some(false));
        assert_eq!(row(&t, "tracker.example"), Some((0, 1)));
        let o = g.handle(1, &msg("check", json!({ "id": "c1", "url": "wss://chat.example/s" })), &mut t, &rules(), now, None, &none);
        assert_eq!(verdict(&o), Some(true));
        assert_eq!(row(&t, "chat.example"), Some((1, 0)));
    }

    #[test]
    fn replies_echo_the_request_nonce_and_a_request_without_one_is_dropped() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let now = Instant::now();
        let nonce_of = |o: &Outcome| match o {
            Outcome::Reply(s) => serde_json::from_str::<serde_json::Value>(s).ok().and_then(|v| v.get("n")?.as_str().map(String::from)),
            _ => None,
        };
        let mut bare = msg("hello", json!({}));
        bare.as_object_mut().unwrap().remove("n");
        assert_eq!(g.handle(1, &bare, &mut t, &rules(), now, None, &none), Outcome::Dropped, "hello without a nonce");
        let o = g.handle(1, &msg("hello", json!({})), &mut t, &rules(), now, None, &none);
        assert_eq!(nonce_of(&o).as_deref(), Some(NONCE));
        let mut bare = msg("check", json!({ "id": "c0", "url": "wss://chat.example/" }));
        bare.as_object_mut().unwrap().remove("n");
        assert_eq!(g.handle(1, &bare, &mut t, &rules(), now, None, &none), Outcome::Dropped, "check without a nonce");
        let mut short = msg("check", json!({ "id": "c0", "url": "wss://chat.example/" }));
        short["n"] = json!("bbbb");
        assert_eq!(g.handle(1, &short, &mut t, &rules(), now, None, &none), Outcome::Dropped, "malformed nonce");
        assert!(t.ledger.snapshot().is_empty(), "nothing ledgered for a dropped check");
        let mut other = msg("check", json!({ "id": "c1", "url": "wss://tracker.example/" }));
        other["n"] = json!("cccccccccccccccccccccccccccccccc");
        let o = g.handle(1, &other, &mut t, &rules(), now, None, &none);
        assert_eq!(nonce_of(&o).as_deref(), Some("cccccccccccccccccccccccccccccccc"), "a refusal echoes too");
        assert_eq!(verdict(&o), Some(false));
    }

    #[test]
    fn a_check_needs_its_own_frames_hello() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let now = Instant::now();
        let check = msg("check", json!({ "id": "c0", "url": "wss://chat.example/" }));
        assert_eq!(g.handle(1, &check, &mut t, &rules(), now, None, &none), Outcome::Dropped, "no hello yet");
        g.handle(1, &msg("hello", json!({})), &mut t, &rules(), now, None, &none);
        assert_eq!(g.handle(2, &check, &mut t, &rules(), now, None, &none), Outcome::Dropped, "another frame");
        assert_eq!(g.handle(2, &msg("hello", json!({})), &mut t, &rules(), now, None, &none), Outcome::Dropped,
                   "another frame cannot take over a generation");
        g.frame_gone(1);
        assert_eq!(g.handle(1, &check, &mut t, &rules(), now, None, &none), Outcome::Dropped, "a gone frame's generation is forgotten");
    }

    #[test]
    fn the_malicious_list_answers_first() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let now = Instant::now();
        g.handle(1, &msg("hello", json!({})), &mut t, &rules(), now, None, &none);
        let bad = |h: &str| h == "evil.example";
        let o = g.handle(1, &msg("check", json!({ "id": "c0", "url": "wss://evil.example/" })), &mut t, &rules(), now, None, &bad);
        assert_eq!(verdict(&o), Some(false));
        assert_eq!(row(&t, "evil.example"), Some((0, 1)));
    }

    #[test]
    fn acks_keep_page_connections_truthful() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let now = Instant::now();
        g.handle(1, &msg("hello", json!({})), &mut t, &rules(), now, None, &none);
        for (id, host) in [("c0", "a.example"), ("c1", "b.example"), ("c2", "c.example")] {
            g.handle(1, &msg("check", json!({ "id": id, "url": format!("wss://{host}/") })), &mut t, &rules(), now, None, &none);
        }
        assert_eq!(g.handle(1, &msg("ack", json!({ "id": "c0", "outcome": "constructed" })), &mut t, &rules(), now, None, &none), Outcome::Accepted);
        g.handle(1, &msg("ack", json!({ "id": "c1", "outcome": "timed-out" })), &mut t, &rules(), now, None, &none);
        g.handle(1, &msg("ack", json!({ "id": "c2", "outcome": "cancelled" })), &mut t, &rules(), now, None, &none);
        assert_eq!(row(&t, "a.example"), Some((1, 0)), "constructed stays allowed");
        assert_eq!(row(&t, "b.example"), Some((0, 1)), "timed-out becomes blocked");
        assert_eq!(row(&t, "c.example"), None, "cancelled is taken back: nothing was contacted");
        assert_eq!(g.handle(1, &msg("ack", json!({ "id": "c0", "outcome": "timed-out" })), &mut t, &rules(), now, None, &none), Outcome::Dropped,
                   "a settled check cannot be settled again");
    }

    #[test]
    fn an_allow_never_acknowledged_becomes_a_block() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let t0 = Instant::now();
        g.handle(1, &msg("hello", json!({})), &mut t, &rules(), t0, None, &none);
        g.handle(1, &msg("check", json!({ "id": "c0", "url": "wss://slow.example/" })), &mut t, &rules(), t0, None, &none);
        g.handle(1, &msg("hello", json!({})), &mut t, &rules(), t0 + ACK_DEADLINE, None, &none);
        assert_eq!(row(&t, "slow.example"), Some((0, 1)));
    }

    #[test]
    fn a_late_constructed_after_the_sweep_moves_the_count_back() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let t0 = Instant::now();
        g.handle(1, &msg("hello", json!({})), &mut t, &rules(), t0, None, &none);
        g.handle(1, &msg("check", json!({ "id": "c0", "url": "wss://slow.example/" })), &mut t, &rules(), t0, None, &none);
        let late = t0 + ACK_DEADLINE;
        let o = g.handle(1, &msg("ack", json!({ "id": "c0", "outcome": "constructed" })), &mut t, &rules(), late, None, &none);
        assert_eq!(o, Outcome::Accepted);
        assert_eq!(row(&t, "slow.example"), Some((1, 0)), "the socket opened, so the row says allowed");
        let again = g.handle(1, &msg("ack", json!({ "id": "c0", "outcome": "constructed" })), &mut t, &rules(), late, None, &none);
        assert_eq!(again, Outcome::Dropped, "only once");
    }

    #[test]
    fn asking_too_often_is_refused_and_still_ledgered() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let now = Instant::now();
        g.handle(1, &msg("hello", json!({})), &mut t, &rules(), now, None, &none);
        let mut last = None;
        for i in 0..(RATE_LIMIT + 1) {
            let o = g.handle(1, &msg("check", json!({ "id": format!("c{i}"), "url": "wss://chat.example/" })), &mut t, &rules(), now, None, &none);
            last = verdict(&o);
        }
        assert_eq!(last, Some(false), "the check past the limit is refused");
        assert_eq!(row(&t, "chat.example"), Some((RATE_LIMIT as u64, 1)), "and ledgered as blocked");
        let later = now + RATE_WINDOW;
        // The next id the guard would use: ids only ever increase.
        let next = format!("c{}", RATE_LIMIT + 1);
        let o = g.handle(1, &msg("check", json!({ "id": next, "url": "wss://chat.example/" })), &mut t, &rules(), later, None, &none);
        assert_eq!(verdict(&o), Some(true), "a new window allows again");
        assert_eq!(row(&t, "chat.example"), Some((RATE_LIMIT as u64 + 1, 1)), "and that allow is counted once");
    }

    #[test]
    fn malformed_messages_are_dropped() {
        let mut g = WsGuard::with_token(TOKEN.into());
        let mut t = tab();
        let now = Instant::now();
        g.handle(1, &msg("hello", json!({})), &mut t, &rules(), now, None, &none);
        for bad in [
            msg("check", json!({ "id": "x0", "url": "wss://a.example/" })),
            msg("check", json!({ "id": "c0" })),
            msg("check", json!({ "id": "c0", "url": "x".repeat(MAX_URL + 1) })),
            msg("nonsense", json!({})),
            json!({ "k": "other" }),
        ] {
            assert_eq!(g.handle(1, &bad, &mut t, &rules(), now, None, &none), Outcome::Dropped, "{bad}");
        }
        let mut short_gen = msg("hello", json!({}));
        short_gen["g"] = json!("abc");
        assert_eq!(g.handle(1, &short_gen, &mut t, &rules(), now, None, &none), Outcome::Dropped);
    }
}
