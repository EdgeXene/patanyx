use super::*;

const PAGE: &str = "0123456789abcdef0123456789abcdef";
const TOKEN: &str = "fedcba9876543210fedcba9876543210";

fn frame(command: &str, args: Value) -> String {
    json!({"v": 1, "id": 7, "generation": "42", "command": command, "args": args, "presence": false}).to_string()
}

fn ok(command: &str, args: Value) -> Command {
    parse(&frame(command, args)).unwrap_or_else(|r| panic!("{command} refused: {r:?}")).command
}

fn refused(raw: &str) -> ProtocolError {
    parse(raw).expect_err("accepted").error
}

#[test]
fn every_listed_command_parses_with_its_minimal_arguments() {
    let cases: Vec<(&str, Value)> = vec![
        ("addon_ready", json!({"host_api": 1})),
        ("addon_presence", json!({})),
        ("addon_store_list", json!({"cursor": null, "limit": 128})),
        ("addon_store_get", json!({"id": PAGE})),
        ("addon_store_put", json!({"id": null, "base_revision": "0", "title": "t", "body_b64": "aGk=", "flush_id": null})),
        ("addon_store_delete", json!({"id": PAGE, "base_revision": "3"})),
        ("window_move", json!({"x": -20.5, "y": 40, "sequence": 1})),
        ("window_resize", json!({"width": 300, "height": 200, "sequence": 2})),
        ("window_collapse", json!({"collapsed": true})),
        ("window_close", json!({})),
        ("vault_notes_list", json!({"cursor": "c1", "limit": 1})),
        ("vault_notes_get", json!({"id": "note-1", "offset": 0, "limit": 4, "revision": null})),
        ("vault_note_edit_in_vault", json!({"id": "note-1"})),
        ("vault_premium_open", json!({})),
        ("premium_purchase_open", json!({"purchase": "patanyx"})),
        ("addon_flush_done", json!({"flush_id": TOKEN, "status": "saved"})),
        ("addon_selection_result", json!({"delivery_id": TOKEN, "status": "saved", "error": null})),
    ];
    let mut seen = Vec::new();
    for (name, args) in cases {
        let c = ok(name, args);
        assert_eq!(c.name(), name);
        seen.push(name);
    }
    // The allowlist and the parser cover the same names, no more.
    seen.sort_unstable();
    let mut listed = COMMANDS.to_vec();
    listed.sort_unstable();
    assert_eq!(seen, listed);
}

#[test]
fn chrome_commands_and_unknown_names_are_not_allowed() {
    for name in ["cred_list", "vault_status", "note_list", "note_update", "licence_status", "tab_new", "settings_set", ""] {
        assert_eq!(refused(&frame(name, json!({}))), ProtocolError::NotAllowed, "{name}");
    }
}

#[test]
fn malformed_frames_are_bad_frames() {
    for raw in [
        "not json",
        r#"{"v":2,"id":1,"generation":"1","command":"addon_presence","args":{},"presence":false}"#,
        r#"{"v":1,"id":0,"generation":"1","command":"addon_presence","args":{},"presence":false}"#,
        r#"{"v":1,"id":1,"generation":"01","command":"addon_presence","args":{},"presence":false}"#,
        r#"{"v":1,"id":1,"generation":"-1","command":"addon_presence","args":{},"presence":false}"#,
        r#"{"v":1,"id":1,"generation":"1","command":"addon_presence","args":{},"presence":false,"extra":1}"#,
        r#"{"v":1,"id":1,"generation":"1","command":"addon_presence","args":{}}"#,
    ] {
        assert_eq!(refused(raw), ProtocolError::BadFrame, "{raw}");
    }
}

#[test]
fn a_frame_over_the_limit_is_refused_before_parsing() {
    let raw = format!(r#"{{"pad":"{}"}}"#, "a".repeat(MAX_FRAME_BYTES));
    assert_eq!(refused(&raw), ProtocolError::FrameTooLarge);
}

#[test]
fn bad_arguments_are_refused_per_command() {
    let cases: Vec<(&str, Value)> = vec![
        ("addon_ready", json!({})),
        ("addon_presence", json!({"x": 1})),
        ("addon_store_list", json!({"cursor": null, "limit": 0})),
        ("addon_store_list", json!({"cursor": null, "limit": 129})),
        ("addon_store_list", json!({"cursor": "", "limit": 5})),
        ("addon_store_get", json!({"id": "ABC"})),
        ("addon_store_get", json!({"id": PAGE.to_uppercase()})),
        // A create with an id, an update without one, a stale shape:
        ("addon_store_put", json!({"id": PAGE, "base_revision": "0", "title": "t", "body_b64": "", "flush_id": null})),
        ("addon_store_put", json!({"id": null, "base_revision": "2", "title": "t", "body_b64": "", "flush_id": null})),
        ("addon_store_put", json!({"id": null, "base_revision": "00", "title": "t", "body_b64": "", "flush_id": null})),
        ("addon_store_put", json!({"id": null, "base_revision": "0", "title": "x".repeat(201), "body_b64": "", "flush_id": null})),
        ("addon_store_put", json!({"id": null, "base_revision": "0", "title": "t", "body_b64": "aGk", "flush_id": null})),
        ("addon_store_put", json!({"id": null, "base_revision": "0", "title": "t", "body_b64": "aG k=", "flush_id": null})),
        ("addon_store_put", json!({"id": null, "base_revision": "0", "title": "t", "body_b64": "/w==", "flush_id": null})),
        ("addon_store_put", json!({"id": null, "base_revision": "0", "title": "t", "body_b64": "", "flush_id": "nope"})),
        ("addon_store_delete", json!({"id": PAGE, "base_revision": "0"})),
        ("window_move", json!({"x": 1, "y": 2})),
        ("window_resize", json!({"width": 0, "height": 2, "sequence": 1})),
        ("window_resize", json!({"width": -5, "height": 2, "sequence": 1})),
        ("vault_notes_get", json!({"id": "n", "offset": 0, "limit": 3, "revision": null})),
        ("vault_notes_get", json!({"id": "../n", "offset": 0, "limit": 4, "revision": null})),
        ("vault_notes_get", json!({"id": "n", "offset": 0, "limit": 4, "revision": "x"})),
        ("vault_note_edit_in_vault", json!({"id": "a b"})),
        ("premium_purchase_open", json!({"purchase": "other"})),
        ("premium_purchase_open", json!({"purchase": "patanyx", "url": "https://example.com/"})),
        ("addon_flush_done", json!({"flush_id": TOKEN, "status": "maybe"})),
        ("addon_selection_result", json!({"delivery_id": TOKEN, "status": "saved", "error": "save_failed"})),
        ("addon_selection_result", json!({"delivery_id": TOKEN, "status": "refused", "error": null})),
        ("addon_selection_result", json!({"delivery_id": TOKEN, "status": "refused", "error": "other"})),
    ];
    for (name, args) in cases {
        let raw = frame(name, args.clone());
        assert_eq!(refused(&raw), ProtocolError::BadArgs, "{name} {args}");
    }
}

#[test]
fn non_finite_coordinates_never_parse() {
    // JSON has no NaN or Infinity literals; serde refuses them as bad args.
    let raw = r#"{"v":1,"id":1,"generation":"1","command":"window_move","args":{"x":NaN,"y":1,"sequence":1},"presence":true}"#;
    assert!(parse(raw).is_err());
    let raw = r#"{"v":1,"id":1,"generation":"1","command":"window_move","args":{"x":1e999,"y":1,"sequence":1},"presence":true}"#;
    assert!(parse(raw).is_err());
}

#[test]
fn the_largest_page_round_trips_and_one_byte_more_is_refused() {
    let body: Vec<u8> = "é".repeat(MAX_PAGE_BYTES / 2).into_bytes();
    assert_eq!(body.len(), MAX_PAGE_BYTES);
    let b64 = encode_body(&body);
    assert!(b64.len() <= MAX_BODY_B64);
    let c = ok("addon_store_put", json!({"id": null, "base_revision": "0", "title": "t", "body_b64": b64, "flush_id": null}));
    let Command::StorePut { body: decoded, .. } = c else { panic!("not a put") };
    assert_eq!(decoded.as_slice(), body.as_slice());
    let mut over = body;
    over.push(b'a');
    assert!(decode_body(&encode_body(&over)).is_none());
    // The whole frame with the largest body stays under the frame limit.
    let raw = frame("addon_store_put", json!({"id": null, "base_revision": "0", "title": "x".repeat(200), "body_b64": encode_body(&"\\\"".repeat(MAX_PAGE_BYTES / 2).into_bytes()), "flush_id": TOKEN}));
    assert!(raw.len() < MAX_FRAME_BYTES, "{}", raw.len());
}

#[test]
fn base64_round_trips_every_tail_length() {
    for n in 0..10usize {
        let bytes: Vec<u8> = (0..n as u8).map(|b| b'a' + b).collect();
        let s = encode_body(&bytes);
        assert_eq!(s.len() % 4, 0);
        assert_eq!(decode_body(&s).as_deref().map(Vec::as_slice), Some(bytes.as_slice()));
    }
}

#[test]
fn a_rejection_keeps_the_id_and_claimed_generation_for_the_reply() {
    let r = parse(&frame("cred_list", json!({}))).unwrap_err();
    assert_eq!((r.id, r.generation), (Some(7), Some(42)));
}

#[test]
fn replies_and_events_carry_the_generation_as_a_string() {
    let s: Value = serde_json::from_str(&success(3, 9, json!({"a": 1}))).unwrap();
    assert_eq!(s["generation"], "9");
    assert_eq!(s["ok"], true);
    let f: Value = serde_json::from_str(&failure(None, 9, "bad_frame")).unwrap();
    assert_eq!(f["id"], Value::Null);
    let e: Value = serde_json::from_str(&event(9, "addon_mode_changed", json!({"mode": "full"})).unwrap()).unwrap();
    assert_eq!(e["event"], "addon_mode_changed");
    // An oversized reply degrades to a refusal rather than an oversized frame.
    let big = success(3, 9, json!({"x": "a".repeat(MAX_FRAME_BYTES)}));
    assert!(big.contains("frame_too_large"));
    assert!(event(9, "e", json!({"x": "a".repeat(MAX_FRAME_BYTES)})).is_none());
}

#[test]
fn a_put_keeps_sets_or_clears_the_site_and_refuses_a_malformed_one() {
    let base = || json!({"id": null, "base_revision": "0", "title": "t", "body_b64": "", "flush_id": null});
    let site_of = |args: Value| match ok("addon_store_put", args) {
        Command::StorePut { site, .. } => site,
        _ => panic!("not a put"),
    };
    assert_eq!(site_of(base()), patanyx_store::SiteChange::Keep);
    let mut set = base();
    set["site"] = json!("example.com");
    assert_eq!(site_of(set), patanyx_store::SiteChange::Set("example.com".into()));
    let mut clear = base();
    clear["site"] = Value::Null;
    assert_eq!(site_of(clear), patanyx_store::SiteChange::Clear);
    for bad in [json!("Example.com"), json!("https://example.com"), json!("com"), json!(7)] {
        let mut args = base();
        args["site"] = bad;
        assert!(parse(&frame("addon_store_put", args)).is_err());
    }
}

#[test]
fn the_final_flush_carries_the_site_like_any_put() {
    let args = json!({"id": PAGE, "base_revision": "4", "title": "t", "body_b64": "", "flush_id": TOKEN, "site": "example.com"});
    let Command::StorePut { flush_id, site, .. } = ok("addon_store_put", args) else { panic!("not a put") };
    assert_eq!(flush_id.as_deref(), Some(TOKEN));
    assert_eq!(site, patanyx_store::SiteChange::Set("example.com".into()));
}

/// A collection rides only on a create, well formed (host-api-1-notebook.md).
#[test]
fn a_collection_is_accepted_only_on_a_create() {
    let create = json!({"id": null, "base_revision": "0", "title": "Note", "body_b64": "", "flush_id": null, "collection": "assistant"});
    let Command::StorePut { collection, id, .. } = ok("addon_store_put", create) else { panic!("not a put") };
    assert_eq!((collection.as_deref(), id.is_none()), (Some("assistant"), true));
    let plain = json!({"id": null, "base_revision": "0", "title": "Note", "body_b64": "", "flush_id": null});
    let Command::StorePut { collection, .. } = ok("addon_store_put", plain) else { panic!("not a put") };
    assert_eq!(collection, None);
    let update = json!({"id": PAGE, "base_revision": "4", "title": "t", "body_b64": "", "flush_id": null, "collection": "assistant"});
    assert!(parse(&frame("addon_store_put", update)).is_err(), "an update cannot carry a collection");
    for bad in [json!("Assistant"), json!(""), json!("a b"), json!(7), json!("x".repeat(33))] {
        let args = json!({"id": null, "base_revision": "0", "title": "t", "body_b64": "", "flush_id": null, "collection": bad});
        assert!(parse(&frame("addon_store_put", args)).is_err());
    }
}
