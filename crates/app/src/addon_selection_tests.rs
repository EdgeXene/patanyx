use super::*;

fn receiver_info() -> ReceiverInfo {
    ReceiverInfo {
        id: "test-receiver".into(),
        name: "Test receiver".into(),
    }
}

fn fixture(text: &str) -> (SelectionState, SharedCapture, SelectionSource) {
    let state = SelectionState {
        fake_receiver: Some(receiver_info()),
        ..Default::default()
    };
    let capture = Capture::new(7);
    let source = capture
        .borrow_mut()
        .begin(&state.receiver().unwrap())
        .unwrap();
    assert!(capture.borrow_mut().accept(&source.request_id, text.into()));
    (state, capture, source)
}

fn send(
    state: &mut SelectionState,
    capture: &SharedCapture,
    source: SelectionSource,
    text: &str,
) -> Result<(), SendError> {
    let active = capture.borrow().identity;
    state.deliver(
        &mut capture.borrow_mut(),
        active,
        state.receiver(),
        text.into(),
        source,
    )
}

#[test]
fn one_use_binding() {
    let (mut state, capture, source) = fixture("selected λ 🦀");
    assert_eq!(
        send(&mut state, &capture, source.clone(), "selected λ 🦀"),
        Ok(())
    );
    assert_eq!(state.sink, vec![("selected λ 🦀".into(), source.clone())]);
    assert_eq!(
        send(&mut state, &capture, source, "selected λ 🦀"),
        Err(SendError::Stale)
    );
    assert_eq!(state.sink.len(), 1, "one-use boundary");
}

#[test]
fn source_identity() {
    // Each native identity component is enforced, including a replaced
    // webview with the same tab id and a different invocation in one page.
    for part in ["tab", "webview", "document", "request"] {
        let (mut state, capture, mut source) = fixture("selection");
        match part {
            "tab" => source.tab_id += 1,
            "webview" => source.webview_id += 1,
            "document" => source.document_generation += 1,
            "request" => source.request_id = "0".repeat(32),
            _ => unreachable!(),
        }
        assert_eq!(
            send(&mut state, &capture, source, "selection"),
            Err(SendError::Stale),
            "source boundary: {part}"
        );
        assert!(state.sink.is_empty());
    }
    let (mut state, capture, source) = fixture("selection");
    assert_eq!(send(&mut state, &capture, source, "selection"), Ok(()));
}

#[test]
fn capture_binding_and_duplicate_response() {
    let capture = Capture::new(1);
    let a = capture.borrow_mut().begin(&receiver_info()).unwrap();
    let b = capture.borrow_mut().begin(&receiver_info()).unwrap();
    assert_ne!(a.request_id, b.request_id);
    assert!(!capture.borrow_mut().accept(&a.request_id, "old".into()));
    assert!(capture.borrow_mut().accept(&b.request_id, "new".into()));
    assert!(!capture
        .borrow_mut()
        .accept(&b.request_id, "replacement".into()));
    assert_eq!(capture.borrow().text(&b).as_deref(), Some("new"));
    assert_eq!(capture.borrow().text(&a), None);
}

#[test]
fn validator_refusals_and_utf8_limit() {
    for (text, result) in [
        (String::new(), Err(SendError::Empty)),
        (
            "x".repeat(MAX_SELECTION_BYTES + 1),
            Err(SendError::TooLarge),
        ),
        (
            "🦀".repeat(MAX_SELECTION_BYTES / 4 + 1),
            Err(SendError::TooLarge),
        ),
        ("🦀".repeat(MAX_SELECTION_BYTES / 4), Ok(())),
        ("x".repeat(MAX_SELECTION_BYTES), Ok(())),
        (" \n\t".into(), Ok(())),
    ] {
        assert_eq!(validate_text(&text), result);
        let capture = Capture::new(1);
        let source = capture.borrow_mut().begin(&receiver_info()).unwrap();
        assert_eq!(
            capture
                .borrow_mut()
                .accept(&source.request_id, text.clone()),
            result.is_ok()
        );
        if result.is_ok() {
            let mut state = SelectionState {
                fake_receiver: Some(receiver_info()),
                ..Default::default()
            };
            assert_eq!(send(&mut state, &capture, source, &text), Ok(()));
            assert_eq!(state.sink.len(), 1);
        }
    }
}

#[test]
fn empty_failed_or_late_capture_never_reuses_text() {
    for failure in ["empty", "oversize", "missing", "late"] {
        let (mut state, capture, old) = fixture("previous selection");
        let source = capture.borrow_mut().begin(&receiver_info()).unwrap();
        match failure {
            "empty" => {
                assert!(!capture
                    .borrow_mut()
                    .accept(&source.request_id, String::new()));
            }
            "oversize" => {
                assert!(!capture
                    .borrow_mut()
                    .accept(&source.request_id, "x".repeat(MAX_SELECTION_BYTES + 1)));
            }
            "late" => {
                capture.borrow_mut().pending.as_mut().unwrap().started =
                    Instant::now() - std::time::Duration::from_secs(3);
                assert!(!capture
                    .borrow_mut()
                    .accept(&source.request_id, "late".into()));
            }
            _ => {}
        }
        assert_eq!(capture.borrow().text(&old), None);
        assert_eq!(
            send(&mut state, &capture, source, "previous selection"),
            Err(SendError::Empty)
        );
        assert!(state.sink.is_empty());
    }
}

#[test]
fn navigation_cancel_and_tab_switch_while_menu_open() {
    for transition in ["navigation", "cancel", "switch-away-and-back"] {
        let (mut state, capture, source) = fixture("from first tab");
        if transition == "navigation" {
            capture.borrow_mut().navigate();
        } else {
            capture.borrow_mut().invalidate();
        }
        assert_eq!(
            send(&mut state, &capture, source, "from first tab"),
            Err(SendError::Stale)
        );
        assert!(state.sink.is_empty());
    }
    let (mut state, capture, source) = fixture("from first tab");
    let other = Capture::new(8);
    assert_eq!(
        state.deliver(
            &mut capture.borrow_mut(),
            other.borrow().identity,
            state.receiver(),
            "from first tab".into(),
            source
        ),
        Err(SendError::Stale)
    );
    assert!(state.sink.is_empty());
}

#[test]
fn receiver_is_dormant_and_rechecked_at_activation() {
    assert!(SelectionState::default().receiver().is_none());
    for replacement in [
        None,
        Some(ReceiverInfo {
            id: "different".into(),
            name: "Different receiver".into(),
        }),
    ] {
        let (mut state, capture, source) = fixture("selection");
        state.fake_receiver = replacement;
        assert!(send(&mut state, &capture, source.clone(), "selection").is_err());
        state.fake_receiver = Some(receiver_info());
        assert_eq!(
            send(&mut state, &capture, source, "selection"),
            Err(SendError::Stale)
        );
        assert!(state.sink.is_empty());
    }
}

#[test]
fn menu_requires_a_receiver_and_valid_text_and_uses_one_locale_key() {
    use crate::platform::menu_compose::{self, Entry, Target};
    for has_receiver in [false, true] {
        for text in ["", "selected"] {
            let capture = Capture::new(1);
            let ready = if has_receiver {
                let source = capture.borrow_mut().begin(&receiver_info()).unwrap();
                capture.borrow_mut().accept(&source.request_id, text.into())
            } else {
                false
            };
            let entries =
                menu_compose::with_selection(menu_compose::compose(Target::default()), ready);
            assert_eq!(
                entries.contains(&Entry::SendSelection),
                has_receiver && !text.is_empty()
            );
        }
    }
    let mut args = crate::i18n::Args::new();
    args.set("name", "Test receiver");
    for locale in ["en", "en-XA"] {
        let i18n = crate::i18n::I18n::bootstrap(locale).unwrap();
        let label = i18n.resolve(crate::i18n::keys::ADDON_SELECTION_SEND, &args);
        assert!(label.contains("Test receiver"));
        assert!(!label.contains("addon-selection-send"));
    }
}

/// The production seam, checked in the source because an AppState cannot be
/// built in a unit test: the menu and every delivery ask the host's live
/// receiver, the text is handed over only after the capture was redeemed,
/// and an answer is accepted only for a selection actually handed over.
#[test]
fn production_delivery_goes_through_the_live_host_after_redemption() {
    let source = include_str!("addon_selection.rs");
    let receiver = &source[source.find("pub fn receiver(").expect("receiver moved")..];
    assert!(receiver[..400].contains("crate::addon_host::selection_receiver(state)"));
    let deliver = &source[source.find("pub fn deliver(\n").expect("deliver moved")..];
    let redeemed = deliver.find(".deliver(&mut capture.borrow_mut()").expect("no redemption");
    let handed = deliver.find("crate::addon_host::deliver_selection(state, &handed)").expect("not handed to the host");
    assert!(redeemed < handed, "the text must not reach the add-on before the capture is redeemed");
    let host = include_str!("addon_host.rs");
    let gate = &host[host.find("pub fn selection_receiver(").expect("selection_receiver moved")..];
    for check in ["app.vault.is_some()", "session.is_ready()", "session.mode.get() == Mode::Full", "!session.is_ending()"] {
        assert!(gate[..500].contains(check), "{check}");
    }
    let answer = &host[host.find("Command::SelectionResult { delivery_id, .. } =>").expect("selection result moved")..];
    assert!(answer[..300].contains("session.deliveries.borrow_mut().remove(&delivery_id)"));
}
