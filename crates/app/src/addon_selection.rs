//! Native-menu selection capture. Content never chooses a receiver or source.
use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use crate::state::AppState;

pub const MAX_SELECTION_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverInfo {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionSource {
    pub tab_id: u64,
    pub webview_id: u64,
    pub document_generation: u64,
    pub request_id: String,
    pub receiver_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    Unavailable,
    Stale,
    Empty,
    TooLarge,
}

#[derive(Default)]
pub struct SelectionState {
    // No production override, environment switch, or persistent text sink.
    #[cfg(test)]
    fake_receiver: Option<ReceiverInfo>,
    #[cfg(test)]
    sink: Vec<(String, SelectionSource)>,
}

impl SelectionState {
    #[cfg(test)]
    fn receiver(&self) -> Option<ReceiverInfo> {
        self.fake_receiver.clone()
    }

    fn deliver(
        &mut self,
        capture: &mut Capture,
        active: Identity,
        receiver: Option<ReceiverInfo>,
        text: String,
        source: SelectionSource,
    ) -> Result<(), SendError> {
        // Consume even a refused activation. A later unlock/receiver change
        // must never turn a previous menu choice into a delivery.
        let pending = capture.redeem(&source, active)?;
        let receiver = receiver.ok_or(SendError::Unavailable)?;
        if receiver.id != source.receiver_id || pending != text {
            return Err(SendError::Stale);
        }
        validate_text(&text)?;
        #[cfg(test)]
        self.sink.push((text, source));
        Ok(())
    }
}

/// The open add-on window, when it can take a selection now (ready,
/// writable, not ending, Vault unlocked: `addon_host::selection_receiver`).
/// Both the menu and every delivery ask here.
pub fn receiver(state: &AppState) -> Option<ReceiverInfo> {
    #[cfg(test)]
    return state.addon_selection.receiver();
    #[cfg(not(test))]
    crate::addon_host::selection_receiver(state)
}

/// Redeems the menu's capture against the live receiver and hands the text
/// to the add-on window, whose answer arrives as `addon_selection_result`.
pub fn deliver(
    state: &mut AppState,
    text: String,
    source: SelectionSource,
) -> Result<(), SendError> {
    let available = receiver(state);
    let tab = state.tabs.get(state.active).ok_or(SendError::Stale)?;
    let capture = tab.selection_capture();
    let active = capture.borrow().identity;
    let handed = text.clone();
    state
        .addon_selection
        .deliver(&mut capture.borrow_mut(), active, available, text, source)?;
    #[cfg(not(test))]
    if !crate::addon_host::deliver_selection(state, &handed) {
        return Err(SendError::Unavailable);
    }
    #[cfg(test)]
    drop(handed);
    Ok(())
}

pub fn activate(state: &mut AppState, source: SelectionSource) {
    let text = state
        .tabs
        .get(state.active)
        .and_then(|tab| tab.selection_capture().borrow().text(&source));
    if let Some(text) = text {
        let _ = deliver(state, text, source);
    }
}

#[derive(Clone)]
pub struct MenuOffer {
    pub receiver: ReceiverInfo,
    pub label: String,
}

thread_local! { static MENU_OFFER: RefCell<Option<MenuOffer>> = const { RefCell::new(None) }; }

/// A display-only projection for native callbacks, which cannot borrow
/// AppState reentrantly. Activation always rechecks the live seam above.
pub fn sync_menu(state: &AppState) {
    let offer = receiver(state).map(|receiver| {
        let mut args = crate::i18n::Args::new();
        args.set("name", receiver.name.clone());
        let label = native_menu_label(
            state
                .i18n
                .resolve(crate::i18n::keys::ADDON_SELECTION_SEND, &args),
        );
        MenuOffer { receiver, label }
    });
    MENU_OFFER.with(|slot| *slot.borrow_mut() = offer);
}

/// Win32 menus draw the bidi isolation marks around a placeable as boxes
/// (seen on WebView2, 2026-10-16); GTK draws nothing for them.
fn native_menu_label(label: String) -> String {
    if cfg!(windows) {
        label.chars().filter(|c| !('\u{2066}'..='\u{2069}').contains(c)).collect()
    } else {
        label
    }
}

pub fn menu_offer() -> Option<MenuOffer> {
    MENU_OFFER.with(|slot| slot.borrow().clone())
}

#[cfg(test)]
pub(crate) fn set_test_menu_offer(offer: Option<MenuOffer>) {
    MENU_OFFER.with(|slot| *slot.borrow_mut() = offer);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    tab_id: u64,
    webview_id: u64,
    document_generation: u64,
}

pub type SharedCapture = Rc<RefCell<Capture>>;

pub struct Capture {
    identity: Identity,
    pending: Option<Pending>,
}

#[derive(Clone)]
struct Pending {
    source: SelectionSource,
    started: Instant,
    answered: bool,
    text: Option<String>,
}

impl Capture {
    pub fn new(tab_id: u64) -> SharedCapture {
        static NEXT_VIEW: AtomicU64 = AtomicU64::new(1);
        Rc::new(RefCell::new(Self {
            identity: Identity {
                tab_id,
                webview_id: NEXT_VIEW.fetch_add(1, Ordering::Relaxed),
                document_generation: 0,
            },
            pending: None,
        }))
    }

    pub fn navigate(&mut self) {
        self.invalidate();
        self.identity.document_generation += 1;
    }

    pub fn invalidate(&mut self) {
        self.pending = None;
    }

    pub fn begin(&mut self, receiver: &ReceiverInfo) -> Option<SelectionSource> {
        self.invalidate();
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).ok()?;
        let source = SelectionSource {
            tab_id: self.identity.tab_id,
            webview_id: self.identity.webview_id,
            document_generation: self.identity.document_generation,
            request_id: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            receiver_id: receiver.id.clone(),
        };
        self.pending = Some(Pending {
            source: source.clone(),
            started: Instant::now(),
            answered: false,
            text: None,
        });
        Some(source)
    }

    /// One bounded response, including empty/failure, consumes the capture
    /// request. A duplicate cannot overwrite the menu's text.
    pub fn accept(&mut self, request: &str, text: String) -> bool {
        let Some(pending) = self.pending.as_mut() else {
            return false;
        };
        if pending.source.request_id != request || pending.answered {
            return false;
        }
        pending.answered = true;
        if pending.started.elapsed().as_secs() >= 2 || validate_text(&text).is_err() {
            return false;
        }
        pending.text = Some(text);
        true
    }

    pub fn text(&self, source: &SelectionSource) -> Option<String> {
        let pending = self.pending.as_ref()?;
        (pending.source == *source)
            .then(|| pending.text.clone())
            .flatten()
    }

    pub fn pending_source_matches(&self, source: &SelectionSource) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.source == *source)
    }

    #[cfg(test)]
    pub(crate) fn test_snapshot(&self) -> Option<(SelectionSource, String)> {
        let pending = self.pending.as_ref()?;
        Some((pending.source.clone(), pending.text.clone()?))
    }

    fn redeem(&mut self, source: &SelectionSource, active: Identity) -> Result<String, SendError> {
        let pending = self.pending.take().ok_or(SendError::Stale)?; // one-use boundary
        let identity = Identity {
            tab_id: source.tab_id,
            webview_id: source.webview_id,
            document_generation: source.document_generation,
        };
        if identity != active || identity != self.identity || pending.source != *source {
            // source boundary
            return Err(SendError::Stale);
        }
        pending.text.ok_or(SendError::Empty)
    }
}

fn validate_text(text: &str) -> Result<(), SendError> {
    if text.is_empty() {
        Err(SendError::Empty)
    } else if text.len() > MAX_SELECTION_BYTES {
        Err(SendError::TooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "addon_selection_tests.rs"]
mod tests;
