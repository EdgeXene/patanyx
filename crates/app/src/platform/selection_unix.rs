//! Dedicated selection channel. Host replies contain data, never source code.
use super::{
    new_poll_token, poll_is_accepted, reply_error, user_content_manager, ParkedReply, ReplyHandler,
};
use crate::{
    addon_selection::{self, SelectionSource, SharedCapture},
    UserEvent,
};
use gtk::prelude::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use tao::event_loop::EventLoopProxy;
use webkit2gtk::{UserContentManagerExt, WebViewExt};
use wry::{WebView, WebViewExtUnix};

const WORLD: &str = "selection-capture";
const ASK: &str = "selectionAsk";
const REPLY: &str = "selectionReply";
const MAX_FRAMES: usize = 64;
const SCRIPT: &str = include_str!("../content_scripts/selection_capture.js");

#[cfg(test)]
#[path = "selection_unix_tests.rs"]
mod tests;

pub(super) type Shared = Rc<RefCell<Channel>>;
pub(super) struct Channel {
    capture: SharedCapture,
    token: String,
    polls: Vec<ParkedReply>,
    menu: Option<Menu>,
    script: Option<webkit2gtk::UserScript>,
    proxy: EventLoopProxy<UserEvent>,
}

struct Menu {
    widget: gtk::glib::WeakRef<gtk::Menu>,
    source: SelectionSource,
    label: String,
    activated: Rc<Cell<bool>>,
    /// The Send item, once `add_send_item` has put it in the menu.
    item: Option<gtk::glib::WeakRef<gtk::MenuItem>>,
}

fn install(native: &webkit2gtk::WebView, token: &str) -> Option<webkit2gtk::UserScript> {
    use webkit2gtk::{UserContentInjectedFrames, UserScript, UserScriptInjectionTime};
    if token.is_empty() {
        return None;
    }
    let ucm = user_content_manager(native)?;
    let source = SCRIPT.replace("__SELECTION_DOCUMENT_TOKEN__", token);
    let script = UserScript::for_world(
        &source,
        UserContentInjectedFrames::AllFrames,
        UserScriptInjectionTime::Start,
        WORLD,
        &[],
        &[],
    );
    ucm.add_script(&script);
    Some(script)
}

pub(super) fn connect(
    webview: &WebView,
    capture: SharedCapture,
    proxy: &EventLoopProxy<UserEvent>,
) -> Option<Shared> {
    use javascriptcore::ValueExt;
    use webkit2gtk::glib::translate::ToGlibPtr;
    let native = webview.webview();
    let ucm = user_content_manager(&native)?;
    // Both endpoints are absent from the page's script world. The only
    // accepted command is a parked capture request, not chrome dispatch.
    if !ucm.register_script_message_handler_in_world(REPLY, WORLD) {
        return None;
    }
    let token = new_poll_token();
    let channel = Rc::new(RefCell::new(Channel {
        script: install(&native, &token),
        token,
        capture,
        polls: Vec::new(),
        menu: None,
        proxy: proxy.clone(),
    }));
    let response = channel.clone();
    ucm.connect_script_message_received(Some(REPLY), move |_, result| {
        let Some(value) = result.js_value() else {
            return;
        };
        if !value.is_string() {
            return;
        }
        let frame = value.to_str().to_string();
        // Plain UTF-8 framing avoids JSON's sixfold escaping expansion.
        if frame.len() > addon_selection::MAX_SELECTION_BYTES + 256 {
            return;
        }
        let Some((token, rest)) = frame.split_once(' ') else {
            return;
        };
        let Ok(mut channel) = response.try_borrow_mut() else {
            return;
        };
        if !poll_is_accepted(token, &channel.token) {
            return;
        }
        // A trusted pagehide in any frame retires its document even when
        // WebKit emits no top-level load-changed signal.
        if rest == "end" {
            channel.capture.borrow_mut().navigate();
            channel.menu = None;
            return;
        }
        let Some((request, text)) = rest.split_once(' ') else {
            return;
        };
        if !channel
            .capture
            .borrow_mut()
            .accept(request, text.to_owned())
        {
            return;
        }
        let Some(menu) = channel.menu.take() else {
            return;
        };
        if menu.source.request_id != request {
            return;
        }
        // The item has been in the menu, disabled, since it opened: enabling
        // it changes nothing about the menu's size (`add_send_item`).
        if let Some(item) = menu.item.as_ref().and_then(|item| item.upgrade()) {
            item.set_sensitive(true);
        }
    });

    let name = std::ffi::CString::new(ASK).ok()?;
    let world = std::ffi::CString::new(WORLD).ok()?;
    let signal =
        std::ffi::CString::new(format!("script-message-with-reply-received::{ASK}")).ok()?;
    let raw: *mut webkit2gtk_sys::WebKitUserContentManager = ucm.to_glib_none().0;
    // Same FFI ownership as the translation channel: one boxed Rc per
    // connection, released by its destroy notify. No AppState reentry.
    unsafe {
        if webkit2gtk_sys::webkit_user_content_manager_register_script_message_handler_with_reply(
            raw,
            name.as_ptr(),
            world.as_ptr(),
        ) == 0
        {
            return None;
        }
        gobject_sys::g_signal_connect_data(
            raw.cast(),
            signal.as_ptr(),
            Some(std::mem::transmute::<ReplyHandler, unsafe extern "C" fn()>(
                ask,
            )),
            Box::into_raw(Box::new(channel.clone())).cast(),
            Some(drop_channel),
            0,
        );
    }
    let loading = channel.clone();
    native.connect_load_changed(move |native, event| {
        if event != webkit2gtk::LoadEvent::Started {
            return;
        }
        let mut channel = loading.borrow_mut();
        channel.capture.borrow_mut().navigate();
        channel.menu = None;
        channel.polls.clear();
        if let Some(script) = channel.script.take() {
            if let Some(ucm) = user_content_manager(native) {
                ucm.remove_script(&script);
            }
        }
        channel.token = new_poll_token();
        channel.script = install(native, &channel.token);
    });
    Some(channel)
}

/// Adds the Send item at the end of a menu `begin` armed, DISABLED until the
/// originating document answers with a nonempty selection. It is there from
/// the start because GTK does not resize a menu already on screen: an item
/// added after the popup left it drawn as an empty, scrolled box.
pub(super) fn add_send_item(channel: &Shared, widget: &gtk::Menu) {
    let mut inner = channel.borrow_mut();
    let proxy = inner.proxy.clone();
    let Some(menu) = inner.menu.as_mut() else {
        return;
    };
    // Use the shared composer's decision for the additional section.
    for entry in super::menu_compose::with_selection(Vec::new(), true) {
        match entry {
            super::menu_compose::Entry::Separator => widget.append(&gtk::SeparatorMenuItem::new()),
            super::menu_compose::Entry::SendSelection => {
                let item = gtk::MenuItem::with_label(&menu.label);
                item.set_sensitive(false);
                let source = menu.source.clone();
                let activated = menu.activated.clone();
                let proxy = proxy.clone();
                item.connect_activate(move |_| {
                    activated.set(true);
                    let _ = proxy.send_event(UserEvent::SendSelection(source.clone()));
                });
                widget.append(&item);
                menu.item = Some(item.downgrade());
            }
            _ => unreachable!(),
        }
    }
}

pub(super) fn begin(channel: &Shared, widget: &gtk::Menu, possible_selection: bool) {
    let mut inner = channel.borrow_mut();
    inner.capture.borrow_mut().invalidate();
    inner.menu = None;
    if !possible_selection || inner.script.is_none() {
        return;
    }
    let Some(offer) = addon_selection::menu_offer() else {
        return;
    };
    let Some(source) = inner.capture.borrow_mut().begin(&offer.receiver) else {
        return;
    };
    let activated = Rc::new(Cell::new(false));
    inner.menu = Some(Menu {
        widget: widget.downgrade(),
        source: source.clone(),
        label: offer.label,
        activated: activated.clone(),
        item: None,
    });
    let weak = Rc::downgrade(channel);
    let closing_source = source.clone();
    widget.connect_deactivate(move |_| {
        let weak = weak.clone();
        let source = closing_source.clone();
        let activated = activated.clone();
        // GTK deactivates before item activation; only cancel after that.
        gtk::glib::idle_add_local_once(move || {
            if activated.get() {
                return;
            }
            if let Some(channel) = weak.upgrade() {
                let mut channel = channel.borrow_mut();
                // Do not cancel a newer invocation that replaced this menu.
                let current = channel.capture.borrow().pending_source_matches(&source);
                if current {
                    channel.capture.borrow_mut().invalidate();
                    channel.menu = None;
                }
            }
        });
    });
    let polls = std::mem::take(&mut inner.polls);
    drop(inner);
    // Release the borrow before crossing into the engine.
    for poll in polls {
        poll.answer(&source.request_id);
    }
}

unsafe extern "C" fn drop_channel(data: glib_sys::gpointer, _: *mut gobject_sys::GClosure) {
    if !data.is_null() {
        drop(unsafe { Box::from_raw(data as *mut Shared) });
    }
}

unsafe extern "C" fn ask(
    _: *mut webkit2gtk_sys::WebKitUserContentManager,
    raw: *mut javascriptcore_rs_sys::JSCValue,
    reply: *mut webkit2gtk_sys::WebKitScriptMessageReply,
    data: glib_sys::gpointer,
) -> glib_sys::gboolean {
    use javascriptcore::ValueExt;
    use webkit2gtk::glib::translate::FromGlibPtrNone;
    if raw.is_null() || reply.is_null() || data.is_null() {
        return 0;
    }
    let channel = unsafe { &*(data as *const Shared) };
    let Ok(mut channel) = channel.try_borrow_mut() else {
        unsafe { reply_error(reply, "refused") };
        return 1;
    };
    let value = unsafe { javascriptcore::Value::from_glib_none(raw) };
    if !value.is_string()
        || !poll_is_accepted(value.to_str().as_str(), &channel.token)
        || channel.polls.len() >= MAX_FRAMES
    {
        unsafe { reply_error(reply, "refused") };
        return 1;
    }
    let Some(context) = value.context() else {
        unsafe { reply_error(reply, "refused") };
        return 1;
    };
    channel
        .polls
        .push(unsafe { ParkedReply::park(reply, context) });
    1
}
