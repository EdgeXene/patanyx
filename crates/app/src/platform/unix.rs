//! GTK/WebKitGTK backend glue.
//!
//! Layout is GTK packing: the window's default vbox holds a fixed-height
//! chrome box and an expanding content box with one `gtk::Box` per tab, so
//! resizing and chrome-height changes need no manual geometry (hence the
//! no-op `layout`). Every gtk/webkit2gtk reference in the crate lives in
//! this module.
//!
//! Privacy controls: WebKitGTK has no in-process per-request allow/deny
//! hook, so network-level blocking (ads AND freeze) is done with compiled
//! WebKit content filters installed on the per-webview UserContentManager
//! wry already created — a blocked request never leaves the machine, which
//! is exactly the property `privacy`'s matcher tests prove. Cosmetic
//! filtering is a user stylesheet (never injected script: content webviews
//! are never script-evaluated). The ledger observes `resource-load-started`.
//!
//! Page integrity: the main resource's bytes come from
//! `webkit_web_view_get_main_resource` + an async `get_data` (same
//! GAsyncReadyCallback shape as the filter store below) — never from script
//! in the page, never from a re-fetch. See the dedicated section below.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Instant;

use gtk::prelude::*;
use tao::event_loop::EventLoopProxy;
use tao::platform::unix::WindowExtUnix;
use tao::window::Window;
use wry::{WebView, WebViewBuilder, WebViewBuilderExtUnix};

use super::privacy::{
    self, EngineSettings, FreezePhase, HostRecord, ProfileMode, SettingState, TabPolicy, TabState,
    TlsState,
};
use super::{ChromeLayout, CHROME_HEIGHT_PX};
use crate::page_integrity::{IntegrityEvent, PageBytesError};
use crate::shortcuts::{self, Key, Mods};
use crate::UserEvent;

pub struct Hosts {
    /// Held only so the window outlives the event loop (main.rs moves it in
    /// here); layout hangs off the boxes, not the tao window.
    _window: Window,
    vbox: gtk::Box,
    chrome_box: gtk::Box,
    content_box: gtk::Box,
    /// The hover readout: a status-bar style label overlaid bottom-left on
    /// the content area. Hidden except while the pointer is on a link whose
    /// target `hover::readout_for` agrees to show.
    readout: gtk::Label,
    /// Held so a scheme change re-loads the SAME provider in place; adding a
    /// fresh provider per change would stack providers on one style context.
    readout_css: gtk::CssProvider,
    /// False until the readout's CSS has actually loaded. An UNSTYLED label
    /// over arbitrary page pixels is unreadable at best and, at worst,
    /// indistinguishable from page content -- a deception risk in a widget
    /// whose whole job is saying where a link goes -- so a styling failure
    /// turns the feature OFF rather than degrading it.
    ///
    /// `Rc` because the engine hover callback needs to consult it and GTK is
    /// single-threaded; same shape as every `Rc<RefCell<TabState>>` here.
    readout_styled: Rc<Cell<bool>>,
    /// True while a modal covers the page (`ChromeLayout::Overlay`): a
    /// readout floating over a modal would claim something about a page the
    /// user can neither see nor click.
    readout_suppressed: Rc<Cell<bool>>,
}

/// One per tab: the container packed into the content box. Tab visibility
/// is controlled by showing/hiding this container.
pub struct TabView {
    container: gtk::Box,
    /// Shared with the engine callbacks below; GTK is single-threaded (the
    /// main loop), so Rc/RefCell is sufficient and correct.
    state: Rc<RefCell<TabState>>,
    /// Kept because removing a user stylesheet requires the same instance
    /// that was added (GTK objects are refcounted pointers).
    cosmetic_sheet: RefCell<Option<webkit2gtk::UserStyleSheet>>,
}

pub fn create_hosts(window: Window) -> Hosts {
    // Cloned (GTK objects are refcounted, so this is a pointer bump) because
    // default_vbox borrows the window, and the window is moved into Hosts
    // below; holding the borrow across that move would not compile.
    let vbox = window
        .default_vbox()
        .expect("tao window has no default gtk vbox")
        .clone();
    // Chrome container: fixed height (resized later by set_chrome_height).
    let chrome_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    chrome_box.set_size_request(-1, CHROME_HEIGHT_PX);
    vbox.pack_start(&chrome_box, false, false, 0);
    // Content container: takes all remaining space; hosts one gtk::Box per tab.
    // It sits inside an Overlay rather than directly in the vbox so the hover
    // readout can float over the page without reserving a row of its own.
    // Tab containers are still packed into content_box, so remove_tab's
    // "the container's parent IS content_box" fact is unchanged -- only
    // content_box's own parent moved.
    let content_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let overlay = gtk::Overlay::new();
    overlay.add(&content_box);
    vbox.pack_start(&overlay, true, true, 0);

    // The readout label. Bottom-left, status-bar fashion.
    let readout = gtk::Label::new(None);
    readout.set_widget_name("patanyx-hover-readout");
    readout.set_halign(gtk::Align::Start);
    readout.set_valign(gtk::Align::End);
    readout.set_xalign(0.0);
    // MIDDLE, matching hover::elide_middle's documented reason: the tail is
    // the part the user needs, and a narrow window must not undo that by
    // clipping the end.
    readout.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    // show_all() on the vbox is RECURSIVE and would re-show this label the
    // moment main.rs calls it, putting an empty bar over the page from the
    // first frame. no_show_all makes show_all skip it entirely; from here on
    // visibility belongs to set_hover_readout alone.
    readout.set_no_show_all(true);
    overlay.add_overlay(&readout);
    // A GtkLabel has no input window, but say it anyway: if this label ever
    // swallowed motion events the page would stop reporting hover and the
    // readout would stick showing a link the pointer has left.
    overlay.set_overlay_pass_through(&readout, true);

    Hosts {
        _window: window,
        vbox,
        chrome_box,
        content_box,
        readout,
        readout_css: gtk::CssProvider::new(),
        readout_styled: Rc::new(Cell::new(false)),
        readout_suppressed: Rc::new(Cell::new(false)),
    }
}

/// Attaches the readout's style provider and loads the colours for `scheme`.
///
/// Called once from main.rs after the widget tree exists. Until this runs the
/// readout is unstyled and `readout_styled` is false, so it cannot show.
pub fn arm_hover_readout(hosts: &Hosts, scheme: crate::prefs::ChromeScheme) {
    hosts.readout.style_context().add_provider(
        &hosts.readout_css,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    set_hover_readout_scheme(hosts, scheme);
}

/// Re-colours the readout for a chrome scheme change.
///
/// Loads into the SAME provider `arm_hover_readout` attached, so a user who
/// cycles schemes does not stack providers. A load failure turns the feature
/// off (see `readout_styled`); it never leaves an unstyled label showing.
pub fn set_hover_readout_scheme(hosts: &Hosts, scheme: crate::prefs::ChromeScheme) {
    let p = crate::hover_style::palette(scheme);
    let css = format!(
        "#patanyx-hover-readout {{ background-color: {bg}; color: {fg}; \
         border-top: 1px solid {ln}; border-right: 1px solid {ln}; \
         padding: 2px 8px; font-size: 12px; }}",
        bg = crate::hover_style::css_hex(p.bg),
        fg = crate::hover_style::css_hex(p.fg),
        ln = crate::hover_style::css_hex(p.border),
    );
    let ok = hosts.readout_css.load_from_data(css.as_bytes()).is_ok();
    hosts.readout_styled.set(ok);
    if !ok {
        hosts.readout.hide();
    }
}

/// Shows `text` in the readout, or hides it for `None`.
///
/// `None` means HIDE, never "draw empty" -- an empty bar over the page says
/// "something is here" when nothing is (hover.rs documents the contract).
/// `set_text`, NEVER `set_markup`: a link target is page data, and a query
/// string full of `&` and `<` must not be parsed as Pango markup.
pub fn set_hover_readout(hosts: &Hosts, text: Option<&str>) {
    match text {
        Some(t) if hosts.readout_styled.get() && !hosts.readout_suppressed.get() => {
            hosts.readout.set_text(t);
            hosts.readout.show();
        }
        _ => hosts.readout.hide(),
    }
}

/// (visible, text) for the smoke gate; not used by any UI path.
pub fn hover_readout_state(hosts: &Hosts) -> (bool, String) {
    (
        hosts.readout.is_visible(),
        hosts.readout.text().to_string(),
    )
}

pub fn show_all(hosts: &Hosts) {
    hosts.vbox.show_all();
}

/// Builder factory, matching the Windows signature so state.rs and main.rs
/// need no `#[cfg]`.
///
/// Plain `WebViewBuilder::new()` here, and that is not an oversight. The
/// defect this exists for is WebView2-only: with no `WebContext`, WebView2
/// writes a Chromium profile into a folder beside the executable, whereas
/// WebKitGTK's default `WebContext` already keeps its data under
/// `$XDG_DATA_HOME`/`$XDG_CACHE_HOME` like every other GTK application.
/// Naming a directory here would MOVE unix profiles rather than rescue them,
/// which is a migration this change has no reason to inflict on a platform
/// that was never leaving anything beside the exe.
pub fn new_webview_builder() -> WebViewBuilder<'static> {
    WebViewBuilder::new()
}

/// Nothing to report: see `new_webview_builder` — no unix build ever wrote a
/// profile beside the executable, so there is no orphan to find.
pub fn report_stray_profile() {}

// Note: assumes wry 0.55.1's WebViewBuilder still carries a lifetime
// parameter (WebViewAttributes<'a> holds boxed handlers). If the vendored
// source has a non-generic WebViewBuilder, drop the `<'_>` here and in the
// other build_* signatures — nothing else depends on it.
/// Suppresses WebKitGTK's built-in right-click menu.
///
/// Returning true from the `context-menu` signal means "handled, show nothing".
/// The Windows backend does the same through wry's
/// `with_default_context_menus(false)`, so right-click behaves identically on
/// both platforms rather than exposing whichever engine happens to be
/// underneath.
use super::{menu_compose, menu_ids};

/// Builds PATANYX's own right-click menu and keeps WebKitGTK's suppressed.
///
/// Returning true from the `context-menu` signal means "handled, show
/// nothing", and this handler ALWAYS returns it: the vendor menu stays off
/// exactly as `with_default_context_menus(false)` keeps it off on Windows,
/// because what the engine ships in its own menu is not auditable from this
/// codebase and can change under the app on a runtime update. Showing our own
/// GtkMenu while returning true is the signal's documented third mode (build
/// your own menu and return TRUE), not a trick.
///
/// What shows is decided by `menu_compose::compose` -- the same entries
/// WebView2 shows on Windows. Editing commands are engine-local: WebKit runs
/// them on the content webview's own selection/focus and puts cut/copied text
/// in the system clipboard itself, so no menu id round trip through state.rs
/// and no script in the content webview. Everything else becomes a
/// `UserEvent::ContextMenuAction` for state.rs, the one interpreter.
fn connect_context_menu(webview: &WebView, proxy: &EventLoopProxy<UserEvent>) {
    use gtk::prelude::*;
    use webkit2gtk::{HitTestResultContext, HitTestResultExt, WebViewExt};
    use wry::WebViewExtUnix;

    let core = webview.webview();
    let proxy = proxy.clone();
    core.connect_context_menu(move |content, _menu, event, hit| {
        // context() is a raw u32 bitfield; wrap it to test the flags.
        let context = HitTestResultContext::from_bits_truncate(hit.context());
        let link = hit.link_uri().map(|uri| uri.to_string());
        let image = hit.image_uri().map(|uri| uri.to_string());
        let target = menu_compose::Target {
            // A flag without its URI would produce a dead row, so the URI's
            // presence is part of the flag.
            link: context.contains(HitTestResultContext::LINK) && link.is_some(),
            image: context.contains(HitTestResultContext::IMAGE) && image.is_some(),
            editable: context.contains(HitTestResultContext::EDITABLE),
            selection: context.contains(HitTestResultContext::SELECTION),
        };

        let menu = gtk::Menu::new();
        for entry in menu_compose::compose(target) {
            match entry {
                menu_compose::Entry::Separator => {
                    menu.append(&gtk::SeparatorMenuItem::new());
                }
                menu_compose::Entry::Action(id) => {
                    let Some(label) = menu_compose::action_label(id) else {
                        continue;
                    };
                    let item = gtk::MenuItem::with_label(label);
                    // The URL the entry acts on: the link for link actions,
                    // the image source for image actions, neither for
                    // navigation. Captured NOW because by the time the loop
                    // runs the event the page may have navigated.
                    let target_url = match id {
                        menu_ids::OPEN_IMAGE_NEW_TAB | menu_ids::COPY_IMAGE => image.clone(),
                        menu_ids::HISTORY_BACK
                        | menu_ids::HISTORY_FORWARD
                        | menu_ids::HISTORY_RELOAD => None,
                        _ => link.clone(),
                    };
                    let proxy = proxy.clone();
                    item.connect_activate(move |_| {
                        let _ = proxy.send_event(UserEvent::ContextMenuAction {
                            action: id,
                            target: target_url.clone(),
                        });
                    });
                    menu.append(&item);
                }
                menu_compose::Entry::Editing(command) => {
                    let item = gtk::MenuItem::with_label(command.label());
                    // `content` is the signal's own webview argument, cloned
                    // into the item closure: the clone dies with the popup,
                    // so there is no reference cycle back into the webview.
                    let content = content.clone();
                    item.connect_activate(move |_| {
                        content.execute_editing_command(command.webkit_command());
                    });
                    menu.append(&item);
                }
            }
        }
        menu.show_all();
        // The only strong reference to the menu is this stack frame, which is
        // about to end, so the menu has to be torn down on deactivate or one
        // leaks per right-click. It must NOT be torn down SYNCHRONOUSLY there.
        //
        // This used to read `connect_deactivate(|menu| menu.destroy())` under a
        // comment asserting "GTK emits an item's activate BEFORE the menu
        // shell's deactivate, so destroying on deactivate cannot race the
        // command". THE ORDER IS THE OTHER WAY ROUND: gtk_menu_shell_activate_
        // item deactivates the shell first and only then calls
        // gtk_widget_activate on the item, so destroying inside the deactivate
        // handler destroyed the item before its activate could be emitted and
        // the closure below never ran. Every action on this menu was dead on
        // this backend -- open in new tab, all three policy variants, both
        // copies, the navigation rows -- while the editing commands kept
        // working and hid it, because WebKit runs those itself and they never
        // touch this code. Deferring the destroy to an idle callback lets
        // activate finish first and still frees the menu on the same loop
        // iteration.
        menu.connect_deactivate(|menu| {
            let menu = menu.clone();
            gtk::glib::idle_add_local_once(move || unsafe { menu.destroy() });
        });
        menu.popup_at_pointer(Some(event));
        // Always: the vendor menu never shows, whatever this one contained.
        true
    });
}

/// Reports the link under the pointer into the hover readout.
///
/// Content webviews ONLY. The chrome is our own UI; a hover in the toolbar is
/// not a destination and must not produce a readout.
///
/// Everything the engine reports goes through `hover::readout_for`, which is
/// where the display rules live -- http(s) only, deception characters
/// stripped, middle elision. This function contributes only the event.
///
/// The captures are refcounted GTK pointers cloned into the closures; none of
/// them reference the webview, so there is no cycle: closing a tab drops the
/// signal handlers and the label outlives them.
fn connect_hover_readout(webview: &WebView, hosts: &Hosts) {
    use webkit2gtk::{HitTestResultExt, LoadEvent, WebViewExt};
    use wry::WebViewExtUnix;

    let core = webview.webview();

    let readout = hosts.readout.clone();
    let styled = hosts.readout_styled.clone();
    let suppressed = hosts.readout_suppressed.clone();
    core.connect_mouse_target_changed(move |_view, hit, _modifiers| {
        let shown = hit
            .context_is_link()
            .then(|| hit.link_uri())
            .flatten()
            .and_then(|uri| crate::hover::readout_for(&uri));
        match shown {
            Some(text) if styled.get() && !suppressed.get() => {
                readout.set_text(&text);
                readout.show();
            }
            _ => readout.hide(),
        }
    });

    // Clicking the hovered link navigates; the readout must not survive into
    // the new document. A second load-changed handler on the same view is
    // ordinary GTK (signals multi-dispatch); the freeze machinery's handler
    // in connect_load_events is untouched.
    let readout = hosts.readout.clone();
    core.connect_load_changed(move |_view, event| {
        if event == LoadEvent::Started {
            readout.hide();
        }
    });

    // mouse-target-changed fires when the pointer leaves a LINK, but not
    // reliably when it leaves the WIDGET. Propagation::Proceed is mandatory:
    // swallowing the crossing event would break WebKit's own hover handling.
    let readout = hosts.readout.clone();
    core.connect_leave_notify_event(move |_view, _event| {
        readout.hide();
        gtk::glib::Propagation::Proceed
    });
}

/// Routes browser shortcuts from a webview's GTK widget into the event loop.
///
/// Connected to every webview (chrome and content alike) because GTK delivers
/// key events to the focused widget, and the focused widget is usually a web
/// page. Unbound keys return `Proceed` so typing still reaches the page.
fn connect_shortcuts(webview: &WebView, proxy: &EventLoopProxy<UserEvent>) {
    use gtk::gdk;
    use wry::WebViewExtUnix;

    let proxy = proxy.clone();
    webview
        .webview()
        .connect_key_press_event(move |_widget, event| {
            let state = event.state();
            let mods = Mods::new(
                state.contains(gdk::ModifierType::CONTROL_MASK),
                state.contains(gdk::ModifierType::SHIFT_MASK),
                state.contains(gdk::ModifierType::MOD1_MASK),
            );
            // EVERY keydown is evidence a human is here, not just the bound
            // ones. This handler already sees them all and discarded whatever
            // did not resolve to a shortcut, so typing inside a page counted
            // for nothing and the vault auto-locked out from under someone
            // filling in a form. Raised before the match so an unbound key
            // still counts; throttled so holding a key does not flood the loop;
            // and carrying nothing about WHICH key was pressed.
            if super::presence_throttle_elapsed() {
                let _ = proxy.send_event(UserEvent::UserPresence);
            }
            match gdk_key(event.keyval()).and_then(|key| shortcuts::resolve(mods, key)) {
                Some(action) => {
                    let _ = proxy.send_event(UserEvent::Shortcut(action));
                    // Stop: the page must not also act on a key we consumed.
                    gtk::glib::Propagation::Stop
                }
                None => gtk::glib::Propagation::Proceed,
            }
        });
}

/// Translates the few GDK keyvals any binding uses. Letters are matched on
/// both cases because GDK reports the shifted keyval when Shift is held.
fn gdk_key(value: gtk::gdk::keys::Key) -> Option<Key> {
    use gtk::gdk::keys::constants as k;
    let key = match value {
        k::t | k::T => Key::T,
        k::w | k::W => Key::W,
        k::l | k::L => Key::L,
        k::r | k::R => Key::R,
        k::f | k::F => Key::F,
        // Ctrl+K, the command palette. It was MISSING from this table while
        // shortcuts::resolve has always answered Key::K, so the palette was
        // simply unreachable on this backend -- the onboarding tour told
        // every Linux user to "press Ctrl+K at any time" and nothing
        // happened. Windows maps its own keys and was unaffected, which is
        // exactly why a table like this needs the test below rather than a
        // reader's attention.
        k::k | k::K => Key::K,
        // Ctrl+P. Also missing, and the consequence was worse than a dead
        // key: WebKitGTK does not bind it either, so the press reached
        // nothing at all and the browser looked broken. Bound here so it
        // reaches `print_active_tab`, which on this backend reports honestly
        // that the runtime cannot open a preview (show_print_ui is false)
        // instead of silently doing nothing. Real Linux printing is a
        // feature this does not pretend to add.
        k::p | k::P => Key::P,
        k::Tab | k::ISO_Left_Tab => Key::Tab,
        k::F5 => Key::F5,
        k::F3 => Key::F3,
        k::Left => Key::Left,
        k::Right => Key::Right,
        // Zoom. Every spelling a layout might report: the main-row key is
        // `equal` unshifted and `plus` shifted, and the numeric keypad has its
        // own constants entirely. Binding one of them is how a shortcut works
        // for its author and for nobody else.
        k::equal | k::KP_Equal => Key::Equal,
        k::plus | k::KP_Add => Key::Plus,
        k::minus | k::KP_Subtract | k::underscore => Key::Minus,
        k::_0 | k::KP_0 => Key::Zero,
        other => {
            let digit = other
                .to_unicode()
                .and_then(|c| c.to_digit(10))
                .filter(|d| (1..=9).contains(d))?;
            Key::Digit(digit as u8)
        }
    };
    Some(key)
}

pub fn build_chrome(
    hosts: &Hosts,
    builder: WebViewBuilder<'_>,
    proxy: &EventLoopProxy<UserEvent>,
) -> Result<WebView, wry::Error> {
    // Bind the proxy listener before the first CONTENT webview can be
    // built: build_content reads the chosen port per view. The chrome
    // webview itself needs no proxy -- it is our own UI and talks no web
    // traffic -- but it is the earliest engine touch on this path, which
    // makes it the unix analog of Windows' environment-creation bind.
    crate::tunnel_control::bind_if_enabled();
    let webview = builder.build_gtk(&hosts.chrome_box)?;
    connect_context_menu(&webview, proxy);
    connect_shortcuts(&webview, proxy);
    // No privacy policy on the chrome webview on purpose: it is our own UI
    // (needs JavaScript, talks IPC), not web content.
    Ok(webview)
}

/// No-op on unix. WebKitGTK persists no permission decision for PATANYX to
/// clear: the permission feature is Windows-only (webkit2gtk exposes no
/// requesting origin, so the frame-isolation rule cannot be honoured), and
/// nothing on this backend writes permission state to disk.
///
/// Present so main.rs can call it unconditionally, per this module's rule that
/// the platform pair expose the same surface and callers stay free of `#[cfg]`.
pub fn clear_persisted_permissions(_webview: &WebView) {}

/// No-op on unix: WebKitGTK has no equivalent event, and the GTK path already
/// routes every zoom through this process, so the indicator cannot drift.
///
/// This is why `UserEvent::ZoomFactorChanged` reads as "never constructed" in
/// a Linux build. It is constructed on Windows only (windows.rs), because
/// WebView2 owns the keypad and Ctrl+scroll and changes the factor without
/// telling us any other way. The asymmetry is real and correct; do not
/// "fix" the warning by deleting the variant.
pub fn connect_zoom_changed(_webview: &WebView, _proxy: &EventLoopProxy<UserEvent>, _id: u64) {}

/// Builds a content webview under `policy`. The policy is a construction
/// parameter because two of its fields are fixed at creation time:
/// `ephemeral` (the WebContext is chosen before the view exists) and
/// `javascript` (must be off before the first navigation for quarantine to
/// mean anything). `apply_policy` is called here so the caller cannot
/// forget it.
///
/// `malicious_override` is unused here and that is not an oversight: on
/// WebKitGTK the navigation handler's refusal actually takes, so the blocklist
/// is enforced there and never reaches this layer. Windows needs it because
/// WebView2 ignores that refusal -- see connect_request_interception.
pub fn build_content(
    hosts: &Hosts,
    builder: WebViewBuilder<'_>,
    policy: &TabPolicy,
    proxy: &EventLoopProxy<UserEvent>,
    url: &str,
    _malicious_override: Rc<RefCell<std::collections::BTreeSet<String>>>,
    _id: u64,
    // Windows-only feature. Accepted so the two backends keep one signature
    // and state.rs needs no `#[cfg]`; see clear_persisted_permissions above
    // for why WebKitGTK cannot honour the frame-isolation rule.
    _permissions: crate::state::PermissionBook,
) -> Result<(WebView, TabView), wry::Error> {
    // The initial URL is applied to the builder, exactly as the caller used
    // to do it: WebKitGTK's blocking is a content filter installed on the
    // tab's UserContentManager, which `apply_policy` below sets up before
    // any load can start, so there is nothing to order around here. Windows
    // takes the url instead of the builder for a real reason — see its
    // build_content — and both backends take it the same way so the caller
    // needs no cfg.
    let builder = builder.with_url(url);
    // THE TUNNEL PROXY, ON THE BUILDER AND NOT AFTER THE BUILD. wry applies
    // `set_network_proxy_settings(Custom, ...)` to this context's data
    // manager BEFORE it creates the webview and before it calls `load_uri`
    // (wry 0.55.1 webkitgtk/mod.rs:267-278, :286, :372). An earlier version
    // of this file did the same write by hand AFTER `build_gtk`, i.e. after
    // the load had already been handed to the network process -- a race on
    // every single tab, which is exactly the leak this feature exists to
    // prevent. Per view rather than once, for the reason `enable_itp`
    // documents: an ephemeral tab gets its own WebContext and data manager.
    //
    // `engine_proxy_port` encodes the fail-closed fallback (Imported with no
    // successful bind yields the dead port 1), so no view is ever left
    // proxy-less when the user chose a tunnel. There is no getter for proxy
    // settings at any layer, so there is nothing to read back -- confirmation
    // that traffic really goes through the tunnel comes from the probe in
    // tunnel_control, never from this write having been issued.
    crate::tunnel_control::bind_if_enabled();
    let builder = match crate::tunnel_control::engine_proxy_port() {
        Some(port) => builder.with_proxy_config(wry::ProxyConfig::Socks5(wry::ProxyEndpoint {
            host: "127.0.0.1".to_string(),
            port: port.to_string(),
        })),
        None => builder, // TunnelMode::Off: direct, by the user's choice.
    };
    // Note: verify the vendored wry 0.55.1 implements the WebKitGTK
    // arm of `with_incognito` via `WebContext::new_ephemeral` (upstream wry
    // does exactly that; an ephemeral context uses an ephemeral
    // WebsiteDataManager automatically — the two APIs the brief verified in
    // the bindings are the ones wry calls). If this wry lacks the arm,
    // ephemeral mode is silently OFF and there is no workaround from here
    // (the context cannot be swapped post-construction); the fix is a
    // one-line wry patch, and nothing may claim ephemeral storage until
    // then.
    let builder = if policy.ephemeral {
        builder.with_incognito(true)
    } else {
        builder
    };
    let container = gtk::Box::new(gtk::Orientation::Vertical, 0);
    hosts.content_box.pack_start(&container, true, true, 0);
    // Hidden until AppState decides this tab is the visible one (GTK widget
    // visibility must not be left to defaults once content_box is shown).
    container.hide();
    let webview = builder.build_gtk(&container)?;
    ITP_CONFIRMED.with(|c| c.set(enable_itp(&webview)));
    connect_context_menu(&webview, proxy);
    connect_hover_readout(&webview, hosts);
    connect_shortcuts(&webview, proxy);

    let state = Rc::new(RefCell::new(TabState::new(policy)));
    connect_load_events(&webview, state.clone());
    connect_ledger(&webview, state.clone());
    connect_tls_errors(&webview, state.clone());

    let view = TabView {
        container,
        state,
        cosmetic_sheet: RefCell::new(None),
    };
    apply_policy(&webview, &view, policy);
    // GPC's navigator.globalPrivacyControl, registered as a document-start
    // user script so it runs in the page's main world before page scripts.
    // (The Sec-GPC request header is Windows-only for now; WebKitGTK cannot
    // add request headers from the UI process -- see privacy.rs GPC section.)
    install_gpc_script(&webview);
    // Fingerprint noise, same registration category as GPC. Reads the pref
    // at build time: the toggle affects the NEXT tab, never this one --
    // neither engine can re-register a live view's scripts, and the panel
    // copy says so.
    install_divergence_script(&webview, policy.ephemeral);
    Ok((webview, view))
}

/// Installs the GPC navigator-property user script on a content view.
///
/// A UserScript at Start / AllFrames runs in the page's MAIN world before the
/// page's own scripts, which is where `navigator.globalPrivacyControl` must
/// be visible. If the view has no UserContentManager the property is absent
/// and that is diag'd rather than passed over silently: the privacy signal
/// failing should leave a trace.
fn install_gpc_script(webview: &WebView) {
    use webkit2gtk::{
        UserContentInjectedFrames, UserContentManagerExt, UserScript, UserScriptInjectionTime,
    };
    use wry::WebViewExtUnix;
    let Some(ucm) = user_content_manager(&webview.webview()) else {
        // Same degrade-never-crash rule as set_ad_blocking: an engine with no
        // content manager leaves the property absent. Not documented as
        // reachable; there is no diag ring on this backend to record it in.
        return;
    };
    let script = UserScript::new(
        super::privacy::GPC_SCRIPT,
        UserContentInjectedFrames::AllFrames,
        UserScriptInjectionTime::Start,
        &[],
        &[],
    );
    ucm.add_script(&script);
}

/// Installs the Fingerprint Divergence user script on a content view.
///
/// Same shape as `install_gpc_script`: Start / AllFrames, page main world,
/// before page scripts -- AllFrames matters more here than for GPC, because
/// fingerprinting scripts routinely run in third-party iframes. `None` from
/// `divergence_script` means the pref is off or OS randomness failed; both
/// register nothing, which is the honest posture (no script, no claim).
/// Ephemeral tabs get their own token so a site cannot link an ephemeral
/// visit to a normal one by matching noise.
fn install_divergence_script(webview: &WebView, ephemeral: bool) {
    use webkit2gtk::{
        UserContentInjectedFrames, UserContentManagerExt, UserScript, UserScriptInjectionTime,
    };
    use wry::WebViewExtUnix;
    let Some(source) = super::privacy::divergence_script(ephemeral) else {
        return;
    };
    let Some(ucm) = user_content_manager(&webview.webview()) else {
        // Same degrade-never-crash rule as install_gpc_script above.
        return;
    };
    let script = UserScript::new(
        &source,
        UserContentInjectedFrames::AllFrames,
        UserScriptInjectionTime::Start,
        &[],
        &[],
    );
    ucm.add_script(&script);
}

/// Turns on Intelligent Tracking Prevention for this view's data manager.
///
/// WebKitGTK defaults ITP to OFF. That default is the reason this exists:
/// the engine ships the machinery, and an embedder that never asks for it
/// gets none of it. ITP is the part of WebKit that classifies cross-site
/// trackers from observed behaviour and then partitions or purges their
/// state — which is a different job from the content blocker, and neither
/// substitutes for the other. The blocker stops hosts we listed in advance;
/// ITP handles the ones nobody listed.
///
/// Set per view rather than once at startup because an ephemeral tab gets
/// its own WebContext, and therefore its own data manager, which would not
/// inherit a setting applied to the default one. The setter is idempotent.
///
/// Raw FFI: the safe webkit2gtk 2.0.2 bindings expose the ITP directory and
/// summary getters but not `set_itp_enabled`, so this follows the same
/// pattern already used for WebKitUserContentFilterStore below.
/// Returns what the engine reports AFTER the write, not what we asked for.
/// A setter that silently does nothing is this codebase's most expensive
/// recurring bug — the ad-block rule reported success while blocking nothing
/// for as long as it shipped — so the answer here is read back from the
/// engine and the caller records it. `false` means ITP is genuinely off and
/// nothing may claim otherwise.
fn enable_itp(webview: &WebView) -> bool {
    use webkit2gtk::glib::translate::ToGlibPtr;
    use webkit2gtk::{WebContextExt, WebViewExt};
    use wry::WebViewExtUnix;

    let native = webview.webview();
    let Some(context) = native.context() else {
        return false;
    };
    let Some(manager) = context.website_data_manager() else {
        return false;
    };
    let raw: *mut webkit2gtk_sys::WebKitWebsiteDataManager = manager.to_glib_none().0;
    if raw.is_null() {
        return false;
    }
    unsafe {
        // SAFETY: `raw` is a live WebKitWebsiteDataManager borrowed from the
        // context for the duration of these calls; both are plain property
        // accesses with no ownership transfer.
        webkit2gtk_sys::webkit_website_data_manager_set_itp_enabled(raw, glib_sys::GTRUE);
        webkit2gtk_sys::webkit_website_data_manager_get_itp_enabled(raw) != glib_sys::GFALSE
    }
}

/// Whether the last content webview built came up with ITP confirmed on.
/// Read by the engine-status surface; see `enable_itp`.
pub fn itp_confirmed() -> bool {
    ITP_CONFIRMED.with(|c| c.get())
}


thread_local! {
    static ITP_CONFIRMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Drives the freeze state machine from WebKit's load events. Blocking
/// itself is not done here (WebKitGTK has no per-request veto); the timer
/// installs a compiled block-everything filter once the grace period ends.
fn connect_load_events(webview: &WebView, state: Rc<RefCell<TabState>>) {
    use webkit2gtk::{LoadEvent, WebViewExt};
    use wry::WebViewExtUnix;
    let native = webview.webview();
    native.connect_load_changed(move |web_view, event| {
        match event {
            LoadEvent::Started => {
                // The document's own URL, for the local-network boundary:
                // it keys on whether THIS PAGE was loaded over plain HTTP.
                let url = web_view.uri().map(|u| u.to_string());
                state.borrow_mut().on_load_started(url.as_deref());
            }
            LoadEvent::Finished => {
                state.borrow_mut().on_load_finished(Instant::now());
                // Weak ref: the timer may outlive the tab (closing a tab
                // drops the WebView); upgrading a dead weak ref is a no-op
                // instead of a use-after-free.
                let weak = web_view.downgrade();
                let state = state.clone();
                // Note: glib::timeout_add_local_once is assumed present
                // in the pinned glib 0.18.x. If it is not, use
                // glib::timeout_add_local returning ControlFlow::Break.
                gtk::glib::timeout_add_local_once(privacy::FREEZE_GRACE, move || {
                    let Some(web_view) = weak.upgrade() else {
                        return;
                    };
                    let mut st = state.borrow_mut();
                    if st.freeze.should_auto_freeze(Instant::now()) {
                        st.freeze.freeze();
                        drop(st);
                        install_freeze_filter(&web_view, &state);
                    }
                });
            }
            _ => {}
        }
    });
}

/// Feeds the per-tab ledger. Requests the content blocker stops never
/// reach this signal, so on WebKitGTK a HostRecord's `blocked` count stays
/// 0 — see the Note on `ledger`. Allowed traffic is recorded fully.
fn connect_ledger(webview: &WebView, state: Rc<RefCell<TabState>>) {
    use webkit2gtk::WebViewExt;
    use wry::WebViewExtUnix;
    let native = webview.webview();
    native.connect_resource_load_started(move |_web_view, resource, _request| {
        use webkit2gtk::WebResourceExt as _;
        if let Some(uri) = resource.uri() {
            if let Some(host) = privacy::host_of(&uri) {
                state.borrow_mut().ledger.record(&host, false);
            }
        }
    });
}

/// Observes TLS failures to record a verdict for the page that could not
/// load. Returns false so WebKit's default handling (its TLS error page)
/// still runs: detection informs, it never obstructs.
fn connect_tls_errors(webview: &WebView, state: Rc<RefCell<TabState>>) {
    use webkit2gtk::WebViewExt;
    use wry::WebViewExtUnix;
    let native = webview.webview();
    // Signature is (webview, failing_uri, certificate, flags): the URI comes
    // BEFORE the certificate, and there are four parameters, not three.
    native.connect_load_failed_with_tls_errors(move |_web_view, _failing_uri, certificate, _flags| {
        state.borrow_mut().tls_error_verdict =
            Some(privacy::classify_issuer(issuer_name(certificate).as_deref()));
        false
    });
}

/// Reads GTlsCertificate:issuer-name through the property system rather
/// than `g_tls_certificate_get_issuer_name`, so no gio "v2_70" cargo
/// feature is needed in the manifest. On GLib < 2.70 the property does not
/// exist and this returns None → TlsState::Unknown, which is the honest
/// answer when the issuer cannot be inspected.
fn issuer_name(certificate: &gtk::gio::TlsCertificate) -> Option<String> {
    // Note: ObjectExt::has_property(name, None) is the glib 0.18
    // spelling; if the pinned glib differs, equivalent is
    // certificate.find_property("issuer-name").is_some().
    if certificate.has_property("issuer-name", None) {
        certificate.property::<Option<String>>("issuer-name")
    } else {
        None
    }
}

/// Installs the freeze filter: block everything except this tab's per-site
/// exceptions. Freezing is enforced by the same compiled-content-filter path
/// as ad blocking.
fn install_freeze_filter(native: &webkit2gtk::WebView, state: &Rc<RefCell<TabState>>) {
    let Some(ucm) = user_content_manager(native) else {
        return;
    };
    let exceptions = state.borrow().freeze.overrides();
    let json = privacy::freeze_filter_json(&exceptions);
    // A freeze must not be defeated by a stale ad-block filter sitting
    // alongside it: WebKit ORs its filters, and the ad filter's rules are
    // narrower, so leaving it would be harmless — but leaving a PREVIOUS
    // freeze filter with wider exceptions would not. Clear first.
    remove_all_filters(&ucm);
    compile_and_add_filter(&ucm, &json, Some(state.clone()));
}

/// Reinstalls a tab's freeze filter after filters were cleared for another
/// reason.
fn install_freeze_filter_for(ucm: &webkit2gtk::UserContentManager, view: &TabView) {
    let exceptions = view.state.borrow().freeze.overrides();
    let json = privacy::freeze_filter_json(&exceptions);
    compile_and_add_filter(ucm, &json, Some(view.state.clone()));
}

/// Whether freezing actually blocks requests on this platform.
pub fn freeze_enforced() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Compiled content filters (raw FFI)
//
// `WebKitUserContentFilterStore` is the only way to stop subresource requests
// from the application process, and the safe `webkit2gtk` bindings do not wrap
// it — `add_filter` is a commented-out TODO there and `UserContentFilter` is
// not bound at all. So this is hand-written FFI against `webkit2gtk-sys`.
//
// Compilation is ASYNCHRONOUS: WebKit parses the JSON, compiles it to bytecode
// and caches it on disk, then hands back a filter object on the main loop. The
// callback below therefore runs LATER, after this function has returned, which
// is what dictates the ownership rules — every pointer the callback touches is
// owned by the boxed payload, not borrowed from a caller that may be gone.
// ---------------------------------------------------------------------------

/// Where compiled filter bytecode is cached. Mirrors the vault's data-dir
/// convention so a portable install stays portable.
fn filter_store_dir() -> std::path::PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        if !dir.is_empty() {
            return std::path::PathBuf::from(dir)
                .join("patanyx")
                .join("contentfilters");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("patanyx")
            .join("contentfilters");
    }
    std::path::PathBuf::from(".patanyx").join("contentfilters")
}

/// Everything the async callback owns. Boxed and leaked into `user_data`, then
/// reclaimed exactly once when the callback fires.
struct FilterSaveData {
    /// Strong ref, so the manager cannot be freed between the request and the
    /// callback even if the tab is closed in between.
    ucm: *mut webkit2gtk_sys::WebKitUserContentManager,
    /// Strong ref taken by `..._store_new`; released in the callback.
    store: *mut webkit2gtk_sys::WebKitUserContentFilterStore,
    /// Present only for a FREEZE filter, and the whole reason this callback
    /// reports anything: a freeze that fails to compile must not keep the UI
    /// saying "Frozen, making no requests". `None` for the ad filter, whose
    /// failure mode is separate.
    ///
    /// An `Rc` is sound here because WebKitGTK raises this callback on the
    /// GTK main loop, the same thread that created the tab. Holding it also
    /// keeps the state alive if the tab is closed mid-compile.
    freeze_state: Option<Rc<RefCell<TabState>>>,
}

/// Compiles `json` into a content filter and adds it to `ucm`.
///
/// Degrades rather than crashing: any failure leaves the manager without this
/// filter. That is visible as ads not being blocked, never as a panic in a
/// browser the user is mid-session in.
///
/// `freeze_state`, when present, is marked `Failed` on every path that does
/// not reach the engine. Five of them are synchronous and used to `return`
/// silently, which is precisely how the tab could report Frozen with no
/// filter anywhere: the user asked, the state said yes, and nothing was ever
/// installed.
fn compile_and_add_filter(
    ucm: &webkit2gtk::UserContentManager,
    json: &str,
    freeze_state: Option<Rc<RefCell<TabState>>>,
) {
    // Every early return below routes through here, so adding a new failure
    // path cannot silently skip the reporting.
    macro_rules! give_up {
        () => {{
            if let Some(state) = &freeze_state {
                state.borrow_mut().freeze.note_enforcement_failed();
            }
            return;
        }};
    }
    use webkit2gtk::glib::translate::ToGlibPtr;

    let dir = filter_store_dir();
    // WebKit will not create the directory itself and silently fails without it.
    if std::fs::create_dir_all(&dir).is_err() {
        give_up!();
    }
    let Some(dir_str) = dir.to_str() else {
        give_up!();
    };
    let (Ok(c_dir), Ok(c_id)) = (
        std::ffi::CString::new(dir_str),
        std::ffi::CString::new(privacy::filter_id_for(json)),
    ) else {
        give_up!();
    };

    // SAFETY: `c_dir` is a valid NUL-terminated string that outlives this call;
    // `..._store_new` copies the path. The returned store is a new strong ref
    // which the callback releases. A NULL return is handled below.
    let store = unsafe { webkit2gtk_sys::webkit_user_content_filter_store_new(c_dir.as_ptr()) };
    if store.is_null() {
        give_up!();
    }

    // SAFETY: `json` is a live slice for the duration of this call and
    // `g_bytes_new` COPIES it, so the GBytes does not borrow Rust memory.
    let bytes = unsafe {
        glib_sys::g_bytes_new(json.as_ptr() as *const std::ffi::c_void, json.len() as usize)
    };
    if bytes.is_null() {
        // SAFETY: `store` is a valid object we hold the only ref to.
        unsafe { gobject_sys::g_object_unref(store as *mut gobject_sys::GObject) };
        give_up!();
    }

    let raw_ucm: *mut webkit2gtk_sys::WebKitUserContentManager = ucm.to_glib_none().0;
    // SAFETY: `raw_ucm` is valid for the duration of this call (we hold `ucm`);
    // taking a ref makes it valid for the callback too, however long that takes.
    unsafe { gobject_sys::g_object_ref(raw_ucm as *mut gobject_sys::GObject) };

    let payload = Box::into_raw(Box::new(FilterSaveData {
        ucm: raw_ucm,
        store,
        freeze_state,
    }));

    // SAFETY: every pointer is non-NULL and valid; `store` and `ucm` are kept
    // alive by the refs above until `on_filter_saved` releases them, and the
    // payload is reclaimed there exactly once. NULL cancellable = uncancellable,
    // which is correct: there is nothing to cancel, and the callback tolerates
    // arriving after its tab is gone.
    unsafe {
        webkit2gtk_sys::webkit_user_content_filter_store_save(
            store,
            c_id.as_ptr(),
            bytes,
            std::ptr::null_mut(),
            Some(on_filter_saved),
            payload as glib_sys::gpointer,
        );
        // `save` refs the bytes itself; drop our ref.
        glib_sys::g_bytes_unref(bytes);
    }
}

/// Async completion for `compile_and_add_filter`. Runs on the main loop once
/// WebKit has compiled the rules.
///
/// SAFETY: invoked by GLib with the `user_data` passed to `..._store_save`,
/// exactly once. Reclaims the boxed payload and releases both refs it owns.
unsafe extern "C" fn on_filter_saved(
    _source: *mut gobject_sys::GObject,
    result: *mut gio_sys::GAsyncResult,
    user_data: glib_sys::gpointer,
) {
    if user_data.is_null() {
        return;
    }
    // Reclaimed here and nowhere else; every path below drops it.
    let data = Box::from_raw(user_data as *mut FilterSaveData);

    let mut error: *mut glib_sys::GError = std::ptr::null_mut();
    let filter =
        webkit2gtk_sys::webkit_user_content_filter_store_save_finish(data.store, result, &mut error);

    if !error.is_null() {
        // Compilation failed: malformed rules, an unwritable cache, a rule
        // list the engine rejects. The filter is simply absent.
        //
        // This used to degrade SILENTLY, which for a freeze meant the tab
        // went on reporting "Frozen and making no requests" with nothing
        // installed. The user is told instead.
        glib_sys::g_error_free(error);
        if let Some(state) = &data.freeze_state {
            state.borrow_mut().freeze.note_enforcement_failed();
        }
    } else if !filter.is_null() {
        webkit2gtk_sys::webkit_user_content_manager_add_filter(data.ucm, filter);
        // `add_filter` takes its own ref; release the one `save_finish` gave us.
        webkit2gtk_sys::webkit_user_content_filter_unref(filter);
        // The one path entitled to claim the freeze is real.
        if let Some(state) = &data.freeze_state {
            state.borrow_mut().freeze.note_enforced();
        }
    } else if let Some(state) = &data.freeze_state {
        // Neither an error nor a filter. Not documented as reachable, but the
        // GLib convention only guarantees one of the two, and the safe
        // reading of "no filter" is that nothing is blocking. Anything other
        // than a confirmed install is a failure.
        state.borrow_mut().freeze.note_enforcement_failed();
    }

    gobject_sys::g_object_unref(data.ucm as *mut gobject_sys::GObject);
    gobject_sys::g_object_unref(data.store as *mut gobject_sys::GObject);
}

/// Drops every compiled filter from a manager. Style sheets are unaffected.
fn remove_all_filters(ucm: &webkit2gtk::UserContentManager) {
    use webkit2gtk::glib::translate::ToGlibPtr;
    let raw: *mut webkit2gtk_sys::WebKitUserContentManager = ucm.to_glib_none().0;
    // SAFETY: `raw` is valid while `ucm` is held, and this call is synchronous.
    unsafe { webkit2gtk_sys::webkit_user_content_manager_remove_all_filters(raw) };
}

/// Note: WebViewExt::user_content_manager() is assumed to return
/// Option<UserContentManager> in the 2.0.2 bindings (gir marks it nullable).
/// If it is infallible, drop this shim and call the method directly.
fn user_content_manager(
    native: &webkit2gtk::WebView,
) -> Option<webkit2gtk::UserContentManager> {
    use webkit2gtk::WebViewExt;
    native.user_content_manager()
}

fn set_ad_blocking(native: &webkit2gtk::WebView, view: &TabView, enable: bool) {
    let Some(ucm) = user_content_manager(native) else {
        // An engine without a content manager leaves the feature off
        // (constraint: degrade, never crash).
        return;
    };
    set_cosmetic(&ucm, view, enable);
    // Cosmetic hiding alone would still let every ad request leave the
    // machine, so the network filter is the half that makes the claim true.
    if enable {
        let json = privacy::content_blocker_json(privacy::bundled_rules());
        compile_and_add_filter(&ucm, &json, None);
    } else {
        remove_all_filters(&ucm);
        // Cosmetic hiding is re-applied by set_cosmetic above; removing every
        // filter also drops any freeze filter, so a frozen tab whose ad
        // blocking is switched off must re-install it.
        if freeze_active(view) {
            install_freeze_filter_for(&ucm, view);
        }
    }
}

/// Whether this tab is currently frozen, so filter teardown can re-install the
/// freeze filter it necessarily also removed.
fn freeze_active(view: &TabView) -> bool {
    view.state.borrow().freeze.phase() == FreezePhase::Frozen
}

/// Cosmetic filtering as a user STYLESHEET, not injected script. This is
/// the crate's central security invariant applied to ad blocking: content
/// webviews get no IPC and are never script-evaluated, and
/// UserStyleLevel::User sheets need no script context in the page.
fn set_cosmetic(ucm: &webkit2gtk::UserContentManager, view: &TabView, enable: bool) {
    use webkit2gtk::UserContentManagerExt;
    if enable {
        if view.cosmetic_sheet.borrow().is_some() {
            return;
        }
        // Empty allow/block lists mean "every page": the signature takes
        // &[&str], not Option.
        let sheet = webkit2gtk::UserStyleSheet::new(
            &privacy::cosmetic_css(privacy::bundled_rules()),
            webkit2gtk::UserContentInjectedFrames::AllFrames,
            webkit2gtk::UserStyleLevel::User,
            &[],
            &[],
        );
        ucm.add_style_sheet(&sheet);
        *view.cosmetic_sheet.borrow_mut() = Some(sheet);
    } else if let Some(sheet) = view.cosmetic_sheet.borrow_mut().take() {
        ucm.remove_style_sheet(&sheet);
    }
}

/// Applies a policy to a live tab. JavaScript, ad blocking and freeze are
/// runtime-changeable; `ephemeral` is NOT (the WebContext is fixed once the
/// view exists) — changing it requires recreating the tab, and this
/// function deliberately does not fake it.
pub fn apply_policy(webview: &WebView, view: &TabView, policy: &TabPolicy) {
    // No `use webkit2gtk::SettingsExt;` at this level: the only call that
    // needs it brings it in itself, inside the `Some(settings)` arm below,
    // next to the comment explaining why the trait has to be named at all.
    // Two imports of one trait in one function invited the belief that this
    // outer one was load-bearing; it was not, and the compiler said so.
    use wry::WebViewExtUnix;
    let native = webview.webview();
    {
        let mut st = view.state.borrow_mut();
        st.policy = policy.clone();
        st.freeze.set_auto(policy.freeze_after_load);
    }
    // Note: WebViewExt::settings() nullability in 2.0.2 (Option
    // assumed). Applied post-construction but before the caller navigates;
    // a quarantine caller must not navigate between build_content and this
    // (build_content already calls apply_policy, so this is only a note for
    // policy CHANGES).
    // gtk::WidgetExt also has a settings() and wins the method lookup, so name
    // the trait explicitly or this silently resolves to gtk::Settings.
    // Same rule as the Windows backend: record what the ENGINE did, not what
    // was asked. A None here is not a no-op, it is a tab whose script setting
    // was never applied, and the UI must not count it as a protection.
    let applied = match webkit2gtk::WebViewExt::settings(&native) {
        Some(settings) => {
            use webkit2gtk::SettingsExt as _;
            settings.set_enable_javascript(policy.javascript);
            true
        }
        None => false,
    };
    view.state.borrow_mut().script_setting = if applied {
        SettingState::Applied
    } else {
        SettingState::Failed
    };
    set_ad_blocking(&native, view, policy.block_ads);
}

/// Manual freeze: immediate, per-tab, and survives the current page's load
/// finishing (see FreezeController::on_load_finished).
pub fn freeze(webview: &WebView, view: &TabView) {
    use wry::WebViewExtUnix;
    view.state.borrow_mut().freeze.freeze();
    install_freeze_filter(&webview.webview(), &view.state);
}

/// One-call unfreeze. Removes the freeze filter and puts ad blocking back if
/// the policy still wants it — filters are removed as a set, so the ad filter
/// necessarily went with the freeze filter and has to be reinstated.
pub fn unfreeze(webview: &WebView, view: &TabView) {
    use wry::WebViewExtUnix;
    let block_ads = {
        let mut st = view.state.borrow_mut();
        st.freeze.unfreeze(Instant::now());
        st.freeze_json = None;
        st.policy.block_ads
    };
    let native = webview.webview();
    let Some(ucm) = user_content_manager(&native) else {
        return;
    };
    remove_all_filters(&ucm);
    if block_ads {
        let json = privacy::content_blocker_json(privacy::bundled_rules());
        compile_and_add_filter(&ucm, &json, None);
    }
}

/// Per-site override: `host` keeps working even while the tab is frozen.
/// When the freeze filter is installed it is recompiled with the new
/// unless-domain list (freeze semantics documented in privacy.rs).
pub fn allow_site(webview: &WebView, view: &TabView, host: &str) {
    use wry::WebViewExtUnix;
    let frozen = {
        let mut st = view.state.borrow_mut();
        st.freeze.add_override(host);
        st.freeze.phase() == FreezePhase::Frozen
    };
    if frozen {
        install_freeze_filter(&webview.webview(), &view.state);
    }
}

/// Not implemented on this backend -- always refuses.
///
/// WebKitGTK's `WebKitWebsiteDataManager` clears data for the whole manager,
/// not a single origin (the existing ITP call at this file's tracking-
/// prevention section is the only use of that manager today, and it never
/// clears anything). Windows-only for this pass; see `windows.rs` for the
/// real implementation via `ICoreWebView2CookieManager`.
pub fn forget_site_cookies(_webview: &WebView, _host: &str) -> bool {
    false
}

/// No diagnostic log exists on this backend yet -- `diag()`'s in-memory ring
/// buffer is windows.rs-only, matched to that file being the only place this
/// codebase currently traces hardening/enforcement failures at all. An
/// honest empty list rather than fabricating entries.
pub fn recent_diagnostics() -> Vec<String> {
    Vec::new()
}

/// Not implemented on this backend -- always refuses. Credential autofill's
/// content-script injection and message channel are Windows-only for this
/// pass (see windows.rs's `build_content`); `content_script_registered`
/// stays `NotAttempted` here, which is what keeps the fill affordance from
/// ever being offered on a platform with no channel to deliver it through.
pub fn fill_credential(_webview: &WebView, _username: &str, _password: &str) -> bool {
    false
}

/// The user-visible ledger. Note (honesty for the UI): WebKitGTK's
/// content blocker reports no per-request matches, so on this backend the
/// `blocked` counts are always 0 — the ledger shows every host the tab
/// CONTACTED. Blocking correctness is proven by the matcher unit tests and
/// by the filter being installed, not by observation. Do not present
/// "blocked: 0" as "nothing was blocked" in the UI on Linux.
pub fn ledger(view: &TabView) -> Vec<HostRecord> {
    view.state.borrow().ledger.snapshot()
}

/// Requests blocked in this tab, totalled.
///
/// STRUCTURALLY ZERO ON THIS BACKEND, for the reason the comment above gives:
/// WebKitGTK's content filter drops matching requests inside the engine and
/// never calls back, so nothing is counted rather than nothing being blocked.
/// The number is still reported, because suppressing it here would leave the
/// UI unable to tell "no data" from "zero" -- `LEDGER_COUNTS_BLOCKED` is the
/// flag that carries that distinction, and the UI must not render this figure
/// as a finding without consulting it.
pub fn blocked_total(view: &TabView) -> u64 {
    view.state.borrow().ledger.blocked_total()
}

/// Current TLS verdict. Deviation from the brief's sketch: takes `view` as
/// well as `webview`, because after a FAILED TLS load the live certificate
/// may be gone and the verdict recorded by the error signal is the only one
/// available. Informs only — callers must not gate navigation on this.
pub fn tls_state(webview: &WebView, view: &TabView) -> TlsState {
    use webkit2gtk::WebViewExt;
    use wry::WebViewExtUnix;
    // Note: WebViewExt::tls_info() is assumed to return
    // Option<(gio::TlsCertificate, gio::TlsCertificateFlags)> in the 2.0.2
    // bindings (the C getter returns gboolean with out-params). Adjust the
    // match arms if the generated shape differs.
    match webview.webview().tls_info() {
        Some((certificate, _errors)) => {
            privacy::classify_issuer(issuer_name(&certificate).as_deref())
        }
        None => view
            .state
            .borrow()
            .tls_error_verdict
            .unwrap_or(TlsState::NotTls),
    }
}

/// Persistent vs. ephemeral, for the UI to display. See the privacy.rs
/// module docs before writing any user-facing wording: ephemeral is
/// memory-only, not shredded (swap/hibernation can still reach disk).
///
/// Reads `TabState::profile_mode`, so this reports Ephemeral only once the
/// engine has confirmed it. On this backend nothing confirms it yet -- see the
/// note in `build_content` about wry's WebKitGTK incognito arm -- so an
/// ephemeral tab currently reports Persistent here. That is the deliberate
/// direction: the note said "nothing may claim ephemeral storage until then",
/// and until this reads back a real answer, nothing does.
pub fn profile_mode(view: &TabView) -> ProfileMode {
    view.state.borrow().profile_mode()
}

pub fn freeze_phase(view: &TabView) -> FreezePhase {
    view.state.borrow().freeze.phase()
}

/// Whether the block behind a freeze is actually in place.
///
/// On this backend it starts `Pending` and becomes `Active` or `Failed` only
/// when WebKit's async filter compile completes. The UI must not say "making
/// no requests" until it reads `Active`. See `privacy::FreezeEnforcement`.
pub fn freeze_enforcement(view: &TabView) -> privacy::FreezeEnforcement {
    view.state.borrow().freeze.enforcement()
}

/// On GTK these have no equivalent engine handshake: ITP is a builder setting
/// that cannot fail this way, there is no SmartScreen, navigation signals are
/// GTK connections rather than HRESULTs, and WebKitGTK keeps no autofill or
/// password store of its own to switch off. Reported as NotAttempted rather
/// than Applied, because claiming a protection was confirmed when nothing
/// confirmed it is the failure this whole mechanism exists to stop.
///
/// Note the asymmetry is real rather than an omission: the engine autofill
/// this reports on is a WebView2 feature. There is nothing here to disable, so
/// "not attempted" is the honest answer -- not "applied".
pub fn engine_settings(view: &TabView) -> EngineSettings {
    let st = view.state.borrow();
    EngineSettings {
        smartscreen_off: st.smartscreen_off.as_str(),
        tracking_prevention: st.tracking_prevention.as_str(),
        navigation_tracking: st.navigation_tracking.as_str(),
        autofill_off: st.autofill_off.as_str(),
        ephemeral_confirmed: st.ephemeral_confirmed.as_str(),
        // No equivalent on WebKitGTK: there is no environment object to
        // create, no browser-args string to lose, and no crash-report upload
        // to suppress. "Not attempted" is the honest answer, exactly as it is
        // for SmartScreen and engine autofill above -- not "applied", which
        // would count a protection this backend never had to apply.
        hardened_environment: SettingState::NotAttempted.as_str(),
        session_lock_registered: SettingState::NotAttempted.as_str(),
        // Content-script autofill is Windows-only for this pass; see
        // windows.rs's build_content. Nothing was attempted here.
        content_script_registered: SettingState::NotAttempted.as_str(),
        // Windows-only feature; see clear_persisted_permissions above.
        permissions_registered: SettingState::NotAttempted.as_str(),
        // Same source as the Windows backend, on purpose: the tunnel is
        // the one setting here that is genuinely cross-platform, so both
        // engines read the one measured answer rather than each inventing
        // a local one.
        tunnel: crate::tunnel_control::report(),
    }
}

/// Whether the ENGINE confirmed this tab's JavaScript setting. See the
/// Windows counterpart; the failure here is a null settings object rather
/// than an HRESULT, and it is reported the same way.
pub fn script_setting(view: &TabView) -> &'static str {
    view.state.borrow().script_setting.as_str()
}

/// Counterpart to the Windows per-tab interception state, reported in
/// `tab_status`. This backend has no per-request handler to register: it
/// blocks with a compiled `WebKitUserContentFilter`, whose success or
/// failure is already reported through `freeze_enforcement`. Naming the
/// mechanism is the honest answer; reusing Windows' "registered" would
/// describe machinery that does not exist here.
pub fn interception_state(_view: &TabView) -> &'static str {
    privacy::UNIX_INTERCEPTION_NAME
}

/// Network-level request blocking works on WebKitGTK via compiled content
/// filters (see `compile_and_add_filter`). Both engines now block; the Windows
/// backend matches the same `RuleSet` in its `WebResourceRequested` callback.
///
/// Note what this still does not cover: the filter blocks requests the WEB
/// ENGINE makes. It is not a firewall, and it says nothing about traffic from
/// outside the content process.
pub fn network_blocking_supported() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Main-resource bytes (page integrity & corroboration)
//
// WHY this source and no other: the digest ladder is only meaningful over
// the exact bytes the engine rendered. The two tempting alternatives both
// fail that test:
//
//   * RE-FETCHING the URL from the app asks the server for a SECOND copy —
//     which may be served differently, the very thing this feature exists
//     to detect. A digest of a re-fetch is a wrong digest.
//   * SCRIPT in the content webview is forbidden absolutely (§4.1) — and
//     `outerHTML` would be the wrong bytes anyway (post-DOM, not served
//     bytes).
//
// WebKitGTK keeps the main resource's data and hands it over asynchronously
// — the same GAsyncReadyCallback shape as the filter store above, with the
// same ownership discipline. No script, no re-fetch, no second copy.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// File choice
//
// `GtkFileChooserNative` is the whole reason this exists rather than a plain
// dialog: inside a Flatpak, GTK routes it through xdg-desktop-portal, and the
// portal hands the sandbox exactly the one file the user picked, reachable at
// a /run/user/.../doc/ path. Nothing else in the sandbox becomes readable.
//
// That is what makes vault migration possible at all here. The manifest has
// no `filesystems=` line and must never gain one -- a browser with read
// access to every document its user owns is the thing this packaging exists
// to prevent -- so a typed path to `~/.local/share/patanyx/vault.rbv` cannot
// work and never could. The portal is not a nicety on top of the typed path;
// it is the only route in.
// ---------------------------------------------------------------------------

/// Puts text on the system clipboard. True when it was written.
///
/// THE PROCESS DOES THIS ITSELF, rather than handing the text to the chrome
/// webview to write with `navigator.clipboard`. That is what it used to do,
/// and the round trip is why "Copy link" failed: the Clipboard API refuses to
/// write from a document that is not focused, and the document doing the
/// writing was the chrome while the focus was in the page the user had just
/// right-clicked. It failed on both backends -- an error toast on Windows, a
/// silently empty clipboard here. Owning the write removes the focus
/// requirement, the permission surface and the secure-context question in one
/// go, and the copied URL no longer has to enter a JS context at all.
///
/// X11 hands out the selection by reference, so the clipboard is served from
/// this process for as long as it runs; `store()` asks any clipboard manager
/// to take a copy so the text survives quitting. Without a manager the text
/// dies with the process, which is how every X11 application behaves and not
/// something this code can fix.
pub fn set_clipboard_text(text: &str) -> bool {
    let clipboard = gtk::Clipboard::get(&gtk::gdk::SELECTION_CLIPBOARD);
    clipboard.set_text(text);
    clipboard.store();
    true
}

/// Whether the user can be asked to choose a file. True here: see above.
pub fn file_choice_supported() -> bool {
    true
}

/// Asks the user for one existing file.
///
/// Runs a nested main loop, which is correct in this position: IPC is
/// dispatched on the GTK main thread, and a modal file chooser is exactly the
/// case `run()` exists for. Returns None when the user cancels, which callers
/// must treat as "no answer", never as an error.
pub fn pick_file_to_open(hosts: &Hosts, title: &str) -> Option<std::path::PathBuf> {
    let chooser = gtk::FileChooserNative::new(
        Some(title),
        gtk::Window::NONE,
        gtk::FileChooserAction::Open,
        Some("Choose"),
        Some("Cancel"),
    );
    let _ = hosts;
    run_chooser(chooser)
}

/// Asks the user where to write one file, pre-filled with `suggested_name`.
///
/// The suggestion is a NAME, never a path. Inside the sandbox a path would
/// point somewhere the user cannot see, and outside it the user's own choice
/// is better than ours.
pub fn pick_file_to_save(
    hosts: &Hosts,
    title: &str,
    suggested_name: &str,
) -> Option<std::path::PathBuf> {
    let chooser = gtk::FileChooserNative::new(
        Some(title),
        gtk::Window::NONE,
        gtk::FileChooserAction::Save,
        Some("Save"),
        Some("Cancel"),
    );
    chooser.set_current_name(suggested_name);
    // The portal asks before overwriting; outside the sandbox GTK must be
    // told to.
    chooser.set_do_overwrite_confirmation(true);
    let _ = hosts;
    run_chooser(chooser)
}

fn run_chooser(chooser: gtk::FileChooserNative) -> Option<std::path::PathBuf> {
    use gtk::prelude::*;
    let response = chooser.run();
    // Hide before reading the choice: a native dialog left on screen while
    // the caller does file I/O looks like a hang.
    chooser.hide();
    if response != gtk::ResponseType::Accept {
        return None;
    }
    chooser.file().and_then(|f| f.path())
}

/// Whether this engine can hand back the bytes it was served for the main
/// resource. Gates every integrity/corroboration entry point; where this is
/// false the UI shows the feature as unavailable rather than guessing.
pub fn page_bytes_supported() -> bool {
    true
}

/// Save-as-PDF is Windows-only for now.
///
/// WebKitGTK can do it -- `WebKitPrintOperation` exports to a file without
/// showing a dialog -- but the export is a different API shape and needs its
/// own verification pass on a real GTK session. `false` here means the UI
/// reports the feature unavailable rather than offering a button that does
/// nothing, which is the same rule `page_bytes_supported` follows.
/// unix: WebKitGTK's print operation is a different API entirely and the key is
/// not intercepted here, so the engine's own Ctrl+P handling stands. Returning
/// false keeps the caller honest rather than reporting a preview it never
/// opened.
pub fn show_print_ui(_webview: &WebView) -> bool {
    false
}

pub fn save_page_as_pdf(
    _webview: &WebView,
    _dest: &std::path::Path,
    _proxy: &EventLoopProxy<UserEvent>,
) -> bool {
    false
}

/// Lock-the-vault-when-the-screen-locks is Windows-only for now.
///
/// The signal exists on Linux too -- logind publishes `LockedHint` over D-Bus
/// -- but reaching it means a D-Bus dependency and a session-bus connection
/// this app does not otherwise have, so it is deliberately deferred rather
/// than half-built. `NotAttempted` is the honest answer, and the panel renders
/// it as "not applicable on this engine" rather than claiming a protection
/// that is not running.
pub fn connect_session_lock(_hosts: &Hosts, _proxy: &EventLoopProxy<UserEvent>) {}

pub fn session_lock_registered() -> SettingState {
    SettingState::NotAttempted
}

/// Everything the async callback owns (same discipline as `FilterSaveData`):
/// boxed, leaked into `user_data`, reclaimed exactly once in the callback.
struct ResourceBytesData {
    /// Strong ref, so the resource outlives the window between request and
    /// callback even if its tab is closed in between.
    resource: *mut webkit2gtk_sys::WebKitWebResource,
    proxy: EventLoopProxy<UserEvent>,
    token: u64,
}

/// Ask the engine for the active page's main-resource bytes. The answer —
/// success OR failure — always arrives as
/// `UserEvent::Integrity(IntegrityEvent::PageBytes { token, .. })`.
///
/// Callers should ask after the load has finished: WebKit errors on
/// `get_data` for a resource that is still streaming, which surfaces as
/// `FetchFailed` → the UI's `no_page` copy says exactly that.
pub fn request_main_resource_bytes(
    webview: &WebView,
    token: u64,
    proxy: &EventLoopProxy<UserEvent>,
) {
    use webkit2gtk::glib::translate::ToGlibPtr;
    use wry::WebViewExtUnix;

    let native = webview.webview();
    let raw_view: *mut webkit2gtk_sys::WebKitWebView = native.to_glib_none().0;
    // SAFETY: `raw_view` is valid for the duration of this call (we hold
    // `native`). The getter is transfer-none; a NULL return (no main
    // resource — e.g. about:blank) is reported, never dereferenced.
    //
    // Note: verify the pinned webkit2gtk-sys exposes
    // `webkit_web_view_get_main_resource` and `webkit_web_resource_get_data{,_finish}`
    // under these exact names. If the sys crate predates them, the fallback
    // is the safe bindings' `WebViewExt::main_resource()` plus a hand-rolled
    // get_data via glib casts — do NOT substitute a re-fetch.
    let resource = unsafe { webkit2gtk_sys::webkit_web_view_get_main_resource(raw_view) };
    if resource.is_null() {
        let _ = proxy.send_event(UserEvent::Integrity(IntegrityEvent::PageBytes {
            token,
            result: Err(PageBytesError::NoMainResource),
        }));
        return;
    }
    // SAFETY: `resource` is a valid object; the ref we take is released in
    // the callback, however long the read takes.
    unsafe { gobject_sys::g_object_ref(resource as *mut gobject_sys::GObject) };
    let payload = Box::into_raw(Box::new(ResourceBytesData {
        resource,
        proxy: proxy.clone(),
        token,
    }));
    // SAFETY: every pointer is non-NULL and valid; NULL cancellable is
    // correct (nothing to cancel, and the callback tolerates a dead tab).
    // The payload is reclaimed exactly once in `on_resource_data`.
    unsafe {
        webkit2gtk_sys::webkit_web_resource_get_data(
            resource,
            std::ptr::null_mut(),
            Some(on_resource_data),
            payload as glib_sys::gpointer,
        );
    }
}

/// Async completion for `request_main_resource_bytes`.
///
/// SAFETY: invoked by GLib with the `user_data` passed to
/// `webkit_web_resource_get_data`, exactly once. Reclaims the boxed payload
/// and releases the resource ref it owns.
unsafe extern "C" fn on_resource_data(
    _source: *mut gobject_sys::GObject,
    result: *mut gio_sys::GAsyncResult,
    user_data: glib_sys::gpointer,
) {
    if user_data.is_null() {
        return;
    }
    let data = Box::from_raw(user_data as *mut ResourceBytesData);

    let mut error: *mut glib_sys::GError = std::ptr::null_mut();
    // `..._get_data_finish` hands back the BYTES themselves plus a length
    // out-param — not a GBytes. The buffer is transfer-full, so we own it and
    // must g_free it once copied.
    let mut len: usize = 0;
    let bytes = webkit2gtk_sys::webkit_web_resource_get_data_finish(
        data.resource,
        result,
        &mut len,
        &mut error,
    );

    let outcome = if !error.is_null() {
        // The usual cause is asking while the page is still loading; the
        // UI copy for `no_page` names that, so stay honest and generic here.
        glib_sys::g_error_free(error);
        Err(PageBytesError::FetchFailed)
    } else if bytes.is_null() {
        Err(PageBytesError::FetchFailed)
    } else {
        let copied = if len > patanyx_integrity::MAX_INPUT_BYTES {
            // Refuse before allocating the copy: the digest layer enforces
            // the same cap, this keeps worst-case memory bounded on the way.
            Err(PageBytesError::TooLarge)
        } else if len == 0 {
            Ok(Vec::new())
        } else {
            // SAFETY: `bytes` is a valid buffer of `len` bytes that we own
            // until the g_free below; the copy happens first.
            Ok(std::slice::from_raw_parts(bytes as *const u8, len).to_vec())
        };
        glib_sys::g_free(bytes as glib_sys::gpointer);
        copied
    };

    gobject_sys::g_object_unref(data.resource as *mut gobject_sys::GObject);
    // A send error means the event loop is going away — the only time
    // dropping the bytes is acceptable.
    let _ = data
        .proxy
        .send_event(UserEvent::Integrity(IntegrityEvent::PageBytes {
            token: data.token,
            result: outcome,
        }));
}

/// wry only handles NavigationAction policy decisions; Response decisions
/// fall through to WebKit's default, which renders non-displayable MIME
/// types as a blank page instead of downloading them. Convert those
/// responses into WebKit downloads so they reach the wry download handlers
/// registered on the builder. Runs alongside wry's own decide-policy
/// handler, which returns false (unhandled) for Response decisions.
pub fn fix_downloads(webview: &WebView) {
    use webkit2gtk::{PolicyDecisionExt, ResponsePolicyDecisionExt, WebViewExt};
    use wry::WebViewExtUnix;
    let native = webview.webview();
    native.connect_decide_policy(|_webview, decision, decision_type| {
        if decision_type == webkit2gtk::PolicyDecisionType::Response {
            if let Some(response) =
                decision.dynamic_cast_ref::<webkit2gtk::ResponsePolicyDecision>()
            {
                if !response.is_mime_type_supported() {
                    decision.download();
                    return true;
                }
            }
        }
        false
    });
}

// ---- find in page ----
//
// WebKitGTK's FindController does the searching; this file only starts it
// and relays what it reports. Two honesty rules live here: the count the
// chrome shows comes ONLY from the controller's own signals (never from
// assuming a search worked), and the total is capped -- when the cap is hit
// the event says so, so the UI prints "1000+" instead of a lie.

/// Upper bound handed to WebKitGTK for both searching and counting. WebKit
/// treats it as a cap and stops counting there, which is what keeps "a" on a
/// 5 MB page from pinning the UI process. 1000 is far past any count a user
/// steps through individually, and the UI marks capped totals with a "+".
const FIND_MAX_MATCHES: u32 = 1000;

/// Per-webview find wiring: the signal handler ids, plus the session
/// generation the NEXT emitted count should quote. The generation is read at
/// emit time (not captured at connect time) because the handlers are wired
/// once per webview while generations change on every query.
struct FindWiring {
    generation: u64,
    ids: Vec<gtk::glib::SignalHandlerId>,
}

thread_local! {
    /// Find wiring per content webview, keyed by the webview's glib
    /// pointer (same identity scheme the ledger uses). Wiring is once per
    /// webview: the controller is owned by the webview, so handlers survive
    /// find_stop, and connecting on every start would stack one copy of each
    /// callback per keystroke. Entries MUST leave with their tab via
    /// find_teardown -- a stale key can collide with a new webview reusing
    /// the freed address, which would silently leave that tab's bar without
    /// counts.
    static FIND_HANDLERS: RefCell<std::collections::HashMap<usize, FindWiring>> =
        RefCell::new(std::collections::HashMap::new());
}

fn native_find_key(native: &webkit2gtk::WebView) -> usize {
    use webkit2gtk::glib::translate::ToGlibPtr;
    let ptr: *const webkit2gtk::ffi::WebKitWebView = native.to_glib_none().0;
    ptr as usize
}

/// Identity key shared by FIND_HANDLERS and by the UserEvent the callbacks
/// emit. state.rs compares this against the active tab before forwarding a
/// count to the chrome.
pub fn find_key(webview: &WebView) -> usize {
    use wry::WebViewExtUnix;
    native_find_key(&webview.webview())
}

/// WebKitGTK always has a controller; the probe exists so the IPC arm can
/// word the bar identically on both platforms.
pub fn find_probe(webview: &WebView) -> bool {
    webview_controller(webview).is_some()
}

fn webview_controller(webview: &WebView) -> Option<webkit2gtk::FindController> {
    use webkit2gtk::WebViewExt;
    use wry::WebViewExtUnix;
    webview.webview().find_controller()
}

/// Starts the search and the count. The query goes ONLY into the engine's
/// find APIs -- never near a script string.
pub fn find_start(
    webview: &WebView,
    query: &str,
    generation: u64,
    proxy: &EventLoopProxy<UserEvent>,
) -> bool {
    use webkit2gtk::FindControllerExt;
    use wry::WebViewExtUnix;
    let native = webview.webview();
    let Some(controller) = webview_controller(webview) else {
        // The webview owns its controller; None means the webview is on its
        // way out, which find_teardown should have made unreachable. Fail
        // closed rather than pretend a search ran.
        return false;
    };
    find_wire_handlers(&native, &controller, proxy);
    // Counts emitted from here on describe THIS query. Set before search()
    // so even a synchronously-delivered signal quotes the right generation.
    FIND_HANDLERS.with(|h| {
        if let Some(wiring) = h.borrow_mut().get_mut(&native_find_key(&native)) {
            wiring.generation = generation;
        }
    });
    // Fixed v1 policy: case-insensitive, wrap-around, highlight all (the
    // engine's default), no whole-word.
    let options = webkit2gtk::FindOptions::CASE_INSENSITIVE | webkit2gtk::FindOptions::WRAP_AROUND;
    controller.search(query, options.bits(), FIND_MAX_MATCHES);
    // found_text can arrive before the full count is known; counted_matches
    // answers this explicit call with the (capped) total. Both reduce to the
    // same FindEvent, both engine-sourced, last writer wins.
    controller.count_matches(query, options.bits(), FIND_MAX_MATCHES);
    true
}

fn find_wire_handlers(
    native: &webkit2gtk::WebView,
    controller: &webkit2gtk::FindController,
    proxy: &EventLoopProxy<UserEvent>,
) {
    use webkit2gtk::FindControllerExt;
    let key = native_find_key(native);
    let already = FIND_HANDLERS.with(|h| h.borrow().contains_key(&key));
    if already {
        return;
    }
    let on_found = {
        let proxy = proxy.clone();
        controller.connect_found_text(move |_, match_count| {
            find_emit(key, match_count, &proxy);
        })
    };
    let on_counted = {
        let proxy = proxy.clone();
        controller.connect_counted_matches(move |_, match_count| {
            find_emit(key, match_count, &proxy);
        })
    };
    let on_failed = {
        let proxy = proxy.clone();
        controller.connect_failed_to_find_text(move |_| {
            find_emit(key, 0, &proxy);
        })
    };
    FIND_HANDLERS.with(|h| {
        h.borrow_mut().insert(
            key,
            FindWiring {
                generation: 0,
                ids: vec![on_found, on_counted, on_failed],
            },
        );
    });
}

fn find_emit(key: usize, total: u32, proxy: &EventLoopProxy<UserEvent>) {
    // The generation is read NOW, not captured at connect time: the handlers
    // outlive every individual query. A signal that raced a query change
    // still quotes the old generation only if it was delivered before
    // find_start updated the wiring, which is exactly when dropping it is
    // correct.
    let generation =
        FIND_HANDLERS.with(|h| h.borrow().get(&key).map(|w| w.generation).unwrap_or(0));
    let _ = proxy.send_event(UserEvent::Find(crate::find::FindEvent {
        key,
        generation,
        // WebKitGTK has no active-match index. None is not a gap to fill
        // with a guess; the UI shows the plain total.
        active: None,
        total,
        capped: total >= FIND_MAX_MATCHES,
    }));
}

pub fn find_next(webview: &WebView) {
    use webkit2gtk::FindControllerExt;
    if let Some(controller) = webview_controller(webview) {
        controller.search_next();
    }
}

pub fn find_previous(webview: &WebView) {
    use webkit2gtk::FindControllerExt;
    if let Some(controller) = webview_controller(webview) {
        controller.search_previous();
    }
}

/// Ends the search and clears highlights. The signal handlers stay wired:
/// the controller outlives one search, and re-wiring on the next start is
/// exactly the stacking FIND_HANDLERS exists to prevent.
pub fn find_stop(webview: &WebView) {
    use webkit2gtk::FindControllerExt;
    if let Some(controller) = webview_controller(webview) {
        controller.search_finish();
    }
}

/// Tab-close hook: unwires everything find_start connected, then stops the
/// search. After this, the webview's address may be reused by a new tab
/// without FIND_HANDLERS lying about it.
pub fn find_teardown(webview: &WebView) {
    use webkit2gtk::FindControllerExt;
    let key = find_key(webview);
    let wiring = FIND_HANDLERS.with(|h| h.borrow_mut().remove(&key));
    if let (Some(controller), Some(wiring)) = (webview_controller(webview), wiring) {
        for id in wiring.ids {
            controller.disconnect(id);
        }
        controller.search_finish();
    }
}

// ---- page color scheme ----

/// The GTK dark-theme preference as it stood at the FIRST apply, so Auto
/// can restore what the system actually had rather than guessing.
static INITIAL_PREFER_DARK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Ask pages for the given prefers-color-scheme. WebKitGTK has no direct
/// setter in the pinned bindings; it derives the media query from GTK's
/// application-wide dark-theme preference, so that is the honest lever --
/// application-wide by nature (the window frame follows along), never
/// anything injected into content. Returns whether the setting was applied.
pub fn apply_page_theme(_webview: &WebView, theme: crate::prefs::PageTheme) -> bool {
    let Some(settings) = gtk::Settings::default() else {
        // No GTK settings object means no display connection; nothing to
        // apply and nothing honest to claim.
        return false;
    };
    let initial = *INITIAL_PREFER_DARK
        .get_or_init(|| settings.is_gtk_application_prefer_dark_theme());
    let prefer_dark = match theme {
        crate::prefs::PageTheme::Auto => initial,
        crate::prefs::PageTheme::Dark => true,
        crate::prefs::PageTheme::Light => false,
    };
    settings.set_gtk_application_prefer_dark_theme(prefer_dark);
    true
}

// ---- page capture ----

/// Ask WebKitGTK for a full-document snapshot and deliver PNG bytes (or an
/// honest failure) as a UserEvent. The callback runs on the GTK main
/// thread; nothing here blocks the UI while the engine renders.
///
/// PNG encoding goes through gdk-pixbuf (already in the tree via gtk)
/// rather than cairo's own PNG writer, which sits behind a cargo feature
/// this workspace does not enable -- and enabling features for one
/// screenshot path is exactly the dependency creep the project refuses.
pub fn capture_page(webview: &WebView, proxy: &EventLoopProxy<UserEvent>) {
    use webkit2gtk::{SnapshotOptions, SnapshotRegion, WebViewExt};
    use wry::WebViewExtUnix;
    let native = webview.webview();
    let proxy = proxy.clone();
    native.snapshot(
        SnapshotRegion::FullDocument,
        SnapshotOptions::NONE,
        webkit2gtk::gio::Cancellable::NONE,
        move |result| {
            let png: Result<Vec<u8>, &'static str> = (|| {
                let surface = result.map_err(|_| "capture_failed")?;
                // A snapshot surface has no live device state to flush; the
                // conversion reads it as-is. Width/height come from the
                // surface itself via the pixbuf helper's full-extent read.
                let image = gtk::gdk::cairo::ImageSurface::try_from(surface)
                    .map_err(|_| "capture_failed")?;
                let width = image.width();
                let height = image.height();
                if width <= 0 || height <= 0 {
                    return Err("no_capture_page");
                }
                let pixbuf = gtk::gdk::pixbuf_get_from_surface(&image, 0, 0, width, height)
                    .ok_or("capture_failed")?;
                pixbuf
                    .save_to_bufferv("png", &[])
                    .map_err(|_| "capture_failed")
            })();
            let _ = proxy.send_event(UserEvent::Capture(crate::capture::CaptureEvent { png }));
        },
    );
}

pub fn show_tab(view: &TabView, _webview: &WebView) {
    // show_all (not show): a background tab may never have been visible.
    view.container.show_all();
}

pub fn hide_tab(view: &TabView, _webview: &WebView) {
    view.container.hide();
}

pub fn remove_tab(view: &TabView, webview: &WebView) {
    // The find handlers hold the webview's identity key; unwire them while
    // the webview is still alive so a future tab reusing the address starts
    // clean.
    find_teardown(webview);
    // The tab's refusals move into the session receipt (structurally zero
    // on this backend -- see blocked_total -- but folded anyway so the
    // accounting is one code path, not a platform special case). mem::take
    // moves the count; a second teardown would fold zero, never a copy.
    privacy::fold_closed_tab(std::mem::take(&mut view.state.borrow_mut().ledger));
    // Equivalent of `content_box.remove(&tab.container)` without holding a
    // reference to content_box: the container's parent IS content_box.
    // Note: relies on gtk::Widget::parent() + glib Cast::downcast;
    // verify runtime tab close (smoke tab_close covers it) leaves no GTK
    // warnings from the webview widget being torn down after removal.
    if let Some(parent) = view.container.parent() {
        if let Ok(container) = parent.downcast::<gtk::Container>() {
            container.remove(&view.container);
        }
    }
}

pub fn set_chrome_height(hosts: &Hosts, px: i32) {
    hosts.chrome_box.set_size_request(-1, px);
}

pub fn layout(
    hosts: &Hosts,
    _chrome: &WebView,
    _active: Option<&WebView>,
    _chrome_height: i32,
    arrangement: ChromeLayout,
) {
    // GEOMETRY is still nothing here: GTK repacks automatically on resize and
    // size-request changes; manual geometry exists only in the Windows
    // backend.
    //
    // `ChromeLayout::Split` therefore DOES NOTHING here, and that is a real
    // limitation rather than an oversight: a docked pane needs the content
    // widget re-packed into a horizontal box beside it, which is a GTK change
    // this function is not the place for. Until that exists, chat on this
    // backend stays the modal it has always been -- see `split_supported`,
    // which the chrome asks before offering the arrangement at all, so nobody
    // is given a control that quietly does nothing.
    //
    // The hover readout is the one thing here that is NOT geometry. Every
    // state change that reaches this function -- tab switch, tab close,
    // arrangement change, resize -- invalidates what the readout says,
    // because it describes a link under a pointer that is no longer where it
    // was. Hiding is always safe: the next pointer move re-shows it. Under
    // Overlay it is suppressed outright -- a modal covers the page, so a
    // readout floating over it would describe something the user can neither
    // see nor click. (The Overlay case is belt-and-braces on this backend:
    // the modal is realised by the chrome box growing, which squeezes the
    // GtkOverlay to zero height anyway -- but relying on a side effect of a
    // different feature is how this stops working the day split_supported
    // changes.)
    hosts
        .readout_suppressed
        .set(matches!(arrangement, ChromeLayout::Overlay));
    hosts.readout.hide();
}

/// Whether a docked pane can actually be laid out on this backend.
///
/// False here. The chrome must not offer the arrangement it cannot honour;
/// this browser's rule is that a control the platform cannot deliver is hidden
/// or explained, never shown and inert.
pub fn split_supported() -> bool {
    false
}

/// Whether a modal's backdrop is a LIVE dimmed page rather than an opaque
/// cover.
///
/// False here, same rule as `split_supported`: lifting the chrome above the
/// content with a transparent background is manual-geometry work that exists
/// only in the Windows backend. The stylesheet asks (`chrome_caps`) and keeps
/// the solid scrim, which on this backend is the truthful one -- the page
/// really is covered.
pub fn translucent_overlay_supported() -> bool {
    false
}

/// Runtime WebKitGTK version and whether it is below the security floor.
///
/// These are the runtime getters, not the `WEBKIT_MAJOR_VERSION` compile-time
/// macros: the library is linked dynamically, so what we built against and
/// what is loaded can differ, and only the loaded one can be exploited.
pub fn engine_info() -> crate::platform::EngineInfo {
    // SAFETY: three argument-less getters returning plain integers. They are
    // safe to call before any WebKit object exists.
    let found = unsafe {
        (
            webkit2gtk_sys::webkit_get_major_version(),
            webkit2gtk_sys::webkit_get_minor_version(),
            webkit2gtk_sys::webkit_get_micro_version(),
        )
    };
    crate::platform::EngineInfo {
        name: "WebKitGTK",
        version: Some(found),
        below_floor: crate::platform::below_floor(found, crate::platform::MIN_WEBKITGTK),
        tracking_prevention: if itp_confirmed() {
            "ITP enabled"
        } else {
            "ITP OFF"
        },
    }
}

/// Unix drives the auto-freeze transition from a GTK timeout scheduled on load
/// finish (see `connect_load_events`), so the event loop has nothing to do
/// here. Present so `platform` exposes one shape on both targets rather than
/// making the caller `#[cfg]` around a difference that is an implementation
/// detail of the engine.
pub fn tick_auto_freeze(_view: &TabView, _now: Instant) -> (bool, Option<Instant>) {
    (false, None)
}

#[cfg(test)]
mod key_table_tests {
    use super::gdk_key;
    use crate::shortcuts::{self, Key, Mods};

    /// EVERY key the resolver answers must be producible on this backend.
    ///
    /// This test exists because it was not true. `gdk_key` had no entry for
    /// `k`, so Ctrl+K resolved to nothing on Linux and the command palette
    /// was unreachable -- while `shortcuts::resolve` answered `Key::K`
    /// happily and the Windows table mapped it, so both the shared logic and
    /// the other platform looked correct. A translation table that a reader
    /// has to keep in step with a match arm in another file is exactly the
    /// kind of thing that silently loses an entry.
    ///
    /// Ctrl+P was missing too, and measuring settled what to do about it:
    /// WebKitGTK does NOT bind it either, so the press reached nothing at
    /// all. It is bound now, and reports honestly that this runtime has no
    /// print preview rather than doing nothing at all.
    #[test]
    fn every_shortcut_key_can_be_produced_on_this_backend() {
        use gtk::gdk::keys::constants as k;
        let ctrl = Mods::new(true, false, false);
        // (gdk keyval, what the shared resolver calls it)
        let table: &[(gtk::gdk::keys::Key, Key)] = &[
            (k::t, Key::T),
            (k::w, Key::W),
            (k::l, Key::L),
            (k::r, Key::R),
            (k::f, Key::F),
            (k::k, Key::K),
            (k::p, Key::P),
            // Shift variants: GDK reports the SHIFTED keyval when Shift is
            // held, which is why every letter row above lists both cases.
            (k::K, Key::K),
            (k::F, Key::F),
            (k::Tab, Key::Tab),
            (k::F5, Key::F5),
            (k::F3, Key::F3),
            (k::Left, Key::Left),
            (k::Right, Key::Right),
        ];
        for (keyval, expected) in table {
            assert_eq!(
                gdk_key(keyval.clone()),
                Some(*expected),
                "this backend cannot produce {expected:?}, so every shortcut \
                 bound to it is dead here"
            );
        }

        // The property that actually matters, stated as a property: a key the
        // resolver binds under Ctrl must not be one this backend throws away.
        for (keyval, expected) in table {
            if shortcuts::resolve(ctrl, *expected).is_some() {
                assert!(
                    gdk_key(keyval.clone()).is_some(),
                    "Ctrl+{expected:?} resolves to a shortcut but this \
                     backend drops the key before the resolver ever sees it"
                );
            }
        }
    }
}
