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
    TlsState, TrackingPreventionState,
};
use super::{ChromeLayout, CHROME_HEIGHT_PX};

/// The chrome box's GTK widget name, so the root overlay's shared
/// `get-child-position` handler can tell its two overlay children apart. A
/// name rather than a captured widget: the handler is a 'static closure and
/// holding a second strong reference to a widget it is installed on is a
/// reference cycle waiting to be forgotten about.
const CHROME_WIDGET_NAME: &str = "patanyx-chrome";
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
    /// What the chrome is using along the top, left and right, in logical
    /// pixels. The page is positioned inside the window by these three values.
    ///
    /// `Rc<Cell>` because the overlay's `get-child-position` handler is a
    /// 'static closure that outlives this call and must read the CURRENT
    /// values on every allocation -- which is what makes the inset survive a
    /// resize without anything recomputing it. GTK is single-threaded, so
    /// this is the same shape as every other shared cell here.
    insets: Rc<Cell<(i32, i32, i32)>>,
    /// The CLOSED strip's top inset, which is where the page starts.
    ///
    /// Separate from `insets.0` because a panel's height arrives through the
    /// same command the strip's does. Positioning the page from this value is
    /// what stops an open panel from pushing the page down the window.
    strip_top: Rc<Cell<i32>>,
    /// True while a modal covers the window (`ChromeLayout::Overlay`), which
    /// is when the chrome is raised over a page that keeps rendering
    /// underneath it.
    lifted: Rc<Cell<bool>>,
    /// The root overlay, held so the two children's z-order can be swapped.
    root: gtk::Overlay,
    /// The content overlay, the other half of that swap.
    content_overlay: gtk::Overlay,
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
    /// The page-scrollbar sheet (`set_page_scrollbar`), kept for the same
    /// reason: swapping it out needs the instance that went in.
    scrollbar_sheet: RefCell<Option<webkit2gtk::UserStyleSheet>>,
    /// Host-to-page translation messages for this tab. Shared with the reply
    /// signal handler, which is why it is an Rc rather than owned outright:
    /// GTK is single-threaded, so Rc/RefCell is sufficient and correct here
    /// for the same reason it is for `state`.
    translate_outbox: Rc<RefCell<TranslateOutbox>>,
}

pub fn create_hosts(window: Window) -> Hosts {
    // Cloned (GTK objects are refcounted, so this is a pointer bump) because
    // default_vbox borrows the window, and the window is moved into Hosts
    // below; holding the borrow across that move would not compile.
    let vbox = window
        .default_vbox()
        .expect("tao window has no default gtk vbox")
        .clone();

    // THE CHROME TAKES THE WHOLE WINDOW AND THE PAGE SITS ON TOP OF IT, inset.
    //
    // It used to be a vertical stack: a fixed-height chrome row, then the
    // page filling what was left. That cannot express either sidebar layout,
    // because the chrome then paints an L -- a strip along the top and a
    // column down one edge -- and a box packs rectangles.
    //
    // So the arrangement is inverted to match what the Windows backend has
    // always done for its docked pane: give the chrome everything, put the
    // page in front of it, and let the page's own rectangle carve out the
    // shape the chrome shows through. One code path describes every layout,
    // and a Top placement is the case where both side insets are zero.
    //
    // `set_size_request` is deliberately gone with it. As the main child it
    // would still force the WINDOW's minimum height to whatever the chrome
    // asked for, so opening a 700px panel would grow the window rather than
    // cover the page -- the old behaviour, kept by accident, in a layout
    // that no longer means it.
    let chrome_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    // Content container: hosts one gtk::Box per tab. It sits inside its own
    // Overlay so the hover readout can float over the page without reserving
    // a row. Tab containers are still packed into content_box, so
    // remove_tab's "the container's parent IS content_box" fact is unchanged
    // -- only content_box's own parent moved.
    let content_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let overlay = gtk::Overlay::new();
    overlay.add(&content_box);

    let insets = Rc::new(Cell::new((CHROME_HEIGHT_PX, 0, 0)));
    // The closed strip's height, remembered apart from `insets.0`.
    //
    // A panel's height arrives through the SAME `set_chrome_insets` the strip
    // uses, so before the lift the two were one number and an open panel
    // simply pushed the page down by its own height. That was the whole of the
    // "the panel does not float, the page moved" defect. The page's rectangle
    // is computed from THIS value, which only ever tracks the closed strip, so
    // a panel's height can no longer move the page.
    let strip_top = Rc::new(Cell::new(CHROME_HEIGHT_PX));
    // Whether a modal is covering the window: `ChromeLayout::Overlay`.
    let lifted = Rc::new(Cell::new(false));
    // GTK3 keeps an Overlay's MAIN child at the BOTTOM of the z-stack, and the
    // chrome used to be that main child with the page overlaid on top of it.
    // That is why the chrome could only ever be seen above the page and never
    // over it, and why revealing a panel meant growing the strip. Both real
    // children are overlays now, so the order is ours to choose: content is
    // added first and the chrome second, which puts the chrome ABOVE the page
    // and lets a transparent chrome float a panel over live content exactly as
    // the Windows backend does. The main child is an empty box that paints
    // nothing and exists only because GtkOverlay requires one.
    let base = gtk::Box::new(gtk::Orientation::Vertical, 0);
    chrome_box.set_widget_name(CHROME_WIDGET_NAME);
    let root = gtk::Overlay::new();
    root.add(&base);
    // Content first, chrome second. The ORDER is not the resting state: the
    // resting state is content on top, which `layout` restores. Adding the
    // chrome last here only establishes that both are overlay children, which
    // is what makes either one reorderable at all -- a GtkOverlay's main child
    // is pinned to the bottom and the chrome used to be it.
    root.add_overlay(&overlay);
    root.add_overlay(&chrome_box);
    // Resting state: the page draws over the chrome and carves the L, exactly
    // as before this change.
    root.reorder_overlay(&overlay, -1);
    // Both children's rectangles, recomputed by GTK on every allocation. A
    // handler rather than margins, for two reasons: margin_start is RTL-aware
    // and would put the page on the wrong side of a right-to-left desktop
    // while the stylesheet still drew the sidebar at left: 0; and a handler
    // reads the insets fresh, so a resize needs nothing re-applied. The page
    // arithmetic is platform::page_rect, the same pure function the Windows
    // backend lays out with.
    {
        let insets = Rc::clone(&insets);
        let strip_top = Rc::clone(&strip_top);
        let lifted = Rc::clone(&lifted);
        root.connect_get_child_position(move |root, child| {
            let alloc = root.allocation();
            let (top, left, right) = insets.get();
            let _ = top;
            if child.widget_name() == CHROME_WIDGET_NAME {
                // THE WHOLE WINDOW, ALWAYS, which is what this backend has
                // always given the chrome. Sizing it to the strip instead
                // clipped both side toolbars: the sidebar is positioned from
                // the closed strip down to the window's floor, so a chrome
                // only `top` pixels tall left its buttons below the webview's
                // bottom edge, invisible and unclickable, while the page still
                // reserved the rail's width. The chrome draws the L; the rest
                // of its surface is either behind the page or transparent.
                return Some(gtk::Rectangle::new(0, 0, alloc.width(), alloc.height()));
            }
            let (x, y, w, h) = crate::platform::page_rect(
                f64::from(alloc.width()),
                f64::from(alloc.height()),
                strip_top.get(),
                left,
                right,
                0,
                crate::platform::PAGE_FRAME_PX,
            );
            #[allow(clippy::cast_possible_truncation)]
            Some(gtk::Rectangle::new(x as i32, y as i32, w as i32, h as i32))
        });
    }
    vbox.pack_start(&root, true, true, 0);

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
        insets,
        strip_top,
        lifted,
        root,
        content_overlay: overlay,
    }
}

/// Attaches the readout's style provider and loads the colours for `scheme`.
///
/// Called once from main.rs after the widget tree exists. Until this runs the
/// readout is unstyled and `readout_styled` is false, so it cannot show.
pub fn arm_hover_readout(hosts: &Hosts, scheme: crate::prefs::ChromeScheme) {
    hosts
        .readout
        .style_context()
        .add_provider(&hosts.readout_css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
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
    (hosts.readout.is_visible(), hosts.readout.text().to_string())
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

/// Builder for the translator webview: its own `WebContext`, and therefore its
/// own website-data store, rather than the process-wide default every other
/// webview shares.
///
/// Phase 0 measured a same-origin translator sharing IndexedDB with the real
/// chrome webview IN THE PRODUCT. A separate origin partitions what WebKitGTK
/// keys by origin; a separate data store is what stops the two views sharing a
/// manager at all. Both, or neither is worth much.
pub fn new_translator_webview_builder() -> WebViewBuilder<'static> {
    let dir = super::translator_profile_dir_for(&patanyx_vault::Vault::default_path());
    let _ = std::fs::create_dir_all(&dir);
    WebViewBuilder::new_with_web_context(Box::leak(Box::new(wry::WebContext::new(Some(dir)))))
        .with_navigation_handler(|url: String| url.starts_with(super::TRANSLATE_ORIGIN_PREFIX))
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
        // Ctrl+Shift+I, developer tools on the page. Both cases, because GDK
        // reports the shifted keyval and this binding always carries Shift.
        k::i | k::I => Key::I,
        k::Tab | k::ISO_Left_Tab => Key::Tab,
        k::F5 => Key::F5,
        k::F3 => Key::F3,
        k::F12 => Key::F12,
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
    // TRANSPARENT BACKGROUND, which is what makes the lift visible.
    //
    // The chrome is stacked above the page now, so an opaque chrome would
    // hide the page whenever a modal covered the window and the "live dimmed
    // page" the stylesheet promises under `translucent-backdrop` would be a
    // lie. With alpha zero the page renders underneath and shows through the
    // scrim the chrome draws. Proven on this stack before the change was
    // written: a WebKitGTK view with a clear background composites over a
    // sibling view inside a GtkOverlay.
    //
    // Failure is not fatal and must not be: `translucent_overlay_supported`
    // is what the UI keys its scrim on, so a chrome that could not be made
    // transparent simply keeps an opaque cover and the stylesheet keeps the
    // solid scrim, which is then the truthful one.
    for child in hosts.chrome_box.children() {
        if let Ok(view) = child.clone().downcast::<webkit2gtk::WebView>() {
            use webkit2gtk::WebViewExt;
            view.set_background_color(&gtk::gdk::RGBA::new(0.0, 0.0, 0.0, 0.0));
            CHROME_TRANSPARENT.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
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

/// Builds the hidden translator webview.
///
/// HIDDEN BY CONSTRUCTION, not by a later call. It gets its own GTK container
/// that is never shown -- the same shape `build_content` uses for a background
/// tab, minus the `show_all` that AppState would eventually call. A view that
/// starts visible and is hidden afterwards can paint for a frame, and this one
/// has no business ever being on screen.
///
/// The translator holds text scraped from hostile pages, so it gets NO ipc
/// handler and NO content-tab wiring: no context menu, no hover readout, no
/// shortcuts, no download handler. What it gets is its own origin, its own
/// data store (from `new_translator_webview_builder`) and its own protocol
/// handler, supplied by the caller.
pub fn build_translator(hosts: &Hosts, builder: WebViewBuilder<'_>) -> Result<WebView, wry::Error> {
    let container = gtk::Box::new(gtk::Orientation::Vertical, 0);
    hosts.content_box.pack_start(&container, true, true, 0);
    // Never shown. Deliberately not `hide()`-after-`show()`: it is simply
    // never asked to appear.
    container.hide();
    builder.build_gtk(&container)
}

/// Debug-only: parents a bare SECOND webview so the in-product isolation
/// probe can measure what a second webview on the chrome origin actually
/// shares with the real chrome UI.
///
/// It exists because the same battery run in an out-of-tree harness only
/// proves things about the harness. `#[cfg(debug_assertions)]` keeps it out
/// of every release binary rather than relying on an env var alone.
#[cfg(debug_assertions)]
pub fn build_probe(hosts: &Hosts, builder: WebViewBuilder<'_>) -> Result<WebView, wry::Error> {
    builder.build_gtk(&hosts.content_box)
}

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
    id: u64,
    // Windows-only feature. Accepted so the two backends keep one signature
    // and state.rs needs no `#[cfg]`; see clear_persisted_permissions above
    // for why WebKitGTK cannot honour the frame-isolation rule.
    _permissions: crate::state::PermissionBook,
) -> Result<(WebView, TabView, bool), wry::Error> {
    // Build blank and navigate only after the per-tab UserContentManager has
    // both the divergence UserScript and its message handler. Applying the
    // URL on the builder starts WebKit loading during `build_gtk`, which
    // races the document-start registration and silently loses the first
    // page's probe reports.
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
    // The translation extractor, injected like autofill.js is on Windows. It
    // installs one function and does NOTHING until asked -- see its header:
    // injection is not consent, and a script that scanned on load would make
    // "never automatic" false regardless of what the UI did.
    // ONE TOKEN PER WEBVIEW, generated before the script that carries it.
    // See `new_poll_token` and `TranslateOutbox::expected_request`.
    let poll_token = new_poll_token();
    // The token goes INTO the script source, which wry injects TopFrame-only
    // (`with_initialization_script` -> `..._for_main_only(js, true)`), so no
    // subframe ever receives it. A placeholder rather than a concatenation
    // because the value has to land inside the script's IIFE rather than on
    // `window`, where a same-origin frame could read it through `parent`.
    let translate_script =
        CONTENT_TRANSLATE_SCRIPT.replace("__PATANYX_POLL_REQUEST__", &format!("{TRANSLATE_POLL_REQUEST}:{poll_token}"));
    let builder = builder.with_initialization_script(translate_script.as_str());
    let webview = builder.build_gtk(&container)?;
    // Register the page-to-host channel the extractor posts through. If the
    // engine gives us no content manager the channel simply does not exist and
    // the capability is reported false, rather than the UI offering a control
    // whose message would go nowhere -- the shape unix.rs:1419 already uses
    // for autofill.
    let translate_channel = connect_translate_channel(&webview, id, proxy);
    ITP_CONFIRMED.with(|c| c.set(enable_itp(&webview)));
    connect_context_menu(&webview, proxy);
    connect_hover_readout(&webview, hosts);
    connect_shortcuts(&webview, proxy);

    // The host-to-page direction. Registered alongside the page-to-host
    // channel above so a tab either has both halves of the conversation or
    // neither -- a page that could send but never be answered would leave the
    // user watching a translation that can never arrive.
    let translate_outbox: Rc<RefCell<TranslateOutbox>> =
        Rc::new(RefCell::new(TranslateOutbox::with_token(&poll_token)));
    let translate_reply = connect_translate_reply_channel(&webview, translate_outbox.clone());
    TRANSLATE_CHANNEL_READY.with(|c| c.set(translate_channel && translate_reply));

    let state = Rc::new(RefCell::new(TabState::new(policy)));
    state.borrow_mut().fingerprint_probe_reporting =
        if connect_fingerprint_probe_messages(&webview, proxy, id) {
            SettingState::Applied
        } else {
            SettingState::Failed
        };
    connect_load_events(&webview, state.clone(), translate_outbox.clone());
    connect_adlist_hold(&webview, state.clone(), proxy.clone(), id);
    connect_ledger(&webview, state.clone());
    connect_tls_errors(&webview, state.clone());

    let view = TabView {
        container,
        state,
        cosmetic_sheet: RefCell::new(None),
        scrollbar_sheet: RefCell::new(None),
        translate_outbox,
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
    // The page-scrollbar courtesy, as a User-level stylesheet: author rules
    // beat it by definition, which is the "the page's own choice wins"
    // contract stated in privacy.rs. Colour is what the chrome last reported.
    set_page_scrollbar(
        &webview,
        &view,
        crate::prefs::load().chrome_palette.scrollbar,
    );
    // Linux used to get cookie loss by engine default and clear no other
    // website data at all. Make the saved-profile promise explicit and match
    // Windows: construction returns while the async manager clear runs, and
    // this tab (plus any fast followers) stays blank until its callback.
    let initial_navigation_pending = if policy.ephemeral {
        false
    } else {
        begin_new_session_wipe(&webview, proxy)
    };
    if !initial_navigation_pending {
        super::load_initial_url(&webview, id, url)?;
    }
    Ok((webview, view, initial_navigation_pending))
}

/// Clears the persistent WebKitWebsiteDataManager once per process and holds
/// every initial navigation behind its asynchronous completion.
///
/// This is not an existing broad wipe narrowed down: before WP-AA the Unix
/// backend had NO session-clear call. WebKitGTK happened not to persist its
/// cookies, while local storage, IndexedDB, service workers and caches were
/// left to the manager. That engine-default asymmetry is now an explicit,
/// matching product decision.
///
/// The mask maps the Windows promise directly: cookies; session/local DOM
/// storage; Web SQL and IndexedDB; service-worker registrations; DOM Cache,
/// memory/disk HTTP cache and legacy offline application cache. Device-id
/// hash salts and plugin data are site-owned identifiers/state too, so they
/// cross no session boundary merely because the Windows ALL_SITE aggregate
/// has no separately named equivalent. HSTS and ITP are deliberately left
/// alone: they are the engine's learned transport-security and tracking-
/// prevention state, not content-accessible site storage, and clearing them
/// would weaken protections. A zero timespan is WebKitGTK's documented "all
/// website data" form; a nonzero span currently fails to delete cookies.
fn begin_new_session_wipe(webview: &WebView, proxy: &EventLoopProxy<UserEvent>) -> bool {
    use webkit2gtk::{WebContextExt, WebViewExt, WebsiteDataManagerExtManual, WebsiteDataTypes};
    use wry::WebViewExtUnix;

    match super::enter_session_wipe() {
        super::SessionWipeEntry::Ready => return false,
        super::SessionWipeEntry::Waiting => return true,
        super::SessionWipeEntry::Start => {}
    }

    let finish = |proxy: &EventLoopProxy<UserEvent>| {
        super::finish_session_wipe();
        let _ = proxy.send_event(UserEvent::SessionWipeFinished);
    };
    let native = webview.webview();
    let Some(context) = native.context() else {
        eprintln!("patanyx session: no WebContext; cookies, DOM storage, service workers, Cache Storage, and HTTP cache were NOT cleared");
        finish(proxy);
        return true;
    };
    let Some(manager) = context.website_data_manager() else {
        eprintln!("patanyx session: no WebsiteDataManager; cookies, DOM storage, service workers, Cache Storage, and HTTP cache were NOT cleared");
        finish(proxy);
        return true;
    };

    let types = WebsiteDataTypes::MEMORY_CACHE
        | WebsiteDataTypes::DISK_CACHE
        | WebsiteDataTypes::OFFLINE_APPLICATION_CACHE
        | WebsiteDataTypes::SESSION_STORAGE
        | WebsiteDataTypes::LOCAL_STORAGE
        | WebsiteDataTypes::WEBSQL_DATABASES
        | WebsiteDataTypes::INDEXEDDB_DATABASES
        | WebsiteDataTypes::PLUGIN_DATA
        | WebsiteDataTypes::COOKIES
        | WebsiteDataTypes::DEVICE_ID_HASH_SALT
        | WebsiteDataTypes::SERVICE_WORKER_REGISTRATIONS
        | WebsiteDataTypes::DOM_CACHE;
    let done_proxy = proxy.clone();
    manager.clear(
        types,
        webkit2gtk::glib::TimeSpan(0),
        None::<&webkit2gtk::gio::Cancellable>,
        move |result| {
            if let Err(error) = result {
                eprintln!("patanyx session: WebsiteDataManager clear FAILED ({error}); cookies, DOM storage, service workers, Cache Storage, and HTTP cache were NOT cleared");
            } else {
                eprintln!("patanyx session: cleared cookies, DOM storage, service workers, Cache Storage, and HTTP cache from the previous session");
            }
            super::finish_session_wipe();
            let _ = done_proxy.send_event(UserEvent::SessionWipeFinished);
        },
    );
    true
}

/// See `chrome_caps`: WebKitGTK does not implement `scrollbar-color` (checked
/// on 2.50.6 under Xvfb, 2026-08-17: the sheet installs, the bar stays the
/// GTK theme's), so the accent does not reach page scrollbars on this
/// backend and the panel copy must not say it does. The sheet is still
/// installed below -- it costs nothing and describes what the page SHOULD
/// do -- but the claim follows the engine, not the intent.
pub fn page_scrollbar_support() -> &'static str {
    "unsupported"
}

/// Gives this tab's pages a scrollbar in the chrome's accent, replacing the
/// previous sheet if there was one. WebKit re-styles the LIVE view when a
/// user stylesheet is swapped, so IF the engine ever honours
/// `scrollbar-color` a palette change is visible in every open tab at once
/// -- today it honours nothing here (see `page_scrollbar_support`). Same
/// instance rule as the cosmetic sheet: removal needs the object that was
/// added.
pub fn set_page_scrollbar(webview: &WebView, view: &TabView, rgb: [u8; 3]) {
    use webkit2gtk::UserContentManagerExt;
    use wry::WebViewExtUnix;
    let Some(ucm) = user_content_manager(&webview.webview()) else {
        // Same degrade-never-crash rule as set_cosmetic: no content manager,
        // no courtesy, and the engine's own scrollbar is what shows.
        return;
    };
    if let Some(old) = view.scrollbar_sheet.borrow_mut().take() {
        ucm.remove_style_sheet(&old);
    }
    let sheet = webkit2gtk::UserStyleSheet::new(
        &privacy::page_scrollbar_css(rgb),
        webkit2gtk::UserContentInjectedFrames::AllFrames,
        webkit2gtk::UserStyleLevel::User,
        &[],
        &[],
    );
    ucm.add_style_sheet(&sheet);
    *view.scrollbar_sheet.borrow_mut() = Some(sheet);
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

/// Wires the count-only push channel used by Fingerprint Divergence.
///
/// WebKitGTK exposes this under its conventional `messageHandlers.ipc`
/// namespace in the page main world. Reusing the engine convention avoids a
/// new product- or feature-named property; it does NOT install wry's
/// `window.ipc` shim (which remains chrome-only). The signal is connected
/// before registration, per WebKit's contract. Every payload is still
/// untrusted page input; the shared decoder strips it down to fixed surface
/// names and u64 deltas before anything reaches AppState.
fn connect_fingerprint_probe_messages(
    webview: &WebView,
    proxy: &EventLoopProxy<UserEvent>,
    id: u64,
) -> bool {
    use webkit2gtk::UserContentManagerExt;
    use wry::WebViewExtUnix;

    const HANDLER: &str = "ipc";
    let Some(ucm) = user_content_manager(&webview.webview()) else {
        return false;
    };
    let proxy = proxy.clone();
    ucm.connect_script_message_received(Some(HANDLER), move |_manager, result| {
        let Some(value) = result.js_value() else {
            return;
        };
        let text = value.to_string();
        let Ok(message) = serde_json::from_str::<serde_json::Value>(&text) else {
            return;
        };
        let Some(counts) = crate::state::fingerprint_probe_report(&message) else {
            return;
        };
        let _ = proxy.send_event(UserEvent::FingerprintProbes { tab_id: id, counts });
    });
    ucm.register_script_message_handler(HANDLER)
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

/// Replaces WebKit's "blocked by a content blocker" page with ours, and tells
/// the chrome, when the ad/tracker filter refuses a TOP-LEVEL document.
///
/// This is where the reported defect actually lived: the shipped lists are
/// built for third-party subresources, a user who navigates straight to a
/// listed host (every IP-lookup service is one) had the main document refused,
/// and WebKit drew its own error page with nothing to explain it.
///
/// Facts this leans on, all MEASURED on 2.52.6 on 2026-09-15 rather than read
/// from a header: the refusal arrives as load-failed with domain
/// WebKitPolicyError and code 104; it fires for the MAIN frame only, a blocked
/// iframe leaves the parent untouched and fires nothing here; returning TRUE
/// suppresses the engine's page; and load_html with the failing URI as the
/// base keeps the address bar on what the user typed.
///
/// Code 104 has no named variant in the pinned bindings (they stop at 103), so
/// it arrives as `PolicyError::__Unknown(104)`. That is matched deliberately
/// rather than mapped to a name it does not have.
fn connect_adlist_hold(
    webview: &WebView,
    state: Rc<RefCell<TabState>>,
    proxy: EventLoopProxy<UserEvent>,
    id: u64,
) {
    use gtk::glib::translate::ToGlibPtr;
    use webkit2gtk::WebViewExt;
    use wry::WebViewExtUnix;
    let native = webview.webview();
    native.connect_load_failed(move |web_view, _event, failing_uri, error| {
        // THE RAW CODE, not the enum. `error.kind::<PolicyError>()` maps a
        // value the bindings do not name to the `Failed` catch-all, and 104
        // is not named (they stop at 103), so going through the enum reported
        // every content-blocker refusal as `Failed` and the classifier never
        // fired. Measured on 2.52.6 with the diag line below, 2026-09-15.
        // SAFETY: a live GError behind a reference that outlives this read.
        let raw: *const gtk::glib::ffi::GError = error.to_glib_none().0;
        let code: i32 = unsafe { (*raw).code };
        let Some(host) = privacy::host_of(failing_uri) else {
            return false;
        };
        let (frozen, overridden) = {
            let st = state.borrow();
            (
                st.freeze.phase() == privacy::FreezePhase::Frozen,
                st.adlist_override_host().as_deref() == Some(host.as_str()),
            )
        };
        // "Is ad blocking on for this tab" is answered by the ENGINE here,
        // not by the policy snapshot on TabState. That snapshot read false on
        // a tab whose compiled filter had just refused the document (probe,
        // 2026-09-15): nothing on this backend writes it back when the
        // filters are installed, so it is a creation-time value, not the
        // truth. The truth is the refusal itself. On WebKitGTK the only
        // content blockers a tab carries are the bundled ad filters and the
        // freeze filter; freeze is attributed first by the classifier; and
        // turning blocking off removes the filters synchronously, so a 104
        // cannot arrive from a tab whose blocking is off. So: a
        // content-blocker refusal that is not the freeze IS the ad filter.
        let block_ads = true;
        let listed = privacy::bundled_rules().blocks_host(&host);
        match crate::adlist_consent::classify_load_failure(
            error.domain().as_str(),
            code,
            listed,
            block_ads,
            frozen,
            overridden,
        ) {
            crate::adlist_consent::LoadFailure::Adlist => {}
            // A frozen tab's refusals belong to the freeze, and everything
            // else keeps whatever handling it already had.
            _ => return false,
        }
        // Observable in a debug build, and the line the engine probe greps
        // for: it is the only evidence from outside the process that the
        // classifier fired rather than WebKit drawing its own page.
        // THE HOST ONLY, and only once this IS ours. `diag` keeps its last
        // fifty lines in release and the diagnostics export ships them, and
        // that export promises no browsing history and no URL beyond the one
        // tab_status already carries. An earlier draft logged the full failing
        // URI, query and all, for EVERY load failure, before classifying it:
        // every mistyped address and every failed login redirect would have
        // become plaintext diagnostic data (R-002). The inputs the classifier
        // saw are reconstructible from this line plus the code, which is a
                // NO host, no URL. The diagnostic buffer is process-global,
                // survives the tab, and goes into the diagnostics export,
                // which promises no browsing history; a listed host visited
                // in a private tab would have stayed in it (review R-001,
                // round 7). The code is the fact the probe needs.
        // constant.
        diag(&format!("adlist: held top-level document (code {code})"));
        // The method does not change what Linux renders: there is no Open
        // anyway here (adlist_consent::CAN_ALLOW), so the one Linux sentence
        // is the same for a GET and a POST. Recorded as GET rather than read
        // from the navigation action because nothing on this platform would
        // act on the difference.
        let _ = proxy.send_event(UserEvent::AdlistBlocked {
            tab_id: id,
            url: failing_uri.to_string(),
            host,
            method: "GET".to_string(),
        });
        // OURS instead of the engine's, at the same address. The base URI is
        // what keeps location.href on the blocked URL rather than about:blank;
        // the placeholder carries nothing that could run there.
        web_view.load_html(crate::adlist_consent::PLACEHOLDER_HTML, Some(failing_uri));
        true
    });
}

/// Drives the freeze state machine from WebKit's load events. Blocking
/// itself is not done here (WebKitGTK has no per-request veto); the timer
/// installs a compiled block-everything filter once the grace period ends.
fn connect_load_events(
    webview: &WebView,
    state: Rc<RefCell<TabState>>,
    translate_outbox: Rc<RefCell<TranslateOutbox>>,
) {
    use webkit2gtk::{LoadEvent, WebViewExt};
    use wry::WebViewExtUnix;
    let native = webview.webview();
    native.connect_load_changed(move |web_view, event| {
        match event {
            LoadEvent::Started => {
                // TRANSLATION CONSENT DIES WITH THE PAGE, and this is where it
                // dies. The decision was that consent attaches to the
                // page the user asked to translate and a new page needs a new
                // click; clearing here is what makes that true by construction
                // rather than by a clear-line someone can forget to call.
                //
                // It is also required for memory safety: a parked reply holds
                // the OLD document's JS context, which does not survive this
                // navigation. See ParkedReply.
                translate_outbox.borrow_mut().clear();
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
    native.connect_load_failed_with_tls_errors(
        move |_web_view, _failing_uri, certificate, _flags| {
            let issuer = issuer_name(certificate);
            let mut st = state.borrow_mut();
            st.tls_error_verdict = Some(privacy::classify_issuer(issuer.as_deref()));
            // Kept for the Info tab, display-only; the verdict above is the
            // only thing any decision reads.
            st.tls_issuer = issuer;
            false
        },
    );
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
/// Which of the two shipped rule lists a pending filter-store operation is
/// for. Carried through the C callback as data rather than a closure: the
/// callback needs to rebuild the JSON on a cache miss, and an enum that
/// names the list is honest about there being exactly two.
#[derive(Clone, Copy)]
enum BundledFilter {
    Ads,
    Tracking,
}

impl BundledFilter {
    fn id(self) -> &'static str {
        match self {
            BundledFilter::Ads => privacy::bundled_ads_filter_id(),
            BundledFilter::Tracking => privacy::bundled_tracking_filter_id(),
        }
    }

    /// ~15MB for the tracking list. Built ONLY on a cache miss -- the entire
    /// point of the load-first path is that the steady state never runs this.
    fn json(self) -> String {
        match self {
            BundledFilter::Ads => privacy::content_blocker_json(privacy::bundled_ads()),
            BundledFilter::Tracking => privacy::content_blocker_json(privacy::bundled_tracking()),
        }
    }
}

/// Installs both shipped ad-and-tracker filters, LOAD-FIRST.
///
/// The rule lists are ~144k entries between them, and `..._store_save` always
/// recompiles: measured on the build machine, ~3.1s and 40MB of bytecode for
/// the pair. That was invisible when the bundled list was 59 hosts and this
/// path called save unconditionally; at this size it would put a multi-second
/// gap at the front of EVERY tab, with ads leaking through until the filter
/// arms. `..._store_load` returns the already-compiled bytecode in ~70ms, so:
/// ask the store first, fall back to compiling only when the id has never
/// been compiled on this machine (first run on a new install, or a list
/// refresh changing the id). Failure anywhere degrades to that one tab
/// browsing without the filter -- never a crash.
///
/// TWO filters, not one merged set, because WebKit refuses a compiled list
/// over 150,000 rules and the merged set already brushes it. Each is well
/// under; the pipeline that generates the lists asserts the ceiling per list.
fn install_bundled_filters(ucm: &webkit2gtk::UserContentManager) {
    ensure_bundled_filter(ucm, BundledFilter::Ads);
    ensure_bundled_filter(ucm, BundledFilter::Tracking);
}

/// One filter: store_load, with `on_bundled_filter_loaded` finishing the job
/// either way. Ref discipline matches `compile_and_add_filter` exactly: the
/// ucm and store refs taken here are owned by the payload and released by
/// whichever callback ends the chain.
fn ensure_bundled_filter(ucm: &webkit2gtk::UserContentManager, which: BundledFilter) {
    use webkit2gtk::glib::translate::ToGlibPtr;

    let dir = filter_store_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let Some(dir_str) = dir.to_str() else {
        return;
    };
    let (Ok(c_dir), Ok(c_id)) = (
        std::ffi::CString::new(dir_str),
        std::ffi::CString::new(which.id()),
    ) else {
        return;
    };

    // SAFETY: same contract as compile_and_add_filter -- the path is copied,
    // the returned store is a strong ref the callback chain releases.
    let store = unsafe { webkit2gtk_sys::webkit_user_content_filter_store_new(c_dir.as_ptr()) };
    if store.is_null() {
        return;
    }

    let raw_ucm: *mut webkit2gtk_sys::WebKitUserContentManager = ucm.to_glib_none().0;
    // SAFETY: `raw_ucm` is valid while we hold `ucm`; the ref keeps it valid
    // for the callback, however long WebKit takes.
    unsafe { gobject_sys::g_object_ref(raw_ucm as *mut gobject_sys::GObject) };

    let payload = Box::into_raw(Box::new(BundledLoadData {
        ucm: raw_ucm,
        store,
        which,
    }));

    // SAFETY: every pointer is non-NULL and valid; the id string is copied by
    // the call. NULL cancellable, as everywhere in this file: the callback
    // tolerates arriving after its tab is gone.
    unsafe {
        webkit2gtk_sys::webkit_user_content_filter_store_load(
            store,
            c_id.as_ptr(),
            std::ptr::null_mut(),
            Some(on_bundled_filter_loaded),
            payload as glib_sys::gpointer,
        );
    }
}

struct BundledLoadData {
    ucm: *mut webkit2gtk_sys::WebKitUserContentManager,
    store: *mut webkit2gtk_sys::WebKitUserContentFilterStore,
    which: BundledFilter,
}

/// Async completion for `ensure_bundled_filter`'s load attempt.
///
/// HIT: add the filter, done -- the steady state, ~70ms after the ask.
/// MISS (or a corrupt store entry, which reports as an error the same way):
/// build the JSON now and hand the refs this payload owns straight to the
/// save path's `FilterSaveData`, so `on_filter_saved` releases them exactly
/// as it does for every other save. The two callbacks share one ref
/// discipline rather than each having its own.
///
/// SAFETY: invoked by GLib with the payload passed to `..._store_load`,
/// exactly once.
unsafe extern "C" fn on_bundled_filter_loaded(
    _source: *mut gobject_sys::GObject,
    result: *mut gio_sys::GAsyncResult,
    user_data: glib_sys::gpointer,
) {
    if user_data.is_null() {
        return;
    }
    let data = Box::from_raw(user_data as *mut BundledLoadData);

    let mut error: *mut glib_sys::GError = std::ptr::null_mut();
    let filter = webkit2gtk_sys::webkit_user_content_filter_store_load_finish(
        data.store, result, &mut error,
    );

    if error.is_null() && !filter.is_null() {
        webkit2gtk_sys::webkit_user_content_manager_add_filter(data.ucm, filter);
        // `add_filter` takes its own ref; release the one load_finish gave us.
        webkit2gtk_sys::webkit_user_content_filter_unref(filter);
        gobject_sys::g_object_unref(data.ucm as *mut gobject_sys::GObject);
        gobject_sys::g_object_unref(data.store as *mut gobject_sys::GObject);
        return;
    }
    if !error.is_null() {
        glib_sys::g_error_free(error);
        // GLib's convention is one OR the other, and the hit branch above
        // already took the both-are-good case. This releases the filter in
        // the combination the convention does not promise cannot happen --
        // returning an error AND a filter -- because falling through to the
        // compile path below would otherwise strand it. Costs one null check
        // on a path that should never run. (Red-team pass, 2026-09-01.)
        if !filter.is_null() {
            webkit2gtk_sys::webkit_user_content_filter_unref(filter);
        }
    }

    // Cache miss: compile. The json allocation is the price of first run.
    let json = data.which.json();
    // THE ID IS BUILT FIRST, before the ~15MB GBytes. The original order
    // allocated the bytes and then took a fallible CString step whose early
    // return released the two object refs but not the GBytes -- a leak of the
    // largest allocation on the path. Ordering the infallible-to-acquire
    // resource last removes the failure window rather than adding a cleanup
    // branch to remember. (Red-team pass, 2026-09-01.)
    let Ok(c_id) = std::ffi::CString::new(data.which.id()) else {
        gobject_sys::g_object_unref(data.ucm as *mut gobject_sys::GObject);
        gobject_sys::g_object_unref(data.store as *mut gobject_sys::GObject);
        return;
    };
    let bytes = glib_sys::g_bytes_new(json.as_ptr() as *const std::ffi::c_void, json.len());
    if bytes.is_null() {
        gobject_sys::g_object_unref(data.ucm as *mut gobject_sys::GObject);
        gobject_sys::g_object_unref(data.store as *mut gobject_sys::GObject);
        return;
    }

    // Ref TRANSFER into the save payload: no unref here, on_filter_saved owns
    // the release for both, the same way it does for compile_and_add_filter.
    let payload = Box::into_raw(Box::new(FilterSaveData {
        ucm: data.ucm,
        store: data.store,
        freeze_state: None,
    }));
    webkit2gtk_sys::webkit_user_content_filter_store_save(
        data.store,
        c_id.as_ptr(),
        bytes,
        std::ptr::null_mut(),
        Some(on_filter_saved),
        payload as glib_sys::gpointer,
    );
    glib_sys::g_bytes_unref(bytes);
}

fn compile_and_add_filter(
    ucm: &webkit2gtk::UserContentManager,
    json: &str,
    freeze_state: Option<Rc<RefCell<TabState>>>,
) {
    // Every early return below routes through here, so adding a new failure
    // path cannot silently skip the reporting.
    macro_rules! give_up {
        ($why:expr) => {{
            // A freeze has its own UI state to correct; the ad filter has
            // only this log, which is why the arm without a `state` is not an
            // empty one. `freeze_state` is None exactly for the ad/tracker
            // filter -- see FilterSaveData -- so it is what distinguishes the
            // two callers here.
            match &freeze_state {
                Some(state) => {
                    state.borrow_mut().freeze.note_enforcement_failed();
                    diag(&format!("freeze filter not installed: {}", $why));
                }
                None => diag(&format!("ad/tracker filter not installed: {}", $why)),
            }
            return;
        }};
    }
    use webkit2gtk::glib::translate::ToGlibPtr;

    let dir = filter_store_dir();
    // WebKit will not create the directory itself and silently fails without it.
    if std::fs::create_dir_all(&dir).is_err() {
        give_up!(format!(
            "cannot create the filter cache at {}",
            dir.display()
        ));
    }
    let Some(dir_str) = dir.to_str() else {
        give_up!("the filter cache path is not UTF-8");
    };
    let (Ok(c_dir), Ok(c_id)) = (
        std::ffi::CString::new(dir_str),
        std::ffi::CString::new(privacy::filter_id_for(json)),
    ) else {
        give_up!("the cache path or filter id contains an interior NUL");
    };

    // SAFETY: `c_dir` is a valid NUL-terminated string that outlives this call;
    // `..._store_new` copies the path. The returned store is a new strong ref
    // which the callback releases. A NULL return is handled below.
    let store = unsafe { webkit2gtk_sys::webkit_user_content_filter_store_new(c_dir.as_ptr()) };
    if store.is_null() {
        give_up!("the engine would not open a filter store");
    }

    // SAFETY: `json` is a live slice for the duration of this call and
    // `g_bytes_new` COPIES it, so the GBytes does not borrow Rust memory.
    let bytes = unsafe {
        glib_sys::g_bytes_new(
            json.as_ptr() as *const std::ffi::c_void,
            json.len() as usize,
        )
    };
    if bytes.is_null() {
        // SAFETY: `store` is a valid object we hold the only ref to.
        unsafe { gobject_sys::g_object_unref(store as *mut gobject_sys::GObject) };
        give_up!("could not allocate the rule buffer");
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
    let filter = webkit2gtk_sys::webkit_user_content_filter_store_save_finish(
        data.store, result, &mut error,
    );

    if !error.is_null() {
        // Compilation failed: malformed rules, an unwritable cache, a rule
        // list the engine rejects. The filter is simply absent.
        //
        // This used to degrade SILENTLY, which for a freeze meant the tab
        // went on reporting "Frozen and making no requests" with nothing
        // installed. The user is told instead.
        // The engine's own words: "Too many rules in JSON array" for a list
        // over the ceiling, or the pattern it would not compile. This is the
        // message that turns "ad blocking silently did nothing" into an
        // answerable question, so it is captured before the error is freed.
        let why = if (*error).message.is_null() {
            "the engine refused the rules".to_string()
        } else {
            std::ffi::CStr::from_ptr((*error).message)
                .to_string_lossy()
                .into_owned()
        };
        glib_sys::g_error_free(error);
        match &data.freeze_state {
            Some(state) => {
                state.borrow_mut().freeze.note_enforcement_failed();
                diag(&format!("freeze filter not installed: {why}"));
            }
            None => diag(&format!("ad/tracker filter not installed: {why}")),
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

/// Asks the ENGINE whether the shipped ad and tracker rules actually compile,
/// synchronously, and reports the verdict. Exists for the CI gate; nothing in
/// the running browser calls it.
///
/// WHY A GATE AND NOT AN ASSERTION ON A NUMBER. WebKit refuses a compiled rule
/// list above an undocumented ceiling -- measured 2026-09-01 as exactly
/// 150,000 on both WebKitGTK 2.50.6 and 2.52.6 -- and refuses individual
/// patterns outside the subset its regex engine accepts. Either refusal
/// produces NO filter, and the browser then runs with ad blocking switched on
/// in the UI and nothing installed. A build-time constant asserting "under
/// 150,000" only restates today's number: if a future engine LOWERS the limit
/// or narrows the accepted pattern subset, the constant still passes and users
/// silently lose protection. Asking the engine we are about to ship against is
/// the only check that survives the engine changing under us.
///
/// Returns Ok(()) when every rule set compiles, Err(reason) on the first that
/// does not.
pub fn verify_content_filters() -> Result<(), String> {
    use webkit2gtk::glib::translate::ToGlibPtr;

    let dir = std::env::temp_dir().join(format!("patanyx-filter-verify-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let dir_str = dir
        .to_str()
        .ok_or_else(|| "verify directory path is not UTF-8".to_string())?;
    let c_dir = std::ffi::CString::new(dir_str).map_err(|e| e.to_string())?;

    // Each shipped rule set is compiled SEPARATELY, exactly as the runtime
    // installs them, so a ceiling breach is attributed to the list that
    // breached it rather than to the pair.
    // The two lists are checked SEPARATELY because that is how they are
    // installed. Compiling the combined set would test something the browser
    // never asks the engine to do, and would fail on a total that is under no
    // real ceiling -- exactly the false alarm that teaches people to ignore a
    // gate. Checked separately, a breach also names the list that breached.
    let sets: [(&str, String); 2] = [
        ("ads", privacy::content_blocker_json(privacy::bundled_ads())),
        (
            "tracking",
            privacy::content_blocker_json(privacy::bundled_tracking()),
        ),
    ];

    for (name, json) in sets {
        let c_id = std::ffi::CString::new(format!("verify-{name}")).map_err(|e| e.to_string())?;
        // SAFETY: the path is copied by the constructor; the store is a strong
        // ref released below on every path.
        let store = unsafe { webkit2gtk_sys::webkit_user_content_filter_store_new(c_dir.as_ptr()) };
        if store.is_null() {
            return Err(format!("{name}: could not open a filter store"));
        }
        // SAFETY: g_bytes_new COPIES the buffer, so it does not borrow `json`.
        let bytes =
            unsafe { glib_sys::g_bytes_new(json.as_ptr() as *const std::ffi::c_void, json.len()) };
        if bytes.is_null() {
            unsafe { gobject_sys::g_object_unref(store as *mut gobject_sys::GObject) };
            return Err(format!("{name}: could not allocate the rule buffer"));
        }

        // The save is async; this is a one-shot CLI mode, so drive the main
        // context until it completes rather than threading a callback through
        // an event loop that does not exist here.
        let outcome: Rc<RefCell<Option<Result<(), String>>>> = Rc::new(RefCell::new(None));
        let payload = Box::into_raw(Box::new(VerifyData {
            outcome: outcome.clone(),
        }));
        unsafe {
            webkit2gtk_sys::webkit_user_content_filter_store_save(
                store,
                c_id.as_ptr(),
                bytes,
                std::ptr::null_mut(),
                Some(on_verify_saved),
                payload as glib_sys::gpointer,
            );
            glib_sys::g_bytes_unref(bytes);
        }

        let ctx = webkit2gtk::glib::MainContext::default();
        // Bounded: a wedged engine must fail the build, not hang CI forever.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while outcome.borrow().is_none() {
            ctx.iteration(true);
            if std::time::Instant::now() > deadline {
                break;
            }
        }
        unsafe { gobject_sys::g_object_unref(store as *mut gobject_sys::GObject) };

        // Taken out of the RefCell before matching: holding the borrow across
        // the arms keeps `outcome` alive into the return expressions, which
        // the borrow checker rejects.
        let verdict = outcome.borrow_mut().take();
        match verdict {
            Some(Ok(())) => {}
            Some(Err(why)) => {
                let n = match name {
                    "ads" => privacy::bundled_ads().blocked_hosts.len(),
                    _ => privacy::bundled_tracking().blocked_hosts.len(),
                };
                return Err(format!("{name}: the engine REFUSED {n} rules: {why}"));
            }
            None => return Err(format!("{name}: the engine did not answer within 120s")),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

struct VerifyData {
    outcome: Rc<RefCell<Option<Result<(), String>>>>,
}

/// SAFETY: invoked by GLib with the payload passed to `..._store_save`,
/// exactly once. Reclaims the box.
unsafe extern "C" fn on_verify_saved(
    source: *mut gobject_sys::GObject,
    result: *mut gio_sys::GAsyncResult,
    user_data: glib_sys::gpointer,
) {
    if user_data.is_null() {
        return;
    }
    let data = Box::from_raw(user_data as *mut VerifyData);
    let mut error: *mut glib_sys::GError = std::ptr::null_mut();
    let filter = webkit2gtk_sys::webkit_user_content_filter_store_save_finish(
        source as *mut webkit2gtk_sys::WebKitUserContentFilterStore,
        result,
        &mut error,
    );
    let verdict = if !error.is_null() {
        let msg = std::ffi::CStr::from_ptr((*error).message)
            .to_string_lossy()
            .into_owned();
        glib_sys::g_error_free(error);
        if !filter.is_null() {
            webkit2gtk_sys::webkit_user_content_filter_unref(filter);
        }
        Err(msg)
    } else if filter.is_null() {
        Err("no filter and no error".to_string())
    } else {
        webkit2gtk_sys::webkit_user_content_filter_unref(filter);
        Ok(())
    };
    *data.outcome.borrow_mut() = Some(verdict);
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
fn user_content_manager(native: &webkit2gtk::WebView) -> Option<webkit2gtk::UserContentManager> {
    use webkit2gtk::WebViewExt;
    native.user_content_manager()
}

/// The name the page posts to: `window.webkit.messageHandlers.<NAME>`.
///
/// Distinct from anything the chrome uses. A content webview has no
/// `window.ipc` by design, and this deliberately does not resemble one.
pub const TRANSLATE_CHANNEL: &str = "patanyxTranslate";

/// The extractor that posts through `TRANSLATE_CHANNEL`.
const CONTENT_TRANSLATE_SCRIPT: &str = include_str!("../content_scripts/translate_extract.js");

thread_local! {
    /// Whether the last-built content webview got a working translation
    /// channel. Mirrors ITP_CONFIRMED's shape: OBSERVED at construction, not
    /// inferred from a pref, because a capability the UI offers must reflect
    /// what the engine actually granted.
    static TRANSLATE_CHANNEL_READY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether content webviews on this backend have a translation channel.
pub fn translate_channel_supported() -> bool {
    TRANSLATE_CHANNEL_READY.with(|c| c.get())
}

/// Gives a CONTENT webview a one-way page-to-host channel for translation.
///
/// WHY THIS EXISTS AT ALL. The plan's original channel had Rust calling
/// `evaluate_script` on content webviews. That contradicts this codebase's
/// own invariant -- `state.rs:256` says content webviews are `load_url` only,
/// and `state.rs:1678` keeps the chrome webview's field private precisely so
/// that stays true. The invariant wins by decision, so the seam becomes
/// a content script talking over a registered message handler, which is the
/// shape `autofill.js` already uses on Windows.
///
/// This is the FIRST page-to-host channel on this backend; `unix.rs:1419`
/// records that autofill's equivalent was Windows-only "for this pass".
///
/// WHAT CROSSES IT IS UNTRUSTED. Everything arriving here was assembled by a
/// script running in a hostile page's document. It is forwarded as an opaque
/// String tagged with the tab id the HOST knows, never one the page supplies,
/// and nothing on this path parses it -- parsing happens once, in one place,
/// against a schema.
///
/// One-way on purpose: there is no host-to-page direction here. Patching
/// translated text back is a later phase and will need its own, separately
/// justified mechanism.
pub fn connect_translate_channel(
    webview: &WebView,
    id: u64,
    proxy: &EventLoopProxy<UserEvent>,
) -> bool {
    use javascriptcore::ValueExt;
    use webkit2gtk::UserContentManagerExt;
    use wry::WebViewExtUnix;
    let native = webview.webview();
    let Some(ucm) = user_content_manager(&native) else {
        // Degrade, never crash -- the caller reports the capability as absent
        // and the UI never offers what cannot be delivered.
        return false;
    };
    if !ucm.register_script_message_handler(TRANSLATE_CHANNEL) {
        return false;
    }
    let proxy = proxy.clone();
    ucm.connect_script_message_received(Some(TRANSLATE_CHANNEL), move |_ucm, result| {
        let Some(value) = result.js_value() else {
            return;
        };
        // A page can post any JS value at all. Only a string is accepted, and
        // it is capped here rather than downstream: an unbounded page-supplied
        // payload is a memory-exhaustion primitive, and the cap belongs at the
        // door.
        if !value.is_string() {
            return;
        }
        let text = value.to_str().to_string();
        if text.len() > MAX_CONTENT_TRANSLATE_BYTES {
            return;
        }
        let _ = proxy.send_event(UserEvent::ContentTranslate(id, text));
    });
    true
}

/// The name the page ASKS on. Unlike `TRANSLATE_CHANNEL`, a `postMessage`
/// here returns a Promise that the HOST resolves.
pub const TRANSLATE_ASK_CHANNEL: &str = "patanyxTranslateAsk";

/// Gives a CONTENT webview a page-initiated REQUEST/REPLY channel, which is
/// how translated text gets back INTO the page.
///
/// WHY IT HAS TO LOOK LIKE THIS. Windows has `PostWebMessageAsJson`, a real
/// host-to-page push. WebKitGTK has no push equivalent, and its obvious
/// substitute -- `evaluate_javascript` on a content webview -- is exactly what
/// `state.rs:256` forbids and what was decided must not be relaxed. So
/// the direction is inverted: the PAGE asks, and the host answers with a JS
/// VALUE. Our data crosses as data, never as source, and nothing on this path
/// evaluates script into a content webview.
///
/// RAW FFI, because the safe bindings cannot receive this signal. webkit2gtk
/// 2.0.2 generates the registration but drops the callback -- its gir output
/// records "Ignored reply: WebKit2.ScriptMessageReply" -- so both the
/// registration and the connection go through `webkit2gtk-sys`, which this
/// crate already depends on for the content-filter store the safe crate also
/// does not wrap. The v2_40 symbols this needs are reachable because
/// `webkit2gtk` is built with that feature; the runtime floor is WebKitGTK
/// 2.40, and this machine builds against 2.50.
///
/// IT LONG-POLLS, AND THAT IS A REQUIREMENT RATHER THAN AN OPTIMIZATION. The
/// content script promises it does nothing until asked: no scan on load, no
/// MutationObserver, no timer. A page that had to POLL the host for work would
/// break that promise on every page the user ever opens, translated or not. So
/// the page makes ONE ask and the host PARKS it -- `webkit_script_message_-
/// reply_ref` keeps it alive -- answering only when the user actually clicks
/// Translate. Until then there is exactly one pending Promise and zero running
/// code, which is what "does nothing" has to mean to be worth saying.
///
/// THE HANDLER MUST STAY CHEAP. It runs inside the GTK main loop, so it only
/// moves messages in and out of a mailbox; it never translates anything itself
/// and never re-enters application state.
pub fn connect_translate_reply_channel(
    webview: &WebView,
    outbox: Rc<RefCell<TranslateOutbox>>,
) -> bool {
    use webkit2gtk::glib::translate::ToGlibPtr;
    use wry::WebViewExtUnix;
    let native = webview.webview();
    let Some(ucm) = user_content_manager(&native) else {
        // Degrade, never crash, exactly as the one-way channel does.
        return false;
    };
    let Ok(name) = std::ffi::CString::new(TRANSLATE_ASK_CHANNEL) else {
        return false;
    };
    let Ok(detailed) = std::ffi::CString::new(format!(
        "script-message-with-reply-received::{TRANSLATE_ASK_CHANNEL}"
    )) else {
        return false;
    };

    let raw_ucm: *mut webkit2gtk_sys::WebKitUserContentManager = ucm.to_glib_none().0;
    // SAFETY: `raw_ucm` is valid while `ucm` is held. A NULL world name means
    // the page's default script world, which is where the extractor already
    // runs -- putting the two halves of one conversation in different worlds
    // would leave the patcher unable to see the nodes the extractor read.
    let registered = unsafe {
        webkit2gtk_sys::webkit_user_content_manager_register_script_message_handler_with_reply(
            raw_ucm,
            name.as_ptr(),
            std::ptr::null(),
        )
    };
    if registered == 0 {
        return false;
    }

    // Owned by the signal connection, not leaked: `drop_answer` below is
    // handed to g_signal_connect_data as the destroy notify, so this handle
    // dies with the content manager rather than living for the process.
    let boxed: Box<Rc<RefCell<TranslateOutbox>>> = Box::new(outbox);
    let user_data = Box::into_raw(boxed) as glib_sys::gpointer;

    // SAFETY: the trampoline's signature matches this signal's C prototype
    // (manager, js_result, reply, user_data) -> gboolean, `user_data` is the
    // box created immediately above and is freed exactly once by
    // `drop_answer`, and the transmute to GCallback is the documented way to
    // pass a typed handler to g_signal_connect_data.
    unsafe {
        gobject_sys::g_signal_connect_data(
            raw_ucm as *mut gobject_sys::GObject,
            detailed.as_ptr(),
            Some(std::mem::transmute::<ReplyHandler, unsafe extern "C" fn()>(
                reply_trampoline,
            )),
            user_data,
            Some(drop_answer),
            0,
        );
    }
    true
}

/// The C prototype of `script-message-with-reply-received`, named so the
/// transmute above states what it is converting FROM rather than casting
/// through an untyped pointer.
type ReplyHandler = unsafe extern "C" fn(
    *mut webkit2gtk_sys::WebKitUserContentManager,
    // A JSCValue, NOT a WebKitJavascriptResult. This differs from the older
    // `script-message-received` signal beside it, and the difference is not
    // cosmetic: an earlier draft of this file assumed the two signals matched,
    // passed the value to `webkit_javascript_result_get_js_value`, and killed
    // the process on the first message. WebKit2-4.1.gir is the authority --
    // `script-message-received` declares `JavascriptResult`,
    // `script-message-with-reply-received` (2.40) declares
    // `JavaScriptCore.Value`.
    *mut javascriptcore_rs_sys::JSCValue,
    *mut webkit2gtk_sys::WebKitScriptMessageReply,
    glib_sys::gpointer,
) -> glib_sys::gboolean;

/// Frees the mailbox handle when the signal connection goes away.
unsafe extern "C" fn drop_answer(data: glib_sys::gpointer, _closure: *mut gobject_sys::GClosure) {
    if data.is_null() {
        return;
    }
    // SAFETY: `data` came from Box::into_raw on exactly this type in
    // connect_translate_reply_channel, and GObject invokes a destroy notify
    // once.
    drop(unsafe { Box::from_raw(data as *mut Rc<RefCell<TranslateOutbox>>) });
}

/// A reply the page is waiting on, kept alive across the main loop until the
/// host has something to say.
///
/// WHY THE CONTEXT RIDES ALONG. Answering means handing back a JSCValue, and a
/// JSCValue only exists inside a JSCContext -- so the context the request
/// arrived on has to be held too. That context belongs to the PAGE, and dies
/// when the page does, which is the reason the outbox is cleared on every
/// navigation (`clear_translate_outbox`). The consent ruling already required
/// that clearing; this makes it load-bearing for memory safety as well, so the
/// two cannot drift apart.
pub struct ParkedReply {
    reply: *mut webkit2gtk_sys::WebKitScriptMessageReply,
    context: javascriptcore::Context,
}

impl ParkedReply {
    /// Takes a ref on the reply so it outlives the signal handler.
    ///
    /// SAFETY: `reply` must be the live, non-null reply for a
    /// `script-message-with-reply-received` emission that has not yet been
    /// answered.
    unsafe fn park(
        reply: *mut webkit2gtk_sys::WebKitScriptMessageReply,
        context: javascriptcore::Context,
    ) -> Self {
        Self {
            reply: unsafe { webkit2gtk_sys::webkit_script_message_reply_ref(reply) },
            context,
        }
    }

    /// Resolves the page's Promise with `text`. Consumes self, so a reply can
    /// be answered at most once.
    fn answer(self, text: &str) {
        use webkit2gtk::glib::translate::ToGlibPtr;
        let value = javascriptcore::Value::new_string(&self.context, Some(text));
        let raw: *mut javascriptcore_rs_sys::JSCValue = value.to_glib_none().0;
        // SAFETY: `self.reply` holds a ref taken in `park` and is answered
        // exactly once because this method takes ownership; `raw` is a live
        // value in the context the request arrived on. Drop then unrefs.
        unsafe { webkit2gtk_sys::webkit_script_message_reply_return_value(self.reply, raw.cast()) };
    }
}

impl Drop for ParkedReply {
    fn drop(&mut self) {
        // Dropping WITHOUT answering is a normal path, not an error: it is
        // what happens when the user navigates away while a poll is parked.
        // WebKitGTK rejects the page's Promise when the last ref goes, which
        // is the correct outcome -- the page learns the request will never be
        // served rather than waiting forever.
        //
        // SAFETY: matched with the ref taken in `park`; nothing else unrefs.
        unsafe { webkit2gtk_sys::webkit_script_message_reply_unref(self.reply) };
    }
}

/// The mailbox between the event loop and one content page.
///
/// It exists because the two halves run at different times: the page's poll
/// arrives whenever the page loads, and the host's answer is ready whenever
/// the user clicks and a translation finishes. Either can be first, so the
/// mailbox holds whichever arrived.
#[derive(Default)]
pub struct TranslateOutbox {
    /// The exact string a poll must carry, `poll:<token>`.
    ///
    /// The token is random per webview and templated into the extractor's
    /// source, which wry injects TopFrame-only. A frame that never received
    /// the script cannot produce this string, so its poll is refused rather
    /// than allowed to displace the top document's parked reply. Empty only
    /// in tests that do not exercise the channel.
    expected_request: String,
    /// A poll the page has made and the host has not yet answered.
    parked: Option<ParkedReply>,
    /// A message the host produced before the page asked for it. Bounded,
    /// because an unbounded queue behind a page that never polls is a leak.
    pending: std::collections::VecDeque<String>,
    /// How many times this mailbox has been cleared.
    ///
    /// COUNTED RATHER THAN SAMPLED, because the state it guards is invisible a
    /// moment later. "Was the outbox cleared by that navigation?" cannot be
    /// answered by looking at the outbox afterwards: the new document opens
    /// its own poll straight away, so a mailbox that was correctly cleared and
    /// one that was never cleared look identical. The probe read exactly that
    /// false negative before this counter existed.
    cleared: u64,
}

/// How many host messages may wait for a page that is not polling.
///
/// Small on purpose. A healthy page re-polls immediately after each answer, so
/// depth beyond one means the page is not keeping up or is not listening at
/// all, and neither is a state to accumulate memory in.
const MAX_PENDING_TRANSLATE_MESSAGES: usize = 8;

/// A fresh poll token, hex, from the OS.
///
/// `getrandom` is already how this crate produces a device id
/// (activation.rs) and archive names. 32 bytes because this is a
/// capability string a hostile frame would otherwise guess, and there is no
/// reason to be thrifty about it.
fn new_poll_token() -> String {
    let mut bytes = [0u8; 32];
    let got = getrandom::getrandom(&mut bytes);
    token_from_bytes(got.map(|()| bytes))
}

/// The pure half of `new_poll_token`, so the FAILURE case can be tested.
///
/// It could not be before: `getrandom` succeeds in every test environment, so
/// the error branch was unreachable and a mutation returning a fixed,
/// predictable token in its place went undetected.
///
/// A token we could not randomise must NOT become a predictable one. An empty
/// string makes `expected_request` unmatchable, so the channel refuses every
/// poll and translation simply does not work. That is the safe direction: a
/// guessable capability string is worse than an unavailable feature.
fn token_from_bytes<E>(got: Result<[u8; 32], E>) -> String {
    let Ok(bytes) = got else {
        return String::new();
    };
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

impl TranslateOutbox {
    /// Builds a mailbox whose channel expects `poll:<token>`.
    pub fn with_token(token: &str) -> Self {
        Self {
            expected_request: if token.is_empty() {
                // Unmatchable on purpose; see `new_poll_token`.
                String::new()
            } else {
                format!("{TRANSLATE_POLL_REQUEST}:{token}")
            },
            ..Self::default()
        }
    }

    /// The exact string this channel will accept. Empty means the channel
    /// accepts nothing, which is what an unrandomised token produces.
    pub fn expected_request(&self) -> &str {
        &self.expected_request
    }

    /// Called by the HOST. Answers a parked poll if there is one, otherwise
    /// queues. Returns false if the message was dropped.
    pub fn deliver(&mut self, message: String) -> bool {
        if let Some(parked) = self.parked.take() {
            parked.answer(&message);
            return true;
        }
        if self.pending.len() >= MAX_PENDING_TRANSLATE_MESSAGES {
            return false;
        }
        self.pending.push_back(message);
        true
    }

    /// Called by the PAGE's poll. Takes a queued message if one is waiting.
    fn take_pending(&mut self) -> Option<String> {
        self.pending.pop_front()
    }

    /// Parks a poll, replacing any previous one. A page that polls twice
    /// without waiting for the first answer gets its earlier Promise rejected
    /// rather than being allowed to accumulate parked replies.
    fn park(&mut self, reply: ParkedReply) {
        self.parked = Some(reply);
    }

    /// Whether a poll is currently held open.
    pub fn is_parked(&self) -> bool {
        self.parked.is_some()
    }

    /// Drops everything. Called on navigation, which ends both the parked
    /// reply's validity and the user's consent for the page that is going
    /// away.
    pub fn clear(&mut self) {
        self.parked = None;
        self.pending.clear();
        self.cleared = self.cleared.wrapping_add(1);
    }

    /// How many times `clear` has run. See the field.
    pub fn clears(&self) -> u64 {
        self.cleared
    }
}

/// The signal handler.
///
/// EVERYTHING ARRIVING HERE IS UNTRUSTED and was assembled by a script in a
/// hostile document. It is accepted only as a string, capped at the door like
/// the one-way channel, and handed to the answering closure as an opaque
/// `&str`; nothing on this path parses it.
///
/// Returning TRUE claims the message. Returning FALSE would leave the page's
/// Promise hanging, so every path below answers -- with a value or with a
/// refusal -- before returning.
///
/// THIS RUNS ACROSS AN `extern "C"` BOUNDARY, so a panic here aborts the
/// process rather than unwinding. Phase 0 lost three hardware runs to exactly
/// that in a protocol handler. Hence no indexing, no unwrap, and no
/// allocation that is not bounded by the cap.
unsafe extern "C" fn reply_trampoline(
    _ucm: *mut webkit2gtk_sys::WebKitUserContentManager,
    raw_value: *mut javascriptcore_rs_sys::JSCValue,
    reply: *mut webkit2gtk_sys::WebKitScriptMessageReply,
    user_data: glib_sys::gpointer,
) -> glib_sys::gboolean {
    use javascriptcore::ValueExt;
    use webkit2gtk::glib::translate::{FromGlibPtrNone, ToGlibPtr};

    if raw_value.is_null() || reply.is_null() || user_data.is_null() {
        return 0;
    }
    // SAFETY: borrowed, never reclaimed -- the mailbox must survive every
    // message on this channel and is freed only by `drop_answer`.
    let outbox = unsafe { &*(user_data as *const Rc<RefCell<TranslateOutbox>>) };
    // A re-entrant borrow would panic, and a panic here ABORTS (see above), so
    // the borrow is attempted rather than asserted. Nothing in this function
    // calls back into the outbox, so this should never fail; if it somehow
    // does, the page gets a refusal instead of the process getting killed.
    let Ok(mut outbox) = outbox.try_borrow_mut() else {
        unsafe { reply_error(reply, "refused") };
        return 1;
    };

    // SAFETY: the gir declares this parameter `transfer-ownership="none"`, so
    // the emitter owns it for the duration of the signal and `from_glib_none`
    // -- which takes a reference rather than ownership -- is the correct
    // translation. Anything else would over- or under-unref a value the page
    // still has a handle to.
    let value = unsafe { javascriptcore::Value::from_glib_none(raw_value) };

    if !value.is_string() {
        unsafe { reply_error(reply, "refused") };
        return 1;
    }
    let request = value.to_str().to_string();
    if request.len() > MAX_CONTENT_TRANSLATE_BYTES {
        unsafe { reply_error(reply, "refused") };
        return 1;
    }

    // The only request this channel understands, and it now carries a token
    // only the top frame has. A page can post any string at all; anything
    // that is not an exact match is refused without inspection, which keeps
    // the accepted surface a single string rather than a parser.
    //
    // CONSTANT TIME, because the expected value is a secret. A byte-at-a-time
    // comparison that returns early leaks the token's prefix to a frame that
    // can time its own rejected polls, and a frame that can do that can
    // recover the whole token one byte at a time.
    if !poll_is_accepted(&request, outbox.expected_request()) {
        unsafe { reply_error(reply, "refused") };
        return 1;
    }

    // Something already waiting: answer immediately.
    if let Some(message) = outbox.take_pending() {
        let Some(ctx) = value.context() else {
            unsafe { reply_error(reply, "refused") };
            return 1;
        };
        let out = javascriptcore::Value::new_string(&ctx, Some(message.as_str()));
        let raw_out: *mut javascriptcore_rs_sys::JSCValue = out.to_glib_none().0;
        // SAFETY: `raw_out` is a live JSCValue in the context the request
        // arrived on, and this path answers the reply exactly once.
        unsafe { webkit2gtk_sys::webkit_script_message_reply_return_value(reply, raw_out.cast()) };
        return 1;
    }

    // Nothing to say yet, so hold the poll open rather than answering
    // "nothing" and forcing the page to ask again on a timer.
    let Some(ctx) = value.context() else {
        unsafe { reply_error(reply, "refused") };
        return 1;
    };
    // SAFETY: `reply` is non-null and unanswered on this path; `park` takes
    // the ref that keeps it alive past this handler.
    outbox.park(unsafe { ParkedReply::park(reply, ctx) });
    1
}

/// Sends one host-authored message to a content page.
///
/// THE PLATFORM-NEUTRAL SEAM. Windows has `PostWebMessageAsJson` and this
/// backend has a parked reply; callers get one function either way and never
/// learn which mechanism carried it. Returns false when the message was
/// dropped, so a caller can report a failure rather than assume delivery.
///
/// `message` is HOST-AUTHORED JSON and crosses as DATA. Nothing on this path
/// builds JavaScript source, which is what keeps translated text -- text that
/// came from a page and is about to go back into one -- off any evaluation
/// path in either direction.
pub fn deliver_translation(_webview: &WebView, view: &TabView, message: String) -> bool {
    // The webview is unused HERE and load-bearing on Windows, which is the
    // point of taking both: state.rs calls one function and never learns which
    // engine carried the message.
    view.translate_outbox.borrow_mut().deliver(message)
}

/// Whether a document in this tab is listening for translation commands.
///
/// The platform-neutral readiness signal. On this backend that means a poll is
/// parked; on Windows it means the page announced itself. Both answer the same
/// question -- is there a document that would act on a command -- and neither
/// is inferred from a pref. A tab showing a PDF, an error page, or a document
/// whose script was blocked reports false, which is the right answer.
pub fn translate_page_ready(view: &TabView) -> bool {
    view.translate_outbox.borrow().is_parked()
}

/// Whether this tab's page currently has a poll open with the host.
///
/// The honest readiness signal, and the reason the UI does not have to guess:
/// it is true only once a document has actually opened its poll, so it
/// distinguishes "the channel was registered" from "a page is listening on
/// it". A tab showing a PDF, an error page, or a document whose script was
/// blocked reports false, which is the right answer.
pub fn translate_poll_parked(view: &TabView) -> bool {
    view.translate_outbox.borrow().is_parked()
}

/// How many times this tab's mailbox has been cleared.
///
/// The observable form of "translation consent died with the page". A caller
/// that saw this number change knows the previous page's session is gone, and
/// that is checkable in a way that the mailbox's momentary contents are not.
pub fn translate_outbox_clears(view: &TabView) -> u64 {
    view.translate_outbox.borrow().clears()
}

/// The one string this channel accepts. Not a protocol: a doorbell.
///
/// The page cannot ask for a specific tab, page, or language through it -- the
/// insecure-continue discipline the rest of the product uses, applied to the
/// one channel a hostile document can reach. Everything about WHAT gets
/// translated is decided host-side from state the page never supplies.
pub const TRANSLATE_POLL_REQUEST: &str = "poll";

/// Equality that does not leak where two byte strings first differ.
///
/// The poll token is a secret held by one frame, so a frame that can time its
/// own refusals must not be able to learn it a byte at a time. Length is
/// compared first and separately, which reveals only the length -- a fixed
/// 64-hex-character value here, so it reveals nothing.
/// Whether a poll may be answered: the whole accept decision, in one place.
///
/// Extracted from the trampoline because a security decision inside an
/// `unsafe extern "C"` function is a decision no test can drive. A mutation
/// that inverted the empty-token guard -- turning "an unrandomised channel
/// accepts nothing" into "accepts everything" -- went undetected while this
/// logic lived there and the test merely restated the condition.
///
/// An EMPTY expected value accepts nothing. That is not a degenerate case to
/// tidy away: it is what an unrandomised token produces, and the channel must
/// refuse rather than open.
fn poll_is_accepted(request: &str, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    constant_time_eq(request.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A refusal the page sees as a rejected Promise.
///
/// ONE FIXED TOKEN for every refusal, never anything derived from what the
/// page sent and never a reason. A refusal that explained itself would tell a
/// hostile page which of its probes got closest, and a refusal that echoed
/// would make this an echo channel.
unsafe fn reply_error(reply: *mut webkit2gtk_sys::WebKitScriptMessageReply, token: &str) {
    if let Ok(msg) = std::ffi::CString::new(token) {
        // SAFETY: `reply` is non-null on every caller path and answered once.
        unsafe {
            webkit2gtk_sys::webkit_script_message_reply_return_error_message(reply, msg.as_ptr())
        };
    }
}

/// Cap on a single page-to-host translation message.
///
/// 1 MiB. Phase 0 measured no payload ceiling below 16 MiB in the other
/// direction, which is a fact about the ENGINE's tolerance, not a licence for
/// a page to send that much: the extractor batches deliberately, so anything
/// approaching this is a page misbehaving rather than a document being long.
const MAX_CONTENT_TRANSLATE_BYTES: usize = 1024 * 1024;

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
        install_bundled_filters(&ucm);
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

/// WebKitGTK's Intelligent Tracking Prevention is only enabled or disabled;
/// it has no Strict/Balanced level corresponding to WebView2's profile API.
/// The Windows-only IPC arm refuses before this can be called, but the
/// platform abstraction keeps one shape and records the honest answer.
pub fn set_tracking_prevention(
    _webview: &WebView,
    view: &TabView,
    _level: crate::prefs::TrackingPreventionLevel,
) -> TrackingPreventionState {
    view.state.borrow_mut().tracking_prevention = TrackingPreventionState::NotAttempted;
    TrackingPreventionState::NotAttempted
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
        install_bundled_filters(&ucm);
    }
}

/// Per-site override: `host` keeps working even while the tab is frozen.
/// When the freeze filter is installed it is recompiled with the new
/// unless-domain list (freeze semantics documented in privacy.rs).
/// Set or clear this tab's ad-list override. Same call in both directions so
/// the revocation cannot be the path nobody wrote. Read by `decide_request` on
/// Windows; on WebKitGTK there is no per-host exception (see
/// `adlist_consent::CAN_ALLOW`), so this only keeps the state honest.
pub fn set_adlist_override(view: &TabView, host: Option<String>) {
    view.state.borrow_mut().set_adlist_override(host);
}

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

/// Not implemented on this backend -- always refuses.
///
/// The browser-wide clear is refused here even though WebKitGTK CAN clear
/// whole-manager data: `WebKitWebsiteDataManager::clear` takes a data-type
/// mask, and the type this feature is allowed to touch is cookies alone. That
/// call is reachable, so this is a "not built and not tested on this backend"
/// refusal rather than an engine limit, and it is stated as one instead of
/// being dressed up as impossibility. Windows-only for this pass, like its
/// per-site neighbour above; see `windows.rs` for the real implementation.
pub fn forget_all_cookies(_webview: &WebView) -> bool {
    false
}

/// Cap matches windows.rs: enough to hold a session's enforcement failures,
/// small enough that the export stays readable.
const DIAG_LOG_CAP: usize = 50;
static DIAG_LOG: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<String>>> =
    std::sync::OnceLock::new();

fn diag_log() -> &'static std::sync::Mutex<std::collections::VecDeque<String>> {
    DIAG_LOG.get_or_init(|| {
        std::sync::Mutex::new(std::collections::VecDeque::with_capacity(DIAG_LOG_CAP))
    })
}

/// Records an enforcement failure so a user can export it.
///
/// This backend had NO diagnostic log until 2026-09-01: `recent_diagnostics`
/// returned an empty vec and every content-filter failure on Linux was
/// discarded. That was survivable while the ad rules were 59 hosts that always
/// compiled. It stops being survivable as the lists grow: WebKit refuses a
/// compiled list over an undocumented ceiling and refuses patterns outside its
/// regex subset, and either refusal installs NOTHING while the UI goes on
/// saying ad blocking is on. A red-team pass named that as the one failure in
/// the ad path with no way for a user -- or us -- to find out it had happened.
///
/// Same shape as windows.rs's `diag` deliberately, including recording in
/// release builds: the `eprintln!` is the only trace a debug run has, and a
/// release build needs the ring buffer or the failure is unreachable again.
/// A poisoned lock is treated as "nothing to log this time"; diagnostics must
/// never be the thing that brings down the browser.
fn diag(message: &str) {
    if cfg!(debug_assertions) {
        eprintln!("patanyx: {message}");
    }
    if let Ok(mut log) = diag_log().lock() {
        if log.len() >= DIAG_LOG_CAP {
            log.pop_front();
        }
        log.push_back(message.to_string());
    }
}

/// A snapshot of the diagnostic log, oldest first. Read-only, so opening the
/// export panel twice shows everything both times.
pub fn recent_diagnostics() -> Vec<String> {
    diag_log()
        .lock()
        .map(|log| log.iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod diag_tests {
    use super::{diag, recent_diagnostics, DIAG_LOG_CAP};


    #[test]
    fn the_log_records_a_failure_and_stays_bounded() {
        // ONE test, not two, because `diag` writes to a process-global ring
        // buffer and cargo runs tests in parallel: split in two, the
        // bounded-ness check evicted the entry the other test was asserting
        // on, and the pair passed or failed depending on interleaving. A
        // flaky test is worse than no test -- it teaches people to re-run.
        diag("ad/tracker filter not installed: probe");
        let first = recent_diagnostics();
        assert!(
            first.iter().any(|l| l.contains("probe")),
            "a recorded failure did not reach the export"
        );
        // Read-only: opening the export panel twice must show it both times.
        assert_eq!(first, recent_diagnostics(), "reading the log drained it");

        // A ring buffer, not an unbounded leak: a wedged engine retrying on
        // every tab must not grow this without limit.
        for i in 0..(DIAG_LOG_CAP * 2) {
            diag(&format!("bound probe {i}"));
        }
        assert!(recent_diagnostics().len() <= DIAG_LOG_CAP);
    }
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

/// Whether the current document was loaded over plain HTTP. For the Info tab's
/// "not encrypted" row.
pub fn page_insecure(view: &TabView) -> bool {
    view.state.borrow().page_insecure
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

/// The current page's certificate issuer, for DISPLAY ONLY.
///
/// Prefers the live certificate; falls back to the issuer stored when a cert
/// error was observed. `None` when there is no TLS or the engine exposes no
/// issuer. Nothing downstream may branch on this string -- it is shown, never
/// consulted; `tls_state`'s verdict is the decision.
pub fn tls_issuer(webview: &WebView, view: &TabView) -> Option<String> {
    use webkit2gtk::WebViewExt;
    use wry::WebViewExtUnix;
    match webview.webview().tls_info() {
        Some((certificate, _errors)) => issuer_name(&certificate),
        None => view.state.borrow().tls_issuer.clone(),
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

pub fn fingerprint_probe_reporting(view: &TabView) -> &'static str {
    view.state.borrow().fingerprint_probe_reporting.as_str()
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
/// Opens WebKitGTK's inspector on this CONTENT webview.
///
/// Aimed explicitly for the same reason the Windows side is: the engine's own
/// key handling follows focus, and the privileged chrome must never be the
/// thing that opens. Developer extras are enabled on content views only.
pub fn open_devtools(webview: &WebView) {
    use webkit2gtk::WebInspectorExt as _;
    use webkit2gtk::WebViewExt as _;
    use wry::WebViewExtUnix;

    let Some(inspector) = webview.webview().inspector() else {
        eprintln!("patanyx devtools: WebKitGTK returned no inspector for this view");
        return;
    };
    inspector.show();
}

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
            let copy = std::slice::from_raw_parts(bytes as *const u8, len).to_vec();
            // The adlist placeholder is loaded with load_html under the held
            // URL, so WebKit reports OUR bytes as that URL's main resource.
            // They are a static document this binary wrote, never anything a
            // server sent, and they must not become the site's integrity
            // evidence (review R-001, round 3). Byte identity is exact here
            // in the way the Windows response nonce is exact there. A site
            // that serves these precise bytes gets "no page", which is the
            // closed direction.
            if copy == crate::adlist_consent::PLACEHOLDER_HTML.as_bytes() {
                Err(PageBytesError::NoMainResource)
            } else {
                Ok(copy)
            }
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
    let initial =
        *INITIAL_PREFER_DARK.get_or_init(|| settings.is_gtk_application_prefer_dark_theme());
    let prefer_dark = match theme {
        crate::prefs::PageTheme::Auto => initial,
        crate::prefs::PageTheme::Dark => true,
        crate::prefs::PageTheme::Light => false,
    };
    settings.set_gtk_application_prefer_dark_theme(prefer_dark);
    true
}

// ---- page capture ----

/// Ask WebKitGTK for the requested snapshot region and deliver PNG bytes (or
/// an honest failure) as a UserEvent. The callback runs on the GTK main
/// thread; nothing here blocks the UI while the engine renders.
///
/// PNG encoding goes through gdk-pixbuf (already in the tree via gtk)
/// rather than cairo's own PNG writer, which sits behind a cargo feature
/// this workspace does not enable -- and enabling features for one
/// screenshot path is exactly the dependency creep the project refuses.
pub fn capture_page(
    webview: &WebView,
    proxy: &EventLoopProxy<UserEvent>,
    requested: crate::capture::CaptureScope,
) {
    use webkit2gtk::{SnapshotOptions, SnapshotRegion, WebViewExt};
    use wry::WebViewExtUnix;
    let native = webview.webview();
    let proxy = proxy.clone();
    let (region, scope) = match requested {
        crate::capture::CaptureScope::VisibleArea => (
            SnapshotRegion::Visible,
            crate::capture::CaptureScope::VisibleArea,
        ),
        crate::capture::CaptureScope::FullPage => (
            SnapshotRegion::FullDocument,
            crate::capture::CaptureScope::FullPage,
        ),
    };
    native.snapshot(
        region,
        SnapshotOptions::NONE,
        webkit2gtk::gio::Cancellable::NONE,
        move |result| {
            let png: Result<Vec<u8>, &'static str> = (|| {
                let surface = result.map_err(|_| "capture_engine_failed")?;
                // A snapshot surface has no live device state to flush; the
                // conversion reads it as-is. Width/height come from the
                // surface itself via the pixbuf helper's full-extent read.
                let image = gtk::gdk::cairo::ImageSurface::try_from(surface)
                    .map_err(|_| "capture_engine_failed")?;
                let width = image.width();
                let height = image.height();
                if width <= 0 || height <= 0 {
                    return Err("no_capture_page");
                }
                let pixbuf = gtk::gdk::pixbuf_get_from_surface(&image, 0, 0, width, height)
                    .ok_or("capture_engine_failed")?;
                pixbuf
                    .save_to_bufferv("png", &[])
                    .map_err(|_| "capture_engine_failed")
            })();
            // The event records the region actually passed to WebKitGTK;
            // the preference never gets to relabel the returned picture.
            let _ = proxy.send_event(UserEvent::Capture(crate::capture::CaptureEvent {
                png,
                scope,
            }));
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

/// What the chrome is using along the top, in logical pixels.
///
/// Stored rather than applied: the overlay's position handler reads it on
/// every allocation, so `queue_resize` is the whole of "apply". That is what
/// makes a window resize need nothing here -- the old size request had to be
/// re-honoured by GTK, this is re-read by GTK.
pub fn set_chrome_height(hosts: &Hosts, px: i32) {
    let (_, left, right) = hosts.insets.get();
    hosts.insets.set((px, left, right));
    hosts.chrome_box.queue_resize();
    hosts.vbox.queue_resize();
}

/// The CLOSED strip's height, which is where the page starts.
///
/// Stated by the chrome rather than worked out here. `set_chrome_height`
/// receives the panel's height while a modal is open, and deciding which kind
/// of height had arrived by consulting the arrangement was wrong: the two
/// commands are not ordered, so a panel height could be recorded as the strip
/// and leave the page pushed down for as long as the modal lasted.
pub fn set_chrome_strip(hosts: &Hosts, px: i32) {
    if hosts.strip_top.get() != px {
        hosts.strip_top.set(px);
        hosts.root.queue_resize();
    }
}

/// The title bar is the window manager's on this backend, and its colour is
/// the desktop theme's, not ours: GTK draws no caption of its own for a
/// server-side-decorated window and this app does not ask for client-side
/// decorations. Accepted so state.rs has one call on both platforms; the
/// chrome's own frame is all the accent there is here.
pub fn set_window_accent(_hosts: &Hosts, _palette: &super::ChromePalette) -> bool {
    false
}

/// See `set_window_accent`: nothing to re-apply on this backend either.
pub fn reapply_window_accent(_hosts: &Hosts, _palette: &super::ChromePalette) {}

/// See `set_window_accent`: nothing to refresh on this backend.
pub fn refresh_window_accent(_hosts: &Hosts, _palette: &super::ChromePalette) {}

/// The window manager's answer; only the Windows backend acts on it.
pub fn window_is_maximized(hosts: &Hosts) -> bool {
    hosts._window.is_maximized()
}

/// See `set_chrome_height`: same mechanism, the left edge.
pub fn set_chrome_left(hosts: &Hosts, px: i32) {
    let (top, _, right) = hosts.insets.get();
    hosts.insets.set((top, px, right));
    hosts.chrome_box.queue_resize();
}

/// See `set_chrome_height`: same mechanism, the right edge.
pub fn set_chrome_right(hosts: &Hosts, px: i32) {
    let (top, left, _) = hosts.insets.get();
    hosts.insets.set((top, left, px));
    hosts.chrome_box.queue_resize();
}

pub fn layout(
    hosts: &Hosts,
    _chrome: &WebView,
    _active: Option<&WebView>,
    _chrome_height: i32,
    // Taken for one signature across both backends, and unused here: this
    // backend already holds the stated strip in `hosts.strip_top`, written by
    // `set_chrome_strip` and read by the size-allocate handler, so the value
    // reaches GTK's geometry by a different route than Windows'.
    _chrome_strip: i32,
    _chrome_left: i32,
    _chrome_right: i32,
    arrangement: ChromeLayout,
) {
    // The ARRANGEMENT is applied here; the geometry that follows from it is
    // not. `Overlay` is recorded and the tree re-laid out, and the root
    // overlay's position handler does the arithmetic on the next allocation:
    // the chrome takes the whole window and the page keeps the rectangle the
    // closed strip gave it. Before this the argument was ignored entirely, so
    // `ChromeLayout::Overlay` did nothing at all on this backend and the only
    // thing an open panel changed was the top inset -- which moved the page
    // rather than covering it.
    let lift = matches!(arrangement, ChromeLayout::Overlay);
    if hosts.lifted.get() != lift {
        hosts.lifted.set(lift);
        // The z-order IS the arrangement. Raising the chrome lets a modal
        // float over a page that keeps rendering; lowering it again puts the
        // page back on top, where it carves the chrome's L out of a
        // full-window allocation the way this backend always has.
        if lift {
            hosts.root.reorder_overlay(&hosts.chrome_box, -1);
        } else {
            hosts.root.reorder_overlay(&hosts.content_overlay, -1);
        }
        hosts.root.queue_resize();
    }
    // The REST is still nothing here, and for the same good reason as
    // before: the page's rectangle is computed by the root overlay's
    // position handler from the insets `set_chrome_height` and
    // `set_chrome_left` / `set_chrome_right` store, so it is already correct
    // on every allocation
    // -- including the ones GTK does on its own, which is what a resize is.
    //
    // `ChromeLayout::Split` still DOES NOTHING here. A docked pane needs a
    // pane widget to dock, which the sidebar work did not add; the geometry
    // it would need is now expressible (page_rect takes a pane width and the
    // handler could pass one), but the chrome asks `split_supported` before
    // offering the arrangement at all, so nobody is given a control that
    // quietly does nothing.
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
/// True once the chrome webview was found and its background colour set to
/// zero alpha.
///
/// HONEST LIMIT: `webkit_web_view_set_background_color` returns void, so this
/// records that the call was MADE on a real view, not that the compositor,
/// driver and engine combination actually composites it. A rendering failure
/// after a successful downcast would leave this true. It is the same shape as
/// the Windows flag but a weaker guarantee, and it is not a substitute for
/// looking at the window.
///
/// This used to be a hardcoded false, with a comment saying the lift was
/// "manual-geometry work that exists only in the Windows backend". The work
/// exists here now: the chrome is stacked above the page in the root overlay
/// and its background is transparent, so the page keeps its rectangle, keeps
/// rendering, and shows through the scrim. Dynamic rather than a constant for
/// the same reason the Windows one is: it reports what this process actually
/// did, not what the code hopes. If the downcast in `build_chrome` ever finds
/// no WebKitGTK view to clear, this stays false and the stylesheet keeps its
/// opaque cover, which would then be the truthful answer.
pub fn translucent_overlay_supported() -> bool {
    CHROME_TRANSPARENT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Set by `build_chrome` once the chrome view's background is cleared.
static CHROME_TRANSPARENT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Runtime WebKitGTK version and whether it is below the security floor.
///
/// These are the runtime getters, not the `WEBKIT_MAJOR_VERSION` compile-time
/// macros: the library is linked dynamically, so what we built against and
/// what is loaded can differ, and only the loaded one can be exploited.
pub fn engine_info() -> crate::platform::EngineInfo {
    // SAFETY: three argument-less getters returning plain integers. They are
    // safe to call before any WebKit object exists.
    // The pretend version, debug builds only; see
    // platform::debug_version_override.
    let found = crate::platform::debug_version_override().unwrap_or_else(|| unsafe {
        vec![
            webkit2gtk_sys::webkit_get_major_version(),
            webkit2gtk_sys::webkit_get_minor_version(),
            webkit2gtk_sys::webkit_get_micro_version(),
        ]
    });
    let compiled = &crate::platform::MIN_WEBKITGTK;
    let floor = crate::platform::effective_floor("WebKitGTK", compiled);
    crate::platform::EngineInfo {
        name: "WebKitGTK",
        below_floor: crate::platform::below_floor(&found, &floor),
        below_compiled_floor: crate::platform::below_floor(&found, compiled),
        version: Some(found),
        floor,
        compiled_floor: compiled,
        advisory: crate::platform::WEBKITGTK_ADVISORY,
        // The library the getters describe IS the loaded library: there is
        // no separately installed runtime to be newer than it.
        installed: None,
        version_source: crate::platform::EngineVersionSource::Running,
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

/// Strip the source address from a finished download's Mark-of-the-Web.
///
/// A no-op here: the `Zone.Identifier` stream is an NTFS feature and neither
/// WebKitGTK nor any Linux filesystem writes one. Present so `platform`
/// exposes one shape on both targets and the event loop stays free of
/// `#[cfg]`. See `platform::motw` for what the Windows arm does and why.
pub fn scrub_download_mark(_path: &std::path::Path) -> super::motw::Outcome {
    super::motw::Outcome::NotApplicable
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
            (k::i, Key::I),
            (k::I, Key::I),
            (k::Tab, Key::Tab),
            (k::F5, Key::F5),
            (k::F3, Key::F3),
            (k::F12, Key::F12),
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

/// The mailbox's bookkeeping, which is the half of the reply channel that can
/// be tested without a browser.
///
/// THE OTHER HALF CANNOT BE, and pretending otherwise would be the more
/// dangerous mistake: a wrong FFI signature or a mis-refcounted reply does not
/// fail a unit test, it corrupts memory at the first message. That half is
/// proven by `translate_channel_probe`, which drives a real WebKitGTK process
/// and has a sabotage mode so its own discrimination is demonstrable. These
/// tests cover the ordering and the bounds; the probe covers the FFI.
#[cfg(test)]
mod translate_outbox_tests {
    use super::*;

    #[test]
    fn a_bare_poll_is_no_longer_accepted() {
        // THE DEFECT. The channel accepted the public constant "poll", so any
        // frame in the webview -- including a cross-origin iframe -- could
        // post it, displace the top document's parked reply, and receive the
        // next delivery. Two independent review lenses found this.
        let outbox = TranslateOutbox::with_token("deadbeef");
        assert_eq!(outbox.expected_request(), "poll:deadbeef");
        assert_ne!(
            outbox.expected_request(),
            TRANSLATE_POLL_REQUEST,
            "the bare poll constant must not be the accepted request"
        );
    }

    #[test]
    fn a_wrong_or_absent_token_is_refused() {
        let outbox = TranslateOutbox::with_token("aabbcc");
        let expected = outbox.expected_request().as_bytes();
        for attempt in [
            "poll",            // the old public request
            "poll:",           // empty token
            "poll:aabbc",      // a prefix of the real one
            "poll:aabbccd",    // the real one plus a byte
            "poll:AABBCC",     // case changed
            "poll:ddeeff",     // a different token
            "",
        ] {
            assert!(
                !constant_time_eq(attempt.as_bytes(), expected),
                "{attempt:?} must not match"
            );
        }
        assert!(constant_time_eq(b"poll:aabbcc", expected));
    }

    #[test]
    fn an_unrandomised_token_accepts_nothing() {
        // The first version of this test was VACUOUS: it asserted
        // `expected.is_empty() || !eq(..)`, which short-circuits to true and
        // passes whatever the guard does. A mutation inverting the guard --
        // making an empty expected value accept EVERYTHING -- went
        // undetected. It now drives the real decision function.
        let outbox = TranslateOutbox::with_token("");
        assert!(outbox.expected_request().is_empty());
        for attempt in ["poll", "poll:", "", "poll:anything", "poll:0000"] {
            assert!(
                !poll_is_accepted(attempt, outbox.expected_request()),
                "{attempt:?} was accepted by an unrandomised channel"
            );
        }
    }

    #[test]
    fn the_accept_decision_is_exact() {
        let outbox = TranslateOutbox::with_token("aabbcc");
        let expected = outbox.expected_request();
        assert!(poll_is_accepted("poll:aabbcc", expected));
        for attempt in [
            "poll", "poll:", "poll:aabbc", "poll:aabbccd", "poll:AABBCC",
            "poll:ddeeff", "", "POLL:aabbcc", " poll:aabbcc",
        ] {
            assert!(!poll_is_accepted(attempt, expected), "{attempt:?} accepted");
        }
    }

    #[test]
    fn a_token_that_could_not_be_randomised_is_empty_not_predictable() {
        // The case that was unreachable before `token_from_bytes` existed:
        // getrandom succeeds in every test environment, so a mutation
        // returning a FIXED token in place of an empty one was invisible.
        let failed: Result<[u8; 32], ()> = Err(());
        assert_eq!(
            token_from_bytes(failed),
            "",
            "a token that could not be randomised must be empty, never a \
             predictable constant"
        );
        // And an empty token must close the channel, not open it.
        let outbox = TranslateOutbox::with_token(&token_from_bytes::<()>(Err(())));
        assert!(!poll_is_accepted("poll", outbox.expected_request()));
        assert!(!poll_is_accepted("poll:", outbox.expected_request()));

        // The success path still produces 32 bytes of hex.
        let ok: Result<[u8; 32], ()> = Ok([0xab; 32]);
        assert_eq!(token_from_bytes(ok), "ab".repeat(32));
    }

    #[test]
    fn constant_time_eq_is_length_safe_and_correct() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
        // Differing only in the LAST byte must still be false: an early-return
        // comparison would get this right too, which is why the timing
        // property is argued in the comment rather than asserted here.
        assert!(!constant_time_eq(b"poll:aaaaaaaa", b"poll:aaaaaaab"));
    }

    #[test]
    fn generated_tokens_are_long_and_distinct() {
        let a = new_poll_token();
        let b = new_poll_token();
        // 32 bytes as lowercase hex. An empty token is the documented
        // failure mode and would make this assertion fire, which is correct:
        // if the OS stops giving randomness we want to know.
        assert_eq!(a.len(), 64, "token is not 32 bytes of hex: {a:?}");
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two tokens collided");
    }

    #[test]
    fn the_extractor_carries_the_placeholder_the_host_substitutes() {
        // The two halves have to agree on the literal. If either side is
        // renamed the substitution silently does nothing, the script keeps
        // the placeholder as its request, and every poll is refused -- the
        // feature would break quietly rather than loudly.
        assert!(
            CONTENT_TRANSLATE_SCRIPT.contains("__PATANYX_POLL_REQUEST__"),
            "the extractor no longer carries the placeholder the host replaces"
        );
        let filled = CONTENT_TRANSLATE_SCRIPT
            .replace("__PATANYX_POLL_REQUEST__", "poll:token123");
        assert!(filled.contains("poll:token123"));
        assert!(
            !filled.contains("__PATANYX_POLL_REQUEST__"),
            "substitution left a placeholder behind"
        );
    }

    #[test]
    fn a_message_with_no_waiting_poll_is_queued_not_dropped() {
        let mut outbox = TranslateOutbox::default();
        assert!(outbox.deliver("first".into()));
        assert_eq!(outbox.take_pending().as_deref(), Some("first"));
        assert_eq!(outbox.take_pending(), None);
    }

    #[test]
    fn queued_messages_come_back_in_order() {
        // Extract-then-patch is a sequence, and a patch that arrived before
        // the extraction it belongs to would address nodes the page has not
        // collected yet.
        let mut outbox = TranslateOutbox::default();
        for n in 0..4 {
            assert!(outbox.deliver(format!("m{n}")));
        }
        let seen: Vec<String> = std::iter::from_fn(|| outbox.take_pending()).collect();
        assert_eq!(seen, vec!["m0", "m1", "m2", "m3"]);
    }

    #[test]
    fn the_queue_is_bounded_and_says_so() {
        // A page that never polls must not become a way to grow the host's
        // memory. The refusal is reported rather than silent, so a caller can
        // tell "delivered" from "dropped".
        let mut outbox = TranslateOutbox::default();
        for n in 0..MAX_PENDING_TRANSLATE_MESSAGES {
            assert!(outbox.deliver(format!("m{n}")), "message {n} should fit");
        }
        assert!(
            !outbox.deliver("one too many".into()),
            "the cap must reject rather than grow"
        );
    }

    #[test]
    fn clearing_drops_queued_work_and_is_counted() {
        // Navigation ends consent for the page that is going away, so nothing
        // queued for it may survive into the next document.
        let mut outbox = TranslateOutbox::default();
        outbox.deliver("for the old page".into());
        assert_eq!(outbox.clears(), 0);
        outbox.clear();
        assert_eq!(outbox.take_pending(), None, "queued work must not survive");
        assert_eq!(outbox.clears(), 1);
        outbox.clear();
        assert_eq!(
            outbox.clears(),
            2,
            "each clear counts, so a probe can see it"
        );
    }

    #[test]
    fn clearing_frees_the_queue_for_the_next_page() {
        // A tab that filled its queue and then navigated must not arrive at
        // the new document already full.
        let mut outbox = TranslateOutbox::default();
        for n in 0..MAX_PENDING_TRANSLATE_MESSAGES {
            outbox.deliver(format!("m{n}"));
        }
        assert!(!outbox.deliver("full".into()));
        outbox.clear();
        assert!(outbox.deliver("new page".into()));
    }

    #[test]
    fn the_poll_request_is_a_doorbell_and_carries_nothing() {
        // The page cannot name a tab, a page, or a language through this
        // channel. If this constant ever grows structure, the insecure-continue
        // discipline has been broken on the one channel a hostile document can
        // reach.
        assert_eq!(TRANSLATE_POLL_REQUEST, "poll");
        assert!(!TRANSLATE_POLL_REQUEST.contains(|c: char| c == '{' || c == '"'));
    }

    #[test]
    fn the_two_channels_have_distinct_names() {
        // They are registered separately and carry opposite directions; one
        // name for both would silently merge them.
        assert_ne!(TRANSLATE_CHANNEL, TRANSLATE_ASK_CHANNEL);
    }
}
