//! Real WebKitGTK/Xvfb transport and native menu check. Not a hardware run.
use super::*;
use std::{
    process::Command,
    time::{Duration, Instant},
};
use wry::WebViewBuilderExtUnix;

fn pump_until(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }
        if done() {
            return;
        }
        assert!(Instant::now() < deadline, "native selection timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn xdo(args: &[&str]) -> String {
    let result = Command::new("xdotool").args(args).output().unwrap();
    assert!(result.status.success(), "xdotool failed");
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

#[test]
#[ignore = "requires an X server, WebKitGTK and xdotool; run alone under Xvfb"]
fn native_selection_menu() {
    use tao::platform::unix::EventLoopBuilderExtUnix;
    let events = tao::event_loop::EventLoopBuilder::<UserEvent>::with_user_event()
        .with_any_thread(true)
        .build();
    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title("Selection channel test");
    window.set_default_size(640, 400);
    let container = gtk::Box::new(gtk::Orientation::Vertical, 0);
    window.add(&container);
    let webview = wry::WebViewBuilder::new()
        .with_incognito(true)
        .build_gtk(&container)
        .unwrap();
    let capture = addon_selection::Capture::new(19);
    let channel = connect(&webview, capture.clone(), &events.create_proxy()).unwrap();
    super::super::connect_context_menu(&webview, &events.create_proxy(), Some(channel.clone()));
    addon_selection::set_test_menu_offer(Some(addon_selection::MenuOffer {
        receiver: addon_selection::ReceiverInfo {
            id: "test-receiver".into(),
            name: "Test receiver".into(),
        },
        label: "Send to Test receiver".into(),
    }));
    window.show_all();
    let clipboard = gtk::Clipboard::get(&gtk::gdk::SELECTION_CLIPBOARD);
    clipboard.set_text("selection-test-clipboard-sentinel");
    let xid = xdo(&["search", "--name", "^Selection channel test$"]);

    for (body, expected) in [
        ("<p id='s'>ordinary λ 🦀</p><script>let r=document.createRange();r.selectNodeContents(document.getElementById('s'));getSelection().addRange(r);</script>", "ordinary λ 🦀"),
        ("<textarea id='s' style='width:400px;height:100px'>textarea λ 🦀</textarea><script>let s=document.getElementById('s');s.focus();s.select();</script>", "textarea λ 🦀"),
        ("<div id='s' contenteditable style='width:400px;height:100px'>editable λ 🦀</div><script>let s=document.getElementById('s');s.focus();let r=document.createRange();r.selectNodeContents(s);getSelection().removeAllRanges();getSelection().addRange(r);</script>", "editable λ 🦀"),
        ("<iframe style='width:500px;height:150px' srcdoc=\"<p id='s'>framed text</p><script>window.focus();let r=document.createRange();r.selectNodeContents(document.getElementById('s'));getSelection().addRange(r);</script>\"></iframe>", "framed text"),
    ] {
        let html = format!("<!doctype html><meta charset='utf-8'><style>body{{margin:0;font:20px sans-serif}}p{{margin:0}}</style>{body}");
        let encoded: String = html.bytes().map(|b| format!("%{b:02x}")).collect();
        webview.load_url(&format!("data:text/html,{encoded}")).unwrap();
        pump_until(|| !webview.webview().is_loading() && !channel.borrow().polls.is_empty());
        xdo(&["windowfocus", &xid]);
        xdo(&["mousemove", "--window", &xid, "30", "15", "click", "3"]);
        pump_until(|| capture.borrow().test_snapshot().is_some());
        let (_, actual) = capture.borrow().test_snapshot().unwrap();
        assert_eq!(actual, expected);
        assert_eq!(clipboard.wait_for_text().as_deref(), Some("selection-test-clipboard-sentinel"));
        xdo(&["key", "Escape"]);
        pump_until(|| capture.borrow().test_snapshot().is_none());
    }
    addon_selection::set_test_menu_offer(None);
    unsafe {
        window.destroy();
    }
}
