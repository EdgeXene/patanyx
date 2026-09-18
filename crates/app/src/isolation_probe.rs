//! The isolation battery, run INSIDE PATANYX against the real chrome webview.
//!
//! WHY THIS EXISTS RATHER THAN THE OUT-OF-TREE HARNESS. Phase 0 measured what
//! a second same-origin webview shares with a privileged one, and it measured
//! it in `examples/translate_spike.rs` against a stand-in page. Storage
//! partitioning depends on how the webviews are CONSTRUCTED, so that result
//! only transfers if the product builds its webviews the way the harness did.
//! It does -- `platform::new_webview_builder()` hands every webview one shared
//! `WebContext` over one profile directory, deliberately -- but "the harness is
//! configured the way the product is" is an argument, not a measurement. This
//! module is the measurement.
//!
//! Webview A is the REAL chrome webview: the real `index.html`, the real
//! `chrome.js`, the real `serve_chrome`, and above all the real IPC handler
//! that dispatches privileged commands. Webview B stands in for the translator:
//! same origin, same profile, same protocol, NO IPC handler.
//!
//! The sharpest question it answers is one no out-of-tree run could: B fires a
//! `postMessage`, and the probe watches the application's own `UserEvent::Ipc`
//! stream for it. If a probe-marked message arrives there, a view holding
//! hostile page text can drive the privileged command surface, and the design
//! is not merely leaky but broken.
//!
//! `#[cfg(debug_assertions)]` on the module, the platform helpers and the call
//! site keeps every line of this out of release binaries. The env var is a
//! second gate, not the only one: a build that ships must not contain the code
//! at all, rather than contain it and decline to run it.

use std::time::Duration;

use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoop};
use wry::WebView;

use crate::platform;
use crate::UserEvent;

/// The env gate. Debug builds only, and only when explicitly asked.
///
/// `=1` builds B the way the ORIGINAL design proposed: same origin as the
/// chrome UI, same protocol handler, same shared profile. That is the
/// arrangement phase 0 measured and found leaking, and it is kept runnable on
/// purpose -- a fix you cannot compare against the defect is not demonstrably
/// a fix.
///
/// `=2` builds B the way the design now says: its own `rbtranslate` origin,
/// its own data store, its own protocol handler. Same battery, so the two runs
/// are directly comparable.
pub fn enabled() -> bool {
    matches!(
        std::env::var("PATANYX_ISOLATION_PROBE").as_deref(),
        Ok("1") | Ok("2")
    )
}

/// Which arrangement to measure. See `enabled`.
fn separate_origin() -> bool {
    std::env::var("PATANYX_ISOLATION_PROBE").as_deref() == Ok("2")
}

fn log(line: &str) {
    use std::io::Write;
    println!("{line}");
    let _ = std::io::stdout().flush();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("patanyx-isolation-probe.jsonl")
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Writes from B. Every store is attempted; each records wrote / threw /
/// silently-dropped, because "it did nothing" is a different finding from
/// "it was blocked" and only one of them is safety.
fn write_script(mark: &str) -> String {
    format!(
        r#"(function(){{var m={m};var r={{}};
function t(k,f){{try{{r[k]=f()}}catch(e){{r[k]="THREW "+e.name}}}}
t("localStorage",function(){{localStorage.setItem("pxprobe",m);return localStorage.getItem("pxprobe")===m?"wrote":"readback-differs"}});
t("sessionStorage",function(){{sessionStorage.setItem("pxprobe",m);return sessionStorage.getItem("pxprobe")===m?"wrote":"readback-differs"}});
t("cookie",function(){{document.cookie="pxprobe="+m+"; path=/";return document.cookie.indexOf(m)>=0?"wrote":"silently-dropped"}});
t("indexedDB",function(){{var q=indexedDB.open("pxprobe",1);
  q.onupgradeneeded=function(){{q.result.createObjectStore("kv")}};
  q.onsuccess=function(){{try{{var x=q.result.transaction("kv","readwrite");x.objectStore("kv").put(m,"k");x.oncomplete=function(){{q.result.close()}}}}catch(e){{}}}};
  return "kicked"}});
t("broadcast",function(){{new BroadcastChannel("pxprobe").postMessage(m);return "posted"}});
t("ipcPostMessage",function(){{if(!(window.ipc&&window.ipc.postMessage))return "window.ipc absent";
  window.ipc.postMessage(JSON.stringify({{cmd:"PXPROBE_FROM_B",mark:m}}));return "fired"}});
t("chromeWebview",function(){{if(!(window.chrome&&window.chrome.webview&&window.chrome.webview.postMessage))return "absent";
  window.chrome.webview.postMessage(JSON.stringify({{cmd:"PXPROBE_FROM_B_CHROMEWV",mark:m}}));return "present and fired"}});
r.origin=String(location.origin);r.secureContext=window.isSecureContext;
t("reachChromeOrigin",function(){{var x=new XMLHttpRequest();try{{x.open("GET","rbchrome://localhost/index.html",false);x.send();return "REACHED status "+x.status}}catch(e){{return "blocked: "+e.name}}}});
return JSON.stringify(r)}})()"#,
        m = serde_json::to_string(mark).unwrap_or_else(|_| "\"x\"".into())
    )
}

/// The navigation attempts, fired ONLY AFTER the storage verdict is in.
///
/// They used to live in `write_script`, and that was a measurement bug I
/// introduced: `location.href = ...` aborted the IndexedDB transaction the same
/// script had just opened, so nothing ever committed, so the chrome view read
/// "store absent" and the storage assertions could never fire. A shared-origin
/// run that HAD leaked would have been reported as clean. Storage first,
/// navigation after.
fn navigate_script() -> String {
    format!(
        r#"(function(){{var r={{}};
function t(k,f){{try{{r[k]=f()}}catch(e){{r[k]="THREW "+e.name}}}}
t("openChromeOrigin",function(){{var w=null;try{{w=window.open({chrome},"_blank")}}catch(e){{return "threw "+e.name}}
  if(!w)return "blocked/null";try{{w.close()}}catch(e2){{}}return "RETURNED A WINDOW"}});
t("navigateToChromeOrigin",function(){{try{{location.href={chrome};return "navigation attempted"}}catch(e){{return "threw "+e.name}}}});
return JSON.stringify(r)}})()"#,
        chrome = serde_json::to_string(platform::CHROME_URL).unwrap_or_else(|_| "\"\"".into())
    )
}

/// Installed on A BEFORE B writes, because a BroadcastChannel with no listener
/// proves nothing: the message would be dropped for want of a receiver rather
/// than by any boundary.
fn listen_script() -> &'static str {
    r#"(function(){if(window.__pxseen)return "already";window.__pxseen={bc:[]};
try{var c=new BroadcastChannel("pxprobe");c.onmessage=function(e){window.__pxseen.bc.push(String(e.data).slice(0,64))}}catch(e){window.__pxseen.bcErr=String(e)}
return "listening"})()"#
}

/// Reads from A. Reports the RAW value, not a verdict: "not visible" and "a
/// value from a previous session" look identical through a boolean, and that
/// difference was the whole finding on WebKitGTK.
fn read_script(mark: &str) -> String {
    format!(
        r#"(function(){{var m={m};var r={{}};
function v(x){{return x==null?"null":(x===m?"SEES B's MARKER":"other value: "+String(x).slice(0,40))}}
function t(k,f){{try{{r[k]=f()}}catch(e){{r[k]="THREW "+e.name}}}}
t("localStorage",function(){{return v(localStorage.getItem("pxprobe"))}});
t("sessionStorage",function(){{return v(sessionStorage.getItem("pxprobe"))}});
t("cookie",function(){{return document.cookie.indexOf(m)>=0?"SEES B's MARKER":"not visible"}});
t("broadcast",function(){{return window.__pxseen?JSON.stringify(window.__pxseen.bc):"no listener"}});
t("indexedDB",function(){{return window.__pxidb||"pending"}});
r.origin=String(location.origin);
return JSON.stringify(r)}})()"#,
        m = serde_json::to_string(mark).unwrap_or_else(|_| "\"x\"".into())
    )
}

/// Kicked separately because IndexedDB cannot answer synchronously and
/// `evaluate_script_with_callback` serializes sync returns only.
fn idb_kick_script(mark: &str) -> String {
    format!(
        r#"(function(){{var m={m};try{{var q=indexedDB.open("pxprobe",1);
q.onsuccess=function(){{try{{var db=q.result;
  if(!db.objectStoreNames.contains("kv")){{window.__pxidb="store absent";db.close();return}}
  var g=db.transaction("kv","readonly").objectStore("kv").get("k");
  g.onsuccess=function(){{window.__pxidb=(g.result===m?"SEES B's MARKER":(g.result==null?"null":"other value"));db.close()}};
  g.onerror=function(){{window.__pxidb="get error";db.close()}}}}catch(e){{window.__pxidb="THREW "+e.name}}}};
q.onerror=function(){{window.__pxidb="open error"}};return "kicked"}}catch(e){{return "THREW "+e.name}}}})()"#,
        m = serde_json::to_string(mark).unwrap_or_else(|_| "\"x\"".into())
    )
}

/// Runs the battery and exits the process. Never returns: it takes the event
/// loop, so the normal UI path is not reachable afterwards.
pub fn run(event_loop: EventLoop<UserEvent>, hosts: &platform::Hosts, chrome: &WebView) -> ! {
    // A fresh marker per run. A fixed string cannot tell "A sees what B just
    // wrote" apart from "A sees what B wrote in a previous run", because these
    // stores persist in the profile directory -- and that difference is the
    // finding.
    let mark = format!(
        "PXPROBE-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    log(&format!(
        "{{\"probe\":\"in-product isolation battery\",\"arrangement\":\"{}\",\"mark\":{},\"engine\":\"{}\"}}",
        if separate_origin() {
            "SEPARATE origin + own data store + own handler (the fix)"
        } else {
            "SHARED rbchrome origin + chrome handler (the original design)"
        },
        serde_json::to_string(&mark).unwrap_or_else(|_| "\"?\"".into()),
        if cfg!(windows) { "WebView2" } else { "WebKitGTK" }
    ));

    // B: the translator stand-in. Same factory as the chrome webview and the
    // content tabs, so it lands in the same profile directory by the same
    // route the product uses. Same custom protocol, exactly as the plan
    // proposed. NO ipc handler.
    let builder = if separate_origin() {
        // The fix under test: own origin, own data store, own handler. The
        // handler is serve_translator and NOT serve_chrome -- that is the part
        // that keeps the screen-capture and decrypted-archive endpoints out of
        // reach of a view holding hostile text.
        platform::new_translator_webview_builder()
            .with_url(platform::TRANSLATE_URL)
            .with_custom_protocol(
                platform::TRANSLATE_SCHEME.to_string(),
                move |_id, request: wry::http::Request<Vec<u8>>| crate::serve_translator(&request),
            )

    } else {
        // The original design, kept runnable so the fix has a control.
        platform::new_webview_builder()
            .with_url(platform::CHROME_URL)
            .with_custom_protocol(
                "rbchrome".to_string(),
                move |_id, request: wry::http::Request<Vec<u8>>| crate::serve_chrome(&request),
            )
    };
    // The fixed arrangement is built by the PRODUCTION function, so this gate
    // exercises the path the product will actually take rather than a
    // test-only parenting helper that could drift from it. The old
    // arrangement still uses build_probe, because build_translator is the
    // thing it is being compared against.
    let b = if separate_origin() {
        platform::build_translator(hosts, builder)
    } else {
        platform::build_probe(hosts, builder)
    };
    let b = match b {
        Ok(v) => v,
        Err(e) => {
            log(&format!("{{\"fatal\":\"probe webview build failed: {e}\"}}"));
            std::process::exit(2);
        }
    };

    let proxy = event_loop.create_proxy();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if proxy.send_event(UserEvent::ProbeDone).is_err() {
            break;
        }
    });

    let a_script = |wv: &WebView, tag: &'static str, js: &str| {
        let t = tag;
        if let Err(e) = wv.evaluate_script_with_callback(js, move |r| {
            log(&format!("{{\"{t}\":{r}}}"));
        }) {
            log(&format!("{{\"eval_error\":\"{tag}: {e}\"}}"));
        }
    };

    let chrome_ptr: *const WebView = chrome;
    let mut step = 0usize;
    // Anything the REAL ipc handler receives arrives here as UserEvent::Ipc.
    // A probe-marked message in this stream means B reached the privileged
    // command surface.
    let mut ipc_from_b = 0usize;
    let mut ipc_total = 0usize;

    event_loop.run(move |event, _target, control_flow| {
        *control_flow = ControlFlow::Wait;
        // SAFETY: `chrome` outlives the loop -- main.rs holds it, and this
        // closure never outlives main. Taken as a raw pointer only because the
        // borrow cannot be moved into a 'static closure.
        let a: &WebView = unsafe { &*chrome_ptr };

        if let Event::UserEvent(UserEvent::Ipc(body)) = &event {
            ipc_total += 1;
            if body.contains("PXPROBE_FROM_B") {
                ipc_from_b += 1;
                log(&format!(
                    "{{\"IPC_BOUNDARY_FAILED\":{}}}",
                    serde_json::to_string(body).unwrap_or_else(|_| "\"?\"".into())
                ));
            }
            return;
        }

        if let Event::UserEvent(UserEvent::ProbeDone) = event {
            step += 1;
            match step {
                4 => a_script(a, "a_listen", listen_script()),
                6 => a_script(&b, "b_write", &write_script(&mark)),
                9 => a_script(a, "a_idb_kick", &idb_kick_script(&mark)),
                // Storage verdict FIRST, while B's document is still the one
                // that wrote. Only then may B try to navigate.
                12 => a_script(a, "a_read", &read_script(&mark)),
                14 => a_script(&b, "b_navigate", &navigate_script()),
                // Does the REAL translator document boot the REAL engine? Only
                // meaningful in the separate-origin arrangement, where B is
                // serving translator.html from serve_translator; the shared
                // arrangement loads the chrome UI and has no __translator.
                16 => a_script(
                    &b,
                    "b_engine",
                    "String(window.__translator?__translator.status():'no __translator')",
                ),
                17 => {
                    // WHERE DID B END UP? "navigation attempted" and
                    // "navigation landed" are indistinguishable from the
                    // caller; only the resulting origin tells them apart.
                    a_script(
                        &b,
                        "b_origin_after_navigation",
                        "JSON.stringify({origin:String(location.origin),href:String(location.href).slice(0,90)})",
                    );
                }
                20 => {
                    log(&format!(
                        "{{\"ipc_boundary\":{{\"messages_real_handler_received\":{ipc_total},\
                         \"of_which_from_B\":{ipc_from_b},\"verdict\":\"{}\"}}}}",
                        if ipc_from_b == 0 {
                            "HELD: B could not reach the real IPC handler"
                        } else {
                            "FAILED: B REACHED THE PRIVILEGED COMMAND SURFACE"
                        }
                    ));
                    log("{\"done\":true}");
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    })
}
