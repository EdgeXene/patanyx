//! Phase-0 spike harness for on-device page translation. AN EXAMPLE, NEVER
//! SHIPPED: `cargo build` ignores examples unless asked, and nothing in the
//! product references this file.
//!
//! What it measures, per the approved plan's hardened phase 0:
//!   1. evaluate_script_with_callback payload ceilings, found by BOUNDARY
//!      SEARCH in both directions (host->page->host), with JSON-escaping
//!      and non-ASCII inflation in the probe text.
//!   2. The PRODUCTION loading path: engine + model served from a custom
//!      scheme (spike://), the same mechanism rbchrome:// uses, with real
//!      MIME types -- not file paths, not data URIs.
//!   3. Translation latency and reported memory for a real model.
//!   4. A first isolation probe: the translator webview gets NO ipc
//!      handler, and the page asserts window.ipc is absent.
//!
//! Artifacts are read from SPIKE_ASSETS (a directory holding the worker js,
//! wasm, and the three enes model files, hash-verified before this runs).
//! Results print to stdout as JSON lines; the run is driven by a timer.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use wry::WebViewBuilder;
#[cfg(not(windows))]
use wry::WebViewBuilderExtUnix;

/// Assets sit beside the executable unless SPIKE_ASSETS overrides it, so the
/// hardware run is "unzip one folder, double-click" with nothing to set up.
fn assets_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SPIKE_ASSETS") {
        return PathBuf::from(dir);
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// wry serves custom protocols under DIFFERENT URL forms per platform:
/// WebKitGTK uses the real scheme, WebView2 rewrites it to an
/// http://<scheme>.localhost/ host (src/custom_protocol_workaround.rs).
/// PATANYX itself splits CHROME_URL the same way (platform/mod.rs:668/671);
/// the first Windows spike run hardcoded the unix form, so the page never
/// loaded and the result file held nothing but the platform stamp.
/// The scheme name is the PRODUCT'S, not a stand-in. "It loaded from a file in
/// the spike" proves nothing about phase 2, so the harness serves the engine,
/// the model and the page the same way the chrome UI is served.
const SPIKE_SCHEME: &str = "rbchrome";
#[cfg(not(windows))]
const SPIKE_URL: &str = "rbchrome://localhost/translator.html";
#[cfg(windows)]
const SPIKE_URL: &str = "http://rbchrome.localhost/translator.html";

/// The EXACT policy every chrome asset ships with, copied verbatim from
/// main.rs:276. It is COPIED rather than imported because `patanyx` is a
/// binary crate with no lib target, so an example cannot name its private
/// items -- and a silent drift between the two would mean this measurement
/// answers a question about a policy the product does not have. Two guards
/// against that: the applied string is logged into the result file, and
/// `check_csp_drift` re-reads main.rs when the run happens inside the repo.
const PRODUCTION_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'";

/// Candidate policies for the translator document, each one directive further
/// from the chrome policy than the last. The point of naming them is that the
/// question "what does this feature cost in policy" gets answered by BISECTION
/// against a real engine, not by reasoning about specs -- and the answer is
/// the smallest of these that works, on both engines.
const CSP_CONNECT_SELF: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'";
const CSP_CONNECT_SELF_WASM: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'";

/// `SPIKE_CSP` selects the policy served on every response. Named modes cover
/// the bisection; anything else non-empty is used VERBATIM as the policy, so a
/// one-off directive can be tested without a rebuild. Default is no policy at
/// all, which is what the first runs measured and is deliberately NOT the
/// answer to "does this work in the product".
fn csp_header() -> Option<&'static str> {
    match std::env::var("SPIKE_CSP") {
        Ok(v) => match v.as_str() {
            "" | "off" | "none" => None,
            "production" => Some(PRODUCTION_CSP),
            "connect-self" => Some(CSP_CONNECT_SELF),
            "connect-self-wasm" => Some(CSP_CONNECT_SELF_WASM),
            // Leaked on purpose: the header wants &'static, this runs once per
            // process, and a spike is the one place that trade is free.
            other => Some(Box::leak(other.to_string().into_boxed_str())),
        },
        Err(_) => None,
    }
}

/// Best-effort drift check, meaningful only when run from the repo (the
/// hardware package ships no source). Reports rather than fails: a spike that
/// refuses to run on a tester's laptop because it cannot find main.rs
/// would be a worse instrument than one that says what it could not check.
fn check_csp_drift() -> &'static str {
    match std::fs::read_to_string("crates/app/src/main.rs") {
        Ok(src) => {
            if src.contains(PRODUCTION_CSP) {
                "matches main.rs"
            } else {
                "DRIFTED from main.rs"
            }
        }
        Err(_) => "unchecked (source not present)",
    }
}

fn mime_for(name: &str) -> &'static str {
    if name.ends_with(".wasm") {
        "application/wasm"
    } else if name.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if name.ends_with(".html") {
        "text/html; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

/// The isolation battery: TWO webviews, one process, ONE ORIGIN.
///
/// Every earlier run measured a single webview and concluded "no ipc handler,
/// so no channel". That is not the question. The question is what a view
/// holding hostile text can reach when a PRIVILEGED view of the same origin is
/// alive beside it -- shared storage, a broadcast channel, a same-origin frame,
/// and above all whether "this webview installed no ipc handler" is a boundary
/// at all when another webview in the same process installed one.
///
/// A is the stand-in for the chrome UI: it gets the ipc handler.
/// B is the translator: it gets none, and it is the one that probes.
fn run_isolation(out_path: PathBuf) {
    use std::sync::{Arc, Mutex};

    let log = {
        let p = out_path.clone();
        move |k: &str, v: &str| {
            use std::io::Write;
            let line = format!("{{\"{k}\":{v}}}");
            println!("{line}");
            let _ = std::io::stdout().flush();
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&p) {
                let _ = writeln!(f, "{line}");
            }
        }
    };

    let event_loop = EventLoopBuilder::<String>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let win_a = WindowBuilder::new().with_title("A: chrome stand-in").build(&event_loop).expect("window a");
    let win_b = WindowBuilder::new().with_title("B: translator").build(&event_loop).expect("window b");

    let protocol = |name: String| -> wry::http::Response<std::borrow::Cow<'static, [u8]>> {
        let safe = !name.is_empty() && !name.contains("..") && !name.contains('/') && !name.contains('\\');
        let body = if safe { std::fs::read(assets_dir().join(&name)).ok() } else { None };
        let b = match &body {
            Some(_) => wry::http::Response::builder().header("Content-Type", mime_for(&name)),
            None => wry::http::Response::builder().status(404).header("Content-Type", "text/plain"),
        };
        let b = match csp_header() {
            Some(c) => b.header("Content-Security-Policy", c),
            None => b,
        };
        match body {
            Some(bytes) => b.body(std::borrow::Cow::Owned(bytes)).expect("asset"),
            None => b.body(std::borrow::Cow::Borrowed(&b"not found"[..])).expect("404"),
        }
    };

    // A FRESH marker per run, stamped into both documents before their own
    // scripts run. With a fixed string the headline result is unreadable:
    // IndexedDB survives on disk, so "A sees B's marker" could equally mean
    // "A sees the marker B wrote twenty minutes ago", and the difference
    // between those two is the whole finding.
    let mark = format!(
        "RB-ISO-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let init = format!(
        "window.__RB_MARK={};",
        serde_json::to_string(&mark).unwrap_or_else(|_| "\"x\"".into())
    );
    log("isolation_marker", &serde_json::to_string(&mark).unwrap_or_else(|_| "\"?\"".into()));

    // Anything A's handler receives lands here. If a message sent BY B ever
    // shows up, the per-webview assumption is wrong and the whole privilege
    // split in the plan collapses.
    let ipc_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let mk = |url: &str, proto: fn(String) -> wry::http::Response<std::borrow::Cow<'static, [u8]>>| {
        let _ = proto;
        WebViewBuilder::new().with_url(url)
    };
    let _ = mk;

    let p_a = protocol;
    let builder_a = WebViewBuilder::new()
        .with_custom_protocol(SPIKE_SCHEME.to_string(), move |_id, request| {
            let path = request.uri().path().trim_start_matches('/').to_string();
            p_a(if path.is_empty() { "chromeprobe.html".into() } else { path })
        })
        .with_ipc_handler({
            let seen = ipc_seen.clone();
            move |req: wry::http::Request<String>| {
                if let Ok(mut v) = seen.lock() {
                    v.push(req.body().clone());
                }
            }
        })
        .with_initialization_script(&init)
        .with_url(chrome_url());

    let p_b = protocol;
    let builder_b = WebViewBuilder::new()
        .with_custom_protocol(SPIKE_SCHEME.to_string(), move |_id, request| {
            let path = request.uri().path().trim_start_matches('/').to_string();
            p_b(if path.is_empty() { "translator.html".into() } else { path })
        })
        .with_initialization_script(&init)
        .with_url(SPIKE_URL);

    #[cfg(not(windows))]
    let (wv_a, wv_b) = {
        use tao::platform::unix::WindowExtUnix;
        (
            builder_a.build_gtk(win_a.default_vbox().expect("vbox a")).expect("webview a"),
            builder_b.build_gtk(win_b.default_vbox().expect("vbox b")).expect("webview b"),
        )
    };
    #[cfg(windows)]
    let (wv_a, wv_b) = (
        builder_a.build(&win_a).expect("webview a"),
        builder_b.build(&win_b).expect("webview b"),
    );

    log("stage", "\"isolation: two webviews built, one origin\"");
    log("platform", &format!(
        "{{\"os\":\"{}\",\"engine\":\"{}\"}}",
        std::env::consts::OS,
        if cfg!(windows) { "WebView2" } else { "WebKitGTK" }
    ));

    let (tx, rx) = mpsc::channel::<(&'static str, String)>();
    let call = |wv: &wry::WebView, tag: &'static str, js: &str, tx: &mpsc::Sender<(&'static str, String)>| {
        let t = tx.clone();
        if let Err(e) = wv.evaluate_script_with_callback(js, move |r| { let _ = t.send((tag, r)); }) {
            let _ = tx.send(("eval_error", format!("\"{tag}: {e}\"")));
        }
    };

    let started = Instant::now();
    let proxy_tick = proxy.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if proxy_tick.send_event("tick".into()).is_err() { break; }
    });

    let mut step = 0usize;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        while let Ok((tag, r)) = rx.try_recv() {
            log("iso", &format!("{{\"{tag}\":{r}}}"));
        }
        if let Event::UserEvent(_) = event {
            step += 1;
            match step {
                2 => { call(&wv_b, "b_start", "String(window.__iso?__iso.start():'no __iso')", &tx); }
                6 => { call(&wv_a, "a_read", "String(window.__chrome?__chrome.read():'no __chrome')", &tx); }
                10 => {
                    call(&wv_b, "b_report", "window.__iso?__iso.report():'no __iso'", &tx);
                    call(&wv_a, "a_report", "window.__chrome?__chrome.report():'no __chrome'", &tx);
                }
                12 => {
                    // The decisive line. B fired a postMessage at step 2; if A's
                    // handler is process-wide rather than per-webview, it is in
                    // this list.
                    let seen = ipc_seen.lock().map(|v| v.clone()).unwrap_or_default();
                    let from_b = seen.iter().filter(|m| m.contains("RB-ISO-IPC-FROM-B")).count();
                    log("ipc_handler_crossing", &format!(
                        "{{\"messages_A_handler_received\":{},\"of_which_sent_by_B\":{},\"verdict\":\"{}\"}}",
                        seen.len(), from_b,
                        if from_b == 0 { "per-webview: B could not reach A's handler" }
                        else { "PROCESS-WIDE: B REACHED A's HANDLER" }
                    ));
                    log("done", "true");
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            }
            if started.elapsed() > Duration::from_secs(60) {
                log("fatal", "\"isolation timeout\"");
                *control_flow = ControlFlow::Exit;
            }
        }
    });
}

/// Webview A's document, platform-split exactly like the translator URL.
fn chrome_url() -> &'static str {
    #[cfg(not(windows))]
    { "rbchrome://localhost/chromeprobe.html" }
    #[cfg(windows)]
    { "http://rbchrome.localhost/chromeprobe.html" }
}

fn main() {
    // The result file and a panic hook come FIRST. On Windows this is
    // double-clicked with no console, so a panic that only reaches stderr is
    // invisible -- the first hardware run returned a file with nothing but
    // the platform stamp and no way to tell whether it crashed or stalled.
    let out_path = assets_dir().join("spike-result.jsonl");
    let _ = std::fs::write(&out_path, "");
    {
        let hook_path = out_path.clone();
        std::panic::set_hook(Box::new(move |info| {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&hook_path) {
                let _ = writeln!(
                    f,
                    "{{\"panic\":{}}}",
                    serde_json::to_string(&info.to_string()).unwrap_or_else(|_| "\"?\"".into())
                );
            }
        }));
    }
    if std::env::var("SPIKE_MODE").as_deref() == Ok("isolation") {
        run_isolation(out_path);
        return;
    }

    let event_loop = EventLoopBuilder::<String>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("translate spike")
        .build(&event_loop)
        .expect("window");

    // The translator webview: custom scheme, NO ipc handler -- the same
    // privilege split the real feature will use.
    // A protocol handler runs across an extern "C" boundary, so a panic inside
    // it does not unwind into Rust -- the process ABORTS. That is what killed
    // the first three hardware runs: WebView2 asks the custom scheme for
    // /favicon.ico on its own (WebKitGTK never does), the missing-file panic
    // aborted before the first tick, and the result file kept nothing but the
    // platform stamp. So: every miss is a 404, never a panic, and every
    // request is RECORDED, because "what does this engine fetch unprompted"
    // is exactly what phase 2 needs to know. The product's own serve_chrome
    // (main.rs:345) already 404s unknown paths and reads nothing from disk;
    // this was a harness defect, not a PATANYX one.
    let proto_log = out_path.clone();
    let protocol = move |name: String| -> wry::http::Response<std::borrow::Cow<'static, [u8]>> {
        use std::io::Write;
        let safe = !name.is_empty()
            && !name.contains("..")
            && !name.contains('/')
            && !name.contains('\\');
        let body = if safe {
            std::fs::read(assets_dir().join(&name)).ok()
        } else {
            None
        };
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&proto_log) {
            let _ = writeln!(
                f,
                "{{\"protocol\":{{\"path\":{},\"served\":{}}}}}",
                serde_json::to_string(&name).unwrap_or_else(|_| "\"?\"".into()),
                body.is_some()
            );
        }
        // Both arms build from &'static header values, so neither can fail.
        // The policy rides on EVERY response, exactly as serve_chrome does it.
        let builder = match &body {
            Some(_) => wry::http::Response::builder()
                .header("Content-Type", mime_for(&name))
                .header("Access-Control-Allow-Origin", "*"),
            None => wry::http::Response::builder()
                .status(404)
                .header("Content-Type", "text/plain; charset=utf-8"),
        };
        let builder = match csp_header() {
            Some(csp) => builder.header("Content-Security-Policy", csp),
            None => builder,
        };
        match body {
            Some(bytes) => builder
                .body(std::borrow::Cow::Owned(bytes))
                .expect("asset response"),
            None => builder
                .body(std::borrow::Cow::Borrowed(&b"not found"[..]))
                .expect("404 response"),
        }
    };
    let builder = WebViewBuilder::new()
        .with_custom_protocol(SPIKE_SCHEME.to_string(), move |_id, request| {
            let path = request.uri().path().trim_start_matches('/').to_string();
            protocol(if path.is_empty() { "translator.html".into() } else { path })
        })
        .with_url(SPIKE_URL);

    // Parent the webview the way the app does per platform: a realized GTK
    // box on unix (build_gtk), the window on Windows.
    #[cfg(not(windows))]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        // The realized container tao already parents into -- the same box the
        // app builds its chrome webview against (platform/unix.rs uses
        // default_vbox()). Adding a fresh GtkBox fails: the window already
        // has this child.
        let vbox = window.default_vbox().expect("default vbox");
        builder.build_gtk(vbox).expect("webview")
    };
    #[cfg(windows)]
    let webview = match builder.build(&window) {
        Ok(w) => w,
        Err(e) => {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&out_path) {
                let _ = writeln!(f, "{{\"webview_build_error\":{}}}",
                    serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"?\"".into()));
            }
            return;
        }
    };

    // Every callback is tagged with the probe it answers, so the single
    // drain below is unambiguous.
    let (tx, rx) = mpsc::channel::<(&'static str, String)>();
    // Results go to a FILE beside the exe as well as stdout.
    let log = move |k: &str, v: &str| {
        use std::io::Write;
        let line = format!("{{\"{k}\":{v}}}");
        println!("{line}");
        let _ = std::io::stdout().flush();
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&out_path) {
            let _ = writeln!(f, "{line}");
        }
    };

    // Phases, promoted in ONE place. A tick fires a probe for the current
    // phase; the callback drain advances the phase. No shared eval closure,
    // no second drain, no reading our own output.
    // Stamp the platform so a returned result file identifies its engine.
    log("stage", "\"webview-built\"");
    log("platform", &format!(
        "{{\"os\":\"{}\",\"engine\":\"{}\"}}",
        std::env::consts::OS,
        if cfg!(windows) { "WebView2" } else { "WebKitGTK" }
    ));
    // Which policy this run actually measured. Without this line a result file
    // cannot be told apart from one produced with no policy at all, and the
    // two answer completely different questions.
    log("csp", &format!(
        "{{\"applied\":{},\"drift\":{}}}",
        serde_json::to_string(csp_header().unwrap_or("none")).unwrap_or_else(|_| "\"?\"".into()),
        serde_json::to_string(check_csp_drift()).unwrap_or_else(|_| "\"?\"".into())
    ));

    let mut phase = 0usize;
    let mut payload_kib = 64usize;
    let mut last_ok_kib = 0usize;
    let mut sent = Instant::now();
    let started = Instant::now();
    let proxy_tick = proxy.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if proxy_tick.send_event("tick".into()).is_err() {
            break;
        }
    });

    // Eval errors were swallowed with `let _`; on a platform where stderr is
    // invisible that turned a hard failure into a silent stall.
    let err_tx = tx.clone();
    let call = move |wv: &wry::WebView, tag: &'static str, js: &str, tx: &mpsc::Sender<(&'static str, String)>| {
        let t = tx.clone();
        if let Err(e) = wv.evaluate_script_with_callback(js, move |r| {
            let _ = t.send((tag, r));
        }) {
            let _ = err_tx.send(("eval_error", format!("\"{tag}: {e}\"")));
        }
    };

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        // Drain: one place, phase advances here only.
        while let Ok((tag, r)) = rx.try_recv() {
            log("cb", &format!("{{\"{tag}\":{r}}}"));
            match tag {
                "ready" => {
                    // Match the FIELD, not the words. The probe payload also
                    // carries "probe":true, and a contains("ready") &&
                    // contains("true") test promotes on a boot-phase reply
                    // whose status is literally "ready":false. Callback
                    // results come back re-quoted, so both encodings count.
                    let is_ready = r.contains("\\\"ready\\\":true") || r.contains("\"ready\":true");
                    if is_ready && phase <= 1 {
                        log("engine_ready_ms", &started.elapsed().as_millis().to_string());
                        phase = 2;
                    }
                }
                "boundary" => {
                    if r.contains("len") {
                        last_ok_kib = payload_kib;
                        if payload_kib >= 16384 {
                            log("payload_boundary", &format!(
                                "{{\"proven_ok_kib\":{last_ok_kib},\"note\":\"no ceiling below 16MiB; search capped\"}}"
                            ));
                            phase = 3;
                        } else {
                            payload_kib *= 2;
                            phase = 2;
                        }
                    } else {
                        log("payload_boundary", &format!(
                            "{{\"last_ok_kib\":{last_ok_kib},\"failed_kib\":{payload_kib}}}"
                        ));
                        phase = 3;
                    }
                }
                "result" => {
                    if r != "null" && !r.is_empty() {
                        log("translation", &format!(
                            "{{\"wall_ms\":{},\"payload\":{}}}", sent.elapsed().as_millis(), r
                        ));
                        log("done", "true");
                        *control_flow = ControlFlow::Exit;
                    }
                }
                _ => {}
            }
        }

        if let Event::UserEvent(_) = event {
            // A policy-blocked run reaches its verdict in about two seconds and
            // then has nothing left to say, so the default 150s wait is pure
            // dead time when sweeping a matrix. SPIKE_MAX_MS shortens it.
            let budget_ms: u128 = std::env::var("SPIKE_MAX_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(150_000);
            if started.elapsed().as_millis() > budget_ms {
                log("fatal", "\"timeout\"");
                *control_flow = ControlFlow::Exit;
                return;
            }
            log("stage", &format!("{{\"tick\":{},\"phase\":{}}}", started.elapsed().as_millis(), phase));
            match phase {
                0 => {
                    // isolation probe: characterize window.ipc, then FIRE a
                    // postMessage from the page. This webview installed no
                    // ipc_handler, so a live handler firing is impossible;
                    // the boundary is proven by CONSEQUENCE -- the process
                    // never observes the message, because wry drops it.
                    call(&webview, "isolation",
                        "(function(){var r=window.__ipcprobe();try{window.ipc.postMessage('SPIKE_BOUNDARY_PROBE');}catch(e){}return r;})()", &tx);
                    phase = 1;
                }
                1 => {
                    // Poll status AND the policy log together. Under the real
                    // chrome CSP the interesting run is the one where __spike
                    // never appears at all, and a status-only probe reports
                    // that as an indefinite "boot" with no reason attached.
                    // __violations lives in its own file loaded first, so it
                    // survives the policy blocking everything after it.
                    call(&webview, "ready",
                        "JSON.stringify({probe:!!window.__probeLoaded,\
                         s:(window.__spike&&__spike.status())||{phase:'boot'},\
                         v:window.__violations?JSON.parse(__violations()):null})", &tx);
                }
                2 => {
                    // boundary search with escaping-hostile, non-ASCII content.
                    let unit = "x\"y\u{20ac}\u{2068}z";
                    let mut s = String::new();
                    while s.len() < payload_kib * 1024 {
                        s.push_str(unit);
                    }
                    let js = format!(
                        "(function(p){{return JSON.stringify({{len:p.length}});}})({})",
                        serde_json::to_string(&s).unwrap()
                    );
                    call(&webview, "boundary", &js, &tx);
                    phase = 21; // in-flight until the boundary callback lands
                }
                21 => {} // waiting on the boundary callback
                3 => {
                    sent = Instant::now();
                    call(&webview, "sent",
                        "String(__spike.translate('t1', Array.from({length:40},(_,i)=>'The quick brown fox number '+i+' jumps over the lazy dog near the riverbank.')))",
                        &tx);
                    phase = 4;
                }
                4 => {
                    call(&webview, "result", "JSON.stringify(__spike.result('t1'))", &tx);
                }
                _ => {}
            }
        }
    });
}
