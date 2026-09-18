//! Proves the host-to-page translation channel, INSIDE PATANYX, against a real
//! content webview built by the production path.
//!
//! WHY A RUNTIME PROBE AND NOT A UNIT TEST. The mechanism is hand-written FFI
//! against three `webkit2gtk-sys` symbols the safe bindings refuse to wrap, a
//! transmuted GObject signal handler, and a refcounted reply object parked
//! across the GTK main loop. Not one of those failure modes is visible to
//! `cargo test`: a wrong signature does not fail to compile, it corrupts the
//! stack at the first emission. The only evidence worth having is a real
//! WebKitGTK process moving a real string into a real document.
//!
//! WHAT IT MEASURES, in order, each step depending on the last:
//!   1. The page opened a poll and the HOST parked it. Proves the registration
//!      and the signal connection are live, and that the ABI of the trampoline
//!      matches what WebKitGTK calls.
//!   2. The host answered that parked poll and the page ACTED on it. Proves
//!      the reply carries a value into the page -- the direction that did not
//!      exist before, and the whole point of the exercise.
//!   3. Text the page extracted came back on the one-way channel. Proves the
//!      two halves are one conversation rather than two channels that each
//!      work alone.
//!   4. A patch changed the DOM. Verified by asking for a SECOND extraction
//!      and reading what comes back, NOT by evaluating script in the content
//!      webview -- which is exactly the thing the invariant forbids and this
//!      whole design exists to avoid. The verification therefore obeys the
//!      rule it is verifying.
//!
//! `#[cfg(debug_assertions)]` on the module and the call site keeps every line
//! out of release binaries, matching isolation_probe.rs. The env var is a
//! second gate, not the only one.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoop};

use crate::platform;
use crate::UserEvent;

/// The env gate. Debug builds only, and only when explicitly asked.
///
/// `=1` proves the CHANNEL: page to host, host to page, patch, navigation.
/// `=2` proves the ENGINE: the real translator webview, built by the
/// production path, loading a real language pack and producing real Spanish.
/// The two are separate because they fail in completely different ways and a
/// combined verdict would hide which half broke.
pub fn enabled() -> bool {
    matches!(
        std::env::var("PATANYX_TRANSLATE_PROBE").as_deref(),
        Ok("1") | Ok("2")
    )
}

fn engine_mode() -> bool {
    std::env::var("PATANYX_TRANSLATE_PROBE").as_deref() == Ok("2")
}

/// Set to make the host answer a poll it never received, so the probe's own
/// discrimination is provable.
///
/// A GATE THAT IS NEVER SEEN FAILING IS NOT A GATE. With this set the probe
/// skips the extract command entirely; every downstream assertion must then
/// report FAILED. If a "clean" run and a sabotaged run print the same verdict,
/// the probe is measuring nothing, and that is worth knowing before the
/// results are believed.
fn sabotage() -> bool {
    std::env::var("PATANYX_TRANSLATE_PROBE_SABOTAGE").as_deref() == Ok("1")
}

fn log(line: &str) {
    use std::io::Write;
    println!("{line}");
    let _ = std::io::stdout().flush();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("patanyx-translate-probe.jsonl")
    {
        let _ = writeln!(f, "{line}");
    }
}

fn j(v: &str) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "\"?\"".into())
}

/// The page under test. Ordinary prose in ordinary elements, plus the two
/// things the extractor promises to leave alone: an input the user could be
/// typing into, and a contenteditable. If either shows up in an extraction,
/// the privacy claim in the content script's header is false.
const PAGE: &str = r#"<!doctype html><meta charset="utf-8"><title>probe</title>
<body>
<h1>Hello world</h1>
<p>The quick brown fox.</p>
<p>Second paragraph here.</p>
<input value="SECRET-TYPED-VALUE">
<div contenteditable="true">SECRET-EDITABLE-VALUE</div>
<script>window.__pageScriptRan = true;</script>
</body>"#;

/// The document navigated to, to prove what happens to a PARKED reply when the
/// page holding its JS context goes away.
///
/// This is the memory-safety path, not a feature path. A parked reply keeps a
/// strong ref on a JSCContext belonging to a document that is about to be
/// destroyed; if clearing it on navigation were wrong, or if WebKitGTK objected
/// to a reply being dropped unanswered, the failure would be a crash rather
/// than a wrong answer.
const PAGE_AFTER_NAV: &str = r#"<!doctype html><meta charset="utf-8"><title>probe2</title>
<body><p>After navigation.</p></body>"#;

/// Proves the translator document end to end: engine boot, pack load, and a
/// real translation of real sentences.
///
/// WHAT MAKES THIS WORTH RUNNING. Phase 0 translated with this engine in a
/// standalone harness. That proved the ENGINE works; it did not prove that
/// PATANYX's translator webview -- built by `build_translator`, served by
/// `serve_translator`, under the translator CSP, reading a pack through the
/// `/pack/` route -- can do the same. Every one of those is a place the
/// standalone result does not transfer, and the CSP and the route are new.
///
/// It asserts on SPANISH, not merely on "some output". A translator that
/// returned its input unchanged would pass any check that only counted
/// strings, and that is exactly what a mis-loaded pack looks like.
fn run_engine(event_loop: EventLoop<UserEvent>, hosts: &platform::Hosts) -> ! {
    log(&format!(
        "{{\"probe\":\"translator engine\",\"pack_root\":{}}}",
        j(&std::env::var("PATANYX_PACK_ROOT").unwrap_or_else(|_| "<default profile>".into()))
    ));

    // ---- C9 real-page proof hooks -------------------------------------------
    // With NONE of these set this is the fixed en->es engine check the gate
    // runs, byte for byte. Setting them drives the SAME production path (same
    // builder, same loadPack contract, same poll loop) with a real pair, real
    // page text, and an optional substring the English output must carry --
    // which is how the Greek-page proof reads a real translation out of the
    // real pack instead of a bundled fixture.
    // An EMPTY pair is not a custom run -- Some("") must not flip grading to the
    // relaxed custom path. A custom run is one with a real pair set.
    let custom_pair = std::env::var("PATANYX_TRANSLATE_PROBE_PAIR")
        .ok()
        .filter(|p| !p.is_empty());
    let pair = custom_pair.clone().unwrap_or_else(|| "en-es".to_string());
    let from = std::env::var("PATANYX_TRANSLATE_PROBE_FROM").unwrap_or_else(|_| "en".to_string());
    let to = std::env::var("PATANYX_TRANSLATE_PROBE_TO").unwrap_or_else(|_| "es".to_string());
    // An EMPTY expected substring cannot be a real expectation (every string
    // contains ""), so it is treated as "no expectation" rather than a pass.
    let expect = std::env::var("PATANYX_TRANSLATE_PROBE_EXPECT")
        .ok()
        .filter(|e| !e.is_empty());
    let custom = custom_pair.is_some();
    // Custom grading is keyed on PAIR alone; TEXT/FROM/TO/EXPECT without it
    // would silently run (and grade) the default corpus under the caller's
    // nose. Refuse the half-configured run instead.
    //
    // NOTE, because this run's inputs and outputs go to the LOG: the caller
    // chooses the text, and the translations are printed for a human to judge.
    // Never feed this probe text from a private page.
    if !custom {
        for orphan in [
            "PATANYX_TRANSLATE_PROBE_TEXT",
            "PATANYX_TRANSLATE_PROBE_FROM",
            "PATANYX_TRANSLATE_PROBE_TO",
            "PATANYX_TRANSLATE_PROBE_EXPECT",
        ] {
            if std::env::var(orphan).is_ok() {
                log(&format!(
                    "{{\"fatal\":\"{orphan} is set but PATANYX_TRANSLATE_PROBE_PAIR is not; set the pair or unset it\"}}"
                ));
                std::process::exit(2);
            }
        }
    }

    // The PRODUCTION builder, protocol handler and parenting function. A
    // test-only arrangement here would prove something the product does not do.
    let builder = platform::new_translator_webview_builder()
        .with_url(platform::TRANSLATE_URL)
        .with_custom_protocol(
            platform::TRANSLATE_SCHEME.to_string(),
            move |_id, request: wry::http::Request<Vec<u8>>| crate::serve_translator(&request),
        );
    let view = match platform::build_translator(hosts, builder) {
        Ok(v) => v,
        Err(e) => {
            log(&format!("{{\"fatal\":\"translator build failed: {e}\"}}"));
            std::process::exit(2);
        }
    };

    let tick = event_loop.create_proxy();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if tick.send_event(UserEvent::ProbeDone).is_err() {
            break;
        }
    });

    // English in, and the Spanish these must become -- the default corpus.
    // Short, unambiguous sentences whose translations are not in dispute; the
    // point is to catch "no pack loaded" and "input echoed back", not to grade
    // the model. A custom run replaces them with real page text from the env.
    const DEFAULT_SOURCE: [&str; 3] = ["Hello world", "The quick brown fox.", "Good morning."];
    let source: Vec<String> = if custom {
        // A custom run's text is the whole point; a missing, malformed or empty
        // TEXT is a user error, not a reason to grade the default corpus.
        match std::env::var("PATANYX_TRANSLATE_PROBE_TEXT") {
            Ok(t) => match serde_json::from_str::<Vec<String>>(&t) {
                Ok(v) if !v.is_empty() && v.iter().any(|s| !s.trim().is_empty()) => v,
                _ => {
                    log("{\"fatal\":\"custom probe needs a non-empty PATANYX_TRANSLATE_PROBE_TEXT JSON array\"}");
                    std::process::exit(2);
                }
            },
            Err(_) => {
                log("{\"fatal\":\"custom probe needs PATANYX_TRANSLATE_PROBE_TEXT\"}");
                std::process::exit(2);
            }
        }
    } else {
        DEFAULT_SOURCE.iter().map(|x| x.to_string()).collect()
    };
    let mut step = 0usize;
    let mut asked_pack = false;
    let mut submitted = false;
    let mut output: Vec<String> = Vec::new();
    let mut engine_ready_ms: Option<i64> = None;
    let mut pack_ready_ms: Option<i64> = None;

    let proxy = event_loop.create_proxy();
    let view_ptr: *const wry::WebView = &view;

    event_loop.run(move |event, _target, control_flow| {
        *control_flow = ControlFlow::Wait;
        // SAFETY: `view` lives for the whole closure -- it is moved into this
        // scope and never dropped before the process exits. Taken as a raw
        // pointer only because the borrow cannot move into a 'static closure,
        // the same shape isolation_probe uses for the chrome webview.
        let view: &wry::WebView = unsafe { &*view_ptr };

        if let Event::UserEvent(UserEvent::TranslateEngine(json)) = &event {
            log(&format!("{{\"status\":{}}}", j(json)));
            let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
            let phase = v.get("phase").and_then(|p| p.as_str()).unwrap_or("");
            if let Some(ms) = v.get("engineReadyMs").and_then(|m| m.as_i64()) {
                engine_ready_ms = Some(ms);
            }
            if let Some(ms) = v.get("packReadyMs").and_then(|m| m.as_i64()) {
                pack_ready_ms = Some(ms);
            }
            if phase == "failed" {
                log(&format!("{{\"FAILED\":{}}}", j(json)));
                log("{\"done\":true}");
                std::process::exit(1);
            }
            if phase == "engine-ready" && !asked_pack {
                asked_pack = true;
                // The GEMM hint mirrors production: the registry row's source
                // decides, and a pair the registry does not carry falls back to
                // the historical setting (overridable for probe experiments).
                // An explicit override wins outright, in EITHER direction.
                // Telling a model that NEEDS alphas from one that merely
                // carries them requires running the same pack both ways, and
                // the registry alone can never express that comparison.
                let forced = std::env::var("PATANYX_TRANSLATE_PROBE_GEMM")
                    .ok()
                    .and_then(|g| match g.as_str() {
                        "int8shiftAlphaAll" => Some("int8shiftAlphaAll"),
                        "int8shiftAll" => Some("int8shiftAll"),
                        _ => None,
                    });
                let row = crate::languages::pair_by_token(&pair);
                let gemm = forced.or_else(|| row
                    .map(|row| {
                        if row.source == "opus-mt" { "int8shiftAlphaAll" } else { "int8shiftAll" }
                    })
                    .or(std::env::var("PATANYX_TRANSLATE_PROBE_GEMM")
                        .ok()
                        .filter(|g| g == "int8shiftAlphaAll")
                        .map(|_| "int8shiftAlphaAll"))
                    ).unwrap_or("int8shiftAll");
                // The vocabulary layout likewise comes from the registry, as
                // production does it: a split pair is handed two segmenters,
                // and asking for the wrong one 404s on a file that does not
                // exist in that pack.
                let vocab = row.map(|r| r.vocab).unwrap_or("joint");
                let script = format!(
                    "window.__translator.loadPack({})",
                    // from/to explicit, matching the production loadPack contract.
                    crate::state::js_string(
                        &serde_json::json!({
                            "pair": pair, "from": from, "to": to,
                            "gemm": gemm, "vocab": vocab,
                        })
                        .to_string()
                    )
                );
                let _ = view.evaluate_script(&script);
            }
            if phase == "ready" && !submitted {
                submitted = true;
                let payload = serde_json::json!({"id":"1","texts":source}).to_string();
                let script = format!(
                    "window.__translator.translate({})",
                    crate::state::js_string(&payload)
                );
                let _ = view.evaluate_script(&script);
            }
            return;
        }

        if let Event::UserEvent(UserEvent::TranslateResult(_, json)) = &event {
            let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
            if v.get("pending").and_then(|p| p.as_bool()) == Some(true) {
                return;
            }
            log(&format!("{{\"result\":{}}}", j(json)));
            if let Some(items) = v.get("items").and_then(|i| i.as_array()) {
                output = items
                    .iter()
                    .filter_map(|it| it.get("t").and_then(|t| t.as_str()).map(str::to_string))
                    .collect();
            }
            // ASSERTED ON MEANING, not on shape. Output that merely exists
            // proves nothing; output identical to the input is precisely the
            // failure a pack that did not load produces.
            let unchanged = output
                .iter()
                .zip(source.iter())
                .filter(|(out, src)| out.trim() == src.as_str())
                .count();
            let spanish = output.iter().any(|t| {
                let t = t.to_lowercase();
                t.contains("hola") || t.contains("mundo") || t.contains("zorro") || t.contains("buenos")
            });
            // A custom run cannot be graded by a Spanish word list, so it passes
            // on the structural facts -- every sentence came back, none echoed --
            // plus, if given, a substring the output must carry. Coherence itself
            // is read from the logged translations by a human; that IS the proof.
            let expect_ok = match &expect {
                Some(e) => output.iter().any(|t| t.to_lowercase().contains(&e.to_lowercase())),
                None => true,
            };
            let produced = !output.is_empty() && output.iter().all(|t| !t.trim().is_empty());
            let pass = output.len() == source.len()
                && unchanged == 0
                && if custom { produced && expect_ok } else { spanish };
            log(&format!(
                "{{\"verdict\":{{\"engine_ready_ms\":{},\"pack_ready_ms\":{},\
                 \"pair\":{},\"in\":{},\"out\":{},\"identical_to_input\":{unchanged},\
                 \"recognisably_spanish\":{spanish},\"expect_present\":{expect_ok},\
                 \"result\":\"{}\"}}}}",
                engine_ready_ms.unwrap_or(-1),
                pack_ready_ms.unwrap_or(-1),
                j(&pair),
                source.len(),
                output.len(),
                if pass {
                    if custom {
                        "PROVEN: real page text produced changed, non-echoed output"
                    } else {
                        "PROVEN: the product's own translator produced Spanish"
                    }
                } else {
                    "FAILED"
                }
            ));
            log(&format!("{{\"translations\":{}}}", j(&output.join(" | "))));
            log("{\"done\":true}");
            std::process::exit(if pass { 0 } else { 1 });
        }

        if let Event::UserEvent(UserEvent::ProbeDone) = event {
            step += 1;
            if step > 240 {
                log("{\"verdict\":{\"result\":\"FAILED: timed out\"}}");
                std::process::exit(1);
            }
            // Poll exactly as the product does: status until a job is with the
            // engine, then result.
            let proxy = proxy.clone();
            let script = if submitted {
                format!(
                    "window.__translator.result({})",
                    crate::state::js_string(&serde_json::json!({"id":"1"}).to_string())
                )
            } else {
                "window.__translator.status()".to_string()
            };
            let is_result = submitted;
            let _ = view.evaluate_script_with_callback(&script, move |raw| {
                let inner = serde_json::from_str::<String>(&raw).unwrap_or(raw);
                let _ = if is_result {
                    proxy.send_event(UserEvent::TranslateResult(1, inner))
                } else {
                    proxy.send_event(UserEvent::TranslateEngine(inner))
                };
            });
        }
    })
}

/// Runs the probe and exits the process. Never returns.
pub fn run(event_loop: EventLoop<UserEvent>, hosts: &platform::Hosts) -> ! {
    if engine_mode() {
        run_engine(event_loop, hosts);
    }
    log(&format!(
        "{{\"probe\":\"translation reply channel\",\"engine\":\"{}\",\"sabotage\":{}}}",
        if cfg!(windows) { "WebView2" } else { "WebKitGTK" },
        sabotage()
    ));

    let dir = std::env::temp_dir().join("patanyx-translate-probe");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log(&format!("{{\"fatal\":\"tempdir: {e}\"}}"));
        std::process::exit(2);
    }
    let page = dir.join("probe.html");
    if let Err(e) = std::fs::write(&page, PAGE) {
        log(&format!("{{\"fatal\":\"write page: {e}\"}}"));
        std::process::exit(2);
    }
    let url = format!("file://{}", page.display());
    // The page navigated TO, for step 5 of the battery. Different text, so a
    // stale extraction cannot be mistaken for a fresh one.
    let page2 = dir.join("probe2.html");
    if let Err(e) = std::fs::write(&page2, PAGE_AFTER_NAV) {
        log(&format!("{{\"fatal\":\"write page2: {e}\"}}"));
        std::process::exit(2);
    }
    let url2 = format!("file://{}", page2.display());

    let proxy = event_loop.create_proxy();
    // The production builder and the production build_content, so the probe
    // exercises the path a real tab takes. A test-only parenting helper could
    // drift from it, and then a green probe would mean nothing.
    let builder = platform::new_webview_builder();
    let built = platform::build_content(
        hosts,
        builder,
        &platform::TabPolicy::default(),
        &proxy,
        &url,
        Rc::new(RefCell::new(std::collections::BTreeSet::new())),
        1,
        Default::default(),
    );
    // The builder gained a third value on the 0.9.66 line (the startup-wipe
    // gate); the probe does not drive that path and only needs the pair.
    let (webview, view, _wipe_pending) = match built {
        Ok(v) => v,
        Err(e) => {
            log(&format!("{{\"fatal\":\"content webview build failed: {e}\"}}"));
            std::process::exit(2);
        }
    };

    log(&format!(
        "{{\"channel_reported_supported\":{}}}",
        platform::translate_channel_supported()
    ));

    let tick = event_loop.create_proxy();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if tick.send_event(UserEvent::ProbeDone).is_err() {
            break;
        }
    });

    let mut step = 0usize;
    // Everything observed, so the verdict at the end is computed from
    // measurements rather than asserted along the way.
    let mut parked_seen = false;
    let mut first_batch: Vec<String> = Vec::new();
    let mut second_batch: Vec<String> = Vec::new();
    let mut extracts = 0usize;
    let mut third_batch: Vec<String> = Vec::new();
    let mut parked_after_nav = false;
    let mut cleared_on_nav = false;
    let mut clears_before_nav = 0u64;

    event_loop.run(move |event, _target, control_flow| {
        *control_flow = ControlFlow::Wait;

        if let Event::UserEvent(UserEvent::ContentTranslate(id, raw)) = &event {
            extracts += 1;
            log(&format!(
                "{{\"page_to_host\":{{\"tab\":{id},\"n\":{extracts},\"payload\":{}}}}}",
                j(&raw.chars().take(600).collect::<String>())
            ));
            // Parsed HERE and nowhere else, exactly as the channel's contract
            // says: one place, against a shape, treating everything as
            // untrusted.
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
                let batch: Vec<String> = v
                    .get("batch")
                    .and_then(|b| b.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                // Filed by SESSION, not by arrival order. The sabotage run
                // showed why: with the first extract withheld, the only
                // payload to arrive was s2's, and order-based bookkeeping
                // filed it as the first batch. The verdict was still right,
                // but a probe whose own record can misstate what happened is
                // one bad day from a wrong conclusion.
                match v.get("session").and_then(|s| s.as_str()) {
                    Some("s1") => first_batch = batch,
                    Some("s2") => second_batch = batch,
                    Some("s3") => third_batch = batch,
                    _ => {}
                }
            }
            return;
        }

        if let Event::UserEvent(UserEvent::ProbeDone) = event {
            step += 1;
            match step {
                // Did the page open a poll, and did the host receive it? This
                // is the ABI question: if the trampoline's signature were
                // wrong, the process would already be gone.
                2 => {
                    parked_seen = platform::translate_poll_parked(&view);
                    log(&format!("{{\"poll_parked_at_host\":{parked_seen}}}"));
                }
                // HOST -> PAGE, the new direction.
                3 => {
                    if sabotage() {
                        log("{\"sabotage\":\"extract command withheld\"}");
                    } else {
                        let cmd = serde_json::json!({
                            "cmd": "extract",
                            "session": "s1",
                            "limitNodes": 50,
                            "limitChars": 5000,
                        });
                        let ok = platform::deliver_translation(&webview, &view, cmd.to_string());
                        log(&format!("{{\"delivered_extract\":{ok}}}"));
                    }
                }
                // PATCH: send back a marked transform of exactly what arrived.
                // A real translation is not needed to prove the seam, and
                // faking one would be worse than useless -- a marker that
                // could not possibly be mistaken for Spanish keeps this an
                // honest channel test rather than a fake feature demo.
                6 => {
                    let items: Vec<serde_json::Value> = first_batch
                        .iter()
                        .enumerate()
                        .map(|(i, t)| serde_json::json!({"i": i, "t": format!("[PATCHED] {t}")}))
                        .collect();
                    let cmd = serde_json::json!({
                        "cmd": "patch", "session": "s1", "items": items,
                    });
                    let ok = platform::deliver_translation(&webview, &view, cmd.to_string());
                    log(&format!(
                        "{{\"delivered_patch\":{ok},\"items\":{}}}",
                        first_batch.len()
                    ));
                }
                // Read the DOM back the only way the invariant allows: ask the
                // page to extract again.
                8 => {
                    let cmd = serde_json::json!({
                        "cmd": "extract", "session": "s2",
                        "limitNodes": 50, "limitChars": 5000,
                    });
                    let ok = platform::deliver_translation(&webview, &view, cmd.to_string());
                    log(&format!("{{\"delivered_second_extract\":{ok}}}"));
                }
                // NAVIGATE while a poll is parked. The outbox holds a reply
                // that owns a ref on the OLD document's JS context, and that
                // document is about to be destroyed.
                11 => {
                    clears_before_nav = platform::translate_outbox_clears(&view);
                    log(&format!(
                        "{{\"parked_before_navigation\":{},\"clears_so_far\":{clears_before_nav}}}",
                        platform::translate_poll_parked(&view)
                    ));
                    if let Err(e) = webview.load_url(&url2) {
                        log(&format!("{{\"nav_error\":{}}}", j(&e.to_string())));
                    }
                }
                // Cleared by the load-started handler, which is where the
                // consent ruling and the memory-safety requirement meet.
                13 => {
                    // The COUNT, not the current state. Sampling
                    // `translate_poll_parked` here reported false: by this
                    // point the new document has opened its own poll, so a
                    // correctly-cleared mailbox looks exactly like one that was
                    // never cleared. That was a probe bug, and it read as a
                    // product failure.
                    let now = platform::translate_outbox_clears(&view);
                    cleared_on_nav = now > clears_before_nav;
                    log(&format!(
                        "{{\"outbox_cleared_by_navigation\":{cleared_on_nav},\
                         \"clears_before\":{clears_before_nav},\"clears_after\":{now}}}"
                    ));
                }
                // The NEW document opens its own poll. If this is false the
                // channel does not survive a navigation, and translation would
                // work exactly once per tab.
                15 => {
                    parked_after_nav = platform::translate_poll_parked(&view);
                    log(&format!("{{\"poll_parked_after_navigation\":{parked_after_nav}}}"));
                    let cmd = serde_json::json!({
                        "cmd": "extract", "session": "s3",
                        "limitNodes": 50, "limitChars": 5000,
                    });
                    let ok = platform::deliver_translation(&webview, &view, cmd.to_string());
                    log(&format!("{{\"delivered_third_extract\":{ok}}}"));
                }
                18 => {
                    let patched = second_batch
                        .iter()
                        .filter(|t| t.starts_with("[PATCHED] "))
                        .count();
                    // The privacy assertion, checked on EVERY extraction: the
                    // input's value and the contenteditable's text must never
                    // appear in anything the page sent up.
                    let leaked = first_batch
                        .iter()
                        .chain(second_batch.iter())
                        .chain(third_batch.iter())
                        .any(|t| {
                            t.contains("SECRET-TYPED-VALUE") || t.contains("SECRET-EDITABLE-VALUE")
                        });
                    let round_trip = parked_seen && !first_batch.is_empty() && patched > 0;
                    // The new document's text, and ONLY the new document's
                    // text. Seeing the old page's nodes here would mean the
                    // session survived a navigation, which the consent ruling
                    // forbids.
                    let survived_nav = parked_after_nav
                        && third_batch.iter().any(|t| t.contains("After navigation"))
                        && !third_batch.iter().any(|t| t.contains("quick brown fox"));
                    log(&format!(
                        "{{\"verdict\":{{\
                         \"poll_parked\":{parked_seen},\
                         \"first_extract_nodes\":{},\
                         \"second_extract_nodes\":{},\
                         \"patched_nodes\":{patched},\
                         \"skipped_editable_and_input\":{},\
                         \"outbox_cleared_by_navigation\":{cleared_on_nav},\
                         \"channel_survived_navigation\":{survived_nav},\
                         \"host_to_page\":\"{}\"}}}}",
                        first_batch.len(),
                        second_batch.len(),
                        !leaked,
                        if round_trip {
                            "PROVEN: host text reached the document"
                        } else {
                            "FAILED: no host text reached the document"
                        }
                    ));
                    log("{\"done\":true}");
                    let pass = round_trip && !leaked && cleared_on_nav && survived_nav;
                    std::process::exit(if pass { 0 } else { 1 });
                }
                _ => {}
            }
        }
    })
}

// ---------------------------------------------------------------------------
// The full-loop self-test
//
// WHY THIS EXISTS SEPARATELY FROM THE TWO PROBES ABOVE. Mode 1 proves the
// channel and mode 2 proves the engine; neither touches `AppState`, so the
// machine that JOINS them -- click, extract, boot, load pack, translate, patch
// -- was the one part of this feature with no evidence at all. Two proven
// halves and unproven glue is exactly the shape of a feature that fails on the
// first real page.
//
// It drives the REAL machine: `translate_active_tab` is the same call the IPC
// arm makes when the user clicks, and everything after it is production code.
// Nothing here reaches around the state machine to make it succeed.
//
// HOW IT CHECKS THE PAGE ACTUALLY CHANGED. It does not trust the host's own
// count of what it sent. After the session reports done, it starts a SECOND
// translation on the same page; that run's extraction reads the DOM as it now
// stands, so if the patch landed, the text coming up is Spanish. The feature
// verifies itself through its own seam, without evaluating script into a
// content webview -- the same discipline mode 1 uses.
use std::cell::Cell;

thread_local! {
    static STEP: Cell<usize> = const { Cell::new(0) };
    static STAGE: Cell<u8> = const { Cell::new(0) };
}

/// Armed by env, debug builds only.
pub fn selftest_enabled() -> bool {
    std::env::var("PATANYX_TRANSLATE_SELFTEST").as_deref() == Ok("1")
}

/// One step of the self-test. Called from the event loop's tick.
pub fn selftest_step(app: &mut crate::state::AppState) {
    let step = STEP.with(|s| {
        s.set(s.get() + 1);
        s.get()
    });
    let stage = STAGE.with(Cell::get);
    let (phase, patched, extracted) = app.selftest_snapshot();

    // A hard ceiling, so a wedged run fails loudly instead of hanging a CI job.
    if step > 240 {
        log(&format!(
            "{{\"verdict\":{{\"result\":\"FAILED: timed out\",\"phase\":{},\"stage\":{stage}}}}}",
            j(&phase)
        ));
        std::process::exit(1);
    }

    // The pair is overridable so the harness can drive a page the fixed en-es
    // fixture cannot express -- a MIXED-LANGUAGE document above all, which is
    // where the per-node script filter lives and where an engine-only probe
    // proves nothing.
    let selftest_pair: &'static str = std::env::var("PATANYX_TRANSLATE_SELFTEST_PAIR")
        .ok()
        .and_then(|p| crate::state::validate_translation_pair(&p))
        .unwrap_or("en-es");

    match stage {
        // Give the start page time to load and open its poll. Translating a
        // document that has not announced itself is a legitimate refusal, and
        // refusing here would be testing the refusal rather than the feature.
        0 if step > 6 => {
            match app.translate_active_tab(selftest_pair) {
                Ok(_) => {
                    log("{\"selftest\":\"clicked Translate (first run)\"}");
                    STAGE.with(|s| s.set(1));
                }
                // The page has not parked its poll yet. Stage 2 already waits
                // for a re-park; stage 0 fataled on the FIRST tick after 3.5 s,
                // which a cold container (fresh font cache, first WebKit
                // process spawn) does not meet. Wait, like stage 2; the 240-step
                // ceiling above still fails a page that never parks.
                Err("page_not_ready") => {
                    if step % 20 == 0 {
                        log("{\"selftest\":\"waiting for the page to park its poll\"}");
                    }
                }
                Err(e) => {
                    log(&format!("{{\"fatal\":\"translate refused: {e}\"}}"));
                    std::process::exit(1);
                }
            }
        }
        // Wait for the machine to finish: boot, pack, translate, patch.
        1 => {
            if phase.starts_with("failed") {
                log(&format!("{{\"verdict\":{{\"result\":\"FAILED\",\"phase\":{}}}}}", j(&phase)));
                std::process::exit(1);
            }
            if phase == "done" {
                log(&format!(
                    "{{\"selftest\":\"first run done\",\"patched\":{patched},\"extracted\":{}}}",
                    j(&extracted.join(" | "))
                ));
                // SHOW ORIGINAL: put the page back to English, engine-free.
                let _ = app.restore_active_tab();
                log("{\"selftest\":\"issued restore (Show original)\"}");
                STAGE.with(|s| s.set(2));
            }
        }
        // The restore consumed the page's parked poll; it must RE-PARK before a
        // second translate is accepted (translate_active_tab checks
        // page_ready). So retry until it takes rather than assuming it is ready
        // the very next tick.
        2 => {
            match app.translate_active_tab(selftest_pair) {
                Ok(_) => {
                    log("{\"selftest\":\"second Translate accepted (page re-parked)\"}");
                    STAGE.with(|s| s.set(3));
                }
                Err("page_not_ready") => { /* wait for the page to re-park */ }
                Err(e) => {
                    log(&format!("{{\"fatal\":\"second translate refused: {e}\"}}"));
                    std::process::exit(1);
                }
            }
        }
        // The second extraction is what the page NOW holds.
        //
        // WAITS FOR THE SECOND RUN TO FINISH, rather than judging the moment
        // any Spanish appears. It used to fire on first sight, which on a long
        // page meant reading back one batch out of three and reporting on a
        // fraction of the document while claiming to describe it. Third time
        // this test family has judged partial data; the rule is now explicit --
        // read the phase, not the first encouraging sign.
        3 => {
            if phase != "done" && !phase.starts_with("failed") && step <= 200 {
                return;
            }
            // `extracted` here is what RUN 2 read off the page -- i.e. the page
            // AFTER restore. If Show original worked, that is English.
            let joined = extracted.join(" | ").to_lowercase();
            let restored_english =
                joined.contains("hello world") || joined.contains("quick brown");
            let still_spanish = ["hola", "mundo", "zorro", "buenos", "rápido"]
                .iter()
                .any(|w| joined.contains(w));
            {
                // Restore proven iff run 2 extracted English and no Spanish
                // survived, and run 2 then re-translated (patched > 0), which
                // proves the whole translate->restore->translate cycle.
                let pass = restored_english && !still_spanish && patched > 0;
                log(&format!(
                    "{{\"verdict\":{{\"patched_nodes\":{patched},\
                     \"page_after_restore_reads\":{},\"english_restored\":{restored_english},\
                     \"spanish_survived_restore\":{still_spanish},\"result\":\"{}\"}}}}",
                    j(&extracted.join(" | ")),
                    if pass {
                        "PROVEN: translate, then Show original restored the page, then translate again"
                    } else {
                        "FAILED"
                    }
                ));
                log("{\"done\":true}");
                std::process::exit(if pass { 0 } else { 1 });
            }
        }
        _ => {}
    }
}
