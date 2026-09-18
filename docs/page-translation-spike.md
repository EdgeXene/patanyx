# Phase 0 spike report: on-device page translation (Bergamot)

Harness: `crates/app/examples/translate_spike.rs` (an EXAMPLE, never shipped).
Model pair: `enes` (English to Spanish), 31.5 MB model + 4.2 MB lexicon +
816 KB vocab, engine `bergamot-translator-worker.wasm` 5.2 MB.

Both legs were run by driving the hardware directly, not by describing a
procedure to someone else. The Linux leg runs under `xvfb-run -a`; the Windows
leg was run on a Windows 11 laptop over the computer-use bridge,
and its numbers were read off that machine's own result file.

EVERYTHING BELOW IS NOW MEASURED ON BOTH ENGINES. The Windows CSP bisection and
isolation battery were run 2026-08-30 by driving that laptop directly.
They did not merely confirm the WebKitGTK results: on the isolation battery
Windows is MATERIALLY WORSE, and on throughput it produced a second number 4.7x
apart from the first.

THE SPIKE GATES THE REST. This report is what phase 1 is allowed to start from.

## Verdict

Bergamot itself is FEASIBLE on both engines. The measured numbers are below.

But phase 0 did NOT come back clean, and the plan cannot proceed to phase 1
unchanged. Two results decide that:

1. The translator document cannot run under the chrome CSP. It needs
   `connect-src 'self'` and `'wasm-unsafe-eval'`, which the chrome policy
   deliberately does not grant.
2. The translator webview was to share the `rbchrome` origin with the
   privileged UI. Measured on BOTH engines, that origin sharing leaks, and it
   leaks worse on the platform most users are on. On WebView2, **localStorage,
   cookies, IndexedDB, Cache Storage and OPFS all cross live** between the two
   views, BroadcastChannel delivers, and a service worker registration on the
   privileged origin was stopped only by a missing file.

   **Corrected by the in-product run:** on Linux only IndexedDB crosses; the
   localStorage cross-session result came from the out-of-tree harness and did
   NOT reproduce inside PATANYX. The WebView2 figures remain harness figures
   until the same probe runs in-product on Windows.

   **Severity, stated precisely:** the storage leak is LATENT, not live. The
   privileged UI reads none of those stores today (checked across the whole
   chrome surface), so nothing can be poisoned right now. It becomes live the
   day one `localStorage.getItem` appears in the chrome UI — and this feature
   would first put attacker-controlled text on the other side of that
   boundary. The iframe result and the protocol-endpoint reach do NOT depend
   on that condition and are not downgraded.

The privilege split the plan relied on -- "no ipc handler, therefore no reach"
-- does hold: a webview with no handler cannot reach another webview's handler
in the same process. That part is confirmed. It is simply not sufficient on its
own, because storage and framing go around it.

**The design change this forces:** the translator webview needs its OWN origin
with its own data store, not `rbchrome`. That also resolves finding 1 cleanly,
since a separate origin can carry a looser policy without loosening the chrome
document's policy by a single directive.

## Measured

| Measure                                        | Linux / WebKitGTK | Windows / WebView2 |
| ---------------------------------------------- | ----------------- | ------------------ |
| Engine + model ready, host wall clock          | 1,500 ms          | 1,506 ms           |
| Engine + model ready, page-reported `loadMs`   | --                | 539 ms             |
| JS heap at ready (`usedJSHeapSize`)            | not exposed       | 37 MB              |
| Payload ceiling, host to page to host          | none below 16 MiB | none below 16 MiB  |
| Largest payload proven to cross                | 10,066,332 chars  | 10,066,332 chars   |
| 40 sentences, engine time                      | 1,263 ms          | 10,357 ms          |
| 40 sentences, host wall clock                  | 1,500 ms          | 10,659 ms          |
| Output                                         | real Spanish      | real Spanish       |
| `window.ipc` present with NO handler installed | yes               | yes                |
| Unrequested custom-protocol fetches            | none              | `/favicon.ico`     |

Boundary search doubled from 64 KiB and was capped at 16 MiB by the harness,
so "no ceiling below 16 MiB" is the honest claim -- not "no ceiling". The probe
text was escaping-hostile and non-ASCII on purpose (`x"y€⁨z`), so these are
serialized-byte crossings, not character counts.

## Throughput: two Windows measurements, 4.7x apart

The same 40 sentences, on the same laptop, same model, same engine:

| Windows run | Engine time | Per sentence |
| --- | --- | --- |
| First (cold: first-ever WebView2 init, model not in page cache) | 10,357 ms | ~259 ms |
| Later (warm, after three prior runs in the same session) | 2,209 ms | ~55 ms |

An earlier version of this report quoted the 259 ms figure alone as "the budget
phase 3 has to design against". That was one cold measurement presented as a
constant, and the second run makes it untenable. Neither number is wrong; a
single number was.

What to carry forward instead:

- **First use is slow and the UI must survive it.** ~10 s for 40 sentences on a
  cold start is what a user meets the first time they press the button.
- **Repeat use is roughly 4-5x faster.** ~55 ms/sentence warm.
- **A 400-sentence page is therefore somewhere between ~22 s and ~100 s.** Both
  ends of that range still make visible-first batching, visible progress and a
  working cancel REQUIREMENTS rather than optimizations, so the design
  conclusion survives even though the number did not.
- **What separates the two runs is not established.** Page cache, WebView2
  first-init, and machine power state are all uncontrolled here. Anyone quoting
  a per-sentence figure should say which run it came from.

Linux measured 1,263 ms and 1,372 ms for the same work across runs, which is
stable. Do NOT compare that to either Windows figure as an engine result: the
legs ran on different machines and engine and hardware are perfectly
confounded.

## The favicon finding

WebView2 requests `/favicon.ico` from a custom scheme ON ITS OWN, for a page
that references no icon. WebKitGTK never does: its request list is exactly the
six assets the document asks for.

This aborted the first three Windows runs. A wry custom-protocol handler runs
across an `extern "C"` boundary, so a panic inside it does not unwind into Rust
-- the process ABORTS. The harness panicked on the missing file, and the result
file kept nothing but the platform stamp, which is why three round trips
produced no information.

Two things follow.

1. **The product is not affected.** `serve_chrome` (`crates/app/src/main.rs:345`)
   already answers unknown paths with a 404 and serves every known path from
   `include_str!` constants, touching no filesystem. This was a harness defect.
   Verified by reading it, not assumed.
2. **Phase 2 inherits a hard requirement.** The translator webview's protocol
   handler must 404 unknown paths and must not panic on any input, because a
   panic there is an abort, not an error. That requirement now has a reason
   attached to it rather than being general caution.

The harness was fixed to 404 misses, to reject traversal-shaped names, and to
RECORD every protocol request, so future runs report what each engine fetches
unprompted instead of dying on it.

## The `window.ipc` fingerprinting surface

The translator webview installs no IPC handler. `window.ipc` is nonetheless
present on BOTH engines as a plain object exposing `postMessage`:

```
{"type":"object","keys":["postMessage"],"hasPostMessage":"function",
 "proto":["constructor","__defineGetter__","__defineSetter__","hasOwnProperty",
          "__lookupGetter__","__lookupSetter__","isPrototypeOf",
          "propertyIsEnumerable","toString","valueOf","__proto__",
          "toLocaleString"]}
```

The page fired `window.ipc.postMessage('SPIKE_BOUNDARY_PROBE')`. That string
appears nowhere host-side on either engine, so the boundary holds BY
CONSEQUENCE: wry drops the message when no handler is installed. What survives
is not a channel but a fingerprinting surface -- a detectable object that says
"this is a wry browser" -- and it is present on both engines, which is what
makes it worth removing from content tabs. That removal is tracked separately;
it is not a translation feature.

That was the whole of the isolation evidence for three rounds, and it was not
enough. The battery below is what actually answers the question.

## Content Security Policy: measured by bisection

Round 1 served the page with no policy at all, so it answered nothing about
whether this works in the product. Under the policy every chrome asset actually
ships (`main.rs:276`), on WebKitGTK:

| Policy | WebKitGTK | WebView2 |
| --- | --- | --- |
| The real chrome policy | Dead. `connect-src 'none'` blocks the engine fetching its OWN `.wasm` (line 531 of the glue), before any model file is touched. | Identical. Same directive, same file, same line. |
| ... plus `connect-src 'self'` | Still dead. `CompileError: ... 'wasm-unsafe-eval' is not an allowed source of script`. | Still dead. `CompileError: WebAssembly.instantiate(): Compiling or instantiating WebAssembly module violates ... 'unsafe-eval' is not an allowed source of script`. |
| ... plus `'wasm-unsafe-eval'` in `script-src` | Works. Ready 263 ms. | Works. Ready 488 ms page-side, 1,501 ms wall, 37 MB heap, no payload ceiling below 16 MiB, 40 sentences in 2,209 ms. |

**The two engines agree exactly on what the feature costs in policy.** That is
the useful result: the translator document needs `connect-src 'self'` and
`'wasm-unsafe-eval'`, on both platforms, and nothing else.

So the translator document costs exactly two directives more than the chrome
document. On a SEPARATE origin that is a contained cost. On the SHARED origin
the plan drafted, it is not, which is the second reason the origin has to move.

One harness lesson worth keeping, with an engine divergence inside it: the
blocked fetch raised a `securitypolicyviolation` event and no error on both
engines. The blocked WebAssembly compile raised an engine error and NO violation
event on WebKitGTK, but on WebView2 it raised BOTH -- an error and two
violations naming `wasm-eval` as the blocked resource. A probe watching only one
channel would have reported half of these failures as an unexplained stall on
one platform and diagnosed them on the other.

## Isolation battery: two webviews, one process, one origin

Earlier runs measured a single webview and concluded "no ipc handler, so no
channel". That was the wrong question. This run builds BOTH views the plan
describes -- A with an ipc handler standing in for the chrome UI, B with none
standing in for the translator -- on the same origin, and has B probe A.

Every run stamps a FRESH marker into both documents. With a fixed string the
headline result is unreadable, because IndexedDB survives on disk and "A sees
B's marker" would not be distinguishable from "A sees the marker B wrote twenty
minutes ago". That distinction turned out to matter.

| Surface | WebKitGTK | WebView2 |
| --- | --- | --- |
| B's `postMessage` reaching A's ipc handler | **Held.** 0 messages. | **Held.** 0 messages. |
| `window.chrome.webview` in B | absent | **PRESENT, and B fired through it** |
| localStorage | shared, previous run only | **SHARED AND LIVE** |
| sessionStorage | shared, previous run only | not visible |
| Cookies | silently dropped | **shared and live** |
| IndexedDB | **shared and live** | **shared and live** |
| Cache Storage | unavailable: not HTTP/HTTPS | **shared and live** |
| OPFS | API absent | **shared and live** |
| BroadcastChannel B to A | not delivered | **DELIVERED** |
| Service Worker registration | refused: scheme not HTTP/HTTPS | **scope ACCEPTED; failed only on a 404 for the script** |
| `window.open` of the chrome document | blocked, null | blocked, null |
| iframe of the chrome document | `contentDocument` READABLE | inconclusive (probe still pending at teardown) |
| `/region-capture/`, `/archive-picture/` from B | request reaches the handler (404) | `TypeError: Failed to fetch` -- see below |
| `isSecureContext` in B | -- | true |

**Windows is the worse platform, decisively.** Five storage mechanisms cross
live between the two views instead of one, cookies work where WebKitGTK dropped
them, and BroadcastChannel delivers. Only `sessionStorage` is isolated, and it
is the one thing WebKitGTK leaked.

Two Windows results deserve singling out.

**Service workers are one 404 away.** The registration did not fail because the
origin was ineligible; it failed because `sw.js` did not exist. WebView2 serves
custom schemes from `http://rbchrome.localhost`, an origin Chromium treats as
secure and service-worker-eligible (`isSecureContext` reported true). A script
at that path would have registered a service worker on the PRIVILEGED UI's
origin, with fetch interception over it. On a shared origin that is not a
theoretical concern, it is a missing file.

**`window.chrome.webview` exists in the translator view.** WebKitGTK exposes no
such object. The ipc-handler crossing test still came back clean -- A's handler
received nothing -- so this did not yield a channel in the harness. It is
another host-object surface present on an untrusted view, and phase 2 should
establish what it does and does not reach rather than leaving it at "the
crossing test was clean".

**The protocol-endpoint probe is INCONCLUSIVE on Windows and should not be read
as a pass.** The fetch failed with `TypeError: Failed to fetch` rather than
returning a status. In this harness those paths do not exist and the 404
response carries no CORS headers, so the failure is as likely to be an artifact
of the harness's own 404 as a real boundary. In the product those paths return
real responses. Treat this as unmeasured on Windows; the WebKitGTK result --
the request reaches the handler -- is the one with evidence behind it.

### Does this transfer to PATANYX? Checked, and mostly yes

The battery ran in `translate_spike.exe` against a stand-in chrome page, not
inside PATANYX against the real UI. Storage partitioning between two
same-origin wry webviews depends on how those webviews are CONSTRUCTED, so the
result only transfers if the product builds its webviews the way the harness
did. Verified by reading rather than assumed:

- `platform::new_webview_builder()` on Windows
  (`platform/windows.rs:585`) builds **every** webview from one shared
  `WebContext` pointing at a single profile directory. Its own comment calls
  the shared user-data folder a constraint the code is designed around.
- `main.rs:640` uses that same factory for the chrome webview, with the
  comment: "Same factory the content tabs use, so the chrome webview shares
  their profile directory rather than creating a second one."
- On unix `new_webview_builder()` is bare `WebViewBuilder::new()` — wry's
  shared default, which is what the harness used.
- `state.rs:2693` already records the consequence for content tabs: there is
  no origin-scoped clear, "only a profile-WIDE clear exists".

So one data store, every webview, deliberately. A translator webview built as
the plan describes lands in exactly the arrangement the harness measured.

### But the privileged UI reads none of those stores, and that changes the severity

The pivot described above is "B writes, A reads it, A trusts it". Checked
across the whole chrome surface — `chrome.js`, `integrity.js`, `update.js`,
`chat.js`, `index.html`, and Rust-injected scripts — for `localStorage`,
`sessionStorage`, `indexedDB`, `caches`, `BroadcastChannel`,
`navigator.storage` and `document.cookie`:

**Zero uses.** The only matches in the tree are the word "caches" inside a
user-facing sentence and a comment in `state.rs`.

So there is no reader today, and therefore no live pivot through storage. This
is a LATENT hazard, not a present vulnerability, and the report should not have
implied otherwise. Its severity is real but conditional: it becomes live the
day someone adds a single `localStorage.getItem` to the chrome UI — and the
whole point of this feature is to put attacker-controlled text on the other
side of that boundary first.

The design conclusion is unchanged, but for a better-stated reason: the
translator moves to its own origin because the boundary is one line of code
away from mattering, not because it is being exploited now.

What is NOT downgraded by this: the iframe result (B can load and read the
chrome document; no storage needed), and the protocol-endpoint reach on
WebKitGTK. Those do not depend on the chrome UI reading anything.

### Run inside PATANYX, and it corrected me

`crates/app/src/isolation_probe.rs` runs the battery inside `patanyx.exe`
itself: webview A is the REAL chrome webview -- real `index.html`, real
`chrome.js`, real `serve_chrome`, real IPC handler -- and B is a second webview
built from the same `platform::new_webview_builder()` on the same origin with
no IPC handler. Debug builds only; the module, the platform helpers and the
call site are all `#[cfg(debug_assertions)]`, so none of it exists in a release
binary.

Three consecutive runs against a PERSISTING profile, Linux/WebKitGTK:

| Surface | Harness said | In PATANYX |
| --- | --- | --- |
| IndexedDB | shared and live | **shared and live** (all 3 runs) |
| localStorage | shared across sessions | **null every run -- DID NOT REPRODUCE** |
| sessionStorage | shared across sessions | not visible |
| Cookies | silently dropped | silently dropped |
| BroadcastChannel | not delivered | not delivered |
| `window.chrome.webview` | absent | absent |
| B reaching the IPC handler | held (0 of 0) | **held (0 of 23)** |

Two things to take from that.

**The localStorage claim is retracted for Linux.** The harness showed run N's A
reading the marker B wrote in run N-1, reproducibly. In the product, across
three runs on the same profile, A read `null` every time. The out-of-tree
result did not transfer and the cause is not established -- the two differ in
that the harness put its webviews in separate windows, but that is a
hypothesis, not a finding. IndexedDB crossed in both, so the leak is real; it
is narrower on Linux than I reported.

**The IPC result got much stronger.** In the harness A's handler received 0
messages, so "0 from B" was consistent with the handler simply being idle. In
the product the real handler received 23 messages of the chrome UI's own
traffic during the run and still zero from B. That is a positive control: the
handler was demonstrably live and B could not reach it.

### Still owed: the same probe on Windows in-product

This ran on Linux only, because the probe is debug-gated and a debug Windows
build has to be cross-compiled and moved to hardware. That gap matters more
than the Linux one: the harness showed FIVE stores crossing on WebView2 against
one on WebKitGTK, and it is the Linux harness result that just failed to
reproduce. **Until the Windows in-product run exists, the WebView2 numbers in
the table above are harness numbers and should be read as such.**

### Superseded: what this section used to say

Until 2026-08-30 this section read "Still owed: run this inside PATANYX", and
said the transfer argument was "from construction, not from measurement".
That is now done and is recorded above; the heading is kept so the change is
legible rather than silently rewritten.

## Provenance and licences

The plan requires the engine artifact and the models to be provenance-pinned
and licence-audited. Audited now, and the audit found gaps.

**What is pinned.** The three model files were fetched from Mozilla's Remote
Settings attachments CDN with their SHA-256 recorded in a `fetch.sh` beside
them, and the hashes verify. That much is sound.

**What is not.**

- The model URLs are opaque record UUIDs on
  `firefox-settings-attachments.cdn.mozilla.net`. They carry no model name, no
  version, and no release identity, and they die whenever Mozilla rotates a
  record. The hash pins the bytes; nothing pins the meaning.
- The WASM engine and its JS glue have NO fetch record at all. Their origin is
  unrecorded. Their hashes are
  `65cf5be7...d145386f` (wasm) and `2cb354e7...41811a5c` (js), which is all we
  can currently say about them.
- A `registry.json` in the asset directory contains the literal text
  `404: Not Found`. One of the original downloads failed and was written to
  disk as if it had succeeded.
- **Neither artifact carries any licence text.** Checked directly rather than
  assumed: word-boundary searches for MPL, MIT, BSD and Apache find nothing in
  either file. An earlier loose grep appeared to find "MPL" 22 times; those hits
  were `implementa`, `simpleReadV`, `impl` and `onComplete`. Attribution cannot
  be derived from the artifacts and must come from pinned upstream provenance.

**Upstream licences, read from the projects rather than recalled.**
`browsermt/bergamot-translator` is MPL-2.0, and
`mozilla/firefox-translations-models` carries MPL-2.0 as its repository
licence. The model repository states no separate licence for the trained
weights and its README makes no redistribution statement about them, so the
weights are covered only by whatever the repository licence is taken to reach.
That ambiguity is a project decision, not something the attribution
gate can resolve on its own.

The WASM binary statically links further projects. They are now identified and
their licences established -- marian (MIT), intgemm (MIT), sentencepiece
(Apache-2.0), protobuf (BSD-3-Clause), yaml-cpp (MIT), pathie-cpp
(BSD-2-Clause), spdlog (MIT), PCRE2 (BSD-3-Clause WITH PCRE2-exception) and
ssplit-cpp (Apache-2.0 code, with an LGPL-2.1 data directory that does not
appear in our artifact). Read from each project's own licence file, not
recalled. The full table, the LGPL analysis and the provenance gaps are in
`docs/page-translation-provenance.md`.

Phase 2 requirement: a provenance note recording, for every shipped artifact,
its source URL, upstream commit, build toolchain version, hash and licence,
before any of it goes near the attribution gate.

## Still open

- **The battery re-run inside `patanyx.exe`**, against the real chrome UI, as a
  test that stays in the tree. Everything here ran in the spike harness; the
  argument that it transfers is from construction (shared `WebContext`, shared
  profile directory) rather than from measurement in the product.
- **What `window.chrome.webview` reaches from the translator view on WebView2.**
  Present there, absent on WebKitGTK, and the crossing test being clean is not
  the same as knowing what it does.
- **The protocol-endpoint probe on Windows**, properly this time: serve real
  responses at those paths in the harness so a failure means a boundary rather
  than a missing file.
- **Whether the throughput spread is cold-start.** Two runs on one machine, 4.7x
  apart, cause unestablished.
- **The attribution gate cannot see any of this.** `attribution-gate.sh` is
  driven entirely by `cargo metadata`, so a shipped WASM, its glue and the
  model files appear in no inventory and the gate prints OK while ten
  components ship unattributed. The precedent confirms it: the OCR models are
  attributed only by a hand-written `NOTICE` entry that nothing verifies.
- A decision on what licence covers the model weights.
- Translated-output expansion and truncation behaviour at the boundary.
- Memory ceiling under sustained translation. 37 MB is the heap at ready on one
  engine, not a ceiling.
- A same-machine engine A/B, if throughput ever decides a platform question.

## Raw artifacts

- Linux: `spike-result.jsonl` beside the assets directory, regenerated by
  `SPIKE_ASSETS=<dir> xvfb-run -a ./target/debug/examples/translate_spike`.
- Windows: 156,901 characters, 121 lines, produced 2026-08-30 on the Windows 11
  laptop at
  `<Downloads>\translate-spike-win\translate-spike-win\spike-result.jsonl`.
  The values in this report were read from that file directly.
