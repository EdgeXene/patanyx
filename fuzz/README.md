# Fuzzing

Coverage-guided fuzzing for the parsers that eat bytes this project did not
write. Added 2026-08-18 by the security audit.

## Running

Needs a nightly toolchain; the repo's pinned 1.98.1 still governs every real
build, and nothing here is part of one. The nightly itself is not pinned to a
date and floats with whatever rustup installs.

    rustup toolchain install nightly --profile minimal
    cargo +nightly install cargo-fuzz

    cd fuzz
    cargo +nightly fuzz list
    cargo +nightly fuzz run chat_wire_decode -- -max_total_time=300

A crash writes its input to `fuzz/artifacts/<target>/`. Reproduce with:

    cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>

**A crashing input belongs in the ordinary test suite, not only here.** The
fuzzer finds it once; a unit test in the owning crate keeps it found.

## What is covered, and what is not

Targets can only reach LIBRARY crates. Since 2026-10-30 `crates/app` is one
too: `src/lib.rs` is the app and `src/main.rs` a one-line launcher, and the
`app_*` targets reach the app's own parsers through `patanyx_app::fuzz_api`,
a module that exists only under the `fuzz-api` feature (no shipped build
enables it; `scripts/fuzz-api-gate.sh` proves that). Known gaps:

* **Page integrity and download compare.** Their entry points take the whole
  application state, so there is no parser to call on its own; the bytes they
  decode arrive over the chat wire, which `chat_wire_*` covers.
* **IPC frames from the chrome.** `ipc::dispatch` parses with `serde_json`
  under a 1 MiB cap and then needs the application state for every command.
  The parse alone is `serde_json`, which is fuzzed upstream far harder than
  this repository could; the per-command handlers are not reachable here.
* **The Windows content-message filter** (`connect_content_messages` in
  `platform/windows.rs`) lives inside a WebView2 event handler. Pulling it out
  is a change to a security boundary, not to fuzzing, and was not made.
* **`chat::envelope::SessionEnvelope::decode`** is a peer's inner message and
  belongs on the list by reachability, but `mod envelope` is private and it is
  not re-exported. Widening a crate's public API to suit a fuzzer is the wrong
  trade.

Covered, ordered by how easily a stranger reaches them:

| target | input comes from |
| --- | --- |
| `chat_wire_decode` | a chat peer's frame, no user action |
| `chat_wire_read_frame` | the length prefix in front of that frame |
| `update_manifest` | the update host, on a schedule |
| `blocklist_manifest` | the same host, hourly |
| `update_delta` | a patch, after its hash is checked |
| `licence_token_parse` | pasted by a user, or over the relay |
| `licence_receipt_parse` | an HTTP response body |
| `app_hover_readout` | a link target on any page, on hover |
| `app_clean_link` | a link on any page, on "Copy clean link" |
| `app_hostset` | the blocklist file on disk, read at every start |
| `app_bounded_picture` | a snapshot picture, from the engine or an imported backup |

The `app_*` targets assert each parser's documented promises, not only that
it returns: the readout never shows a deceptive or control character and stays
within its budget; unwrapping yields the input or an accepted http(s) URL;
stripping only removes and keeps the fragment; a listed host is still found
under any number of extra subdomains; a kept picture is inside the preview
bounds. Seed them first, or the picture target never reaches its downscale:

    python3 fuzz/seeds.py

## Same versions as a release

This is a separate workspace, so the root `[patch.crates-io]` does not reach
it; `Cargo.toml` here repeats the `wry` patch, and `Cargo.lock` here was seeded
from the root lock (copy it over, then let cargo add `libfuzzer-sys` and its
two dependencies). Every crate the two locks share must resolve to a version
the root lock ships, or the fuzzer is testing code no user runs.
`scripts/fuzz-api-gate.sh` checks that too. Before 2026-10-30 the old lock had
drifted on eight crates (`mdns-sd` 0.20.3 against a shipped 0.20.2, among
others).

The app is one of the shared crates, so every version bump moves it. After a
bump, refresh that one entry and nothing else:

    cargo +nightly update --manifest-path fuzz/Cargo.toml -p patanyx --offline

Otherwise check 4 fails with `patanyx: fuzz resolves ['<old>'], a release
ships ['<new>']`.

## Reading a clean run

A run that finds nothing is not proof the parser is safe. It means the fuzzer
did not find anything in the budget it was given. Record the budget alongside
the result, or "clean" means nothing:

2026-08-18, first run, nightly 1.100.0, 180-300s per target, no crashes:

    chat_wire_decode        39,023,962 runs / 301s
    chat_wire_read_frame    25,069,089 runs / 181s
    update_manifest          6,371,461 runs / 181s
    blocklist_manifest      10,605,847 runs / 181s

The manifest targets run two orders of magnitude fewer executions per second
than the wire targets because each one builds a key ring and runs Ed25519
verification. That is the real cost of the path and not a problem, but it does
mean they need a longer wall clock to reach the same depth.

2026-10-30, the `app_*` targets added, nightly 1.100.0 (2026-09-10), on the
host, 300s each:

    app_hover_readout      37,689,235 runs / 301s   clean
    app_hostset             2,086,142 runs / 301s   clean
    app_bounded_picture         2,179 runs / 302s   clean (seeded; each large
                                                    seed decodes ~9M pixels)
    app_clean_link          CRASHED after about 136,000 runs (about 2s,
                            seeded); after the fix 4,007,200 runs / 301s clean

The crash was real and shipped: a page could nest a Bing click URL whose
carrier starts with a multi-byte character inside a Google redirect, and
"Copy clean link" then sliced Bing's two-character marker inside that
character and panicked on the event-loop thread. Fixed in
`ipc::decode_candidate`; the input is in `artifacts/app_clean_link/` and the
regression test is
`ipc::unwrap_redirect_tests::a_nested_bing_carrier_starting_with_a_multibyte_character_does_not_panic`.

2026-11-06, every target on this branch rebased onto 1.0.10, nightly 1.100.0
(2026-09-10), on the host, 60s each, no crashes (the one artifact is the 2026-10-30 crash above):

    chat_wire_read_frame    11,251,490 runs / 61s
    app_hover_readout       12,478,506 runs / 61s
    chat_wire_decode         8,240,385 runs / 61s
    licence_token_parse      3,909,028 runs / 61s
    licence_receipt_parse    3,854,525 runs / 61s
    blocklist_manifest       3,359,821 runs / 61s
    update_manifest          1,899,406 runs / 61s
    update_delta             1,583,825 runs / 61s
    app_clean_link           1,455,687 runs / 61s
    app_hostset                787,414 runs / 61s
    backup_records              25,597 runs / 61s   (each input is sealed
                                                    and opened like a real
                                                    backup)
    app_bounded_picture            692 runs / 62s

Each new target was also proven to reach its code with a planted defect,
reverted afterwards: dropping the readout's deceptive-character filter was
caught in seconds (a soft hyphen), and restoring the 0.9.66 subdomain-padding
miss in `HostSet::matched_rule` was caught by the padded-host assertion.
