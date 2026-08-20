# Fuzzing

Coverage-guided fuzzing for the parsers that eat bytes this project did not
write. Added 2026-08-18 by the security audit.

## Running

Needs a nightly toolchain; the repo's pinned 1.96.0 still governs every real
build, and nothing here is part of one.

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

Targets can only reach LIBRARY crates. Two known gaps, both structural rather
than oversights:

* **`crates/app` is a binary with no lib target.** Its own parsers are
  unreachable from here: the hover readout (`hover.rs`, a page-controlled link
  target), the capture PNG header (`capture.rs`), the blocklist binary format
  (`blocklist.rs`), page integrity, and download compare. Covering them needs
  a lib target on `crates/app`, which is a structural decision about the crate,
  not a fuzzing one.
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
