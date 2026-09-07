# Contributing to PATANYX

Thank you for looking. This file explains how to obtain the code, how to send
feedback, and what a change has to satisfy before it can be accepted.

## How this repository works

PATANYX is developed by EdgeXene LLC in a private tree and published here as a
complete, buildable snapshot at each release. That has two consequences worth
stating plainly, because they are not what a reader would assume:

- The commit history here is coarse. Most commits correspond to a published
  release rather than to a single change; documentation fixes occasionally land
  directly.
- A pull request is not merged by pressing the merge button. An accepted change
  is applied in the development tree, credited, and appears in the next
  published snapshot.

The split between what is published and what is not is described in the README
under "Source policy": the browser and its client-side crates are open source
and auditable, and the commercial backend services and deployment
infrastructure are not part of this repository.

## Getting the code

```bash
git clone https://github.com/EdgeXene/patanyx.git
cd patanyx
cargo build --release --bin patanyx
```

Building on Linux needs the GTK 3 and WebKitGTK development packages
(`libgtk-3-dev`, `libwebkit2gtk-4.1-dev` on Debian). The Rust toolchain is
pinned by `rust-toolchain.toml` and rustup selects it for you. Do not build
with a different compiler and expect the published hashes to verify: the
toolchain is as much an input to the binary as the source is.

## Reporting a bug or suggesting a feature

Open an issue at https://github.com/EdgeXene/patanyx/issues. Issues are the
public record: they are searchable, each has its own URL, and anyone may open
one or join a discussion on one.

If you would rather not use GitHub, the contact form at
https://patanyx.net/contact/ has "Bug report" and "Feedback" categories and
reaches the same people.

A useful report says what you expected, what happened instead, the version and
platform (Windows or Linux, and the build variant), and the steps that produce
it. If the problem is with a specific page, name the page.

**Do not open a public issue for a security or privacy vulnerability.** Report
those privately by the process in [SECURITY.md](SECURITY.md). You will get an
acknowledgement within 5 business days.

Some limits are documented rather than treated as defects. PATANYX is not an
anonymity tool, and the
["What it cannot hide"](https://patanyx.net/about/#cannot-hide) section of the
About page lists what its anti-fingerprinting deliberately does not cover.
Reports in those areas are welcome as feature discussion, not as regressions.

## Proposing a change

1. Open an issue first for anything beyond an obvious fix, so the design can be
   discussed before you spend time on it. A change that is correct but does not
   fit the architecture still has to be turned down, and that is a waste of your
   evening.
2. Fork the repository and work on a branch.
3. Open a pull request against `main`. Describe what the change does and why,
   and say how you tested it.

EdgeXene is small, so a review may take a while, and you will be told where
things stand rather than left waiting. Reviews focus on whether the change is
correct, whether it can be verified, and whether it holds under the privacy
claims the project makes publicly.

## Requirements for an acceptable contribution

A change is expected to satisfy all of the following.

**Formatting and lints.** Run `cargo clippy --workspace --all-targets` before
you open a pull request and resolve what it reports in the code you touched.
`scripts/ci-trixie.sh` runs it before a release. Two things worth knowing so you
do not chase them: the gate does not use `-D warnings` yet, because there is a
small backlog of style findings, and the tree has never been run through
`rustfmt`, so `cargo fmt --all --check` reports most of the repository. Match the
formatting of the code around your change rather than reformatting files.

**Tests must pass.** `cargo test --workspace` must pass. The fuller Linux gate
is `scripts/ci-trixie.sh`, which runs the test suites plus the project's own
gates and then exercises the real binary against the real engine. Some gates in
it are skipped automatically when a component that is not part of this
repository is absent; that is expected, and most such skips are announced in
the output.

**New functionality comes with tests.** As major new functionality is added,
tests for that functionality are added to the automated test suite in the same
change. A behavior that nothing asserts is a behavior that will regress
silently, and this project has been bitten by exactly that more than once.

**Memory safety.** Every crate except `crates/app` and `crates/vault` declares
`#![forbid(unsafe_code)]` and must keep doing so. `crates/vault` has exactly one
`unsafe` block, the `flock(2)` call in `src/lock.rs`, and `crates/app` uses
`unsafe` where a platform API requires it. New `unsafe` in either needs a
comment saying what invariant makes it sound, in the style of the one already
there.

**No new runtime dependency without a reason.** PATANYX ships no bundled
Chromium, no JavaScript framework, and no npm dependency tree, and that is a
design position rather than an accident. A pull request that adds a dependency
should say what it buys and what was considered instead. If it adds one,
regenerate the attribution list with `python3 scripts/shipping-licenses.py` and
commit the result. `scripts/attribution-gate.sh` is the check: it fails when the
About panel stops matching what the binary is built from.

**Chrome scripts.** The browser chrome under `crates/app/src/chrome/` is
hand-written JavaScript served under a strict CSP. `scripts/chrome-js-gate.sh`
validates it and rejects `innerHTML` in the webview that holds IPC and the
vault. Do not add a build step or a framework there.

**Commit messages.** Write a subject line that says what changed and why it
matters, in plain sentences. The history is meant to be read.

**Attribution.** Keep tooling out of the record. Commit messages, code comments
and documentation describe the change and the reasons for it, not what was used
to produce it, so do not add trailers or comments crediting an editor, a
generator, or an assistant.

## Licensing of contributions

PATANYX is licensed under Apache-2.0. Under section 5 of that license, anything
you deliberately submit for inclusion is licensed to the project under the same
terms, unless you say otherwise in writing.

By opening a pull request you are confirming one thing: that you have the right
to license what you submitted under Apache-2.0. That is the requirement, and it
does not change with how the code was produced. Writing it by hand, adapting
something you already owned, and using a code-generating assistant are all
acceptable, so long as the result is yours to license. What is not acceptable is
submitting code carrying someone else's terms, or code whose origin you cannot
account for.

## What is out of scope here

Server-side services and deployment infrastructure are not in this repository.
Reports about them are still welcome through the same channels; they simply
cannot be fixed by a pull request here.
