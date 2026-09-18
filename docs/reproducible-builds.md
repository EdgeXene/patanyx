# Reproducible builds

## Why this matters here specifically

PATANYX's claim is "private by architecture, not just settings". That is a claim
about the code. Nobody runs the code — they run a binary. Without a reproducible
build, the only reason to believe the binary corresponds to the source is that
whoever built it says so, which is exactly the trust the project exists to avoid
requiring.

With a reproducible build the claim becomes checkable by a stranger: rebuild,
compare hashes, and if they match, the published binary contains what the
published source says it does.

This does not make the binary trustworthy on its own. It makes it _auditable_,
which is the most a build can offer.

## What was actually wrong

The build looked reproducible and was not.

Our own crates were already fine. Cargo passes workspace members to rustc as
relative paths, so the binary carries `crates/app/src/ipc.rs`, not an absolute
path. Moving the checkout therefore changed nothing, and a test that only varied
the source directory reported success.

Dependencies were the problem. rustc embeds the absolute path of every source
file that can appear in a panic location, so the binary carried hundreds of
strings like:

```
/root/.cargo/registry/src/index.crates.io-<hash>/gtk-0.18.2/src/auto/settings.rs
```

That is the builder's home directory baked into the artifact. Measured on one
machine, same source, same toolchain, with only `CARGO_HOME` differing:

| build                     | sha256      |
| ------------------------- | ----------- |
| `CARGO_HOME=/root/.cargo` | `67370fab…` |
| `CARGO_HOME=<elsewhere>`  | `fa97df92…` |

So every verifier whose home was not `/root` would have concluded the binary did
not match the source — and would have been right to.

## The fix

`scripts/repro-build.sh` normalizes the three path roots that reach the binary:

```
--remap-path-prefix=$CARGO_HOME=/cargo
--remap-path-prefix=$PWD=/build
--remap-path-prefix=$(rustc --print sysroot)=/rust
```

The sysroot was added 2026-08-27 and the first two alone were not enough. std's
own panic locations carry the toolchain path, not our source path and not a
dependency path, so neither of the other prefixes could reach them: a shipped
Windows exe still contained 25 copies of
`/root/.rustup/toolchains/1.96.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/...`,
naming the build account, the pinned toolchain version and the build host
triple. Remapping the sysroot removes all three facts at once.

> **Historical note.** This finding refers to the 0.9.65 / pre-release
> artifact, which was built with Rust 1.96.0. The stable release toolchain was
> subsequently moved to Rust 1.98.0. The path above is quoted as it was
> recovered from that binary and is deliberately not updated: it is evidence of
> what a shipped artifact contained, not a statement of current configuration.
> The same applies to the published 0.9.65 source snapshot, which keeps its
> 1.96.0 pin because that pin is part of what its published hashes verify
> against. `scripts/toolchain-pin-gate.sh` enforces the current pin across
> active build configuration and deliberately does not police this document. (The separate
`/rustc/<hash>/library/...` paths in the binary are normalized by rustc itself
upstream and never named this machine.)

`scripts/build-windows.sh` sets the SAME three, spelled identically. If the two
scripts ever disagree they produce different bytes, which is the failure this
document exists to prevent. `build-windows.sh` also asserts the result: it
fails the build if any `.cargo` or `.rustup` path survives into the exe, with a
positive control so that a binary containing neither the real paths nor the
remapped ones cannot pass silently.

computed at runtime rather than checked into `.cargo/config.toml`, because a
hardcoded `/root/.cargo` would only be correct on one machine and would defeat
the point. It also sets `CARGO_INCREMENTAL=0` (incremental codegen splits
differently depending on what was built before), passes `--locked` (the lockfile
is an input to the binary), and exports `SOURCE_DATE_EPOCH` from the commit date
so any build timestamp is a property of the code rather than of the clock.

`rust-toolchain.toml` pins rustc. A different compiler emits different code, so
path normalization alone is not enough — the toolchain is as much an input as the
source. **Bumping it changes every published hash**, and release notes must say
so.

The script fails loudly if any absolute build path survives into the binary,
rather than printing a hash that only verifies on the machine that produced it.

## Verifying

```bash
scripts/repro-verify.sh
```

builds twice while varying both the source path and `CARGO_HOME`, and exits
non-zero if the hashes differ. To check a published binary yourself:

```bash
git checkout <tag>
scripts/repro-build.sh
```

and compare the printed sha256 with the published one.

## What this does NOT claim

- **Cross-OS and cross-architecture reproducibility.** A Linux build and a
  Windows build of the same commit are different binaries; only same-platform
  rebuilds are expected to match.
- **That the toolchain itself is trustworthy.** Reproducing a build with the same
  rustc proves the source and binary correspond, not that rustc is honest. That
  is the bootstrap problem and it is out of scope.
- **That the dependency set is trustworthy.** `--locked` pins exact versions;
  auditing what those versions do is separate work.
- **Anything about telemetry.** On Windows the embedded WebView2 reports
  component health that no embedding application can disable. A reproducible
  build makes that verifiable in the source; it does not make it untrue. See the
  project's standing rule never to claim zero telemetry.
