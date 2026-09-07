<!-- Two files rather than one, because GitHub renders this page on a light
     or a dark background depending on the reader's theme, and a logo drawn
     for one is unreadable on the other. The <picture> element lets the
     browser pick; the <img> inside it is what every other renderer falls
     back to, so the light version has to be the one that stands alone. -->
<h1>
  <picture>
    <source
      media="(prefers-color-scheme: dark)"
      srcset="packaging/brand/patanyx-logo-horizontal-on-dark.svg"
    />
    <img
      src="packaging/brand/patanyx-logo-horizontal-on-light.svg"
      alt="PATANYX"
      width="279"
      height="64"
    />
  </picture>
</h1>

**Leave less behind.**

> **Prerelease.** PATANYX is pre-1.0 software under active development. Behavior, interfaces, and formats may change between releases.

PATANYX is a lightweight, Rust-based desktop browser built with privacy at its core. Protection is part of the architecture from the start, not something buried behind a maze of settings.

EdgeXene designed PATANYX around transparency, local control, and verifiable protection while staying honest about what no browser can hide.

PATANYX runs on Windows and Linux and is actively under development.

## Source policy

Browser-side privacy and security mechanisms are open source and auditable; commercial backend services and deployment infrastructure are proprietary.

This repository contains the browser and its client-side crates: the ad and tracker blocker, the network freeze and privacy ledger, the encrypted vault and session store, page integrity checks, the signed update and blocklist clients, the Private Tunnel client, and on-device OCR. Server-side services and deployment infrastructure are not part of this repository.

## Architecture

PATANYX is a Rust-based browser, and it is worth being precise about what that means. The browser's application logic and privacy and security policy are implemented in Rust. The ad and tracker blocker, encrypted vault and session store, signed update and blocklist clients, encrypted DNS and Private Tunnel, page capture, on-device OCR, permission policy, and license checks all live there.

PATANYX does not implement its own rendering engine. Pages are rendered by WebView2 on Windows and WebKitGTK on Linux, using the platform's maintained web-engine runtime rather than bundling a separate browser engine with PATANYX.

That is deliberate. A rendering engine is one of the largest and most security-sensitive components of a browser. A small team maintaining its own engine would not make PATANYX safer; it would create another enormous attack surface to patch and maintain. PATANYX instead concentrates on what it can genuinely own: the privacy, security, storage, networking, permissions, and application behavior around the page.

At a high level, the architecture looks like this:

```text
PATANYX
├── Rust application core
│   ├── Privacy and security policy
│   ├── Ad and tracker blocking
│   ├── Vault and session storage
│   ├── Permissions
│   ├── Encrypted DNS
│   ├── Private Tunnel
│   ├── OCR and page capture
│   ├── Updates and blocklists
│   └── Licensing
│
├── Privileged UI webview
│   └── Hand-written HTML / CSS / JavaScript
│
└── Content webview
    ├── WebView2 (Windows)
    └── WebKitGTK (Linux)
```

The browser's own interface, its toolbar, panels, vault prompt, settings, and other chrome, is drawn with HTML, CSS, and JavaScript inside a privileged UI webview. That layer carries no framework, no npm packages, and no bundler. It is a small set of hand-written files that ask Rust to perform operations and then render what Rust returns.

There is no JavaScript build step and no dependency tree to audit. The trusted UI layer is also served under a content security policy that forbids inline script outright.

The UI and the web itself are separate. Websites are loaded in the content webview; PATANYX's privileged interface lives in the UI webview. The page does not become the browser simply because both ultimately involve a web engine.

Because PATANYX uses the maintained web-engine runtime already available on the platform, it does not ship an application directory containing its own copy of Chromium. The application itself remains compact, while engine security updates continue to come through the platform's normal update mechanism. That is what lightweight means here.

It is also why the third-party notices describe the rendering engine as something PATANYX links to and calls rather than redistributes as part of the application.

### About GitHub's language breakdown

A browser repository can produce some surprising language percentages, so one detail is worth calling out.

- About half of the JavaScript in this repository never ships. The files under `scripts/` are test gates that run before a release, generally one per feature. A built PATANYX browser contains none of them. They are still counted because they are first-party project code; marking first-party code as vendored simply to make the language statistics look better is not something this repository does.

### Toolchain

The Rust toolchain is pinned to version `1.96.0` through `rust-toolchain.toml`. Pinning the compiler reduces build-environment drift and is one part of PATANYX's reproducible-build process.

## Quick start

The toolchain is pinned to **Rust 1.96.0** by `rust-toolchain.toml` as part of PATANYX's reproducible-build process (see [docs/reproducible-builds.md](docs/reproducible-builds.md)); rustup selects it automatically when you build.

### Linux (native build)

PATANYX renders with WebKitGTK. Building needs the GTK 3 and WebKitGTK development packages (Debian: `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`); running needs WebKitGTK 2.52.5 or newer, which ships with Debian 13.

```bash
git clone https://github.com/EdgeXene/patanyx.git
cd patanyx

cargo build --release --bin patanyx

./target/release/patanyx
```

### Windows (cross-build from Linux)

Official Windows binaries are cross-compiled from Linux with `scripts/build-windows.sh`, which uses cargo-xwin to target `x86_64-pc-windows-msvc` and verifies the produced binary before accepting it. The resulting binary runs on Windows with the WebView2 runtime.

## Downloads

Prebuilt binaries are published on the [releases page](https://github.com/EdgeXene/patanyx/releases) and at [patanyx.edgexene.io/download/](https://patanyx.edgexene.io/download/). Releases here are marked prerelease while PATANYX is pre-1.0.

Every published binary carries a [Sigstore](https://www.sigstore.dev/) bundle. Verify a download before running it:

```bash
cosign verify-blob PATANYX.exe \
  --bundle PATANYX.exe.sigstore.json \
  --certificate-identity contact@edgexene.io \
  --certificate-oidc-issuer https://accounts.google.com
```

Windows binaries are also Authenticode-signed, so Windows will name the publisher in the file's Properties.

The browser updates itself from `patanyx.edgexene.io` over its own signed update channel, independently of this repository: each update is described by an Ed25519-signed manifest that the browser verifies against a key compiled into the binary, and nothing installs without your say-so.

## Testing

Run the tests with `cargo test --workspace`.

## Website

https://patanyx.edgexene.io/

## Contributing

Bug reports, feature suggestions, and pull requests are welcome.
[CONTRIBUTING.md](CONTRIBUTING.md) explains how this repository works, how to send
feedback, and what a change has to satisfy to be accepted. Report vulnerabilities
privately instead, by the process in [SECURITY.md](SECURITY.md).

## Security

If you believe you have found a security or privacy vulnerability, report it privately: use the contact form at https://patanyx.edgexene.io/contact/.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) is the full third-party crate inventory, generated by `scripts/third-party-licenses.sh`.

Created by EdgeXene LLC.
