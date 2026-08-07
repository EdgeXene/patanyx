# Security Policy

## Reporting a vulnerability

If you believe you have found a security or privacy vulnerability in PATANYX,
report it privately using the contact form at
https://patanyx.edgexene.io/contact/ and choose the **Privacy question**
category.

Useful things to include, to the extent you have them:

- what the issue is, and what an attacker gains from it
- the affected version, platform (Windows or Linux), and build variant
- steps to reproduce, or a proof of concept
- whether the issue is already public anywhere

You will get an acknowledgement within 5 business days. EdgeXene LLC is a small
team, so a full assessment may take longer; we will tell you where things stand
rather than go quiet.

We do not operate a paid bug bounty. Reporters who want credit will be named in
the release notes for the fix, and reporters who would rather stay anonymous
will not be named.

## Supported versions

PATANYX is pre-1.0 software under active development. Only the current release
line receives security fixes; there are no long-term support branches, and older
prerelease versions are not patched. Fixes ship in the next release rather than
as backports.

## Scope

This repository contains the browser and its client-side crates: the ad and
tracker blocker, the network freeze and privacy ledger, the encrypted vault and
session store, page integrity checks, the signed update and blocklist clients,
the Private Tunnel client, on-device OCR, and the chat client with its wire
protocol. Server-side services and deployment infrastructure are not part of this
repository, but reports about them are still welcome through the same channel.

Some limits are known and documented rather than treated as vulnerabilities. The
["What it cannot hide"](https://patanyx.edgexene.io/about/#cannot-hide) section of
the About page states them in full. In particular, PATANYX is not an anonymity
tool. Its anti-fingerprinting adds noise to some readouts and deliberately does
not cover others -- workers and OffscreenCanvas, `readPixels`, screen size,
fonts, and the user agent are all documented as uncovered. Reports in those
areas are welcome as feature discussion, but they are not treated as security
regressions.

## Verifying a release

Released binaries are signed with [Sigstore](https://www.sigstore.dev/), and the
signature is recorded in a public, append-only transparency log. The
[About page](https://patanyx.edgexene.io/about/#verify) documents the
`cosign verify-blob` invocation along with the signing identity and issuer.

Update manifests and blocklists are separately signed with Ed25519 keys whose
verifying halves are compiled into the browser, so a compromise of the
distribution server, its DNS, or a certificate for it still cannot make an
installation accept a modified update.
