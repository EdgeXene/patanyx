# Authenticode signing, and why it is not optional

Every PATANYX binary is currently **unsigned**. The certificate table in the PE
header is empty, checked rather than assumed.

That is a distribution problem, not a cosmetic one. SmartScreen attaches
reputation to a specific file hash and a publisher identity. With no publisher
identity, reputation resets to zero on **every build** — which is why, on
2026-07-28, four consecutive test builds downloaded fine and the fifth was
blocked outright, on a build that imported _fewer_ suspicious Windows APIs than
one that had passed. Nothing about the binary changed for the worse. There was
simply nothing for reputation to accumulate against.

The update channel hides this from existing users, because PATANYX fetches and
verifies updates itself and nothing arrives through the browser. That helps
exactly the people who already have PATANYX, and not at all the people trying
to install it for the first time. It is the wrong way round.

## Four signatures, four jobs

Conflating these causes real mistakes, so they are tabulated rather than
described:

|              | Update manifests                         | Blocklist manifests                      | Authenticode                               | Sigstore                                   |
| ------------ | ---------------------------------------- | ---------------------------------------- | ------------------------------------------ | ------------------------------------------ |
| Algorithm    | Ed25519, ours                            | Ed25519, ours, separate domain           | RSA/ECDSA via a public CA                  | ephemeral key, Fulcio-issued certificate   |
| Verified by  | PATANYX itself, against `PUBLISHER_KEYS` | PATANYX itself, against `BLOCKLIST_KEYS` | Windows, before the file runs              | anyone, via Rekor — never by PATANYX       |
| Answers      | is this update really ours               | is this host list really ours            | who published this, so Windows lets it run | which commit produced this artifact        |
| Signed by    | a human, per release                     | cron, hourly, unattended                 | the release pipeline                       | the CI workflow                            |
| Key location | offline, **never** on a build machine    | on the publishing server, by design      | must be reachable by the release pipeline  | no key at all; identity is the CI workflow |
| If it leaks  | arbitrary code on every install          | a wrong host list                        | builds that Windows trusts                 | nothing the browser reads                  |

The offline rule for the **update** key is correct and stays. The blocklist key
is the deliberate exception: it signs every hour, so it cannot be offline, and
it is only acceptable online because its worst case is a bad host list rather
than arbitrary code. That is the entire argument for splitting them, and it
collapses the moment `publisher.key` is copied to the publishing server.
Authenticode is a different case again: it has to be in the release path, which
is why an HSM-backed or cloud-hosted signing service fits this project and a key
file on a laptop does not. Sigstore is a fourth: it signs what is PUBLISHED, for
the benefit of people auditing the project, and nothing in the browser ever
reads it.

The two Ed25519 keys cannot be substituted for each other even by mistake —
signatures are domain-separated (`manifest.rs`), so a blocklist signature
presented as an update is refused before the key is even considered. That is
tested, and re-verified by hand against live manifests on 2026-07-31.

### The updater keeps Ed25519 — decided 2026-07-29

Sigstore verification inside the updater was considered and **refused**.

`patanyx-update` is deliberately five dependencies (ed25519-dalek, sha2, serde,
serde_json, thiserror) and its manifest names what it refuses to carry: no HTTP
client, no async runtime, no filesystem, **no clock**, no RNG. It is pure
verification over bytes the caller supplies, which is what lets the guarantee be
stated in one sentence — an attacker holding the update host, its DNS and a
valid certificate for it still cannot make one install accept an update.

Sigstore would replace that question ("was this signed by the key only we
hold?") with a larger one ("was this signed by someone who could authenticate
as our identity, vouched for by Fulcio, and recorded in Rekor?"), and would drag
X.509 chain validation, Sigstore's rotating TUF trust root — which the updater
would then have to update, a bootstrapping problem — Rekor inclusion proofs, and
a CLOCK into the one path built to need none of them. The clock alone ends the
pure-function property.

The upside it offers is real but does not apply here: it removes long-lived key
custody. That is a trade worth taking for projects whose signing key lives on
build machines. This key never does.

Precision is the other argument. `93359f7` refuses small-order keys and moved
verification to `verify_strict` — reasoning of that grain is tractable across one
algorithm and very hard across X.509 plus TUF plus Merkle proofs.

## The choice, and why

| Option                  | Cost             | Blocker                                                  |
| ----------------------- | ---------------- | -------------------------------------------------------- |
| Certum SimplySign Cloud | paid             | none for a commercial OV cert; cloud HSM, no smartcard   |
| SignPath Foundation     | free             | requires public source + OSI licence                     |
| Azure Trusted Signing   | ~$10/mo          | none as of 2026; open to self-employed in US/CA/EU/UK    |
| Certum Open Source      | ~€69 then €29/yr | **also requires open source**, plus a physical smartcard |
| Self-signed             | free             | worthless — Windows does not trust it                    |

Certum's CHEAP certificate sits behind the _same_ open-source gate as
SignPath's free one, so paying for that one buys independence, not access. Its
physical smartcard also cannot sign on a headless Linux build server, which is
where PATANYX is cross-compiled; only the SimplySign cloud option avoids that,
and that is the reason it was chosen.

**Decision, settled 2026-08-05: Azure Artifact Signing, plus Sigstore for
provenance. PURCHASED, CONFIGURED, AND PROVEN.** This supersedes both the
2026-07-29 Certum SimplySign decision and the 2026-07-28 SignPath one; the rows
above are kept only so nobody re-opens a closed comparison. The Apache-2.0
licensing that the SignPath decision brought with it is unaffected and stays.

Note the service has been renamed twice: Azure Code Signing -> Trusted Signing
-> **Azure Artifact Signing**. Docs live under `/azure/artifact-signing/`; the
resource provider is still `Microsoft.CodeSigning`. Searching the old names
finds stale pages.

**The certificate names a PERSON, not EdgeXene.** The EdgeXene LLC was formed in
2026 and organization validation requires roughly three years of verifiable
operating history, so individual validation was the only available route. The
subject is therefore `CN=Rhoda Faye Tomines, O=Rhoda Faye Tomines, L=Hammond,
S=IN`, and a custom CN or O is not supported by the service. Windows will name
that individual as publisher on every signed binary. The certificate profile
happens to be _named_ EdgeXene, which changes nothing -- a profile name never
appears in a signature. Any download-page or About copy presenting EdgeXene as
the publisher should be read against this before v1.0. Revisit around 2029, when
the LLC could clear the org bar.

**What it does NOT do is remove a SmartScreen warning on day one.** The service
does not issue EV certificates and has no plans to. Microsoft's own position is
that reputation accrues and the prompt stops once a file hash has sufficient
download history. What was bought is a stable publisher identity for reputation
to accumulate against, which is precisely what the 2026-07-28 incident at the
top of this file shows was missing. This is also the argument for signing every
pre-1.0 build rather than waiting for release: the monthly fee is flat, the
Basic tier allows 5,000 signatures a month against the two or three a release
needs, and reputation earned before the announcement is reputation the launch
does not have to earn from zero.

Sigstore is NOT an alternative to any row in that table. It cannot remove a
SmartScreen warning: Windows honours an Authenticode signature in the PE
certificate table chaining to a CA in its own trust program, Fulcio is not in
that program, and Cosign signatures are detached rather than embedded. It is
listed here only so nobody later mistakes it for a way to skip this purchase.

## What SignPath requires, and where we stand

From <https://signpath.org/terms.html>:

| Requirement                                                      | Status                                                                                                                 |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| OSI-approved licence, no commercial dual-licensing               | **done** — Apache-2.0                                                                                                  |
| No proprietary or non-open-source component                      | **done** — 466 crates all permissive; OCR models Apache-2.0; WebView2 and WebKitGTK are platform runtimes, not bundled |
| Publicly available codebase                                      | **outstanding** — no git remote yet                                                                                    |
| Already released in the form to be signed                        | **done** — 0.9.2 is published                                                                                          |
| Functionality documented on the download page                    | partial — `patanyx.edgexene.io` is logo and slogans                                                                    |
| Actively maintained                                              | yes                                                                                                                    |
| Binaries from **verifiable automated builds** of that repository | **outstanding — the real work**                                                                                        |
| MFA on repository and SignPath accounts                          | to do                                                                                                                  |
| Defined Author / Reviewer / Approver roles                       | to do                                                                                                                  |
| Published code-signing policy on the project homepage            | to do                                                                                                                  |
| SignPath Foundation attribution                                  | to do                                                                                                                  |

That table applies ONLY IF the Certum purchase falls through and SignPath
becomes the route. It is kept for that case and is not a to-do list today.

The one item on it that is not paperwork is **verifiable automated builds**.
SignPath signs artifacts produced by a CI pipeline it can trace to a commit; it
does not sign a binary someone built by hand and uploaded. PATANYX is currently
built with `scripts/build-windows.sh` on a VPS, by hand, and on the SignPath
route that would have to become a CI workflow building from a tagged commit.
This requirement is SignPath's alone; a purchased OV certificate imposes none of
it.

`scripts/repro-build.sh` helps here rather than being extra work — a build whose
output depends only on its source is exactly what "verifiable" means, and it
already exists for the Linux target.

## Publishing the source is NOT a prerequisite here

Recorded because an earlier revision of this file got it wrong. "Publish the
repository" and "move the build into CI" were **SignPath's** requirements: it
signs artifacts produced by a pipeline it can trace to a public commit, and it
does not sign a binary someone built by hand.

A PURCHASED commercial OV certificate has no such condition. It signs what its
holder tells it to sign. So on the Certum path the hand-built VPS release stays
exactly as it is, the repository stays private, and nothing waits on CI.

Worth knowing while sequencing: the Windows build is **cross-compiled from
Linux** (`cargo xwin --target x86_64-pc-windows-msvc`, `scripts/build-windows.sh`).
"Windows CI" never meant a Windows machine, only automating that existing
cross-compile.

## Signing is WINDOWS-ONLY, and it CHANGES THE FILE HASH

Both facts reorder the release procedure, so they come before the steps.

There is no Linux signing path: SignTool plus a Microsoft-supplied dlib, on
Windows 10 1809 or newer. PATANYX is cross-compiled on the Debian VPS, so the
release gains a round trip to the Windows machine -- the same one that already
holds `publisher.key`.

Authenticode writes into the PE certificate table, so the file it signs is not
the file that went in. Measured on the first real run: 39,726,080 bytes became
39,741,720, a 15,640-byte certificate table and an entirely different sha256.
Everything that pins a hash therefore happens AFTER signing, never before.

There is nothing to store or guard. Each signing call mints a certificate inside
the service, uses it, and discards it; the private key is never released. Those
certificates live **three days**, which is why `/tr http://timestamp.acs.microsoft.com`
is mandatory rather than hygiene -- the timestamp is what makes a signature
outlive the certificate that produced it.

## Steps, in order -- Authenticode, the part that fixes SmartScreen

1. **Cross-compile** on the server exactly as today. Run any reproducibility
   check HERE, before signing: Authenticode embeds a wall-clock timestamp, so
   signed output is deliberately not byte-reproducible.
2. **Copy the unsigned exes to the Windows machine and sign both** --
   `PATANYX.exe` and `PATANYX-Premium.exe`. The Premium build is not exempt for
   being the paid tier; an unsigned premium binary would give paying users the
   worse install experience. Both are signed by the same certificate profile,
   so publisher reputation accumulates across them, which matters because the
   Premium build will always have the smaller download count.
3. **Verify on Windows before the files travel back**: `signtool verify /v /debug /pa`
   must report the chain reaching Microsoft ID Verified Code Signing PCA 2021
   AND a timestamp line. A signature without a timestamp is worthless in 72
   hours.
4. **Copy the SIGNED exes back to the server.** Only now compute sha256,
   generate deltas, and assemble the manifest payload.
5. **Ed25519 manifest ceremony**, then **Sigstore**, then publish, unchanged.
6. **Never retro-sign a published version in place.** Its manifest, Sigstore
   bundle and deltas all pin the unsigned hash; replacing the bytes under a
   version that `decide()` already answers for is how 0.9.54 was burned. Fold
   Authenticode into the next cut instead.
7. **Verify a signed binary on a clean machine** before announcing. The
   certificate table being non-empty is not the test; a fresh download on a
   machine with no history is.

What does NOT get signed: the Linux binary (Authenticode is a PE format), the
delta patches, and the update manifests. The latter two already carry Ed25519
signatures that PATANYX verifies itself, and the browser never reads an
Authenticode signature. `patanyx-sign.exe` never reaches a user, so signing it
buys nothing.

## Sigstore — identity settled 2026-07-29, signing may start now

**Identity: `contact@edgexene.io`, issuer `https://accounts.google.com`.** A
Google account is registered under that address, so Fulcio's certificate carries
exactly that string. The mailbox itself is Proton-hosted and that is irrelevant:
what matters is which provider will ASSERT the address in an OIDC token, not who
delivers mail to it.

An earlier revision of this file said Sigstore should wait for a public
repository and "buys nothing until then". **That was too strong and is
withdrawn.** With the source still private a signature cannot help anyone audit
what the code does, but it still does two useful things: it ties each published
binary to a named publisher, and it puts that publication in an append-only
public log, so a binary cannot later be swapped quietly under the same name
without leaving a trace. Both are worth having before the source is published.

The privacy objection that argued for waiting also does not apply to this
address. It was about publishing a PERSONAL identity permanently. This is a role
address already printed on the project's own sites, so Rekor discloses nothing
new, and it can outlive any individual account.

### Scope: sign the published binaries, nothing else

Sign the artifacts in `/srv/patanyx-dist/dl/`. Do NOT sign the update manifests
in `/v1/`: they already carry an Ed25519 signature that PATANYX itself verifies,
and PATANYX never reads a Sigstore bundle, so a second signature there would be
decoration. Same for `blocklist-*.bin`, which the browser verifies the same way.

### There is no rehearsal

cosign 3.1.2's `sign-blob` has no `--tlog-upload=false`; keyless signing always
writes to the transparency log. The first real run publishes the identity
permanently. Confirm the account BEFORE running, because there is no way to
discover mid-flow that it authenticated as something else and undo it.

### Publishing the identity is mandatory, not optional

Verification requires the verifier to pin an expected identity, so
`contact@edgexene.io` and `https://accounts.google.com` must appear on the
download page. Without both values nobody can construct a working
`cosign verify-blob` command, and the signature is inert.

## Later, when the repository goes public

1. **Publish the repository.** Apache-2.0, `LICENSE`, `NOTICE` and
   `THIRD_PARTY_LICENSES.md` are already in place. Confirm no secrets are in
   history before pushing — `publisher.key` must never have been committed, and
   and no `/root/.*env` credential file may appear anywhere.
2. **Move the cross-compile into CI**, building from a tag, producing the same
   artifact `build-windows.sh` produces today, with the public-build assertion
   (no chat marker) kept as a gate.
3. **Consider moving to a workflow identity** in that CI. If it happens, the
   download page must then say which identity covers which releases — an
   email-signed 0.9.x and a workflow-signed 1.0 are both valid and verifiers
   need to know which to pin.

Nothing here waits on the product being finished. A signature attests WHO
PUBLISHED AN ARTIFACT, not that the artifact is mature; signing prototypes is
normal and correct.

### On identity choice generally

Rekor is public, append-only and permanent. Fulcio accepts email-based
identities (its Dex instance federates GitHub, Google and Microsoft accounts, and
Google directly) as well as workload identities from GitHub Actions, GitLab
CI/CD, cloud Kubernetes and SPIFFE. An email identity publishes that email
forever in a log anyone can query, which is why a ROLE address was chosen over a
personal one rather than why signing was deferred.

**CI does not mean GitHub.** GitLab CI/CD is a supported Fulcio issuer and is
not Microsoft-owned; a forge can also be self-hosted. A fully self-hosted runner
is the one case to check carefully — Fulcio accepts additional configured
issuers, but the public-good instance's accepted list is what governs, not what
a private runner emits.

This is also why Sigstore's own operational maturity does not gate a release:
PATANYX never verifies a Sigstore signature, so an outage, a trust-root
rotation, or a breaking API change costs a release step and not a single user's
update. The dependency is quarantined outside the product on purpose.

## Do not skip the clean-machine check

The whole reason this document exists is that an unverified assumption about
Windows trust cost an evening. "It is signed now" is not evidence; a download on
a clean machine is.
