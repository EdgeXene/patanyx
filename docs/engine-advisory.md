# The engine advisory: automatic WebView2 security threshold

The browser compiles in the oldest WebView2 runtime it considers free of a
known, exploited bug (`platform::MIN_WEBVIEW2`) and warns with a banner when
the engine underneath its pages is older. `docs/update-channel.md` ("The
engine floor") describes how a signed release manifest raises that floor
without a browser release. That path needs the offline release key and a
human, so it cannot run on the day Microsoft's notes land.

This document describes the automated path that sits beside it: a fourth
signed document class, the ENGINE ADVISORY, whose entire authority is to
raise the WebView2 warning threshold; the hourly monitor that discovers
exploited desktop Chromium fixes and publishes advisories; and the client
half that fetches, verifies, persists and reports them.

Nothing here can install anything, refuse startup, name a URL, or reach the
Linux side. SmartScreen stays off. A compromised advisory key buys a false
banner on Windows until the key is revoked in a release, and nothing more.

## Status of this document

Implemented, reviewed and tested. The production advisory key was
provisioned on the publishing server on 11 September 2026 and its verifying
half is compiled into `ADVISORY_KEYS` (`crates/app/src/updater.rs`); a unit
test pins exactly one real key and refuses every test seed. Builds from
this source fetch and verify advisories. Browsers already in the field
cannot use this channel until they install a release built from this
source; until then their only floor path is the release manifest. Whether
the feed is served and the timer is active is recorded by the publisher's
activation steps below, not by this document.

## The document

Signed under its own domain, `PATANYX-ENGINE-ADVISORY-V1\n`, verified only
by `verify_advisory_manifest`, against only `ADVISORY_KEYS`:

```json
{
  "engine": "webview2",
  "floor": "152.0.4191.66",
  "published_at": 1757570000,
  "reason": "CVE-2026-87491"
}
```

- `engine` is a closed one-member set. The advisory cannot speak for
  WebKitGTK, whose compiled floor is a refusal rather than a banner.
- `floor` is exactly four decimal fields, each fitting u32. Three or five
  fields, a suffix, a blank, or `0.0.0.0` are refused at signing and by
  every client.
- `published_at` is a real timestamp. A client refuses one more than seven
  days ahead of its clock.
- `reason` is at most 200 characters with no control or direction-override
  characters; diagnostics only, never the banner's words.

Two bounds are policy rather than shape and take the compiled floor and the
clock as inputs (`AdvisoryManifest::check_plausible`): a floor more than
`ADVISORY_MAX_MAJOR_AHEAD` (24) majors past the compiled constant is refused,
as is the future timestamp above. The signer applies the same bounds against
`--baseline` before emitting, so a mistake is a signing refusal first.

Cross-class separation is two independent mechanisms, both tested in both
directions: domain separation stops REPLAY (an advisory signed by a trusted
key fails the SIGNATURE check of every other verifier, and vice versa) and
the disjoint key set stops FORGERY (a stolen advisory key is refused by the
release, blocklist and model verifiers because they do not trust it).

## Signer

```text
patanyx-sign keygen advisory.key advisory
patanyx-sign sign-advisory advisory.key payload.json --baseline 152.0.4191.66 [--now N]
patanyx-sign verify-advisory envelope.json <verifying-key-hex> [--baseline a.b.c.d] [--now N]
```

`sign-advisory` self-verifies with the browser's verifier AND the client
bounds against `--baseline`, which is required. `verify-advisory` without
`--baseline` checks signature and schema only and says so in its output.

## The client

`crates/app/src/engine_advisory.rs`, on the existing six-hour update
schedule. After the release manifest check has finished, whatever it
concluded (up to date, refused, unreachable), the worker fetches ONE fixed
URL, `<UPDATE_BASE_URL>/v1/engine-advisory.json`, with no version, token,
query string or cache validator. This is one additional request to the
same host in the same check: the host and the network path see, once more,
an IP address, the request time, the requested path and the generic
`patanyx` user agent, and nothing that identifies an install. The Updates
panel describes update checks as release information plus, when
configured, engine advisories; it states no exact request count, because
an unconfigured build makes no advisory request and the transport retries
a failed connection. The runtime version never leaves the machine; the
comparison is local.

The verified advisory is persisted in `updates/engine-advisory.json` beside
the release register, NEVER merged into it:

- Entries are keyed by the verifying key that authenticated them and hold
  the signed envelope. Every read and every write re-verifies each envelope
  against the compiled `ADVISORY_KEYS`. A revoked key's entries stop
  counting the moment the key leaves the list and are pruned on the next
  write. The unsigned copies of the floor beside each envelope have no
  authority; a corrupt copy is repaired from the envelope, and an edited
  envelope is dropped.
- Monotonic per key at exact four-field precision: lower, equal, replayed
  and omitted floors change neither the answer nor the bytes.
- The read-verify-merge-replace transaction holds a process-wide mutex AND
  an exclusive OS file lock on `engine-advisory.lock` (`std::fs::File::lock`:
  `flock` on Unix, `LockFileEx` on Windows), so a second browser process
  sharing the directory re-reads after the first commits instead of
  renaming a stale lower document over it. The file is replaced whole
  through a temp file and rename; a failed write leaves the previous bytes
  and is reported in the status snapshot as `persist:`.

The effective floor is the maximum of three authorities that can each only
raise: the compiled constant, the release-manifest register, and the
advisory register (`platform::effective_floor_from`). The release-floor
register now uses the same locked, atomic transaction and returns its
write result instead of discarding it.

### The running engine, not the installed one

`GetAvailableCoreWebView2BrowserVersionString` reports the Evergreen build
on disk, which updates itself while the browser is open. Every live webview
keeps the build it was created with. The Windows backend therefore records
each built webview's own environment `BrowserVersionString` (chrome,
content, translator and debug probe paths, in the hardened and the fallback
environment regime alike) and keeps the LOWEST. Before any webview exists
the installed number serves startup diagnostics; once environments exist a
failed read stays UNKNOWN and never borrows the installed number.

When the running engine is below the floor and the installed runtime is
not, the banner uses a body that names the installed build and says a
restart is what clears it (`chrome-engine-floor-body-restart`). The
standard body claims only what is observed: pages in this session still
use an older version. It says nothing about the installed runtime, which an
unknown or partial read cannot establish. The `engine_status` reply carries `version_source`, `installed` and
`restart_clears` for diagnostics.

### Unconfigured

With `ADVISORY_KEYS` empty, `advisory_trusted_keys()` is `NoTrustedKeys`,
nothing is fetched, nothing is persisted, and the update status snapshot
carries `"advisory": {"state": "unconfigured", ...}`. Tests inject explicit
test keys; no test key is compiled in.

## The monitor and publisher

`scripts/engine-advisory-monitor.py`, Python standard library only,
scheduled by the publisher-side hourly timer (
`RandomizedDelaySec=300`, `Persistent=true`).

Sources, fixed and host-pinned, https only, no redirects, `text/html` only,
2 MiB cap, 25 s timeout:

1. `https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security`
2. `https://www.catalog.update.microsoft.com/Search.aspx?q=Microsoft%20Edge-WebView2%20Runtime%20<version>`

Selection rule, in order:

1. Split the notes at EVERY heading of any level inside the content
   container. A section is dated only when it is an `<h2>` whose text is a
   plain date; the title, "In this article", "See also", irregular dates
   such as "February - 26, 2026", a "(updated)" suffix or an `<h3>` are
   undated. Dated sections must be newest-first.
2. Walk in document order until the first dated section holding a relevant
   notice. Everything above that point is classified strictly: a relevant
   paragraph (one mentioning an exploit, other than Microsoft's standalone
   "enhanced security mode mitigates" commentary, which names no build and
   no fix) must parse, or the run refuses; a relevant notice under an
   undated heading refuses; exploit-related text outside a `<p>` refuses.
   Nothing newer can disappear underneath an older match. Android, iOS and
   macOS-only notices are out of scope and ignored.
3. A notice parses only when ONE sentence associates the exploited CVE(s)
   with the fix: "The Chromium team reported that CVE-... has/have an
   exploit in the wild, and this update contains a fix for it/them", or
   "This update contains a fix for CVE-..., which has/have been reported by
   the Chromium team as having an exploit in the wild". Every CVE in that
   sentence must be a link (either quote style) whose target ends in the
   CVE it names; no other CVE may appear in the paragraph; the paragraph
   must name a desktop Stable build. An exploited CVE in one sentence and a
   fix for another CVE in the next is not an association and refuses.
4. The selected section decides. It must name exactly one desktop Stable
   build and must not be dated in the future. An Extended Stable-only
   notice is refused (the runtime follows Stable). The selected CVE must
   not be associated with a different desktop build anywhere else on the
   page; if it is, the association is ambiguous and refused. Other CVEs'
   parallel branches (for example CVE-2026-2441 on 145.0.3800.58 and
   144.0.3719.130 in February 2026) are history and do not veto.
5. Two floors, two jobs. `--baseline` is the floor the shipped browser
   compiles in and is the ONLY thing the client's plausibility bound is
   judged against: a candidate more than `--max-major-ahead` (24) majors
   past it is refused here, and the same baseline is passed to the signer
   and the verifier. The floor already published (last-good and the served
   manifest, verified under the configured key when a signer is available)
   is the MONOTONIC authority: below it is a no-op, equal to it is a no-op
   while a valid publication is served.
6. Bootstrap. When no valid publication is served and the candidate equals
   the published floor or nothing has been published, the candidate is
   corroborated, signed and published like a raise, so the endpoint exists
   before clients ship. A dry run with `--publish-root` reports
   `would-bootstrap`; a served file the dry run cannot verify counts as
   existing. A live run refuses to replace a served file it cannot verify.
7. Fetch the Catalog search for the exact build. Require EXACTLY ONE row
   titled `Microsoft Edge-WebView2 Runtime Version <major> Update for x64
based Editions (Build <version>)` with product `Microsoft Edge`,
   classification `Updates`, an `M/D/YYYY` date not in the future, and a
   positive integer `originalSize` belonging to that row's own GUID. x86 and
   ARM64 rows are not evidence for x64; ordinary Edge rows are not evidence
   for WebView2. Catalog listing establishes availability, not rollout.
8. Write `candidate-payload.json`. In `--dry-run`, stop here with
   `would-raise` or `would-bootstrap`.
9. Sign with `patanyx-sign sign-advisory <key> payload --baseline <compiled
baseline> --now <now>`. The signer's reported verifying key must equal
   `--public-key` (required for publishing), and `verify-advisory` under
   that key and baseline must accept the envelope. A refusal is exit 5 or
   7 and publishes nothing.
10. Publish atomically to `<publish-root>/v1/engine-advisory.json` (mkstemp,
    fsync, rename, directory fsync, mode 0644), then record
    `last-good.json`. A publish failure is exit 6 with last-good untouched.
    A malformed `last-good.json` is exit 7 with status written and nothing
    published.

Every run writes `status.json` (timestamp, outcome, reason, candidate,
catalog row, source hashes, published path) and keeps raw source bytes in
`evidence/` on any candidate or refusal (last 12). It never sends email, a
webhook or a message. Exit codes: 0 ok, 2 fetch, 3 refused, 4 locked, 5
signing, 6 publish, 7 config.

Tests: `python3 scripts/test_engine_advisory_monitor.py` (set
`PATANYX_SIGN` to a built `patanyx-sign` for the end-to-end signing test).
Fixtures under `scripts/fixtures/engine-advisory/` are direct-origin
captures with `PROVENANCE.json`; the test re-checks their sha256.

## Evidence for the compiled baseline

`MIN_WEBVIEW2` is 152.0.4191.66. Captured 11 September 2026 06:16 Central
by root (`PROVENANCE.json`): the security notes' "September 4, 2026" entry
names Microsoft Edge for Stable (Version 152.0.4191.66) with CVE-2026-87491
"has an exploit in the wild, and this update contains a fix for it"; the
Catalog lists "Microsoft Edge-WebView2 Runtime Version 152 Update for x64
based Editions (Build 152.0.4191.66)", 9/4/2026, 262787408 bytes. The
monitor's dry run against those captures selects exactly that. A first
launch that is offline warns from this constant alone.

## One-time provisioning and activation (publisher landing steps)

Steps 1 and 2 were performed on 11 September 2026; the rest are the
activation sequence.

1. Done. On the publishing server: `patanyx-sign keygen
   /root/.patanyx-keys/advisory.key advisory` (0600; same terms as
   blocklist.key). The printed verifying key is
   `e16998e637f88c04a57c7093aec5711e14cfd0811b157f67872896f14e4ea768`.
2. Done. The verifying key is in `ADVISORY_KEYS`;
   `advisory_keys_hold_exactly_one_real_provisioned_key` pins exactly one
   well-formed key that is not any test seed's, and
   `the_advisory_key_set_is_disjoint_from_every_other_class` keeps the sets
   apart. That test pair is the release-time gate: non-empty, real,
   disjoint. Rotation adds a second entry deliberately in both places.
3. Write `/etc/patanyx-engine-advisory.env` (0600):
   `PATANYX_ADVISORY_BASELINE=152.0.4191.66`,
   `PATANYX_ADVISORY_PUBLISH_ROOT=/srv/patanyx-dist`,
   `PATANYX_ADVISORY_KEY=/root/.patanyx-keys/advisory.key`,
   `PATANYX_ADVISORY_SIGNER=<path to a release-built patanyx-sign>`,
   `PATANYX_ADVISORY_PUBLIC_KEY=<the verifying key hex>`.
4. Dry-run by hand against the live sources with `--dry-run --state-dir
/var/lib/patanyx-engine-advisory --baseline 152.0.4191.66 --publish-root
<the served root>`; expect `would-bootstrap` (nothing is served yet) and
   inspect `status.json`, including the catalog row.
5. Run once live by hand with the key, signer and verifying key; expect
   `published-bootstrap`, then `unchanged` on a second run with identical
   served bytes. Confirm the served `/v1/engine-advisory.json` verifies with
   `patanyx-sign verify-advisory <file> <hex> --baseline 152.0.4191.66`.
   The served endpoint now exists before any client ships.
6. Ship the browser release carrying the key and the .66 baseline through
   the standing release gates. Only then install the unit and timer
   (`systemctl enable --now patanyx-engine-advisory.timer`) and confirm the
   first scheduled run's journal line and `status.json` say `unchanged`.
7. Confirm `/v1/engine-advisory.json` is served with the same cache policy
   as `/v1/*.json` (300 s, must-revalidate) and that the browser's status
   snapshot on a provisioned build reports `advisory.state` other than
   `unconfigured`.
