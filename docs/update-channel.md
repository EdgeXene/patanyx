# Operating the update channel

Everything the browser needs to accept an update is compiled into it. Everything
needed to _publish_ one lives here.

Both compiled-in constants are now real, as of 2026-07-28:

- `PUBLISHER_KEYS` carries the project owner's verifying key.
- `UPDATE_BASE_URL` is `https://patanyx.edgexene.io`.

**There are TWO key lists, and the difference is the whole point.** As of
2026-07-31, `BLOCKLIST_KEYS` verifies blocklist manifests and `PUBLISHER_KEYS`
verifies binaries. See "Two keys, two blast radii" below before touching
either.

ONE THING REMAINS, and it is not code: **that host must actually serve
`/v1/<platform>.json`.** Until it does, checks fail with a network error rather
than "not configured" — still loud, still safe, and still not an update
channel.

## The trust model in one paragraph

A manifest is trusted because a key compiled into the binary signed it — never
because it arrived over TLS from the expected host. TLS protects the download's
privacy; the signature is what protects its integrity. So an attacker who owns
the hosting, the DNS, or a certificate authority still cannot make a PATANYX
install accept an update. Only the signing key can do that, which is why the
whole of this document is really about protecting one file.

## One-time: generate the keypair

**Done 2026-07-28.** Kept here because rotation repeats it.

Run on a machine that is not a build machine, and ideally not networked. Key
generation works on Linux, macOS and Windows — `/dev/urandom` on the first two,
CNG's `BCryptGenRandom` on Windows.

```bash
cargo run -p patanyx-update --example patanyx-sign -- keygen publisher.key
```

Or with a prebuilt tool, which is the usual case since the ceremony machine has
no reason to have a Rust toolchain:

```powershell
.\patanyx-sign.exe keygen publisher.key
```

It prints the verifying key, already formatted:

```
    const PUBLISHER_KEYS: &[&str] =
        &["<64 hex chars>"];
```

Paste that into `crates/app/src/updater.rs`, replacing the placeholder, and
commit it. The verifying key is public: it belongs in the repository, it appears
in every binary, and publishing it costs nothing.

`publisher.key` is the opposite. Anyone holding it can sign an update that every
existing install will accept and install without further checks. It must not
reach a build machine, a repository, a CI secret store, or any backup that syncs
somewhere. The tool writes it `0600` and refuses to overwrite an existing file,
which protects against a slip, not against a bad storage decision.

If it leaks, rotation is the answer and it is slow: ship a build whose
`PUBLISHER_KEYS` lists both old and new keys, wait for that build to propagate,
then ship one listing only the new key. Installs that never took the
intermediate build are stranded on the old key. Plan for that before you need it.

## Two keys, two blast radii

The blocklist needs signing every hour. Binaries need signing a few times a
year. One key cannot serve both jobs, because automating the hourly signature
means putting the key on a networked machine, and the key that signs blocklists
was also the key that signs releases.

So there are two, and they are not interchangeable:

|                          | `PUBLISHER_KEYS`                | `BLOCKLIST_KEYS`         |
| ------------------------ | ------------------------------- | ------------------------ |
| Signs                    | release binaries                | blocklist manifests      |
| Private key lives        | offline, operator-held          | on the publishing server |
| Signed by                | a human, per release            | cron, hourly, unattended |
| If the private key leaks | arbitrary code on every install | a wrong host list        |
| Recovery                 | slow two-release rotation       | publish a corrected list |

**`publisher.key` must never arrive on the publishing server.** That separation
is the entire reason automated signing is acceptable at all. A convenience that
puts them on the same machine silently undoes it.

`crates/app/src/updater.rs` asserts the direction that matters in
`compiled_blocklist_keys_parse`: the automated key must not appear in
`PUBLISHER_KEYS`. No CI step anywhere checks key configuration, so that unit
test is the only coverage this will ever have.

**Rotating the blocklist key is cheap** and does not follow the release
procedure above. It signs data the browser re-fetches every hour, so a
compromised list is corrected by publishing a good one — generate a new key,
add it to `BLOCKLIST_KEYS`, ship, then drop the old entry. There is no
pre-shipped reserve for this channel, so a build must go out either way.

### Transitional, and it needs removing

`BLOCKLIST_KEYS` currently also carries the **release working key**, so installs
predating 2026-07-31 keep receiving blocklist refreshes. While that entry is
there, the blocklist channel still accepts release-key signatures. That is the
price of not stranding existing installs.

Drop it one release after the build carrying `BLOCKLIST_KEYS` has propagated,
and tighten the assertion in `compiled_blocklist_keys_parse` to full
disjointness at the same time.

## Per release: sign a manifest

Write the unsigned payload. Every field is used by the browser and every field
is checked:

```json
{
  "version": "1.0.0",
  "platform": "windows-x86_64",
  "url": "https://patanyx.edgexene.io/dl/patanyx-1.0.0-windows-x86_64.exe",
  "sha256": "<sha256 of that exact file, 64 hex chars>",
  "size": <size of that exact file, in bytes>,
  "published_at": <unix seconds>,
  "notes": "<optional: a short user-facing blurb, shown in the update panel>"
}
```

`platform` must be one of `linux-x86_64`, `linux-aarch64`, `macos-x86_64`,
`macos-aarch64`, `windows-x86_64`. The set is closed: a platform the browser
cannot name is one it cannot safely match.

`notes` is optional and rides INSIDE the signature on purpose: it is shown
beside the install decision, so nobody but the publisher may write it. At
most 500 characters, newlines allowed, no other control or
direction-override characters (the signer and every client refuse them).
Write it for users, not for the changelog: what changed for THEM, in plain
American English. Clients older than the field ignore it; only clients
carrying the display code show it, so the first release that carries notes
will be read by nobody updating FROM an older build -- that is expected,
not a defect. Omit the field rather than writing an empty string.

Get `sha256` and `size` from the file you are actually going to serve, not from
the build output you assume is identical:

```bash
sha256sum patanyx-1.0.0-windows-x86_64.exe
stat -c %s patanyx-1.0.0-windows-x86_64.exe
```

Then sign. A release is one manifest per platform, and `sign-all` does the
whole set in one invocation:

```powershell
.\patanyx-sign.exe sign-all publisher.key windows-x86_64.json linux-x86_64.json
```

It writes `<name>.signed.json` for each and prints ONE combined object keyed by
platform, so a release is a single artifact to move rather than one per
platform.

**ALL OR NOTHING.** Every payload is signed and self-verified in memory before
anything is written. If any one would be rejected, none are written — so a
malformed payload cannot leave you with one platform signed and sent and the
other not, which is a half-published release.

Two payloads declaring the same platform are refused rather than collapsed,
since the combined object is keyed by platform and would otherwise publish one
and silently drop the other.

`sign` still exists for re-cutting a single platform:

```bash
cargo run -p patanyx-update --example patanyx-sign -- \
    sign publisher.key release.json > windows-x86_64.json
```

**The signer verifies its own output before printing it**, using the same
`verify_manifest` the browser runs. A non-https url, a zero size, a truncated
sha256, malformed JSON, a wire-format drift — all of them fail on your machine
with `REFUSING TO EMIT` and nothing is written. The tool cannot produce a
manifest the browser would reject.

One manifest per platform. Sign each one separately.

## Artifact naming: PATANYX, and no version

A decision that has had to be restated more than once, so it is written
here rather than left to whoever names the next file.

**The product is PATANYX.** Every artifact a person receives and reads is named
`PATANYX-...`. Lowercase `patanyx` is the cargo package, the binary inside the
Flatpak, the app id and the host name -- none of which a user reads as a name.

    PATANYX.exe          Windows
    PATANYX              Linux
    PATANYX.flatpak      Linux, Flatpak
    PATANYX-Premium.exe  private build, NEVER published (until the paid tier
                         ships a delivery path; named PATANYX-chat.exe before
                         2026-08-05 -- chat is one premium feature, not the
                         whole of them)
    PATANYX-debug.exe    NEVER published

**No platform or architecture in the filename either.** `x86_64` is a Linux
packaging habit and it does not belong here. Nothing needs it: the extension
already separates `PATANYX.exe` from `PATANYX` in the same directory, and the
platform is carried by the MANIFEST, which is per-platform by construction --
`/v1/windows-x86_64.json` and `/v1/linux-x86_64.json` each point at their own
`url`. The manifest path is compiled into every binary (`manifest_url` builds
`/v1/<platform>.json`) and CANNOT be renamed; the binary it points at is free,
and is named for the product.

**No version in the filename.** Settled in 6b43fe9 and restated since. The
version is a property of the bytes, and the place it is meant to be read is the
Updates panel, which reports what the running binary actually says about
itself. A version in a filename is a second copy of that fact that nothing
keeps true -- and it has already gone wrong twice, once as
`patanyx-v1.0-rc.flatpak` for a version that never shipped, and once as a
`0.9.52` exe served under a name whose manifest still said `0.9.51`.

The published `/dl/` names are inside SIGNED manifest payloads. Changing one is
therefore a release-time decision, not a rename: the URL in the payload and the
file on disk have to move together, and the manifest has to be re-signed. Do
not rename a published artifact outside a release.

## Version numbering: 0.9.51, 0.9.52, ... 0.9.99

Decided 2026-07-29. The PATCH component is the release counter:
`0.9.51`, `0.9.52`, and so on. On reaching `0.9.99` the next release rolls the
MINOR to `0.10.0`.

Stays in the `0.x` line deliberately: the browser is not 1.0, Windows is still
Preview, and the version should not claim otherwise.

A first attempt at this shipped as `9.51.0` -- MAJOR 9 -- and was WITHDRAWN
within minutes. Withdrawing is possible only because nothing had installed it;
see below for why that is luck rather than a procedure.

Two constraints shaped the scheme, both verified rather than assumed:

- **Cargo rejects four-component versions.** `0.9.5.1` does not parse, so
  there is no way to add a level underneath an existing `0.9.5`.
- **Versions can never go backwards.** `decide` returns
  `RefusalReason::NotNewer` for anything not strictly greater, so once a
  version is published every install refuses everything below it. Choosing
  `9.x` permanently ends the `0.x` line -- there is no undoing it.

### Withdrawing a published version is NOT possible once anything installs it

`decide` refuses anything not strictly newer. An install that has taken version
N will refuse every version below N, permanently, with no mechanism to override
it -- the FLOOR constant only pushes the minimum UP. Removing a manifest stops
FURTHER installs taking it, and does nothing for one that already has.

So a wrong version number is recoverable only in the minutes before anyone
updates, and only by pulling the manifest. After that the sole remedy is a
manual reinstall on every affected machine.

Read the number back from the signed payload before publishing. The signer
prints it (`verified: windows-x86_64 0.9.51 ...`) precisely so it can be
checked at the moment it still costs nothing.

## File naming: NO VERSION IN THE FILENAME

Decided 2026-07-29. Published binaries are named:

```
patanyx-windows-x86_64.exe
patanyx-linux-x86_64
```

The version lives in ONE place a user can see: the Updates panel, which reads
it from the running binary's own `CARGO_PKG_VERSION`.

WHY. The updater writes to `current_exe()` -- it replaces the executable at
whatever path it was launched from, and it must, because renaming would break
every shortcut, taskbar pin and file association pointing there. So a file
downloaded as `patanyx-0.9.2-windows-x86_64.exe` still carries that name after
updating to 0.9.4, and the name is now a lie that the user reads before they
read anything else. A version in the filename is guaranteed to become wrong on
the first update; the only question is how confusing it is when it does.

TWO THINGS THIS DEPENDS ON:

1. **`/dl/` must not be immutably cached.** It was `max-age=31536000,
immutable`, justified by "a released binary never changes under the same
   name" -- true while names carried versions and false the instant they stop.
   A cached old binary under a new manifest fails its hash check and the update
   is refused permanently. Now `max-age=300, must-revalidate`, matching `/v1/`
   so a manifest and its binary expire together.
2. **Replace atomically.** Write beside the target and `mv` onto it, so a
   client mid-download gets either the whole old file or the whole new one.
   `install` to a temp name then `mv` -- never write in place.

Archiving an old release means copying it somewhere with a version in the name,
NOT leaving a versioned copy in `/dl/`: an unreferenced binary in the download
directory invites someone installing it by hand later.

## Publish

Serve each manifest at:

```
<UPDATE_BASE_URL>/v1/<platform>.json
```

and the binary at the `url` inside it. Both over TLS.

The manifest URL is identical for every install of a platform: no version, no
token, no query string. That is load-bearing for the privacy story — a check
reveals an IP address and a timestamp, and nothing that singles out a user or
says which version they are running. The version comparison happens locally, in
`decide`. Do not add a version parameter "for analytics"; it would convert an
anonymous fetch into a per-install report.

Recommendation: host manifests and binaries on the same origin the browser
already contacts for anything else, so a check is one DNS lookup, one TLS
session, one disclosure event.

## The beta channel: a second fixed URL, not a version scheme

An install may opt in to `Beta` (`Prefs.update_channel`, `chrome/update.js`'s
Stable/Beta row). This does **not** create a diverged version line, a
pre-release suffix, or anything `decide()` needs to know about specially --
it changes only which URL is fetched:

```
<UPDATE_BASE_URL>/v1/<platform>-beta.json
```

Publish it exactly like the stable manifest, same signing process, same
`sign`/`verify` steps below, same TLS-only rule. The property that matters is
preserved by construction: every Beta subscriber fetches this one fixed
address, indistinguishable from every other Beta subscriber, exactly as every
Stable client is indistinguishable from every other Stable client today. There
is no per-install variant of either URL.

**"Beta" means early access to what will become the next Stable release, not a
permanently-diverged line.** `crates/update/src/version.rs` already refuses to
parse a pre-release suffix on purpose (see its own doc), so do not try to
express "beta-ness" as part of the version number in either manifest --
`0.9.54` on the beta manifest and `0.9.54` on the stable manifest later are the
SAME version, one simply reached that number first.

**Channel switching is one-way: adopt whatever the newly-fetched manifest
says, never merge.** `decide()` (`crates/update/src/lib.rs`) takes whichever
manifest was fetched and compares its version against the current one, exactly
as it always has -- there is no channel-aware branch and none is needed. Two
cases fall out of that with no extra code:

- **Stable -> Beta**, beta ahead: the beta manifest's version is newer, offered
  normally.
- **Beta -> Stable rollback**: if the beta version this install is running is
  AHEAD of what stable currently offers, `decide()` compares the stable
  manifest's version against `current` and returns `Refused(NotNewer)` -- the
  existing, correct behaviour for "the manifest offers something not newer
  than what is already running." Nothing downgrades a running install
  automatically; switching to Stable only changes what the NEXT check asks,
  and that next check answers honestly that there is nothing newer yet.

**Operational dependency, and it is a real one:** whatever process signs and
uploads `<platform>.json` today needs a parallel upload step for
`<platform>-beta.json`, or Beta subscribers get 404s forever the moment
someone opts in. This is outside what the browser's code can enforce.

`PATANYX-Premium.exe` (see "Artifact naming" above) stays never-published,
Beta included -- the public build is the only one either channel serves.

## Confirm what you published

Check the file as served, not the file you think you uploaded:

```bash
curl -sO https://patanyx.edgexene.io/v1/windows-x86_64.json
cargo run -p patanyx-update --example patanyx-sign -- \
    verify windows-x86_64.json <verifying-key-hex>
```

`accepted:` means every install carrying that key will take it. Anything else
means they will refuse it, and it is far better to learn that here.

## The floor

`FLOOR` in `updater.rs` is the version below which updates are refused **even
when validly signed**. It is how a known-bad release is retired permanently:
raise it, and no install will ever accept that version again, whatever manifest
appears.

Bump it deliberately, in a commit of its own, naming the incident it answers.

## Scheduled checks, and what they do not do

Since 2026-07-28 the browser checks roughly every six hours, jittered by ±25%,
in addition to the user's "Check now" button (`schedule.rs`). This section
previously said there were none and called an automatic schedule "the obvious
follow-up"; it landed, because an install nobody clicks never learns a security
fix exists.

**It notifies and nothing else.** A scheduled check verifies the manifest and
decides, then stops. Nothing downloads, nothing installs. The banner's button
opens the Updates panel, where the accept has always lived.

Jitter is not decoration: an exact interval turns "when this machine is awake"
into a fingerprint, even though the request carries no identifier. The first
check waits 90 seconds after startup so a fleet started by one deploy does not
arrive in lockstep.

## Per release: sign a BLOCKLIST manifest

Different domain, different subcommand, and deliberately not a flag on the
first one — see `patanyx-sign`'s usage text for why.

The payload:

```json
{
  "list_version": 1,
  "url": "https://patanyx.edgexene.io/dl/blocklist-1.bin",
  "sha256": "<sha256 of the served list>",
  "size": <bytes>,
  "entries": <host count>,
  "published_at": <unix seconds>
}
```

`list_version` is **monotonic and independent of the browser version**. It is
what refuses a replayed older list, so it only ever goes up, and it goes up
whenever the list content changes. `entries` is cross-checked against what
`HostSet` actually parses; a list declaring far more than it parses to is
refused as a probable format change rather than accepted as a smaller list.

The served file is **compiled hashes, not text**: sorted little-endian 128-bit
SHA-256 prefixes, 16 bytes per host. Produce it from the binary itself, never
by re-deriving it:

```bash
patanyx --emit-blocklist blocklist-N.bin
```

That writes the exact bytes the browser matches against, so the manifest's
hash cannot end up covering something installs do not use. `entries` is the
host count the command prints.

Why hashed: ~400k domain names as plaintext inside an executable is
indistinguishable, to a signature scanner, from a banking trojan carrying the
banks it targets. On 2026-07-29 ClamAV quarantined every Windows build of this
browser over exactly that. The plaintext `crates/app/src/blocklist.txt` stays
in the repository so additions remain reviewable in a diff; only the shipped
artifact is hashed.

Sign it with the **blocklist** key, never `publisher.key`:

```bash
patanyx-sign sign-blocklist /path/to/blocklist.key blocklist.json
```

Publish the result at `<UPDATE_BASE_URL>/v1/blocklist.json` and the list at the
`url` inside it. Confirm with:

```powershell
.\patanyx-sign.exe verify-blocklist blocklist-signed.json <verifying-key-hex>
```

### Pre-flight the payload before asking for a signature

Sign it with a THROWAWAY key first and verify the result. The signer runs the
browser's own verifier over its output, so a malformed payload, an implausible
size or a bad URL fails on a machine that is not holding the real key. This
caught a real fault the first time it was used: the signer had been built
before `MAX_BLOCKLIST_BYTES` was raised, so it still carried the old 8 MiB cap
and refused a 10.9 MB list that the current browser accepts. Destroy the
throwaway key afterwards.

### Size

`MAX_BLOCKLIST_BYTES` is 24 MiB, raised from 8 MiB on 2026-07-28 because the
first real list was 10.9 MB. An install running an older build refuses a list
above ITS cap and keeps the one it has — the correct failure, and the reason
publishing a larger list does not harm installs that predate the change.
