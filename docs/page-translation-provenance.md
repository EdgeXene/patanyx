# Page translation: provenance and licences

Written 2026-08-30, provenance completed 2026-08-31. Covers the artifacts
phase 0 measured and that the feature would ship.

The machine-readable half of this now exists: `shipped-artifacts.json` plus
`scripts/artifact-manifest-gate.py`, which verifies hashes, refuses an
undeclared artifact and refuses a row with no licence. The engine's rows are
still in that file's `_pending` block, because it is not vendored into this
repository yet — a row describing a file the repo does not contain would be a
worse lie than no row.

## Licences: established, not assumed

Every row below was read from the project's own licence file (via
`raw.githubusercontent.com` or the GitHub API) rather than recalled. Components
were identified from strings present in the shipped
`bergamot-translator-worker.wasm`, so the list reflects the artifact rather than
an upstream dependency manifest.

| Component           | Licence                                     | Copyright line                                                                                          |
| ------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| bergamot-translator | MPL-2.0                                     | Mozilla Public License 2.0                                                                              |
| marian (marian-dev) | MIT                                         | Marcin Junczys-Dowmunt, the University of Edinburgh, Adam Mickiewicz University                         |
| intgemm             | MIT                                         | University of Edinburgh, Nikolay Bogoychev, Mateusz Chudyk, Kenneth Heafield, and Microsoft Corporation |
| sentencepiece       | Apache-2.0                                  | Google                                                                                                  |
| protobuf            | BSD-3-Clause                                | Copyright 2008 Google Inc.                                                                              |
| yaml-cpp            | MIT                                         |                                                                                                         |
| pathie-cpp          | BSD-2-Clause                                |                                                                                                         |
| spdlog              | MIT                                         | Gabi Melman and spdlog contributors                                                                     |
| PCRE2               | BSD-3-Clause WITH PCRE2-exception           | JIT component separately 2-clause BSD                                                                   |
| ssplit-cpp          | Apache-2.0 (code) — see the LGPL note below | Copyright 2019 University of Edinburgh                                                                  |

A `sqlite` string also appears twice in the artifact. marian uses SQLiteCpp for
its translation cache, which is very likely compiled out of the WASM build; two
occurrences is consistent with a leftover format string rather than a linked
library. Treated as unresolved rather than claimed either way.

## The LGPL question, and why it does not bite

`ssplit-cpp` is dual-licensed. Its C++ and build files are Apache-2.0, but the
files in `nonbreaking_prefixes` were copied from mosesdecoder and are
**LGPL-2.1**. Upstream's own note says those files are "read by the compiled
library and not compiled into the library" — an assumption worth checking
rather than trusting, because a WASM build has no filesystem to read them from
and embedding would be the obvious workaround.

Checked against the artifact:

- the phrase `nonbreaking prefixes` appears exactly ONCE, consistent with a
  message or config key;
- the characteristic Moses English prefix list (`Adj`, `Adm`, `Adv`, `Bros`,
  `Capt`, `Cmdr`, `Msgr`, `Sfc`, `Supt`, `Surg`, …) produces **zero** exact
  matches. An embedded plain-text prefix list would show dozens.

That was strong evidence, not proof, and it is left here because it is how the
question was first approached. **It has since been settled positively from the
build recipe** — see "The LGPL question is now closed by the build recipe"
below. Read that section, not this one, for the answer.

## What is still genuinely open

**The model weights.** `mozilla/firefox-translations-models` carries MPL-2.0 as
its repository licence and says nothing specific about the trained weights, and
its README makes no redistribution statement about them. Whether an MPL-2.0
repository licence reaches model weights is a legal-interpretation question,
not a lookup, and it is a project decision, not a build script's.

DECISION 2026-08-30: attribute the weights AS IF MPL-2.0 reaches them,
carrying the notice and a pointer upstream with the exact record versions.
Correct if MPL reaches weights, harmless if not, and consistent with what this
product already does for the Baidu PP-OCR weights, which `NOTICE` describes as
"Licensed under the Apache License 2.0, code and weights."

The one thing still genuinely open is now the ENGINE STALENESS decision below,
not the licence.

## Provenance: ESTABLISHED 2026-08-31

Both engine artifacts were identified by matching their SHA-256 against the
published release assets, so this is not an inference from filenames.

| Artifact | Identity |
| --- | --- |
| `bergamot-translator-worker.wasm` | byte-identical to the `latest` release asset of `browsermt/bergamot-translator`. SHA-256 `65cf5be7…d145386f`, 5,243,384 bytes |
| `bergamot-translator-worker.js` | byte-identical to the same release's glue. SHA-256 `2cb354e7…41811a5c` |
| Release | "Latest Build", tag `latest`, published **2023-09-20T08:15:28Z**, target `main` |
| Upstream commit | **321be8ae0486de3af67307c4cb2e005994593597**, dated 2023-09-20T07:10:18Z, "Bump 3rd_party/marian-dev from `780df27` to `11c6ae7` (#466)" |

The commit is not guessed either: the same release's Python wheels are named
`bergamot-0.4.5+321be8a-…`, and that short hash resolves upstream to the commit
above.

**The tag is a MOVING target and must never be the pin.** `latest` is a rolling
release name; upstream can republish it and the bytes change underneath anyone
citing it. The SHA-256 is the pin, and the commit is the identity.

Model files: `model.enes.intgemm.alphas.bin` v2.1, `lex.50.50.enes.s2t.bin`
v2.1 and `vocab.enes.spm` v2.1, all `en->es`, all hash-matched against
Mozilla's Remote Settings collection, which carries `name`, `version`,
`fromLang`, `toLang`, `hash` and `size` per record. The opaque-UUID problem is
therefore closed: the UUIDs are addresses, and the records give identity. Note
the same vocab bytes are published under three records (`enes` v2.1, `enes`
v2.0, `esen` v2.0), so an `es->en` pack would reuse the identical file.

## The LGPL question is now closed by the build recipe, not by strings

The earlier answer rested on `strings` finding no Moses prefix list, and said
so — strong evidence, not proof, because a compressed or re-encoded list would
not show. The build configuration at commit `321be8a` settles it positively:

- `CMakeLists.txt` WASM link flags contain **no** `--embed-file` and **no**
  `--preload-file`, anywhere;
- and they contain `-sFILESYSTEM=0`, commented upstream as "No need for
  filesystem code in the generated Javascript".

A build with the filesystem compiled out and no embed directive cannot be
carrying `ssplit-cpp`'s LGPL-2.1 `nonbreaking_prefixes` data. **The LGPL does
not reach this product through that path.** Re-check if the pair set grows or
the engine is rebuilt from a different configuration.

## THE ENGINE IS STALE, AND THAT IS A RELEASE DECISION

Established while pinning the provenance, and it matters more than the pin:

- the binary we measured was built **2023-09-20**;
- upstream `main` is **7 commits ahead** of it and was last pushed
  **2024-05-12**;
- the repository is not archived, but nothing has landed in roughly two years.

So shipping this in 1.0.0 means shipping a prebuilt binary that is about three
years old, from an upstream that is effectively dormant, into the one component
that parses **attacker-controlled text**. WASM's sandbox is a real mitigation
for the memory-safety class that a C++ NMT stack would otherwise carry, and it
is the reason this is a decision rather than a blocker — but it is a decision,
and it is a project decision rather than a build script's.

The options, none of which is free:

1. **Ship the pinned 2023 artifact.** Cheapest, fully provenance-pinned today,
   and no upstream security response should be expected.
2. **Build from `main` (7 commits newer) ourselves.** Drags emscripten into a
   build pipeline; the plan explicitly bans a native toolchain from the product
   build, so this would be a separate, out-of-tree pipeline.
3. **Take Mozilla's build instead. INVESTIGATED, AND IT IS THE RECOMMENDATION.**
   See the section below.

## Recommended: take the engine from Mozilla's Remote Settings

Mozilla ships the engine through the SAME channel we already fetch models
from. `main/translations-wasm-v2` holds one record, and it carries the
metadata the GitHub release never had:

```
name              bergamot-translator
license           MPL-2.0                 <- an explicit licence field
release           v0.6.0
revision          1de4a085d3a7afb625c51a60aabb5ad298e4059f
fx_release        144.0a1
version           4.0
hash              327fcfc7...839a6255     1,211,955 bytes (zstd)
decompressedHash  f38ef807...d7bbe926     4,960,506 bytes
```

That revision resolves to **mozilla/translations**, commit dated
**2025-06-04** ("Update BERGAMOT_VERSION (#1140)"). It is not in
`browsermt/bergamot-translator`, `mozilla/bergamot-translator` or
`mozilla/firefox-translations` — checked all three.

The maintenance comparison is the argument:

| | last push | activity |
| --- | --- | --- |
| `mozilla/translations` | **2026-08-28** | 10 commits in the last 90 days, MPL-2.0, not archived |
| `browsermt/bergamot-translator` | 2024-05-12 | dormant |

So Mozilla's artifact is newer by roughly 21 months, comes from a repository
touched three days ago, states its own licence and its own upstream revision
in the record, is pinned by hash in BOTH compressed and decompressed form, is
tied to a specific upstream browser release, and is **four times smaller** to ship
(1.2 MB zstd against 5.2 MB raw). It also collapses two supply chains into
one: the same host, the same signing story and the same trust anchor as the
models, instead of GitHub releases for the engine and Remote Settings for the
models.

### DECISION 2026-08-31: take Mozilla's build (option B)

Validated end to end before anything is switched. Everything below was run, not
reasoned about.

**The glue is not a gap after all.** Upstream VENDORS it, checked in at
`toolkit/components/translations/bergamot-translator/` in mozilla-central,
alongside its own `LICENSE`. Its `moz.yaml` states:

```
origin    https://github.com/mozilla/translations.git
release   v0.6.0
revision  1de4a085d3a7afb625c51a60aabb5ad298e4059f
license   MPL-2.0
```

That is the SAME revision the Remote Settings wasm record names. The binary and
the glue are provably a matched pair from one revision, which is better than
what we have today for the 0.4.5 artifacts, where the glue's correspondence to
the wasm rests on them having been in the same GitHub release.

**One real API break, found by running it rather than by reading.** Symbol
presence matched and the `.d.ts` looked compatible, so I wrote that the page
"should not need rewriting". That was too strong. The engine rejected the model
with:

```
Tried to invoke ctor of TranslationModel with invalid number of parameters (5)
- expected (7) parameters instead!
```

v0.6.0 prepends `sourceLanguage` and `targetLanguage`
(`inference/wasm/bindings/service_bindings.cpp:62-70`), which then calls
`registerSourceLanguage` / `registerTargetLanguage` on the model. Those two
arguments are what make `translateViaPivoting` possible, so the break is the
pivoting feature, not churn. A two-argument fix, not a rewrite — but a real
break, and only running it found it.

**The integration also differs.** Mozilla's glue is a function,
`loadBergamot(Module)`, not a self-initialising emscripten script, and upstream
hands it `wasmBinary` as an ArrayBuffer, so THE ENGINE NEVER FETCHES ITS OWN
WASM. The caller fetches it. Config shape copied from
`translations-engine.worker.js:634-659`, including its `INITIAL_MEMORY` of
234,291,200 and the microtask wait before the module is touched.

**Measured, Linux/WebKitGTK, against the same models and the same harness:**

| | 0.4.5 (`321be8a`) | v0.6.0 (`1de4a085`) |
| --- | --- | --- |
| Engine + model ready | 1,500 ms | 1,500 ms |
| Payload ceiling | none below 16 MiB | none below 16 MiB |
| 40 sentences | 1,263 / 1,372 ms | **1,239 ms** |
| Output | real Spanish | real Spanish |

**CSP: the conclusion transfers unchanged.** Same bisection, same answer —
`connect-src 'self'` plus `'wasm-unsafe-eval'`, exactly two directives past the
chrome policy. One nuance worth recording: under the chrome policy v0.6.0 fails
at OUR fetch of the wasm ("wasm fetch: Load failed") rather than at the
engine's own internal fetch, because the caller now supplies the bytes. Same
directive, different actor. And the compile failure still raises an engine
error with NO violation event on WebKitGTK, exactly as with 0.4.5.

**Still owed for the switch:** the Windows re-measurement, and a decision on
how the glue reaches us — vendored from mozilla-central as upstream does, or
fetched. The glue is not in Remote Settings, so it cannot ride the model
channel.

## Before ship## Before ship

1. DONE for the engine and the models — see above. Still missing: the
   emscripten version the released binary was built with, which the release
   does not record.
2. Wire the table above into `scripts/attribution-gate.sh` so a changed
   artifact fails the build rather than silently shipping unattributed.
3. Delete the `404: Not Found` `registry.json`.
4. Settle the licence question for the model weights.
