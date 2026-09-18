# Bergamot translation engine (Mozilla build)

The WebAssembly engine for on-device page translation, and its emscripten glue.
Both ship inside PATANYX; the language models do NOT — those download on demand
(`docs/page-translation-provenance.md`).

## Provenance

Taken from Mozilla rather than from `browsermt/bergamot-translator`, because
Mozilla's is the maintained build: `mozilla/translations` was pushed within days
of this being vendored, while `browsermt` has been dormant since 2024-05-12.
The full comparison and the decision are in
`docs/page-translation-provenance.md`.

| | |
| --- | --- |
| Release | v0.6.0 |
| Revision | `1de4a085d3a7afb625c51a60aabb5ad298e4059f` (mozilla/translations, 2025-06-04) |
| Licence | MPL-2.0, full text in `LICENSE` beside this file |

**`bergamot-translator.wasm`** — from Mozilla Remote Settings, collection
`main/translations-wasm-v2`. The record publishes both hashes and the
decompressed one is what is stored here:

```
attachment (zstd)  327fcfc7b7e9d95f6fa0844ebf899cfc05469872ef02d3aef5783182839a6255   1,211,955 B
decompressed       f38ef807636a7c994afedaab7ff8ffe0d590d21897f05139f747b80fd7bbe926   4,960,506 B
```

**`bergamot-translator.js`** — the glue is NOT in Remote Settings. Upstream
vendors it, and so do we, from
`toolkit/components/translations/bergamot-translator/bergamot-translator.js`.
Its `moz.yaml` names the same release and revision as the wasm record, so the
two are a matched pair rather than two things that happen to be near each
other.

## Updating

Both files move together, always. Take the wasm from the Remote Settings record
and the glue from the mozilla-central path whose `moz.yaml` names the SAME
revision — a wasm and a glue from different revisions will fail in ways that
look like data corruption.

Then update the hashes in `shipped-artifacts.json`; the artifact gate refuses a
file whose bytes no longer match its row, and refuses a file with no row at
all.

## API note, learned the hard way

v0.6.0's `TranslationModel` constructor takes SEVEN arguments —
`(sourceLanguage, targetLanguage, config, model, shortlist, vocabs,
qualityEstimator)`. The 0.4.5 build took five. The two extra register the
model's languages, which is what enables `translateViaPivoting` (e.g. fr→es
routed through en). Neither a symbol scan nor the upstream `.d.ts` revealed
this; only running it did.
