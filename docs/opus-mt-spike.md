# OPUS-MT in the shipped WASM engine: the la->en spike

2026-08-31, on the build server (xvfb, debug build, engine probe
`PATANYX_TRANSLATE_PROBE=2` with the env pair/text hooks). One question
gated the whole tier-2 plan: **does the shipped Bergamot WASM engine run a
stock OPUS-MT transformer-base model at all?** Every model the engine had
ever run was a distilled tiny/base student with an SSRU decoder; a full
6-layer self-attention decoder in the WASM build was unproven.

## Verdict: GO, with a settled recipe and honest limits

The stock `ine-eng` opus2m-2020-08-01 release (transformer-base, the best
Latin->English in the OPUS-MT catalogue, CC-BY 4.0 LICENSE **in the release
zip itself**) loads and translates real Latin in the engine after three
pieces of conversion work, all now in `scripts/opus-mt/`:

1. **Vocabulary alignment** (`build-aligned-vocab.py`). The release carries
   TWO SentencePiece segmenters and ONE joint 61,013-entry vocab.yml; the
   engine tokenizes internally from a single .spm whose piece ids ARE the
   model's ids. Measured: only 5/32000 of source.spm's ids coincide with the
   yml's -- the naive path is word salad. The tool rebuilds a single .spm
   with the pieces in yml-id order (source scores kept, so segmentation is
   REPRODUCED -- validated 0/6 drift on Latin, English, German, Vulgate),
   target-only and rare-char pieces present but scored below reach.
2. **Dimension padding** (`pad-marian-vocab.py`). intgemm aborts on the tied
   output projection: "Rows of matrix: param must be multiple of 8"
   (61013 % 8 = 5). Padded to 61,056 (x64 clears every kernel width): zero
   embedding rows, -1e9 logit bias so a filler id can never win, dim-vocabs
   rewritten, filler pieces appended to the vocab (`--pad-to=61056`).
3. **Alphas calibration** (required, not optional). Plain intgemm8 produced
   repetition loops and dropped named entities; the float32 original decoded
   the same sentences cleanly natively, isolating quantization as the cause.
   Recipe that works: decode a real-text corpus (42 Vicipaedia sentences)
   with `marian-decoder --dump-quantmult` -- **single-threaded** (parallel
   threads interleave the dump mid-line) -- filter to the `Name:` lines
   (marian's own log lines break `extract_stats.py`), run
   `scripts/alphas/extract_stats.py`, reconvert, and run the engine with
   `gemm-precision: int8shiftAlphaAll`.

## Measurements (all this hardware; a laptop will be slower)

| configuration                      | 5 real Latin sentences | quality                                                                                             |
| ---------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------- |
| WASM int8, beam 1, no alphas       | 2,610 ms               | gist-only; loops; "Gallia" dropped                                                                  |
| WASM int8, beam 4, no alphas       | --                     | WORSE (quantization noise amplified)                                                                |
| WASM int8+alphas, beam 1           | ~2.6 s                 | readable: "Gallia is divided in three parts, with one of the Belgian, and Aqui..."                  |
| WASM int8+alphas, beam 4           | 12,064 ms              | badly degraded again                                                                                |
| native float32, beam 6 (reference) | 4.7 s CPU              | clean: "Gallia is all divided into three parts... the third of which are called Celtae, our Galli." |

- Engine boot ~40 ms; pack load ~520 ms for the 72.5 MiB int8 model plus
  1.4 MB vocab, with a **null shortlist** (the engine accepts it; the
  spike bent the glue locally to pass null for a zero-byte lex.bin --
  reverted, lands properly with container v2).
- **~520 ms/sentence at beam 1 -- about 11x the Mozilla tiny models**,
  matching the research projection. Fine for selected-text and paragraph
  translation; a full page needs the progress UI doing real work.
- **The production recipe is alphas + beam 1.** Wider beams degrade in the
  WASM int8 path even calibrated -- measured twice, treat as a property of
  the engine, revisit only with evidence.
- Residual gap to float32 remains (int8 in WASM); the honest label for
  tier-2 packs is slower/experimental, per the marketing rules.

## What the spike bent and put back

`spike-product-edits.diff` (session scratchpad): null-shortlist handling and
INITIAL_MEMORY 1.5 GiB in translator.js, gemm-precision switch, and a
debug-only `la-en` constant in serve_translator_pack's allowlist. All
REVERTED the same night; the tree's probes and selftest re-verified green
after the revert. Those changes land for real in container v2 with the
audit row the plan assigns them, not as spike residue.

## What this changes in the tier-2 plan

- Old-generation OPUS-MT joint-vocab models need NO split-vocab container:
  the aligned rebuild collapses both segmenters into one .spm. The
  vocab-XOR-srcvocab+trgvocab container change is still owed, but its
  driver is the four excluded Mozilla ja/zh pairs (and future genuinely
  split models), not this model class.
- en->la stays deferred (transformer-big only; unproven in WASM and an
  order of magnitude past this speed class).
- The alphas step becomes a required stage of the H4 converter, exactly as
  run here.
