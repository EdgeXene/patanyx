#!/usr/bin/env python3
"""Pad a Marian npz model's vocabulary dimension to an intgemm-legal size.

WHY. The int8 GEMM the browser engine runs (intgemm) requires matrix
dimensions aligned to its kernel widths; a stock OPUS-MT vocabulary of 61,013
aborts at runtime with "Rows of matrix: param must be multiple of 8" when the
tied output projection is prepared. Measured, not theorized: the la->en spike
died there and ran after this padding. Padding to a multiple of 64 clears
every intgemm alignment requirement at the cost of a few dozen dead rows.

WHAT IT TOUCHES. Exactly the arrays that carry the vocab dimension in an
OPUS-MT transformer with tied-embeddings-all: `Wemb` gains zero rows (a dead
embedding) and `decoder_ff_logit_out_b` gains -1e9 bias columns (a dead id
can never win a beam), and dim-vocabs inside special:model.yml is rewritten.
Anything else with the vocab dimension is refused loudly rather than guessed
about. The vocabulary .spm must be padded to the same size with filler pieces
(build-aligned-vocab.py --pad-to).

usage: pad-marian-vocab.py <in.npz> <out.npz> [--pad-to N]
       (default: next multiple of 64)
"""
import sys
import numpy as np


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    pad_to = None
    for a in sys.argv[1:]:
        if a.startswith("--pad-to"):
            pad_to = int(a.split("=", 1)[1])
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = args
    z = dict(np.load(src))
    n = z["Wemb"].shape[0]
    target = pad_to or ((n + 63) // 64) * 64
    add = target - n
    if add < 0:
        raise SystemExit(f"model vocab {n} already exceeds --pad-to {target}")

    # Refuse silently-unhandled vocab-sized arrays instead of corrupting them.
    handled = {"Wemb", "decoder_ff_logit_out_b"}
    for k, v in z.items():
        if k in handled or not hasattr(v, "shape"):
            continue
        if n in v.shape:
            raise SystemExit(
                f"{k} has shape {v.shape} carrying the vocab dimension {n}; "
                "this model layout is not the tied-embeddings-all shape this "
                "tool understands -- extend it deliberately")

    z["Wemb"] = np.vstack(
        [z["Wemb"], np.zeros((add, z["Wemb"].shape[1]), dtype=z["Wemb"].dtype)])
    b = z["decoder_ff_logit_out_b"]
    z["decoder_ff_logit_out_b"] = np.hstack(
        [b, np.full((1, add), -1e9, dtype=b.dtype)])
    yml = bytes(z["special:model.yml"]).decode()
    replaced = yml.replace(f"  - {n}\n  - {n}", f"  - {target}\n  - {target}")
    if replaced == yml:
        raise SystemExit("dim-vocabs not found in special:model.yml in the "
                         "expected two-line form; refusing to guess")
    z["special:model.yml"] = np.frombuffer(replaced.encode() + b"\x00", dtype=np.int8)
    np.savez(dst, **z)
    print(f"padded {src}: vocab {n} -> {target} (+{add}) -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
