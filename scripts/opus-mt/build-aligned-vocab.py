#!/usr/bin/env python3
"""Build a SentencePiece model whose piece ids equal Marian's vocab.yml ids.

The OPUS-MT release was trained on text tokenized by source.spm/target.spm and
mapped through a JOINT vocab.yml (61,013 entries, ids 0..61012). Bergamot
tokenizes internally from a single .spm whose piece ids ARE the model ids, so
the stock .spm files produce wrong ids (measured: 5/32000 coincidental
matches). This rebuilds the segmenter with the pieces in vocab.yml id order:

  - id 0 </s> (CONTROL), id 1 <unk> (UNKNOWN), matching the yml and Marian.
  - Source pieces keep source.spm's scores -> segmentation of source text is
    reproduced (validated below, not assumed).
  - Target-only and yml-only pieces get strongly negative scores: decodable
    (id -> piece is all decode needs) but never preferred while encoding.
"""
import sys, yaml
import sentencepiece as spm
from sentencepiece import sentencepiece_model_pb2 as sp_pb2

BASE = sys.argv[1] if len(sys.argv) > 1 else "ine-eng/"
OUT = sys.argv[2] if len(sys.argv) > 2 else "vocab.aligned.spm"
# --pad-to N appends <madeupwordK> filler pieces so the vocab size matches a
# model padded by pad-marian-vocab.py (intgemm needs aligned dimensions; the
# fillers score far below everything and their model bias is -1e9, so they
# are never encoded and never predicted).
PAD_TO = None
for _a in sys.argv[1:]:
    if _a.startswith("--pad-to="):
        PAD_TO = int(_a.split("=", 1)[1])

def parse_yml(path):
    pairs = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line:
            continue
        k, v = line.rsplit(": ", 1)
        if k.startswith('"') and k.endswith('"') and len(k) >= 2:
            k = yaml.safe_load(k)  # unescape the quoted form only
        pairs.append((k, int(v)))
    return pairs

# The release names its vocab after the training run ("opus2m.", "opus.",
# "opus+bt."), so it is FOUND rather than assumed: hardcoding one release's
# filename is what limited this tool to the model it was written for.
import glob as _glob
_ymls = sorted(_glob.glob(BASE + "*vocab.yml"))
if len(_ymls) != 1:
    raise SystemExit(f"expected exactly one *vocab.yml in {BASE}, found {_ymls}")
pairs = parse_yml(_ymls[0])
ids = sorted(v for _, v in pairs)
assert ids == list(range(len(pairs))), "vocab ids must be contiguous"
by_id = {v: k for k, v in pairs}
assert len(by_id) == len(pairs), "duplicate ids"

src_proto = sp_pb2.ModelProto(); src_proto.ParseFromString(open(BASE + "source.spm", "rb").read())
trg_proto = sp_pb2.ModelProto(); trg_proto.ParseFromString(open(BASE + "target.spm", "rb").read())
src_score = {p.piece: p.score for p in src_proto.pieces}
trg_score = {p.piece: p.score for p in trg_proto.pieces}
floor = min(src_score.values())

new = sp_pb2.ModelProto(); new.CopyFrom(src_proto)
del new.pieces[:]
n_src = n_trg = n_extra = 0
for i in range(len(by_id)):
    piece = by_id[i]
    sp = new.pieces.add(); sp.piece = piece
    if piece == "</s>":
        sp.type = sp_pb2.ModelProto.SentencePiece.CONTROL; sp.score = 0.0
    elif piece == "<unk>":
        sp.type = sp_pb2.ModelProto.SentencePiece.UNKNOWN; sp.score = 0.0
    elif piece in src_score:
        sp.type = sp_pb2.ModelProto.SentencePiece.NORMAL; sp.score = src_score[piece]; n_src += 1
    elif piece in trg_score:
        # A FLAT PENALTY IS NOT "OUT OF REACH", and this was measured rather
        # than reasoned: SentencePiece picks the segmentation with the best
        # TOTAL score, so one target-only piece at floor-25 beats six source
        # pieces summing to far less. On ha-en the rebuilt vocab preferred
        # `_Catholic` (a target-side English word) where source.spm splits
        # `_C a t ho li c` -- so an English proper noun inside Hausa text
        # reached the encoder as a token the encoder was never trained on.
        # Latin-alphabet pages are full of English proper nouns, so this was
        # a real quality leak on every pack, not a Hausa quirk; the other
        # languages passed only because their sample text happened not to
        # contain one.
        #
        # The penalty is therefore made unreachable BY LENGTH: a piece of n
        # characters can never beat the n single characters it would decompose
        # into. Scores only affect ENCODING; decoding is id -> piece and is
        # untouched, so these pieces remain fully decodable as output.
        sp.type = sp_pb2.ModelProto.SentencePiece.NORMAL
        sp.score = floor - 25.0 - 1000.0 * len(piece); n_trg += 1
    else:
        sp.type = sp_pb2.ModelProto.SentencePiece.NORMAL
        sp.score = floor - 50.0 - 1000.0 * len(piece); n_extra += 1
if PAD_TO is not None:
    for i in range(PAD_TO - len(new.pieces)):
        sp = new.pieces.add(); sp.piece = f"<madeupword{i}>"
        sp.score = floor - 100.0
        sp.type = sp_pb2.ModelProto.SentencePiece.NORMAL
new.trainer_spec.vocab_size = len(new.pieces)
new.trainer_spec.unk_piece = "<unk>"
new.trainer_spec.eos_piece = "</s>"
new.trainer_spec.bos_piece = "<s>"      # absent on purpose -> bos_id -1
new.trainer_spec.pad_piece = "<pad>"    # absent on purpose
new.trainer_spec.unk_id = 1
open(OUT, "wb").write(new.SerializeToString())
# len(new.pieces), not len(by_id): the padding above is what makes the vocab
# a multiple of the intgemm tile width, and reporting the PRE-padding count
# made a correctly padded file look unpadded.
print(f"wrote {OUT}: {len(new.pieces)} pieces "
      f"({len(by_id)} from the vocab + {len(new.pieces) - len(by_id)} filler; "
      f"src-scored {n_src}, trg-only {n_trg}, extra {n_extra})")

# ---- validation, not assumption -------------------------------------------
proc = spm.SentencePieceProcessor(model_file=OUT)
src = spm.SentencePieceProcessor(model_file=BASE + "source.spm")
assert proc.eos_id() == 0, f"eos_id {proc.eos_id()}"
assert proc.unk_id() == 1, f"unk_id {proc.unk_id()}"
yml = {k: v for k, v in pairs}
# WHAT THIS CHECK IS FOR: the rebuilt segmenter must reproduce source.spm's
# segmentation, because the model's ids were trained against it. So the text
# it is checked on has to be text the model will actually SEE -- i.e. the
# SOURCE language.
#
# It used to be these six sentences, always: four Latin, one English, one
# German. That was right for the ine-eng spike this tool was written for and
# wrong for every model since. On ht-en (Haitian->English) it failed on the
# ENGLISH sentence -- target-side text a Haitian->English model is never fed
# -- while checking Haitian not at all. A validation set that tests the wrong
# language is worse than none: it fails correct work and passes unexamined
# work.
#
# --validate=FILE takes real source-language text (the calibration corpus is
# exactly this). The Latin set remains the fallback so the tool still runs
# bare, and the run PRINTS which set it used.
_VALIDATE = None
for _a in sys.argv[1:]:
    if _a.startswith("--validate="):
        _VALIDATE = _a.split("=", 1)[1]
if _VALIDATE:
    tests = [l.strip() for l in open(_VALIDATE, encoding="utf-8") if l.strip()][:40]
    if not tests:
        raise SystemExit(f"--validate={_VALIDATE} is empty")
    print(f"validating on {len(tests)} lines of source text from {_VALIDATE}")
else:
    print("validating on the BUILT-IN Latin/English/German set "
          "(pass --validate=<source-text> for a model whose source is neither)")
    tests = [
        "Gallia est omnis divisa in partes tres.",
        "Senatus Populusque Romanus imperium tenet.",
        "Quo usque tandem abutere, Catilina, patientia nostra?",
        "The quick brown fox jumps over the lazy dog.",
        "Der schnelle braune Fuchs springt.",
        "In principio erat Verbum, et Verbum erat apud Deum.",
    ]
seg_mismatch = id_mismatch = 0
for t in tests:
    p_new = proc.encode(t, out_type=str)
    p_src = src.encode(t, out_type=str)
    if p_new != p_src:
        seg_mismatch += 1
        print(f"SEGMENTATION DRIFT: {t!r}\n  new {p_new}\n  src {p_src}")
    want = [yml.get(p, 1) for p in p_new]
    got = proc.encode(t, out_type=int)
    if got != want:
        id_mismatch += 1
        print(f"ID DRIFT: {t!r}\n  got  {got}\n  want {want}")
    back = proc.decode(got)
    if back.replace(" ", "") != t.replace(" ", ""):
        print(f"ROUND-TRIP loss: {t!r} -> {back!r}")
print(f"validation: segmentation drift {seg_mismatch}/{len(tests)}, id drift {id_mismatch}/{len(tests)}")
sys.exit(1 if (seg_mismatch or id_mismatch) else 0)
