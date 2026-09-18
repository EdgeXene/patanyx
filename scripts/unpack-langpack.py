#!/usr/bin/env python3
"""Unpack a PXPACK1 container back into model.bin, lex.bin, vocab.spm.

The inverse of the packing step in build-langpack.sh, for probes and the
self-test, which want the three files on disk under a PATANYX_PACK_ROOT.
usage: unpack-langpack.py <pack.pxpack> <out-dir>
"""
import pathlib, sys

def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr); return 2
    data = pathlib.Path(sys.argv[1]).read_bytes()
    if data[:8] != b"PXPACK1\n":
        print("not a PXPACK1 container", file=sys.stderr); return 2
    pos, lens = 8, []
    for _ in range(3):
        nl = data.index(b"\n", pos); lens.append(int(data[pos:nl])); pos = nl + 1
    out = pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
    for name, ln in zip(("model.bin", "lex.bin", "vocab.spm"), lens):
        (out / name).write_bytes(data[pos:pos + ln]); pos += ln
    if pos != len(data):
        print(f"trailing bytes: {len(data) - pos}", file=sys.stderr); return 1
    print(f"unpacked {sys.argv[1]} -> {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
