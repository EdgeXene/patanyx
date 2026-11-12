#!/usr/bin/env python3
"""Seed corpora for the app_* fuzz targets, written into fuzz/corpus/<target>/.

corpus/ is gitignored (libFuzzer's working state), so the seeds are generated
rather than committed. They matter most for app_bounded_picture: its
downscale path needs a VALID PNG over 8,000,000 pixels or 8,192 pixels on a
side, and a fuzzer does not invent a well-formed deflate stream that large.

    python3 fuzz/seeds.py            # from the repository root
"""
import base64
import os
import struct
import sys
import urllib.parse
import zlib

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


def png(width, height, color_type, channels, fill=0x80):
    """A minimal non-interlaced 8-bit PNG of one flat colour."""
    def chunk(kind, body):
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF))
    row = b"\x00" + bytes([fill]) * (width * channels)
    raw = zlib.compressobj(9)
    data = b"".join(raw.compress(row) for _ in range(height)) + raw.flush()
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", data)
            + chunk(b"IEND", b""))


def write(target, name, data):
    d = os.path.join(ROOT, target)
    os.makedirs(d, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def main():
    # Pictures: kept as they are, and streamed down (pixel bound, side bound).
    write("app_bounded_picture", "rgba-1x1.png", png(1, 1, 6, 4))
    write("app_bounded_picture", "rgb-3x2.png", png(3, 2, 2, 3))
    write("app_bounded_picture", "gray-16x16.png", png(16, 16, 0, 1))
    write("app_bounded_picture", "graya-5x7.png", png(5, 7, 4, 2))
    write("app_bounded_picture", "rgb-3000x3000-over-pixels.png", png(3000, 3000, 2, 3))
    write("app_bounded_picture", "gray-9000x2-over-side.png", png(9000, 2, 0, 1))

    # Links: every wrapper shape in ipc.rs REDIRECT_WRAPPERS, plus tracking
    # parameters, fragments and encodings.
    dest = "https://example.org/a/b?keep=1&utm_source=x#frag"
    enc = urllib.parse.quote(dest, safe="")
    b64 = base64.urlsafe_b64encode(dest.encode()).decode().rstrip("=")
    links = [
        f"https://eur01.safelinks.protection.outlook.com/?url={enc}&data=1",
        f"https://www.google.com/url?q={enc}&sa=D",
        f"https://www.bing.com/ck/a?u=a1{b64}&ntb=1",
        f"https://duckduckgo.com/l/?uddg={enc}",
        f"https://l.facebook.com/l.php?u={enc}&h=AT",
        f"https://out.reddit.com/t3_x?url={enc}",
        f"https://steamcommunity.com/linkfilter/?url={enc}",
        "https://example.com/p?fbclid=1&gclid=2&a=b&UTM_medium=m#x?y=z",
        "https://example.com/?utm_source=a",
        "http://example.com/?a=&&b=1&mc_eid=9",
        f"https://www.google.com/url?q=" + urllib.parse.quote(
            f"https://www.google.com/url?q={enc}", safe=""),
    ]
    for i, link in enumerate(links):
        write("app_clean_link", f"link-{i:02}.txt", link)

    # Hover: web, non-web, bidi and zero-width, long.
    hovers = [
        "https://example.com/path",
        "javascript:alert(1)",
        "https://evil.example/‮gnp.exe",
        "https://exa​mple.com/",
        "https://example.com/" + "a" * 300,
        "  HTTPS://EXAMPLE.COM/\t",
    ]
    for i, h in enumerate(hovers):
        write("app_hover_readout", f"hover-{i:02}.txt", h)

    # Hostset: text form (hosts-file style, comments) and compiled form.
    write("app_hostset", "lines.txt",
          "# comment\nads.example.com\n0.0.0.0 tracker.example\nbad..host\nEXAMPLE.org\n")
    write("app_hostset", "hashes-2.bin", bytes(range(32)))
    write("app_hostset", "hashes-truncated.bin", bytes(range(17)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
