#!/usr/bin/env python3
"""Checks the Windows exe's runtime linkage and Control Flow Guard from the PE headers.

Run by build-windows.sh after the build. It reads the ARTIFACT, never the
source tree, and fails the build when:

  * the exe imports a Visual C++ runtime DLL (any name starting vcruntime140,
    msvcp140, concrt140 or vccorlib140, ordinary or delay-load import). Those
    are not part of Windows; on a clean Windows 11 the exe cannot load
    (STATUS_DLL_NOT_FOUND; opened from Explorer, Windows reports the DLL as
    not found; measured 2026-10-11). The build links
    vcruntime statically and keeps the Universal CRT dynamic, which ships with
    Windows 10 and 11 (api-ms-win-crt-* / ucrtbase.dll), so that import set is
    expected, and its absence means the fully static configuration that
    aborts at startup under CFG (build-windows.sh explains);
  * DllCharacteristics lacks GUARD_CF, high-entropy ASLR, dynamic base or NX;
  * the load configuration does not declare CFG instrumentation with a
    function table that is really there (mapped, read, every entry inside
    .text), or the code holds too few guarded indirect calls through
    __guard_dispatch_icall_fptr. The linker alone can set the GUARD_CF bit on
    code that was never instrumented (the 2026-08 review found exactly that);
    the dispatch-call count is what proves the rustc flag reached our code.

Every read is bounded to the file-backed part of a section (SizeOfRawData),
because Windows zero-fills a section's virtual tail: bytes that happen to sit
after a section in the file are not what the loader maps there.

Usage: check-windows-pe.py <exe> [--min-guarded-calls N]
       check-windows-pe.py --self-test
"""
import struct
import sys

FORBIDDEN_PREFIXES = ("vcruntime140", "msvcp140", "concrt140", "vccorlib140")
HARDENING = {"GUARD_CF": 0x4000, "HIGH_ENTROPY_VA": 0x20, "DYNAMIC_BASE": 0x40, "NX_COMPAT": 0x100}
MIN_TABLE_ENTRIES = 100
DEFAULT_MIN_CALLS = 500


class CheckError(Exception):
    pass


class Image:
    def __init__(self, data):
        self.d = data
        d = data
        if d[:2] != b"MZ" or len(d) < 0x40:
            raise CheckError("not a PE file")
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if pe + 24 > len(d) or d[pe:pe + 4] != b"PE\0\0":
            raise CheckError("bad PE signature")
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        opt = pe + 24
        if optsz < 112 or opt + optsz > len(d):
            raise CheckError("optional header truncated")
        if struct.unpack_from("<H", d, opt)[0] != 0x20B:
            raise CheckError("not a PE32+ (64-bit) image")
        self.base = struct.unpack_from("<Q", d, opt + 24)[0]
        self.entry = struct.unpack_from("<I", d, opt + 16)[0]
        self.dllc = struct.unpack_from("<H", d, opt + 70)[0]
        self.ndirs = struct.unpack_from("<I", d, opt + 108)[0]
        if 112 + self.ndirs * 8 > optsz:
            raise CheckError("NumberOfRvaAndSizes exceeds the optional header")
        self.opt = opt
        self.secs = []
        for i in range(nsec):
            s = opt + optsz + i * 40
            if s + 40 > len(d):
                raise CheckError("section table truncated")
            name = d[s:s + 8].rstrip(b"\0").decode(errors="replace")
            vsz, va, rawsz, raw = struct.unpack_from("<IIII", d, s + 8)
            if raw + rawsz > len(d):
                raise CheckError(f"section {name} raw data runs past the end of the file")
            self.secs.append((name, va, vsz, raw, rawsz))

    def directory(self, idx):
        if idx >= self.ndirs:
            return 0, 0
        return struct.unpack_from("<II", d_(self), self.opt + 112 + idx * 8)

    def span(self, rva, size):
        """File offset of [rva, rva+size) if that whole span is file-backed in one section."""
        if size <= 0:
            raise CheckError(f"empty span at RVA 0x{rva:x}")
        for name, va, vsz, raw, rawsz in self.secs:
            if va <= rva < va + vsz:
                backed = min(vsz, rawsz)
                if rva + size > va + backed:
                    raise CheckError(f"RVA 0x{rva:x}+0x{size:x} runs past the file-backed part of {name}")
                return raw + (rva - va)
        raise CheckError(f"RVA 0x{rva:x} is outside every section")

    def cstr(self, rva):
        for name, va, vsz, raw, rawsz in self.secs:
            if va <= rva < va + vsz:
                backed = min(vsz, rawsz)
                end = raw + backed
                o = raw + (rva - va)
                nul = self.d.find(b"\0", o, end)
                if nul < 0:
                    raise CheckError(f"string at RVA 0x{rva:x} has no terminator inside {name}")
                return self.d[o:nul].decode(errors="replace")
        raise CheckError(f"string RVA 0x{rva:x} is outside every section")

    def section(self, name):
        for s in self.secs:
            if s[0] == name:
                return s
        raise CheckError(f"no {name} section")


def d_(img):
    return img.d


def imports(img):
    """DLL names from the ordinary and delay-load import directories."""
    names = []
    for idx, entry, delay in ((1, 20, False), (13, 32, True)):
        rva, size = img.directory(idx)
        if not rva:
            continue
        if size < entry:
            raise CheckError(f"import directory {idx} declares {size} bytes, less than one descriptor")
        o = img.span(rva, size)
        count = size // entry
        for i in range(count):
            if not delay:
                ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", img.d, o + i * entry)
                if not ilt and not name_rva and not iat:
                    break
            else:
                _, name_rva = struct.unpack_from("<II", img.d, o + i * entry)
                if not name_rva:
                    break
            names.append((img.cstr(name_rva), delay))
        else:
            raise CheckError(f"import directory {idx} has no terminating descriptor inside its declared size")
    return names


def check(data, min_calls=DEFAULT_MIN_CALLS):
    img = Image(data)
    names = imports(img)
    bad = [n + (" (delay-load)" if delay else "") for n, delay in names
           if n.lower().startswith(FORBIDDEN_PREFIXES)]
    if bad:
        raise CheckError("imports the Visual C++ runtime: " + ", ".join(bad) +
                         ". A clean Windows has no such DLL; the build links vcruntime statically.")
    ucrt = [n for n, _ in names if n.lower().startswith("api-ms-win-crt-") or n.lower() == "ucrtbase.dll"]
    if not ucrt:
        raise CheckError("imports no Universal CRT forwarder (api-ms-win-crt-*): the UCRT must stay dynamic; "
                         "a fully static CRT aborts at startup under CFG (build-windows.sh explains)")
    missing = [k for k, bit in HARDENING.items() if not img.dllc & bit]
    if missing:
        raise CheckError(f"DllCharacteristics 0x{img.dllc:04x} lacks {', '.join(missing)}")

    lc_rva, lc_size = img.directory(10)
    if not lc_rva or lc_size < 0x94:
        raise CheckError(f"load configuration directory missing or too small ({lc_size} bytes) for GuardFlags")
    o = img.span(lc_rva, lc_size)
    declared = struct.unpack_from("<I", img.d, o)[0]
    if declared < 0x94 or declared > lc_size:
        raise CheckError(f"load configuration declares 0x{declared:x} bytes, directory holds {lc_size}")
    chk, disp, tab, cnt, flags = struct.unpack_from("<QQQQI", img.d, o + 0x70)
    if not flags & 0x100 or not flags & 0x400:
        raise CheckError(f"GuardFlags 0x{flags:08x} does not declare CF_INSTRUMENTED and CF_FUNCTION_TABLE_PRESENT")
    stride = 4 + ((flags >> 28) & 0xF)
    if cnt < MIN_TABLE_ENTRIES:
        raise CheckError(f"guard function table has {cnt} entries, fewer than {MIN_TABLE_ENTRIES}")
    if cnt >= 1 << 24:
        raise CheckError(f"guard function table count {cnt} is not credible")
    if tab < img.base:
        raise CheckError(f"guard function table address 0x{tab:x} is below the image base")
    to = img.span(tab - img.base, cnt * stride)
    tname, tva, tvsz, traw, trawsz = img.section(".text")
    tbacked = min(tvsz, trawsz)
    outside = 0
    prev = -1
    for i in range(cnt):
        e = struct.unpack_from("<I", img.d, to + i * stride)[0]
        if not (tva <= e < tva + tbacked):
            outside += 1
        if e <= prev:
            raise CheckError(f"guard table entry {i} (0x{e:x}) is not above the previous one (0x{prev:x}): "
                             "Windows requires a sorted table of unique RVAs")
        prev = e
    if outside:
        raise CheckError(f"{outside} of {cnt} guard table entries point outside the file-backed .text")
    if not disp or disp < img.base:
        raise CheckError("no __guard_dispatch_icall_fptr in the load configuration")
    img.span(disp - img.base, 8)
    disp_rva = disp - img.base

    # A linear byte scan for `call/jmp qword ptr [rip+disp32]` aimed at the
    # dispatch pointer, advancing one byte at a time so bytes that merely look
    # like such an instruction can never hide a real one behind them. It is
    # not a disassembler: an operand could in theory mimic the pattern, so the
    # count is a floor that a misconfigured build (CFG flag missing) cannot
    # reach, not a defence against an artifact crafted to fool it, which this
    # script builds itself.
    code = img.d[traw:traw + tbacked]
    calls = 0
    last = len(code) - 6
    for i in range(last + 1):
        if code[i] == 0xFF and code[i + 1] in (0x15, 0x25):
            rel = struct.unpack_from("<i", code, i + 2)[0]
            if tva + i + 6 + rel == disp_rva:
                calls += 1
    if calls < min_calls:
        raise CheckError(f"only {calls} guarded indirect calls through the CFG dispatch pointer in .text "
                         f"(expected at least {min_calls}): the GUARD_CF bit is set on code that was not instrumented")
    return (f"{len(names)} imports, no vcruntime DLL, UCRT dynamic ({len(ucrt)} forwarders); "
            f"DllCharacteristics 0x{img.dllc:04x} (CFG, high-entropy ASLR, DEP); "
            f"CFG table {cnt} entries, all in .text; {calls} guarded indirect calls")


# --- self-test: synthetic PE32+ images, built in memory ---------------------

def synth(dlls=("KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"), delay_dlls=(), dllc=0xC160,
          flags=0x500, table_count=120, calls=600, call_at_end=False, table_addr=None,
          lc_dir_size=None, declared_size=None, text_tail=0, name_past_section=False,
          table_order="sorted", tail_call=False, lookalike_prefix=False):
    """A minimal 64-bit PE: .text with `calls` dispatch calls, .rdata with the load
    configuration, the guard table, the dispatch pointer and the import tables."""
    base = 0x140000000
    align = 0x1000
    # .text: dispatch calls, then padding so the section boundary cuts an instruction when asked.
    text_va = 0x1000
    body = bytearray()
    calls_left = calls
    if lookalike_prefix:
        body += b"\xb9\xff\x15\x90\x90"  # mov ecx, 0x909015ff: operand bytes that look like a call
    # dispatch pointer will sit at rdata_va + 0x800; relative displacement computed per call
    rdata_va = 0x3000
    disp_rva = rdata_va + 0x800
    for _ in range(calls_left):
        at = text_va + len(body)
        rel = disp_rva - (at + 6)
        body += b"\xff\x15" + struct.pack("<i", rel)
    if call_at_end:
        text_raw_size = len(body)  # last call ends exactly at the boundary
    else:
        body += b"\xcc" * 16
        text_raw_size = len(body)
    text = bytes(body)
    text_vsz = text_raw_size + text_tail
    # .rdata layout
    rd = bytearray(0x1000)
    table_off = 0x100
    written = min(table_count, 200)  # the declared count is what is under test; write what fits
    entries = [text_va + i * 6 for i in range(written)]  # distinct, ascending, inside the calls
    if table_order == "descending":
        entries.reverse()
    elif table_order == "duplicate":
        entries = [entries[0]] * written
    for i, e in enumerate(entries):
        struct.pack_into("<I", rd, table_off + i * 4, e)
    struct.pack_into("<Q", rd, 0x800, base + text_va)  # dispatch pointer -> somewhere in .text
    lc_off = 0x900
    lc_size = 0x140
    struct.pack_into("<I", rd, lc_off, declared_size if declared_size is not None else lc_size)
    tab_addr = table_addr if table_addr is not None else base + rdata_va + table_off
    struct.pack_into("<QQQQI", rd, lc_off + 0x70, base + rdata_va + 0x810, base + disp_rva, tab_addr, table_count, flags)
    # import directory at 0xA00: descriptors (20 bytes) + terminator; names at 0xC00
    imp_off, names_off = 0xA00, 0xC00
    name_cursor = names_off
    for i, dll in enumerate(dlls):
        name_rva = rdata_va + name_cursor
        if name_past_section and i == len(dlls) - 1:
            name_rva = rdata_va + len(rd) - 3  # the terminator would lie beyond the section
            rd[len(rd) - 3:] = b"abc"
        else:
            rd[name_cursor:name_cursor + len(dll) + 1] = dll.encode() + b"\0"
            name_cursor += len(dll) + 1
        struct.pack_into("<IIIII", rd, imp_off + i * 20, rdata_va + 0xE00, 0, 0, name_rva, rdata_va + 0xE10)
    imp_size = (len(dlls) + 1) * 20
    # delay-load directory at 0xD00: 32-byte descriptors + terminator
    dl_off = 0xD00
    for i, dll in enumerate(delay_dlls):
        rd[name_cursor:name_cursor + len(dll) + 1] = dll.encode() + b"\0"
        struct.pack_into("<II", rd, dl_off + i * 32, 1, rdata_va + name_cursor)
        name_cursor += len(dll) + 1
    dl_size = (len(delay_dlls) + 1) * 32 if delay_dlls else 0
    # headers
    hdr = bytearray(0x400)
    hdr[:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    pe = 0x80
    hdr[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, pe + 4, 0x8664, 2, 0, 0, 0, 240, 0x22)
    opt = pe + 24
    struct.pack_into("<H", hdr, opt, 0x20B)
    struct.pack_into("<I", hdr, opt + 16, text_va)
    struct.pack_into("<Q", hdr, opt + 24, base)
    struct.pack_into("<II", hdr, opt + 32, align, 0x200)
    struct.pack_into("<H", hdr, opt + 70, dllc)
    struct.pack_into("<I", hdr, opt + 108, 16)
    struct.pack_into("<II", hdr, opt + 112 + 1 * 8, rdata_va + imp_off, imp_size)
    struct.pack_into("<II", hdr, opt + 112 + 10 * 8, rdata_va + lc_off, lc_dir_size if lc_dir_size is not None else lc_size)
    if delay_dlls:
        struct.pack_into("<II", hdr, opt + 112 + 13 * 8, rdata_va + dl_off, dl_size)
    sec0 = opt + 240
    text_raw = 0x400
    rdata_raw = text_raw + ((text_raw_size + 0x1FF) // 0x200) * 0x200
    struct.pack_into("<8sIIIIIIHHI", hdr, sec0, b".text", text_vsz, text_va, text_raw_size, text_raw, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", hdr, sec0 + 40, b".rdata", len(rd), rdata_va, len(rd), rdata_raw, 0, 0, 0, 0, 0x40000040)
    out = bytearray(hdr)
    out += text
    pad_at = len(out)
    out += b"\0" * (rdata_raw - len(out))
    if tail_call:
        # A dispatch call in the file padding right after .text's raw data, inside
        # its virtual tail: Windows zero-fills that tail, so it must not count.
        at = text_va + text_raw_size
        out[pad_at:pad_at + 6] = b"\xff\x15" + struct.pack("<i", disp_rva - (at + 6))
    out += rd
    return bytes(out)


def self_test():
    def expect_ok(name, data, **kw):
        try:
            check(data, **kw)
        except CheckError as e:
            raise SystemExit(f"self-test {name}: expected pass, got: {e}")

    def expect_fail(name, data, needle, **kw):
        try:
            check(data, **kw)
        except CheckError as e:
            if needle not in str(e):
                raise SystemExit(f"self-test {name}: wrong failure: {e}")
            return
        raise SystemExit(f"self-test {name}: expected failure containing {needle!r}, passed")

    expect_ok("baseline", synth())
    for dll in ("VCRUNTIME140.dll", "vcruntime140d.dll", "MSVCP140_2.dll", "CONCRT140.dll", "VCRUNTIME140_1.dll"):
        expect_fail("import " + dll, synth(dlls=("KERNEL32.dll", "api-ms-win-crt-heap-l1-1-0.dll", dll)), "Visual C++ runtime")
        expect_fail("delay import " + dll, synth(delay_dlls=(dll,)), "Visual C++ runtime")
    expect_fail("no ucrt", synth(dlls=("KERNEL32.dll",)), "Universal CRT")
    expect_fail("no cfg bit", synth(dllc=0x8160), "GUARD_CF")
    expect_fail("no nx", synth(dllc=0xC060), "NX_COMPAT")
    expect_fail("flags", synth(flags=0), "CF_INSTRUMENTED")
    expect_fail("small table", synth(table_count=50), "fewer than")
    expect_fail("bogus table address", synth(table_addr=1), "below the image base")
    expect_fail("huge count", synth(table_count=1_000_000_000), "not credible")
    expect_fail("table past section", synth(table_count=2000), "runs past")
    expect_fail("lc dir size 0", synth(lc_dir_size=0), "load configuration")
    expect_fail("lc declared larger than dir", synth(declared_size=0x400), "declares")
    expect_fail("name past section", synth(name_past_section=True), "terminator")
    expect_fail("few calls", synth(calls=499), "only 499")
    expect_ok("call ending at the boundary", synth(calls=500, call_at_end=True))
    expect_ok("virtual tail ignored", synth(calls=500, text_tail=0x100))
    expect_fail("call in the virtual tail does not count", synth(calls=499, text_tail=0x100, tail_call=True), "only 499")
    expect_ok("look-alike bytes before a real call do not hide it", synth(calls=500, lookalike_prefix=True))
    expect_fail("descending table", synth(table_order="descending"), "sorted")
    expect_fail("duplicate entries", synth(table_order="duplicate"), "sorted")
    expect_fail("count at the limit", synth(table_count=1 << 24), "not credible")
    print("self-test ok")


def main():
    args = sys.argv[1:]
    if args == ["--self-test"]:
        self_test()
        return
    min_calls = DEFAULT_MIN_CALLS
    if "--min-guarded-calls" in args:
        i = args.index("--min-guarded-calls")
        min_calls = int(args[i + 1])
        del args[i:i + 2]
    if len(args) != 1:
        print("usage: check-windows-pe.py <exe> [--min-guarded-calls N] | --self-test", file=sys.stderr)
        sys.exit(2)
    try:
        summary = check(open(args[0], "rb").read(), min_calls)
    except CheckError as e:
        print(f"BUILD FAIL: {args[0]}: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"pe check ok: {summary}")


if __name__ == "__main__":
    main()
