#!/usr/bin/env python3
"""Generate the attribution text that ships INSIDE each binary.

WHY THIS EXISTS SEPARATELY FROM scripts/third-party-licenses.sh.

That script writes THIRD_PARTY_LICENSES.md from `cargo metadata --all-features`,
which is the UNION over every feature and every target. 466 crates. It says so
about itself, in bold, because for a repository attribution file over-reporting
is the safe direction.

It is the wrong direction for something shown to a user inside the browser. The
Windows public binary contains 228 of those crates; the chat build contains 254.
A panel rendering the union would tell someone that 238 pieces of software are
in their browser which are not in it. "We listed extra" is not a defence when
the whole point of the surface is to say what you are running.

So this resolves the tree PER SHIPPED CONFIGURATION and emits one file each.
Only one is compiled into any given binary.

WHAT GOES IN, AND THE LICENCE REASONING.

MIT, BSD and ISC all require that the copyright notice travel with binary
redistribution; the permission text may be shared between works that use the
same licence. So the output stores, per crate, its own copyright line(s), and
stores each distinct licence BODY exactly once. That is both the compliant
shape and the compact one -- 228 near-identical MIT texts would be about ten
times the size and no more correct.

A crate whose licence file cannot be found locally is REPORTED, not silently
dropped. An attribution file that quietly omits what it could not resolve looks
like diligence and is not.

Run: python3 scripts/shipping-licenses.py
"""

import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_OUTDIR = ROOT / "crates/app/src/chrome/attribution"
# Overridable so the gate can regenerate into a scratch directory and diff,
# rather than writing over the checked-in files it is trying to verify.
OUTDIR = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTDIR

# The configurations that are actually built and handed to someone. Keep this
# list in step with the release scripts; a configuration missing here ships
# with no attribution compiled in at all.
CONFIGS = [
    ("windows", "x86_64-pc-windows-msvc", [], "PATANYX for Windows"),
    (
        "windows-chat",
        "x86_64-pc-windows-msvc",
        ["chat", "relay-client"],
        "PATANYX-Premium for Windows",
    ),
    ("linux", "x86_64-unknown-linux-gnu", [], "PATANYX for Linux"),
    (
        "linux-chat",
        "x86_64-unknown-linux-gnu",
        ["chat", "relay-client"],
        "PATANYX-Premium for Linux",
    ),
]

# Matched case-INSENSITIVELY against each filename. pathlib.glob is
# case-sensitive on Linux, and an uppercase-only pattern silently missed every
# Microsoft crate: windows-core, windows-sys and the rest ship their terms as
# `license-mit` and `license-apache-2.0` in lower case. The first run of this
# script reported thirteen of them as "no licence file in crate" while the
# files sat right there in the crate source -- an attribution file confidently
# announcing a gap that did not exist.
LICENCE_FILE_PREFIXES = ("license", "licence", "copying", "unlicense", "notice")
COPYRIGHT_RE = re.compile(r"^\s*(copyright|\(c\)|©)\s*.+", re.IGNORECASE)


def sh(args):
    return subprocess.run(
        args, cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout


def shipping_packages(target, features):
    """(name, version) actually reachable for this target and feature set."""
    args = [
        "cargo",
        "tree",
        "--target",
        target,
        "-p",
        "patanyx",
        "--prefix",
        "none",
        "--no-dedupe",
        "--edges",
        "normal,build",
    ]
    if features:
        args += ["--features", ",".join(features)]
    out = sh(args)
    found = set()
    for line in out.splitlines():
        line = line.strip().removesuffix(" (*)")
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        # A trailing path means a workspace member: ours, not third party.
        if len(parts) > 2 and parts[2].startswith("("):
            continue
        found.add((parts[0], parts[1][1:]))
    return found


def metadata_index():
    meta = json.loads(sh(["cargo", "metadata", "--format-version", "1", "--all-features"]))
    index = {}
    for p in meta["packages"]:
        if p.get("source") is None:
            continue  # workspace member
        index[(p["name"], p["version"])] = {
            "license": p.get("license"),
            "license_file": p.get("license_file"),
            "repository": p.get("repository"),
            "manifest_path": p.get("manifest_path"),
        }
    return index


def licence_texts(manifest_path):
    """Every licence file shipped in the crate source, as (filename, text)."""
    if not manifest_path:
        return []
    crate_dir = pathlib.Path(manifest_path).parent
    if not crate_dir.is_dir():
        return []
    seen = {}
    for path in sorted(crate_dir.iterdir()):
        if not path.is_file():
            continue
        low = path.name.lower()
        if not low.startswith(LICENCE_FILE_PREFIXES):
            continue
        # Skip pointers-to-elsewhere and templates rather than storing a file
        # whose content is a sentence about where the licence is.
        if low.endswith((".rs", ".toml", ".py")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if text:
            seen[path.name] = text
    return sorted(seen.items())


def copyright_lines(text):
    out = []
    for line in text.splitlines():
        if COPYRIGHT_RE.match(line):
            cleaned = line.strip()
            # Apache's boilerplate carries a placeholder rather than a holder.
            if "[yyyy]" in cleaned or "[name of copyright owner]" in cleaned:
                continue
            if cleaned not in out:
                out.append(cleaned)
    return out


def body_without_copyright(text):
    """The shareable part: the licence terms with holder lines removed."""
    kept = [ln for ln in text.splitlines() if not COPYRIGHT_RE.match(ln)]
    return "\n".join(kept).strip()


def build(name, target, features, title, index):
    pkgs = sorted(shipping_packages(target, features))
    bodies = {}  # sha -> text
    body_users = {}  # sha -> [crate labels]
    rows = []
    unresolved = []

    for pkg_name, version in pkgs:
        info = index.get((pkg_name, version))
        if info is None:
            unresolved.append(f"{pkg_name} {version} (not in cargo metadata)")
            rows.append((pkg_name, version, "UNRESOLVED", []))
            continue
        spdx = info["license"] or (
            f"see {info['license_file']}" if info["license_file"] else "UNDECLARED"
        )
        texts = licence_texts(info["manifest_path"])
        holders = []
        for _fname, text in texts:
            for line in copyright_lines(text):
                if line not in holders:
                    holders.append(line)
            body = body_without_copyright(text)
            if body:
                sha = hashlib.sha256(body.encode()).hexdigest()[:16]
                bodies.setdefault(sha, body)
                body_users.setdefault(sha, [])
                label = f"{pkg_name} {version}"
                if label not in body_users[sha]:
                    body_users[sha].append(label)
        if not texts:
            unresolved.append(f"{pkg_name} {version} ({spdx}, no licence file in crate)")
        rows.append((pkg_name, version, spdx, holders))

    lines = []
    lines.append(f"{title} -- third-party software")
    lines.append("")
    lines.append(
        "Generated by scripts/shipping-licenses.py from the dependency tree of"
    )
    lines.append(
        "THIS configuration. It lists what is compiled into this binary, not the"
    )
    lines.append(
        "union across every build -- see THIRD_PARTY_LICENSES.md for that wider"
    )
    lines.append("inventory.")
    lines.append("")
    lines.append(f"{len(rows)} third-party packages.")
    lines.append("")

    counts = {}
    for _n, _v, spdx, _h in rows:
        counts[spdx] = counts.get(spdx, 0) + 1
    lines.append("LICENCES IN USE")
    for spdx, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {n:>4}  {spdx}")
    lines.append("")

    if unresolved:
        lines.append("NOT RESOLVED LOCALLY")
        lines.append(
            "  These declare a licence but no licence file was found in the crate"
        )
        lines.append(
            "  source on the machine that generated this. Listed rather than"
        )
        lines.append("  omitted, so the gap is visible instead of invisible.")
        for item in unresolved:
            lines.append(f"  - {item}")
        lines.append("")

    lines.append("PACKAGES")
    for pkg_name, version, spdx, holders in rows:
        lines.append(f"  {pkg_name} {version} -- {spdx}")
        for h in holders:
            lines.append(f"      {h}")
    lines.append("")

    lines.append("LICENCE TEXTS")
    lines.append(
        "  Each distinct licence body appears once. Copyright holders are listed"
    )
    lines.append(
        "  per package above; MIT, BSD and ISC require the holder's notice to"
    )
    lines.append("  travel with the software, and it does.")
    lines.append("")
    for sha in sorted(bodies, key=lambda s: (-len(body_users[s]), s)):
        users = body_users[sha]
        shown = ", ".join(users[:8])
        more = f", and {len(users) - 8} more" if len(users) > 8 else ""
        lines.append(f"  --- used by {len(users)} package(s): {shown}{more}")
        lines.append("")
        for ln in bodies[sha].splitlines():
            lines.append(f"  {ln}" if ln.strip() else "")
        lines.append("")

    text = "\n".join(lines).rstrip() + "\n"
    OUTDIR.mkdir(parents=True, exist_ok=True)
    (OUTDIR / f"{name}.txt").write_text(text)
    return len(rows), len(bodies), len(unresolved), len(text)


def main():
    index = metadata_index()
    print(f"{len(index)} third-party packages known to cargo metadata")
    worst_unresolved = 0
    for name, target, features, title in CONFIGS:
        n, b, u, size = build(name, target, features, title, index)
        worst_unresolved = max(worst_unresolved, u)
        print(
            f"  {name:<13} {n:>4} packages  {b:>3} distinct licence texts  "
            f"{u:>3} unresolved  {size // 1024:>4} KB"
        )
    if worst_unresolved:
        print(
            f"NOTE: up to {worst_unresolved} package(s) per configuration had no "
            "licence file locally; they are named in the output."
        )


if __name__ == "__main__":
    sys.exit(main())
