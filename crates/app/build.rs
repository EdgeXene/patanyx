// Compiles the malicious-host list from text into sorted 128-bit hashes.
//
// WHY THIS EXISTS. The list shipped as plaintext inside the binary, and on
// 2026-07-29 ClamAV quarantined every Windows build as
// `Win.Keylogger.Stawin-9837241-0`. The signature is five bank names ANDed
// together -- commbank, bendigo, bankwest, scotiabank, e-bendigo -- because
// real banking trojans embed the banks they target. So does any phishing
// blocklist, for the opposite reason. Proven by blanking one string in an
// otherwise byte-identical binary and watching FOUND become OK.
//
// Hashing removes the strings without obfuscating anything: a sorted hash
// index is a normal data structure, not a packed blob that would itself look
// suspicious. It is also 72% smaller.
//
// THE PLAINTEXT STAYS IN THE REPOSITORY. src/blocklist.txt remains the source
// of truth precisely so additions are reviewable in a diff -- a malicious
// insertion that blocked a legitimate bank must not be invisible. Only the
// compiled artifact is hashed.
use std::path::PathBuf;

// The acceptance and hashing rules, shared verbatim with the crate. See the
// header of hostrules.rs for why this is an include and not an import.
include!("src/platform/hostrules.rs");

fn main() {
    let src = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("src")
        .join("blocklist.txt");
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed=src/platform/hostrules.rs");

    let text = std::fs::read_to_string(&src)
        .unwrap_or_else(|e| panic!("reading {}: {e}", src.display()));
    let hashes = hashes_from_lines(&text);

    // A build that produced an empty or tiny set would compile fine and ship a
    // browser with no malicious-host protection while every count still
    // reported a list. Fail the BUILD instead.
    assert!(
        hashes.len() > 300_000,
        "blocklist.txt compiled to {} hosts, far below the shipped list -- \
         either the file was truncated or most lines were rejected",
        hashes.len()
    );

    let mut bytes = Vec::with_capacity(hashes.len() * 16);
    for h in &hashes {
        bytes.extend_from_slice(&h.to_le_bytes());
    }

    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("blocklist.bin");
    std::fs::write(&out, &bytes).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
    println!(
        "cargo:warning=blocklist: {} hosts -> {} bytes of hashes",
        hashes.len(),
        bytes.len()
    );

    build_psl();
}

/// Compiles the Public Suffix List into three sorted hash sets.
///
/// HASHED FOR THE SAME REASON THE BLOCKLIST IS. That list ships hashed because
/// plaintext bank names got an otherwise clean Windows build quarantined as a
/// keylogger. The PSL carries brand gTLDs -- `hsbc`, `barclays`, `citi`,
/// `chase` -- which is the same shape of string in the same binary, so it gets
/// the same treatment rather than waiting to find out. The text stays in the
/// repository (`src/public_suffix_list.txt`) so additions remain reviewable in
/// a diff; only the compiled artifact is hashed.
///
/// Three sets rather than one, because the list has three kinds of rule and
/// they mean different things:
///
///   normal      `co.uk`      -- this is a public suffix
///   wildcard    `*.ck`       -- any ONE label under `ck` is a public suffix
///   exception   `!www.ck`    -- except this one, which is registrable
///
/// Wildcards are stored by their PARENT (`*.ck` is filed as `ck`), so the
/// matcher asks "is my parent a wildcard root" with one lookup instead of
/// building a `*.` string per candidate.
fn build_psl() {
    let src = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("src")
        .join("public_suffix_list.txt");
    println!("cargo:rerun-if-changed={}", src.display());

    let text = std::fs::read_to_string(&src)
        .unwrap_or_else(|e| panic!("reading {}: {e}", src.display()));

    let (mut normal, mut wildcard, mut exception) = (Vec::new(), Vec::new(), Vec::new());
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("!") {
            exception.push(hash_host(rest));
        } else if let Some(parent) = line.strip_prefix("*.") {
            wildcard.push(hash_host(parent));
        } else {
            normal.push(hash_host(line));
        }
    }
    for set in [&mut normal, &mut wildcard, &mut exception] {
        set.sort_unstable();
        set.dedup();
    }

    // A truncated list compiles and runs fine, and fails OPEN: every missing
    // rule makes some registrable domain LARGER, which is how a saved password
    // ends up offered to a stranger who happens to share a public suffix.
    // There is no runtime symptom, so the build is the only place to catch it.
    assert!(
        normal.len() > 9_000 && wildcard.len() > 200 && exception.len() >= 5,
        "public suffix list compiled to {} normal / {} wildcard / {} exception \
         rules, far below the real list -- regenerate it with \
         scripts/build-psl.py rather than shipping a browser that silently \
         widens every credential's blast radius",
        normal.len(),
        wildcard.len(),
        exception.len()
    );

    let mut bytes = Vec::new();
    for set in [&normal, &wildcard, &exception] {
        bytes.extend_from_slice(&(set.len() as u32).to_le_bytes());
    }
    for set in [&normal, &wildcard, &exception] {
        for h in set.iter() {
            bytes.extend_from_slice(&h.to_le_bytes());
        }
    }

    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("psl.bin");
    std::fs::write(&out, &bytes).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
    println!(
        "cargo:warning=psl: {} normal, {} wildcard, {} exception -> {} bytes",
        normal.len(),
        wildcard.len(),
        exception.len(),
        bytes.len()
    );
}
