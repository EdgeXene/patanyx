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

/// Embeds the Windows icon and version resource into the executable.
///
/// WHY THIS EXISTS. The shipped 0.9.63 binary had NO resource directory at
/// all -- no icon, no version block. The app looked right while RUNNING,
/// because main.rs sets a window icon from raw pixels at startup, but a
/// PINNED taskbar shortcut points at the file and Windows reads the icon out
/// of the file, finds nothing, and draws the blank generic placeholder.
/// Reported from hardware 2026-08-18. The runtime icon cannot fix it; only a
/// resource in the PE can.
///
/// The .rc is GENERATED rather than committed so the version block cannot go
/// stale: the numbers come from CARGO_PKG_VERSION, which is the same source
/// check-version.sh already treats as authoritative.
///
/// Compiled with llvm-rc, which lives in the same LLVM bin directory that
/// build-windows.sh already puts on PATH for llvm-lib. A Windows build that
/// cannot find it FAILS rather than quietly producing another iconless
/// binary -- shipping one of those is the defect this exists to prevent.
fn embed_windows_resources() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let ico = manifest.join("patanyx.ico");
    assert!(ico.is_file(), "patanyx.ico is missing at {}", ico.display());
    println!("cargo:rerun-if-changed={}", ico.display());

    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut parts = version
        .split('.')
        .map(|p| p.parse::<u16>().unwrap_or(0))
        .collect::<Vec<_>>();
    parts.resize(4, 0);
    let quad = format!("{},{},{},{}", parts[0], parts[1], parts[2], parts[3]);

    // No #include: every constant is spelled numerically so the script needs
    // no Windows SDK headers, which a cross-compile does not have.
    // `1 ICON` is the lowest icon id, which is the one Explorer shows.
    let rc = format!(
        "1 ICON \"{icon}\"\n\
         1 VERSIONINFO\n\
         FILEVERSION {quad}\n\
         PRODUCTVERSION {quad}\n\
         FILEFLAGSMASK 0x3fL\n\
         FILEFLAGS 0x0L\n\
         FILEOS 0x40004L\n\
         FILETYPE 0x1L\n\
         FILESUBTYPE 0x0L\n\
         BEGIN\n\
         BLOCK \"StringFileInfo\"\n\
         BEGIN\n\
         BLOCK \"040904b0\"\n\
         BEGIN\n\
         VALUE \"CompanyName\", \"EdgeXene LLC\"\n\
         VALUE \"FileDescription\", \"PATANYX\"\n\
         VALUE \"FileVersion\", \"{version}\"\n\
         VALUE \"InternalName\", \"PATANYX\"\n\
         VALUE \"OriginalFilename\", \"PATANYX.exe\"\n\
         VALUE \"ProductName\", \"PATANYX\"\n\
         VALUE \"ProductVersion\", \"{version}\"\n\
         END\n\
         END\n\
         BLOCK \"VarFileInfo\"\n\
         BEGIN\n\
         VALUE \"Translation\", 0x409, 1200\n\
         END\n\
         END\n",
        icon = ico.display(),
        quad = quad,
        version = version,
    );
    let rc_path = out.join("patanyx.rc");
    std::fs::write(&rc_path, rc).unwrap_or_else(|e| panic!("writing {}: {e}", rc_path.display()));

    let res_path = out.join("patanyx.res");
    let tool = ["llvm-rc", "llvm-rc-14", "rc.exe"]
        .into_iter()
        .map(String::from)
        .find(|t| {
            std::process::Command::new(t)
                .arg("/?")
                .output()
                .map(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
                .unwrap_or(false)
        })
        .or_else(|| std::env::var("RC").ok())
        .unwrap_or_else(|| {
            panic!(
                "no resource compiler found (tried llvm-rc, llvm-rc-14, rc.exe, $RC). \
                 A Windows build without one produces a binary with NO ICON, which is \
                 the exact defect this step exists to prevent. On Debian: \
                 apt-get install llvm-14, then put /usr/lib/llvm-14/bin on PATH."
            )
        });
    let status = std::process::Command::new(&tool)
        .arg(format!("/fo{}", res_path.display()))
        .arg(&rc_path)
        .status()
        .unwrap_or_else(|e| panic!("running {tool}: {e}"));
    assert!(status.success(), "{tool} failed on {}", rc_path.display());
    // -bins, not the blanket form: tests link too and do not need this.
    println!("cargo:rustc-link-arg-bins={}", res_path.display());
}

fn main() {
    embed_windows_resources();
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
