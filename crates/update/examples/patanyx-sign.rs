//! Publisher tooling: generate the signing keypair, and sign update manifests.
//!
//! WHY THIS EXISTS. Until now the only code in this repository that could
//! produce a signature lived inside `#[cfg(test)]`. The project owner could
//! generate a keypair (an `--ignored` test printed one) and then had no way to
//! sign anything with it, so the update channel was unshippable for a reason
//! nobody had written down. This is the missing half.
//!
//! It is an EXAMPLE, not a binary in the browser. It never ships, and the
//! browser never gains the ability to sign anything -- it only verifies. That
//! asymmetry is the point of the design and this file must not erode it.
//!
//! # The ceremony
//!
//! Works on Linux, macOS and Windows: key generation draws from
//! `/dev/urandom` or CNG's `BCryptGenRandom` respectively.
//!
//! Once, on a machine that is not a build machine and ideally not networked:
//!
//! ```text
//! cargo run -p patanyx-update --example patanyx-sign -- keygen publisher.key release
//! ```
//!
//! It prints the VERIFYING key. Paste that into `PUBLISHER_KEYS` in
//! `crates/app/src/updater.rs`. Keep `publisher.key` off every build machine,
//! every repository and every backup that syncs anywhere. Losing it means
//! rotating; leaking it means an attacker can sign updates for every install.
//!
//! # Two keys, two jobs
//!
//! There is a SECOND key, for the blocklist channel only:
//!
//! ```text
//! cargo run -p patanyx-update --example patanyx-sign -- keygen blocklist.key blocklist
//! ```
//!
//! That one goes in `BLOCKLIST_KEYS`, and it exists because the blocklist is
//! republished constantly while releases are not. Signing hourly by hand is not
//! a thing anyone does, so the blocklist key lives on a server and is used by
//! an automated publisher -- handled far more often, and protected far less.
//!
//! Separating them bounds what losing that key costs. A stolen blocklist key
//! buys a wrong host list, repairable by publishing a corrected one. A stolen
//! RELEASE key buys arbitrary code on every install. Those must never be the
//! same key, which is why `keygen` now demands to be told which it is making.
//!
//! Domain separation already stops a blocklist signature being replayed as an
//! update (see `SIGNING_DOMAIN` vs `SIGNING_DOMAIN_BLOCKLIST`); this is the
//! other half, stopping one stolen secret from being able to do both.
//!
//! Then, per release:
//!
//! ```text
//! cargo run -p patanyx-update --example patanyx-sign -- \
//!     sign publisher.key release.json > windows-x86_64.json
//! ```
//!
//! where `release.json` is the unsigned payload document:
//!
//! ```json
//! {
//!   "version": "1.0.0",
//!   "platform": "windows-x86_64",
//!   "url": "https://example.invalid/patanyx-1.0.0-windows-x86_64.exe",
//!   "sha256": "<64 hex chars: sha256 of that exact file>",
//!   "size": 12345678,
//!   "published_at": 1753660800
//! }
//! ```
//!
//! Serve the output at `<UPDATE_BASE_URL>/v1/<platform>.json`.
//!
//! # The one design decision worth knowing
//!
//! `sign` VERIFIES ITS OWN OUTPUT before printing it, using the same
//! `verify_manifest` the browser runs, against the verifying key derived from
//! the signing key it just used. If that fails, nothing is written.
//!
//! So this tool cannot emit a manifest the browser would refuse. A malformed
//! URL, a zero size, a truncated sha256, a payload that is not valid JSON, a
//! wire-format drift -- all of them fail HERE, on the project owner's machine,
//! instead of silently on every user's. Publishing an unusable manifest is the
//! failure mode a signing tool exists to prevent, and a tool that merely
//! produced bytes would not prevent it.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use ed25519_dalek::{Signer, SigningKey};
use patanyx_update::{
    hex, verify_blocklist_manifest, verify_manifest, TrustedKeys, SIGNING_DOMAIN,
    SIGNING_DOMAIN_BLOCKLIST,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match refs.as_slice() {
        ["keygen", out, "release"] => keygen(Path::new(out), KeyPurpose::Release),
        ["keygen", out, "blocklist"] => keygen(Path::new(out), KeyPurpose::Blocklist),
        ["keygen", out, "licence"] => keygen(Path::new(out), KeyPurpose::Licence),
        ["sign", key, payload] => sign(Path::new(key), Path::new(payload)),
        ["sign-all", key, rest @ ..] => sign_all(Path::new(key), rest),
        ["verify", envelope, key_hex] => verify(Path::new(envelope), key_hex),
        ["sign-blocklist", key, payload] => sign_blocklist(Path::new(key), Path::new(payload)),
        ["verify-blocklist", envelope, key_hex] => {
            verify_blocklist(Path::new(envelope), key_hex)
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("patanyx-sign: {message}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
patanyx-sign -- publisher tooling for the signed update channel

  keygen <out-key-file> release    generate a RELEASE signing keypair
  keygen <out-key-file> blocklist  generate a BLOCKLIST signing keypair
  keygen <out-key-file> licence    generate a LICENCE signing keypair
                                   The purpose is required: it decides which
                                   constant the key belongs in, and the two
                                   are not interchangeable.
  sign   <key-file> <payload.json> sign an UPDATE payload, envelope to stdout
  sign-all <key-file> <payload.json>...  sign EVERY update payload at once:
                                   writes <name>.signed.json for each and
                                   prints one combined object keyed by
                                   platform. All or nothing -- if any payload
                                   would be rejected, none are written.
  verify <envelope.json> <key-hex> check an update envelope as the browser does

  sign-blocklist   <key-file> <payload.json>  sign a BLOCKLIST payload
  verify-blocklist <envelope.json> <key-hex>  check a blocklist envelope

Update and blocklist manifests are signed under DIFFERENT domains and are not
interchangeable. Signing a blocklist with `sign` produces a manifest the
browser will refuse, which is the point: one subcommand, one domain.

Run `keygen` once, offline. Keep the key file off every build machine.";

/// 32 bytes from the operating system's CSPRNG.
///
/// Straight to the OS on each platform rather than through a crate, because
/// this crate declares "no RNG" as a dependency-surface promise and adding one
/// would also mean regenerating the Flatpak offline source list. Both arms use
/// the interface the platform intends for key material -- neither is a
/// fallback or a convenience.
fn os_random_seed() -> Result<[u8; 32], String> {
    let mut seed = [0u8; 32];
    fill_random(&mut seed)?;
    if seed == [0u8; 32] {
        // Astronomically improbable, and exactly the value the placeholder key
        // in updater.rs already uses. If the random source is broken this is
        // the shape the breakage takes, so it is worth one comparison on a
        // value the whole update channel's security rests on.
        return Err("the random source returned all zeros; refusing to use it".to_string());
    }
    Ok(seed)
}

#[cfg(unix)]
fn fill_random(out: &mut [u8; 32]) -> Result<(), String> {
    let mut file = fs::File::open("/dev/urandom")
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    file.read_exact(out)
        .map_err(|e| format!("short read from /dev/urandom: {e}"))
}

/// Windows: CNG's system-preferred RNG.
///
/// `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` is the documented
/// way to get cryptographic randomness on Windows, and passing a null
/// algorithm handle with that flag is exactly how it is meant to be called for
/// this purpose. It is NOT `RandomState`, which this codebase uses elsewhere
/// for scheduling jitter and which is explicitly documented there as unsuitable
/// for anything security-bearing.
///
/// This is the only `unsafe` in the publisher tooling. It exists because the
/// operator runs Windows and the alternative was telling them to install
/// another operating system to perform the single most important security step
/// in the project -- friction on a key ceremony is how key ceremonies end up
/// being skipped, or done somewhere worse.
#[cfg(windows)]
fn fill_random(out: &mut [u8; 32]) -> Result<(), String> {
    // STATUS_SUCCESS. NTSTATUS is negative on failure, so this is checked
    // exactly rather than with a >= 0 test.
    const STATUS_SUCCESS: i32 = 0;
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            len: u32,
            flags: u32,
        ) -> i32;
    }

    // SAFETY: `out` is a live, exclusively borrowed 32-byte buffer and the
    // length passed is exactly its size. A null algorithm handle is the
    // documented contract when BCRYPT_USE_SYSTEM_PREFERRED_RNG is set.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            out.as_mut_ptr(),
            out.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(format!(
            "BCryptGenRandom failed (NTSTATUS {status:#x}); refusing to \
             generate a key without the operating system's random source"
        ));
    }
    Ok(())
}

fn keygen(out: &Path, purpose: KeyPurpose) -> Result<(), String> {
    // Never clobber. A signing key overwritten is a signing key lost, and with
    // it the ability to publish an update every existing install will accept.
    if out.exists() {
        return Err(format!(
            "{} already exists. Refusing to overwrite a signing key -- if you \
             mean to rotate, move the old one aside deliberately.",
            out.display()
        ));
    }
    let seed = os_random_seed()?;
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();

    // Hex, one line, no surrounding JSON: this file is read back by this tool
    // and by nothing else, and a format with no parser has no parser bugs.
    fs::write(out, hex::encode(&seed)).map_err(|e| format!("writing {}: {e}", out.display()))?;
    restrict(out)?;

    println!("Signing key written to {}", out.display());
    println!();
    match purpose {
        KeyPurpose::Release => {
            println!("Paste this into PUBLISHER_KEYS in crates/app/src/updater.rs:");
            println!();
            println!("    const PUBLISHER_KEYS: &[&str] =");
            println!("        &[\"{}\"];", hex::encode(verifying.as_bytes()));
            println!();
            println!("Then keep the key file OFF every build machine, repository and");
            println!("synced backup. Anyone holding it can sign an update that every");
            println!("existing install will accept and install.");
        }
        KeyPurpose::Licence => {
            println!("Paste this into LICENCE_KEYS in crates/licence/src/keys.rs:");
            println!();
            println!("    pub const LICENCE_KEYS: &[&str] =");
            println!("        &[\"{}\"];", hex::encode(verifying.as_bytes()));
            println!();
            println!("This key MINTS Premium tokens. Unlike the release key it lives");
            println!("ON the server (the licence server reads it at startup), in a");
            println!("0600 file under a 0700 directory, plus one offline backup.");
            println!("Losing it ends minting under this key id; leaking it lets");
            println!("anyone mint tokens every shipped browser accepts.");
        }
        KeyPurpose::Blocklist => {
            println!("Paste this into BLOCKLIST_KEYS in crates/app/src/updater.rs:");
            println!();
            println!("    const BLOCKLIST_KEYS: &[&str] =");
            println!("        &[\"{}\"];", hex::encode(verifying.as_bytes()));
            println!();
            println!("NOT into PUBLISHER_KEYS. That list authorises BINARY installs,");
            println!("and this key is meant to live on a server and be used by an");
            println!("automated publisher -- handled constantly, protected less. The");
            println!("whole reason it exists separately is so that losing it costs a");
            println!("wrong host list rather than arbitrary code on every install.");
        }
    }
    Ok(())
}

/// Which list a generated key belongs in.
///
/// REQUIRED, not defaulted. This used to print one instruction -- paste it into
/// PUBLISHER_KEYS -- whatever the key was for, so generating a blocklist key
/// told the project owner to hand it the power to sign a release. A default would
/// reintroduce that at whichever call site forgot to pass the argument, and
/// this command is run a handful of times in a project's life, always beside
/// the documentation. Being asked is cheap; being told the wrong destination
/// once is not.
#[derive(Clone, Copy)]
enum KeyPurpose {
    Licence,
    Release,
    Blocklist,
}

/// Owner-only permissions on the key file.
///
/// Best-effort and reported rather than fatal: the key is already written by
/// this point, and failing loudly after the fact would leave the project owner
/// thinking no key exists when one does.
fn restrict(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            eprintln!(
                "warning: could not set 0600 on {} ({e}); tighten it by hand",
                path.display()
            );
        }
    }
    // Windows has no chmod, and "restrict it by hand" is advice nobody acts on.
    // Print the exact command instead: strip inherited ACLs and grant only the
    // current user, which is the equivalent of 0600 here.
    //
    // THE USERNAME IS RESOLVED HERE, not left as a shell variable. The first
    // version printed `%USERNAME%`, which is cmd.exe syntax -- in PowerShell,
    // where the project owner actually was, that is a literal string and icacls
    // rejects it. There is no spelling of a variable that works in both shells,
    // so the right answer is to print neither and substitute the real name,
    // which every shell copies verbatim.
    #[cfg(not(unix))]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "<your-username>".to_string());
        eprintln!(
            "NOTE: {} inherits its folder's permissions. Lock it to your account:\n\
             \n    icacls \"{}\" /inheritance:r /grant:r \"{}:F\"\n",
            path.display(),
            path.display(),
            user
        );
    }
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let seed = hex::decode_32(raw.trim())
        .map_err(|_| format!("{} is not 32 bytes of hex", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Build a signed envelope for ONE update payload and check it the way the
/// browser will.
///
/// Shared by `sign` and `sign-all` rather than copied. The self-check is the
/// entire value of this tool -- it is what turns "produced some bytes" into
/// "produced bytes the browser accepts" -- and two copies of it would
/// eventually differ, which is exactly the failure a signing tool must not
/// have.
///
/// Returns the envelope bytes and the manifest they parsed to, so a caller can
/// report what it just signed without re-parsing.
fn sign_one(
    signing: &SigningKey,
    payload_path: &Path,
) -> Result<(Vec<u8>, patanyx_update::Manifest), String> {
    let payload = fs::read_to_string(payload_path)
        .map_err(|e| format!("reading {}: {e}", payload_path.display()))?;

    // The payload is signed as EXACT BYTES and travels as a JSON string inside
    // the envelope, so what is signed and what is verified are the same bytes
    // with no canonicalisation step in between. Trailing whitespace would be
    // signed too -- harmless, but trimmed so a stray newline from an editor
    // does not change the signature of an otherwise identical release.
    let payload = payload.trim().to_string();

    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + payload.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(payload.as_bytes());
    let signature = signing.sign(&message);

    let envelope = serde_json::json!({
        "v": 1,
        "payload": payload,
        "sig": hex::encode(&signature.to_bytes()),
    });
    let bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| format!("serialising the envelope: {e}"))?;

    // THE SELF-CHECK. Run the browser's own verifier over what we are about to
    // publish, against this key's verifying key. Everything the browser would
    // refuse -- bad signature, wire-version drift, malformed payload JSON, a
    // non-https url, a zero size, a truncated sha256, an oversized envelope --
    // fails here instead of on every user's machine.
    //
    // A BLOCKLIST payload also fails here, and that is deliberate: it is signed
    // under a different domain and parses to a different shape, so passing one
    // to an update subcommand is refused rather than silently mis-signed.
    let keys = TrustedKeys::new(vec![signing.verifying_key()])
        .map_err(|e| format!("the key derived from this file is not usable: {e}"))?;
    let manifest = verify_manifest(&bytes, &keys).map_err(|e| {
        format!(
            "REFUSING TO EMIT: the browser would reject the manifest from {} -- {e}\n\
             Nothing was written. Fix it and sign again.",
            payload_path.display()
        )
    })?;
    Ok((bytes, manifest))
}

fn sign(key_path: &Path, payload_path: &Path) -> Result<(), String> {
    let signing = read_signing_key(key_path)?;
    let (bytes, manifest) = sign_one(&signing, payload_path)?;
    eprintln!(
        "verified: {} {} ({} bytes) -> {}",
        manifest.platform(),
        manifest.version(),
        manifest.size(),
        manifest.url()
    );
    println!(
        "{}",
        String::from_utf8(bytes).map_err(|e| format!("envelope is not utf-8: {e}"))?
    );
    Ok(())
}

/// Sign EVERY staged update payload in one invocation.
///
/// Exists because a release is two manifests and signing them separately meant
/// two commands and two copy-pastes, with a malformed second payload only
/// discovered after the first had already been signed and sent -- a release
/// half-published.
///
/// ALL OR NOTHING. Every payload is signed and self-verified in memory before
/// anything is written or printed, so a failed batch leaves no files behind and
/// fix-and-rerun has no partial state to clean up.
///
/// UPDATE manifests only. Blocklists keep `sign-blocklist`, for the reason that
/// subcommand's own comment gives: the domain separation is what stops one
/// being replayed as the other, and a `--domain` flag would turn a type-system
/// guarantee into a guarantee about what someone typed.
fn sign_all(key_path: &Path, payload_paths: &[&str]) -> Result<(), String> {
    if payload_paths.is_empty() {
        return Err("sign-all needs at least one payload file".to_string());
    }
    let signing = read_signing_key(key_path)?;

    // Phase 1: sign and verify EVERYTHING. Nothing touches the disk yet.
    let mut signed: Vec<(String, std::path::PathBuf, Vec<u8>)> = Vec::new();
    for raw in payload_paths {
        let path = Path::new(raw);
        let (bytes, manifest) = sign_one(&signing, path)?;
        let platform = manifest.platform().to_string();
        // Two payloads for one platform would collapse into a single key in
        // the combined object below, publishing one and silently losing the
        // other. That is a release with a platform missing and no error.
        if let Some((dupe, _, _)) = signed.iter().find(|(p, _, _)| *p == platform) {
            return Err(format!(
                "two payloads both declare platform {dupe}; refusing the batch \
                 rather than publishing one and dropping the other"
            ));
        }
        eprintln!(
            "verified: {} {} ({} bytes) -> {}",
            platform,
            manifest.version(),
            manifest.size(),
            manifest.url()
        );
        let out = path.with_extension("signed.json");
        signed.push((platform, out, bytes));
    }

    // Phase 2: everything verified, so now write.
    let mut combined = serde_json::Map::new();
    for (platform, out, bytes) in &signed {
        fs::write(out, bytes).map_err(|e| format!("writing {}: {e}", out.display()))?;
        let envelope: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| format!("re-reading the envelope just built: {e}"))?;
        combined.insert(platform.clone(), envelope);
        eprintln!("wrote {}", out.display());
    }

    // One object, so the whole release is a single paste.
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Object(combined))
            .map_err(|e| format!("serialising the combined output: {e}"))?
    );
    Ok(())
}

/// Sign a BLOCKLIST payload.
///
/// A separate subcommand rather than a `--domain` flag, deliberately. The
/// domain is what stops an update manifest being replayed as a blocklist and
/// vice versa; making it a parameter would turn a type-system guarantee into a
/// guarantee about whoever typed the command line. Two entry points, two
/// hard-wired constants, one shared body.
fn sign_blocklist(key_path: &Path, payload_path: &Path) -> Result<(), String> {
    let signing = read_signing_key(key_path)?;
    let payload = fs::read_to_string(payload_path)
        .map_err(|e| format!("reading {}: {e}", payload_path.display()))?;
    let payload = payload.trim().to_string();

    let mut message = Vec::with_capacity(SIGNING_DOMAIN_BLOCKLIST.len() + payload.len());
    message.extend_from_slice(SIGNING_DOMAIN_BLOCKLIST);
    message.extend_from_slice(payload.as_bytes());
    let signature = signing.sign(&message);

    let envelope = serde_json::json!({
        "v": 1,
        "payload": payload,
        "sig": hex::encode(&signature.to_bytes()),
    });
    let bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| format!("serialising the envelope: {e}"))?;

    // Same self-check as `sign`, through the blocklist verifier: a zero entry
    // count, an implausible size, a non-https url or a truncated hash fails
    // here rather than leaving every install unable to refresh.
    let keys = TrustedKeys::new(vec![signing.verifying_key()])
        .map_err(|e| format!("the key derived from {} is not usable: {e}", key_path.display()))?;
    let manifest = verify_blocklist_manifest(&bytes, &keys).map_err(|e| {
        format!(
            "REFUSING TO EMIT: the browser would reject this blocklist manifest -- {e}\n\
             Nothing was written. Fix {} and sign again.",
            payload_path.display()
        )
    })?;

    eprintln!(
        "verified: blocklist v{} ({} hosts, {} bytes) -> {}",
        manifest.list_version(),
        manifest.entries(),
        manifest.size(),
        manifest.url()
    );
    println!(
        "{}",
        String::from_utf8(bytes).map_err(|e| format!("envelope is not utf-8: {e}"))?
    );
    Ok(())
}

/// Check a published blocklist envelope exactly as the browser will.
fn verify_blocklist(envelope_path: &Path, key_hex: &str) -> Result<(), String> {
    let bytes =
        fs::read(envelope_path).map_err(|e| format!("reading {}: {e}", envelope_path.display()))?;
    let keys = TrustedKeys::from_hex(&[key_hex])
        .map_err(|e| format!("the verifying key is not usable: {e}"))?;
    let manifest = verify_blocklist_manifest(&bytes, &keys)
        .map_err(|e| format!("the browser would REJECT this blocklist manifest: {e}"))?;
    println!(
        "accepted: blocklist v{} ({} hosts, {} bytes)\n  url:     {}\n  sha256:  {}\n  published_at: {}",
        manifest.list_version(),
        manifest.entries(),
        manifest.size(),
        manifest.url(),
        hex::encode(manifest.sha256()),
        manifest.published_at()
    );
    Ok(())
}

/// Check a published envelope exactly as the browser will.
///
/// The point is to answer "is what I uploaded what the browser accepts?"
/// against the file as served, not against what the signer remembers writing.
fn verify(envelope_path: &Path, key_hex: &str) -> Result<(), String> {
    let bytes =
        fs::read(envelope_path).map_err(|e| format!("reading {}: {e}", envelope_path.display()))?;
    let keys = TrustedKeys::from_hex(&[key_hex])
        .map_err(|e| format!("the verifying key is not usable: {e}"))?;
    let manifest = verify_manifest(&bytes, &keys)
        .map_err(|e| format!("the browser would REJECT this manifest: {e}"))?;
    println!(
        "accepted: {} {} ({} bytes)\n  url:     {}\n  sha256:  {}\n  published_at: {}",
        manifest.platform(),
        manifest.version(),
        manifest.size(),
        manifest.url(),
        hex::encode(manifest.sha256()),
        manifest.published_at()
    );
    Ok(())
}
