//! Publish-time delta generator. Runs on the build host, never ships.
//!
//!     patanyx-delta <old-binary> <new-binary> <out.patch>
//!
//! Writes a patch in the format `crates/update/src/delta.rs` applies (the
//! `bsdiff` crate's RAW control stream -- NOT bspatch(1)-compatible; see
//! that module's header for why) and prints the exact JSON object to
//! append to the signed payload's "deltas" array. The payload is then
//! signed by patanyx-sign as always -- this tool touches no keys.

use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let [_, old_path, new_path, out_path] = args.as_slice() else {
        eprintln!("usage: patanyx-delta <old-binary> <new-binary> <out.patch>");
        std::process::exit(2);
    };
    let old = std::fs::read(old_path)?;
    let new = std::fs::read(new_path)?;
    let mut raw = Vec::new();
    bsdiff::diff(&old, &new, &mut raw)?;
    // Compression is what makes a delta a delta -- see delta.rs's header.
    let patch = patanyx_update::compress_delta(&raw);

    // Refuse to emit a "delta" that saves nothing: the manifest validator
    // rejects size >= full size, so catching it here saves a signing round.
    if patch.len() >= new.len() {
        eprintln!(
            "refusing: patch ({} bytes) is not smaller than the new binary ({} bytes)",
            patch.len(),
            new.len()
        );
        std::process::exit(1);
    }

    // Round-trip before anything is written: a patch this tool cannot apply
    // back to the exact new bytes must never reach the manifest.
    let applied = patanyx_update::apply_delta(&old, &patch, new.len() as u64)?;
    if applied != new {
        eprintln!("refusing: patch round-trip did not reproduce the new binary");
        std::process::exit(1);
    }

    std::fs::write(out_path, &patch)?;
    eprintln!(
        "wrote {out_path}: {} bytes ({}% of full)",
        patch.len(),
        patch.len() * 100 / new.len()
    );
    println!(
        "{{\"from\":\"{}\",\"url\":\"https://patanyx.edgexene.io/dl/delta/REPLACE-ME\",\"sha256\":\"{}\",\"size\":{}}}",
        sha256_hex(&old),
        sha256_hex(&patch),
        patch.len()
    );
    Ok(())
}
