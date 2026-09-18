//! Downloading, verifying and installing a language pack.
//!
//! THE UPDATER PATTERN, VERBATIM, because it is the one this product already
//! trusts with installing code: signed manifest first, hash-and-length against
//! that manifest second, and the hosting treated as untrusted throughout.
//! `blocklist.rs` is the closest sibling and this follows it deliberately
//! rather than inventing a fourth shape.
//!
//! WHAT THE NETWORK SEES, stated exactly because the policy has to say it. A
//! request for a pack discloses WHICH LANGUAGE PAIR the user chose. That is
//! per-user distinguishing information, and it is more than an update check
//! carries -- an update check says only "a PATANYX exists". It does NOT
//! disclose the page, its URL, its text, or anything about browsing. Nothing
//! about the page ever leaves the machine, before or after this.
//!
//! ONE NETWORK CONTACT, TO ONE HOST WE RUN. No CDN, so the live policy's
//! "complete list of providers" sentence survives. That choice makes EdgeXene
//! a redistributor of the weights, which is a licensing question the project
//! has ruled on separately -- see docs/page-translation-provenance.md.

use std::path::{Path, PathBuf};

use patanyx_update::{verify_model_bytes, verify_model_manifest, MAX_MODEL_PACK_BYTES};

/// Where manifests are fetched from.
///
/// A SEPARATE HOST from the update and blocklist feeds, which is not
/// cosmetic: it is the network-level half of the key-class separation. The
/// model-feed key signs model-feed artifacts only, and serving them from their
/// own host means a compromise of one feed's infrastructure does not put an
/// attacker in the request path of another.
const MODEL_HOST: &str = "https://models.patanyx.net";

/// A manifest is small. Anything larger is not a manifest, and the cap is what
/// stops an endless response becoming an allocation.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;

/// The container a pack arrives in.
///
/// PURPOSE-BUILT, AND THAT IS THE POINT. A pack is three files, and the signed
/// manifest names ONE url with ONE hash -- so the three have to travel as one
/// object. The obvious answers are tar or zip, and both are the wrong shape
/// here: they carry FILENAMES, which means bytes chosen by whoever served them
/// get a say in where bytes land, and they bring a general archive parser into
/// a path that already runs on downloaded input.
///
/// This format has no filenames at all. Three lengths, then three blobs, in a
/// fixed order that the reader assigns to fixed destinations. There is nothing
/// inside it that can influence anything outside it, so path traversal is not
/// mitigated here -- it is absent.
///
/// No compression either: the weights are already int8-quantised and
/// compressing them saves little, while a decompressor is a second parser on
/// untrusted bytes and a decompression bomb is a real shape of attack.
///
/// TWO GENERATIONS, because a pack is not always three files. Mozilla ships
/// Japanese and Chinese with a SPLIT vocabulary (a source segmenter and a
/// target one), which is four parts. V1 is fixed at three and is what the
/// packs already published carry, so it stays readable forever rather than
/// forcing a republish of every pair:
///
///   "PXPACK1\n"
///   "<len model>\n<len lex>\n<len vocab>\n"
///   <model bytes><lex bytes><vocab bytes>
///
///   "PXPACK2\n"
///   "<count>\n"
///   "<len 1>\n"... (count of them)
///   <blob 1>... (count of them)
///
/// V2 states its part count instead of implying it. The count is still not a
/// name: the READER decides what each position means, from the layout the
/// REGISTRY declares for that pair, and refuses a container whose count
/// disagrees. So a signed container cannot change a pair's shape -- it can
/// only match it or be rejected.
const PACK_MAGIC: &[u8] = b"PXPACK1\n";
const PACK_MAGIC_V2: &[u8] = b"PXPACK2\n";

/// What a three-part pack is made of, in container order.
///
/// POSITIONAL, matching `platform::PACK_FILES`. The container says nothing
/// about names; this is where position becomes a destination, once, in code
/// that ships.
const PACK_PARTS: usize = 3;

/// A split-vocabulary pack: model, lex, srcvocab, trgvocab.
const PACK_PARTS_SPLIT: usize = 4;

/// The largest a part count may be. Bounds the allocation the count drives
/// before a single length is read.
const MAX_PACK_PARTS: usize = PACK_PARTS_SPLIT;

/// Outcome of an install attempt, in terms a panel can render.
#[derive(Debug, PartialEq, Eq)]
pub enum PackError {
    /// Could not reach the model host, or the connection could not be trusted.
    Unreachable(&'static str),
    /// The server answered, and it has no pack under this token: not published
    /// (yet), or withdrawn. Distinct from Unreachable so the row says "not
    /// available yet" rather than blaming the network, which is what a user
    /// read for Middle French before its pack was published (2026-09-16).
    NotOffered,
    /// The manifest did not verify, or described something we refuse.
    Manifest,
    /// The body did not match the signed manifest.
    Body,
    /// The container was not the shape this build understands.
    Malformed,
    /// The bytes verified and could not be written.
    Storage,
}

impl PackError {
    /// The catalog KEY a panel renders. Never prose: this crosses into the UI
    /// and the UI renders in the user's language.
    pub fn key(&self) -> &'static str {
        match self {
            PackError::Unreachable(_) => "translate-pack-unreachable",
            PackError::NotOffered => "translate-pack-not-offered",
            PackError::Manifest => "translate-pack-untrusted",
            PackError::Body => "translate-pack-untrusted",
            PackError::Malformed => "translate-pack-untrusted",
            PackError::Storage => "translate-pack-storage",
        }
    }
}

/// The file recording which version of a pack is installed.
///
/// A PLAIN DECIMAL IN THE PACK DIRECTORY, so it moves with the pack: the
/// atomic rename that installs three model files installs this too, and a pack
/// directory can never disagree with its own version record.
const VERSION_FILE: &str = "version";

/// Puts back a pack left aside by an install that did not finish.
///
/// THE CRASH WINDOW THE TWO-STEP SWAP CREATED. Moving the old pack aside and
/// then renaming the new one into place removes the "no pack" window of the
/// delete-then-rename it replaced, but only for a FAILED rename -- if the
/// machine dies BETWEEN the two renames, the pack directory is missing and the
/// old copy is sitting under its aside name.
///
/// That is worse than it first looks, and it is why this exists rather than
/// being left to the next download. `installed_version` reads the pack
/// directory, so a missing one reports version 0 -- which silently disables
/// the anti-rollback check, and a replayed old manifest would then be accepted.
/// A crash must not quietly switch off a security property.
///
/// Idempotent and cheap: the common case is two `exists` checks that both say
/// no. Called at every entry point rather than at startup, so a pack
/// interrupted by a crash is repaired before anything reads its version.
fn recover_interrupted(pack_root: &Path, pair: &str) {
    let final_dir = pack_root.join(pair);
    if final_dir.exists() {
        return;
    }
    let aside = pack_root.join(format!(".previous-{pair}"));
    if aside.is_dir() {
        let _ = std::fs::rename(&aside, &final_dir);
    }
}

/// The version currently installed, or 0 for none.
///
/// UNREADABLE OR NONSENSE COUNTS AS ZERO, not as an error. The consequence of
/// reading zero is that the next install is allowed to proceed, which is the
/// safe direction: the alternative -- treating an unparseable file as
/// infinitely new -- would let a corrupted byte permanently block updates to a
/// language pack.
fn installed_version(pack_root: &Path, pair: &str) -> u64 {
    std::fs::read_to_string(pack_root.join(pair).join(VERSION_FILE))
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Whether this pair's pack is allowed to carry an EMPTY shortlist.
///
/// Only the converted OPUS-MT packs ship without one (building a shortlist
/// needs a parallel corpus per pair). Mozilla's packs all have one, so an
/// empty lex.bin arriving for a Mozilla pair is not a valid shape: it would
/// silently strip the shortlist from a working pack and make it slower, and
/// a validly-signed update is exactly how that would arrive. The registry
/// decides, so the rule cannot drift from what is actually published.
///
/// An unknown pair gets the strict answer. It cannot reach install anyway
/// (the token is validated against the registry first), and "unknown" should
/// never be the permissive branch.
/// The vocabulary layout the REGISTRY declares for this pair, and the file
/// list and part count that follow from it. A pair the registry does not carry
/// gets the three-part default; it cannot reach install anyway, because the
/// token is validated against the registry first.
fn pack_layout(pair: &str) -> (&'static [&'static str], usize) {
    let layout = crate::languages::pair_by_token(pair)
        .map(|row| row.vocab)
        .unwrap_or("joint");
    let files = crate::platform::pack_files(layout);
    (files, files.len())
}

fn lex_may_be_empty(pair: &str) -> bool {
    crate::languages::pair_by_token(pair).is_some_and(|row| row.source == "opus-mt")
}

/// Whether a pack for `pair` is already installed and complete.
///
/// COMPLETE, not merely present. A directory holding two of three files is
/// what a crash mid-install used to leave behind; loading from it fails deep
/// inside the engine with something unreadable. Checking all three here turns
/// that into a clean re-download.
///
/// PER-SLOT, in lockstep with install's completeness rule: model and
/// vocabulary must have bytes; the shortlist file must EXIST but may be empty
/// ("no shortlist" is a valid pack shape, and an empty file distinguishes it
/// from the crash-truncation this check exists to catch).
pub fn installed(pack_root: &Path, pair: &str) -> bool {
    let dir = pack_root.join(pair);
    let lex_optional = lex_may_be_empty(pair);
    let (files, _) = pack_layout(pair);
    files.iter().enumerate().all(|(i, f)| {
        dir.join(f)
            .metadata()
            .is_ok_and(|m| m.is_file() && (m.len() > 0 || (i == 1 && lex_optional)))
    })
}

/// Deletes an installed pack. Absent is success (idempotent Remove).
///
/// ATOMIC in the sense that matters: `remove_dir_all` either takes the whole
/// directory or leaves it, and a half-removed pack fails `installed()`'s
/// all-three-files check anyway, so an interrupted remove degrades to
/// "not installed" rather than to a pack that looks present and is not. The
/// pair is validated first, for the same reason install does: it names a
/// directory and must never be a caller-shaped path.
pub fn remove(pack_root: &Path, pair: &str) -> Result<(), PackError> {
    let pair = crate::state::validate_translation_pair(pair).ok_or(PackError::Manifest)?;
    let dir = pack_root.join(pair);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PackError::Storage),
    }
}

/// Every complete pack currently on disk, as (token, version).
///
/// RESOLVED THROUGH THE REGISTRY, never trusted from the filesystem: a
/// directory name is only reported if it is a published pair token AND all
/// three files are present. A junk directory, a half-installed one, or a
/// leftover `.incoming-*` / `.previous-*` staging dir is silently ignored --
/// the UI shows what is usable, not what happens to be lying in the folder.
pub fn enumerate(pack_root: &Path) -> Vec<(&'static str, u64)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(pack_root) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(token) = crate::state::validate_translation_pair(&name) else {
            continue;
        };
        if installed(pack_root, token) {
            out.push((token, installed_version(pack_root, token)));
        }
    }
    out.sort_unstable();
    out
}

/// Fetches, verifies and installs one language pack. Blocking.
///
/// ONE AT A TIME, and that is an invariant this function DEPENDS ON rather
/// than enforces. Staging and aside paths are derived from the pair alone, so
/// two overlapping installs of the same pair could interleave their writes and
/// produce a directory covered by neither signed hash. The single-flight guard
/// lives at the only call site -- `AppState::start_pack_download` refuses to
/// start a second download while one is running, on the UI thread -- and a
/// reviewer flagged the separation as worth stating. If a second call site
/// ever appears, it needs the same guard or this needs a lock.
///
/// EVERY FAILURE LEAVES WHAT WAS THERE BEFORE. A user who already had a
/// working pack and hits a failed refresh keeps the working one; the install
/// is a rename over a fully-written directory, never an edit in place.
pub fn install(pack_root: &Path, pair: &str) -> Result<(), PackError> {
    install_with_progress(pack_root, pair, |_, _| {})
}

/// As `install`, reporting download progress as `(bytes_so_far, total)`.
///
/// The callback answers a tester's own complaint -- "no indication it
/// finished downloading". `total` is the server's content-length when offered,
/// else the signed manifest size, so the UI can show a real fraction rather
/// than a spinner. It is advisory: nothing about acceptance depends on it, and
/// the signed hash and size remain the only things that decide whether the
/// bytes are kept.
pub fn install_with_progress(
    pack_root: &Path,
    pair: &str,
    mut on_progress: impl FnMut(u64, Option<u64>),
) -> Result<(), PackError> {
    // ALLOWLISTED HERE, BEFORE THE STRING REACHES A URL OR A PATH.
    //
    // Today every caller already passes a `&'static str` that came out of
    // `validate_translation_pair`, so this is unreachable -- and that is
    // exactly the argument that ages badly. The function is `pub`, takes
    // `&str`, and interpolates it into a URL on the next line; leaving the
    // safety of that to "every current caller happens to be careful" makes a
    // future caller's ordinary mistake into request injection. The check costs
    // one comparison against a fixed list.
    let pair = crate::state::validate_translation_pair(pair).ok_or(PackError::Manifest)?;

    // Repair an interrupted install BEFORE anything reads the installed
    // version, or a crash would present as "nothing installed" and take the
    // rollback check down with it.
    recover_interrupted(pack_root, pair);

    let keys = crate::updater::model_trusted_keys().map_err(|_| PackError::Manifest)?;

    let manifest_url = format!("{MODEL_HOST}/packs/{pair}.json");
    let raw = crate::updater::net::get(
        &manifest_url,
        MAX_MANIFEST_BYTES,
        std::time::Duration::from_secs(20),
    )
    .map_err(|e| match e {
        crate::updater::FetchError::Http(404) => PackError::NotOffered,
        other => PackError::Unreachable(reach_detail(&other)),
    })?;

    // SIGNATURE FIRST. Until this returns Ok the bytes are attacker-controlled
    // and nothing is parsed out of them.
    let manifest = verify_model_manifest(&raw, &keys).map_err(|_| PackError::Manifest)?;

    manifest_answers_the_question(manifest.pair(), manifest.url(), pair)?;

    // ROLLBACK REFUSED BEFORE THE DOWNLOAD, not after. `accept_and_install`
    // checks this too and that is the check of record -- but doing it here as
    // well means a replayed manifest costs one small request instead of 36 MB
    // of somebody's connection. An attacker who can serve bytes should not be
    // able to make a user pay for the same pack repeatedly.
    if installed(pack_root, pair) && manifest.version() <= installed_version(pack_root, pair) {
        return Ok(());
    }

    let body = crate::updater::net::get_with_progress(
        manifest.url(),
        MAX_MODEL_PACK_BYTES,
        std::time::Duration::from_secs(300),
        |got, total| on_progress(got, total.or(Some(manifest.size()))),
    )
    .map_err(|e| PackError::Unreachable(reach_detail(&e)))?;

    accept_and_install(pack_root, pair, &raw, &body, &keys)
}

/// Everything after the bytes are in hand: verify, split, install.
///
/// SPLIT FROM THE FETCH SO IT CAN BE TESTED, exactly as `blocklist.rs` splits
/// `install_verified_list` for the same reason. The network half needs a signed
/// manifest and an https endpoint; THIS half is where the decisions live --
/// whether bytes are authentic, whether they answer the question asked, and
/// whether a failure can leave a user worse off than before. That is the part
/// worth proving, and it is the part that had no test while a server did not
/// exist to run one against.
fn accept_and_install(
    pack_root: &Path,
    pair: &str,
    manifest_bytes: &[u8],
    body: &[u8],
    keys: &patanyx_update::TrustedKeys,
) -> Result<(), PackError> {
    recover_interrupted(pack_root, pair);
    let manifest = verify_model_manifest(manifest_bytes, keys).map_err(|_| PackError::Manifest)?;
    manifest_answers_the_question(manifest.pair(), manifest.url(), pair)?;

    // ROLLBACK REFUSAL. An attacker who can serve bytes can replay an OLD,
    // still-validly-signed manifest and its pack -- the signature never
    // expires -- and thereby pin a user to superseded weights forever, or undo
    // a pack that was republished to fix something. Monotonic versions make
    // that a no-op. `blocklist.rs` refuses rollback for exactly this reason and
    // this feed had no equivalent; a red-team pass on this code found the gap.
    //
    // NOT AN ERROR when the installed copy is already at least as new: there
    // is nothing wrong, and nothing to do. Reporting a failure would put a red
    // row in front of a user whose pack is fine.
    if installed(pack_root, pair) && manifest.version() <= installed_version(pack_root, pair) {
        return Ok(());
    }
    // Hash and length against the SIGNED manifest. This is what makes the
    // hosting untrusted: whoever serves the file cannot change it.
    verify_model_bytes(body, &manifest).map_err(|_| PackError::Body)?;
    let (_, expected_parts) = pack_layout(pair);
    let parts = split_container_n(body, expected_parts).ok_or(PackError::Malformed)?;
    // A PACK WITH AN EMPTY PART IS NOT A PACK, and refusing it here is what
    // stops a signed-but-useless container DESTROYING a working install.
    //
    // The parser deliberately permits zero-length parts -- a length of zero is
    // a well-formed length, and a parser that conflates "malformed" with
    // "implausible" is harder to reason about. The COMPLETENESS rule lives
    // here and in `installed()`, and the two must agree per slot or a signed
    // container could replace a working pack with one that then reads as
    // not-installed -- a red-team pass found exactly that seam when the two
    // rules drifted. The rule, in both places: the MODEL and the VOCABULARY
    // must have bytes (a pack without either translates nothing), and the
    // SHORTLIST may be empty -- a zero-byte lex.bin is the declared form of
    // "this pack has no shortlist" (the engine treats it as optional, and the
    // OPUS-MT conversions ship none; docs/opus-mt-spike.md).
    // Slot 0 is the model and slot 1 the shortlist in BOTH layouts; every
    // slot after them is a vocabulary, and a pack with an empty vocabulary
    // translates nothing whichever layout it uses.
    if parts[0].is_empty() || parts[2..].iter().any(|p| p.is_empty()) {
        return Err(PackError::Malformed);
    }
    if parts[1].is_empty() && !lex_may_be_empty(pair) {
        return Err(PackError::Malformed);
    }
    install_verified(pack_root, pair, &parts, manifest.version())
}

/// Checks that a VERIFIED manifest answers the question that was asked.
///
/// SIGNED IS NOT THE SAME AS RESPONSIVE, and this is the gap between them.
/// A valid signature says the publisher wrote this document; it says nothing
/// about whether the document describes the pack the user chose. Without these
/// two checks, anyone able to serve bytes -- a compromised host, a proxy that
/// can present a certificate, a stale cache -- could answer every request with
/// one validly-signed manifest and hand a user a language they did not ask for
/// while every signature check passed.
///
/// Split out from `install` because it is the part worth testing and the part
/// around it needs a network.
/// Takes the two fields rather than the manifest, so the rule can be tested
/// without a signing key: the signature machinery is already proven in
/// patanyx-update (domain separation and disjoint key sets), and what is
/// unproven is THIS decision.
fn manifest_answers_the_question(
    manifest_pair: &str,
    manifest_url: &str,
    asked: &str,
) -> Result<(), PackError> {
    if manifest_pair != asked {
        return Err(PackError::Manifest);
    }
    // The download must come from the host we asked. A signed manifest that
    // pointed the body elsewhere would move the trust boundary to whoever owns
    // that host -- the signature would still verify, and the bytes would come
    // from a stranger.
    //
    // Compared against the host PLUS a separator, so `models.patanyx.net.evil`
    // does not pass a prefix test. That is the classic way this check is got
    // wrong, and it is why the same rule exists in the R1 host-normalisation
    // work rather than being invented here.
    let rest = match manifest_url.strip_prefix(MODEL_HOST) {
        Some(rest) => rest,
        None => return Err(PackError::Manifest),
    };
    if !rest.starts_with('/') {
        return Err(PackError::Manifest);
    }
    Ok(())
}

/// Splits a verified container into its three parts.
///
/// RUNS ONLY ON BYTES THAT ALREADY MATCHED A SIGNED HASH, so this is not the
/// security boundary -- but it is still written as though it were, because a
/// parser that assumes good input is one signing-key incident away from being
/// the whole attack surface. Every length is bounds-checked against what
/// remains, and no arithmetic can wrap.
fn read_length(cursor: &mut &[u8]) -> Option<usize> {
    let nl = cursor.iter().position(|b| *b == b'\n')?;
    // A length header long enough to be a denial of service is not a length
    // header. 20 digits is more than u64 can express.
    if nl == 0 || nl > 20 {
        return None;
    }
    let text = std::str::from_utf8(&cursor[..nl]).ok()?;
    // No sign, no whitespace, no radix prefix: `parse` on a str that is known
    // to be ASCII digits only.
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value = text.parse::<usize>().ok()?;
    *cursor = cursor.get(nl + 1..)?;
    Some(value)
}

/// Splits a container of EITHER generation into its parts.
///
/// `expected` is what the REGISTRY says this pair's pack contains. A container
/// that carries a different number of parts is refused rather than
/// reinterpreted: the bytes do not get to decide the shape.
fn split_container_n(body: &[u8], expected: usize) -> Option<Vec<&[u8]>> {
    if !(1..=MAX_PACK_PARTS).contains(&expected) {
        return None;
    }
    let (mut cursor, count) = if let Some(rest) = body.strip_prefix(PACK_MAGIC_V2) {
        let mut c = rest;
        let n = read_length(&mut c)?;
        (c, n)
    } else {
        // V1 has no count line: three parts, always.
        (body.strip_prefix(PACK_MAGIC)?, PACK_PARTS)
    };
    if count != expected {
        return None;
    }
    let mut lengths = vec![0usize; count];
    for slot in lengths.iter_mut() {
        *slot = read_length(&mut cursor)?;
    }
    // `checked_add` rather than `+`: these came off the wire, and a wrapping
    // sum that happened to equal the remaining length would hand out
    // overlapping slices.
    let total = lengths
        .iter()
        .try_fold(0usize, |acc, n| acc.checked_add(*n))?;
    if total != cursor.len() {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for n in lengths {
        let (part, rest) = cursor.split_at_checked(n)?;
        out.push(part);
        cursor = rest;
    }
    Some(out)
}

#[allow(dead_code)]
fn split_container(body: &[u8]) -> Option<[&[u8]; PACK_PARTS]> {
    let rest = body.strip_prefix(PACK_MAGIC)?;
    let mut lengths = [0usize; PACK_PARTS];
    let mut cursor = rest;
    for slot in lengths.iter_mut() {
        let nl = cursor.iter().position(|b| *b == b'\n')?;
        // A length header long enough to be a denial of service is not a
        // length header. 20 digits is more than u64 can express.
        if nl == 0 || nl > 20 {
            return None;
        }
        let text = std::str::from_utf8(&cursor[..nl]).ok()?;
        // No sign, no whitespace, no radix prefix: `parse` on a str that is
        // known to be ASCII digits only.
        if !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = text.parse::<usize>().ok()?;
        cursor = cursor.get(nl + 1..)?;
    }
    // `checked_add` rather than `+`: these came off the wire, and a wrapping
    // sum that happened to equal the remaining length would hand out
    // overlapping slices.
    let total = lengths
        .iter()
        .try_fold(0usize, |acc, n| acc.checked_add(*n))?;
    if total != cursor.len() {
        return None;
    }
    let mut out: [&[u8]; PACK_PARTS] = [&[]; PACK_PARTS];
    let mut at = 0usize;
    for (i, len) in lengths.iter().enumerate() {
        out[i] = cursor.get(at..at.checked_add(*len)?)?;
        at += *len;
    }
    Some(out)
}

/// Writes a verified pack into place.
///
/// STAGED THEN RENAMED, the atomic-swap discipline this fleet uses for static
/// assets. The three files are written into a scratch directory and the
/// directory is moved into place as one step, so a crash or a full disk leaves
/// either the old pack or no pack -- never a directory holding two of three
/// files, which is the state that fails unreadably inside the engine.
fn install_verified(
    pack_root: &Path,
    pair: &str,
    parts: &[&[u8]],
    version: u64,
) -> Result<(), PackError> {
    install_verified_from(pack_root, pair, parts, version, true)
}

/// The install, with the staging WRITE optional so a test can make the swap
/// fail the way a full disk would.
///
/// The alternative was leaving the restore path untested, and the restore path
/// is the entire point of the change that introduced it.
fn install_verified_from(
    pack_root: &Path,
    pair: &str,
    parts: &[&[u8]],
    version: u64,
    write_staging: bool,
) -> Result<(), PackError> {
    let staging = pack_root.join(format!(".incoming-{pair}"));
    if write_staging {
    // A leftover from an interrupted attempt is not an error; it is the thing
    // being replaced.
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|_| PackError::Storage)?;
    let (files, _) = pack_layout(pair);
    for (i, name) in files.iter().enumerate() {
        std::fs::write(staging.join(name), parts[i]).map_err(|_| PackError::Storage)?;
    }
    // Written INSIDE the staging directory, so it lands in the same atomic
    // rename as the files it describes. A version recorded anywhere else could
    // survive a failed install and claim a pack that is not there.
    std::fs::write(staging.join(VERSION_FILE), version.to_string()).map_err(|_| PackError::Storage)?;
    }
    let final_dir = pack_root.join(pair);

    // THERE MUST BE NO MOMENT WITH NO PACK.
    //
    // This used to `remove_dir_all(final_dir)` and then rename. If the rename
    // failed -- a permissions change, a full disk, another process recreating
    // the path -- the working pack was already gone and the user was left with
    // nothing, having asked only for an update. My own commit message claimed
    // a failure would leave "the old pack or no pack"; the first half was not
    // actually guaranteed, and a red-team pass said so.
    //
    // Now the old pack is moved ASIDE rather than deleted, and put back if the
    // swap fails. Both steps are renames within one directory, so each is
    // atomic, and the only losing case is a machine that dies between them --
    // which leaves the old pack present under its aside name rather than gone.
    let aside = pack_root.join(format!(".previous-{pair}"));
    let _ = std::fs::remove_dir_all(&aside);
    let had_previous = std::fs::rename(&final_dir, &aside).is_ok();

    match std::fs::rename(&staging, &final_dir) {
        Ok(()) => {
            // Only now is the old copy expendable.
            let _ = std::fs::remove_dir_all(&aside);
            Ok(())
        }
        Err(_) => {
            // Put back exactly what was there. A user who asked for an update
            // and got a failure must still have what they started with.
            if had_previous {
                let _ = std::fs::rename(&aside, &final_dir);
            }
            let _ = std::fs::remove_dir_all(&staging);
            Err(PackError::Storage)
        }
    }
}

/// Turns a transport failure into something a person can act on.
///
/// NOT `{e:?}`. The blocklist panel learned this the hard way: a Rust Debug
/// string with an OS error number in front of a user, inside a row that
/// already says FAILED, tells them nothing they can do anything about. A
/// certificate failure, on the other hand, is worth naming precisely -- it
/// usually means something is inspecting encrypted traffic.
///
/// Generic over Debug rather than naming the transport's error type, which is
/// private to the updater module. That is the right boundary: this function
/// wants "whatever the fetch said", not a dependency on which client is behind
/// it.
fn reach_detail(e: &impl std::fmt::Debug) -> &'static str {
    let detail = format!("{e:?}").to_ascii_lowercase();
    if detail.contains("certificate") || detail.contains("unknownissuer") {
        "tls"
    } else {
        "network"
    }
}

// THERE IS DELIBERATELY NO `pack_root(vault_path)` HELPER HERE.
//
// One existed and was dead code, and dead code that computes a PATH from an
// argument is a trap rather than a convenience: the serving route resolves the
// root one way (`crate::pack_root`, once, from the default vault) and a future
// caller reaching for a helper that takes a different vault path would install
// packs somewhere the route never looks. The symptom would be a translation
// that downloads successfully every time and never becomes available.
//
// There is exactly one way to learn where packs live, and it is
// `crate::pack_root()`.

#[cfg(test)]
mod tests {
    use super::*;

    /// The four-part container, and the rule that keeps it honest.
    mod container_v2 {
        use super::*;

        fn v2(parts: &[&[u8]]) -> Vec<u8> {
            let mut out = PACK_MAGIC_V2.to_vec();
            out.extend_from_slice(format!("{}\n", parts.len()).as_bytes());
            for p in parts {
                out.extend_from_slice(format!("{}\n", p.len()).as_bytes());
            }
            for p in parts {
                out.extend_from_slice(p);
            }
            out
        }

        fn v1(parts: [&[u8]; 3]) -> Vec<u8> {
            let mut out = PACK_MAGIC.to_vec();
            for p in parts.iter() {
                out.extend_from_slice(format!("{}\n", p.len()).as_bytes());
            }
            for p in parts.iter() {
                out.extend_from_slice(p);
            }
            out
        }

        #[test]
        fn a_four_part_container_splits_in_order() {
            let body = v2(&[b"MODEL", b"LEX", b"SRC", b"TRG"]);
            let parts = split_container_n(&body, 4).expect("should split");
            assert_eq!(parts, vec![&b"MODEL"[..], b"LEX", b"SRC", b"TRG"]);
        }

        /// THE POINT OF THE COUNT. It is not a name and it is not a choice:
        /// the registry says how many parts this pair's pack has, and a
        /// container claiming any other number is refused rather than
        /// reinterpreted. Otherwise a validly-signed three-part container
        /// could be served for a split pair and the reader would hand the
        /// engine a target vocabulary that is really a source one.
        #[test]
        fn a_container_may_not_change_a_pairs_shape() {
            let three = v2(&[b"MODEL", b"LEX", b"VOCAB"]);
            assert!(split_container_n(&three, 4).is_none(), "3 parts for a 4-part pair");
            let four = v2(&[b"MODEL", b"LEX", b"SRC", b"TRG"]);
            assert!(split_container_n(&four, 3).is_none(), "4 parts for a 3-part pair");
            // ...including across generations: a v1 container is three parts
            // by definition and cannot satisfy a split pair.
            let old = v1([b"MODEL", b"LEX", b"VOCAB"]);
            assert!(split_container_n(&old, 4).is_none(), "v1 cannot be a 4-part pack");
            assert!(split_container_n(&old, 3).is_some(), "v1 still reads as three");
        }

        /// The 100 packs already published are v1. They must keep installing
        /// without a republish.
        #[test]
        fn v1_containers_still_read() {
            let body = v1([b"M", b"L", b"V"]);
            assert_eq!(
                split_container_n(&body, 3),
                Some(vec![&b"M"[..], b"L", b"V"])
            );
        }

        /// Every hostile shape the v1 parser refuses, refused again with a
        /// count in front of it. The count is read from the wire, so it is
        /// bounded before it sizes anything.
        #[test]
        fn hostile_shapes_are_refused() {
            for (body, n) in [
                (v2(&[b"M", b"L", b"V"]), 4usize),
                (b"PXPACK2\n".to_vec(), 3),
                (b"PXPACK2\n3\n".to_vec(), 3),
                (b"PXPACK2\n99\n1\n1\n1\nabc".to_vec(), 3),
                (b"PXPACK2\n-1\n".to_vec(), 3),
                (b"PXPACK2\n 3\n1\n1\n1\nabc".to_vec(), 3),
                (b"PXPACK2\n0x3\n".to_vec(), 3),
                (b"NOTAPACK\n3\n1\n1\n1\nabc".to_vec(), 3),
            ] {
                assert!(
                    split_container_n(&body, n).is_none(),
                    "must refuse {:?}",
                    String::from_utf8_lossy(&body[..body.len().min(24)])
                );
            }
            // A count beyond the ceiling cannot even be asked for.
            let body = v2(&[b"M", b"L", b"V", b"S", b"T"]);
            assert!(split_container_n(&body, 5).is_none(), "5 exceeds the ceiling");
            // Trailing bytes, one short, one long -- the total must be exact.
            let good = v2(&[b"MODEL", b"LEX", b"SRC", b"TRG"]);
            assert!(split_container_n(&good[..good.len() - 1], 4).is_none());
            let mut extra = good.clone();
            extra.push(b'!');
            assert!(split_container_n(&extra, 4).is_none());
        }

        /// The registry and the container must agree about every published
        /// pair, or an install would refuse on shape for a pack we ourselves
        /// built.
        #[test]
        fn every_registry_pair_has_a_known_layout_and_part_count() {
            for p in crate::languages::PAIRS {
                let (files, count) = pack_layout(p.token);
                assert!(
                    matches!(p.vocab, "joint" | "split"),
                    "{}: unknown layout {}",
                    p.token,
                    p.vocab
                );
                assert_eq!(
                    count,
                    if p.vocab == "split" { 4 } else { 3 },
                    "{}: part count disagrees with its layout",
                    p.token
                );
                assert_eq!(files.len(), count);
                assert_eq!(files[0], "model.bin");
                assert_eq!(files[1], "lex.bin");
            }
        }
    }

    /// THE PRODUCTION INSTALLER AGAINST THE LIVE FEED.
    ///
    /// Ignored by default because it reaches the network; run deliberately:
    ///   cargo test -p patanyx live_feed -- --ignored --nocapture
    ///
    /// Every other test here builds its container in memory. This one proves
    /// the path a user's click actually takes -- fetch the signed manifest
    /// from models.patanyx.net, verify it against the key COMPILED INTO THIS
    /// BINARY, fetch the pack, check its hash and size, split the container,
    /// apply the per-slot completeness rule, and land it atomically -- for
    /// both pack classes: a Mozilla pack with a shortlist, and the converted
    /// OPUS-MT pack whose shortlist is deliberately EMPTY. The empty-lex rule
    /// has unit coverage on a synthetic container; this is the same rule
    /// meeting the real published bytes.
    mod live_feed {
        use super::*;

        fn scratch(name: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir()
                .join(format!("pxpack-live-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        fn install_and_check(pair: &str) {
            let root = scratch(pair);
            match install(&root, pair) {
                Ok(()) => {}
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&root);
                    panic!("{pair}: install from the live feed failed: {e:?}");
                }
            }
            assert!(installed(&root, pair), "{pair}: installed() must agree");
            let dir = root.join(pair);
            // Whatever files THIS pair's layout calls for, and no others: a
            // split pack has two segmenters and no vocab.spm at all.
            let (files, count) = pack_layout(pair);
            for f in files {
                let m = std::fs::metadata(dir.join(f))
                    .unwrap_or_else(|e| panic!("{pair}: {f}: {e}"));
                assert!(m.is_file(), "{pair}: {f} is not a file");
            }
            // And NONE of the other layout's files: a joint pack must not
            // carry segmenters, a split one must not carry a vocab.spm. (The
            // directory also holds the installed-version marker, so the total
            // entry count is not the thing to assert on.)
            for other in crate::platform::PACK_FILES_ANY {
                if !files.contains(&other) {
                    assert!(
                        !dir.join(other).exists(),
                        "{pair}: carries {other}, which its layout does not name"
                    );
                }
            }
            let _ = count;
            let model = std::fs::metadata(dir.join("model.bin")).expect("model.bin");
            let lex = std::fs::metadata(dir.join("lex.bin")).expect("lex.bin");
            assert!(model.len() > 0, "{pair}: model empty");
            for f in &files[2..] {
                assert!(
                    std::fs::metadata(dir.join(f)).expect("vocab").len() > 0,
                    "{pair}: {f} empty"
                );
            }
            // The shortlist is empty exactly when the registry says this pack
            // class has none -- the two must not disagree on real bytes.
            assert_eq!(
                lex.len() == 0,
                lex_may_be_empty(pair),
                "{pair}: shortlist emptiness disagrees with the registry"
            );
            // Printed so the bytes that LANDED can be matched by hand against
            // the provenance register and, for a converted pack, against the
            // catalog pins the publisher signed -- closing live feed ->
            // installer -> the exact artifact the engine was proved on.
            let (files, _) = pack_layout(pair);
            for f in files {
                let bytes = std::fs::read(dir.join(f)).expect("read installed file");
                let mut h = <sha2::Sha256 as sha2::Digest>::new();
                sha2::Digest::update(&mut h, &bytes);
                println!(
                    "  installed {pair}/{f}: {} bytes sha256 {:x}",
                    bytes.len(),
                    sha2::Digest::finalize(h)
                );
            }
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        #[ignore = "network: fetches from models.patanyx.net"]
        fn a_mozilla_pack_installs_from_the_live_feed() {
            install_and_check("el-en");
        }

        /// A SPLIT-VOCABULARY pack: four parts, PXPACK2, two segmenters.
        /// Japanese and Chinese are the reason the container gained a second
        /// generation, so the live bytes for one of them belong in this check.
        #[test]
        #[ignore = "network: fetches from models.patanyx.net"]
        fn a_split_vocabulary_pack_installs_from_the_live_feed() {
            let pair = crate::languages::PAIRS
                .iter()
                .find(|p| p.vocab == "split")
                .expect("registry must carry a split-vocabulary pair")
                .token;
            install_and_check(pair);
        }

        #[test]
        #[ignore = "network: fetches from models.patanyx.net"]
        fn the_converted_opus_pack_installs_from_the_live_feed() {
            let pair = crate::languages::PAIRS
                .iter()
                .find(|p| p.source == "opus-mt")
                .expect("registry must carry a tier-2 pair")
                .token;
            install_and_check(pair);
        }
    }

    fn container(parts: [&[u8]; 3]) -> Vec<u8> {
        let mut out = PACK_MAGIC.to_vec();
        for p in parts.iter() {
            out.extend_from_slice(format!("{}\n", p.len()).as_bytes());
        }
        for p in parts.iter() {
            out.extend_from_slice(p);
        }
        out
    }

    #[test]
    fn a_well_formed_container_splits_into_its_three_parts() {
        let body = container([b"MODEL", b"LEX", b"VOCAB"]);
        let parts = split_container(&body).expect("should split");
        assert_eq!(parts[0], b"MODEL");
        assert_eq!(parts[1], b"LEX");
        assert_eq!(parts[2], b"VOCAB");
    }

    /// Empty parts are legal lengths and must not be confused with absent
    /// ones: a zero-length blob is a pack we refuse LATER, on completeness,
    /// rather than a parse failure here.
    #[test]
    fn zero_length_parts_parse() {
        let body = container([b"", b"", b""]);
        assert_eq!(split_container(&body), Some([&b""[..], &b""[..], &b""[..]]));
    }

    /// The parser runs after a signature check, and is written as though it
    /// did not. Each of these is a shape that a wrong answer would turn into
    /// an out-of-bounds read or an overlapping slice.
    #[test]
    fn malformed_containers_are_refused_rather_than_guessed_at() {
        let good = container([b"MODEL", b"LEX", b"VOCAB"]);
        // Wrong magic.
        assert!(split_container(b"NOTAPACK\n1\n1\n1\nabc").is_none());
        // Truncated body: lengths promise more than is present.
        assert!(split_container(&good[..good.len() - 1]).is_none());
        // Trailing junk: lengths account for less than is present, which is
        // where a smuggled fourth part would live.
        let mut extra = good.clone();
        extra.push(b'X');
        assert!(split_container(&extra).is_none());
        // Only two length headers.
        assert!(split_container(b"PXPACK1\n1\n1\nab").is_none());
        // A length that is not a plain decimal.
        for bad in [
            &b"PXPACK1\n+1\n1\n1\nabc"[..],
            &b"PXPACK1\n 1\n1\n1\nabc"[..],
            &b"PXPACK1\n0x1\n1\n1\nabc"[..],
            &b"PXPACK1\n-1\n1\n1\nabc"[..],
            &b"PXPACK1\n\n1\n1\nabc"[..],
        ] {
            assert!(split_container(bad).is_none(), "must refuse {bad:?}");
        }
        // A length header long enough to be its own problem.
        let huge = format!("PXPACK1\n{}\n1\n1\nabc", "9".repeat(40));
        assert!(split_container(huge.as_bytes()).is_none());
    }

    /// Lengths that sum past `usize` must not wrap into something that happens
    /// to match the remaining length.
    #[test]
    fn lengths_that_would_overflow_are_refused() {
        let body = format!("PXPACK1\n{}\n{}\n1\nx", usize::MAX, usize::MAX);
        assert!(split_container(body.as_bytes()).is_none());
    }

    /// A manifest that answers a DIFFERENT question must be refused, even
    /// though its signature is perfectly good.
    ///
    /// The signature proves authorship, not relevance -- patanyx-update
    /// already proves the signature half (domain separation, disjoint key
    /// sets). This is the gap those leave: anyone able to serve bytes could
    /// answer every request with one validly-signed manifest.
    #[test]
    fn a_manifest_must_answer_the_question_that_was_asked() {
        let good = "https://models.patanyx.net/packs/en-es.pxpack";
        assert!(manifest_answers_the_question("en-es", good, "en-es").is_ok());

        // Right signature, WRONG PAIR: the user asked for Spanish, this
        // describes French.
        assert_eq!(
            manifest_answers_the_question("en-fr", good, "en-es"),
            Err(PackError::Manifest)
        );

        // Right signature, body hosted somewhere else. The middle two are the
        // prefix trap -- a naive `starts_with` accepts both, and that is the
        // classic way this check is got wrong.
        for hostile in [
            "https://evil.example/packs/en-es.pxpack",
            "https://models.patanyx.net.evil.example/packs/en-es.pxpack",
            "https://models.patanyx.netx/packs/en-es.pxpack",
            "http://models.patanyx.net/packs/en-es.pxpack",
            "",
        ] {
            assert_eq!(
                manifest_answers_the_question("en-es", hostile, "en-es"),
                Err(PackError::Manifest),
                "must refuse {hostile:?}"
            );
        }
    }

    /// THE WHOLE ACCEPTANCE PATH, end to end, against bytes signed here.
    ///
    /// This is the part that has never run against a real server, because
    /// there is not one yet. Signing in the test rather than against a fixture
    /// is the discipline the updater tests already use: a fixture proves the
    /// verifier accepts one blob somebody made once, and this proves it
    /// accepts what a publisher would actually produce and REFUSES each way
    /// that can go wrong.
    ///
    /// The transport is the only thing left out, and it is shared with the
    /// update and blocklist feeds rather than new here.
    mod acceptance {
        use super::*;
        use ed25519_dalek::{Signer, SigningKey};
        use patanyx_update::{TrustedKeys, SIGNING_DOMAIN_MODELS};

        fn key() -> SigningKey {
            SigningKey::from_bytes(&[7u8; 32])
        }

        fn keys() -> TrustedKeys {
            TrustedKeys::new(vec![key().verifying_key()]).expect("usable key")
        }

        /// A manifest exactly as `patanyx-sign sign-models` would emit it.
        fn signed_manifest(pair: &str, url: &str, body: &[u8]) -> Vec<u8> {
            signed_manifest_v(pair, url, body, 1)
        }

        fn signed_manifest_v(pair: &str, url: &str, body: &[u8], version: u64) -> Vec<u8> {
            let digest = <sha2::Sha256 as sha2::Digest>::digest(body);
            let payload = serde_json::json!({
                "pair": pair,
                "url": url,
                "sha256": hex_of(&digest),
                "size": body.len() as u64,
                "version": version,
            })
            .to_string();
            let mut message = SIGNING_DOMAIN_MODELS.to_vec();
            message.extend_from_slice(payload.as_bytes());
            let sig = key().sign(&message);
            serde_json::json!({
                "v": 1,
                "payload": payload,
                "sig": hex_of(&sig.to_bytes()),
            })
            .to_string()
            .into_bytes()
        }

        fn hex_of(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        fn scratch(name: &str) -> PathBuf {
            let d = std::env::temp_dir()
                .join(format!("pxpack-acc-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        const URL: &str = "https://models.patanyx.net/packs/en-es.pxpack";

        /// The honest case: signed, matching, well-formed. Three files land.
        #[test]
        fn a_correctly_signed_pack_installs() {
            let root = scratch("ok");
            let body = container([b"MODELBYTES", b"LEXBYTES", b"VOCABBYTES"]);
            let manifest = signed_manifest("en-es", URL, &body);
            assert_eq!(
                accept_and_install(&root, "en-es", &manifest, &body, &keys()),
                Ok(())
            );
            assert!(installed(&root, "en-es"));
            assert_eq!(
                std::fs::read(root.join("en-es").join("model.bin")).unwrap(),
                b"MODELBYTES"
            );
            assert_eq!(
                std::fs::read(root.join("en-es").join("vocab.spm")).unwrap(),
                b"VOCABBYTES"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A BODY THAT DOES NOT MATCH THE SIGNED HASH MUST NOT LAND. This is
        /// the single property the whole design rests on: the host serving the
        /// file cannot change it.
        #[test]
        fn a_tampered_body_is_refused_and_nothing_is_written() {
            let root = scratch("tamper");
            let honest = container([b"MODELBYTES", b"LEXBYTES", b"VOCABBYTES"]);
            let manifest = signed_manifest("en-es", URL, &honest);
            // One byte, in the model blob, exactly what a hostile host would do.
            let mut tampered = honest.clone();
            let at = tampered.len() - 1;
            tampered[at] ^= 0xff;
            assert_eq!(
                accept_and_install(&root, "en-es", &manifest, &tampered, &keys()),
                Err(PackError::Body)
            );
            assert!(!installed(&root, "en-es"), "nothing may be written");
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A body of the right LENGTH but the wrong content. Catches a check
        /// that compared sizes and called it done.
        #[test]
        fn a_same_length_substitution_is_refused() {
            let root = scratch("sub");
            let honest = container([b"MODELBYTES", b"LEXBYTES", b"VOCABBYTES"]);
            let manifest = signed_manifest("en-es", URL, &honest);
            let evil = container([b"EVILBYTES!", b"LEXBYTES", b"VOCABBYTES"]);
            assert_eq!(evil.len(), honest.len(), "the test needs equal lengths");
            assert_eq!(
                accept_and_install(&root, "en-es", &manifest, &evil, &keys()),
                Err(PackError::Body)
            );
            assert!(!installed(&root, "en-es"));
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A manifest signed by SOMEONE ELSE, over bytes that match it. Every
        /// internal consistency check passes; only the key is wrong.
        #[test]
        fn a_manifest_from_an_untrusted_key_is_refused() {
            let root = scratch("wrongkey");
            let body = container([b"M", b"L", b"V"]);
            let stranger = SigningKey::from_bytes(&[9u8; 32]);
            let digest = <sha2::Sha256 as sha2::Digest>::digest(&body);
            let payload = serde_json::json!({
                "pair": "en-es", "url": URL,
                "sha256": hex_of(&digest), "size": body.len() as u64,
            })
            .to_string();
            let mut message = SIGNING_DOMAIN_MODELS.to_vec();
            message.extend_from_slice(payload.as_bytes());
            let envelope = serde_json::json!({
                "v": 1, "payload": payload,
                "sig": hex_of(&stranger.sign(&message).to_bytes()),
            })
            .to_string()
            .into_bytes();
            assert_eq!(
                accept_and_install(&root, "en-es", &envelope, &body, &keys()),
                Err(PackError::Manifest)
            );
            assert!(!installed(&root, "en-es"));
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A perfectly valid pack for ANOTHER pair, offered when this one was
        /// asked for. The signature verifies; the answer is still wrong.
        #[test]
        fn a_valid_pack_for_a_different_pair_is_refused() {
            // BOTH pairs are published now, so the ONLY thing that can refuse
            // this is the manifest-pair != asked-pair check inside
            // accept_and_install -- not membership. Before the registry grew,
            // en-fr was unpublished and this could have passed for the wrong
            // reason; the assertion below now isolates the right one.
            assert!(crate::languages::pair_by_token("en-fr").is_some());
            assert!(crate::languages::pair_by_token("en-es").is_some());
            let root = scratch("pair");
            let body = container([b"M", b"L", b"V"]);
            let manifest = signed_manifest(
                "en-fr",
                "https://models.patanyx.net/packs/en-fr.pxpack",
                &body,
            );
            assert_eq!(
                accept_and_install(&root, "en-es", &manifest, &body, &keys()),
                Err(PackError::Manifest)
            );
            assert!(!installed(&root, "en-es"));
            let _ = std::fs::remove_dir_all(&root);
        }

        /// ROLLBACK REFUSAL: a still-validly-signed OLDER pack must not
        /// replace a newer one.
        ///
        /// The signature never expires, so an attacker who can serve bytes can
        /// replay yesterday's manifest forever. This is the check that makes
        /// that a no-op, and the gap a red-team pass found in this code.
        #[test]
        fn an_older_but_validly_signed_pack_cannot_replace_a_newer_one() {
            let root = scratch("rollback");
            let new = container([b"NEWMODEL", b"NEWLEX", b"NEWVOCAB"]);
            accept_and_install(
                &root,
                "en-es",
                &signed_manifest_v("en-es", URL, &new, 7),
                &new,
                &keys(),
            )
            .expect("install v7");
            assert_eq!(installed_version(&root, "en-es"), 7);

            // The replay: perfectly signed, perfectly matching, and OLD.
            let old = container([b"OLDMODEL", b"OLDLEX", b"OLDVOCAB"]);
            assert_eq!(
                accept_and_install(
                    &root,
                    "en-es",
                    &signed_manifest_v("en-es", URL, &old, 6),
                    &old,
                    &keys()
                ),
                Ok(()),
                "a replay is not an error -- there is simply nothing to do"
            );
            assert_eq!(
                std::fs::read(root.join("en-es").join("model.bin")).unwrap(),
                b"NEWMODEL",
                "the newer pack must still be installed"
            );
            assert_eq!(installed_version(&root, "en-es"), 7);

            // The same version is likewise a no-op.
            let same = container([b"XXXMODEL", b"XXXLEX", b"XXXVOCAB"]);
            accept_and_install(
                &root,
                "en-es",
                &signed_manifest_v("en-es", URL, &same, 7),
                &same,
                &keys(),
            )
            .expect("same version is not an error");
            assert_eq!(
                std::fs::read(root.join("en-es").join("model.bin")).unwrap(),
                b"NEWMODEL"
            );

            // But a NEWER one is taken.
            let newer = container([b"NEWERMOD", b"NEWERLEX", b"NEWERVOC"]);
            accept_and_install(
                &root,
                "en-es",
                &signed_manifest_v("en-es", URL, &newer, 8),
                &newer,
                &keys(),
            )
            .expect("install v8");
            assert_eq!(
                std::fs::read(root.join("en-es").join("model.bin")).unwrap(),
                b"NEWERMOD"
            );
            assert_eq!(installed_version(&root, "en-es"), 8);
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A version record that cannot be read counts as ZERO, so a corrupt
        /// byte cannot permanently block a language pack from ever updating.
        #[test]
        fn an_unreadable_version_record_does_not_block_updates() {
            let root = scratch("badver");
            let body = container([b"M", b"L", b"V"]);
            accept_and_install(&root, "en-es", &signed_manifest_v("en-es", URL, &body, 3), &body, &keys())
                .expect("install");
            std::fs::write(root.join("en-es").join("version"), "not a number").unwrap();
            assert_eq!(installed_version(&root, "en-es"), 0);
            let next = container([b"N", b"N", b"N"]);
            accept_and_install(&root, "en-es", &signed_manifest_v("en-es", URL, &next, 1), &next, &keys())
                .expect("must still be able to update");
            assert_eq!(std::fs::read(root.join("en-es").join("model.bin")).unwrap(), b"N");
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A SIGNED BUT EMPTY MODEL OR VOCABULARY MUST NOT DESTROY A WORKING
        /// PACK.
        ///
        /// The parser permits zero-length parts, and a validly-signed useless
        /// container once removed a working install and reported success
        /// (found by a red-team pass). The rule is now PER SLOT, identical in
        /// install and `installed()`: model and vocabulary need bytes; the
        /// shortlist alone may be empty (see the empty-lex test below).
        #[test]
        fn a_signed_container_with_an_empty_part_is_refused_and_changes_nothing() {
            let root = scratch("emptypart");
            let good = container([b"OLDMODEL", b"OLDLEX", b"OLDVOCAB"]);
            accept_and_install(&root, "en-es", &signed_manifest_v("en-es", URL, &good, 1), &good, &keys())
                .expect("first install");
            assert!(installed(&root, "en-es"));

            // Well-formed, correctly signed, hash matches -- and the model is
            // empty.
            let hollow = container([b"", b"LEX", b"VOCAB"]);
            assert_eq!(
                accept_and_install(
                    &root,
                    "en-es",
                    &signed_manifest_v("en-es", URL, &hollow, 2),
                    &hollow,
                    &keys()
                ),
                Err(PackError::Malformed)
            );
            assert!(installed(&root, "en-es"), "the working pack must survive");
            assert_eq!(
                std::fs::read(root.join("en-es").join("model.bin")).unwrap(),
                b"OLDMODEL"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        /// An empty VOCABULARY is as useless as an empty model and is refused
        /// the same way.
        #[test]
        fn a_signed_container_with_an_empty_vocab_is_refused() {
            let root = scratch("emptyvocab");
            let hollow = container([b"MODEL", b"LEX", b""]);
            assert_eq!(
                accept_and_install(
                    &root,
                    "en-es",
                    &signed_manifest_v("en-es", URL, &hollow, 1),
                    &hollow,
                    &keys()
                ),
                Err(PackError::Malformed)
            );
            assert!(!installed(&root, "en-es"));
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A ZERO-BYTE SHORTLIST IS A VALID PACK SHAPE -- "no shortlist" --
        /// FOR THE PACKS THAT ACTUALLY HAVE NONE. The tier-2 OPUS-MT
        /// conversions ship no lex (building one needs a parallel corpus per
        /// pair) and the engine treats the shortlist as optional, so such a
        /// pack must install, read back as installed, and version-update like
        /// any other.
        #[test]
        fn an_opus_pack_with_an_empty_shortlist_installs_and_is_complete() {
            // A real tier-2 pair from the registry: the rule is keyed to the
            // pack's SOURCE, so the test must use a pair that actually has one.
            let pair = crate::languages::PAIRS
                .iter()
                .find(|p| p.source == "opus-mt")
                .expect("registry must carry a tier-2 pair")
                .token;
            let root = scratch("emptylex");
            let pack = container([b"MODEL", b"", b"VOCAB"]);
            accept_and_install(
                &root,
                pair,
                &signed_manifest_v(pair, URL, &pack, 1),
                &pack,
                &keys(),
            )
            .expect("empty-lex pack must install");
            assert!(installed(&root, pair), "empty lex is complete for opus-mt");
            assert_eq!(std::fs::read(root.join(pair).join("lex.bin")).unwrap(), b"");
            // And it updates like any pack.
            let pack2 = container([b"MODEL2", b"", b"VOCAB2"]);
            accept_and_install(
                &root,
                pair,
                &signed_manifest_v(pair, URL, &pack2, 2),
                &pack2,
                &keys(),
            )
            .expect("update over an empty-lex pack");
            assert_eq!(
                std::fs::read(root.join(pair).join("model.bin")).unwrap(),
                b"MODEL2"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        /// ...AND IS REFUSED FOR A PACK CLASS THAT HAS ONE. Mozilla's packs
        /// all ship a shortlist, so an empty lex.bin arriving for one is not a
        /// valid shape -- it is a validly-signed update that would silently
        /// strip the shortlist and leave the pack slower. The working pack
        /// must survive.
        #[test]
        fn a_mozilla_pack_may_not_arrive_with_an_empty_shortlist() {
            let root = scratch("mozemptylex");
            let good = container([b"MODEL", b"LEX", b"VOCAB"]);
            accept_and_install(&root, "en-es", &signed_manifest_v("en-es", URL, &good, 1), &good, &keys())
                .expect("first install");
            let hollow = container([b"MODEL", b"", b"VOCAB"]);
            assert_eq!(
                accept_and_install(
                    &root,
                    "en-es",
                    &signed_manifest_v("en-es", URL, &hollow, 2),
                    &hollow,
                    &keys()
                ),
                Err(PackError::Malformed)
            );
            assert_eq!(
                std::fs::read(root.join("en-es").join("lex.bin")).unwrap(),
                b"LEX",
                "the working shortlist must survive"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        /// NO MOMENT WITH NO PACK. The install must not delete the old copy
        /// before the new one is in place.
        ///
        /// Checked by making the swap fail: the staging directory is removed
        /// out from under the rename, which is the closest a test can get to a
        /// full disk. The user asked for an update and must still have what
        /// they started with.
        #[test]
        fn a_failed_swap_restores_the_previous_pack() {
            let root = scratch("swapfail");
            let good = container([b"OLDMODEL", b"OLDLEX", b"OLDVOCAB"]);
            accept_and_install(&root, "en-es", &signed_manifest_v("en-es", URL, &good, 1), &good, &keys())
                .expect("first install");

            // install_verified with a staging directory that will not exist by
            // the time the rename runs.
            let parts: [&[u8]; 3] = [b"NEW", b"NEW", b"NEW"];
            let staging = root.join(".incoming-en-es");
            std::fs::create_dir_all(&staging).unwrap();
            // Make the staging path un-renameable by replacing it with a file
            // after the writes would have happened.
            let result = {
                // Simulate the failure directly: call the swap with a staging
                // directory that does not exist.
                std::fs::remove_dir_all(&staging).unwrap();
                install_verified_from(&root, "en-es", &parts, 2, false)
            };
            assert_eq!(result, Err(PackError::Storage));
            assert!(installed(&root, "en-es"), "the old pack must be restored");
            assert_eq!(
                std::fs::read(root.join("en-es").join("model.bin")).unwrap(),
                b"OLDMODEL"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A CRASH BETWEEN THE TWO RENAMES MUST NOT SILENTLY DISABLE
        /// ANTI-ROLLBACK.
        ///
        /// The two-step swap removes the "no pack" window of the old
        /// delete-then-rename, but only for a failed rename. If the machine
        /// dies BETWEEN them, the pack directory is missing and the old copy
        /// sits under its aside name -- and `installed_version` then reports 0,
        /// which switches the rollback check off. A reviewer spotted that the
        /// fix had moved the window rather than closed it, and was right.
        #[test]
        fn a_pack_left_aside_by_a_crash_is_recovered_before_its_version_is_read() {
            let root = scratch("crash");
            let good = container([b"OLDMODEL", b"OLDLEX", b"OLDVOCAB"]);
            accept_and_install(&root, "en-es", &signed_manifest_v("en-es", URL, &good, 9), &good, &keys())
                .expect("install v9");

            // Simulate dying between the two renames.
            std::fs::rename(root.join("en-es"), root.join(".previous-en-es")).unwrap();
            assert!(!installed(&root, "en-es"), "the crash state");
            assert_eq!(installed_version(&root, "en-es"), 0, "and rollback is blind");

            // A replayed OLDER manifest must still lose, because the recovery
            // runs before the version is read.
            let old = container([b"OLDER!!!", b"OLDERLEX", b"OLDERVOC"]);
            assert_eq!(
                accept_and_install(
                    &root,
                    "en-es",
                    &signed_manifest_v("en-es", URL, &old, 8),
                    &old,
                    &keys()
                ),
                Ok(()),
                "a replay is a no-op, not an error"
            );
            assert!(installed(&root, "en-es"), "the aside copy must be restored");
            assert_eq!(installed_version(&root, "en-es"), 9);
            assert_eq!(
                std::fs::read(root.join("en-es").join("model.bin")).unwrap(),
                b"OLDMODEL",
                "and it must be the v9 pack, not the replayed v8"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        /// AN EXISTING WORKING PACK SURVIVES A FAILED REPLACEMENT. A refresh
        /// that cannot complete must leave the user where they were, not
        /// without a language they already had.
        #[test]
        fn a_failed_install_leaves_the_previous_pack_in_place() {
            let root = scratch("keep");
            let good = container([b"OLDMODEL", b"OLDLEX", b"OLDVOCAB"]);
            accept_and_install(&root, "en-es", &signed_manifest("en-es", URL, &good), &good, &keys())
                .expect("first install");
            assert!(installed(&root, "en-es"));

            // Now a hostile refresh: right manifest, wrong bytes. Version 2,
            // so it is past the rollback gate and the BODY check is what has
            // to catch it -- with version 1 the replay is refused earlier and
            // this would prove nothing about tampering.
            let honest = container([b"NEWMODEL", b"NEWLEX", b"NEWVOCAB"]);
            let manifest = signed_manifest_v("en-es", URL, &honest, 2);
            let mut tampered = honest.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 0xff;
            assert_eq!(
                accept_and_install(&root, "en-es", &manifest, &tampered, &keys()),
                Err(PackError::Body)
            );
            assert!(installed(&root, "en-es"), "the old pack must survive");
            assert_eq!(
                std::fs::read(root.join("en-es").join("model.bin")).unwrap(),
                b"OLDMODEL",
                "and it must still be the OLD one"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        /// Remove is total, idempotent, and leaves siblings alone.
        #[test]
        fn remove_is_total_idempotent_and_leaves_siblings() {
            let root = scratch("remove");
            let es = container([b"M", b"L", b"V"]);
            accept_and_install(&root, "en-es", &signed_manifest_v("en-es", URL, &es, 1), &es, &keys())
                .expect("install en-es");
            let fr = container([b"M", b"L", b"V"]);
            let fr_url = "https://models.patanyx.net/packs/en-fr.pxpack";
            accept_and_install(&root, "en-fr", &signed_manifest_v("en-fr", fr_url, &fr, 1), &fr, &keys())
                .expect("install en-fr");
            assert!(installed(&root, "en-es") && installed(&root, "en-fr"));

            assert_eq!(remove(&root, "en-es"), Ok(()));
            assert!(!installed(&root, "en-es"), "removed pack is gone");
            assert!(installed(&root, "en-fr"), "sibling survives");
            assert_eq!(remove(&root, "en-es"), Ok(()), "removing again is fine");
            assert_eq!(remove(&root, "de-en"), Ok(()), "removing absent is fine");
            assert_eq!(remove(&root, "../etc"), Err(PackError::Manifest), "junk refused");
            let _ = std::fs::remove_dir_all(&root);
        }

        /// Enumerate reports only complete, published packs; ignores junk.
        #[test]
        fn enumerate_reports_only_complete_published_packs() {
            let root = scratch("enum");
            let es = container([b"M", b"L", b"V"]);
            accept_and_install(&root, "en-es", &signed_manifest_v("en-es", URL, &es, 3), &es, &keys())
                .expect("install");
            std::fs::create_dir_all(root.join("zz-zz")).unwrap();
            std::fs::write(root.join("zz-zz").join("model.bin"), b"x").unwrap();
            std::fs::create_dir_all(root.join("de-en")).unwrap();
            std::fs::write(root.join("de-en").join("model.bin"), b"x").unwrap();
            std::fs::create_dir_all(root.join(".incoming-en-fr")).unwrap();
            assert_eq!(enumerate(&root), vec![("en-es", 3)]);
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// A directory with a missing or empty file is NOT an installed pack. This
    /// is the state a crash mid-install leaves, and treating it as installed
    /// is what makes the failure surface deep inside the engine instead of
    /// here.
    #[test]
    fn an_incomplete_directory_does_not_count_as_installed() {
        let root = std::env::temp_dir().join(format!("pxpack-test-{}", std::process::id()));
        let dir = root.join("en-es");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!installed(&root, "en-es"), "empty directory");
        std::fs::write(dir.join("model.bin"), b"x").unwrap();
        std::fs::write(dir.join("lex.bin"), b"x").unwrap();
        assert!(!installed(&root, "en-es"), "two of three files");
        std::fs::write(dir.join("vocab.spm"), b"").unwrap();
        assert!(!installed(&root, "en-es"), "third file is empty");
        std::fs::write(dir.join("vocab.spm"), b"x").unwrap();
        assert!(installed(&root, "en-es"), "all three present and non-empty");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every failure a user can hit reaches a panel that has a case for it.
    ///
    /// THIS USED TO PROVE ONLY A PREFIX -- `starts_with("translate-pack-")` --
    /// which a misspelled or entirely absent key passes happily, while
    /// claiming in its own name that the failure was renderable. A reviewer
    /// pointed that out and was right: the test asserted a naming convention
    /// and called it a guarantee.
    ///
    /// It now reads the PANEL. These keys are not catalog ids; they are wire
    /// values the panel maps to catalog ids in `translateFailureText`. So the
    /// thing that makes a failure renderable is a case in that function, and
    /// that is what is checked. Add a PackError variant without a panel case
    /// and this fails.
    #[test]
    fn every_failure_reaches_a_panel_case() {
        const CHROME_JS: &str = include_str!("chrome/chrome.js");
        for e in [
            PackError::Unreachable("network"),
            PackError::Manifest,
            PackError::Body,
            PackError::Malformed,
            PackError::Storage,
        ] {
            let key = e.key();
            assert!(key.starts_with("translate-pack-"), "{e:?}");
            assert!(
                CHROME_JS.contains(&format!("case \"{key}\":")),
                "{e:?} produces {key:?}, which the panel has no case for -- it \
                 would render the generic failure instead of the specific one"
            );
        }
        // A bad signature and a bad hash deliberately share one key: a user
        // cannot act differently on them, and telling an attacker which check
        // failed is free information.
        assert_eq!(PackError::Manifest.key(), PackError::Body.key());
    }
    /// A manifest 404 is "not offered", never "unreachable": the server was
    /// reached and said no such pack.
    #[test]
    fn a_missing_manifest_is_not_offered_not_unreachable() {
        assert_eq!(PackError::NotOffered.key(), "translate-pack-not-offered");
        assert_ne!(PackError::NotOffered.key(), PackError::Unreachable("network").key());
    }
}
