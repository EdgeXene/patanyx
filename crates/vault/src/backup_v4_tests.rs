//! Backup file version 4 (`backup_v4.rs`).
//!
//! Pinned here: sections of any size round-trip in order, including across
//! and exactly on segment boundaries; a wrong passphrase, a cut, an appended
//! byte, a flipped bit and swapped segments all fail to open; a stream that is
//! well sealed but badly formed (no END, a second vault, data after END, an
//! unknown kind, a false END) is refused; limits are applied before a body is
//! read; the vault inside follows the unlock schema rule; reading writes
//! nothing; and a failed export leaves no file behind.

use super::*;
use crate::crypto;
use crate::model::SCHEMA_VERSION;

const TEST_M: u32 = 8192;
const TEST_T: u32 = 1;
const TEST_P: u32 = 1;
const PASS: &str = "export passphrase";

struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let random: [u8; 8] = crypto::random_bytes();
        let mut name = format!("rbv-backup4-test-{tag}-");
        for b in random {
            name.push_str(&format!("{b:02x}"));
        }
        let path = std::env::temp_dir().join(name);
        fs::create_dir_all(&path).unwrap();
        TestDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn vault_in(dir: &TestDir) -> Vault {
    let (mut vault, _) =
        Vault::create_with_params(&dir.path().join("vault.rbv"), "vault pw", TEST_M, TEST_T, TEST_P)
            .unwrap();
    vault.add_note("a note", "kept with the vault").unwrap();
    vault
}

fn limits() -> SectionLimits {
    SectionLimits {
        library: 64 << 20,
        picture: 80 << 20,
        addon: 16 << 20,
    }
}

type Sections = Vec<(SectionKind, String, Vec<u8>)>;

fn export(vault: &Vault, dest: &Path, sections: &Sections) -> Result<BackupStats, ExportError> {
    vault.export_backup(dest, PASS, limits(), &mut |sink| {
        for (kind, name, body) in sections {
            sink.section(*kind, name, body)?;
        }
        Ok(())
    })
}

fn read_all(src: &Path, pass: &str) -> Result<(PendingImport, Vec<Section>), ExportError> {
    let mut reader = BackupReader::open(src, pass, limits())?;
    let mut out = Vec::new();
    while let Some(section) = reader.next_section()? {
        out.push(section);
    }
    Ok((reader.finish()?, out))
}

fn pseudo_random(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn sample_sections() -> Sections {
    vec![
        (SectionKind::Library, String::new(), br#"{"bookmarks":[]}"#.to_vec()),
        // Crosses several segment boundaries.
        (SectionKind::Picture, "aaa".into(), pseudo_random(3 * SEGMENT_PLAIN + 7, 1)),
        (SectionKind::Picture, "bbb".into(), Vec::new()),
        (SectionKind::Addon, "example-addon/item-1".into(), pseudo_random(100, 2)),
    ]
}

#[test]
fn sections_of_any_size_round_trip_in_order_with_the_vault() {
    let dir = TestDir::new("roundtrip");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    let sections = sample_sections();
    let stats = export(&vault, &dest, &sections).unwrap();
    assert_eq!(stats.sections, 4);

    let (pending, got) = read_all(&dest, PASS).unwrap();
    assert_eq!(pending.data.notes.len(), 1);
    assert_eq!(serde_json::to_value(&pending.data).unwrap(), serde_json::to_value(vault.data_ref()).unwrap());
    assert_eq!(got.len(), sections.len());
    for (section, (kind, name, body)) in got.iter().zip(&sections) {
        assert_eq!(section.kind, *kind);
        assert_eq!(&section.name, name);
        assert_eq!(&section.body[..], &body[..]);
    }
    assert_eq!(backup_file_version(&dest).unwrap(), BACKUP_VERSION);
}

/// The plaintext length that makes the whole stream end exactly on a segment
/// boundary for a vault and one picture of `body` bytes.
fn end_record_len(records: u64, bytes: u64) -> usize {
    let manifest = EndManifest {
        records,
        bytes,
        sha256: "0".repeat(64),
    };
    1 + 2 + 8 + serde_json::to_vec(&manifest).unwrap().len()
}

#[test]
fn a_stream_ending_exactly_on_a_segment_boundary_round_trips() {
    let dir = TestDir::new("boundary");
    let vault = vault_in(&dir);
    let vault_len = serde_json::to_vec(vault.data_ref()).unwrap().len();
    let vault_rec = 1 + 2 + 8 + vault_len;
    let picture_frame = 1 + 2 + 1 + 8; // name "p"
    // Solve for a body whose total, END included, is exactly two segments;
    // the END record's own length depends on the body's, so iterate.
    let target = 2 * SEGMENT_PLAIN;
    let mut body = target - vault_rec - picture_frame;
    for _ in 0..4 {
        let end = end_record_len(2, (vault_len + body) as u64);
        body = target - vault_rec - picture_frame - end;
    }
    for delta in [0isize, -1, 1] {
        let size = (body as isize + delta) as usize;
        let dest = dir.path().join(format!("b{delta}.rbvx"));
        let sections = vec![(SectionKind::Picture, "p".to_string(), pseudo_random(size, 3))];
        export(&vault, &dest, &sections).unwrap();
        let (_, got) = read_all(&dest, PASS).unwrap();
        assert_eq!(got[0].body.len(), size, "delta {delta}");
    }
}

#[test]
fn a_wrong_passphrase_is_the_same_coarse_failure_as_tampering() {
    let dir = TestDir::new("wrongpw");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &sample_sections()).unwrap();
    assert!(matches!(read_all(&dest, "not it"), Err(ExportError::AuthFailed)));
}

fn mutated(dir: &TestDir, from: &Path, name: &str, change: impl FnOnce(&mut Vec<u8>)) -> std::path::PathBuf {
    let mut bytes = fs::read(from).unwrap();
    change(&mut bytes);
    let path = dir.path().join(name);
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn a_cut_an_appended_byte_or_a_flipped_bit_never_opens() {
    let dir = TestDir::new("tamper");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &sample_sections()).unwrap();
    let len = fs::metadata(&dest).unwrap().len() as usize;

    let cuts = [
        30,
        EXPORT_HEADER_LEN,
        EXPORT_HEADER_LEN + 10,
        EXPORT_HEADER_LEN + SEGMENT_CIPHER,     // exactly after the first segment
        EXPORT_HEADER_LEN + 2 * SEGMENT_CIPHER, // exactly after the second
        len - 1,
    ];
    for (i, cut) in cuts.iter().enumerate() {
        let path = mutated(&dir, &dest, &format!("cut{i}"), |b| b.truncate(*cut));
        assert!(read_all(&path, PASS).is_err(), "cut at {cut} opened");
    }
    let appended = mutated(&dir, &dest, "appended", |b| b.push(0));
    assert!(read_all(&appended, PASS).is_err());
    for offset in [25usize, 40, EXPORT_HEADER_LEN + 5, len / 2, len - 3] {
        let flipped = mutated(&dir, &dest, &format!("flip{offset}"), |b| b[offset] ^= 0x01);
        assert!(read_all(&flipped, PASS).is_err(), "flip at {offset} opened");
    }
    // The reserved bytes are refused before any key is derived.
    let reserved = mutated(&dir, &dest, "reserved", |b| b[57] = 1);
    assert!(matches!(read_all(&reserved, PASS), Err(ExportError::BadExport(_))));
}

#[test]
fn swapped_segments_never_open() {
    let dir = TestDir::new("swap");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &sample_sections()).unwrap();
    let swapped = mutated(&dir, &dest, "swapped", |b| {
        let first = EXPORT_HEADER_LEN..EXPORT_HEADER_LEN + SEGMENT_CIPHER;
        let second = first.end..first.end + SEGMENT_CIPHER;
        let a: Vec<u8> = b[first.clone()].to_vec();
        let c: Vec<u8> = b[second.clone()].to_vec();
        b[first].copy_from_slice(&c);
        b[second].copy_from_slice(&a);
    });
    assert!(matches!(read_all(&swapped, PASS), Err(ExportError::AuthFailed)));
}

// ---- well sealed, badly formed --------------------------------------------------

/// Writes a sealed stream from raw records, with or without END, so the
/// reader's structural checks can be reached past the AEAD.
fn craft(dir: &TestDir, name: &str, records: &[(u8, &str, Vec<u8>)], end: Option<EndManifest>) -> std::path::PathBuf {
    let params = KdfParams {
        m_cost: TEST_M,
        t_cost: TEST_T,
        p_cost: TEST_P,
    };
    let salt: [u8; SALT_LEN] = crypto::random_bytes();
    let prefix: [u8; NONCE_PREFIX_LEN] = crypto::random_bytes();
    let key = crypto::derive_key(PASS.as_bytes(), &salt, &params).unwrap();
    let header = encode_header(&params, &salt, &prefix);
    let path = dir.path().join(name);
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(&header).unwrap();
    let mut writer = SegmentWriter::new(&mut file, &key, &prefix, header);
    for (kind, name, body) in records {
        writer.record(*kind, name, body).unwrap();
    }
    if let Some(manifest) = end {
        let body = serde_json::to_vec(&manifest).unwrap();
        writer.push(&frame(KIND_END, "", body.len() as u64).unwrap()).unwrap();
        writer.push(&body).unwrap();
    }
    let encryptor = writer.encryptor.take().unwrap();
    let sealed = encryptor
        .encrypt_last(Payload {
            msg: &writer.buffer[..],
            aad: &writer.header,
        })
        .unwrap();
    writer.file.write_all(&sealed).unwrap();
    path
}

fn vault_json(dir: &TestDir) -> Vec<u8> {
    serde_json::to_vec(vault_in(dir).data_ref()).unwrap()
}

/// An END record that truly matches `records`.
fn true_end(records: &[(u8, &str, Vec<u8>)]) -> EndManifest {
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    for (kind, name, body) in records {
        hasher.update(frame(*kind, name, body.len() as u64).unwrap());
        hasher.update(body);
        bytes += body.len() as u64;
    }
    EndManifest {
        records: records.len() as u64,
        bytes,
        sha256: hex(&hasher.finalize()),
    }
}

#[test]
fn a_crafted_stream_that_is_sealed_but_well_formed_opens() {
    // The control for the refusals below: craft() itself makes valid files.
    let dir = TestDir::new("craft-ok");
    let records = vec![(KIND_VAULT, "", vault_json(&dir)), (KIND_LIBRARY, "", b"{}".to_vec())];
    let path = craft(&dir, "ok", &records, Some(true_end(&records)));
    let (_, got) = read_all(&path, PASS).unwrap();
    assert_eq!(got.len(), 1);
}

#[test]
fn a_stream_without_end_never_yields_its_vault() {
    let dir = TestDir::new("noend");
    let records = vec![(KIND_VAULT, "", vault_json(&dir)), (KIND_LIBRARY, "", b"{}".to_vec())];
    let path = craft(&dir, "noend", &records, None);
    assert!(read_all(&path, PASS).is_err());
}

#[test]
fn the_vault_must_come_first_and_only_once() {
    let dir = TestDir::new("vaultorder");
    let vault = vault_json(&dir);
    let late = vec![(KIND_LIBRARY, "", b"{}".to_vec()), (KIND_VAULT, "", vault.clone())];
    let path = craft(&dir, "late", &late, Some(true_end(&late)));
    assert!(read_all(&path, PASS).is_err());
    let twice = vec![(KIND_VAULT, "", vault.clone()), (KIND_VAULT, "", vault)];
    let path = craft(&dir, "twice", &twice, Some(true_end(&twice)));
    assert!(read_all(&path, PASS).is_err());
}

#[test]
fn an_unknown_kind_or_a_false_end_is_refused() {
    let dir = TestDir::new("structure");
    let vault = vault_json(&dir);
    // An unknown kind is authenticated, so it was written by a newer build:
    // the person is told to update, not that the file is damaged.
    let unknown = vec![(KIND_VAULT, "", vault.clone()), (9u8, "", b"x".to_vec())];
    let path = craft(&dir, "unknown", &unknown, Some(true_end(&unknown)));
    assert!(matches!(
        read_all(&path, PASS),
        Err(ExportError::UnreadableVersion(BACKUP_VERSION))
    ));

    let records = vec![(KIND_VAULT, "", vault.clone()), (KIND_LIBRARY, "", b"{}".to_vec())];
    let mut lying = true_end(&records);
    lying.records += 1;
    let path = craft(&dir, "lying", &records, Some(lying));
    assert!(read_all(&path, PASS).is_err());

    let mut wrong_hash = true_end(&records);
    wrong_hash.sha256 = "0".repeat(64);
    let path = craft(&dir, "hash", &records, Some(wrong_hash));
    assert!(read_all(&path, PASS).is_err());
}

#[test]
fn a_kind_this_build_does_not_read_is_from_a_newer_build() {
    let dir = TestDir::new("not-read");
    let vault = vault_json(&dir);
    let records = vec![(KIND_VAULT, "", vault), (KIND_ADDON, "notes/1", b"page".to_vec())];
    let path = craft(&dir, "addon", &records, Some(true_end(&records)));
    let no_addons = SectionLimits {
        addon: 0,
        ..limits()
    };
    let mut reader = BackupReader::open(&path, PASS, no_addons).unwrap();
    assert!(matches!(
        reader.next_section(),
        Err(ExportError::UnreadableVersion(BACKUP_VERSION))
    ));
}

#[test]
fn nothing_may_follow_end() {
    let dir = TestDir::new("after-end");
    let vault = vault_json(&dir);
    let records = vec![(KIND_VAULT, "", vault)];
    let end = true_end(&records);
    // END, then one more record, all inside the sealed stream.
    let mut with_tail = records.clone();
    let body = serde_json::to_vec(&end).unwrap();
    with_tail.push((KIND_END, "", body));
    with_tail.push((KIND_LIBRARY, "", b"{}".to_vec()));
    let path = craft(&dir, "tail", &with_tail, None);
    assert!(read_all(&path, PASS).is_err());
}

#[test]
fn a_section_over_its_limit_is_refused_and_the_export_leaves_nothing() {
    let dir = TestDir::new("limit");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    let small = SectionLimits {
        library: 64,
        picture: 10,
        addon: 64,
    };
    let result = vault.export_backup(&dest, PASS, small, &mut |sink| {
        sink.section(SectionKind::Picture, "p", &[0u8; 11])
    });
    assert!(matches!(result, Err(ExportError::BadExport(_))), "the read-back applies the limits");
    assert!(!dest.exists(), "a backup this build would refuse is never left behind");
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "the temporary file was removed");
}

#[test]
fn a_failing_section_writer_leaves_no_file_and_an_old_backup_untouched() {
    let dir = TestDir::new("failing");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &sample_sections()).unwrap();
    let before = fs::read(&dest).unwrap();
    let result = vault.export_backup(&dest, PASS, limits(), &mut |_| Err(ExportError::BadExport("stop".into())));
    assert!(result.is_err());
    assert_eq!(fs::read(&dest).unwrap(), before);
}

#[test]
fn the_export_never_lands_on_the_live_vault() {
    let dir = TestDir::new("live");
    let vault = vault_in(&dir);
    let live = dir.path().join("vault.rbv");
    assert!(matches!(export(&vault, &live, &Vec::new()), Err(ExportError::TargetIsLiveVault)));
}

// ---- versions and the vault inside ---------------------------------------------

fn with_version(dir: &TestDir, from: &Path, version: u8) -> std::path::PathBuf {
    mutated(dir, from, &format!("v{version}"), |b| b[7] = version)
}

#[test]
fn other_versions_are_named_not_called_broken() {
    let dir = TestDir::new("versions");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &Vec::new()).unwrap();
    for version in [0x03u8, 0x05, 0x7f] {
        let path = with_version(&dir, &dest, version);
        assert!(matches!(BackupReader::open(&path, PASS, limits()), Err(ExportError::UnreadableVersion(v)) if v == version));
        let target = dir.path().join(format!("imported-{version}.rbv"));
        assert!(matches!(
            Vault::import_encrypted(&path, &target, PASS, "new pw"),
            Err(ExportError::UnreadableVersion(v)) if v == version
        ));
    }
    // A version 4 file handed to the version 1/2 importer says which reader to use.
    let target = dir.path().join("imported.rbv");
    assert!(matches!(Vault::import_encrypted(&dest, &target, PASS, "new pw"), Err(ExportError::BadExport(_))));
}

#[test]
fn a_vault_from_a_newer_build_is_refused_as_newer() {
    let dir = TestDir::new("newer");
    let mut value = serde_json::to_value(vault_in(&dir).data_ref()).unwrap();
    value["schema"] = serde_json::json!(SCHEMA_VERSION + 1);
    let records = vec![(KIND_VAULT, "", serde_json::to_vec(&value).unwrap())];
    let path = craft(&dir, "newer", &records, Some(true_end(&records)));
    assert!(matches!(
        BackupReader::open(&path, PASS, limits()),
        Err(ExportError::Vault(VaultError::NewerVault { .. }))
    ));
}

#[test]
fn reading_writes_nothing_and_install_is_the_commit() {
    let dir = TestDir::new("install");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &sample_sections()).unwrap();
    let live = dir.path().join("vault.rbv");
    drop(vault);
    let before = fs::read(&live).unwrap();

    let (pending, _) = read_all(&dest, PASS).unwrap();
    assert_eq!(fs::read(&live).unwrap(), before, "reading the backup wrote nothing");

    let library_key = pending.library_key().unwrap();
    let (installed, recovery) = pending.install(&live, "new vault pw").unwrap();
    assert_eq!(*installed.library_key().unwrap(), *library_key, "the Library key known before install is the vault's");
    assert_eq!(installed.list_notes().len(), 1);
    drop(installed);
    assert!(Vault::unlock(&live, "new vault pw").is_ok());
    assert!(Vault::unlock(&live, "vault pw").is_err(), "the old passphrase opens nothing");
    assert!(!recovery.as_bytes().iter().all(|b| *b == 0));
}

#[test]
fn a_version_2_export_still_imports_with_its_bookmarks() {
    let dir = TestDir::new("v2");
    let vault = vault_in(&dir);
    let dest = dir.path().join("old.rbvx");
    vault.export_encrypted_with(&dest, PASS, Some(b"[carried]")).unwrap();
    assert_eq!(backup_file_version(&dest).unwrap(), 0x02);
    let target = dir.path().join("imported.rbv");
    let (imported, _, extra) = Vault::import_encrypted(&dest, &target, PASS, "new pw").unwrap();
    assert_eq!(extra.as_deref(), Some(&b"[carried]"[..]));
    assert_eq!(imported.list_notes().len(), 1);
}

#[test]
fn a_section_never_prints_its_body() {
    let section = Section {
        kind: SectionKind::Library,
        name: String::new(),
        body: Zeroizing::new(b"https://private.example.test/".to_vec()),
    };
    assert!(!format!("{section:?}").contains("private"));
    let dir = TestDir::new("debug");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &Vec::new()).unwrap();
    let reader = BackupReader::open(&dest, PASS, limits()).unwrap();
    assert!(!format!("{:?}", reader.pending()).contains("kept with the vault"));
}

/// The fuzz target's entry reads a well-formed stream to its end, so the
/// fuzzer starts from input that reaches every record kind and END. With
/// PATANYX_FUZZ_SEED set to a file path, the stream is also written there as
/// the target's seed.
#[cfg(fuzzing)]
#[test]
fn the_fuzz_entry_reads_a_well_formed_stream_to_its_end() {
    let dir = TestDir::new("fuzz-seed");
    let records = vec![
        (KIND_VAULT, "", vault_json(&dir)),
        (KIND_LIBRARY, "", br#"{"schema":1}"#.to_vec()),
        (KIND_PICTURE, "0123456789abcdef", vec![9u8; 64]),
        (KIND_ADDON, "example-addon/item-1", b"a page".to_vec()),
    ];
    let end = serde_json::to_vec(&true_end(&records)).unwrap();
    let mut plain = Vec::new();
    for (kind, name, body) in &records {
        plain.extend(frame(*kind, name, body.len() as u64).unwrap());
        plain.extend(body);
    }
    plain.extend(frame(KIND_END, "", end.len() as u64).unwrap());
    plain.extend(&end);
    super::read_sealed(&plain).expect("a well-formed stream reads to its end");
    let mut cut = plain.clone();
    cut.pop();
    assert!(super::read_sealed(&cut).is_err());
    if let Ok(path) = std::env::var("PATANYX_FUZZ_SEED") {
        std::fs::write(path, &plain).unwrap();
    }
}

// ---- stopping and progress (BackupWatch) -----------------------------------

fn temp_files(dir: &TestDir) -> usize {
    fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .count()
}

fn export_watched(vault: &Vault, dest: &Path, sections: &Sections, watch: &BackupWatch) -> Result<BackupStats, ExportError> {
    vault.backup_source().unwrap().write(
        dest,
        PASS,
        limits(),
        &mut |sink| {
            for (kind, name, body) in sections {
                sink.section(*kind, name, body)?;
            }
            Ok(())
        },
        watch,
    )
}

/// A stop at any point before the rename: `Cancelled`, no temporary file,
/// and a backup already at the destination keeps its exact bytes.
#[test]
fn a_stop_at_any_stage_before_the_rename_writes_nothing() {
    let dir = TestDir::new("stop-stages");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &sample_sections()).unwrap();
    let before = fs::read(&dest).unwrap();
    let total = before.len() as u64;
    for (stage, at) in [
        (BackupStage::Preparing, 0),
        (BackupStage::Writing, 1),
        (BackupStage::Writing, 2 * SEGMENT_CIPHER as u64),
        (BackupStage::Checking, 1),
        (BackupStage::Checking, 2 * SEGMENT_CIPHER as u64),
        // The read-back's very last segment: everything is written and
        // checked, and the stop still lands before the rename.
        (BackupStage::Checking, total),
    ] {
        let watch = BackupWatch::new();
        watch.stop_at(stage, at);
        let result = export_watched(&vault, &dest, &sample_sections(), &watch);
        assert!(matches!(result, Err(ExportError::Cancelled)), "a stop at {stage:?} {at} was not honoured: {result:?}");
        assert_eq!(fs::read(&dest).unwrap(), before, "a stop at {stage:?} {at} changed the existing backup");
        assert_eq!(temp_files(&dir), 0, "a stop at {stage:?} {at} left a temporary file");
    }
}

#[test]
fn a_stop_before_the_first_write_leaves_no_destination() {
    let dir = TestDir::new("stop-early");
    let vault = vault_in(&dir);
    let dest = dir.path().join("new-backup.rbvx");
    let watch = BackupWatch::new();
    watch.stop();
    let result = export_watched(&vault, &dest, &sample_sections(), &watch);
    assert!(matches!(result, Err(ExportError::Cancelled)));
    assert!(!dest.exists());
    assert_eq!(temp_files(&dir), 0);
}

/// Past the rename the backup is whole; a stop then changes nothing.
#[test]
fn a_stop_after_the_rename_is_not_honoured() {
    let dir = TestDir::new("stop-late");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    let watch = BackupWatch::new();
    export_watched(&vault, &dest, &sample_sections(), &watch).unwrap();
    watch.stop();
    let (_, got) = read_all(&dest, PASS).unwrap();
    assert_eq!(got.len(), sample_sections().len());
}

/// The stages run in order, the bytes never go back within a stage, and the
/// read-back ends exactly at the file's size.
#[test]
fn progress_runs_in_stage_order_and_never_goes_back() {
    let dir = TestDir::new("progress");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    let watch = BackupWatch::new();
    watch.set_estimate(3 * SEGMENT_PLAIN as u64);
    export_watched(&vault, &dest, &sample_sections(), &watch).unwrap();
    let history = watch.history();
    let stages: Vec<BackupStage> = history.iter().map(|(s, _)| *s).fold(Vec::new(), |mut v, s| {
        if v.last() != Some(&s) {
            v.push(s);
        }
        v
    });
    assert_eq!(stages, [BackupStage::Preparing, BackupStage::Writing, BackupStage::Checking]);
    for pair in history.windows(2) {
        if pair[0].0 == pair[1].0 {
            assert!(pair[1].1 >= pair[0].1, "progress went back within {:?}: {pair:?}", pair[0].0);
        }
    }
    let size = fs::metadata(&dest).unwrap().len();
    let snapshot = watch.snapshot();
    assert_eq!(snapshot.stage, BackupStage::Checking);
    assert_eq!(snapshot.total, Some(size));
    assert_eq!(snapshot.done, size, "the read-back did not report the whole file");
    assert!(!snapshot.stopped);
}

/// An import's reader reports Preparing, then Reading up to the file's exact
/// size, and stops at the next segment once asked.
#[test]
fn the_reader_reports_the_whole_file_and_stops_when_asked() {
    let dir = TestDir::new("reader-watch");
    let vault = vault_in(&dir);
    let dest = dir.path().join("backup.rbvx");
    export(&vault, &dest, &sample_sections()).unwrap();
    let size = fs::metadata(&dest).unwrap().len();

    let watch = BackupWatch::new();
    let mut reader = BackupReader::open_watched(&dest, PASS, limits(), &watch).unwrap();
    while reader.next_section().unwrap().is_some() {}
    reader.finish().unwrap();
    let snapshot = watch.snapshot();
    assert_eq!(snapshot.stage, BackupStage::Reading);
    assert_eq!((snapshot.done, snapshot.total), (size, Some(size)));
    assert_eq!(watch.history().first().map(|(s, _)| *s), Some(BackupStage::Preparing));

    let watch = BackupWatch::new();
    watch.stop_at(BackupStage::Reading, 2 * SEGMENT_CIPHER as u64);
    let mut reader = BackupReader::open_watched(&dest, PASS, limits(), &watch).unwrap();
    let mut outcome = Ok(());
    loop {
        match reader.next_section() {
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(error) => {
                outcome = Err(error);
                break;
            }
        }
    }
    assert!(matches!(outcome, Err(ExportError::Cancelled)), "the reader did not stop: {outcome:?}");
}

/// Everything an export or import hands to a worker thread must be Send.
#[test]
fn what_a_backup_worker_holds_can_cross_threads() {
    fn send<T: Send + 'static>() {}
    send::<BackupSource>();
    send::<BackupWatch>();
    send::<BackupReader>();
    send::<PendingImport>();
    send::<Vault>();
}

/// The vault's contents never print from a BackupSource.
#[test]
fn a_backup_source_never_prints_the_vault() {
    let dir = TestDir::new("source-debug");
    let vault = vault_in(&dir);
    let printed = format!("{:?}", vault.backup_source().unwrap());
    assert!(!printed.contains("kept with the vault"), "{printed}");
    assert!(printed.contains("bytes"));
}
