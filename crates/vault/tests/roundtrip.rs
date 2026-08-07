use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use patanyx_vault::{Vault, VaultError};

// Reduced KDF parameters so the test suite stays fast.
const M: u32 = 8192;
const T: u32 = 1;
const P: u32 = 1;
const PASS: &str = "correct horse battery staple";

fn test_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbv-{name}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_vault(dir: &Path) -> (PathBuf, Vault) {
    let path = dir.join("vault.rbv");
    let (vault, _recovery) = Vault::create_with_params(&path, PASS, M, T, P).unwrap();
    (path, vault)
}

fn unlock_err(path: &Path, passphrase: &str) -> VaultError {
    Vault::unlock(path, passphrase).err().unwrap()
}

#[test]
fn roundtrip_create_add_unlock() {
    let dir = test_dir("roundtrip");
    let (path, mut vault) = make_vault(&dir);
    let cred1 = vault.add_credential("example.com", None, "alice", "s3cret!", "work account").unwrap();
    let cred2 = vault.add_credential("mail.example.org", None, "bob@example.org", "hunter2", "").unwrap();
    let note1 = vault.add_note("recovery codes", "code1 code2 code3").unwrap();
    drop(vault);

    let vault = Vault::unlock(&path, PASS).unwrap();

    let c1 = vault.get_credential(&cred1).unwrap();
    assert_eq!(c1.site, "example.com");
    assert_eq!(c1.username, "alice");
    assert_eq!(c1.password, "s3cret!");
    assert_eq!(c1.note, "work account");
    assert!(c1.created_at > 0);
    assert!(c1.updated_at >= c1.created_at);

    let c2 = vault.get_credential(&cred2).unwrap();
    assert_eq!(c2.username, "bob@example.org");
    assert_eq!(c2.password, "hunter2");

    let n1 = vault.get_note(&note1).unwrap();
    assert_eq!(n1.title, "recovery codes");
    assert_eq!(n1.body, "code1 code2 code3");

    assert_eq!(vault.list_credentials().len(), 2);
    assert_eq!(vault.list_notes().len(), 1);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_passphrase_is_auth_failed() {
    let dir = test_dir("wrongpw");
    let (path, vault) = make_vault(&dir);
    drop(vault);
    let err = unlock_err(&path, "not the passphrase");
    assert!(matches!(err, VaultError::AuthFailed), "got {err:?}");
    fs::remove_dir_all(&dir).ok();
}

fn flip_and_unlock(path: &Path, offset: usize) -> VaultError {
    let mut bytes = fs::read(path).unwrap();
    bytes[offset] ^= 0x01;
    fs::write(path, &bytes).unwrap();
    unlock_err(path, PASS)
}

#[test]
fn tampered_ciphertext_is_auth_failed() {
    let dir = test_dir("tamper-ct");
    let (path, mut vault) = make_vault(&dir);
    vault.add_credential("example.com", None, "alice", "s3cret!", "").unwrap();
    drop(vault);
    let len = fs::metadata(&path).unwrap().len() as usize;
    let err = flip_and_unlock(&path, len - 1); // last byte of the Poly1305 tag
    assert!(matches!(err, VaultError::AuthFailed), "got {err:?}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn tampered_salt_is_auth_failed() {
    let dir = test_dir("tamper-salt");
    let (path, vault) = make_vault(&dir);
    drop(vault);
    // v2: byte 20 is the slot count and 21..45 the content nonce, so the first
    // slot's salt now begins right after the fixed prefix.
    let err = flip_and_unlock(&path, 46); // first salt byte of slot 0
    assert!(matches!(err, VaultError::AuthFailed), "got {err:?}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn tampered_m_cost_is_auth_failed() {
    let dir = test_dir("tamper-mcost");
    let (path, vault) = make_vault(&dir);
    drop(vault);
    // 8192 -> 8193: still within plausible KDF bounds, so this exercises
    // authentication (AAD + derived key), not parameter validation.
    let err = flip_and_unlock(&path, 8);
    assert!(matches!(err, VaultError::AuthFailed), "got {err:?}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn unknown_version_is_bad_format() {
    let dir = test_dir("bad-version");
    let (path, vault) = make_vault(&dir);
    drop(vault);
    let mut bytes = fs::read(&path).unwrap();
    bytes[7] = 0xfe; // 0x02 is the current version; pick one that is not
    fs::write(&path, &bytes).unwrap();
    let err = unlock_err(&path, PASS);
    assert!(matches!(err, VaultError::BadFormat(_)), "got {err:?}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn truncated_and_empty_files_are_bad_format_without_panicking() {
    let dir = test_dir("truncated");
    let (path, vault) = make_vault(&dir);
    drop(vault);

    let bytes = fs::read(&path).unwrap();
    let truncated = dir.join("truncated.rbv");
    fs::write(&truncated, &bytes[..30]).unwrap();
    let err = unlock_err(&truncated, PASS);
    assert!(matches!(err, VaultError::BadFormat(_)), "got {err:?}");

    let empty = dir.join("empty.rbv");
    fs::write(&empty, b"").unwrap();
    let err = unlock_err(&empty, PASS);
    assert!(matches!(err, VaultError::BadFormat(_)), "got {err:?}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn create_refuses_to_clobber_existing_vault() {
    let dir = test_dir("clobber");
    let (path, vault) = make_vault(&dir);
    drop(vault);
    let before = fs::read(&path).unwrap();

    let err = Vault::create_with_params(&path, "another passphrase", M, T, P)
        .err()
        .unwrap();
    assert!(matches!(err, VaultError::AlreadyExists(_)), "got {err:?}");
    assert_eq!(fs::read(&path).unwrap(), before, "original file was modified");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn save_leaves_no_tmp_file_and_mode_0600() {
    let dir = test_dir("atomic");
    let (path, mut vault) = make_vault(&dir);
    vault.add_credential("example.com", None, "alice", "s3cret!", "").unwrap();

    let mut tmp = path.clone().into_os_string();
    tmp.push(".tmp");
    assert!(
        !PathBuf::from(&tmp).exists(),
        "temporary file must not survive save"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault file mode is {mode:o}");
    }

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn credential_meta_never_contains_password() {
    let dir = test_dir("meta");
    let (_path, mut vault) = make_vault(&dir);
    vault.add_credential("example.com", None, "alice", "supersecret", "").unwrap();

    let metas = vault.list_credentials();
    assert_eq!(metas.len(), 1);
    let value = serde_json::to_value(&metas[0]).unwrap();
    let obj = value.as_object().unwrap();
    assert!(obj.get("password").is_none());
    // EXACT count on purpose. This fails on ANY new field, which is the whole
    // job: somebody has to look at the addition and decide it is not secret
    // material before this number moves. Do not relax it to `>=`.
    //
    // Went 3 -> 4 for `origin`, and that was reviewed: it is the host parsed
    // from the user's own free-text `site` label, already visible in `site`
    // for anything that parsed, and the listing needs it so the UI can show
    // which credentials will actually be offered for filling and which are
    // inert. No key material, no password, nothing derived from either.
    assert_eq!(obj.len(), 4);
    assert!(obj.contains_key("id"));
    assert!(obj.contains_key("site"));
    assert!(obj.contains_key("username"));
    assert!(obj.contains_key("origin"));

    // The credential above was added with origin None, so the listing must say
    // so rather than inventing one from the site label -- a UI that showed a
    // host here would claim this entry fills somewhere when it fills nowhere.
    assert!(obj.get("origin").unwrap().is_null());

    fs::remove_dir_all(&dir).ok();
}

// ---- recovery key -----------------------------------------------------------

#[test]
fn recovery_key_opens_the_vault() {
    let dir = test_dir("recovery-open");
    let path = dir.join("vault.rbv");
    let (mut vault, recovery) = Vault::create_with_params(&path, PASS, M, T, P).unwrap();
    let id = vault.add_credential("example.com", None, "user", "pw", "").unwrap();
    vault.save().unwrap();
    drop(vault);

    // The whole point: the passphrase is gone and the data is not.
    let recovered = Vault::unlock_with_recovery(&path, &recovery).unwrap();
    assert_eq!(recovered.get_credential(&id).unwrap().password, "pw");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_passphrase_still_works_after_a_recovery_key_exists() {
    let dir = test_dir("recovery-both");
    let (path, vault) = make_vault(&dir);
    drop(vault);
    assert!(Vault::unlock(&path, PASS).is_ok());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_different_recovery_key_is_refused() {
    let dir = test_dir("recovery-wrong");
    let path = dir.join("vault.rbv");
    let (_vault, _recovery) = Vault::create_with_params(&path, PASS, M, T, P).unwrap();
    let impostor = patanyx_vault::RecoveryKey::generate();
    // Indistinguishable from tampering, exactly like a wrong passphrase.
    assert!(matches!(
        Vault::unlock_with_recovery(&path, &impostor),
        Err(VaultError::AuthFailed)
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn opting_out_leaves_no_second_door() {
    let dir = test_dir("recovery-optout");
    let path = dir.join("vault.rbv");
    let vault = Vault::create_without_recovery(&path, PASS).unwrap();
    assert!(!vault.has_recovery());
    drop(vault);
    let any_key = patanyx_vault::RecoveryKey::generate();
    assert!(matches!(
        Vault::unlock_with_recovery(&path, &any_key),
        Err(VaultError::NoRecoverySlot)
    ));
    // The passphrase must still work; opting out removes recovery, not access.
    assert!(Vault::unlock(&path, PASS).is_ok());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_stripped_slot_breaks_the_contents() {
    // The content AAD covers every slot, so deleting the recovery slot to force
    // a downgrade must not yield a readable vault.
    let dir = test_dir("recovery-strip");
    let (path, vault) = make_vault(&dir);
    drop(vault);
    let bytes = fs::read(&path).unwrap();
    let slot_count = bytes[20] as usize;
    assert_eq!(slot_count, 2, "expected passphrase + recovery slots");
    let prefix_len = 45;
    let slot_len = 89;
    let mut stripped = Vec::new();
    stripped.extend_from_slice(&bytes[..20]);
    stripped.push(1); // claim one slot
    stripped.extend_from_slice(&bytes[21..prefix_len + slot_len]); // nonce + slot 0
    stripped.extend_from_slice(&bytes[prefix_len + slot_count * slot_len..]); // ciphertext
    fs::write(&path, &stripped).unwrap();
    let err = unlock_err(&path, PASS);
    assert!(matches!(err, VaultError::AuthFailed), "got {err:?}");
    fs::remove_dir_all(&dir).ok();
}
