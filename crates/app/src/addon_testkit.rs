//! Harmless generated packages and test-only signing authority.
use crate::addon_install::{InstallStore, PreparedInstall, ReleaseChoice};
use ed25519_dalek::{Signer, SigningKey};
use patanyx_update::{addon::*, TrustedKeys};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) const ID: &str = "text-pages";
pub(crate) fn keys() -> TrustedKeys {
    TrustedKeys::new(vec![SigningKey::from_bytes(
        &crate::updater::ADDON_TEST_SEED,
    )
    .verifying_key()])
    .unwrap()
}
pub(crate) fn sign(value: &Value, domain: &[u8]) -> Vec<u8> {
    let signing = SigningKey::from_bytes(&crate::updater::ADDON_TEST_SEED);
    let payload = value.to_string();
    serde_json::to_vec(&json!({"v":1,"payload":payload,
        "sig":patanyx_update::hex::encode(&signing.sign(&[domain,payload.as_bytes()].concat()).to_bytes())})).unwrap()
}
pub(crate) struct Package {
    pub manifest: Vec<u8>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub release: Value,
}
pub(crate) fn package(version: &str, text: &str) -> Package {
    let files = BTreeMap::from([
        ("index.html".to_string(), text.as_bytes().to_vec()),
        ("assets/main.js".to_string(), b"void 0;".to_vec()),
    ]);
    let manifest = sign(
        &json!({"id":ID,"name":"Test pages","version":version,"host_api":1,
            "data_format":"text-pages-v1","premium":true,"mark":addon_mark(),
            "capabilities":["text_pages","vault_notes_read","selection_receive"],
            "files":files.iter().map(|(path,bytes)|json!({"path":path,"size":bytes.len(),
                "sha256":patanyx_update::hex::encode(&Sha256::digest(bytes))})).collect::<Vec<_>>()
        }),
        SIGNING_DOMAIN_ADDON_MANIFEST,
    );
    let release = json!({"version":version,"host_api":1,"data_format":"text-pages-v1",
        "manifest_size":manifest.len(),"manifest_sha256":patanyx_update::hex::encode(&Sha256::digest(&manifest))});
    Package {
        manifest,
        files,
        release,
    }
}
pub(crate) fn index(sequence: u64, current: &Package, rollback: Option<&Package>) -> Value {
    json!({"schema":1,"id":ID,"sequence":sequence,"issued_at":1,"expires_at":u64::MAX,
        "current":current.release,"rollback":rollback.map(|p|p.release.clone())})
}
pub(crate) fn prepare(
    store: &InstallStore,
    sequence: u64,
    current: &Package,
    rollback: Option<&Package>,
) -> PreparedInstall {
    let bytes = sign(
        &index(sequence, current, rollback),
        SIGNING_DOMAIN_ADDON_INDEX,
    );
    let index = store
        .accept_index(ID, &bytes, crate::addon_install::now().unwrap())
        .unwrap();
    let selected = store
        .verify_package(
            &index,
            index.current(),
            current.manifest.clone(),
            current.files.clone(),
        )
        .unwrap();
    let rollback = rollback.map(|p| {
        store
            .verify_package(
                &index,
                index.rollback().unwrap(),
                p.manifest.clone(),
                p.files.clone(),
            )
            .unwrap()
    });
    store
        .prepare(bytes, ReleaseChoice::Current, selected, rollback)
        .unwrap()
}
pub(crate) fn store() -> (tempfile::TempDir, InstallStore) {
    let temp = tempfile::tempdir().unwrap();
    let store = InstallStore::test_store(temp.path().join("updates/addon-code"), keys());
    (temp, store)
}
/// A catalog (display data) signed by the test authority.
pub(crate) fn catalog(sequence: u64, entries: &[(&str, &str, &str)]) -> Vec<u8> {
    sign(
        &json!({"schema":1,"sequence":sequence,"issued_at":1,"expires_at":u64::MAX,
            "addons":entries.iter().map(|(id,name,version)|json!({"id":id,"name":name,
                "summary":"A test add-on.","version":version,"size":10})).collect::<Vec<_>>()}),
        SIGNING_DOMAIN_ADDON_CATALOG,
    )
}
