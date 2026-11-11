use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x73; 32])
}
fn keys() -> TrustedKeys {
    TrustedKeys::new(vec![key().verifying_key()]).unwrap()
}
fn sign(value: &Value, domain: &[u8], key: &SigningKey) -> Vec<u8> {
    let payload = value.to_string();
    serde_json::to_vec(&json!({"v":1, "payload":payload,
        "sig":hex::encode(&key.sign(&[domain, payload.as_bytes()].concat()).to_bytes())}))
    .unwrap()
}
fn manifest() -> Value {
    json!({"id":"text-pages", "name":"Test pages", "version":"1.0.0", "host_api":1,
        "data_format":"text-pages-v1", "premium":true,
        "capabilities":["text_pages", "vault_notes_read", "selection_receive"], "mark":addon_mark(),
        "files":[{"path":"index.html", "size":5, "sha256":hex::encode(&Sha256::digest(b"hello"))}]})
}
fn index() -> Value {
    let bytes = sign(&manifest(), SIGNING_DOMAIN_ADDON_MANIFEST, &key());
    json!({"schema":1,"id":"text-pages","sequence":7,"issued_at":100,"expires_at":200,
        "current":{"version":"1.0.0","host_api":1,"data_format":"text-pages-v1",
            "manifest_size":bytes.len(),"manifest_sha256":hex::encode(&Sha256::digest(&bytes))},"rollback":null})
}

#[test]
fn addon_signature_authority_and_domain() {
    let m = manifest();
    assert!(
        verify_addon_manifest(&sign(&m, SIGNING_DOMAIN_ADDON_MANIFEST, &key()), &keys()).is_ok()
    );
    for (domain, signer) in [
        (SIGNING_DOMAIN_ADDON_INDEX, key()),
        (
            SIGNING_DOMAIN_ADDON_MANIFEST,
            SigningKey::from_bytes(&[0x74; 32]),
        ),
        (crate::SIGNING_DOMAIN, key()),
    ] {
        assert!(verify_addon_manifest(&sign(&m, domain, &signer), &keys()).is_err());
    }
    assert!(
        verify_addon_index(&sign(&index(), SIGNING_DOMAIN_ADDON_INDEX, &key()), &keys()).is_ok()
    );
    assert!(verify_addon_index(
        &sign(&index(), SIGNING_DOMAIN_ADDON_MANIFEST, &key()),
        &keys()
    )
    .is_err());
    let mut envelope: Value =
        serde_json::from_slice(&sign(&m, SIGNING_DOMAIN_ADDON_MANIFEST, &key())).unwrap();
    envelope["payload"] = json!(envelope["payload"]
        .as_str()
        .unwrap()
        .replace("Test pages", "Evil pages"));
    assert!(verify_addon_manifest(&serde_json::to_vec(&envelope).unwrap(), &keys()).is_err());
}

#[test]
fn addon_manifest_validator_table() {
    let good = manifest();
    let mut bad = Vec::new();
    for (field, value) in [
        ("id", json!("../escape")),
        ("id", json!("A")),
        ("id", json!("a".repeat(33))),
        ("name", json!("")),
        ("name", json!("é".repeat(81))),
        ("version", json!("1.0")),
        ("version", json!("1.0.0.0")),
        ("version", json!("01.0.0")),
        ("version", json!("1.0.0-rc")),
        ("version", json!("+1.0.0")),
        ("host_api", json!(2)),
        ("data_format", json!("unknown")),
        ("premium", json!(false)),
        ("mark", json!("wrong")),
        ("capabilities", json!(["execute"])),
        ("capabilities", json!(["text_pages", "text_pages"])),
        ("files", json!([])),
        ("unknown", json!(1)),
    ] {
        let mut m = good.clone();
        m[field] = value;
        bad.push(m);
    }
    let mut absent = good.clone();
    absent.as_object_mut().unwrap().remove("mark");
    bad.push(absent);
    for path in [
        "../x",
        "/x",
        "a//b",
        "a/./b",
        "a/../b",
        "a\\b",
        "%2fx",
        "a%5cb",
        "a?x",
        "C:x",
        "a.",
        "con",
        "NUL.txt",
        "COM1.js",
        "lpt9/x",
        "file ",
        "script.js",
    ] {
        let mut m = good.clone();
        m["files"][0]["path"] = json!(path);
        bad.push(m);
    }
    let mut m = good.clone();
    m["files"][0]["path"] = json!("a".repeat(129));
    bad.push(m);
    for (field, value) in [
        ("size", json!(MAX_ADDON_FILE_BYTES + 1)),
        ("sha256", json!("ab")),
    ] {
        let mut m = good.clone();
        m["files"][0][field] = value;
        bad.push(m);
    }
    for extra in ["index.html", "INDEX.html", "index.html/x"] {
        let mut m = good.clone();
        let mut f = m["files"][0].clone();
        f["path"] = json!(extra);
        m["files"].as_array_mut().unwrap().push(f);
        bad.push(m);
    }
    let mut m = good.clone();
    m["files"] = Value::Array(
        (0..257)
            .map(|i| json!({"path":format!("a{i}"),"size":0,"sha256":"0".repeat(64)}))
            .collect(),
    );
    bad.push(m);
    let mut m = good.clone();
    m["files"]=Value::Array((0..5).map(|i| {
        json!({"path":if i==0 {"index.html".to_string()} else {format!("a{i}")},"size":MAX_ADDON_FILE_BYTES,"sha256":"0".repeat(64)})
    }).collect());
    bad.push(m);
    for (n, m) in bad.into_iter().enumerate() {
        assert!(
            verify_addon_manifest(&sign(&m, SIGNING_DOMAIN_ADDON_MANIFEST, &key()), &keys())
                .is_err(),
            "case {n}"
        );
    }
    let mut collision = manifest();
    for path in ["Assets/a.js", "assets/b.js"] {
        collision["files"].as_array_mut().unwrap().push(json!({
            "path":path,"size":0,"sha256":"0".repeat(64)
        }));
    }
    assert!(verify_addon_manifest(
        &sign(&collision, SIGNING_DOMAIN_ADDON_MANIFEST, &key()),
        &keys()
    )
    .is_err());
    let mut boundary = good;
    boundary["name"] = json!("é".repeat(80));
    boundary["files"] = Value::Array(
        (0..4)
            .map(|i| {
                json!({
                    "path":if i==0 {"index.html".to_string()} else {format!("a{i}")},
                    "size":MAX_ADDON_FILE_BYTES, "sha256":"0".repeat(64)
                })
            })
            .collect(),
    );
    assert!(verify_addon_manifest(
        &sign(&boundary, SIGNING_DOMAIN_ADDON_MANIFEST, &key()),
        &keys()
    )
    .is_ok());
}

/// The notebook capability is a known word: a manifest that names it is
/// valid, still only once, and still never instead of `text_pages`.
#[test]
fn addon_manifest_accepts_the_notebook_capability() {
    let mut m = manifest();
    m["capabilities"] = json!(["text_pages", "selection_receive", "notebook"]);
    let verified = verify_addon_manifest(&sign(&m, SIGNING_DOMAIN_ADDON_MANIFEST, &key()), &keys()).unwrap();
    assert!(verified.capabilities().iter().any(|c| c == "notebook"));
    for caps in [json!(["text_pages", "notebook", "notebook"]), json!(["notebook"]), json!(["text_pages", "notebooks"])] {
        m["capabilities"] = caps.clone();
        assert!(
            verify_addon_manifest(&sign(&m, SIGNING_DOMAIN_ADDON_MANIFEST, &key()), &keys()).is_err(),
            "{caps}"
        );
    }
}

#[test]
fn addon_index_validator_and_binding_table() {
    let good = index();
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("rollback");
    assert!(
        verify_addon_index(&sign(&missing, SIGNING_DOMAIN_ADDON_INDEX, &key()), &keys()).is_err()
    );
    let bytes = sign(&manifest(), SIGNING_DOMAIN_ADDON_MANIFEST, &key());
    let checked =
        verify_addon_index(&sign(&good, SIGNING_DOMAIN_ADDON_INDEX, &key()), &keys()).unwrap();
    assert!(checked
        .current()
        .verify_manifest("text-pages", &bytes, &keys())
        .is_ok());
    assert!(checked
        .current()
        .verify_manifest("another", &bytes, &keys())
        .is_err());
    assert!(checked.valid_at(100));
    assert!(!checked.valid_at(200));
    assert!(!checked.valid_at(99));
    for (field, value) in [
        ("schema", json!(2)),
        ("id", json!("../x")),
        ("expires_at", json!(100)),
        ("sequence", json!(-1)),
        ("extra", json!(1)),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(
            verify_addon_index(&sign(&bad, SIGNING_DOMAIN_ADDON_INDEX, &key()), &keys()).is_err()
        );
    }
    for (field, value) in [
        ("manifest_size", json!(0)),
        ("manifest_size", json!(16385)),
        ("manifest_sha256", json!("bad")),
        ("version", json!("1")),
        ("host_api", json!(2)),
        ("data_format", json!("unknown")),
    ] {
        let mut bad = good.clone();
        bad["current"][field] = value;
        assert!(
            verify_addon_index(&sign(&bad, SIGNING_DOMAIN_ADDON_INDEX, &key()), &keys()).is_err()
        );
    }
    for (field, value) in [
        ("manifest_size", json!(bytes.len() + 1)),
        ("manifest_sha256", json!("0".repeat(64))),
        ("version", json!("2.0.0")),
    ] {
        let mut bad = good.clone();
        bad["current"][field] = value;
        let checked =
            verify_addon_index(&sign(&bad, SIGNING_DOMAIN_ADDON_INDEX, &key()), &keys()).unwrap();
        assert!(checked
            .current()
            .verify_manifest("text-pages", &bytes, &keys())
            .is_err());
    }
}

#[test]
fn addon_envelope_validator_table() {
    let good = sign(&manifest(), SIGNING_DOMAIN_ADDON_MANIFEST, &key());
    assert!(verify_addon_manifest(&good, &keys()).is_ok());
    let value: Value = serde_json::from_slice(&good).unwrap();
    let mut bad = vec![
        vec![b' '; MAX_ADDON_ENVELOPE_BYTES + 1],
        b"{}".to_vec(),
        [good.clone(), b"x".to_vec()].concat(),
    ];
    for (field, v) in [
        ("v", json!(2)),
        ("sig", json!("00")),
        ("payload", json!("x".repeat(MAX_ADDON_PAYLOAD_BYTES + 1))),
        ("unknown", json!(true)),
    ] {
        let mut v1 = value.clone();
        v1[field] = v;
        bad.push(serde_json::to_vec(&v1).unwrap());
    }
    for b in bad {
        assert!(verify_addon_manifest(&b, &keys()).is_err());
    }
}

#[test]
fn addon_asset_hash_refuses_same_size_tamper() {
    let m = verify_addon_manifest(
        &sign(&manifest(), SIGNING_DOMAIN_ADDON_MANIFEST, &key()),
        &keys(),
    )
    .unwrap();
    assert!(m.files()[0].verify(b"hello").is_ok());
    assert!(m.files()[0].verify(b"jello").is_err());
    assert!(m.files()[0].verify(b"hell").is_err());
}

fn catalog() -> Value {
    json!({"schema":1,"sequence":4,"issued_at":100,"expires_at":200,"addons":[
        {"id":"text-pages","name":"Test pages","summary":"Pages in a window over any site.",
         "version":"1.0.0","size":153033},
        {"id":"other-tool","name":"Other tool","summary":"Something else.","version":"0.2.0","size":1}]})
}

#[test]
fn addon_catalog_verifies_under_its_own_domain_only() {
    let good = sign(&catalog(), SIGNING_DOMAIN_ADDON_CATALOG, &key());
    let c = verify_addon_catalog(&good, &keys()).unwrap();
    assert_eq!(c.sequence(), 4);
    assert_eq!(c.addons().len(), 2);
    assert_eq!(c.addons()[0].id(), "text-pages");
    assert_eq!(c.addons()[0].name(), "Test pages");
    assert_eq!(c.addons()[0].summary(), "Pages in a window over any site.");
    assert_eq!(c.addons()[0].version().to_string(), "1.0.0");
    assert_eq!(c.addons()[0].size(), 153033);
    assert!(c.valid_at(100) && c.valid_at(199) && !c.valid_at(99) && !c.valid_at(200));
    for (domain, signer) in [
        (SIGNING_DOMAIN_ADDON_INDEX, key()),
        (SIGNING_DOMAIN_ADDON_MANIFEST, key()),
        (crate::SIGNING_DOMAIN, key()),
        (SIGNING_DOMAIN_ADDON_CATALOG, SigningKey::from_bytes(&[0x74; 32])),
    ] {
        assert!(verify_addon_catalog(&sign(&catalog(), domain, &signer), &keys()).is_err());
    }
    // A catalog can never pass as an index or a manifest.
    assert!(verify_addon_index(&good, &keys()).is_err());
    assert!(verify_addon_manifest(&good, &keys()).is_err());
    let mut envelope: Value = serde_json::from_slice(&good).unwrap();
    envelope["payload"] = json!(envelope["payload"].as_str().unwrap().replace("Test pages", "Evil pages"));
    assert!(verify_addon_catalog(&serde_json::to_vec(&envelope).unwrap(), &keys()).is_err());
}

#[test]
fn addon_catalog_validator_table() {
    let mut bad = Vec::new();
    for (field, value) in [
        ("schema", json!(2)),
        ("issued_at", json!(200)),
        ("addons", json!([])),
        ("unknown", json!(true)),
    ] {
        let mut c = catalog();
        c[field] = value;
        bad.push(c);
    }
    let one = |id: &str| json!({"id":id,"name":"N","summary":"S","version":"1.0.0","size":1});
    let mut many = catalog();
    many["addons"] = json!((0..=MAX_CATALOG_ENTRIES).map(|i| one(&format!("a{i}"))).collect::<Vec<_>>());
    bad.push(many);
    let mut duplicate = catalog();
    duplicate["addons"][1]["id"] = json!("text-pages");
    bad.push(duplicate);
    for (field, value) in [
        ("id", json!("../escape")),
        ("id", json!("A")),
        ("id", json!("1abc")),
        ("name", json!("")),
        ("name", json!("   ")),
        ("name", json!("é".repeat(81))),
        ("name", json!("line\nbreak")),
        ("summary", json!("")),
        ("summary", json!("s".repeat(MAX_CATALOG_SUMMARY_CHARS + 1))),
        ("summary", json!("tab\there")),
        ("version", json!("1.0")),
        ("version", json!("01.0.0")),
        ("size", json!(0)),
        ("size", json!(MAX_CATALOG_SIZE + 1)),
        ("size", json!(-1)),
        ("extra", json!("x")),
    ] {
        let mut c = catalog();
        c["addons"][0][field] = value;
        bad.push(c);
    }
    for c in bad {
        let text = c.to_string();
        assert!(
            verify_addon_catalog(&sign(&c, SIGNING_DOMAIN_ADDON_CATALOG, &key()), &keys()).is_err(),
            "accepted {text}"
        );
    }
    // At the limits.
    let mut edge = catalog();
    edge["addons"][0]["name"] = json!("é".repeat(80));
    edge["addons"][0]["summary"] = json!("s".repeat(MAX_CATALOG_SUMMARY_CHARS));
    edge["addons"][0]["size"] = json!(MAX_CATALOG_SIZE);
    assert!(verify_addon_catalog(&sign(&edge, SIGNING_DOMAIN_ADDON_CATALOG, &key()), &keys()).is_ok());
}

#[test]
fn addon_catalog_succession() {
    let first = verify_addon_catalog(&sign(&catalog(), SIGNING_DOMAIN_ADDON_CATALOG, &key()), &keys()).unwrap();
    assert!(first.succeeds(&first));
    let mut next = catalog();
    next["sequence"] = json!(5);
    let next = verify_addon_catalog(&sign(&next, SIGNING_DOMAIN_ADDON_CATALOG, &key()), &keys()).unwrap();
    assert!(next.succeeds(&first));
    assert!(!first.succeeds(&next));
    let mut same_sequence = catalog();
    same_sequence["addons"][0]["summary"] = json!("Changed.");
    let same = verify_addon_catalog(&sign(&same_sequence, SIGNING_DOMAIN_ADDON_CATALOG, &key()), &keys()).unwrap();
    assert!(!same.succeeds(&first));
}
