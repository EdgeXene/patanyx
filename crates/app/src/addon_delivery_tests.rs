use super::*;
use crate::addon_testkit::*;
use std::io::Cursor;

fn auth() -> Credentials {
    Credentials::new("disposable-test-token".into(), "a".repeat(32)).unwrap()
}
fn response(status: u16, bytes: Vec<u8>, file: bool) -> Response {
    Response {
        status,
        length: Some(bytes.len() as u64),
        content_type: Some(
            if file {
                "application/octet-stream"
            } else {
                "application/json"
            }
            .into(),
        ),
        retry_after: None,
        reader: Box::new(Cursor::new(bytes)),
    }
}
const LICENCE: &str = "https://licence.invalid";
const CDN: &str = "https://cdn.invalid";
/// The licence service (index and passes) and the CDN (files, by pass) as
/// one fake, counting each side, and asserting what each side may see.
struct Service {
    index: Vec<u8>,
    packages: Vec<Package>,
    requests: usize,
    cdn_requests: usize,
    /// Answer every CDN request with this refusal instead of the file.
    cdn_refusal: Option<(u16, &'static str)>,
    /// What /premium/addon/catalog answers.
    catalog: Option<Response>,
}
fn pass_for(version: &str) -> String {
    format!("cGFzcy{}.c2ln", version.replace('.', "x"))
}
fn json(status: u16, value: serde_json::Value) -> Response {
    response(status, serde_json::to_vec(&value).unwrap(), false)
}
impl Transport for Service {
    fn post(&mut self, r: Request) -> Result<Response, DeliveryError> {
        self.requests += 1;
        assert!(r.url.starts_with(LICENCE), "a POST left the licence service: {}", r.url);
        assert!(!r.url.contains("disposable-test-token"));
        assert!(!r.url.contains('?'));
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body["token"], "disposable-test-token");
        assert_eq!(body["device_id"], "a".repeat(32));
        if r.url.ends_with("/premium/addon/catalog") {
            // Credentials and nothing else: no add-on id, no version.
            assert_eq!(body.as_object().unwrap().len(), 2);
            return Ok(self.catalog.take().expect("an unexpected catalog request"));
        }
        assert_eq!(body["id"], ID);
        if r.url.ends_with("/premium/addon/index") {
            assert_eq!(body.as_object().unwrap().len(), 3);
            return Ok(response(200, self.index.clone(), true));
        }
        assert!(r.url.ends_with("/premium/addon/grant"), "{}", r.url);
        assert_eq!(body.as_object().unwrap().len(), 4);
        Ok(json(200, serde_json::json!({ "grant": pass_for(body["version"].as_str().unwrap()) })))
    }
    fn get(&mut self, r: CdnRequest) -> Result<Response, DeliveryError> {
        self.cdn_requests += 1;
        let rest = r.url.strip_prefix(&format!("{CDN}/addons/{ID}/")).expect("a GET outside the CDN's add-on path");
        assert!(!r.url.contains("disposable-test-token") && !r.url.contains(&"a".repeat(32)) && !r.url.contains('?'));
        let (version, path) = rest.split_once('/').unwrap();
        assert_eq!(r.pass.as_str(), pass_for(version), "the pass is for another release");
        if let Some((status, error)) = self.cdn_refusal {
            return Ok(json(status, serde_json::json!({ "error": error })));
        }
        let package = self.packages.iter().find(|p| p.release["version"] == version).unwrap();
        let bytes = if path == "manifest.sig.json" {
            package.manifest.clone()
        } else {
            package.files[path.strip_prefix("files/").unwrap()].clone()
        };
        Ok(response(200, bytes, true))
    }
}
fn service(index: Vec<u8>, packages: Vec<Package>) -> Service {
    Service { index, packages, requests: 0, cdn_requests: 0, cdn_refusal: None, catalog: None }
}

#[test]
fn addon_delivery_success_and_token_only_in_body() {
    let (_temp, store) = store();
    let p = package("1.0.0", "test");
    let files = p.files.len();
    let mut service = service(sign(&index(1, &p, None), SIGNING_DOMAIN_ADDON_INDEX), vec![p]);
    let cancel = Cancellation::new();
    let client = DeliveryClient::new(auth(), cancel.clone());
    let prepared = client
        .download_with(LICENCE, CDN, ID, ReleaseChoice::Current, &store, &mut service)
        .unwrap();
    store.activate(prepared, &cancel, || true).unwrap();
    // The licence service: the index and one pass. The CDN: manifest + files.
    assert_eq!(service.requests, 2);
    assert_eq!(service.cdn_requests, 1 + files);
    let r = request(LICENCE, &auth(), ID, None).unwrap();
    assert_eq!(r.url, "https://licence.invalid/premium/addon/index");
    assert!(!r.url.contains("disposable-test-token"));
}

#[test]
fn addon_delivery_cdn_refusal_stops_the_install_and_says_why() {
    for (status, error, want) in [(401, "bad_grant", Refusal::BadGrant), (404, "not_found", Refusal::NotFound)] {
        let (_temp, store) = store();
        let p = package("1.0.0", "test");
        let mut service = service(sign(&index(1, &p, None), SIGNING_DOMAIN_ADDON_INDEX), vec![p]);
        service.cdn_refusal = Some((status, error));
        let client = DeliveryClient::new(auth(), Cancellation::new());
        let result = client.download_with(LICENCE, CDN, ID, ReleaseChoice::Current, &store, &mut service);
        assert!(matches!(result, Err(DeliveryError::Refused { code, .. }) if code == want), "{error}");
        // It stopped at the manifest: no file was asked for after a refusal.
        assert_eq!(service.cdn_requests, 1);
    }
}

#[test]
fn addon_delivery_pass_answers_are_strict() {
    assert_eq!(parse_pass(br#"{"grant":"YWJj.ZGVm"}"#).unwrap().as_str(), "YWJj.ZGVm");
    for bad in [
        &br#"{"grant":"YWJj"}"#[..],
        br#"{"grant":"YWJj.ZGVm.Z2hp"}"#,
        br#"{"grant":"YW Jj.ZGVm"}"#,
        br#"{"grant":".ZGVm"}"#,
        br#"{"grant":"YWJj.ZGVm","extra":1}"#,
        br#"{"pass":"YWJj.ZGVm"}"#,
        b"not json",
    ] {
        assert!(parse_pass(bad).is_err(), "{}", String::from_utf8_lossy(bad));
    }
    let long = format!(r#"{{"grant":"{}.ZGVm"}}"#, "a".repeat(MAX_PASS_CHARS));
    assert!(parse_pass(long.as_bytes()).is_err());
}

#[test]
fn addon_delivery_cdn_request_validator_table() {
    let (_temp, store) = store();
    let p = package("1.0.0", "test");
    let signed = sign(&index(1, &p, None), SIGNING_DOMAIN_ADDON_INDEX);
    let idx = store.accept_index(ID, &signed, crate::addon_install::now().unwrap()).unwrap();
    let release = idx.current();
    let pass = Zeroizing::new("YWJj.ZGVm".to_string());
    let r = cdn_request(CDN, ID, release, "files/index.html", &pass).unwrap();
    assert_eq!(r.url, format!("{CDN}/addons/{ID}/1.0.0/files/index.html"));
    for path in ["../x", "files/../x", "files/", "other.json", "files/a?b"] {
        assert!(cdn_request(CDN, ID, release, path, &pass).is_err(), "{path}");
    }
    for origin in ["http://external.invalid", "https://x/path", "https://x/?a=b", "https://u:p@x/"] {
        assert!(cdn_request(origin, ID, release, "manifest.sig.json", &pass).is_err(), "{origin}");
    }
}

#[test]
fn addon_delivery_response_validator_table() {
    let cancel = Cancellation::new();
    assert_eq!(
        receive(response(200, b"ok".to_vec(), true), 2, true, &cancel).unwrap(),
        b"ok"
    );
    assert_eq!(
        receive(response(302, vec![], false), 20, false, &cancel),
        Err(DeliveryError::Redirect)
    );
    assert_eq!(
        receive(response(200, vec![0; 3], true), 2, true, &cancel),
        Err(DeliveryError::TooLarge)
    );
    let mut r = response(200, vec![0; 3], true);
    r.length = None;
    assert_eq!(receive(r, 2, true, &cancel), Err(DeliveryError::TooLarge));
    let mut r = response(200, vec![0; 1], true);
    r.length = Some(2);
    assert_eq!(receive(r, 2, true, &cancel), Err(DeliveryError::Response));
    for (status, code) in [
        (400, "bad_request"),
        (401, "bad_token"),
        (403, "not_activated"),
        (404, "not_found"),
        (410, "expired"),
        (429, "rate_limited"),
        (401, "bad_grant"),
        (503, "unavailable"),
    ] {
        assert!(matches!(
            receive(
                response(
                    status,
                    serde_json::to_vec(&serde_json::json!({"error":code})).unwrap(),
                    false
                ),
                10,
                false,
                &cancel
            ),
            Err(DeliveryError::Refused { .. })
        ));
    }
    for (status, bytes) in [
        (500, b"{}".to_vec()),
        (401, b"{\"error\":\"arbitrary secret\"}".to_vec()),
        (401, vec![0; 4097]),
        (
            403,
            b"{\"error\":\"not_activated\",\"extra\":true}".to_vec(),
        ),
    ] {
        let error = receive(response(status, bytes, false), 20, false, &cancel).unwrap_err();
        assert!(!format!("{error:?}").contains("arbitrary secret"));
    }
    cancel.cancel();
    assert_eq!(
        receive(response(200, vec![], false), 10, false, &cancel),
        Err(DeliveryError::Cancelled)
    );
}

#[test]
fn addon_delivery_request_validator_table() {
    for origin in [
        "https://x/?token=secret",
        "https://name:password@x/",
        "https://x/#frag",
        "https://x/path",
        "http://external.invalid",
        "file:///tmp/x",
    ] {
        assert!(request(origin, &auth(), ID, None).is_err());
    }
    assert!(Credentials::new("x".into(), "A".repeat(32)).is_err());
    assert!(Credentials::new("".into(), "a".repeat(32)).is_err());
}

#[test]
fn addon_delivery_rejects_corruption_and_cancellation() {
    let (_temp, store) = store();
    let mut p = package("1.0.0", "good");
    let bytes = sign(&index(1, &p, None), SIGNING_DOMAIN_ADDON_INDEX);
    p.files.insert("index.html".into(), b"evil".to_vec());
    let mut service = service(bytes, vec![p]);
    let cancel = Cancellation::new();
    let client = DeliveryClient::new(auth(), cancel.clone());
    assert!(client
        .download_with(LICENCE, CDN, ID, ReleaseChoice::Current, &store, &mut service)
        .is_err());
    let before = (service.requests, service.cdn_requests);
    cancel.cancel();
    assert!(matches!(
        client.download_with(LICENCE, CDN, ID, ReleaseChoice::Current, &store, &mut service),
        Err(DeliveryError::Cancelled)
    ));
    assert_eq!(before, (service.requests, service.cdn_requests));
}

#[cfg(feature = "updater-net")]
#[test]
#[ignore = "requires loopback sockets; sandbox denies bind"]
fn addon_delivery_http_refuses_redirect_without_sending_token_to_target() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let location = format!("http://{}/stolen", target.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        assert!(bytes.starts_with(b"POST /premium/addon/index HTTP/1.1\r\n"));
        write!(stream,"HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    let mut http = Http::new().unwrap();
    let r = http
        .post(request(&origin, &auth(), ID, None).unwrap())
        .unwrap();
    assert_eq!(
        receive(r, 100, false, &Cancellation::new()),
        Err(DeliveryError::Redirect)
    );
    worker.join().unwrap();
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(feature = "updater-net")]
#[test]
fn addon_delivery_agent_disables_redirects_and_bounds_time() {
    // ureq exposes its effective AgentConfig through Debug, without a request.
    let http = Http::new().unwrap();
    for agent in [&http.agent, &http.cdn] {
        let configuration = format!("{agent:?}");
        assert!(configuration.contains("redirects: 0,"));
        assert!(configuration.contains("timeout: Some(30s)"));
        assert!(configuration.contains("timeout_connect: Some(10s)"));
    }
}

#[test]
fn addon_delivery_downloads_the_authorized_rollback_alongside_current() {
    let (_temp, store) = store();
    let old = package("1.0.0", "old");
    let new = package("2.0.0", "new");
    let files = new.files.len() + old.files.len();
    let mut service = service(sign(&index(2, &new, Some(&old)), SIGNING_DOMAIN_ADDON_INDEX), vec![new, old]);
    let cancel = Cancellation::new();
    let client = DeliveryClient::new(auth(), cancel.clone());
    let prepared = client
        .download_with(LICENCE, CDN, ID, ReleaseChoice::Current, &store, &mut service)
        .unwrap();
    store.activate(prepared, &cancel, || true).unwrap();
    store.rollback(ID, &cancel, || true).unwrap();
    // The index and a pass for each release; two manifests and every file.
    assert_eq!(service.requests, 3);
    assert_eq!(service.cdn_requests, 2 + files);
}

/// QUALIFICATION, run by hand (M17): the published add-on, exactly the signed
/// bytes the licence service serves, through the delivery client and install
/// store a release build uses, under the PRODUCTION add-on keys. Then the same
/// with one byte of one file changed, which must be refused. Ignored: the
/// bundle is closed code and never in this tree. Point
/// PATANYX_ADDON_QUAL_DIR at a copy of the service's folder for one add-on
/// (index.sig.json, <version>/manifest.sig.json, <version>/files/...):
///   PATANYX_ADDON_QUAL_DIR=/path/to/<id> cargo test -p patanyx -- --ignored qualification_
#[test]
#[ignore]
fn qualification_the_published_addon_installs_under_the_production_keys() {
    use std::path::PathBuf;
    struct Published {
        dir: PathBuf,
        id: String,
        tamper: Option<&'static str>,
    }
    impl Transport for Published {
        fn post(&mut self, r: Request) -> Result<Response, DeliveryError> {
            let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            assert_eq!(body["id"], self.id.as_str());
            if r.url.ends_with("/premium/addon/grant") {
                return Ok(json(200, serde_json::json!({ "grant": "cXVhbA.c2ln" })));
            }
            Ok(response(200, std::fs::read(self.dir.join("index.sig.json")).unwrap(), true))
        }
        fn get(&mut self, r: CdnRequest) -> Result<Response, DeliveryError> {
            let rest = r.url.strip_prefix(&format!("{CDN}/addons/{}/", self.id)).unwrap();
            let (version, path) = rest.split_once('/').unwrap();
            let mut bytes = std::fs::read(self.dir.join(version).join(path)).unwrap();
            if Some(path) == self.tamper {
                bytes[0] ^= 0x01;
            }
            Ok(response(200, bytes, true))
        }
    }
    let dir = PathBuf::from(std::env::var("PATANYX_ADDON_QUAL_DIR").expect("set PATANYX_ADDON_QUAL_DIR"));
    let id = dir.file_name().unwrap().to_str().unwrap().to_string();
    let attempt = |tamper: Option<&'static str>| {
        let temp = tempfile::tempdir().unwrap();
        let keys = crate::updater::addon_trusted_keys().expect("the production add-on keys");
        let store = InstallStore::test_store(temp.path().join("addon-code"), keys);
        let cancel = Cancellation::new();
        let client = DeliveryClient::new(auth(), cancel.clone());
        let mut service = Published { dir: dir.clone(), id: id.clone(), tamper };
        let installed = client
            .download_with(LICENCE, CDN, &id, ReleaseChoice::Current, &store, &mut service)
            .map_err(|e| e.to_string())
            .and_then(|prepared| store.activate(prepared, &cancel, || true).map_err(|e| e.to_string()))
            .and_then(|()| store.open_for_test(&id).map_err(|e| e.to_string()));
        installed.map(|bundle| (bundle.manifest().version().to_string(), bundle.files().len()))
    };
    let (version, files) = attempt(None).expect("the published add-on did not install");
    eprintln!("installed {id} {version}: {files} files, every one verified");
    assert!(files > 0 && version.split('.').count() == 3);
    assert!(attempt(Some("files/index.html")).is_err(), "a changed byte was installed");
}

/// QUALIFICATION, run by hand before a successor release is published (plan
/// R-031, R-033): a profile that holds the LIVE catalog and index, with the
/// live release installed, takes the staged successor catalog and index,
/// upgrades, rolls back to the authorized release and forward again, refuses
/// the older live envelopes once it holds the successors, and, when a
/// rehearsal folder is given, takes a later rollback publication that names
/// the previous release as current. All under the PRODUCTION add-on keys,
/// through the delivery client and install store a release build uses.
/// Each *_DIR is a copy of the service's folder for one add-on; each
/// *_CATALOG is a catalog.sig.json:
///   PATANYX_ADDON_QUAL_LIVE_DIR, PATANYX_ADDON_QUAL_LIVE_CATALOG,
///   PATANYX_ADDON_QUAL_NEXT_DIR, PATANYX_ADDON_QUAL_NEXT_CATALOG,
///   optional PATANYX_ADDON_QUAL_BACK_DIR, PATANYX_ADDON_QUAL_BACK_CATALOG
///   cargo test -p patanyx -- --ignored qualification_a_profile
#[test]
#[ignore]
fn qualification_a_profile_holding_the_live_release_takes_the_successor() {
    use std::path::PathBuf;
    struct Folder(PathBuf, String);
    impl Transport for Folder {
        fn post(&mut self, r: Request) -> Result<Response, DeliveryError> {
            if r.url.ends_with("/premium/addon/grant") {
                return Ok(json(200, serde_json::json!({ "grant": "cXVhbA.c2ln" })));
            }
            Ok(response(200, std::fs::read(self.0.join("index.sig.json")).unwrap(), true))
        }
        fn get(&mut self, r: CdnRequest) -> Result<Response, DeliveryError> {
            let rest = r.url.strip_prefix(&format!("{CDN}/addons/{}/", self.1)).unwrap();
            let (version, path) = rest.split_once('/').unwrap();
            Ok(response(200, std::fs::read(self.0.join(version).join(path)).unwrap(), true))
        }
    }
    let env = |k: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| panic!("set {k}")));
    let live_dir = env("PATANYX_ADDON_QUAL_LIVE_DIR");
    let id = live_dir.file_name().unwrap().to_str().unwrap().to_string();
    let temp = tempfile::tempdir().unwrap();
    let store = InstallStore::test_store(temp.path().join("addon-code"), crate::updater::addon_trusted_keys().unwrap());
    let cancel = Cancellation::new();
    let client = DeliveryClient::new(auth(), cancel.clone());
    let now = crate::addon_install::now().unwrap();
    let catalog = |k: &str| store.accept_catalog(&std::fs::read(env(k)).unwrap(), now);
    let install = |dir: &PathBuf| {
        let prepared = client
            .download_with(LICENCE, CDN, &id, ReleaseChoice::Current, &store, &mut Folder(dir.clone(), id.clone()))
            .map_err(|e| format!("{e:?}"))?;
        store.activate(prepared, &cancel, || true).map_err(|e| format!("{e:?}"))
    };
    let version = || store.open_for_test(&id).unwrap().manifest().version().to_string();

    let held = catalog("PATANYX_ADDON_QUAL_LIVE_CATALOG").expect("the live catalog");
    install(&live_dir).expect("the live release");
    let live = version();
    eprintln!("seeded: catalog seq {} ({}), installed {live}", held.sequence(), held.addons()[0].version());

    let next = catalog("PATANYX_ADDON_QUAL_NEXT_CATALOG").expect("the successor catalog over the live one");
    assert!(next.sequence() > held.sequence());
    assert_eq!(store.saved_catalog().unwrap().unwrap().sequence(), next.sequence());
    install(&env("PATANYX_ADDON_QUAL_NEXT_DIR")).expect("the successor index and release over the live ones");
    let upgraded = version();
    assert_ne!(upgraded, live);
    assert_eq!(upgraded, next.addons()[0].version().to_string(), "the catalog names the installed release");
    eprintln!("upgraded {live} -> {upgraded} under catalog seq {}", next.sequence());

    store.rollback(&id, &cancel, || true).expect("the authorized rollback");
    assert_eq!(version(), live, "the rollback is the release the profile had");
    install(&env("PATANYX_ADDON_QUAL_NEXT_DIR")).expect("forward again");
    assert_eq!(version(), upgraded);
    eprintln!("rolled back to {live} and forward to {upgraded}");

    assert!(catalog("PATANYX_ADDON_QUAL_LIVE_CATALOG").is_err(), "the older catalog replaced the successor");
    assert!(install(&live_dir).is_err(), "the older index replaced the successor");
    assert_eq!(version(), upgraded);
    assert_eq!(store.saved_catalog().unwrap().unwrap().sequence(), next.sequence());
    eprintln!("the live envelopes are refused once the successors are held");

    if std::env::var_os("PATANYX_ADDON_QUAL_BACK_DIR").is_some() {
        let back = catalog("PATANYX_ADDON_QUAL_BACK_CATALOG").expect("the rehearsed rollback catalog");
        install(&env("PATANYX_ADDON_QUAL_BACK_DIR")).expect("the rehearsed rollback publication");
        assert_eq!(version(), back.addons()[0].version().to_string());
        eprintln!("rehearsal: catalog seq {} puts {} back as current", back.sequence(), version());
    }
}

/// END TO END, run by hand before a delivery change ships: the real HTTP
/// client against a real licence service (throwaway, loopback) and the real
/// add-on CDN Worker (`wrangler dev`, loopback), installing the published
/// bundle under the PRODUCTION add-on keys. Debug builds only (the origin
/// overrides exist only there). Environment:
///   PATANYX_LICENCE_ORIGIN=http://127.0.0.1:<port>  PATANYX_ADDON_CDN=http://127.0.0.1:<port>
///   ADDON_E2E_TOKEN=<throwaway token>  ADDON_E2E_DEVICE=<32 hex, activated>  ADDON_E2E_ID=text-pages
#[cfg(all(feature = "updater-net", debug_assertions))]
#[test]
#[ignore = "needs a loopback licence service and CDN Worker"]
fn end_to_end_install_through_the_licence_service_and_the_cdn() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
    let id = env("ADDON_E2E_ID");
    assert!(crate::activation::licence_origin().starts_with("http://127.0.0.1:"), "licence origin override not taken");
    assert!(addon_cdn_origin().starts_with("http://127.0.0.1:"), "CDN origin override not taken");
    let temp = tempfile::tempdir().unwrap();
    let keys = crate::updater::addon_trusted_keys().expect("the production add-on keys");
    let store = InstallStore::test_store(temp.path().join("addon-code"), keys);
    let cancel = Cancellation::new();
    let client = DeliveryClient::new(Credentials::new(env("ADDON_E2E_TOKEN"), env("ADDON_E2E_DEVICE")).unwrap(), cancel.clone());
    let prepared = client.download(&id, ReleaseChoice::Current, &store).expect("download");
    store.activate(prepared, &cancel, || true).unwrap();
    let bundle = store.open_for_test(&id).unwrap();
    eprintln!("E2E installed {id} {} ({} files) through the CDN", bundle.manifest().version(), bundle.files().len());
    store.rollback(&id, &cancel, || true).expect("the authorized rollback installed from the same download");
    eprintln!("E2E rolled back to {}", store.open_for_test(&id).unwrap().manifest().version());
    // A device that is not activated gets no pass, so nothing from the CDN.
    let stranger = DeliveryClient::new(Credentials::new(env("ADDON_E2E_TOKEN"), "e".repeat(32)).unwrap(), Cancellation::new());
    let temp2 = tempfile::tempdir().unwrap();
    let store2 = InstallStore::test_store(temp2.path().join("addon-code"), crate::updater::addon_trusted_keys().unwrap());
    assert!(matches!(
        stranger.download(&id, ReleaseChoice::Current, &store2),
        Err(DeliveryError::Refused { code: Refusal::NotActivated, .. })
    ));
}

#[test]
fn the_catalog_is_fetched_with_credentials_only_verified_and_recorded() {
    let (_temp, store) = store();
    let client = DeliveryClient::new(auth(), Cancellation::new());
    let mut licence = service(Vec::new(), Vec::new());
    licence.catalog = Some(response(200, catalog(1, &[(ID, "Test pages", "1.0.0")]), true));
    let held = client.catalog_with(LICENCE, &store, &mut licence).unwrap();
    assert_eq!(licence.requests, 1);
    assert_eq!(licence.cdn_requests, 0);
    assert_eq!(held.addons()[0].name(), "Test pages");
    assert_eq!(store.saved_catalog().unwrap(), Some(held));
    // A refusal says why, with the server's Retry-After for a 429, and
    // leaves the held catalog alone.
    for (status, error, want) in [
        (401, "bad_token", Refusal::BadToken),
        (403, "not_activated", Refusal::NotActivated),
        (410, "expired", Refusal::Expired),
        (404, "not_found", Refusal::NotFound),
        (429, "rate_limited", Refusal::RateLimited),
    ] {
        let mut answer = json(status, serde_json::json!({ "error": error }));
        answer.retry_after = Some(120);
        licence.catalog = Some(answer);
        match client.catalog_with(LICENCE, &store, &mut licence) {
            Err(DeliveryError::Refused { code, retry_after }) => {
                assert_eq!(code, want);
                assert_eq!(retry_after, if status == 429 { Some(120) } else { None });
            }
            other => panic!("{status}: {other:?}"),
        }
    }
    // A catalog that does not verify is not recorded.
    let mut forged: serde_json::Value = serde_json::from_slice(&catalog(2, &[(ID, "Test pages", "1.0.0")])).unwrap();
    forged["payload"] = serde_json::json!(forged["payload"].as_str().unwrap().replace("Test pages", "Evil"));
    licence.catalog = Some(response(200, serde_json::to_vec(&forged).unwrap(), true));
    assert!(client.catalog_with(LICENCE, &store, &mut licence).is_err());
    assert_eq!(store.saved_catalog().unwrap().unwrap().sequence(), 1);
    // Over the envelope cap: refused before it is read whole.
    licence.catalog = Some(response(200, vec![b' '; MAX_ADDON_ENVELOPE_BYTES + 1], true));
    assert_eq!(client.catalog_with(LICENCE, &store, &mut licence).unwrap_err(), DeliveryError::TooLarge);
    // A plain-HTTP or credentialed origin is refused before anything is sent.
    let before = licence.requests;
    for origin in ["http://licence.invalid", "https://user:pw@licence.invalid", "https://licence.invalid/x"] {
        assert_eq!(client.catalog_with(origin, &store, &mut licence).unwrap_err(), DeliveryError::InvalidRequest);
    }
    assert_eq!(licence.requests, before);
}

#[test]
fn a_front_server_rate_limit_with_an_html_body_is_still_a_rate_limit() {
    let mut answer = response(429, b"<html>429 Too Many Requests</html>".to_vec(), false);
    answer.retry_after = Some(30);
    assert_eq!(
        receive(answer, 1024, false, &Cancellation::new()).unwrap_err(),
        DeliveryError::Refused { code: Refusal::RateLimited, retry_after: Some(30) }
    );
    // Even when its page is larger than an error body may be (review R-004).
    let mut answer = response(429, vec![b'x'; 4097], false);
    answer.retry_after = Some(3600);
    assert_eq!(
        receive(answer, 1024, false, &Cancellation::new()).unwrap_err(),
        DeliveryError::Refused { code: Refusal::RateLimited, retry_after: Some(3600) }
    );
    let mut answer = response(429, vec![b'x'; 4097], false);
    answer.length = None;
    answer.retry_after = Some(120);
    assert_eq!(
        receive(answer, 1024, false, &Cancellation::new()).unwrap_err(),
        DeliveryError::Refused { code: Refusal::RateLimited, retry_after: Some(120) }
    );
    // A route the front server does not know is "nothing published".
    let answer = response(404, b"<html>404 Not Found</html>".to_vec(), false);
    assert_eq!(
        receive(answer, 1024, false, &Cancellation::new()).unwrap_err(),
        DeliveryError::Refused { code: Refusal::NotFound, retry_after: None }
    );
    // Any other unreadable error body is still a broken answer.
    let answer = response(500, b"<html>oops</html>".to_vec(), false);
    assert_eq!(receive(answer, 1024, false, &Cancellation::new()).unwrap_err(), DeliveryError::Response);
}
