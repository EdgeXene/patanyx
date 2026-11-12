//! Sealed Premium calls, seal v1. The Premium token is never exposed, and every
//! Premium call works on a network that inspects TLS, with nothing to set up.
//!
//! A TLS-inspecting proxy (Zscaler on a managed laptop) decrypts and re-signs
//! every connection, so TLS alone cannot keep the Premium token from it. Each
//! Premium call therefore seals its body to the licence server's own X25519
//! key, pinned below, and the server seals its answer back to this call's
//! one-time key. Only then may the call trust the operating system's
//! certificate store and the machine's proxy: what such a network can read is
//! ciphertext both ways. The server side is the licence server's seal.rs; both
//! check the same test vector.
//!
//! - a fresh ephemeral key `e` per call; `shared = X25519(e, S)`; HKDF-SHA256
//!   with salt `e_pub || S_pub` gives `k_req` and `k_resp`;
//! - request: XChaCha20-Poly1305 under `k_req`, AAD `"pps1-req" || path`, over
//!   `{"body","path","ts"}` (`body` is the exact JSON the call sent in clear
//!   before); wire form `{"v":1,"epk","n","ct"}` (hex);
//! - response: XChaCha20-Poly1305 under `k_resp`, AAD
//!   `"pps1-resp" || path || status`, wire form `{"v":1,"n","ct"}`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The licence server's sealed-request key (public half). The server refuses
/// to start with a key that does not derive exactly this.
const SEAL_PUBLIC_KEY: [u8; 32] = [
    0x59, 0xd1, 0x8c, 0x07, 0x63, 0xfd, 0x8c, 0x96, 0x83, 0x04, 0x83, 0x22, 0x34, 0xe6, 0x38, 0x8a,
    0xe3, 0xd4, 0x85, 0x63, 0xf2, 0xe1, 0xb0, 0x72, 0x53, 0x3f, 0xe9, 0x3a, 0xc6, 0x22, 0xc8, 0x41,
];

const INFO_REQ: &[u8] = b"patanyx premium seal v1 request";
const INFO_RESP: &[u8] = b"patanyx premium seal v1 response";
const AAD_REQ: &[u8] = b"pps1-req";
const AAD_RESP: &[u8] = b"pps1-resp";

/// The largest sealed answer read: the server seals at most 1 MiB, doubled by
/// hex, plus the envelope.
pub(crate) const MAX_SEALED_RESPONSE: usize = 2 * 1024 * 1024 + 4096;

/// The server key in force. DEBUG BUILDS ONLY may take a test key from
/// `PATANYX_SEAL_PUBLIC_KEY`, for the end-to-end gate's local server, exactly as
/// `activation::licence_origin` takes a loopback origin.
fn server_key() -> [u8; 32] {
    #[cfg(debug_assertions)]
    if let Some(key) = std::env::var("PATANYX_SEAL_PUBLIC_KEY")
        .ok()
        .and_then(|v| unhex(&v))
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        return key;
    }
    SEAL_PUBLIC_KEY
}

/// One sealed call: the body to send, and what opens its answer.
pub(crate) struct Sealed {
    pub(crate) wire: Vec<u8>,
    path: String,
    k_resp: Zeroizing<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SealError {
    /// The OS random source failed, or the server key is unusable.
    Setup,
    /// The answer is not a sealed answer to this call (tampered, replaced, or
    /// from something other than the licence server).
    Answer,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seals `body` (the clear JSON the call would have sent) for `path`.
pub(crate) fn seal(path: &str, body: &[u8]) -> Result<Sealed, SealError> {
    let mut eph = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 24];
    getrandom::getrandom(eph.as_mut()).map_err(|_| SealError::Setup)?;
    getrandom::getrandom(&mut nonce).map_err(|_| SealError::Setup)?;
    seal_with(&server_key(), *eph, nonce, path, body, now_secs())
}

fn seal_with(
    server: &[u8; 32],
    eph_seed: [u8; 32],
    nonce: [u8; 24],
    path: &str,
    body: &[u8],
    ts: u64,
) -> Result<Sealed, SealError> {
    let body = std::str::from_utf8(body).map_err(|_| SealError::Setup)?;
    serde_json::from_str::<serde_json::Value>(body).map_err(|_| SealError::Setup)?;
    let e = StaticSecret::from(eph_seed);
    let e_pub = PublicKey::from(&e);
    let shared = e.diffie_hellman(&PublicKey::from(*server));
    if !shared.was_contributory() {
        return Err(SealError::Setup);
    }
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(e_pub.as_bytes());
    salt[32..].copy_from_slice(server);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut k_req = Zeroizing::new([0u8; 32]);
    let mut k_resp = Zeroizing::new([0u8; 32]);
    hk.expand(INFO_REQ, k_req.as_mut()).map_err(|_| SealError::Setup)?;
    hk.expand(INFO_RESP, k_resp.as_mut()).map_err(|_| SealError::Setup)?;
    // Keys in sorted order, as the server's serde_json writes them; the body
    // is carried as the JSON it already is.
    let path_json = serde_json::to_string(path).map_err(|_| SealError::Setup)?;
    let clear = Zeroizing::new(format!("{{\"body\":{body},\"path\":{path_json},\"ts\":{ts}}}"));
    let mut aad = AAD_REQ.to_vec();
    aad.extend_from_slice(path.as_bytes());
    let ct = XChaCha20Poly1305::new((&*k_req).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: clear.as_bytes(), aad: &aad })
        .map_err(|_| SealError::Setup)?;
    let wire = format!(
        "{{\"v\":1,\"epk\":\"{}\",\"n\":\"{}\",\"ct\":\"{}\"}}",
        hex(e_pub.as_bytes()),
        hex(&nonce),
        hex(&ct)
    );
    Ok(Sealed { wire: wire.into_bytes(), path: path.to_string(), k_resp })
}

impl Sealed {
    /// Opens the server's answer to this call, for the status it came with.
    /// Anything that does not open is `Answer`: never read as a clear body.
    pub(crate) fn open(&self, status: u16, wire: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Answer {
            v: u8,
            n: String,
            ct: String,
        }
        let answer: Answer = serde_json::from_slice(wire).map_err(|_| SealError::Answer)?;
        if answer.v != 1 {
            return Err(SealError::Answer);
        }
        let nonce: [u8; 24] = unhex(&answer.n).and_then(|b| b.try_into().ok()).ok_or(SealError::Answer)?;
        let ct = unhex(&answer.ct).ok_or(SealError::Answer)?;
        let mut aad = AAD_RESP.to_vec();
        aad.extend_from_slice(self.path.as_bytes());
        aad.extend_from_slice(status.to_string().as_bytes());
        XChaCha20Poly1305::new((&*self.k_resp).into())
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad: &aad })
            .map(Zeroizing::new)
            .map_err(|_| SealError::Answer)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The licence server's seal.rs test vector: server seed [7; 32], ephemeral
    // seed [9; 32], nonce [3; 24], ts 1_800_000_000, path
    // /premium/addon/catalog, body {"device_id":"00"*16,"token":"ptx1-v"}.
    const VECTOR_SERVER_PUB: &str = "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d";
    const VECTOR_EPK: &str = "57db4b359f23ae5e146e4e2512056704722506348c150c14753d0c933d04d421";
    const VECTOR_CT: &str = "185fb5158dbe295a257db33994bd915168657b54cb4a47b2b277fb0ebc3eeb09e9f21d1e52e6c945c5c1e4855c82b320437e1c82e2ae864124ebfd3aa1adbf43292f631288409660232c9d1d129957b85eb70134a080283903e2330b93025fa60499f46cf2ee02efd1476a07811c1129c1cfa0b34ec8a002bd591ab618fe74a2fe385947e48b49f82b40";
    const VECTOR_RESPONSE: &str = r#"{"ct":"828026391bdb028afa75c70aca82cab07bb7cff53ba0b2c8520c7a","n":"60d92d9a64872a72c9dd793e6a638cced281ffb294b60ef1","v":1}"#;
    const PATH: &str = "/premium/addon/catalog";

    fn vector() -> Sealed {
        let server: [u8; 32] = unhex(VECTOR_SERVER_PUB).unwrap().try_into().unwrap();
        let body = format!(r#"{{"device_id":"{}","token":"ptx1-v"}}"#, "00".repeat(16));
        seal_with(&server, [9u8; 32], [3u8; 24], PATH, body.as_bytes(), 1_800_000_000).unwrap()
    }

    #[test]
    fn the_app_and_the_server_agree_on_the_shared_vector() {
        let sealed = vector();
        let wire: serde_json::Value = serde_json::from_slice(&sealed.wire).unwrap();
        assert_eq!(wire["epk"], VECTOR_EPK);
        assert_eq!(wire["ct"], VECTOR_CT, "the request is not byte-identical to the server's vector");
        assert_eq!(&sealed.open(200, VECTOR_RESPONSE.as_bytes()).unwrap()[..], br#"{"ok":true}"#);
    }

    #[test]
    fn an_answer_for_another_status_path_or_call_does_not_open() {
        let sealed = vector();
        assert_eq!(sealed.open(500, VECTOR_RESPONSE.as_bytes()), Err(SealError::Answer), "status is bound");
        let server: [u8; 32] = unhex(VECTOR_SERVER_PUB).unwrap().try_into().unwrap();
        let other_path = seal_with(&server, [9u8; 32], [3u8; 24], "/premium/addon/grant", b"{}", 1).unwrap();
        assert_eq!(other_path.open(200, VECTOR_RESPONSE.as_bytes()), Err(SealError::Answer), "path is bound");
        let other_call = seal_with(&server, [8u8; 32], [3u8; 24], PATH, b"{}", 1).unwrap();
        assert_eq!(other_call.open(200, VECTOR_RESPONSE.as_bytes()), Err(SealError::Answer), "key is per call");
    }

    #[test]
    fn a_clear_or_malformed_answer_is_never_read() {
        let sealed = vector();
        for wire in [
            &br#"{"receipt":"prx1-x"}"#[..],
            br#"{"error":"bad_token"}"#,
            b"<html>blocked</html>",
            br#"{"v":2,"n":"00","ct":"00"}"#,
            br#"{"v":1,"n":"zz","ct":"00"}"#,
            b"",
        ] {
            assert_eq!(sealed.open(200, wire), Err(SealError::Answer), "{}", String::from_utf8_lossy(wire));
        }
    }

    #[test]
    fn the_token_and_device_id_never_appear_on_the_wire() {
        let body = br#"{"token":"ptx1-SECRET-TOKEN","device_id":"0123456789abcdef0123456789abcdef"}"#;
        let sealed = seal("/premium/activate", body).unwrap();
        let wire = String::from_utf8(sealed.wire.clone()).unwrap();
        assert!(!wire.contains("ptx1") && !wire.contains("SECRET") && !wire.contains("0123456789abcdef"));
        assert!(seal("/premium/activate", b"not json").is_err(), "only a JSON body is sealed");
    }

    #[test]
    fn the_pinned_key_is_the_server_production_key() {
        assert_eq!(hex(&SEAL_PUBLIC_KEY), "59d18c0763fd8c968304832234e6388ae3d48563f2e1b072533fe93ac622c841");
    }
}
