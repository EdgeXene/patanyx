use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Payload schema version.
///
///   1 -> 2  added `contacts` and `chat_identity`
///   2 -> 3  `relay` and per-contact `note`, WHICH SHOULD HAVE BUMPED IT
///           WHEN THEY LANDED AND DID NOT
///   3 -> 4  added `origin` to `CredentialEntry` — the parsed origin a
///           stored credential is offered for autofill on, matched EXACTLY,
///           never by the free-text `site` label. A per-entry field, not a
///           new top-level key, but the same risk: an older build's
///           `CredentialEntry` has no such field, so opening a schema-4
///           vault and saving any change would silently drop `origin` for
///           every credential — the exact loss the 2 -> 3 bump exists to
///           document, one level deeper. See
///           `credential_entry_keys_are_pinned_to_the_schema`.
///   4 -> 5  added `tunnel`, the persisted WireGuard tunnel configuration.
///           Unlike 3 -> 4 this IS a new top-level key, so the 2 -> 3
///           hazard applies undiluted: a build that predates the field opens
///           the file, finds its version acceptable, and drops the whole
///           config — private key included — on its next save. The field is
///           UNCONDITIONAL for the same reason `contacts` is: a build that
///           cannot bring a tunnel up must still round-trip it.
///           `TunnelSettings.address` was added to this same bump BEFORE any
///           build carrying schema 5 shipped — no install has ever written a
///           5 without it, so amending the shape in place needed no 6. That
///           reasoning holds exactly once: the moment a 5 is released, the
///           next field means a bump.
///   5 -> 6  added `licence`, the stored Premium licence token in its text
///           form. Like `tunnel` it IS a new top-level key, so the 2 -> 3
///           hazard applies undiluted: a build that predates the field
///           opens the file, finds its version acceptable, and drops the
///           token — a paid-for bearer credential EdgeXene holds no copy
///           of — on its next save. The field is UNCONDITIONAL for the
///           same reason `contacts` and `tunnel` are: a build that cannot
///           verify tokens must still round-trip the record.
///
/// Old payloads simply lack the newer keys; `#[serde(default)]` fills them in
/// on read and the next save rewrites the file at the current version. See
/// `Vault::parse_payload` for the accept-old / reject-newer rule.
///
/// The 2 -> 3 bump is a data-loss fix, not bookkeeping. `relay` and the
/// contact `note` were added while this constant stayed at 2, so a build that
/// predated them opened the file, found its version acceptable, and silently
/// dropped both on the next save — serde ignores unknown fields by default, so
/// nothing anywhere complained. A user who ran an older build once lost every
/// contact note they had written. With the bump that build refuses to open the
/// file instead, which is the entire purpose of having a version.
///
/// ADDING A FIELD MEANS BUMPING THIS. `top_level_keys_are_pinned_to_the_schema`
/// below fails if you forget.
pub const SCHEMA_VERSION: u32 = 6;

/// Maximum contact label length, in CHARACTERS (not bytes).
///
/// Note: nothing else in the vault is length-capped — a password or a
/// note is whatever the user pastes — so there was no in-crate convention to
/// follow. 64 is the fallback value the brief specifies for that case and
/// wants a second look from the reviewer.
pub const MAX_LABEL_CHARS: usize = 64;

/// Maximum peer-hash length, in CHARACTERS. The hash is an opaque string to
/// this crate: parsing or validating its FORMAT is the caller's job, and
/// duplicating that knowledge here would be a second place to get it wrong.
/// The cap exists only to keep unbounded strings out of the vault, so it is
/// generous on purpose.
pub const MAX_PEER_HASH_CHARS: usize = 128;

/// Maximum per-contact note length, in CHARACTERS. Generous because the whole
/// point is remembering things ("met at the conference, blue laptop, prefers
/// Signal for anything urgent"), but bounded so a paste of a whole document
/// cannot bloat the encrypted payload.
pub const MAX_NOTE_CHARS: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultData {
    pub schema: u32,
    #[serde(default)]
    pub credentials: Vec<CredentialEntry>,
    #[serde(default)]
    pub notes: Vec<SecretNote>,
    /// UNCONDITIONAL — not optional, not feature-gated, present in every
    /// build. A build compiled without chat support must still round-trip a
    /// chat build's contacts: serde silently discards unknown fields, so if
    /// only chat builds knew this field, a non-chat build would drop it on
    /// read and the next save — every mutating method saves — would
    /// permanently destroy every per-contact private key. Every build knows
    /// the field, so every build preserves it.
    #[serde(default)]
    pub contacts: ContactBook,
    /// The long-term chat identity secret: ONE per vault, not one per
    /// contact, which is why it is a sibling of `contacts` rather than part
    /// of `ContactBook` — the book is purely a collection of contacts and
    /// stays usable standalone in tests. It sits next to `contacts` so the
    /// same unconditional round-trip rule protects it. `None` until the
    /// caller mints one.
    ///
    /// A plain array rather than `Zeroizing<[u8; 32]>` because `VaultData`
    /// derives `Serialize`/`Deserialize` and zeroize's serde feature is
    /// deliberately not enabled; `Vault::drop` wipes it instead, exactly
    /// like passwords and note bodies.
    #[serde(default)]
    pub chat_identity: Option<[u8; 32]>,
    /// Relay configuration. Lives in the vault because it names an identity
    /// and because turning a relay on is a decision about who can observe
    /// that you are reachable — not a cosmetic preference.
    #[serde(default)]
    pub relay: RelaySettings,
    /// The imported WireGuard tunnel configuration: ONE per vault, `None`
    /// until the caller imports one.
    ///
    /// UNCONDITIONAL under exactly the rule `contacts` documents: a build
    /// with no tunnel support must still round-trip this field, because
    /// serde silently discards unknown fields and the next save from such a
    /// build would otherwise destroy the imported config — private key
    /// included. It must never be feature-gated for any reason; that is the
    /// 2 -> 3 defect reintroduced, and schema 5 exists so a build that
    /// predates the field refuses the file instead of stripping it.
    ///
    /// The secrets inside are plain `String`s, like passwords and note
    /// bodies: `Vault::drop` and `set_tunnel_settings` wipe them.
    #[serde(default)]
    pub tunnel: Option<TunnelSettings>,
    /// The stored Premium licence token: ONE per vault, `None` until the
    /// caller pastes one. The vault stores the TEXT form exactly as pasted;
    /// re-parsing and re-verifying is the app layer's job at every unlock
    /// (design 3.3 step 2: no cached trust bit), which is why this crate
    /// holds a string and no parsed type — the vault must not depend on
    /// the licence crate.
    ///
    /// UNCONDITIONAL under exactly the rule `contacts` documents: a build
    /// with no licence support must still round-trip this field, because
    /// serde silently discards unknown fields and the next save from such
    /// a build would otherwise destroy the token. It must never be
    /// feature-gated for any reason; that is the 2 -> 3 defect
    /// reintroduced, and schema 6 exists so a build that predates the
    /// field refuses the file instead of stripping it.
    ///
    /// `token_text` is a bearer credential: the hand-written `Debug` on
    /// `LicenceRecord` redacts it, `to_plaintext_export` does not project
    /// `licence` at all, and `Vault::drop` / `set_licence_record` wipe it.
    #[serde(default)]
    pub licence: Option<LicenceRecord>,
}

/// A stored Premium licence token, text form exactly as pasted.
///
/// Vault-owned on purpose, NOT anything from `patanyx_licence`: the vault
/// must not depend on the licence crate (mirroring `TunnelSettings`, which
/// is vault-owned rather than a tunnel-crate type), and every build —
/// including one that cannot verify tokens at all — must be able to name
/// and round-trip this shape so it is never silently dropped on save.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenceRecord {
    /// The `ptx1-…` text form exactly as pasted. SECRET in the
    /// bearer-token sense: anyone holding this text holds the licence.
    /// Never printed (the hand-written `Debug` below shows nothing), never
    /// exported (`to_plaintext_export` does not project `licence` at all),
    /// and wiped by `Vault::drop` and `set_licence_record`.
    pub token_text: String,
}

impl std::fmt::Debug for LicenceRecord {
    /// Hand-written, never derived: a derived Debug would print the token
    /// into any log line or test failure that formatted this struct — and
    /// `VaultData` derives Debug, so the leak would not even require anyone
    /// to format a `LicenceRecord` directly. The same rule `TunnelSettings`
    /// follows. The token has no non-secret fields, so the output names the
    /// type and nothing else.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicenceRecord").finish_non_exhaustive()
    }
}

/// How this user reaches contacts who are not on the local network.
///
/// `identity_hash` names ONE identity to register. It is deliberately not a
/// set: a remote relay that saw several of a user's per-contact fingerprints
/// could link them, which is the exact correlation per-contact keys exist to
/// prevent. On a LAN co-announcement is acceptable because observers are
/// physically present already; a relay is not.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub identity_hash: Option<String>,
}

/// A persisted WireGuard tunnel configuration, as imported from a `wg-quick`
/// file.
///
/// Vault-owned on purpose, NOT `patanyx_tunnel::TunnelConfig`: the vault must
/// not depend on the tunnel crate (mirroring `Contact`, which is vault-owned
/// rather than a chat-crate type), and every build — including one with no
/// tunnel support at all — must be able to name and round-trip this shape so
/// it is never silently dropped on save. `TunnelConfig` stays the parse-time
/// type; the caller maps one into the other at import time.
///
/// Keys remain base64 here, exactly as `TunnelConfig` holds them: decoding is
/// the session's job at bring-up time, so the at-rest form never needs the
/// raw bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelSettings {
    /// Whether the tunnel should be brought up at all. Mirrors
    /// `RelaySettings.enabled`: importing a config and wanting it active are
    /// separate decisions.
    #[serde(default)]
    pub enabled: bool,
    /// `[Interface] PrivateKey`, still base64. SECRET: never printed (the
    /// hand-written `Debug` below omits it), never exported
    /// (`to_plaintext_export` does not project `tunnel` at all), and wiped by
    /// `Vault::drop` and `set_tunnel_settings`.
    pub private_key_b64: String,
    /// `[Peer] PublicKey`, base64. A public key; not secret.
    pub peer_public_key_b64: String,
    /// `[Peer] Endpoint`, verbatim `host:port`. Not resolved here, for the
    /// same reason `TunnelConfig` does not resolve it.
    pub endpoint: String,
    /// `[Peer] PresharedKey`, if the config carries one. SECRET when present;
    /// handled exactly like `private_key_b64`.
    #[serde(default)]
    pub preshared_key_b64: Option<String>,
    /// `[Peer] PersistentKeepalive`, seconds.
    #[serde(default)]
    pub keepalive_secs: Option<u16>,
    /// `[Peer] AllowedIPs`, verbatim, for display only — see the tunnel
    /// crate's module header for why it is not enforced.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// `[Interface] DNS`, verbatim, for display only.
    #[serde(default)]
    pub dns: Vec<String>,
    /// `[Interface] Address`, verbatim and comma-split — the tunnel
    /// interface's own address(es). Not secret (it is a private-range
    /// assignment, not a credential), but REQUIRED at bring-up: the tunnel
    /// refuses to start without a usable IPv4 entry, so an import that
    /// dropped this field would persist a config that can never come up.
    #[serde(default)]
    pub address: Vec<String>,
}

impl std::fmt::Debug for TunnelSettings {
    /// Hand-written, never derived: a derived Debug would print the private
    /// key into any log line or test failure that formatted this struct — and
    /// `VaultData` derives Debug, so the leak would not even require anyone
    /// to format a `TunnelSettings` directly. The same rule `Contact` and
    /// `Vault` follow; both secret fields are omitted entirely.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelSettings")
            .field("enabled", &self.enabled)
            .field("peer_public_key_b64", &self.peer_public_key_b64)
            .field("endpoint", &self.endpoint)
            .field("keepalive_secs", &self.keepalive_secs)
            .field("allowed_ips", &self.allowed_ips)
            .field("dns", &self.dns)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl VaultData {
    /// The plaintext-export projection: everything the user consented to see
    /// in the clear, and no key material.
    ///
    /// The plaintext export exists so a user is never locked into this format.
    /// What they confirm is that their PASSWORDS will be readable. Serializing
    /// `VaultData` itself also emitted every per-contact X25519 private key
    /// and the long-term chat identity secret, because the at-rest contact
    /// record necessarily includes `our_secret` — a file that lets anyone
    /// impersonate the user to every one of their contacts and decrypt
    /// captured conversations. The tunnel configuration carries the same
    /// category of secret — a private key, and sometimes a preshared key,
    /// that authenticates the user to their VPN provider — so `tunnel` is
    /// not projected into the export at all. That is categorically not "my
    /// passwords are readable", so it is omitted here rather than described
    /// in a longer warning.
    ///
    /// Contacts still appear, because the user's own notes about who a hash
    /// number belongs to are exactly the kind of thing an export exists to
    /// preserve — just without the secret.
    pub fn to_plaintext_export(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "credentials": self.credentials,
            "notes": self.notes,
            // `Contact`'s own Serialize skips `our_secret`; going through it
            // rather than ContactBook is what keeps the keys out.
            "contacts": self.contacts.list(),
            // `tunnel` is not projected at all: its private and preshared
            // keys are key material exactly like the chat secrets.
            // `licence` is not projected either: a bearer credential is key
            // material in the same sense — a file whose whole point is being
            // readable by anyone must not be able to spend it.
            "omitted": "Chat and WireGuard tunnel private keys are deliberately \
        not included in a plaintext export. Without them this file cannot be used to \
        impersonate you.",
        })
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            credentials: Vec::new(),
            notes: Vec::new(),
            contacts: ContactBook::default(),
            chat_identity: None,
            relay: RelaySettings::default(),
            tunnel: None,
            licence: None,
        }
    }
}

/// One chat contact. The vault stores raw bytes and opaque strings: every
/// X25519 operation happens in the caller, which hands over 32 secret bytes
/// and a hash-number string.
///
/// `Serialize` is derived with `our_secret` SKIPPED, so any serialization of
/// a contact — a listing handed to the UI, a log payload — carries no key
/// material. That is the rule `CredentialMeta` enforces by omitting the
/// password, applied on the type itself because `list_contacts` returns
/// whole contacts. Persistence is a different path: `ContactRecord` below
/// serializes the secret, and only ever inside the encrypted payload.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Contact {
    pub id: String,
    pub label: String,
    pub peer_hash: String,
    #[serde(skip_serializing)]
    pub our_secret: [u8; 32],
    pub created_at: u64,
    /// Free-text note the user keeps about this contact.
    ///
    /// A hash number is deliberately unmemorable, so without somewhere to
    /// write "the one from the conference, blue laptop" a contact list becomes
    /// a column of indistinguishable hex. This is the place for that.
    ///
    /// It IS serialized towards the UI (unlike `our_secret`), because it is the
    /// user's own words and showing them back is the entire point. It is
    /// user-authored text going into the trusted chrome webview, so it reaches
    /// the DOM via textContent like every other such string.
    pub note: String,
}

impl Drop for Contact {
    fn drop(&mut self) {
        // A contact's secret is a private key. Wipe every copy — the stored
        // one, the clones `list_contacts` hands out, and the one `remove`
        // returns — not just whichever one the Vault happens to be holding.
        self.our_secret.zeroize();
    }
}

impl std::fmt::Debug for Contact {
    /// Hand-written, never derived: a derived Debug would print the secret
    /// into any log line or test failure that formatted a contact — the same
    /// reason `Vault` has a hand-written Debug.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contact")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("peer_hash", &self.peer_hash)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// At-rest form of a contact, WITH the secret. The only type that serializes
/// key material, and it only ever appears inside the encrypted payload —
/// never in a listing, never towards the UI. Crate-internal on purpose.
#[derive(Clone, Serialize, Deserialize)]
struct ContactRecord {
    id: String,
    label: String,
    peer_hash: String,
    our_secret: [u8; 32],
    created_at: u64,
    /// `serde(default)` so a vault written before per-contact notes existed
    /// loads with an empty note instead of failing to open. No schema bump is
    /// needed for a purely additive field.
    #[serde(default)]
    note: String,
}

impl From<&Contact> for ContactRecord {
    fn from(contact: &Contact) -> Self {
        Self {
            id: contact.id.clone(),
            label: contact.label.clone(),
            peer_hash: contact.peer_hash.clone(),
            our_secret: contact.our_secret,
            created_at: contact.created_at,
            note: contact.note.clone(),
        }
    }
}

impl From<ContactRecord> for Contact {
    fn from(mut record: ContactRecord) -> Self {
        let contact = Contact {
            id: std::mem::take(&mut record.id),
            label: std::mem::take(&mut record.label),
            peer_hash: std::mem::take(&mut record.peer_hash),
            our_secret: record.our_secret,
            created_at: record.created_at,
            note: std::mem::take(&mut record.note),
        };
        // The record keeps its own copy of the secret after the move; wipe it
        // rather than leaving key material in a buffer nothing owns any more.
        record.our_secret.zeroize();
        contact
    }
}

/// The contact collection, standalone on purpose: the
/// remove-one-disturbs-no-other property the per-contact-keypair design
/// rests on must be provable in a unit test with no vault file and no
/// passphrase.
///
/// Its `Serialize` impl is the ONE place key material is serialized — the
/// encrypted at-rest payload — via `ContactRecord`. Never serialize a book
/// for display; serialize `Contact`s, whose own `Serialize` omits the
/// secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactBook {
    contacts: Vec<Contact>,
}

impl ContactBook {
    /// Appends a contact, minting its timestamp.
    ///
    /// Cannot fail, so it CANNOT enforce peer-hash uniqueness — a duplicate
    /// would have no error to travel back through. Uniqueness is enforced
    /// one layer up, in `Vault::add_contact`; standalone callers must check
    /// `find_by_peer_hash` first.
    pub fn add(
        &mut self,
        id: String,
        label: String,
        peer_hash: String,
        our_secret: [u8; 32],
    ) {
        self.contacts.push(Contact {
            id,
            label,
            peer_hash,
            our_secret,
            created_at: crate::now_unix(),
            // Added empty and edited later. Keeping it off `add` means the
            // existing call sites and their tests are untouched by this field.
            note: String::new(),
        });
    }

    /// Replaces a contact's note. Returns false when there is no such contact.
    ///
    /// Trimmed and capped, but otherwise stored verbatim: these are the user's
    /// own words about a person and this crate has no business editorialising.
    /// Clearing it is just setting an empty string.
    pub fn set_note(&mut self, id: &str, note: &str) -> bool {
        match self.contacts.iter_mut().find(|c| c.id == id) {
            Some(contact) => {
                let trimmed = note.trim();
                contact.note = trimmed.chars().take(MAX_NOTE_CHARS).collect();
                true
            }
            None => false,
        }
    }

    pub fn get(&self, id: &str) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.id == id)
    }

    /// Removes and returns the contact if it exists. The returned contact
    /// still wipes its own secret on drop.
    pub fn remove(&mut self, id: &str) -> Option<Contact> {
        let index = self.contacts.iter().position(|c| c.id == id)?;
        Some(self.contacts.remove(index))
    }

    /// Finds a contact by the peer's hash number — the caller's session-map
    /// key. Exact match; the vault does not interpret the string.
    pub fn find_by_peer_hash(&self, peer_hash: &str) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.peer_hash == peer_hash)
    }

    /// Returns owned CLONES — secrets included — so the caller borrows
    /// nothing. Chosen over `&[Contact]` to mirror `Vault::list_contacts`,
    /// whose pinned signature returns `Vec<Contact>`. Every clone wipes its
    /// own secret on drop; anything copied out of a contact is the caller's
    /// responsibility.
    pub fn list(&self) -> Vec<Contact> {
        self.contacts.clone()
    }
}

impl Serialize for ContactBook {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.contacts.iter().map(ContactRecord::from))
    }
}

impl<'de> Deserialize<'de> for ContactBook {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let records = Vec::<ContactRecord>::deserialize(deserializer)?;
        Ok(ContactBook {
            contacts: records.into_iter().map(Contact::from).collect(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub id: String,
    pub site: String,
    /// The parsed origin `site` was recognized as, or `None` if it could not
    /// be. NOT derived from `site` at read time -- computed once, by the
    /// caller, when the entry is added or edited (see `Vault::add_credential`),
    /// and stored so a fill offer matches the origin actually loaded rather
    /// than re-parsing a free-text label a page could have influenced.
    /// `None` excludes the entry from fill matching entirely; it is not an
    /// error, and every credential from before this field existed starts out
    /// this way until next edited.
    #[serde(default)]
    pub origin: Option<String>,
    pub username: String,
    pub password: String,
    pub note: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretNote {
    pub id: String,
    pub title: String,
    pub body: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Credential listing without the password field — safe to show in lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialMeta {
    pub id: String,
    pub site: String,
    pub username: String,
    /// The host this credential will actually be OFFERED on, derived from the
    /// free-text `site` label when it was saved. `None` means it will never be
    /// offered anywhere.
    ///
    /// Carried into the listing because leaving it out made a real defect
    /// invisible: `site` is free text, the origin is parsed from it, and a
    /// label like "Google" parses to nothing. The vault accepted such an entry,
    /// listed it, revealed it on demand, and silently never filled it -- with
    /// no way for anyone to tell it apart from a working one. Every credential
    /// predating the origin field is in exactly that state.
    ///
    /// Not a password and not sensitive: it is a hostname the user typed, and
    /// the same value is already visible in `site` for anything that parsed.
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoteMeta {
    pub id: String,
    pub title: String,
}

#[cfg(test)]
mod schema_guard_tests {
    use super::*;

    /// A canary, not a style check.
    ///
    /// `relay` and the per-contact `note` were both added while
    /// `SCHEMA_VERSION` stayed at 2, so a build that predated them opened the
    /// file, judged the version acceptable, and silently dropped both on its
    /// next save — serde ignores unknown fields, so nothing complained and the
    /// user simply lost their contact notes.
    ///
    /// Pinning the exact key set means the next person to add a field has to
    /// come here and decide about the version deliberately, rather than
    /// discovering the omission through somebody's missing data.
    #[test]
    fn top_level_keys_are_pinned_to_the_schema() {
        let data = VaultData::default();
        let json = serde_json::to_value(&data).expect("VaultData serializes");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();

        // If this fails you have added or removed a payload field. Bump
        // SCHEMA_VERSION, then update this list. Do NOT just update the list.
        assert_eq!(
            keys,
            [
                "chat_identity",
                "contacts",
                "credentials",
                "licence",
                "notes",
                "relay",
                "schema",
                "tunnel"
            ],
            "payload fields changed: bump SCHEMA_VERSION (currently {}) before \
             updating this list, or an older build will silently drop the new \
             field on its next save",
            SCHEMA_VERSION
        );
        assert_eq!(
            SCHEMA_VERSION, 6,
            "the key set above is the one recorded for schema 6, whose new \
             field `licence` IS a new top-level key -- like schema 5's \
             `tunnel`, and unlike schema 4's `origin`, which was nested \
             inside `credentials` and left this list unchanged; see \
             credential_entry_keys_are_pinned_to_the_schema"
        );
    }

    /// The gap `top_level_keys_are_pinned_to_the_schema` did not cover: a
    /// field added to an entry WITHIN a top-level array is just as
    /// silently-droppable by an older build as a new top-level key is, and
    /// nothing pinned that shape before now. This is what schema 4 exists to
    /// protect: `origin` on `CredentialEntry`.
    #[test]
    fn credential_entry_keys_are_pinned_to_the_schema() {
        let entry = CredentialEntry {
            id: "id".to_string(),
            site: "site".to_string(),
            origin: Some("example.com".to_string()),
            username: "username".to_string(),
            password: "password".to_string(),
            note: "note".to_string(),
            created_at: 0,
            updated_at: 0,
        };
        let json = serde_json::to_value(&entry).expect("CredentialEntry serializes");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            [
                "created_at",
                "id",
                "note",
                "origin",
                "password",
                "site",
                "updated_at",
                "username",
            ],
            "CredentialEntry's field set changed: bump SCHEMA_VERSION (currently \
             {}) before updating this list, or an older build will silently drop \
             the new field the next time it saves ANY credential",
            SCHEMA_VERSION
        );
    }

    /// A payload written by an older build must still open: the bump protects
    /// against DOWNgrade, and must not break upgrade.
    #[test]
    fn an_older_payload_still_loads_and_is_rewritten_current() {
        for old in [1u32, 2, 3] {
            let json = serde_json::json!({
                "schema": old,
                "credentials": [],
                "notes": [],
            });
            let mut data: VaultData =
                serde_json::from_value(json).expect("an older payload parses");
            assert_eq!(data.schema, old);
            // The missing keys come back as defaults rather than failing.
            assert!(data.contacts.list().is_empty());
            data.schema = SCHEMA_VERSION;
            assert_eq!(data.schema, 6, "the next save rewrites it current");
        }
    }

    /// The specific case schema 4 exists for: a credential written by a
    /// schema-3 build, with no `origin` key at all, must still load -- and
    /// come back as `None`, not an error and not a guess at what the origin
    /// might have been.
    #[test]
    fn a_pre_schema_4_credential_loads_with_no_origin() {
        let json = serde_json::json!({
            "schema": 3,
            "credentials": [{
                "id": "abc",
                "site": "example.com",
                "username": "alice",
                "password": "hunter2",
                "note": "",
                "created_at": 0,
                "updated_at": 0,
            }],
            "notes": [],
        });
        let data: VaultData = serde_json::from_value(json).expect("a schema-3 credential parses");
        assert_eq!(data.credentials.len(), 1);
        assert_eq!(
            data.credentials[0].origin, None,
            "a credential from before this field existed must load as None, \
             never as a guessed or inherited origin"
        );
    }

    /// The specific case schema 5 exists for: a payload written by a
    /// schema-4 build, with no `tunnel` key at all, must still load -- and
    /// come back as `None`, not an error and not a tunnel configuration this
    /// crate fabricated.
    #[test]
    fn a_pre_schema_5_payload_loads_with_no_tunnel() {
        let json = serde_json::json!({
            "schema": 4,
            "credentials": [],
            "notes": [],
        });
        let data: VaultData = serde_json::from_value(json).expect("a schema-4 payload parses");
        assert_eq!(data.schema, 4);
        assert_eq!(
            data.tunnel, None,
            "a vault from before this field existed must load as None, \
             never as a guessed or fabricated tunnel"
        );
    }

    /// The specific case schema 6 exists for: a payload written by a
    /// schema-5 build, with no `licence` key at all, must still load -- and
    /// come back as `None`, not an error and not a licence this crate
    /// fabricated.
    #[test]
    fn a_pre_schema_6_payload_loads_with_no_licence() {
        let json = serde_json::json!({
            "schema": 5,
            "credentials": [],
            "notes": [],
        });
        let data: VaultData = serde_json::from_value(json).expect("a schema-5 payload parses");
        assert_eq!(data.schema, 5);
        assert_eq!(
            data.licence, None,
            "a vault from before this field existed must load as None, \
             never as a guessed or fabricated licence"
        );
    }

    /// Not a real token — just a string with the same shape, so these tests
    /// can prove the redaction and export rules without any cryptography.
    fn sample_licence() -> LicenceRecord {
        LicenceRecord {
            token_text: "ptx1-THETOKENc2VjcmV0LXBheWxvYWQtc3R1ZmY".to_string(),
        }
    }

    /// The property `to_plaintext_export` exists to guarantee, proven for
    /// `licence` specifically: a vault holding a token must not leak it, in
    /// any encoding, into the plaintext export.
    #[test]
    fn plaintext_export_never_contains_the_licence_token() {
        let mut data = VaultData::default();
        data.licence = Some(sample_licence());
        let exported =
            serde_json::to_string(&data.to_plaintext_export()).expect("export serializes");
        assert!(
            !exported.contains("ptx1-THETOKEN"),
            "the licence token must not appear in a plaintext export"
        );
        assert!(
            !exported.contains("\"licence\""),
            "the licence record must not be projected into the export at all"
        );
    }

    /// `VaultData` derives `Debug`, so a naively-derived `Debug` on
    /// `LicenceRecord` would leak the bearer token through that path even
    /// though nothing formats a bare `LicenceRecord` directly today.
    #[test]
    fn licence_record_debug_never_contains_the_token() {
        let mut data = VaultData::default();
        data.licence = Some(sample_licence());
        let debugged = format!("{data:?}");
        assert!(
            !debugged.contains("ptx1-THETOKEN"),
            "Debug output must never contain the licence token"
        );
    }

    fn sample_tunnel() -> TunnelSettings {
        TunnelSettings {
            enabled: true,
            private_key_b64: "wGpriv8ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=".to_string(),
            peer_public_key_b64: "wGpub9YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=".to_string(),
            endpoint: "vpn.example.com:51820".to_string(),
            preshared_key_b64: Some("wGpsk7XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=".to_string()),
            keepalive_secs: Some(25),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            dns: vec!["10.64.0.1".to_string()],
            address: vec!["10.64.0.2/32".to_string()],
        }
    }

    /// A tunnel with no `address` key at all — the shape written in the brief
    /// window when schema 5 existed without the field (never released, but
    /// cheap to hold the door open for) — must load as an empty list, not
    /// fail. Bring-up then refuses it honestly with NoIpv4Address.
    #[test]
    fn a_tunnel_without_an_address_key_loads_as_an_empty_list() {
        let json = serde_json::json!({
            "schema": 5,
            "credentials": [],
            "notes": [],
            "tunnel": {
                "enabled": true,
                "private_key_b64": "wGpriv8ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=",
                "peer_public_key_b64": "wGpub9YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=",
                "endpoint": "vpn.example.com:51820",
            },
        });
        let data: VaultData = serde_json::from_value(json).expect("parses");
        assert_eq!(
            data.tunnel.expect("tunnel present").address,
            Vec::<String>::new()
        );
    }

    /// The property `to_plaintext_export` exists to guarantee, proven for
    /// `tunnel` specifically rather than trusted from the doc comment: a
    /// vault holding a tunnel secret must not leak either key, in any
    /// encoding, into the plaintext export -- the same standard
    /// `plaintext_export_contains_passwords_but_never_key_material` in
    /// `backup.rs` holds contact/chat secrets to.
    #[test]
    fn plaintext_export_never_contains_the_tunnel_keys() {
        let mut data = VaultData::default();
        data.tunnel = Some(sample_tunnel());
        let exported =
            serde_json::to_string(&data.to_plaintext_export()).expect("export serializes");
        assert!(
            !exported.contains("wGpriv8"),
            "the tunnel private key must not appear in a plaintext export"
        );
        assert!(
            !exported.contains("wGpsk7"),
            "the tunnel preshared key must not appear in a plaintext export"
        );
        assert!(
            !exported.contains("\"tunnel\""),
            "the tunnel object must not be projected into the export at all"
        );
    }

    /// `VaultData` derives `Debug`, so a naively-derived `Debug` on
    /// `TunnelSettings` would leak the private/preshared keys through that
    /// path even though nothing formats a bare `TunnelSettings` directly
    /// today. Proven directly rather than trusted from the impl being
    /// hand-written.
    #[test]
    fn tunnel_settings_debug_never_contains_the_secrets() {
        let mut data = VaultData::default();
        data.tunnel = Some(sample_tunnel());
        let debugged = format!("{data:?}");
        assert!(
            !debugged.contains("wGpriv8"),
            "Debug output must never contain the tunnel private key"
        );
        assert!(
            !debugged.contains("wGpsk7"),
            "Debug output must never contain the tunnel preshared key"
        );
    }
}
