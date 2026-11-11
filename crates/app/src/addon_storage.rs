//! The add-on's storage worker: every disk read, write, sync and recovery
//! for an add-on's pages runs here, never on the event loop.
//!
//! One worker per open add-on window. It owns that window's namespace (a
//! path and a derived key, never the Store), so a job can never be pointed
//! at a later Library: a job carries the generation it was admitted under,
//! and a completion for an older generation is dropped by the host.
//!
//! The host admits a job (session current, Vault unlocked, Library open, no
//! import running, queue and byte bounds) BEFORE it reaches this worker.

use std::sync::{mpsc, Arc};

use patanyx_store::{AddonNamespace, AddonWriteError, PageMeta, SiteChange, ADDON_QUOTA_BYTES};
use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;
use zeroize::Zeroizing;

use crate::addon_protocol as proto;
use crate::UserEvent;

/// The most storage requests waiting at once, per add-on window.
pub const MAX_PENDING: usize = 16;
/// The most body bytes waiting at once, per add-on window.
pub const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;

pub enum Job {
    List { cursor: Option<String>, limit: u16 },
    Get { id: String },
    Put {
        id: Option<String>,
        base_revision: u64,
        title: String,
        body: Zeroizing<Vec<u8>>,
        site: SiteChange,
        /// Only on a create (checked by the protocol and again by the store).
        collection: Option<String>,
    },
    Delete { id: String, base_revision: u64 },
}

impl Job {
    /// Bytes this job holds while queued, for the queue bound.
    pub fn queued_bytes(&self) -> usize {
        match self {
            Self::Put { body, title, site, .. } => {
                body.len() + title.len() + if let SiteChange::Set(s) = site { s.len() } else { 0 }
            }
            _ => 0,
        }
    }
}

/// What a finished job answers.
pub enum Outcome {
    Reply(Value),
    Refuse(&'static str),
}

struct Request {
    request_id: u32,
    job: Job,
}

/// The handle the host keeps.
pub struct Worker {
    tx: mpsc::Sender<Request>,
    pub pending: usize,
    pub queued_bytes: usize,
    /// The thread holds a clone until it has stopped touching the namespace.
    quiet: Arc<()>,
}

impl Worker {
    /// Starts the worker for `namespace`. Its first act is recovery, so no job
    /// runs against debris from an interrupted write.
    pub fn spawn(namespace: AddonNamespace, generation: u64, proxy: EventLoopProxy<UserEvent>) -> Self {
        let (tx, rx) = mpsc::channel::<Request>();
        let quiet = Arc::new(());
        let held = quiet.clone();
        std::thread::spawn(move || {
            let _ = namespace.recover();
            // Runs until the window's handle is dropped and every job it had
            // queued is done: a save already given is never thrown away.
            while let Ok(Request { request_id, job }) = rx.recv() {
                let bytes = job.queued_bytes();
                let outcome = run(&namespace, job);
                if proxy
                    .send_event(UserEvent::AddonStorageDone { generation, request_id, outcome: Box::new(outcome), bytes })
                    .is_err()
                {
                    break;
                }
            }
            drop(namespace);
            drop(held);
            let _ = proxy.send_event(UserEvent::AddonWorkerQuiet);
        });
        Self { tx, pending: 0, queued_bytes: 0, quiet }
    }

    /// Held by the host after the window goes: its strong count falls to one
    /// when this worker's thread has stopped.
    pub fn quiet_token(&self) -> Arc<()> {
        self.quiet.clone()
    }

    /// Queues `job`, or refuses it with `busy` at the bounds.
    pub fn submit(&mut self, request_id: u32, job: Job) -> Result<(), &'static str> {
        let bytes = job.queued_bytes();
        if self.pending >= MAX_PENDING || self.queued_bytes + bytes > MAX_QUEUED_BYTES {
            return Err("busy");
        }
        self.tx.send(Request { request_id, job }).map_err(|_| "storage_unavailable")?;
        self.pending += 1;
        self.queued_bytes += bytes;
        Ok(())
    }

    /// A job finished.
    pub fn done(&mut self, bytes: usize) {
        self.pending = self.pending.saturating_sub(1);
        self.queued_bytes = self.queued_bytes.saturating_sub(bytes);
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The protocol's `PageMeta`.
pub fn page_json(meta: &PageMeta, readable: bool) -> Value {
    let mut page = json!({
        "id": meta.id, "title": meta.title, "revision": meta.revision.to_string(),
        "created_at_ms": meta.created_at_ms, "updated_at_ms": meta.updated_at_ms,
        "body_bytes": meta.body_bytes, "readable": readable, "site": meta.site,
    });
    // Only a page that has a collection says so, so a page record from a
    // build without collections is byte-for-byte what it always was.
    if let (Some(c), Some(map)) = (&meta.collection, page.as_object_mut()) {
        map.insert("collection".to_string(), json!(c));
    }
    page
}

fn code(e: &AddonWriteError) -> &'static str {
    match e {
        AddonWriteError::NotFound => "not_found",
        AddonWriteError::Conflict => "conflict",
        AddonWriteError::PageTooLarge => "page_too_large",
        AddonWriteError::TitleTooLong => "title_too_long",
        AddonWriteError::InvalidBody => "invalid_body",
        AddonWriteError::InvalidSite => "invalid_site",
        AddonWriteError::InvalidCollection => "bad_args",
        AddonWriteError::TooManyPages => "too_many_pages",
        AddonWriteError::QuotaExceeded => "quota_exceeded",
        AddonWriteError::IndexUnreadable => "index_unreadable",
        AddonWriteError::Store(_) => "io_error",
    }
}

fn run(ns: &AddonNamespace, job: Job) -> Outcome {
    let used = || ns.used_bytes().unwrap_or(0);
    match job {
        Job::List { cursor, limit } => match ns.list() {
            Ok(entries) => {
                let mut items = entries
                    .iter()
                    .filter(|e| cursor.as_deref().is_none_or(|c| e.meta.id.as_str() > c))
                    .take(usize::from(limit) + 1)
                    .map(|e| (e.meta.id.clone(), page_json(&e.meta, e.readable)))
                    .collect::<Vec<_>>();
                let next = if items.len() > usize::from(limit) {
                    items.truncate(usize::from(limit));
                    items.last().map(|(id, _)| id.clone())
                } else {
                    None
                };
                Outcome::Reply(json!({
                    "items": items.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
                    "next_cursor": next, "used_bytes": used(), "quota_bytes": ADDON_QUOTA_BYTES,
                }))
            }
            Err(e) => Outcome::Refuse(code(&e)),
        },
        Job::Get { id } => match ns.get(&id) {
            Ok((meta, body)) => Outcome::Reply(json!({ "page": page_json(&meta, true), "body_b64": proto::encode_body(&body) })),
            Err(AddonWriteError::Store(_)) => Outcome::Refuse("page_unreadable"),
            Err(e) => Outcome::Refuse(code(&e)),
        },
        Job::Put { id, base_revision, title, body, site, collection } => {
            match ns.put_in(id.as_deref(), base_revision, &title, &body, site, collection.as_deref(), now_ms()) {
                Ok(meta) => Outcome::Reply(json!({ "page": page_json(&meta, true), "used_bytes": used() })),
                Err(e) => Outcome::Refuse(code(&e)),
            }
        }
        Job::Delete { id, base_revision } => match ns.delete(&id, base_revision) {
            Ok(()) => Outcome::Reply(json!({ "deleted": true, "used_bytes": used() })),
            Err(e) => Outcome::Refuse(code(&e)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patanyx_store::Store;

    #[test]
    fn the_worker_carries_keep_set_and_clear_and_every_record_states_the_site() {
        let (dir, ns) = namespace("site");
        let put = |id: Option<String>, rev: u64, site: SiteChange| {
            reply(run(&ns, Job::Put { id, base_revision: rev, title: "t".into(), body: Zeroizing::new(b"x".to_vec()), site, collection: None }))
        };
        let created = put(None, 0, SiteChange::Set("example.com".into()));
        assert_eq!(created["page"]["site"], json!("example.com"));
        let id = created["page"]["id"].as_str().unwrap().to_string();
        assert_eq!(put(Some(id.clone()), 1, SiteChange::Keep)["page"]["site"], json!("example.com"));
        let listed = reply(run(&ns, Job::List { cursor: None, limit: 10 }));
        assert_eq!(listed["items"][0]["site"], json!("example.com"));
        assert_eq!(reply(run(&ns, Job::Get { id: id.clone() }))["page"]["site"], json!("example.com"));
        assert_eq!(put(Some(id.clone()), 2, SiteChange::Clear)["page"]["site"], Value::Null);
        assert_eq!(reply(run(&ns, Job::Get { id: id.clone() }))["page"]["site"], Value::Null);
        let bad = run(&ns, Job::Put { id: Some(id), base_revision: 3, title: "t".into(), body: Zeroizing::new(b"x".to_vec()),
            site: SiteChange::Set("Not A Site".into()), collection: None });
        assert_eq!(refused(bad), "invalid_site");
        // A page made in a collection says so; one made without does not
        // mention the field at all (host-api-1-notebook.md).
        let note = reply(run(&ns, Job::Put { id: None, base_revision: 0, title: "Note".into(), body: Zeroizing::new(b"a".to_vec()),
            site: SiteChange::Keep, collection: Some("assistant".into()) }));
        assert_eq!(note["page"]["collection"], "assistant");
        let plain = reply(run(&ns, Job::Put { id: None, base_revision: 0, title: "Plain".into(), body: Zeroizing::new(b"a".to_vec()),
            site: SiteChange::Keep, collection: None }));
        assert!(plain["page"].get("collection").is_none());
        drop(ns);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn namespace(tag: &str) -> (std::path::PathBuf, AddonNamespace) {
        let mut n = [0u8; 8];
        getrandom::getrandom(&mut n).unwrap();
        let dir = std::env::temp_dir().join(format!("patanyx-addon-storage-{tag}-{:016x}", u64::from_le_bytes(n)));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::create_with_params(&dir.join("store.rbs"), "pw", 8192, 1, 1).unwrap();
        let ns = store.addon_namespace("text-pages").unwrap();
        (dir, ns)
    }

    fn reply(o: Outcome) -> Value {
        match o {
            Outcome::Reply(v) => v,
            Outcome::Refuse(code) => panic!("refused: {code}"),
        }
    }

    fn refused(o: Outcome) -> &'static str {
        match o {
            Outcome::Reply(v) => panic!("answered: {v}"),
            Outcome::Refuse(code) => code,
        }
    }

    #[test]
    fn put_get_list_and_delete_through_the_worker_jobs() {
        let (dir, ns) = namespace("jobs");
        let created = reply(run(&ns, Job::Put { id: None, base_revision: 0, title: "One".into(), body: Zeroizing::new(b"first".to_vec()), site: SiteChange::Keep, collection: None }));
        let id = created["page"]["id"].as_str().unwrap().to_string();
        assert_eq!(created["page"]["revision"], "1");
        let got = reply(run(&ns, Job::Get { id: id.clone() }));
        assert_eq!(proto::decode_body(got["body_b64"].as_str().unwrap()).unwrap().as_slice(), b"first");
        assert_eq!(refused(run(&ns, Job::Put { id: Some(id.clone()), base_revision: 5, title: "x".into(), body: Zeroizing::new(b"x".to_vec()), site: SiteChange::Keep, collection: None })), "conflict");
        for i in 0..3 {
            reply(run(&ns, Job::Put { id: None, base_revision: 0, title: format!("p{i}"), body: Zeroizing::new(b"b".to_vec()), site: SiteChange::Keep, collection: None }));
        }
        // Paging: two, then the rest, then nothing more.
        let first = reply(run(&ns, Job::List { cursor: None, limit: 2 }));
        assert_eq!(first["items"].as_array().unwrap().len(), 2);
        let cursor = first["next_cursor"].as_str().unwrap().to_string();
        let second = reply(run(&ns, Job::List { cursor: Some(cursor), limit: 2 }));
        assert_eq!(second["items"].as_array().unwrap().len(), 2);
        assert!(second["next_cursor"].is_null());
        assert!(first["quota_bytes"].as_u64().unwrap() > 0);
        reply(run(&ns, Job::Delete { id: id.clone(), base_revision: 1 }));
        assert_eq!(refused(run(&ns, Job::Get { id })), "not_found");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_missing_page_body_is_unreadable_not_an_io_crash() {
        let (dir, ns) = namespace("unreadable");
        let created = reply(run(&ns, Job::Put { id: None, base_revision: 0, title: "t".into(), body: Zeroizing::new(b"x".to_vec()), site: SiteChange::Keep, collection: None }));
        let id = created["page"]["id"].as_str().unwrap().to_string();
        let ns_dir = dir.join("addons").join("text-pages");
        std::fs::remove_file(ns_dir.join(format!("p-{id}-1"))).unwrap();
        assert_eq!(refused(run(&ns, Job::Get { id })), "page_unreadable");
        let list = reply(run(&ns, Job::List { cursor: None, limit: 10 }));
        assert_eq!(list["items"][0]["readable"], false);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_queue_refuses_past_its_bounds() {
        let (dir, ns) = namespace("queue");
        // A worker whose thread never runs the jobs: the bounds alone decide.
        let (tx, _rx) = mpsc::channel::<Request>();
        let mut w = Worker { tx, pending: 0, queued_bytes: 0, quiet: Arc::new(()) };
        for i in 0..MAX_PENDING {
            assert!(w.submit(i as u32, Job::Get { id: "0".repeat(32) }).is_ok());
        }
        assert_eq!(w.submit(99, Job::Get { id: "0".repeat(32) }), Err("busy"));
        w.done(0);
        let big = Zeroizing::new(vec![b'a'; MAX_QUEUED_BYTES]);
        assert_eq!(w.submit(100, Job::Put { id: None, base_revision: 0, title: "t".into(), body: big, site: SiteChange::Keep, collection: None }), Err("busy"));
        drop(ns);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
