use patanyx_integrity::ContentDigest;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreData {
    pub schema: u32,
    #[serde(default)]
    pub bookmarks: Vec<Bookmark>,
    /// Known bookmark folder names, so a folder can exist while empty. A
    /// folder IS a tag; this list only records the ones a user has made but
    /// not yet filed anything into, since a tag with no bookmark is stored
    /// nowhere else. ADDITIVE ONLY, the same rule `shelves` and
    /// `Bookmark::tags` document: a store written before this field existed
    /// reads it as an empty list, so `schema` stays at SCHEMA_VERSION.
    #[serde(default)]
    pub bookmark_folders: Vec<String>,
    #[serde(default)]
    pub downloads: Vec<DownloadRecord>,
    /// Set-aside shelves. ADDITIVE ONLY: files written before this field
    /// existed deserialize with an empty list, and older builds ignore the
    /// key on read -- which is why `schema` stays at SCHEMA_VERSION.
    #[serde(default)]
    pub shelves: Vec<Shelf>,
    /// Monotonically increasing shelf sequence; never reused even after a
    /// delete, so ids and the stored creation order survive deletions.
    #[serde(default)]
    pub next_shelf_seq: u64,
}

impl Default for StoreData {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            bookmarks: Vec::new(),
            bookmark_folders: Vec::new(),
            downloads: Vec::new(),
            shelves: Vec::new(),
            next_shelf_seq: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    pub id: String,
    pub url: String,
    pub title: String,
    pub created_at: u64,
    /// User-assigned tags, for grouping bookmarks by topic.
    ///
    /// ADDITIVE, same rule as `Shelf::note`: entries written before this
    /// existed read as an empty list, so `SCHEMA_VERSION` stays put. The
    /// export path serialises this whole struct, so tags ride the vault
    /// export and import round trip with no work at either end.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Pinned to the Quick Access row at the top of the bookmarks manager.
    ///
    /// A BOOL rather than a reserved folder name on purpose: a folder called
    /// "quick access" would collide with a real one a user might make, and
    /// would then appear in the folder list as though it were theirs.
    ///
    /// ADDITIVE, same rule as `tags` above: bookmarks written before this
    /// field existed read as `false`, so `SCHEMA_VERSION` stays put.
    #[serde(default)]
    pub quick_access: bool,
    /// What the page looked like when last seen, and when that was
    /// recorded. Owned by the entry, so deleting the bookmark necessarily
    /// deletes the digest.
    pub digest: Option<RecordedDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedDigest {
    pub digest: ContentDigest,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadRecord {
    pub id: String,
    pub url: String,
    pub filename: String,
    pub byte_len: u64,
    /// SHA-256 of the file contents, computed by the caller at download
    /// completion.
    pub sha256: [u8; 32],
    pub recorded_at: u64,
    /// HMAC-SHA256 over the canonical encoding of the fields above, under a
    /// key derived from the store key. Owner-only tamper evidence — see the
    /// crate docs for exactly what this proves and what it does not.
    pub hmac: [u8; 32],
}

/// A named set-aside shelf: one window's tabs, stored so they could be
/// closed without being lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shelf {
    pub id: String,
    pub name: String,
    /// Creation order, assigned from `StoreData::next_shelf_seq` and never
    /// reused, even after a delete. Listing order and telling same-named
    /// shelves apart rest on this, so no timestamp ever appears in a name.
    pub seq: u64,
    /// Seconds since the unix epoch, stamped for parity with
    /// `Bookmark::created_at`. Never shown in the name.
    pub created_at: u64,
    /// Free text the user attached to this shelf, for the reason a set of
    /// tabs was set aside in the first place ("chem lab, due Friday").
    ///
    /// ADDITIVE, under the same rule the `shelves` field itself documents:
    /// shelves written before this existed deserialize with an empty string
    /// and older builds ignore the key, so `SCHEMA_VERSION` stays put.
    ///
    /// It lives on the SHELF, never on a `ShelfTab`. That type's two-key
    /// shape is the feature's privacy contract and is pinned by a test.
    #[serde(default)]
    pub note: String,
    pub tabs: Vec<ShelfTab>,
}

/// One tab on a shelf: title + URL. Nothing else is stored anywhere in the
/// feature -- no favicons, no scroll positions, no cookies, no history.
/// That minimality is the privacy contract of set-aside, not a shortcut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShelfTab {
    pub title: String,
    pub url: String,
}

impl StoreData {
    /// Pure shelf bookkeeping: assigns the next seq/id and appends. No IO,
    /// so `Store` can persist afterwards and roll back on write failure.
    pub fn plan_new_shelf(
        &mut self,
        name: String,
        tabs: Vec<ShelfTab>,
        created_at: u64,
    ) -> Shelf {
        let seq = self.next_shelf_seq;
        self.next_shelf_seq += 1;
        let shelf = Shelf {
            id: format!("shelf-{}", seq),
            name,
            seq,
            created_at,
            note: String::new(),
            tabs,
        };
        self.shelves.push(shelf.clone());
        shelf
    }

    /// Removes a shelf without persisting, returning it with its index so
    /// the caller can put it back exactly where it was if the write fails.
    pub fn take_shelf(&mut self, id: &str) -> Option<(usize, Shelf)> {
        let index = self.shelves.iter().position(|shelf| shelf.id == id)?;
        Some((index, self.shelves.remove(index)))
    }

    // ---- bookmark folders (a folder IS a tag) -----------------------------
    // All pure, no IO: `Store` clones `self.data`, calls one of these, then
    // saves and restores the clone on write failure -- the same
    // mutate-then-persist-with-rollback shape `set_bookmark_tags` uses, but a
    // whole-data snapshot because rename and delete touch every bookmark.
    //
    // The names handed in are ALREADY normalized (`normalize_folder_name`),
    // which produces the identical trim+lowercase a tag gets, so a folder and
    // the tag that stands for it can never drift into two spellings.

    /// Records an empty folder. Idempotent: `false` if it already existed
    /// (nothing to persist), `true` if it was added.
    pub fn plan_folder_create(&mut self, name: &str) -> bool {
        if self.bookmark_folders.iter().any(|f| f == name) {
            return false;
        }
        self.bookmark_folders.push(name.to_string());
        true
    }

    /// Renames `from` to `to` across the known list AND every bookmark tagged
    /// `from`. A bookmark (or the list) already carrying `to` keeps ONE copy,
    /// never two. `from == to` changes nothing. Returns whether anything moved.
    pub fn plan_folder_rename(&mut self, from: &str, to: &str) -> bool {
        if from == to {
            return false;
        }
        let mut changed = false;
        if let Some(pos) = self.bookmark_folders.iter().position(|f| f == from) {
            if self.bookmark_folders.iter().any(|f| f == to) {
                self.bookmark_folders.remove(pos);
            } else {
                self.bookmark_folders[pos] = to.to_string();
            }
            changed = true;
        }
        for bookmark in &mut self.bookmarks {
            if let Some(pos) = bookmark.tags.iter().position(|t| t == from) {
                if bookmark.tags.iter().any(|t| t == to) {
                    bookmark.tags.remove(pos);
                } else {
                    bookmark.tags[pos] = to.to_string();
                }
                changed = true;
            }
        }
        changed
    }

    /// Drops `name` from the known list and strips it from every bookmark's
    /// tags. THE BOOKMARKS ARE NOT DELETED -- deleting a folder unfiles its
    /// contents, it does not destroy them. Returns whether anything was found.
    pub fn plan_folder_delete(&mut self, name: &str) -> bool {
        let mut changed = false;
        if let Some(pos) = self.bookmark_folders.iter().position(|f| f == name) {
            self.bookmark_folders.remove(pos);
            changed = true;
        }
        for bookmark in &mut self.bookmarks {
            if let Some(pos) = bookmark.tags.iter().position(|t| t == name) {
                bookmark.tags.remove(pos);
                changed = true;
            }
        }
        changed
    }

    /// Files one bookmark into a folder by ADDING the tag to that bookmark's
    /// CURRENT tags -- read here, authoritatively, never computed from a
    /// client-side cache, so two quick drops cannot each overwrite the whole
    /// list and lose the other's folder. `Ok`-shaped returns: `None` = no such
    /// bookmark, `Some(false)` = already in that folder (no write needed),
    /// `Some(true)` = added.
    pub fn plan_folder_file(&mut self, id: &str, folder: &str) -> Option<bool> {
        let bookmark = self.bookmarks.iter_mut().find(|b| b.id == id)?;
        if bookmark.tags.iter().any(|t| t == folder) {
            return Some(false);
        }
        bookmark.tags.push(folder.to_string());
        Some(true)
    }

    /// Removes one bookmark from one folder, leaving its other folders and the
    /// bookmark itself intact. Same return shape as `plan_folder_file`.
    pub fn plan_folder_unfile(&mut self, id: &str, folder: &str) -> Option<bool> {
        let bookmark = self.bookmarks.iter_mut().find(|b| b.id == id)?;
        match bookmark.tags.iter().position(|t| t == folder) {
            Some(pos) => {
                bookmark.tags.remove(pos);
                Some(true)
            }
            None => Some(false),
        }
    }
}

/// A folder name normalized exactly as a tag is: trimmed and lowercased,
/// with the same 40-character cap. Rejecting (rather than truncating) an
/// over-long name is the one deliberate difference from tag handling, and it
/// cannot cause drift because a rejected name is never created; every name
/// that IS created is <= 40 chars, where the two normalizations are identical
/// (a test pins that). `Err` carries the IPC code for an empty or over-long
/// name.
pub fn normalize_folder_name(raw: &str) -> Result<String, &'static str> {
    let name = raw.trim().to_lowercase();
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 40 {
        return Err("bad_args");
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_shelf_files_still_load() {
        // JSON exactly as a build from before shelves would have written
        // it. This is the additive-schema promise, pinned.
        let json = r#"{"schema":1,"bookmarks":[],"downloads":[]}"#;
        let data: StoreData = serde_json::from_str(json).expect("old file still loads");
        assert!(data.shelves.is_empty());
        assert_eq!(data.next_shelf_seq, 0);
        assert_eq!(data.schema, SCHEMA_VERSION);
    }

    #[test]
    fn shelf_seq_is_monotonic_and_never_reused() {
        let mut data = StoreData::default();
        let a = data.plan_new_shelf("Set aside 2 tabs".to_string(), vec![], 100);
        let b = data.plan_new_shelf("Set aside 3 tabs".to_string(), vec![], 200);
        assert_eq!(a.seq, 0);
        assert_eq!(a.id, "shelf-0");
        assert_eq!(a.created_at, 100);
        assert_eq!(b.seq, 1);
        assert_eq!(b.id, "shelf-1");
        let (index, taken) = data.take_shelf(&a.id).expect("present");
        assert_eq!(index, 0);
        assert_eq!(taken.id, "shelf-0");
        // The next shelf must not reuse the deleted one's seq or id.
        let c = data.plan_new_shelf("Set aside 4 tabs".to_string(), vec![], 300);
        assert_eq!(c.seq, 2);
        assert_eq!(c.id, "shelf-2");
        assert_eq!(data.shelves.len(), 2);
    }

    #[test]
    fn take_and_reinsert_restores_position() {
        // The rollback half of Store::remove_shelf, exercised at the level
        // where no Store (and no passphrase) is needed.
        let mut data = StoreData::default();
        let a = data.plan_new_shelf("a".to_string(), vec![], 1);
        data.plan_new_shelf("b".to_string(), vec![], 2);
        let (index, taken) = data.take_shelf(&a.id).expect("present");
        data.shelves.insert(index, taken);
        assert_eq!(data.shelves[0].id, a.id);
        assert_eq!(data.shelves.len(), 2);
    }

    #[test]
    fn shelf_tab_serializes_as_title_and_url_only() {
        // The privacy contract, pinned: exactly two keys per entry. Any
        // field that creeps in later fails this test.
        let tab = ShelfTab {
            title: "Example".to_string(),
            url: "https://example.test/".to_string(),
        };
        let value = serde_json::to_value(&tab).expect("serializes");
        let object = value.as_object().expect("an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, vec!["title", "url"]);
    }

    #[test]
    fn store_data_with_shelves_roundtrips_through_json() {
        let mut data = StoreData::default();
        data.plan_new_shelf(
            "Set aside 1 tabs".to_string(),
            vec![ShelfTab {
                title: "Example".to_string(),
                url: "https://example.test/".to_string(),
            }],
            42,
        );
        let text = serde_json::to_string(&data).expect("serialize");
        let back: StoreData = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(data, back);
    }

    // ---- bookmark folders --------------------------------------------------

    fn bookmark_with_tags(id: &str, tags: &[&str]) -> Bookmark {
        Bookmark {
            id: id.to_string(),
            url: format!("https://example.test/{id}"),
            title: id.to_string(),
            created_at: 0,
            tags: tags.iter().map(|t| t.to_string()).collect(),
            quick_access: false,
            digest: None,
        }
    }

    #[test]
    fn folder_files_written_before_this_field_still_load() {
        // A store from a build that predates bookmark_folders has no such key;
        // it must read as an empty list, never a load failure. Additive rule.
        let json = r#"{"schema":1,"bookmarks":[],"downloads":[],"shelves":[]}"#;
        let data: StoreData = serde_json::from_str(json).expect("old file still loads");
        assert!(data.bookmark_folders.is_empty());
        assert_eq!(data.schema, SCHEMA_VERSION);
    }

    #[test]
    fn bookmarks_written_before_quick_access_still_load() {
        // A store from a build that predates quick_access carries no such key
        // on any bookmark. Each must read as unpinned, never a load failure.
        // Same additive rule `bookmark_folders` documents, one struct down.
        let json = r#"{"schema":1,"bookmarks":[{"id":"b1","url":"https://a.test/","title":"A","created_at":0,"tags":["chem"],"digest":null}],"downloads":[]}"#;
        let data: StoreData = serde_json::from_str(json).expect("old file still loads");
        assert!(!data.bookmarks[0].quick_access, "absent reads as unpinned");
        assert_eq!(data.bookmarks[0].tags, vec!["chem".to_string()], "tags survive");
        assert_eq!(data.schema, SCHEMA_VERSION, "no version bump");
    }

    #[test]
    fn folder_create_is_idempotent() {
        let mut data = StoreData::default();
        assert!(data.plan_folder_create("chem"));
        assert!(!data.plan_folder_create("chem"));
        assert_eq!(data.bookmark_folders, vec!["chem".to_string()]);
    }

    #[test]
    fn folder_file_reads_authoritative_tags_and_is_idempotent() {
        // The concurrency-safety property: filing ADDS to whatever tags the
        // bookmark currently has, so a second unrelated folder is not lost.
        let mut data = StoreData::default();
        data.bookmarks.push(bookmark_with_tags("b1", &["physics"]));
        assert_eq!(data.plan_folder_file("b1", "chem"), Some(true));
        assert_eq!(data.plan_folder_file("b1", "chem"), Some(false)); // already there
        assert_eq!(data.plan_folder_file("missing", "chem"), None);
        let b = &data.bookmarks[0];
        assert_eq!(b.tags, vec!["physics".to_string(), "chem".to_string()]);
    }

    #[test]
    fn folder_unfile_leaves_other_folders_and_the_bookmark() {
        let mut data = StoreData::default();
        data.bookmarks
            .push(bookmark_with_tags("b1", &["chem", "physics"]));
        assert_eq!(data.plan_folder_unfile("b1", "chem"), Some(true));
        assert_eq!(data.plan_folder_unfile("b1", "chem"), Some(false)); // gone already
        assert_eq!(data.plan_folder_unfile("missing", "chem"), None);
        assert_eq!(data.bookmarks.len(), 1); // NOT deleted
        assert_eq!(data.bookmarks[0].tags, vec!["physics".to_string()]);
    }

    #[test]
    fn folder_rename_moves_the_list_and_every_bookmark_and_dedups() {
        let mut data = StoreData::default();
        data.bookmark_folders = vec!["chem".to_string()];
        data.bookmarks.push(bookmark_with_tags("b1", &["chem"]));
        // b2 already carries the destination -- rename must not duplicate it.
        data.bookmarks
            .push(bookmark_with_tags("b2", &["chem", "chemistry"]));
        assert!(data.plan_folder_rename("chem", "chemistry"));
        assert_eq!(data.bookmark_folders, vec!["chemistry".to_string()]);
        assert_eq!(data.bookmarks[0].tags, vec!["chemistry".to_string()]);
        assert_eq!(data.bookmarks[1].tags, vec!["chemistry".to_string()]); // deduped
        // Renaming to itself, or a name nothing carries, changes nothing.
        assert!(!data.plan_folder_rename("chemistry", "chemistry"));
        assert!(!data.plan_folder_rename("nope", "whatever"));
    }

    #[test]
    fn folder_delete_unfiles_but_never_destroys() {
        let mut data = StoreData::default();
        data.bookmark_folders = vec!["chem".to_string()];
        data.bookmarks
            .push(bookmark_with_tags("b1", &["chem", "physics"]));
        assert!(data.plan_folder_delete("chem"));
        assert!(!data.plan_folder_delete("chem")); // gone already
        assert!(data.bookmark_folders.is_empty());
        assert_eq!(data.bookmarks.len(), 1); // the bookmark SURVIVES
        assert_eq!(data.bookmarks[0].tags, vec!["physics".to_string()]);
    }

    #[test]
    fn folder_name_normalizes_exactly_like_a_tag_for_every_creatable_name() {
        // The load-bearing invariant: a folder and the tag that stands for it
        // are the SAME string, so they can never split into two groups. This
        // reimplements the tag rule from lib.rs (trim -> cap40 -> lowercase ->
        // trim) and asserts it agrees with normalize_folder_name for every
        // name short enough to be created. If lib.rs's normalize_tags changes,
        // this pins the contract that the folder path must track it.
        fn tag_normalize(raw: &str) -> String {
            let capped: String = raw.trim().chars().take(40).collect();
            capped.to_lowercase().trim().to_string()
        }
        for raw in [
            "Chem",
            "  Physics  ",
            "MiXeD CaSe Folder",
            "café",
            "ün Ü",
            "a",
            "study group 2026",
        ] {
            let folder = normalize_folder_name(raw).expect("creatable");
            assert_eq!(folder, tag_normalize(raw), "mismatch for {raw:?}");
        }
    }

    #[test]
    fn folder_name_rejects_empty_and_overlong() {
        assert!(normalize_folder_name("").is_err());
        assert!(normalize_folder_name("   ").is_err());
        assert!(normalize_folder_name(&"x".repeat(41)).is_err());
        assert!(normalize_folder_name(&"x".repeat(40)).is_ok());
    }
}
