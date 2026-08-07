use patanyx_integrity::ContentDigest;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreData {
    pub schema: u32,
    #[serde(default)]
    pub bookmarks: Vec<Bookmark>,
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
}
