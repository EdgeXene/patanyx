//! Seeds a store with demo shelves and tagged bookmarks, for screenshotting
//! the Library panel with realistic data. Development helper: it writes only
//! to the path it is given, and is never compiled into the browser.
use patanyx_store::{Store, ShelfTab};

fn tab(title: &str, url: &str) -> ShelfTab {
    ShelfTab { title: title.to_string(), url: url.to_string() }
}

fn main() {
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("usage: seed-demo <store-path> <passphrase>");
    let pass = a.next().expect("passphrase required");
    let path = std::path::PathBuf::from(path);
    let mut store = if Store::exists(&path) {
        Store::unlock(&path, &pass).expect("unlock")
    } else {
        Store::create(&path, &pass).expect("create")
    };

    let sets = [
        ("Chem lab report", "Due Friday. Cite the 2019 paper, not the preprint.",
         vec![tab("Reaction kinetics overview", "https://example.edu/kinetics"),
              tab("2019 rate constants paper", "https://example.edu/rates-2019"),
              tab("Lab safety sheet", "https://example.edu/safety")]),
        ("History essay, WW1 causes", "Prof wants primary sources only. 2000 words.",
         vec![tab("Archive: 1914 telegrams", "https://example.org/telegrams"),
              tab("Treaty text", "https://example.org/treaty")]),
        ("Apartment hunting", "Viewings booked for Saturday morning.",
         vec![tab("Listing, Elm Street", "https://example.net/elm"),
              tab("Listing, Maple Ave", "https://example.net/maple"),
              tab("Commute times", "https://example.net/commute"),
              tab("Deposit rules", "https://example.net/deposits")]),
    ];
    for (name, note, tabs) in sets {
        let shelf = store.add_shelf(name.to_string(), tabs).expect("add shelf");
        store.set_shelf_note(&shelf.id, note).expect("note");
    }

    let marks = [
        ("https://example.com/warehouse-docs", "Reporting Warehouse Documentation", vec!["data"]),
        ("https://dbml.dbdiagram.io/docs", "DBML Syntax, Core Database Markup", vec!["data", "reference"]),
        ("https://example.com/ekkn", "EKKN, Account Assignment in Purchasing Document", vec!["data", "sap"]),
        ("https://example.com/ekpo", "EKPO, Purchasing Document Item", vec!["data", "sap"]),
        ("https://make.powerautomate.com/", "Power Automate", vec!["data", "tools"]),
        ("https://app.powerbi.com/", "Power BI", vec!["data", "tools"]),
        ("https://example.com/pmc", "PMC Tracker", vec!["tools"]),
        ("https://example.edu/kinetics", "Reaction kinetics overview", vec!["chem", "coursework"]),
        ("https://example.org/treaty", "Treaty of Versailles, full text", vec!["history", "primary source"]),
        ("https://example.net/deposits", "Tenancy deposit rules", vec!["housing"]),
        ("https://example.com/rust-book", "The Rust Programming Language", vec!["rust", "reference", "coursework"]),
    ];
    for (url, title, tags) in marks {
        let id = store.add_bookmark(url, title).expect("bookmark");
        store
            .set_bookmark_tags(&id, tags.iter().map(|t| t.to_string()).collect())
            .expect("tags");
    }
    println!("seeded {} shelves, {} bookmarks", store.shelves().len(), store.bookmarks().len());
}
