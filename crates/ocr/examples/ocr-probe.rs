//! Runs the real models against real images. Not a unit test: this is the
//! small command-line harness used for local model and parity probes.
//!
//!   cargo run -p patanyx-ocr --example ocr-probe -- <model-dir> <image>
//!   cargo run -p patanyx-ocr --example ocr-probe -- --parity <image>...
use patanyx_ocr::OcrEngine;
use std::path::Path;

fn main() {
    let mut a = std::env::args().skip(1);
    let first = a.next().expect("model dir or --parity");
    if first == "--parity" {
        let images: Vec<String> = a.collect();
        if images.is_empty() {
            eprintln!("--parity needs at least one image");
            std::process::exit(2);
        }
        let engine = OcrEngine::load_embedded().unwrap_or_else(|e| {
            eprintln!("LOAD FAILED: {e}");
            std::process::exit(1);
        });
        for img in images {
            let bytes = std::fs::read(&img).unwrap_or_else(|e| {
                eprintln!("READ FAILED {img}: {e}");
                std::process::exit(1);
            });
            let regions = engine.recognize(&bytes).unwrap_or_else(|e| {
                eprintln!("RECOGNIZE FAILED {img}: {e}");
                std::process::exit(1);
            });
            let text = regions
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            // Rust's Debug string spelling is valid JSON for ordinary OCR
            // text and escapes tabs/newlines/quotes, making this a stable
            // one-record-per-line protocol without another dependency.
            println!("PARITY\t{img}\t{text:?}");
        }
        return;
    }

    let dir = first;
    let img = a.next().expect("image path");
    let t0 = std::time::Instant::now();
    let engine = match OcrEngine::load(Path::new(&dir)) {
        Ok(e) => e,
        Err(e) => {
            println!("LOAD FAILED: {e}");
            std::process::exit(1);
        }
    };
    println!("loaded in {:?}", t0.elapsed());
    let bytes = std::fs::read(&img).expect("read image");
    let t1 = std::time::Instant::now();
    match engine.recognize(&bytes) {
        Err(e) => println!("RECOGNIZE FAILED: {e}"),
        Ok(regions) => {
            println!(
                "recognized in {:?} -- {} region(s)",
                t1.elapsed(),
                regions.len()
            );
            for r in &regions {
                println!("  [{},{} {}x{}]  {:?}", r.x, r.y, r.w, r.h, r.text);
            }
        }
    }
}
