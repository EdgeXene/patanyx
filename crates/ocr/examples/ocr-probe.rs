//! Runs the real models against a real image. Not a unit test: it needs the
//! converted ONNX files, which are not in the repo.
//!
//!   cargo run -p patanyx-ocr --example ocr-probe -- <model-dir> <image>
use patanyx_ocr::OcrEngine;
use std::path::Path;

fn main() {
    let mut a = std::env::args().skip(1);
    let dir = a.next().expect("model dir");
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
