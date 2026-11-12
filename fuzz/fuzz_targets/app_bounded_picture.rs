// The stored copy of a snapshot picture (crates/app/src/capture.rs). The PNG
// arrives from the engine's capture or inside an imported backup, and the
// promise is that whatever is kept is a PNG inside the preview bounds: small
// pictures are kept as they are after every row decodes, large ones are
// streamed down. A header can claim any size, so the bound is the property
// worth checking, not just the absence of a panic.
//
// Reaching the downscale needs a VALID large PNG, which a fuzzer will not
// invent from nothing: seed it with fuzz/seeds.py.
#![no_main]
use libfuzzer_sys::fuzz_target;
use patanyx_app::fuzz_api::{
    bounded_picture_png, png_dimensions, PICTURE_MAX_PIXELS, PICTURE_MAX_SIDE,
};

fuzz_target!(|data: &[u8]| {
    let Ok(kept) = bounded_picture_png(data) else {
        return;
    };
    let (w, h) = png_dimensions(&kept).expect("a kept picture has a readable PNG header");
    assert!(w > 0 && h > 0, "kept a {w}x{h} picture");
    assert!(
        w <= PICTURE_MAX_SIDE && h <= PICTURE_MAX_SIDE,
        "kept {w}x{h}, past the side bound"
    );
    assert!(
        u64::from(w) * u64::from(h) <= PICTURE_MAX_PIXELS,
        "kept {w}x{h}, past the pixel bound"
    );
});
