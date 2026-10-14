//! The feature videos (1.0.5): three silent screen recordings of Reader View,
//! Tab Groups and Side by Side, made on a fictional test site and compiled
//! into the browser, so watching one contacts nobody. Tab Groups and Side by
//! Side come from the 1.0.5 build; Reader View was re-recorded from a 1.0.7
//! build, because 1.0.7 moved its toolbar button into the Menu.
//!
//! HOW THEY REACH THE PLAYER. The chrome asks for one by name over its IPC
//! (`tutorial_video`) and plays the bytes from a `blob:` URL. Not from a
//! chrome-origin URL: WebKitGTK's media pipeline fetches only http(s), file
//! and blob sources, so a video at `rbchrome://...` fails at once with
//! FormatError (measured on WebKitGTK 2.50.6, 2026-10-07), and a blob plays
//! the same way on both engines. The chrome CSP gains `media-src blob:` and
//! nothing else; `connect-src` stays `'none'`.
//!
//! WebM/VP9: the one format both engines decode with only their declared
//! dependencies (WebView2 natively; WebKitGTK through
//! gstreamer1.0-plugins-good, which Debian's libwebkit2gtk-4.1-0 Depends on).
//!
//! 1.0.7 adds one on Windows only: Kept Sites, recorded from the 1.0.7 build
//! on a Windows 11 VM against a fictional site served on that machine's
//! loopback. Keeping sites exists only there (kept_profile.rs), so the
//! Linux binary carries neither the video nor a way to ask for it.

const VIDEOS: &[(&str, &[u8])] = &[
    ("reader-view", include_bytes!("chrome/tutorial/reader-view.webm")),
    ("tab-groups", include_bytes!("chrome/tutorial/tab-groups.webm")),
    ("side-by-side", include_bytes!("chrome/tutorial/side-by-side.webm")),
    #[cfg(windows)]
    ("keep-sites", include_bytes!("chrome/tutorial/keep-sites.webm")),
];

/// The named video, base64-encoded for the IPC reply, or None for any name
/// that is not exactly one of them.
pub fn video_base64(name: &str) -> Option<String> {
    VIDEOS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, bytes)| encode_base64(bytes))
}

/// Standard base64 with padding (RFC 4648), which the chrome's `atob` reads.
fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vectors_and_round_trips() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_base64(raw.as_bytes()), enc);
        }
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(crate::capture::decode_base64(&encode_base64(&all)).as_deref(), Some(&all[..]));
    }

    #[test]
    fn only_the_listed_videos_are_served_and_they_are_webm() {
        assert_eq!(VIDEOS.len(), if cfg!(windows) { 4 } else { 3 });
        assert_eq!(video_base64("keep-sites").is_some(), cfg!(windows), "Kept Sites is Windows only");
        for &(name, bytes) in VIDEOS {
            assert!(bytes.len() > 10_000, "{name} is suspiciously small");
            assert!(bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]), "{name} is not a WebM/Matroska file");
            let b64 = video_base64(name).expect(name);
            assert_eq!(crate::capture::decode_base64(&b64).as_deref(), Some(bytes));
        }
        for name in ["", "reader-view.webm", "../reader-view", "READER-VIEW", "tab-groups ", "index"] {
            assert!(video_base64(name).is_none(), "{name:?}");
        }
    }
}
