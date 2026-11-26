//! JSON encoding of secret data into ONE exactly sized, wiped buffer.
//!
//! `serde_json::to_vec` starts from a small `Vec` and reallocates as it
//! grows; every outgrown buffer is freed with part of the plaintext still in
//! it, and `Zeroizing` around the result wipes only the last one (SecScan
//! S-5db9b51b6852, 2026-11-24). The read side already grows by hand
//! (`backup_v4.rs`, `read_plain`); this is the write side's equivalent.
//!
//! Two passes: the first only counts bytes, the second writes into a
//! fixed-size slice, which cannot grow. A second pass that disagrees with the
//! first is an error, never a silent reallocation.
//!
//! A twin of `patanyx-vault`'s `sealed_json.rs`; the crates share no code.

use serde::Serialize;
use zeroize::Zeroizing;

struct Count(usize);

impl std::io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode<T: Serialize + ?Sized, W: std::io::Write>(w: W, value: &T, pretty: bool) -> serde_json::Result<()> {
    if pretty {
        serde_json::to_writer_pretty(w, value)
    } else {
        serde_json::to_writer(w, value)
    }
}

/// `value` as JSON, in a buffer allocated once at its final size.
pub fn to_vec<T: Serialize + ?Sized>(value: &T, pretty: bool) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    let mut count = Count(0);
    encode(&mut count, value, pretty)?;
    let mut out = Zeroizing::new(vec![0u8; count.0]);
    let mut rest: &mut [u8] = &mut out[..];
    encode(&mut rest, value, pretty)?;
    if !rest.is_empty() {
        return Err(serde::ser::Error::custom("the second encoding was shorter than the first"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::to_vec;
    use std::collections::HashMap;

    #[test]
    fn matches_serde_json_byte_for_byte_in_one_exact_allocation() {
        let mut map = HashMap::new();
        for i in 0..200 {
            map.insert(format!("key-{i}"), "secret ".repeat(i));
        }
        let plain = serde_json::to_vec(&map).unwrap();
        let sealed = to_vec(&map, false).unwrap();
        assert_eq!(&sealed[..], &plain[..]);
        assert_eq!(sealed.capacity(), sealed.len(), "allocated once, at its final size");

        let pretty = serde_json::to_vec_pretty(&map).unwrap();
        assert_eq!(&to_vec(&map, true).unwrap()[..], &pretty[..]);
        assert_eq!(&to_vec(&(), false).unwrap()[..], b"null");
    }
}
