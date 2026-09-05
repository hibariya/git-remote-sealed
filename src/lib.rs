//! Rust reference implementation of the sealed vault format, version 2.
//!
//! On-format modules (names, manifest, pin store, crypto glue), the vault
//! container (`vaultrepo`), the §6 reader pipeline (`reader`), the §8 writer
//! (`writer`, with `srcrepo` + `bundling` underneath), §9 compaction
//! (`compact`), the git remote-helper protocol (`helper`), and the
//! user-facing subcommands (`cli`).
//!
//! Provenance rule: this crate is derived from `docs/FORMAT.md`
//! (plus the formal model for the protocol core) and from nothing else.
//! See README.md.

#![forbid(unsafe_code)]

pub mod bundling;
pub mod cli;
pub mod compact;
pub mod crypt;
mod durable;
pub mod helper;
mod json;
pub mod manifest;
pub mod names;
pub mod pinstore;
pub mod reader;
pub mod settings;
pub mod srcrepo;
pub mod vaultrepo;
pub mod writer;

/// §3 / §7.2: the format version this implementation speaks.
pub const FORMAT_VERSION: u64 = 2;

/// §3: the encrypted manifest's file name. Named for the format, not for
/// this tool — the format has more than one implementation.
pub const MANIFEST_FILE: &str = "sealed-manifest.age";

/// §3: version 1 called the manifest `refs.age`, back when refs were most
/// of what it held. A v2 writer MUST DROP this on any tree rewrite rather
/// than preserve it as an unknown entry: a migrated vault that carried its
/// old manifest forward would keep serving a stale view of itself.
pub const LEGACY_MANIFEST_FILE: &str = "refs.age";

/// §3: the plaintext version hint.
pub const FORMAT_HINT_FILE: &str = "sealed-format";

/// SHA-256 of `bytes`, lowercase hex — the digest used for `bundle` lines
/// (§7.2) and the manifest-ciphertext pin (§7.4).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
}

/// A `Write` adapter that feeds everything written through SHA-256 as well —
/// the reader's chunk reassembly and the writer's ciphertext generation both
/// need a digest of a stream they are already writing to a file.
pub(crate) struct HashingWriter<W: std::io::Write> {
    pub(crate) inner: W,
    pub(crate) hasher: sha2::Sha256,
}

impl<W: std::io::Write> HashingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        use sha2::Digest;
        HashingWriter {
            inner,
            hasher: sha2::Sha256::new(),
        }
    }

    /// Finish hashing: the digest (lowercase hex) and the inner writer.
    pub(crate) fn finish(self) -> (String, W) {
        use sha2::Digest;
        (to_hex(&self.hasher.finalize()), self.inner)
    }
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("abc"), the FIPS 180-2 test vector.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn to_hex_lowercase() {
        assert_eq!(to_hex(&[0x00, 0xff, 0x1a]), "00ff1a");
    }

    #[test]
    fn hashing_writer_matches_sha256_hex() {
        use std::io::Write;
        let mut sink = HashingWriter::new(Vec::new());
        sink.write_all(b"abc").expect("writes");
        let (digest, inner) = sink.finish();
        assert_eq!(inner, b"abc");
        assert_eq!(digest, sha256_hex(b"abc"));
    }
}
