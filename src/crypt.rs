//! Encryption glue: §5 — every encrypted file is a binary age v1 file,
//! encrypted to the vault's recipient set. X25519 recipients are the
//! baseline; this skeleton implements only those.

use std::fmt;
use std::io::{Read, Write};

use age::x25519::{Identity, Recipient};

#[derive(Debug)]
pub enum CryptError {
    Encrypt(String),
    /// Includes authentication failure: §10 — each age file authenticates
    /// its whole plaintext on decryption.
    Decrypt(String),
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptError::Encrypt(e) => write!(f, "age encryption failed: {e}"),
            CryptError::Decrypt(e) => write!(f, "age decryption failed: {e}"),
        }
    }
}

impl std::error::Error for CryptError {}

/// Encrypt `plaintext` to the recipient set (§5: one or more recipients,
/// binary age v1 output).
pub fn encrypt(recipients: &[Recipient], plaintext: &[u8]) -> Result<Vec<u8>, CryptError> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| CryptError::Encrypt(e.to_string()))?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| CryptError::Encrypt(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CryptError::Encrypt(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| CryptError::Encrypt(e.to_string()))?;
    Ok(ciphertext)
}

/// Streaming encrypt: `input` to `output` without holding either side in
/// memory (bundles can be large; the writer streams `git bundle` output
/// through age into a scratch file). Returns the plaintext byte count and
/// hands the output writer back so the caller can finish whatever it was
/// wrapping (e.g. a digest).
pub fn encrypt_stream<R: Read, W: Write>(
    recipients: &[Recipient],
    mut input: R,
    output: W,
) -> Result<(u64, W), CryptError> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| CryptError::Encrypt(e.to_string()))?;
    let mut writer = encryptor
        .wrap_output(output)
        .map_err(|e| CryptError::Encrypt(e.to_string()))?;
    let n =
        std::io::copy(&mut input, &mut writer).map_err(|e| CryptError::Encrypt(e.to_string()))?;
    let output = writer
        .finish()
        .map_err(|e| CryptError::Encrypt(e.to_string()))?;
    Ok((n, output))
}

/// What an age header's recipient stanzas say about who can open the
/// file. The header is plaintext by design (that is what lets a recipient
/// find its own stanza), so this needs no identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderStanzas {
    /// `-> X25519 ...` stanzas: one per X25519 recipient the file was
    /// encrypted to.
    pub x25519: usize,
    /// Stanzas of any other type — a passphrase (`scrypt`) or a plugin
    /// recipient. Grease is NOT counted here (see `header_stanzas`).
    pub other: usize,
}

/// §5 declared-vs-actual: count the recipient stanzas in an age file's
/// header, by type.
///
/// Counting every `-> ` line would be wrong, and the reason is not obvious
/// from the spec: age writes a random **grease** stanza into some headers
/// on purpose, so that parsers cannot assume they know every stanza type.
/// A grease stanza is not a recipient, so it is skipped. Documented
/// choice: grease is recognized by the `-grease` tag suffix the age
/// crate (rage) emits; a plugin stanza is `-> <plugin-name> ...`, shape-
/// identical otherwise, so no stronger rule exists. Every file this
/// implementation reads was written by the age crate or by an
/// implementation of this format, and neither produces a non-grease
/// stanza with that suffix.
///
/// `None` when the bytes are not an age file we recognize (or the header
/// is truncated); callers treat that as "cannot tell".
pub fn header_stanzas(ciphertext: &[u8]) -> Option<HeaderStanzas> {
    let mut lines = ciphertext.split(|b| *b == b'\n');
    let first = lines.next()?;
    if !first.starts_with(b"age-encryption.org/") {
        return None;
    }
    let mut counts = HeaderStanzas {
        x25519: 0,
        other: 0,
    };
    for line in lines {
        if line.starts_with(b"---") {
            return Some(counts);
        }
        let Some(stanza) = line.strip_prefix(b"-> ") else {
            continue; // a stanza body line
        };
        let tag = stanza.split(|b| *b == b' ').next().unwrap_or_default();
        if tag == b"X25519" {
            counts.x25519 += 1;
        } else if !tag.ends_with(b"-grease") {
            counts.other += 1;
        }
    }
    None // no MAC line: truncated header, not something to reason about
}

/// The X25519 stanza count alone (`header_stanzas`), for the §5 check.
pub fn recipient_count(ciphertext: &[u8]) -> Option<usize> {
    header_stanzas(ciphertext).map(|h| h.x25519)
}

/// Decrypt with any of the given identities.
pub fn decrypt(identities: &[Identity], ciphertext: &[u8]) -> Result<Vec<u8>, CryptError> {
    let mut plaintext = Vec::new();
    decrypt_stream(identities, ciphertext, &mut plaintext)?;
    Ok(plaintext)
}

/// Streaming decrypt: `input` to `output` without holding the plaintext in
/// memory (bundles can be large; §6.5's reassembly/apply path streams).
/// Returns the plaintext byte count. Authentication is still whole-file:
/// age fails loudly before `output` is complete if the ciphertext was
/// tampered with, so callers MUST treat an error as "discard the output",
/// never as a partial success.
pub fn decrypt_stream<R: Read, W: Write>(
    identities: &[Identity],
    input: R,
    output: &mut W,
) -> Result<u64, CryptError> {
    let decryptor = age::Decryptor::new(input).map_err(|e| CryptError::Decrypt(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i as &dyn age::Identity))
        .map_err(|e| CryptError::Decrypt(e.to_string()))?;
    std::io::copy(&mut reader, output).map_err(|e| CryptError::Decrypt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_count_matches_the_number_encrypted_to() {
        for n in 1..=4usize {
            let ids: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
            let rcpts: Vec<Recipient> = ids.iter().map(Identity::to_public).collect();
            let ct = encrypt(&rcpts, b"hello").expect("encrypt");
            assert_eq!(recipient_count(&ct), Some(n), "for {n} recipients");
        }
        assert_eq!(recipient_count(b"not an age file"), None);

        // The grease stanza age sprinkles into headers must not be counted:
        // it is random, so counting it makes the §5 check fail at random.
        let greased: &[u8] = b"age-encryption.org/v1\n-> X25519 aaaa\nbbbb\n-> <+=V!r-grease *pYpm6zm pr\n\n--- mac\n";
        assert_eq!(recipient_count(greased), Some(1));
        assert_eq!(
            header_stanzas(greased),
            Some(HeaderStanzas {
                x25519: 1,
                other: 0
            })
        );
        // A non-X25519 recipient (passphrase, plugin) is counted apart: the
        // §5/§9.2 counts are not comparable then.
        let mixed: &[u8] = b"age-encryption.org/v1\n-> X25519 aaaa\nbbbb\n-> scrypt cccc 18\ndddd\n-> piv-p256 eeee\nffff\n--- mac\n";
        assert_eq!(
            header_stanzas(mixed),
            Some(HeaderStanzas {
                x25519: 1,
                other: 2
            })
        );
        assert_eq!(
            header_stanzas(b"age-encryption.org/v1\n-> X25519 a\n"),
            None
        );
    }

    #[test]
    fn round_trips_to_multiple_recipients() {
        // §5: all files encrypted to the recipient set; any identity opens.
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let recipients = vec![id_a.to_public(), id_b.to_public()];
        let ciphertext = encrypt(&recipients, b"# v2 git bundle\n").expect("encrypts");
        assert_ne!(&ciphertext, b"# v2 git bundle\n");
        for id in [&id_a, &id_b] {
            let plaintext = decrypt(std::slice::from_ref(id), &ciphertext).expect("decrypts");
            assert_eq!(plaintext, b"# v2 git bundle\n");
        }
    }

    #[test]
    fn wrong_identity_fails() {
        let id = Identity::generate();
        let other = Identity::generate();
        let ciphertext = encrypt(&[id.to_public()], b"secret").expect("encrypts");
        assert!(decrypt(&[other], &ciphertext).is_err());
    }

    #[test]
    fn decrypt_stream_round_trips_and_reports_length() {
        let id = Identity::generate();
        let payload = vec![0xa5u8; 300_000]; // spans several age STREAM chunks
        let ciphertext = encrypt(&[id.to_public()], &payload).expect("encrypts");
        let mut out = Vec::new();
        let n = decrypt_stream(&[id], ciphertext.as_slice(), &mut out).expect("decrypts");
        assert_eq!(n, payload.len() as u64);
        assert_eq!(out, payload);
    }

    #[test]
    fn encrypt_stream_round_trips() {
        let id = Identity::generate();
        let payload = vec![0x5au8; 200_000];
        let (n, cipher) =
            encrypt_stream(&[id.to_public()], payload.as_slice(), Vec::new()).expect("encrypts");
        assert_eq!(n, payload.len() as u64);
        assert_eq!(decrypt(&[id], &cipher).expect("decrypts"), payload);
    }

    #[test]
    fn tampered_ciphertext_fails_loudly() {
        // §10: the age file authenticates its whole plaintext on decryption.
        let id = Identity::generate();
        let mut ciphertext = encrypt(&[id.to_public()], b"payload bytes").expect("encrypts");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        assert!(decrypt(&[id], &ciphertext).is_err());
    }
}
