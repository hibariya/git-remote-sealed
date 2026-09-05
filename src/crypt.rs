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

/// Decrypt with any of the given identities.
/// §5/M4: how many recipient stanzas an age file's header carries — i.e.
/// how many keys can open it. The header is plaintext by design (that is
/// what lets a recipient find its own stanza), so this needs no identity.
///
/// Counts `X25519` stanzas only. The reason is not obvious from the spec:
/// age writes a random **grease** stanza (`-> <+=V!r-grease ...`) into some
/// headers on purpose, so that parsers cannot assume they know every stanza
/// type. Counting every `-> ` line therefore over-counts, at random, and a
/// guard built on it refuses legitimate writes.
///
/// **Known limitation.** §5 does NOT make this format X25519-only — it says
/// X25519 is the baseline and implementations MAY support other recipient
/// types (passphrase, plugins). This count is therefore a LOWER bound in
/// general, and the §5/M4 shrink guard built on it only covers X25519
/// recipients. That is sound today because both implementations emit
/// nothing else, and it stays sound only while that holds: the first
/// non-X25519 recipient (a post-quantum plugin, say) is silently
/// uncounted, and the guard stops protecting it. An allow-list cannot be
/// grown to fix this — a plugin stanza is `-> <plugin-name> ...`, shape-
/// identical to grease. The fix, when this format gains a non-X25519
/// recipient, is to record the count in the manifest as a `recipients <n>`
/// line and compare against that: exact, type-agnostic, no header parsing.
/// Deferred deliberately (2026-09-04 review, L2).
///
/// `None` when the bytes are not an age file we recognize; callers treat
/// that as "cannot tell" and do not block on it.
pub fn recipient_count(ciphertext: &[u8]) -> Option<usize> {
    let mut lines = ciphertext.split(|b| *b == b'\n');
    let first = lines.next()?;
    if !first.starts_with(b"age-encryption.org/") {
        return None;
    }
    let mut n = 0usize;
    for line in lines {
        if line.starts_with(b"---") {
            return Some(n);
        }
        if line.starts_with(b"-> X25519 ") {
            n += 1;
        }
    }
    None // no MAC line: truncated header, not something to reason about
}

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
        // it is random, so counting it makes the §5 guard refuse at random.
        let greased: &[u8] = b"age-encryption.org/v1\n-> X25519 aaaa\nbbbb\n-> <+=V!r-grease *pYpm6zm pr\n\n--- mac\n";
        assert_eq!(recipient_count(greased), Some(1));
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
