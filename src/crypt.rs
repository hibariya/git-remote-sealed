//! Encryption glue: §5 — every encrypted file is a binary age v1 file,
//! encrypted to the vault's recipient set. X25519 recipients are the
//! baseline; this skeleton implements only those.

use std::collections::BTreeMap;
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

/// The stanza tag of an X25519 recipient (`-> X25519 ...`).
pub const X25519_TAG: &str = "X25519";

/// What an age header's recipient stanzas say about who can open the
/// file: one count per stanza type (the tag after `-> `), grease excluded
/// (see `header_stanzas`). The header is plaintext by design (that is
/// what lets a recipient find its own stanza), so this needs no identity.
///
/// Counting by type rather than "X25519 vs. the rest" is what lets the §5
/// check reject a stanza of a type nobody declared, and what a future
/// recipient type (post-quantum) plugs into: one more recognized tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderStanzas {
    /// tag -> number of stanzas with that tag.
    pub by_type: BTreeMap<String, usize>,
}

impl HeaderStanzas {
    fn add(&mut self, tag: &str) {
        *self.by_type.entry(tag.to_owned()).or_insert(0) += 1;
    }

    /// `-> X25519 ...` stanzas: one per X25519 recipient the file was
    /// encrypted to.
    pub fn x25519(&self) -> usize {
        self.by_type.get(X25519_TAG).copied().unwrap_or(0)
    }

    /// Stanzas of any other type — a passphrase (`scrypt`) or a plugin
    /// recipient.
    pub fn other(&self) -> usize {
        self.total() - self.x25519()
    }

    /// Every recipient stanza, whatever its type.
    pub fn total(&self) -> usize {
        self.by_type.values().sum()
    }
}

/// "2 X25519 key(s)", or with the other types spelled out: "2 X25519
/// key(s) and 1 other recipient stanza(s) (scrypt)".
impl fmt::Display for HeaderStanzas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} X25519 key(s)", self.x25519())?;
        let others: Vec<&str> = self
            .by_type
            .keys()
            .map(String::as_str)
            .filter(|t| *t != X25519_TAG)
            .collect();
        if !others.is_empty() {
            write!(
                f,
                " and {} other recipient stanza(s) ({})",
                self.other(),
                others.join(", ")
            )?;
        }
        Ok(())
    }
}

/// The stanza tag a `recipient` line's key type corresponds to, when this
/// implementation recognizes the type (§5). `None` for a type it cannot
/// tell apart (a plugin recipient): its stanzas are not comparable.
pub fn recipient_tag(recipient: &str) -> Option<&'static str> {
    use std::str::FromStr;
    if Recipient::from_str(recipient).is_ok() {
        return Some(X25519_TAG);
    }
    None
}

/// §5: the stanzas a set of `recipient` lines calls for, by type — or
/// `None` when a line is of a type this implementation does not recognize
/// (the check does not apply then).
pub fn declared_stanzas<'a, I>(recipients: I) -> Option<HeaderStanzas>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut counts = HeaderStanzas::default();
    for r in recipients {
        counts.add(recipient_tag(r)?);
    }
    Some(counts)
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
    let mut counts = HeaderStanzas::default();
    for line in lines {
        if line.starts_with(b"---") {
            return Some(counts);
        }
        let Some(stanza) = line.strip_prefix(b"-> ") else {
            continue; // a stanza body line
        };
        let tag = stanza.split(|b| *b == b' ').next().unwrap_or_default();
        if !tag.ends_with(b"-grease") {
            counts.add(&String::from_utf8_lossy(tag));
        }
    }
    None // no MAC line: truncated header, not something to reason about
}

/// The X25519 stanza count alone (`header_stanzas`).
pub fn recipient_count(ciphertext: &[u8]) -> Option<usize> {
    header_stanzas(ciphertext).map(|h| h.x25519())
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
        let h = header_stanzas(greased).expect("readable header");
        assert_eq!((h.x25519(), h.other(), h.total()), (1, 0, 1));
        assert_eq!(h.to_string(), "1 X25519 key(s)");
        // A non-X25519 recipient (passphrase, plugin) is counted under its
        // own tag: the §5 check compares by type.
        let mixed: &[u8] = b"age-encryption.org/v1\n-> X25519 aaaa\nbbbb\n-> scrypt cccc 18\ndddd\n-> piv-p256 eeee\nffff\n--- mac\n";
        let h = header_stanzas(mixed).expect("readable header");
        assert_eq!((h.x25519(), h.other(), h.total()), (1, 2, 3));
        assert_eq!(h.by_type["scrypt"], 1);
        assert_eq!(h.by_type["piv-p256"], 1);
        assert_eq!(
            h.to_string(),
            "1 X25519 key(s) and 2 other recipient stanza(s) (piv-p256, scrypt)"
        );
        assert_eq!(
            header_stanzas(b"age-encryption.org/v1\n-> X25519 a\n"),
            None
        );
    }

    #[test]
    fn declared_stanzas_follow_the_recipient_types() {
        // §5: what the `recipient` lines call for, by type; a type this
        // implementation cannot classify makes the set incomparable.
        let a = Identity::generate().to_public().to_string();
        let b = Identity::generate().to_public().to_string();
        let d = declared_stanzas([&a, &b]).expect("two X25519 lines");
        assert_eq!(
            d.by_type,
            [(X25519_TAG.to_owned(), 2)].into_iter().collect()
        );
        assert_eq!(recipient_tag(&a), Some(X25519_TAG));
        assert_eq!(recipient_tag("age1yubikey1qwerty"), None);
        assert_eq!(
            declared_stanzas([&a, &"age1yubikey1qwerty".to_owned()]),
            None
        );
        assert_eq!(declared_stanzas([]), Some(HeaderStanzas::default()));
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
