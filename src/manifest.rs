//! The manifest (`sealed-manifest.age` plaintext): §7 parse/serialize, §6.7 expected
//! file set, §4.3 bundle-header verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::names::{self, BundleName, NameClass};

/// §7.2: counter values up to at least 2^63-1 (fixes the integer type);
/// §4.1 fixes seq identically.
pub const MAX_COUNTER: u64 = (1 << 63) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    Sha1,
    Sha256,
}

impl ObjectFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectFormat::Sha1 => "sha1",
            ObjectFormat::Sha256 => "sha256",
        }
    }

    pub fn from_str_exact(s: &str) -> Option<Self> {
        match s {
            "sha1" => Some(ObjectFormat::Sha1),
            "sha256" => Some(ObjectFormat::Sha256),
            _ => None,
        }
    }

    /// §7.2: ref sha width — 40 hex iff sha1, 64 hex iff sha256.
    pub fn ref_hex_width(self) -> usize {
        match self {
            ObjectFormat::Sha1 => 40,
            ObjectFormat::Sha256 => 64,
        }
    }

    /// §4.3: bundle payload version follows the object format, strictly.
    pub fn bundle_header_line(self) -> &'static str {
        match self {
            ObjectFormat::Sha1 => "# v2 git bundle",
            ObjectFormat::Sha256 => "# v3 git bundle",
        }
    }
}

/// One `bundle` line (§7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRecord {
    pub seq: u64,
    pub full: bool,
    /// SHA-256 of the (reassembled) ciphertext, 64 lowercase hex.
    pub digest: String,
    /// `Some(count)` iff chunked into parts `.0` .. `.(count-1)`; count >= 2.
    pub chunks: Option<u64>,
}

impl BundleRecord {
    pub fn logical_name(&self) -> Result<BundleName, names::NameError> {
        BundleName::new(self.seq, self.full, None)
    }
}

/// A validated v2 manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// §7.2 `format` — always 2 after a successful parse; kept as a field so
    /// the pin's format-monotonicity check (§7.4) has a value to compare.
    pub format: u64,
    pub object_format: ObjectFormat,
    /// §7.2 `vault` — lowercase hex, >= 128 bits.
    pub vault_id: String,
    pub counter: u64,
    pub seqfloor: u64,
    /// Keyed by seq: §7.2 forbids two bundle lines sharing a sequence number.
    pub bundles: BTreeMap<u64, BundleRecord>,
    /// §7.2 `@<refname> HEAD` — zero or one.
    pub head: Option<String>,
    /// refname -> sha (lowercase hex of the declared width).
    pub refs: BTreeMap<String, String>,
}

/// Parse result: the manifest plus the §7.3 writer rule surfaced as a flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedManifest {
    pub manifest: Manifest,
    /// §7.3: true iff the text contained a line with an unrecognized first
    /// token. A writer MUST then refuse to write (become read-only), because
    /// regenerating the manifest would silently delete the unknown line.
    pub writer_must_be_read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// §7.1: decrypted content is UTF-8 text.
    NotUtf8,
    /// Documented choice: an empty line has no first token, cannot be a
    /// future extension line (§7.3 extensions are line *types*), and is
    /// therefore invalid rather than ignorable.
    EmptyLine { line_no: usize },
    /// §7.2: a REQUIRED singleton line is absent.
    Missing(&'static str),
    /// §7.3: duplicate of an at-most-once line (singletons, HEAD symref,
    /// a refname, a logical bundle name).
    Duplicate(String),
    /// §7.2: no two `bundle` lines may share a sequence number, with or
    /// without `-full`.
    DuplicateBundleSeq(u64),
    /// §3: refuse versions we do not support.
    UnsupportedFormat(String),
    /// §7.3: a recognized first token whose line does not match its grammar
    /// (arity included) is invalid, never an unknown line.
    BadLine { line_no: usize, what: &'static str },
    /// §7.2: a ref line whose hex width disagrees with the declared object
    /// format is INVALID, never an unknown line (the silent-ref-drop rule).
    RefWidthMismatch { line_no: usize },
    /// §7.2: seqfloor >= every sequence in the bundle list.
    SeqfloorBelowBundle { seqfloor: u64, seq: u64 },
    /// §7.2 (reader assertion): a nonempty bundle list carries the -full
    /// label at its lowest sequence number — the recovery root Appendix A
    /// starts from (model: `inv_p_rooting`).
    NotRooted { lowest: u64 },
    /// §4.3: a decrypted bundle whose header disagrees with the vault's
    /// object format.
    BadBundleHeader(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::NotUtf8 => write!(f, "manifest is not UTF-8 text"),
            ManifestError::EmptyLine { line_no } => {
                write!(f, "manifest line {line_no}: empty line")
            }
            ManifestError::Missing(key) => {
                write!(f, "manifest is missing its `{key}` line")
            }
            ManifestError::Duplicate(what) => {
                write!(f, "manifest repeats at-most-once item `{what}`")
            }
            ManifestError::DuplicateBundleSeq(seq) => {
                write!(f, "manifest has two bundle lines for sequence {seq}")
            }
            ManifestError::UnsupportedFormat(v) => {
                write!(f, "unsupported vault format '{v}'")
            }
            ManifestError::BadLine { line_no, what } => {
                write!(f, "manifest line {line_no}: malformed {what} line")
            }
            ManifestError::RefWidthMismatch { line_no } => write!(
                f,
                "manifest line {line_no}: ref sha width disagrees with the declared objectformat"
            ),
            ManifestError::SeqfloorBelowBundle { seqfloor, seq } => write!(
                f,
                "manifest seqfloor {seqfloor} is below listed bundle sequence {seq}"
            ),
            ManifestError::NotRooted { lowest } => write!(
                f,
                "manifest bundle list is not rooted: lowest sequence {lowest} is not a -full bundle"
            ),
            ManifestError::BadBundleHeader(got) => {
                write!(
                    f,
                    "bundle header does not match the vault object format: {got:?}"
                )
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Line classification for pass 2 (§7.1: validation is two-pass — singletons
/// first, everything else judged with their values in hand).
enum Pass2Line<'a> {
    Bundle(Vec<&'a str>),
    Head(Vec<&'a str>),
    /// First token was 40- or 64-hex (both widths are reserved shapes, §7.2).
    Ref {
        toks: Vec<&'a str>,
        width: usize,
    },
}

/// Parse and validate a decrypted manifest per §7.
pub fn parse(bytes: &[u8]) -> Result<ParsedManifest, ManifestError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ManifestError::NotUtf8)?;

    // §7.1: LF line endings. A single trailing LF is the terminator of the
    // last line, not an empty line. (Documented choice: a manifest without a
    // final LF is accepted; nothing in §7 forbids it.)
    let text = text.strip_suffix('\n').unwrap_or(text);

    let mut format: Option<(usize, &str)> = None;
    let mut object_format: Option<ObjectFormat> = None;
    let mut vault_id: Option<String> = None;
    let mut counter: Option<u64> = None;
    let mut seqfloor: Option<u64> = None;
    let mut pass2: Vec<(usize, Pass2Line)> = Vec::new();
    let mut unknown_seen = false;

    // Pass 1: locate the singletons; queue everything else.
    for (idx, line) in text.split('\n').enumerate() {
        let line_no = idx + 1;
        if line.is_empty() {
            return Err(ManifestError::EmptyLine { line_no });
        }
        let toks: Vec<&str> = line.split(' ').collect();
        let first = toks[0];
        match first {
            "format" => {
                if format.is_some() {
                    return Err(ManifestError::Duplicate("format".into()));
                }
                // Arity first, value later: an unsupported version must
                // surface as UnsupportedFormat, not as a grammar error.
                if toks.len() != 2 || toks[1].is_empty() {
                    return Err(ManifestError::BadLine {
                        line_no,
                        what: "format",
                    });
                }
                format = Some((line_no, toks[1]));
            }
            "objectformat" => {
                if object_format.is_some() {
                    return Err(ManifestError::Duplicate("objectformat".into()));
                }
                let of = (toks.len() == 2)
                    .then(|| ObjectFormat::from_str_exact(toks[1]))
                    .flatten()
                    .ok_or(ManifestError::BadLine {
                        line_no,
                        what: "objectformat",
                    })?;
                object_format = Some(of);
            }
            "vault" => {
                if vault_id.is_some() {
                    return Err(ManifestError::Duplicate("vault".into()));
                }
                // §7.2: random identity, at least 128 bits, shown as hex.
                // Documented choices: lowercase hex only, even length (it
                // names a byte string).
                let ok = toks.len() == 2 && is_vault_id(toks[1]);
                if !ok {
                    return Err(ManifestError::BadLine {
                        line_no,
                        what: "vault",
                    });
                }
                vault_id = Some(toks[1].to_owned());
            }
            "counter" => {
                if counter.is_some() {
                    return Err(ManifestError::Duplicate("counter".into()));
                }
                // §7.2: canonical decimal (as seq/seqfloor), value >= 1,
                // 2^63-1 type-fixing bound.
                let v = (toks.len() == 2)
                    .then(|| names::parse_canonical(toks[1]))
                    .flatten()
                    .filter(|v| (1..=MAX_COUNTER).contains(v))
                    .ok_or(ManifestError::BadLine {
                        line_no,
                        what: "counter",
                    })?;
                counter = Some(v);
            }
            "seqfloor" => {
                if seqfloor.is_some() {
                    return Err(ManifestError::Duplicate("seqfloor".into()));
                }
                // §7.2: grammar and bounds as seq (§4.1); zero is invalid.
                let v = (toks.len() == 2)
                    .then(|| names::parse_canonical(toks[1]))
                    .flatten()
                    .filter(|v| (1..=names::MAX_SEQ).contains(v))
                    .ok_or(ManifestError::BadLine {
                        line_no,
                        what: "seqfloor",
                    })?;
                seqfloor = Some(v);
            }
            "bundle" => pass2.push((line_no, Pass2Line::Bundle(toks))),
            _ if first.starts_with('@') => pass2.push((line_no, Pass2Line::Head(toks))),
            _ if is_lower_hex(first) && (first.len() == 40 || first.len() == 64) => {
                let width = first.len();
                pass2.push((line_no, Pass2Line::Ref { toks, width }));
            }
            _ => {
                // §7.3: unrecognized first token — ignore the line, but the
                // writer must go read-only.
                unknown_seen = true;
            }
        }
    }

    let (_, format_str) = format.ok_or(ManifestError::Missing("format"))?;
    // §3/§7.2: version selection comes from this line alone; refuse
    // versions we do not support. "2" is the only spelling of the only
    // version this implementation speaks.
    if format_str != "2" {
        return Err(ManifestError::UnsupportedFormat(format_str.to_owned()));
    }
    let object_format = object_format.ok_or(ManifestError::Missing("objectformat"))?;
    let vault_id = vault_id.ok_or(ManifestError::Missing("vault"))?;
    let counter = counter.ok_or(ManifestError::Missing("counter"))?;
    let seqfloor = seqfloor.ok_or(ManifestError::Missing("seqfloor"))?;

    // Pass 2: judge the remaining lines with the singleton values in hand.
    let mut bundles: BTreeMap<u64, BundleRecord> = BTreeMap::new();
    let mut head: Option<String> = None;
    let mut refs: BTreeMap<String, String> = BTreeMap::new();

    for (line_no, line) in pass2 {
        match line {
            Pass2Line::Bundle(toks) => {
                let bad = ManifestError::BadLine {
                    line_no,
                    what: "bundle",
                };
                if toks.len() != 3 && toks.len() != 4 {
                    // §7.2: both arities (3 and 4 tokens) are frozen shapes;
                    // any other arity is INVALID.
                    return Err(bad);
                }
                // §7.2: <logical-name> — a canonical bundle name with no
                // chunk suffix.
                let name = match names::classify(toks[1]) {
                    NameClass::Canonical(n) if n.chunk().is_none() => n,
                    _ => return Err(bad),
                };
                if toks[2].len() != 64 || !is_lower_hex(toks[2]) {
                    return Err(bad);
                }
                let chunks = if toks.len() == 4 {
                    // §7.2: canonical decimal, value >= 2, at most 7 digits
                    // (count 1 would duplicate the whole-file spelling).
                    let c = Some(toks[3])
                        .filter(|t| t.len() <= names::MAX_CHUNK_DIGITS)
                        .and_then(names::parse_canonical)
                        .filter(|c| *c >= 2)
                        .ok_or(bad)?;
                    Some(c)
                } else {
                    None
                };
                let record = BundleRecord {
                    seq: name.seq(),
                    full: name.is_full(),
                    digest: toks[2].to_owned(),
                    chunks,
                };
                // §7.2: no two bundle lines share a sequence number,
                // regardless of -full labeling (also covers §7.3's duplicate
                // logical-name rule).
                if bundles.insert(name.seq(), record).is_some() {
                    return Err(ManifestError::DuplicateBundleSeq(name.seq()));
                }
            }
            Pass2Line::Head(toks) => {
                let bad = ManifestError::BadLine {
                    line_no,
                    what: "HEAD symref",
                };
                // §7.2: `@<refname> HEAD`.
                let name = toks[0].strip_prefix('@').unwrap_or(toks[0]);
                if toks.len() != 2 || toks[1] != "HEAD" || !plausible_refname(name) {
                    return Err(bad);
                }
                if head.is_some() {
                    return Err(ManifestError::Duplicate("@HEAD".into()));
                }
                head = Some(name.to_owned());
            }
            Pass2Line::Ref { toks, width } => {
                // §7.2: both widths are reserved shapes; the wrong one is
                // INVALID, never an unknown line.
                if width != object_format.ref_hex_width() {
                    return Err(ManifestError::RefWidthMismatch { line_no });
                }
                if toks.len() != 2 || !plausible_refname(toks[1]) {
                    return Err(ManifestError::BadLine {
                        line_no,
                        what: "ref",
                    });
                }
                let sha = toks[0].to_owned();
                if refs.insert(toks[1].to_owned(), sha).is_some() {
                    return Err(ManifestError::Duplicate(toks[1].to_owned()));
                }
            }
        }
    }

    // §7.2: seqfloor >= every sequence in the bundle list.
    if let Some((&seq, _)) = bundles.iter().next_back() {
        if seq > seqfloor {
            return Err(ManifestError::SeqfloorBelowBundle { seqfloor, seq });
        }
    }
    // §7.2 (reader assertion): a nonempty bundle list is rooted — the
    // lowest sequence number carries -full, or recovery has no start.
    if let Some((&lowest, record)) = bundles.iter().next() {
        if !record.full {
            return Err(ManifestError::NotRooted { lowest });
        }
    }

    Ok(ParsedManifest {
        manifest: Manifest {
            format: 2,
            object_format,
            vault_id,
            counter,
            seqfloor,
            bundles,
            head,
            refs,
        },
        writer_must_be_read_only: unknown_seen,
    })
}

impl Manifest {
    /// Serialize per §7.1 (writers SHOULD sort refs by name and bundles by
    /// sequence). The output is validated by re-parsing, so a writer can
    /// never emit a manifest its own reader would refuse.
    pub fn to_text(&self) -> Result<String, ManifestError> {
        let mut out = String::new();
        out.push_str(&format!("format {}\n", self.format));
        out.push_str(&format!("objectformat {}\n", self.object_format.as_str()));
        out.push_str(&format!("vault {}\n", self.vault_id));
        out.push_str(&format!("counter {}\n", self.counter));
        out.push_str(&format!("seqfloor {}\n", self.seqfloor));
        for record in self.bundles.values() {
            let name = record.logical_name().map_err(|_| ManifestError::BadLine {
                line_no: 0,
                what: "bundle",
            })?;
            match record.chunks {
                None => out.push_str(&format!("bundle {name} {}\n", record.digest)),
                Some(c) => out.push_str(&format!("bundle {name} {} {c}\n", record.digest)),
            }
        }
        if let Some(head) = &self.head {
            out.push_str(&format!("@{head} HEAD\n"));
        }
        for (refname, sha) in &self.refs {
            out.push_str(&format!("{sha} {refname}\n"));
        }

        // Self-check: emit nothing the reader would reject.
        let reparsed = parse(out.as_bytes())?;
        if &reparsed.manifest != self {
            // Field content that does not survive a round trip (should be
            // unreachable given the per-line checks above).
            return Err(ManifestError::BadLine {
                line_no: 0,
                what: "manifest",
            });
        }
        Ok(out)
    }

    /// §6.7: the expected file set, total and exact.
    pub fn expected_files(&self) -> Result<BTreeSet<String>, names::NameError> {
        let mut set = BTreeSet::new();
        for record in self.bundles.values() {
            let name = record.logical_name()?;
            match record.chunks {
                None => {
                    set.insert(name.to_string());
                }
                Some(count) => {
                    for i in 0..count {
                        set.insert(name.part(i)?.to_string());
                    }
                }
            }
        }
        Ok(set)
    }

    /// §6.4/§6.7: compare the vault tree's entry names against the expected
    /// file set. Grammar-matching (canonical) entries must equal the set
    /// exactly; bundle-shaped-non-canonical and non-grammar entries are
    /// outside the comparison (§3).
    pub fn check_tree_files<'a, I>(&self, tree_names: I) -> Result<(), TreeMismatch>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let expected = self
            .expected_files()
            .map_err(|e| TreeMismatch::BadManifestName(e.to_string()))?;
        let mut present = BTreeSet::new();
        for name in tree_names {
            if let NameClass::Canonical(_) = names::classify(name) {
                present.insert(name.to_owned());
            }
        }
        if let Some(extra) = present.difference(&expected).next() {
            return Err(TreeMismatch::UnexpectedFile(extra.clone()));
        }
        if let Some(missing) = expected.difference(&present).next() {
            return Err(TreeMismatch::MissingFile(missing.clone()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeMismatch {
    /// §6.4: extra grammar-matching files (e.g. resurrected pre-compaction
    /// ciphertexts) are a hard error.
    UnexpectedFile(String),
    /// §6.4: missing files are a hard error.
    MissingFile(String),
    BadManifestName(String),
}

impl fmt::Display for TreeMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeMismatch::UnexpectedFile(n) => {
                write!(
                    f,
                    "vault tree has a bundle file the manifest does not list: {n}"
                )
            }
            TreeMismatch::MissingFile(n) => {
                write!(
                    f,
                    "vault tree is missing a manifest-listed bundle file: {n}"
                )
            }
            TreeMismatch::BadManifestName(e) => write!(f, "manifest names an impossible file: {e}"),
        }
    }
}

impl std::error::Error for TreeMismatch {}

/// §4.3: verify a decrypted bundle's header against the vault object format.
/// sha1 vaults require `# v2 git bundle`; sha256 vaults require
/// `# v3 git bundle` plus the `@object-format=sha256` capability.
pub fn verify_bundle_header(plaintext: &[u8], of: ObjectFormat) -> Result<(), ManifestError> {
    let mut lines = plaintext.split(|b| *b == b'\n');
    let first = lines.next().unwrap_or_default();
    if first != of.bundle_header_line().as_bytes() {
        return Err(ManifestError::BadBundleHeader(
            String::from_utf8_lossy(first).into_owned(),
        ));
    }
    if of == ObjectFormat::Sha256 {
        // v3 capability lines follow the header line, each starting with '@'.
        let has_capability = lines
            .take_while(|l| l.first() == Some(&b'@'))
            .any(|l| l == b"@object-format=sha256");
        if !has_capability {
            return Err(ManifestError::BadBundleHeader(
                "v3 bundle without @object-format=sha256".into(),
            ));
        }
    }
    Ok(())
}

/// §7.2's `vault` grammar: lowercase hex, an even number of digits, at
/// least 32 of them. Shared with the pin store, which keys directories by
/// vault identity and must not accept anything else as a path component.
pub(crate) fn is_vault_id(s: &str) -> bool {
    s.len() >= 32 && s.len().is_multiple_of(2) && is_lower_hex(s)
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Documented choice: §7 gives no refname grammar. We require a nonempty
/// token of printable non-space bytes (git's own rules are stricter; the
/// manifest is authenticated, so this only guards against writer bugs).
fn plausible_refname(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b > 0x20 && b != 0x7f)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_A: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    const SHA1_B: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const D64_A: &str = "9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c";
    const D64_B: &str = "11d411d411d411d411d411d411d411d411d411d411d411d411d411d411d411d4";
    const VAULT: &str = "3f9a6c0e6d1b4b0d9a4f2e7c8b5a1d02";
    const SHA256_REF: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn base_text() -> String {
        format!(
            "format 2\n\
             objectformat sha1\n\
             vault {VAULT}\n\
             counter 42\n\
             seqfloor 8\n\
             bundle 7-full.bundle.age {D64_A} 87\n\
             bundle 8.bundle.age {D64_B}\n\
             @refs/heads/main HEAD\n\
             {SHA1_A} refs/heads/main\n"
        )
    }

    fn parse_ok(text: &str) -> ParsedManifest {
        match parse(text.as_bytes()) {
            Ok(p) => p,
            Err(e) => panic!("expected valid manifest, got {e}\n---\n{text}"),
        }
    }

    fn parse_err(text: &str) -> ManifestError {
        match parse(text.as_bytes()) {
            Ok(_) => panic!("expected invalid manifest, parsed OK:\n---\n{text}"),
            Err(e) => e,
        }
    }

    #[test]
    fn parses_the_spec_example_shape() {
        let p = parse_ok(&base_text());
        let m = &p.manifest;
        assert_eq!(m.format, 2);
        assert_eq!(m.object_format, ObjectFormat::Sha1);
        assert_eq!(m.vault_id, VAULT);
        assert_eq!(m.counter, 42);
        assert_eq!(m.seqfloor, 8);
        assert_eq!(m.bundles.len(), 2);
        assert_eq!(m.bundles[&7].chunks, Some(87));
        assert!(m.bundles[&7].full);
        assert_eq!(m.bundles[&8].chunks, None);
        assert_eq!(m.head.as_deref(), Some("refs/heads/main"));
        assert_eq!(m.refs["refs/heads/main"], SHA1_A);
        assert!(!p.writer_must_be_read_only);
    }

    #[test]
    fn round_trips_serialize_then_parse() {
        let p = parse_ok(&base_text());
        let text = p.manifest.to_text().expect("serializable");
        let again = parse_ok(&text);
        assert_eq!(again.manifest, p.manifest);
        // The base text is already in writer order, so bytes round-trip too.
        assert_eq!(text, base_text());
    }

    #[test]
    fn line_order_is_not_significant() {
        // §7.1: two-pass validation over the whole text.
        let shuffled = format!(
            "{SHA1_A} refs/heads/main\n\
             bundle 8.bundle.age {D64_B}\n\
             seqfloor 8\n\
             @refs/heads/main HEAD\n\
             counter 42\n\
             bundle 7-full.bundle.age {D64_A} 87\n\
             vault {VAULT}\n\
             objectformat sha1\n\
             format 2\n"
        );
        assert_eq!(
            parse_ok(&shuffled).manifest,
            parse_ok(&base_text()).manifest
        );
    }

    #[test]
    fn unknown_first_token_is_tolerated_but_flags_read_only() {
        // §7.3.
        let text = base_text() + "chunkweights 7 heavy\n";
        let p = parse_ok(&text);
        assert!(p.writer_must_be_read_only);
        assert_eq!(p.manifest, parse_ok(&base_text()).manifest);
    }

    #[test]
    fn missing_singletons_each_fail() {
        for key in ["format", "objectformat", "vault", "counter", "seqfloor"] {
            let text: String = base_text()
                .lines()
                .filter(|l| !l.starts_with(key))
                .map(|l| format!("{l}\n"))
                .collect();
            assert_eq!(parse_err(&text), ManifestError::Missing(key), "{key}");
        }
    }

    #[test]
    fn duplicate_singletons_each_fail() {
        for line in [
            "format 2",
            "objectformat sha1",
            &format!("vault {VAULT}"),
            "counter 42",
            "seqfloor 8",
        ] {
            let text = base_text() + line + "\n";
            let key = line.split(' ').next().expect("token");
            assert_eq!(
                parse_err(&text),
                ManifestError::Duplicate(key.into()),
                "{line}"
            );
        }
    }

    #[test]
    fn duplicate_head_symref_fails() {
        let text = base_text() + "@refs/heads/dev HEAD\n";
        assert_eq!(parse_err(&text), ManifestError::Duplicate("@HEAD".into()));
    }

    #[test]
    fn duplicate_refname_fails() {
        let text = base_text() + &format!("{SHA1_B} refs/heads/main\n");
        assert_eq!(
            parse_err(&text),
            ManifestError::Duplicate("refs/heads/main".into())
        );
    }

    #[test]
    fn two_bundle_lines_for_one_seq_fail_regardless_of_full() {
        // §7.2: with or without -full.
        let text = base_text() + &format!("bundle 8-full.bundle.age {D64_A}\n");
        assert_eq!(parse_err(&text), ManifestError::DuplicateBundleSeq(8));
    }

    #[test]
    fn unsupported_versions_are_refused() {
        // §3: readers MUST refuse versions they do not support; Appendix A's
        // old-tool symptom expects this exact family.
        for v in ["1", "3", "02", "2x"] {
            let text = base_text().replace("format 2\n", &format!("format {v}\n"));
            assert_eq!(
                parse_err(&text),
                ManifestError::UnsupportedFormat(v.into()),
                "{v}"
            );
        }
    }

    #[test]
    fn recognized_tokens_with_bad_grammar_fail_not_ignore() {
        // §7.3: arity errors on recognized tokens fail parsing outright.
        let cases: Vec<(String, &str)> = vec![
            ("format\n".into(), "format"),
            ("counter 1 2\n".into(), "counter"),
            ("counter 0\n".into(), "counter"),
            ("counter 042\n".into(), "counter"),
            ("counter 9223372036854775808\n".into(), "counter"),
            ("counter x\n".into(), "counter"),
            ("seqfloor 0\n".into(), "seqfloor"),
            ("seqfloor 08\n".into(), "seqfloor"),
            ("objectformat sha512\n".into(), "objectformat"),
            ("objectformat sha1 x\n".into(), "objectformat"),
            ("vault zzzz\n".into(), "vault"),
            ("vault abcd\n".into(), "vault"), // < 128 bits
            (format!("vault {}\n", VAULT.to_uppercase()), "vault"),
            (format!("bundle 9.bundle.age {D64_A} 3 4\n"), "bundle"),
            ("bundle 9.bundle.age\n".into(), "bundle"),
            (format!("bundle 09.bundle.age {D64_A}\n"), "bundle"),
            (format!("bundle 9.bundle.age.0 {D64_A}\n"), "bundle"),
            (format!("bundle 9.bundle.age {}\n", &D64_A[..40]), "bundle"),
            (
                format!("bundle 9.bundle.age {}\n", D64_A.to_uppercase()),
                "bundle",
            ),
            (format!("bundle 9.bundle.age {D64_A} 1\n"), "bundle"),
            (format!("bundle 9.bundle.age {D64_A} 0\n"), "bundle"),
            (format!("bundle 9.bundle.age {D64_A} 02\n"), "bundle"),
            (format!("bundle 9.bundle.age {D64_A} 12345678\n"), "bundle"),
            ("@refs/heads/x FOO\n".into(), "HEAD symref"),
            ("@ HEAD\n".into(), "HEAD symref"),
            ("@refs/heads/x HEAD extra\n".into(), "HEAD symref"),
            (format!("{SHA1_B} refs/x extra\n"), "ref"),
            (format!("{SHA1_B}\n"), "ref"),
        ];
        for (line, what) in cases {
            // Replace a conflicting base line where needed.
            let base = match what {
                "format" => base_text().replace("format 2\n", ""),
                "counter" => base_text().replace("counter 42\n", ""),
                "seqfloor" => base_text().replace("seqfloor 8\n", ""),
                "objectformat" => base_text().replace("objectformat sha1\n", ""),
                "vault" => base_text().replace(&format!("vault {VAULT}\n"), ""),
                "HEAD symref" => base_text().replace("@refs/heads/main HEAD\n", ""),
                _ => base_text(),
            };
            let text = base + &line;
            match parse_err(&text) {
                ManifestError::BadLine { what: got, .. } => assert_eq!(got, what, "{line:?}"),
                other => panic!("{line:?}: expected BadLine({what}), got {other:?}"),
            }
        }
    }

    #[test]
    fn wrong_ref_width_is_invalid_not_unknown() {
        // §7.2: both widths are reserved shapes in every manifest.
        let text = base_text() + &format!("{SHA256_REF} refs/heads/wide\n");
        assert!(matches!(
            parse_err(&text),
            ManifestError::RefWidthMismatch { .. }
        ));

        // And the mirror image in a sha256 vault.
        let text = format!(
            "format 2\n\
             objectformat sha256\n\
             vault {VAULT}\n\
             counter 1\n\
             seqfloor 1\n\
             bundle 1-full.bundle.age {D64_A}\n\
             {SHA1_A} refs/heads/main\n"
        );
        assert!(matches!(
            parse_err(&text),
            ManifestError::RefWidthMismatch { .. }
        ));
    }

    #[test]
    fn sha256_manifest_takes_64_hex_refs() {
        let text = format!(
            "format 2\n\
             objectformat sha256\n\
             vault {VAULT}\n\
             counter 1\n\
             seqfloor 1\n\
             bundle 1-full.bundle.age {D64_A}\n\
             {SHA256_REF} refs/heads/main\n"
        );
        let p = parse_ok(&text);
        assert_eq!(p.manifest.refs["refs/heads/main"], SHA256_REF);
    }

    #[test]
    fn uppercase_hex_first_token_is_an_unknown_line() {
        // Documented choice: §7.2 reserves "40- or 64-hex object id" tokens;
        // git object ids are lowercase, so an uppercase token is not a
        // recognized shape and takes the §7.3 ignore-plus-read-only path.
        let text = base_text() + &format!("{} refs/heads/up\n", SHA1_B.to_uppercase());
        let p = parse_ok(&text);
        assert!(p.writer_must_be_read_only);
        assert!(!p.manifest.refs.contains_key("refs/heads/up"));
    }

    #[test]
    fn unrooted_bundle_list_fails() {
        // §7.2 reader assertion: lowest seq must be -full.
        let text = base_text().replace(
            &format!("bundle 7-full.bundle.age {D64_A} 87\n"),
            &format!("bundle 7.bundle.age {D64_A} 87\n"),
        );
        assert_eq!(parse_err(&text), ManifestError::NotRooted { lowest: 7 });
    }

    #[test]
    fn seqfloor_must_cover_bundle_seqs() {
        // §7.2: seqfloor >= every sequence in the bundle list.
        let text = base_text() + &format!("bundle 9.bundle.age {D64_B}\n");
        assert_eq!(
            parse_err(&text),
            ManifestError::SeqfloorBelowBundle {
                seqfloor: 8,
                seq: 9
            }
        );
    }

    #[test]
    fn empty_lines_are_invalid() {
        let text = base_text() + "\n";
        assert_eq!(parse_err(&text), ManifestError::EmptyLine { line_no: 10 });
        let text = "format 2\n\nobjectformat sha1\n";
        assert_eq!(parse_err(text), ManifestError::EmptyLine { line_no: 2 });
    }

    #[test]
    fn non_utf8_is_refused() {
        assert_eq!(parse(&[0xff, 0xfe, b'\n']), Err(ManifestError::NotUtf8));
    }

    #[test]
    fn manifest_only_generation_is_valid() {
        // §9 zero-ref compaction: empty bundle list, empty refs.
        let text = format!(
            "format 2\n\
             objectformat sha1\n\
             vault {VAULT}\n\
             counter 5\n\
             seqfloor 3\n"
        );
        let p = parse_ok(&text);
        assert!(p.manifest.bundles.is_empty());
        assert!(p.manifest.refs.is_empty());
        assert_eq!(p.manifest.expected_files().expect("derivable").len(), 0);
    }

    #[test]
    fn expected_file_set_derivation() {
        // §6.7: COUNT absent -> the bare name; COUNT present -> .0 .. .(n-1).
        let p = parse_ok(&base_text());
        let expected = p.manifest.expected_files().expect("derivable");
        assert_eq!(expected.len(), 87 + 1);
        assert!(expected.contains("7-full.bundle.age.0"));
        assert!(expected.contains("7-full.bundle.age.86"));
        assert!(!expected.contains("7-full.bundle.age"));
        assert!(!expected.contains("7-full.bundle.age.87"));
        assert!(expected.contains("8.bundle.age"));
    }

    #[test]
    fn tree_check_accepts_the_exact_set_and_ignores_carved_out_names() {
        let p = parse_ok(&base_text());
        let mut tree: Vec<String> = p
            .manifest
            .expected_files()
            .expect("derivable")
            .into_iter()
            .collect();
        // §3: non-grammar and bundle-shaped-non-canonical entries are outside
        // the comparison.
        tree.push("sealed-format".into());
        tree.push("sealed-manifest.age".into());
        tree.push("refs.age".into());
        tree.push("future-extension.dat".into());
        tree.push("08.bundle.age".into());
        p.manifest
            .check_tree_files(tree.iter().map(String::as_str))
            .expect("exact set must pass");
    }

    #[test]
    fn tree_check_flags_extra_and_missing_files() {
        // §6.4: both are hard errors.
        let p = parse_ok(&base_text());
        let expected: Vec<String> = p
            .manifest
            .expected_files()
            .expect("derivable")
            .into_iter()
            .collect();

        let mut extra = expected.clone();
        extra.push("9.bundle.age".into()); // resurrected/planted canonical file
        assert_eq!(
            p.manifest
                .check_tree_files(extra.iter().map(String::as_str)),
            Err(TreeMismatch::UnexpectedFile("9.bundle.age".into()))
        );

        let missing: Vec<String> = expected
            .iter()
            .filter(|n| *n != "8.bundle.age")
            .cloned()
            .collect();
        assert_eq!(
            p.manifest
                .check_tree_files(missing.iter().map(String::as_str)),
            Err(TreeMismatch::MissingFile("8.bundle.age".into()))
        );
    }

    #[test]
    fn tree_check_rejects_manifest_says_chunked_tree_has_whole() {
        // §6.7's single-rule collapse: bare-name-plus-parts, extra parts,
        // and whole-vs-chunked disagreements are all set inequality.
        let p = parse_ok(&base_text());
        let mut tree: Vec<String> = p
            .manifest
            .expected_files()
            .expect("derivable")
            .into_iter()
            .collect();
        tree.push("7-full.bundle.age".into()); // bare name next to its parts
        assert_eq!(
            p.manifest.check_tree_files(tree.iter().map(String::as_str)),
            Err(TreeMismatch::UnexpectedFile("7-full.bundle.age".into()))
        );
    }

    #[test]
    fn serializer_refuses_nonsense() {
        let p = parse_ok(&base_text());
        let mut m = p.manifest;
        m.bundles.insert(
            9,
            BundleRecord {
                seq: 9,
                full: false,
                digest: "nothex".into(),
                chunks: None,
            },
        );
        assert!(m.to_text().is_err());
    }

    #[test]
    fn bundle_header_verification_both_formats() {
        // §4.3, strictly both ways.
        verify_bundle_header(b"# v2 git bundle\nrest", ObjectFormat::Sha1).expect("sha1 takes v2");
        verify_bundle_header(
            b"# v3 git bundle\n@object-format=sha256\nrest",
            ObjectFormat::Sha256,
        )
        .expect("sha256 takes v3 + capability");

        assert!(verify_bundle_header(
            b"# v3 git bundle\n@object-format=sha256\n",
            ObjectFormat::Sha1
        )
        .is_err());
        assert!(verify_bundle_header(b"# v2 git bundle\n", ObjectFormat::Sha256).is_err());
        assert!(
            verify_bundle_header(b"# v3 git bundle\nno-capability", ObjectFormat::Sha256).is_err()
        );
        assert!(verify_bundle_header(b"garbage", ObjectFormat::Sha1).is_err());
    }
}
