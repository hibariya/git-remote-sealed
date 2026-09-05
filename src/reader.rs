//! The §6 reader algorithm (fetch / restore), end to end: hint check,
//! manifest decrypt+validate, the §7.4 pin battery, the §6.7 tree check,
//! chunk reassembly with digest-before-decrypt, bundle-header check, apply
//! via `git bundle unbundle`, sequence-memory-driven skipping with §6.5's
//! re-apply rule, and the §6.6 exact-refs report.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

use age::x25519::Identity;

use crate::manifest::{self, Manifest, ManifestError, ObjectFormat, TreeMismatch};
use crate::names::{self, NameClass};
use crate::pinstore::{self, PinError};
use crate::vaultrepo::{self, GitError, VaultRepo, VaultTree};
use crate::{sha256_hex, HashingWriter, FORMAT_VERSION};

/// §6.6: what the reader reports — exactly the manifest's refs and HEAD
/// symref, never the bundles' embedded ref claims (§4.3: those are
/// informative only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOutcome {
    /// refname -> sha. Empty for an empty (uninitialized) vault.
    pub refs: BTreeMap<String, String>,
    /// The manifest's HEAD symref target, if any.
    pub head: Option<String>,
    /// `None` only for an empty vault (no manifest to declare it).
    pub object_format: Option<ObjectFormat>,
    /// §7.3: the manifest contained a line type this implementation does not
    /// know. Surfaced for the (future) writer, which MUST then refuse to
    /// write; the read itself is unaffected.
    pub writer_must_be_read_only: bool,
}

#[derive(Debug)]
pub enum ReadError {
    Git(GitError),
    Crypt(crate::crypt::CryptError),
    Manifest(ManifestError),
    Pin(PinError),
    Tree(TreeMismatch),
    /// §3: `sealed-format` belongs in every vault tree; the file is
    /// host-controlled, so its absence is indistinguishable from deletion —
    /// fail loudly. (Documented choice: the spec never states the missing
    /// case; §6.2 just says "check sealed-format".)
    MissingSealedFormat,
    /// §3: the hint MUST be the ASCII decimal version followed by a single
    /// LF. (Documented choice: the canonical spelling only — `02\n` is
    /// malformed, matching §7.1's no-leading-zeros rule for the manifest.)
    MalformedHint(String),
    /// §3: refuse versions we do not support — the hint MAY fast-fail the
    /// operation. It never *selects* semantics: had the hint lied low, the
    /// manifest's own `format` line (the sole authority) would still refuse,
    /// and hint/manifest agreement is implied by both being checked against
    /// the one supported version.
    UnsupportedHint(String),
    /// §3: the tree holds version 1's manifest and no version 2 one. Not
    /// an empty vault — refusing here is what stops a v2 tool from
    /// initializing a fresh vault on top of a v1 one.
    LegacyVault,
    /// §3: a tree with bundle files but no `sealed-manifest.age` is invalid (one
    /// deleted file must not read as an empty vault and seed ref loss).
    BundlesWithoutManifest,
    /// §6.4: a reassembled ciphertext does not match its manifest digest.
    DigestMismatch {
        name: String,
    },
    /// The caller's repository uses a different object format than the
    /// vault. (Documented choice: §6 leaves this to `unbundle`'s own
    /// failure; checking first gives a diagnosable error instead of a git
    /// index-pack complaint.)
    ObjectFormatMismatch {
        vault: ObjectFormat,
        local: String,
    },
    /// §6.6: a manifest-listed sha is still absent after (re-)application —
    /// a corrupt or incomplete vault.
    MissingObject {
        refname: String,
        sha: String,
    },
    Io(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Git(e) => write!(f, "{e}"),
            ReadError::Crypt(e) => write!(f, "{e}"),
            ReadError::Manifest(e) => write!(f, "{e}"),
            ReadError::Pin(e) => write!(f, "{e}"),
            ReadError::Tree(e) => write!(f, "{e}"),
            ReadError::MissingSealedFormat => {
                write!(f, "the vault tree has no sealed-format file")
            }
            ReadError::MalformedHint(got) => {
                write!(f, "malformed sealed-format content {got:?}")
            }
            ReadError::UnsupportedHint(v) => {
                write!(f, "unsupported vault format '{v}' (sealed-format hint)")
            }
            ReadError::LegacyVault => write!(
                f,
                "this is a version 1 sealed vault (it stores its manifest as {}); this tool implements version {}. Migrate it with a version 2 implementation first",
                crate::LEGACY_MANIFEST_FILE,
                crate::FORMAT_VERSION
            ),
            ReadError::BundlesWithoutManifest => write!(
                f,
                "the vault tree has bundle files but no sealed-manifest.age: refusing to read it as empty"
            ),
            ReadError::DigestMismatch { name } => write!(
                f,
                "bundle {name}: reassembled ciphertext does not match its manifest digest"
            ),
            ReadError::ObjectFormatMismatch { vault, local } => write!(
                f,
                "the vault stores a {} repository but the local repository is {local}",
                vault.as_str()
            ),
            ReadError::MissingObject { refname, sha } => write!(
                f,
                "object {sha} for {refname} is still missing after applying every bundle: corrupt or incomplete vault"
            ),
            ReadError::Io(e) => write!(f, "reader I/O error: {e}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<GitError> for ReadError {
    fn from(e: GitError) -> Self {
        ReadError::Git(e)
    }
}
impl From<crate::crypt::CryptError> for ReadError {
    fn from(e: crate::crypt::CryptError) -> Self {
        ReadError::Crypt(e)
    }
}
impl From<ManifestError> for ReadError {
    fn from(e: ManifestError) -> Self {
        ReadError::Manifest(e)
    }
}
impl From<PinError> for ReadError {
    fn from(e: PinError) -> Self {
        ReadError::Pin(e)
    }
}
impl From<TreeMismatch> for ReadError {
    fn from(e: TreeMismatch) -> Self {
        ReadError::Tree(e)
    }
}

/// Everything `inspect` established about a non-empty vault, handed to
/// `apply`: the committed tree, the validated manifest, the pin before and
/// after the §7.4 battery.
pub struct Prepared {
    tree: VaultTree,
    manifest: Manifest,
    /// SHA-256 of the `sealed-manifest.age` ciphertext as fetched (the pin's twin
    /// witness, §7.4).
    manifest_cipher_digest: String,
    writer_must_be_read_only: bool,
    prev_pin: Option<pinstore::Pin>,
    next_pin: pinstore::Pin,
}

impl Prepared {
    /// The committed vault tree this read validated (§6.1).
    pub fn tree(&self) -> &VaultTree {
        &self.tree
    }

    /// The validated manifest (§7).
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn manifest_cipher_digest(&self) -> &str {
        &self.manifest_cipher_digest
    }

    /// §7.3: the manifest carried a line type this implementation does not
    /// know; a writer MUST refuse to write.
    pub fn writer_must_be_read_only(&self) -> bool {
        self.writer_must_be_read_only
    }

    /// The pin the §7.4 battery ran against (`None` = first contact). This
    /// is the strongest pin the repository holds for the vault, sibling
    /// state directories included.
    pub fn prev_pin(&self) -> Option<&pinstore::Pin> {
        self.prev_pin.as_ref()
    }

    /// The pin the battery produced. Its sequence memory includes every
    /// bundle of the manifest — persist it only after those were applied
    /// (§7.4: "accepted AND applied"); a listing-only session must not.
    pub fn next_pin(&self) -> &pinstore::Pin {
        &self.next_pin
    }
}

/// The result of `inspect`: an empty (uninitialized) vault, or a validated
/// one ready to apply.
pub enum Inspection {
    Empty,
    /// Boxed: `Prepared` carries the whole tree and manifest.
    Vault(Box<Prepared>),
}

impl Inspection {
    /// §6.6: what to report as the remote's refs.
    pub fn outcome(&self) -> ReadOutcome {
        match self {
            Inspection::Empty => empty_outcome(),
            Inspection::Vault(p) => ReadOutcome {
                refs: p.manifest.refs.clone(),
                head: p.manifest.head.clone(),
                object_format: Some(p.manifest.object_format),
                writer_must_be_read_only: p.writer_must_be_read_only,
            },
        }
    }
}

/// §6 steps 1-4: fetch the vault, check the hint, decrypt and validate the
/// manifest with the §7.4 battery, and check the tree against the expected
/// file set. Touches no objects in the caller's repository — the remote
/// helper answers `list` from this alone.
pub fn inspect(vault: &VaultRepo, identities: &[Identity]) -> Result<Inspection, ReadError> {
    // §6.1: current committed tree (the mirror was reset, not merged).
    let tree = vault.fetch()?;
    let prev_pin = pinstore::load(&vault.pin_dir())?;

    let Some(tree) = tree else {
        // §7.4: a pinned reader MUST refuse an empty vault (no manifest) —
        // otherwise a host could reset the pin via re-initialization.
        pinstore::check_empty_vault(prev_pin.as_ref())?;
        return Ok(Inspection::Empty);
    };

    let has_bundles = tree
        .files
        .keys()
        .any(|n| matches!(names::classify(n), NameClass::Canonical(_)));

    let Some(manifest_oid) = tree.files.get(crate::MANIFEST_FILE) else {
        if has_bundles {
            // §3/§6.3: bundles present with no manifest is a hard error.
            return Err(ReadError::BundlesWithoutManifest);
        }
        // §3: version 1 kept its manifest under a different name, and its
        // bundle names are non-canonical here — so without this check a v1
        // vault would read as EMPTY to this tool, and a fresh clone would
        // then happily initialize a new vault over it. The `sealed-format`
        // hint does not save us: it is checked below, after this point.
        if tree.files.contains_key(crate::LEGACY_MANIFEST_FILE) {
            return Err(ReadError::LegacyVault);
        }
        // A committed tree with no manifest and no bundles is an empty
        // vault for §7.4's purposes ("no manifest at all"), whatever else
        // the tree holds.
        pinstore::check_empty_vault(prev_pin.as_ref())?;
        return Ok(Inspection::Empty);
    };

    // §6.2: check `sealed-format` (§3). It is a hint — host-controlled and
    // unauthenticated — so this MAY fast-fail but never selects semantics.
    check_hint(vault, &tree)?;

    // §6.3: decrypt and validate the manifest (§7)...
    let manifest_cipher = vault.read_blob(manifest_oid)?;
    let manifest_cipher_digest = sha256_hex(&manifest_cipher);
    let manifest_plain = crate::crypt::decrypt(identities, &manifest_cipher)?;
    let parsed = manifest::parse(&manifest_plain)?;
    let manifest = parsed.manifest;
    // §3: "readers MUST fail if the two disagree" — implied here: the hint
    // passed check_hint (== FORMAT_VERSION) and manifest::parse accepts
    // `format 2` only, so hint == manifest format on every success path.

    // §7.4: pins are per (repository, VAULT). First contact through THIS
    // URL spelling still inherits the strongest pin the repository holds
    // for the vault identity the manifest declares — a respelled remote
    // must not reset rollback protection.
    let prev_pin = match prev_pin {
        Some(pin) => Some(pin),
        None => pinstore::find_by_vault_id(&vault.sealed_root(), &manifest.vault_id)?,
    };

    // ...including the §7.4 trust-on-first-use battery.
    let next_pin =
        pinstore::validate_and_advance(prev_pin.as_ref(), &manifest, &manifest_cipher_digest)?;

    // §6.4/§6.7: the grammar-matching tree files must equal the expected
    // file set exactly.
    manifest.check_tree_files(tree.files.keys().map(String::as_str))?;

    Ok(Inspection::Vault(Box::new(Prepared {
        tree,
        manifest,
        manifest_cipher_digest,
        writer_must_be_read_only: parsed.writer_must_be_read_only,
        prev_pin,
        next_pin,
    })))
}

/// §6 steps 5-6: apply every listed bundle not yet applied into the
/// repository at `dest_git_dir` (objects only — never refs, §6.5), verify
/// every manifest sha exists (re-applying per §6.5 if not), then persist
/// the advanced pin.
pub fn apply(
    vault: &VaultRepo,
    dest_git_dir: &Path,
    identities: &[Identity],
    prepared: &Prepared,
) -> Result<(), ReadError> {
    let m = &prepared.manifest;
    let tree = &prepared.tree;

    // Documented choice (see ReadError::ObjectFormatMismatch): fail with a
    // real diagnosis before unbundle would.
    let local_format = vaultrepo::repo_object_format(dest_git_dir)?;
    if local_format != m.object_format.as_str() {
        return Err(ReadError::ObjectFormatMismatch {
            vault: m.object_format,
            local: local_format,
        });
    }

    // §6.5: apply listed bundles in ascending numeric sequence order.
    // The previous pin's sequence memory doubles as the applied-bundle
    // record (§7.4): a remembered (seq -> digest) binding was verified and
    // applied by this device before, and §7.4 makes re-binding a hard
    // error, so skipping it is sound (§6.4).
    let scratch = vault.scratch_dir()?;
    let mut skipped: Vec<u64> = Vec::new();
    for (seq, record) in &m.bundles {
        let remembered = prepared
            .prev_pin
            .as_ref()
            .and_then(|p| p.sequence_memory.get(seq))
            .is_some_and(|d| *d == record.digest);
        if remembered {
            skipped.push(*seq);
        } else {
            apply_one(vault, tree, m, *seq, &scratch, dest_git_dir, identities)?;
        }
    }

    // §6.6: every listed sha MUST now exist locally...
    if let Some((refname, sha)) = first_missing_object(dest_git_dir, m)? {
        // §6.5: a required object can be absent despite the applied record —
        // a local `git gc` prunes unbundled objects no ref reached — so
        // re-apply the skipped bundles rather than wedging. Application is
        // idempotent.
        if skipped.is_empty() {
            return Err(ReadError::MissingObject { refname, sha });
        }
        for seq in &skipped {
            apply_one(vault, tree, m, *seq, &scratch, dest_git_dir, identities)?;
        }
        if let Some((refname, sha)) = first_missing_object(dest_git_dir, m)? {
            // §6.6: ...and a miss after re-application is a loud error.
            return Err(ReadError::MissingObject { refname, sha });
        }
    }

    // Persist the advanced pin only now: every §6 step succeeded, so the
    // sequence memory's "verified and applied" meaning holds. Persisting
    // earlier (e.g. after `inspect`) would let a never-applied bundle be
    // skipped forever — its objects are not ref tips, so §6.5's re-apply
    // trigger would never fire. A crash before this line simply re-runs
    // the full battery next time (idempotent).
    pinstore::save(&vault.pin_dir(), &prepared.next_pin)?;
    Ok(())
}

/// Convenience: the whole §6 pipeline in one call (inspect, apply, report).
pub fn fetch_and_report(
    vault: &VaultRepo,
    dest_git_dir: &Path,
    identities: &[Identity],
) -> Result<ReadOutcome, ReadError> {
    let inspection = inspect(vault, identities)?;
    if let Inspection::Vault(prepared) = &inspection {
        apply(vault, dest_git_dir, identities, prepared)?;
    }
    Ok(inspection.outcome())
}

fn empty_outcome() -> ReadOutcome {
    ReadOutcome {
        refs: BTreeMap::new(),
        head: None,
        object_format: None,
        writer_must_be_read_only: false,
    }
}

/// §6.2/§3: `sealed-format` must exist, spell a canonical ASCII decimal
/// version plus a single LF, and be a version we support.
fn check_hint(vault: &VaultRepo, tree: &VaultTree) -> Result<(), ReadError> {
    let oid = tree
        .files
        .get(crate::FORMAT_HINT_FILE)
        .ok_or(ReadError::MissingSealedFormat)?;
    let bytes = vault.read_blob(oid)?;
    let version = parse_hint(&bytes)
        .ok_or_else(|| ReadError::MalformedHint(String::from_utf8_lossy(&bytes).into_owned()))?;
    if version != FORMAT_VERSION.to_string() {
        return Err(ReadError::UnsupportedHint(version));
    }
    Ok(())
}

fn parse_hint(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let version = text.strip_suffix('\n')?;
    // §3: "the ASCII decimal version number followed by a single LF".
    if version.contains('\n') || names::parse_canonical(version).is_none() {
        return None;
    }
    Some(version.to_owned())
}

/// §6.5 for one listed bundle: reassemble chunks (parts `.0` upward) by
/// streaming into a scratch file, verify the digest BEFORE decrypting
/// (§6.4), decrypt (streaming), verify the bundle header line (§4.3), and
/// apply.
fn apply_one(
    vault: &VaultRepo,
    tree: &VaultTree,
    m: &Manifest,
    seq: u64,
    scratch: &Path,
    dest_git_dir: &Path,
    identities: &[Identity],
) -> Result<(), ReadError> {
    let record = &m.bundles[&seq];
    let logical = record
        .logical_name()
        .map_err(|e| ReadError::Io(e.to_string()))?;

    // Part names in ascending numeric order — §4.2/§6.5. (Names are built
    // from the manifest's count, so string order never enters.)
    let part_names: Vec<String> = match record.chunks {
        None => vec![logical.to_string()],
        Some(count) => (0..count)
            .map(|i| logical.part(i).map(|p| p.to_string()))
            .collect::<Result<_, _>>()
            .map_err(|e| ReadError::Io(e.to_string()))?,
    };

    let cipher_path = scratch.join("reassembled.tmp");
    let plain_path = scratch.join("plain.tmp");
    let result: Result<(), ReadError> = (|| {
        // Reassembly streams git's blob output through the digest into the
        // scratch file — the logical ciphertext never lives in memory.
        let file = fs::File::create(&cipher_path)
            .map_err(|e| ReadError::Io(format!("{}: {e}", cipher_path.display())))?;
        let mut sink = HashingWriter::new(file);
        for part in &part_names {
            // §6.7 ran first, so every expected part is in the tree.
            let oid = tree
                .files
                .get(part)
                .ok_or_else(|| ReadError::Tree(TreeMismatch::MissingFile(part.clone())))?;
            vault.stream_blob(oid, &mut sink)?;
        }
        sink.flush()
            .map_err(|e| ReadError::Io(format!("{}: {e}", cipher_path.display())))?;
        let (digest, file) = sink.finish();
        drop(file);

        // §6.4: the digest gate is BEFORE decrypt-and-apply.
        if digest != record.digest {
            return Err(ReadError::DigestMismatch {
                name: logical.to_string(),
            });
        }

        let cipher = fs::File::open(&cipher_path)
            .map_err(|e| ReadError::Io(format!("{}: {e}", cipher_path.display())))?;
        let mut plain = fs::File::create(&plain_path)
            .map_err(|e| ReadError::Io(format!("{}: {e}", plain_path.display())))?;
        crate::crypt::decrypt_stream(identities, std::io::BufReader::new(cipher), &mut plain)?;
        plain
            .flush()
            .map_err(|e| ReadError::Io(format!("{}: {e}", plain_path.display())))?;
        drop(plain);

        // §4.3: verify the header line (and the sha256 capability) of every
        // decrypted bundle. The header region is plain text before the
        // binary pack; a 64 KiB prefix covers it many times over.
        let header = read_prefix(&plain_path, 64 * 1024)?;
        manifest::verify_bundle_header(&header, m.object_format)?;

        // §6.5: apply — objects only, never refs.
        vaultrepo::apply_bundle(dest_git_dir, &plain_path)?;
        Ok(())
    })();

    // Scratch hygiene either way; the lock (§6.1) makes this safe.
    let _ = fs::remove_file(&cipher_path);
    let _ = fs::remove_file(&plain_path);
    result
}

fn read_prefix(path: &Path, limit: usize) -> Result<Vec<u8>, ReadError> {
    use std::io::Read;
    let file =
        fs::File::open(path).map_err(|e| ReadError::Io(format!("{}: {e}", path.display())))?;
    let mut buf = Vec::with_capacity(limit);
    file.take(limit as u64)
        .read_to_end(&mut buf)
        .map_err(|e| ReadError::Io(format!("{}: {e}", path.display())))?;
    Ok(buf)
}

/// §6.6: find a manifest-listed sha absent from the local repository.
fn first_missing_object(
    dest_git_dir: &Path,
    m: &Manifest,
) -> Result<Option<(String, String)>, ReadError> {
    for (refname, sha) in &m.refs {
        if !vaultrepo::object_exists(dest_git_dir, sha)? {
            return Ok(Some((refname.clone(), sha.clone())));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_grammar_is_decimal_plus_single_lf() {
        assert_eq!(parse_hint(b"2\n").as_deref(), Some("2"));
        assert_eq!(parse_hint(b"10\n").as_deref(), Some("10"));
        for bad in [
            &b"2"[..], // no LF
            b"2\n\n",  // extra line
            b"2\r\n",  // CRLF (a transformation would be corruption)
            b"02\n",   // leading zero: not the canonical spelling
            b" 2\n",
            b"two\n",
            b"",
            b"\xff\n",
        ] {
            assert_eq!(parse_hint(bad), None, "{bad:?}");
        }
    }
}
