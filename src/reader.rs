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

use crate::crypt::{self, HeaderStanzas};
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
    /// §5 declared vs. actual: the manifest ciphertext's recipient stanzas
    /// do not match its `recipient` lines. The host cannot forge the
    /// manifest, so this is a writer bug, never an attack.
    RecipientCountMismatch(RecipientMismatch),
    Io(String),
}

/// §5: what a manifest declares against what its ciphertext is encrypted
/// to, when the two disagree. Recoverable: the manifest still decrypts
/// for its real recipients, so `git-remote-sealed compact --repair`
/// rewrites the vault encrypted to the declared set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientMismatch {
    /// The number of `recipient` lines (every one of a recognized type).
    pub declared: usize,
    /// The ciphertext's recipient stanzas, by type.
    pub stanzas: HeaderStanzas,
}

impl RecipientMismatch {
    /// Who is wronged: fewer stanzas than lines means a declared recipient
    /// cannot read; more, or a stanza of a type no line declares, means an
    /// undeclared key can.
    pub fn consequence(&self) -> &'static str {
        match self.stanzas.total().cmp(&self.declared) {
            std::cmp::Ordering::Less => "a declared recipient cannot read it",
            std::cmp::Ordering::Greater => "an undeclared key can read it",
            std::cmp::Ordering::Equal => {
                "a declared recipient cannot read it and an undeclared key can"
            }
        }
    }
}

impl fmt::Display for RecipientMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the manifest declares {} recipient(s) but its ciphertext is encrypted to {}: {}",
            self.declared,
            self.stanzas,
            self.consequence()
        )
    }
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
            ReadError::RecipientCountMismatch(m) => write!(
                f,
                "{m}. This is not an attack — the host cannot forge the manifest — but a buggy or misconfigured writer; \
                 fix that device, then run `git-remote-sealed compact --repair` from a device that can read the vault: \
                 it rewrites every file encrypted to the declared set"
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
    /// The manifest ciphertext's recipient stanzas by type (§5), for the
    /// writer's pre-recipient diagnostics and the §9.2 upgrade check.
    manifest_stanzas: Option<HeaderStanzas>,
    /// §5: the declared-vs-actual mismatch a repair read tolerated
    /// (`inspect_with(.., repair = true)`); `None` on every other read.
    recipient_mismatch: Option<RecipientMismatch>,
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

    /// The manifest ciphertext's recipient stanzas by type (§5); `None`
    /// when the header could not be read (never on a decrypted manifest).
    pub fn manifest_stanzas(&self) -> Option<&HeaderStanzas> {
        self.manifest_stanzas.as_ref()
    }

    /// §5: the mismatch this read tolerated because it was asked to repair
    /// it (`inspect_with`); `None` when declared and actual agree, or on a
    /// read that would have refused a mismatch.
    pub fn recipient_mismatch(&self) -> Option<&RecipientMismatch> {
        self.recipient_mismatch.as_ref()
    }

    /// §7.3: the manifest carried a line type this implementation does not
    /// know; a writer MUST refuse to write.
    pub fn writer_must_be_read_only(&self) -> bool {
        self.writer_must_be_read_only
    }

    /// The pin the §7.4 battery ran against (`None` = first contact). This
    /// is the one pin the repository holds for the vault, whichever URL it
    /// was saved through.
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
    inspect_with(vault, identities, false)
}

/// `inspect`, with the §5 declared-vs-actual mismatch either refused
/// (`repair = false`, every ordinary read) or recorded on the `Prepared`
/// for the explicit repair compaction (`repair = true`) that rewrites the
/// vault encrypted to the declared set. The manifest still decrypts for
/// its real recipients, which is what makes the repair possible.
pub fn inspect_with(
    vault: &VaultRepo,
    identities: &[Identity],
    repair: bool,
) -> Result<Inspection, ReadError> {
    // §6.1: current committed tree (the mirror was reset, not merged).
    let tree = vault.fetch()?;
    // §7.4: ONE pin per vault, shared by every URL that reaches it; each
    // URL is bound to the vault first pinned through it.
    let pins = vault.pins()?;

    let Some(tree) = tree else {
        // §7.4: a pinned reader MUST refuse an empty vault (no manifest) —
        // otherwise a host could reset the pin via re-initialization.
        pins.check_empty_at(vault.url())?;
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
        pins.check_empty_at(vault.url())?;
        return Ok(Inspection::Empty);
    };

    // §6.2: check `sealed-format` (§3). It is a hint — host-controlled and
    // unauthenticated — so this MAY fast-fail but never selects semantics.
    check_hint(vault, &tree)?;

    // §6.3: decrypt and validate the manifest (§7)...
    let manifest_cipher = vault.read_blob(manifest_oid)?;
    let manifest_cipher_digest = sha256_hex(&manifest_cipher);
    let manifest_plain = crypt::decrypt(identities, &manifest_cipher)?;
    let parsed = manifest::parse(&manifest_plain)?;
    let manifest = parsed.manifest;
    // §3: "readers MUST fail if the two disagree" — implied here: the hint
    // passed check_hint (== FORMAT_VERSION) and manifest::parse accepts
    // `format 2` only, so hint == manifest format on every success path.

    // §7.4 vault identity, before anything else about the manifest: a URL
    // bound to a vault must keep serving that vault; a new URL spelling
    // meets the one pin the repository holds for the vault (`pin_for_read`).
    let prev_pin = pins.pin_for_read(vault.url(), &manifest.vault_id)?;

    // ...including the §7.4 trust-on-first-use battery.
    let next_pin =
        pinstore::validate_and_advance(prev_pin.as_ref(), &manifest, &manifest_cipher_digest)?;

    // §5 declared vs. actual, AFTER the §7.4 battery: a rolled-back or
    // substituted generation that also happens to mismatch is reported as
    // the attack §7.4 names, not as the writer bug this check names (its
    // error says "not an attack", and would be wrong there).
    let manifest_stanzas = crypt::header_stanzas(&manifest_cipher);
    let recipient_mismatch = match check_declared_recipients(&manifest, manifest_stanzas.as_ref()) {
        Ok(()) => None,
        Err(mismatch) if repair => Some(mismatch),
        Err(mismatch) => return Err(ReadError::RecipientCountMismatch(mismatch)),
    };

    // §6.4/§6.7: the grammar-matching tree files must equal the expected
    // file set exactly.
    manifest.check_tree_files(tree.files.keys().map(String::as_str))?;

    Ok(Inspection::Vault(Box::new(Prepared {
        tree,
        manifest,
        manifest_cipher_digest,
        manifest_stanzas,
        recipient_mismatch,
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
            match apply_one(vault, tree, m, *seq, &scratch, dest_git_dir, identities) {
                Err(ReadError::Git(GitError::Command { what, .. }))
                    if what == "bundle verify" && !skipped.is_empty() =>
                {
                    // A new incremental can need objects GC removed from
                    // an earlier, cached bundle. Restore its predecessors
                    // before retrying; the final ref-tip check is too late.
                    for prior in skipped.drain(..) {
                        apply_one(vault, tree, m, prior, &scratch, dest_git_dir, identities)?;
                    }
                    apply_one(vault, tree, m, *seq, &scratch, dest_git_dir, identities)?;
                }
                result => result?,
            }
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
    vault.save_pin(&prepared.next_pin)?;
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

/// §5 declared vs. actual: when this implementation recognizes the type of
/// every `recipient` line, the manifest ciphertext's recipient stanzas,
/// counted by type, MUST equal what the lines call for — as many X25519
/// stanzas as X25519 lines, and no stanza of a type no line declares. A
/// pre-recipient manifest declares nothing, and a line of a type this
/// implementation cannot classify makes the counts incomparable — the
/// check does not apply to either.
pub fn check_declared_recipients(
    m: &Manifest,
    stanzas: Option<&HeaderStanzas>,
) -> Result<(), RecipientMismatch> {
    if m.is_pre_recipient() {
        return Ok(());
    }
    let Some(declared) = crypt::declared_stanzas(&m.recipients) else {
        return Ok(()); // a recipient type we cannot classify: not comparable
    };
    let Some(stanzas) = stanzas else {
        return Ok(()); // unreadable header: nothing to compare (the file decrypted)
    };
    if *stanzas != declared {
        return Err(RecipientMismatch {
            declared: m.recipients.len(),
            stanzas: stanzas.clone(),
        });
    }
    Ok(())
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
        crypt::decrypt_stream(identities, std::io::BufReader::new(cipher), &mut plain)?;
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
    fn declared_vs_actual_compares_stanzas_by_type() {
        // §5: fewer stanzas than lines, or more, is INVALID — and so is a
        // stanza of a type no line declares; a pre-recipient manifest and a
        // set with a member of an unrecognized type are outside the check.
        use age::x25519::Identity;
        let ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
        let text = format!(
            "format 2\nobjectformat sha1\nvault {}\ncounter 1\nseqfloor 1\nrecipient {}\nrecipient {}\n",
            "ab".repeat(16),
            ids[0].to_public(),
            ids[1].to_public()
        );
        let m = manifest::parse(text.as_bytes()).expect("parses").manifest;
        let stanzas = |n: usize| {
            let rcpts: Vec<_> = ids[..n].iter().map(Identity::to_public).collect();
            crypt::header_stanzas(&crypt::encrypt(&rcpts, text.as_bytes()).expect("encrypt"))
        };
        let outcome = |s: Option<HeaderStanzas>| {
            check_declared_recipients(&m, s.as_ref()).map_err(|e| (e.declared, e.stanzas.total()))
        };
        assert_eq!(outcome(stanzas(2)), Ok(()));
        let more = check_declared_recipients(&m, stanzas(3).as_ref()).expect_err("3 stanzas");
        assert_eq!((more.declared, more.stanzas.x25519()), (2, 3));
        assert_eq!(more.consequence(), "an undeclared key can read it");
        let fewer = check_declared_recipients(&m, stanzas(1).as_ref()).expect_err("1 stanza");
        assert_eq!((fewer.declared, fewer.stanzas.x25519()), (2, 1));
        assert_eq!(fewer.consequence(), "a declared recipient cannot read it");
        assert_eq!(outcome(None), Ok(()), "unreadable header: no check");

        // Two X25519 stanzas plus a plugin stanza, two X25519 lines: the
        // X25519 count matches, and the plugin key can still read it.
        let mixed: &[u8] = b"age-encryption.org/v1\n-> X25519 aaaa\nbbbb\n-> X25519 cccc\ndddd\n-> piv-p256 eeee\nffff\n--- mac\n";
        let extra = check_declared_recipients(&m, crypt::header_stanzas(mixed).as_ref())
            .expect_err("an undeclared plugin stanza");
        assert_eq!((extra.declared, extra.stanzas.total()), (2, 3));
        assert_eq!(extra.consequence(), "an undeclared key can read it");
        assert!(
            extra.to_string().contains(
                "encrypted to 2 X25519 key(s) and 1 other recipient stanza(s) (piv-p256)"
            ),
            "{extra}"
        );
        // One X25519 stanza plus a plugin stanza: same total, wrong types.
        let swapped: &[u8] =
            b"age-encryption.org/v1\n-> X25519 aaaa\nbbbb\n-> piv-p256 eeee\nffff\n--- mac\n";
        let e = check_declared_recipients(&m, crypt::header_stanzas(swapped).as_ref())
            .expect_err("a plugin stanza in place of an X25519 one");
        assert_eq!(
            e.consequence(),
            "a declared recipient cannot read it and an undeclared key can"
        );

        let mut pre = m.clone();
        pre.recipients.clear();
        check_declared_recipients(&pre, stanzas(3).as_ref()).expect("pre-recipient: no check");
        let mut plugin = m.clone();
        plugin.recipients.insert("age1yubikey1qwerty".into());
        check_declared_recipients(&plugin, stanzas(1).as_ref())
            .expect("a member of an unrecognized type: no check");
    }

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
