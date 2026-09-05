//! The §8 writer algorithm (push), end to end: preamble refusals (shallow,
//! partial, object-format mismatch), step 1 (a validated read —
//! `reader::inspect`, §6.1–6.4), step 2 (per-ref update checks), step 3
//! (one bundle with prerequisite exclusion, or none), step 4 (allocation
//! with the §8.4 guard, encryption, chunking, manifest, ONE commit, a
//! non-forced porcelain push), step 5 (rejection → discard and retry from
//! step 1, bounded), the §7.3 read-only refusal, and the pin/memory
//! persistence rules. Vault initialization (empty remote) is the same
//! algorithm with no manifest to start from.
//!
//! **Pin and memory persistence — a documented decision.** The formal
//! model's `doPush` moves the device's sequence memory even when the push
//! is acknowledged and the device then crashes before moving its pin
//! (`crash=true`, the "T9 lag window"); its
//! `crashLaggedWriterReallocationTest` shows why: with the memory not yet
//! moved, a host replaying the pre-push state makes the same device
//! re-allocate the same sequence number with different content. So this
//! writer persists the new (sequence → digest) binding BEFORE pushing —
//! as PENDING — and persists the advanced pin (counter, twin digest,
//! seqfloor) only AFTER the push was acknowledged, promoting the binding
//! to CONFIRMED at the same time. Only a definitive, REF-LEVEL rejection
//! (§8.5) proves the write did not land and withdraws the binding; a
//! dropped connection, a killed process or a lost status report leaves it
//! pending. A pending number is never re-bound: §8.4 allocation SKIPS it
//! and takes the next one, so an interrupted push costs one sequence
//! number rather than wedging the writer forever. The next read settles
//! it — the published line either binds the number to our own ciphertext
//! (confirm) or has moved its `seqfloor` past it (forget). The memory
//! never records the base manifest's bundles here: a push reads them but
//! does not apply them. An acknowledged push also CONFIRMS the numbers it
//! skipped: publishing a seqfloor past them burns them for every writer, so
//! they stop being guesses (`pinstore::confirm_acked`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};

use crate::bundling::{self, BundleError, BundleSpec, Stored};
use crate::crypt::{self, CryptError};
use crate::manifest::{BundleRecord, Manifest, ManifestError, ObjectFormat, MAX_COUNTER};
use crate::names::{self, BundleName, NameClass, NameError, MAX_SEQ};
use crate::pinstore::{self, Pin, PinError};
use crate::reader::{self, Inspection, Prepared, ReadError};
use crate::srcrepo;
use crate::vaultrepo::{self, GitError, PushOutcome, TreeEntry, VaultRepo};
use crate::{sha256_hex, FORMAT_VERSION};

/// §8.5 says retry; nothing bounds it, so this does (documented choice).
pub const MAX_ATTEMPTS: usize = 5;

/// §8.5 (review finding L5): how many attempts may end WITHOUT a ref-level
/// verdict before we stop and hand the outcome back to the caller.
///
/// A rejected attempt is free to retry: the binding is withdrawn and nothing
/// is consumed. An INDETERMINATE one is not — the binding stays pending and
/// this device's next acknowledged write burns the number for good (§8.4),
/// so every such attempt costs one sequence number permanently. Retrying a
/// dropped connection a second later usually meets the same dropped
/// connection, so the retries buy little and the cost is certain. One is
/// enough; the next sync settles the binding either way (§7.4).
pub const MAX_INDETERMINATE_ATTEMPTS: usize = 1;

/// §3: an empty remote is initialized on `main`.
const INIT_BRANCH: &str = "refs/heads/main";

#[derive(Debug)]
pub enum WriteError {
    Read(ReadError),
    Git(GitError),
    Bundle(BundleError),
    Crypt(CryptError),
    Manifest(ManifestError),
    Pin(PinError),
    Name(NameError),
    /// §7.3: the manifest contained a line type this implementation does not
    /// know; writing would silently delete it.
    ReadOnlyVault,
    /// §5/M4: this device would encrypt to fewer recipients than the vault
    /// currently has, locking the others out of everything it writes.
    RecipientShrink {
        vault: usize,
        ours: usize,
    },
    /// §8 preamble.
    ShallowRepository,
    /// §8 preamble.
    PartialRepository,
    /// §8 preamble: the source repository's object format is not the
    /// vault's `objectformat`.
    ObjectFormatMismatch {
        vault: ObjectFormat,
        local: String,
    },
    /// The source repository's object format is one this format does not
    /// define (§3 supports sha1 and sha256).
    UnsupportedObjectFormat(String),
    /// §4.1: the sequence space is exhausted.
    SequenceExhausted,
    /// §7.2: the counter cannot advance past 2^63-1.
    CounterExhausted,
    /// §8.4 allocation guard.
    AllocationCollision {
        seq: u64,
    },
    /// A `push` source that names nothing in the source repository.
    UnknownSource {
        dst: String,
        src: String,
    },
    /// §8.5: rejected on every attempt.
    Rejected {
        attempts: usize,
        last: String,
    },
    /// §8.5: the remote never said whether it took the update. It may have
    /// landed; the next read settles it (§7.4). Not an error about the
    /// vault — an unknown outcome, reported as one.
    Unreported {
        last: String,
    },
    /// The push was acknowledged but the advanced pin could not be saved:
    /// the vault is updated; this repository's pin lags (its memory already
    /// holds the new binding, so the §8.4 guard still protects it).
    AckedButPinNotSaved(PinError),
    /// §9 on an empty vault: nothing to compact.
    EmptyVault,
    Io(String),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::Read(e) => write!(f, "{e}"),
            WriteError::Git(e) => write!(f, "{e}"),
            WriteError::Bundle(e) => write!(f, "{e}"),
            WriteError::Crypt(e) => write!(f, "{e}"),
            WriteError::Manifest(e) => write!(f, "{e}"),
            WriteError::Pin(e) => write!(f, "{e}"),
            WriteError::Name(e) => write!(f, "{e}"),
            WriteError::ReadOnlyVault => write!(
                f,
                "the vault manifest has lines this version does not understand; refusing to write (read-only) — update git-remote-sealed"
            ),
            WriteError::RecipientShrink { vault, ours } => write!(
                f,
                "refusing to write: this vault is encrypted to {vault} recipients but this device would encrypt to {ours}. Everything written from here would be unreadable to the others — check `sealed.recipients` (`git-remote-sealed info`). If you really are removing a device, set `git config sealed.allow-recipient-shrink true`"
            ),
            WriteError::ShallowRepository => write!(
                f,
                "refusing to push from a shallow repository: a bundle cannot represent a shallow boundary"
            ),
            WriteError::PartialRepository => write!(
                f,
                "refusing to push from a partial (promisor) repository: the bundle could be missing objects"
            ),
            WriteError::ObjectFormatMismatch { vault, local } => write!(
                f,
                "the vault stores a {} repository but this repository is {local}",
                vault.as_str()
            ),
            WriteError::UnsupportedObjectFormat(of) => {
                write!(f, "unsupported source repository object format {of:?}")
            }
            WriteError::SequenceExhausted => write!(
                f,
                "the vault's sequence space is exhausted; compact into a fresh vault"
            ),
            WriteError::CounterExhausted => {
                write!(f, "the vault's write counter is exhausted; start a fresh vault")
            }
            WriteError::AllocationCollision { seq } => write!(
                f,
                "refusing to allocate sequence number {seq}: this repository has already seen it bound, so the vault state just fetched predates this repository's own history — fetch again; if the state does not change, the host is serving a rolled-back vault (or a push from here was interrupted before it was acknowledged); see `git-remote-sealed forget`"
            ),
            WriteError::UnknownSource { dst, src } => {
                write!(f, "push to {dst}: source {src:?} names nothing in this repository")
            }
            WriteError::Rejected { attempts, last } => write!(
                f,
                "the vault push was rejected {attempts} times in a row (last: {last}); another writer keeps winning the race — try again later"
            ),
            WriteError::Unreported { last } => write!(
                f,
                "the remote did not report whether it took the push ({last}), so it may or may not have landed. Nothing is lost either way: fetch or push again and this repository will find out"
            ),
            WriteError::AckedButPinNotSaved(e) => write!(
                f,
                "the push was accepted by the remote, but this repository's pin could not be saved: {e}"
            ),
            WriteError::EmptyVault => write!(f, "the vault is empty; nothing to compact"),
            WriteError::Io(e) => write!(f, "writer I/O error: {e}"),
        }
    }
}

impl std::error::Error for WriteError {}

impl From<ReadError> for WriteError {
    fn from(e: ReadError) -> Self {
        WriteError::Read(e)
    }
}
impl From<GitError> for WriteError {
    fn from(e: GitError) -> Self {
        WriteError::Git(e)
    }
}
impl From<BundleError> for WriteError {
    fn from(e: BundleError) -> Self {
        WriteError::Bundle(e)
    }
}
impl From<CryptError> for WriteError {
    fn from(e: CryptError) -> Self {
        WriteError::Crypt(e)
    }
}
impl From<ManifestError> for WriteError {
    fn from(e: ManifestError) -> Self {
        WriteError::Manifest(e)
    }
}
impl From<PinError> for WriteError {
    fn from(e: PinError) -> Self {
        match e {
            PinError::AllocationCollision { seq } => WriteError::AllocationCollision { seq },
            e => WriteError::Pin(e),
        }
    }
}
impl From<NameError> for WriteError {
    fn from(e: NameError) -> Self {
        WriteError::Name(e)
    }
}

/// One ref update as the remote-helper protocol states it:
/// `push [+]<src>:<dst>`; `src` absent = delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub dst: String,
    /// A revision expression in the source repository (git passes full
    /// refnames or object ids); `None` deletes `dst`.
    pub src: Option<String>,
    pub force: bool,
}

/// Per-ref outcome for the protocol's `ok`/`error` lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefResult {
    pub dst: String,
    /// `None` = ok; `Some(reason)` = refused (§8.2), one line of text.
    pub error: Option<String>,
}

/// What a push wrote, when it wrote anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub counter: u64,
    /// The sequence number allocated, with its `-full` label; `None` for a
    /// manifest-only push (§8.4: nothing allocated).
    pub allocated: Option<(u64, bool)>,
    pub attempts: usize,
    /// The vault was initialized by this push (§3, §8 preamble).
    pub initialized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushReport {
    pub results: Vec<RefResult>,
    /// `None` when every update was a no-op or refused: nothing was written
    /// and the counter did not move.
    pub written: Option<Written>,
}

/// Writer-local policy (§4.2 threshold) and the recipient set (§5).
pub struct WriterConfig {
    pub recipients: Vec<Recipient>,
    pub chunk_bytes: u64,
    /// §5/M4 opt-in (`git config sealed.allow-recipient-shrink true`): write
    /// even when this device has fewer recipients than the vault. The
    /// deliberate case is removing a lost device.
    pub allow_recipient_shrink: bool,
}

/// One update after resolving its source: the new object and its type.
struct Resolved {
    dst: String,
    /// `(sha, type)`; `None` = delete.
    new: Option<(String, String)>,
    force: bool,
}

/// An update the §8.2 checks let through.
struct Applied {
    dst: String,
    new: Option<(String, String)>,
}

enum Attempt {
    Done(PushReport),
    /// §8.5 definitive: the remote reported it did not take the update.
    Rejected(String),
    /// §8.5: the attempt ended with no ref-level verdict. Counted
    /// separately — each one costs a sequence number (`MAX_INDETERMINATE_ATTEMPTS`).
    Indeterminate(String),
}

/// §8: push `updates` from the repository at `source_git_dir` into the
/// vault. `first` lets the remote helper reuse the inspection its `list
/// for-push` already did; retries always re-inspect (§8.5).
pub fn push(
    vault: &VaultRepo,
    source_git_dir: &Path,
    identities: &[Identity],
    cfg: &WriterConfig,
    updates: &[RefUpdate],
    first: Option<Inspection>,
) -> Result<PushReport, WriteError> {
    let local_format = preflight(source_git_dir)?;
    let resolved = resolve_updates(source_git_dir, updates)?;

    let mut inspection = first;
    let mut last = String::new();
    let mut unreported = 0usize;
    for attempt in 1..=MAX_ATTEMPTS {
        // §8.1 (and §8.5: retry from step 1, discarding local vault state —
        // the mirror is reset by the fetch inside `inspect`).
        let insp = match inspection.take() {
            Some(i) => i,
            None => reader::inspect(vault, identities)?,
        };
        let ctx = Ctx {
            vault,
            source: source_git_dir,
            cfg,
            local_format: &local_format,
            attempt,
        };
        let outcome = match insp {
            Inspection::Empty => ctx.attempt_init(&resolved)?,
            Inspection::Vault(p) => ctx.attempt_incremental(&resolved, &p)?,
        };
        match outcome {
            Attempt::Done(report) => return Ok(report),
            Attempt::Rejected(summary) => last = summary,
            Attempt::Indeterminate(summary) => {
                // §8.5/L5: each of these costs a sequence number, and a
                // retry is unlikely to do better. Stop and say so.
                unreported += 1;
                if unreported >= MAX_INDETERMINATE_ATTEMPTS {
                    return Err(WriteError::Unreported { last: summary });
                }
                last = summary;
            }
        }
    }
    Err(WriteError::Rejected {
        attempts: MAX_ATTEMPTS,
        last,
    })
}

/// §8 preamble: refuse shallow and partial/promisor repositories; return
/// the source object format (`sha1`/`sha256`).
pub(crate) fn preflight(source_git_dir: &Path) -> Result<String, WriteError> {
    if srcrepo::is_shallow(source_git_dir)? {
        return Err(WriteError::ShallowRepository);
    }
    if srcrepo::is_partial(source_git_dir)? {
        return Err(WriteError::PartialRepository);
    }
    let local = vaultrepo::repo_object_format(source_git_dir)?;
    if ObjectFormat::from_str_exact(&local).is_none() {
        return Err(WriteError::UnsupportedObjectFormat(local));
    }
    Ok(local)
}

fn resolve_updates(source: &Path, updates: &[RefUpdate]) -> Result<Vec<Resolved>, WriteError> {
    let mut out = Vec::with_capacity(updates.len());
    for u in updates {
        let new = match &u.src {
            None => None,
            Some(src) => {
                let unknown = || WriteError::UnknownSource {
                    dst: u.dst.clone(),
                    src: src.clone(),
                };
                let sha = srcrepo::resolve(source, src)?.ok_or_else(unknown)?;
                let kind = srcrepo::object_type(source, &sha)?.ok_or_else(unknown)?;
                Some((sha, kind))
            }
        };
        out.push(Resolved {
            dst: u.dst.clone(),
            new,
            force: u.force,
        });
    }
    Ok(out)
}

struct Ctx<'a> {
    vault: &'a VaultRepo,
    source: &'a Path,
    cfg: &'a WriterConfig,
    local_format: &'a str,
    attempt: usize,
}

impl Ctx<'_> {
    /// Vault initialization: the empty-remote case (§8.1 "reads as no
    /// refs"; §3 branch `main`; §4.1 `-full` at sequence 1; §7.2 counter 1,
    /// seqfloor 1, fresh vault identity; HEAD from the source repository).
    fn attempt_init(&self, resolved: &[Resolved]) -> Result<Attempt, WriteError> {
        let mut results = Vec::new();
        let mut refs: BTreeMap<String, String> = BTreeMap::new();
        let mut bundle_refs: Vec<(String, String)> = Vec::new();
        for r in resolved {
            results.push(RefResult {
                dst: r.dst.clone(),
                error: None,
            });
            if let Some((sha, _)) = &r.new {
                refs.insert(r.dst.clone(), sha.clone());
                bundle_refs.push((r.dst.clone(), sha.clone()));
            }
            // A deletion on an empty vault is a no-op (git normally refuses
            // it client-side before we see it).
        }
        if refs.is_empty() {
            return Ok(Attempt::Done(PushReport {
                results,
                written: None,
            }));
        }
        let of = ObjectFormat::from_str_exact(self.local_format)
            .ok_or_else(|| WriteError::UnsupportedObjectFormat(self.local_format.to_owned()))?;
        let head = pick_head(srcrepo::head_symref(self.source)?.as_deref(), &refs);

        let scratch = self.vault.scratch_dir()?;
        let bundle = bundling::create(
            self.source,
            of,
            &scratch,
            &BundleSpec {
                refs: &bundle_refs,
                head: head.as_deref(),
                excludes: &[],
            },
        )?;

        // Documented choice — the mirror's object format for an EMPTY remote.
        // §6.1 has the mirror learn the vault repository's format from the
        // advertised object ids, but an empty remote advertises none (and
        // `git clone` of an empty remote does not learn it either). So: if
        // a mirror already exists, use it; otherwise create it in the
        // source repository's format (the common case: one user, one git
        // default), and if the remote refuses the push outright — not a
        // ref rejection, a transport-level refusal such as a hash-algorithm
        // mismatch — discard the mirror and try the other format once.
        let formats: Vec<String> = if self.vault.mirror_exists() {
            vec![self.vault.mirror_object_format()?]
        } else {
            let other = if self.local_format == "sha256" {
                "sha1"
            } else {
                "sha256"
            };
            vec![self.local_format.to_owned(), other.to_owned()]
        };

        let mut result = Err(WriteError::Io("no mirror format to try".into()));
        for (i, format) in formats.iter().enumerate() {
            self.vault.ensure_mirror_with_format(format)?;
            let name = BundleName::new(1, true, None)?;
            let stored = bundling::encrypt_and_store(
                self.vault,
                &bundle,
                &self.cfg.recipients,
                name,
                self.cfg.chunk_bytes,
                &scratch,
            )?;
            let manifest = Manifest {
                format: FORMAT_VERSION,
                object_format: of,
                vault_id: fresh_vault_id(),
                counter: 1,
                seqfloor: 1,
                bundles: [(
                    1,
                    BundleRecord {
                        seq: 1,
                        full: true,
                        digest: stored.digest.clone(),
                        chunks: stored.chunks,
                    },
                )]
                .into_iter()
                .collect(),
                head: head.clone(),
                refs: refs.clone(),
            };
            let (commit, manifest_digest) = build_commit(
                self.vault,
                &manifest,
                &self.cfg.recipients,
                &stored,
                &[],
                None,
            )?;
            match self.vault.push_commit(&commit, INIT_BRANCH, None) {
                Ok(PushOutcome::Accepted) => {
                    // No pin existed (a pinned reader refuses an empty vault,
                    // §7.4), so there was nothing to bind before the push;
                    // the advanced pin now records generation 1 and our
                    // binding for sequence 1.
                    let pin = Pin {
                        vault_id: manifest.vault_id.clone(),
                        counter: 1,
                        manifest_digest,
                        format: FORMAT_VERSION,
                        object_format: of,
                        seqfloor: 1,
                        sequence_memory: [(1, stored.digest.clone())].into_iter().collect(),
                        pending: BTreeMap::new(),
                    };
                    self.vault
                        .save_pin(&pin)
                        .map_err(WriteError::AckedButPinNotSaved)?;
                    result = Ok(Attempt::Done(PushReport {
                        results,
                        written: Some(Written {
                            counter: 1,
                            allocated: Some((1, true)),
                            attempts: self.attempt,
                            initialized: true,
                        }),
                    }));
                    break;
                }
                Ok(PushOutcome::Rejected(summary)) => {
                    // Someone initialized the vault concurrently (§8.5); the
                    // retry's read finds their vault.
                    result = Ok(Attempt::Rejected(summary));
                    break;
                }
                Ok(PushOutcome::Indeterminate(summary)) => {
                    // The remote never reported. An initialization that did
                    // land is simply the vault this repository pins on the
                    // next read; one that did not is refused by the branch
                    // CAS. Nothing is bound here (§8.4's initialization
                    // carve-out, note 8d), so no sequence number is at
                    // stake — but the outcome is still unknown, and saying
                    // so beats retrying into the same dropped connection.
                    result = Ok(Attempt::Indeterminate(summary));
                    break;
                }
                Err(GitError::PushFailed(detail)) if i + 1 < formats.len() => {
                    self.vault.discard_mirror()?;
                    result = Err(GitError::PushFailed(detail).into());
                }
                Err(e) => {
                    result = Err(e.into());
                    break;
                }
            }
        }
        let _ = fs::remove_file(&bundle);
        result
    }

    /// A push into an existing vault: §8 steps 2–5.
    fn attempt_incremental(
        &self,
        resolved: &[Resolved],
        p: &Prepared,
    ) -> Result<Attempt, WriteError> {
        // §7.3: read-only against a manifest with unknown line types.
        if p.writer_must_be_read_only() {
            return Err(WriteError::ReadOnlyVault);
        }
        check_recipient_shrink(self.vault, p, self.cfg)?;
        let m = p.manifest();
        // §8 preamble: object format equality.
        if self.local_format != m.object_format.as_str() {
            return Err(WriteError::ObjectFormatMismatch {
                vault: m.object_format,
                local: self.local_format.to_owned(),
            });
        }

        // §8.2: per-ref checks against the manifest just read.
        let (results, applied) = check_updates(self.source, m, resolved)?;
        if applied.is_empty() {
            return Ok(Attempt::Done(PushReport {
                results,
                written: None,
            }));
        }

        let mut refs = m.refs.clone();
        let mut bundle_refs: Vec<(String, String, String)> = Vec::new();
        for a in &applied {
            match &a.new {
                None => {
                    refs.remove(&a.dst);
                }
                Some((sha, kind)) => {
                    refs.insert(a.dst.clone(), sha.clone());
                    bundle_refs.push((a.dst.clone(), sha.clone(), kind.clone()));
                }
            }
        }

        // §8.3: exclude history reachable from any pre-update manifest sha
        // present in this repository (commit-ish only: `^<blob>` would be
        // an error, and a blob reaches nothing anyway).
        let mut excludes: Vec<String> = Vec::new();
        let mut seen = BTreeSet::new();
        for sha in m.refs.values() {
            if !seen.insert(sha.clone()) {
                continue;
            }
            match srcrepo::object_type(self.source, sha)?.as_deref() {
                Some("commit") | Some("tag") => excludes.push(sha.clone()),
                _ => {}
            }
        }

        // §8.3's emptiness rule, applied by us rather than by parsing git's
        // refusal text: a bundle may be omitted only when every updated
        // ref's new object is already in the vault. A commit tip is, iff it
        // reaches nothing beyond the exclusions; a tag object (or any
        // non-commit) always needs shipping.
        let mut needs_bundle = false;
        for (_, sha, kind) in &bundle_refs {
            if kind != "commit" || srcrepo::has_new_commits(self.source, sha, &excludes)? {
                needs_bundle = true;
                break;
            }
        }

        let counter = m
            .counter
            .checked_add(1)
            .filter(|c| *c <= MAX_COUNTER)
            .ok_or(WriteError::CounterExhausted)?;
        // HEAD: unchanged while it names a ref that still exists; otherwise
        // re-picked from the source repository's HEAD (documented choice —
        // see `pick_head`).
        let head = match &m.head {
            Some(h) if refs.contains_key(h) => Some(h.clone()),
            _ => pick_head(srcrepo::head_symref(self.source)?.as_deref(), &refs),
        };
        let mut manifest = Manifest {
            format: FORMAT_VERSION,
            object_format: m.object_format,
            vault_id: m.vault_id.clone(),
            counter,
            seqfloor: m.seqfloor,
            bundles: m.bundles.clone(),
            head: head.clone(),
            refs,
        };

        // The pin we build on: the battery's result, but with THIS
        // repository's memory only — the base manifest's bundles were read,
        // not applied (§7.4), so they are not recorded here.
        let mut pin_base = p.next_pin().clone();
        pin_base.sequence_memory = p
            .prev_pin()
            .map(|prev| prev.sequence_memory.clone())
            .unwrap_or_default();
        // §8.4: settle this device's pending bindings against the base. One
        // the base binds to OUR ciphertext landed after all — it is ours and
        // applied by construction, so it joins the memory even here; one the
        // base's `seqfloor` has passed without binding it to us drops out.
        let resolution = pinstore::resolve_pending(p.prev_pin(), m);
        pin_base.sequence_memory.extend(resolution.promoted.clone());
        pin_base.pending = resolution.pending;

        let scratch = self.vault.scratch_dir()?;
        let mut stored = Stored {
            digest: String::new(),
            chunks: None,
            blobs: Vec::new(),
        };
        let mut allocated: Option<(u64, bool)> = None;
        if needs_bundle {
            // §8.4: allocate seqfloor + 1 — or the next number above it that
            // this device has not already bound (see `allocate_from`).
            let first = m
                .seqfloor
                .checked_add(1)
                .filter(|s| *s <= MAX_SEQ)
                .ok_or(WriteError::SequenceExhausted)?;
            let seq = pinstore::allocate_from(&pin_base.sequence_memory, &pin_base.pending, first)?;
            // §4.1: -full iff the pre-push generation's bundle list is empty.
            let full = m.bundles.is_empty();
            let name = BundleName::new(seq, full, None)?;
            let refs_only: Vec<(String, String)> = bundle_refs
                .iter()
                .map(|(n, s, _)| (n.clone(), s.clone()))
                .collect();
            let bundle = bundling::create(
                self.source,
                m.object_format,
                &scratch,
                &BundleSpec {
                    refs: &refs_only,
                    head: head.as_deref(),
                    excludes: &excludes,
                },
            )?;
            let encrypted = bundling::encrypt_and_store(
                self.vault,
                &bundle,
                &self.cfg.recipients,
                name,
                self.cfg.chunk_bytes,
                &scratch,
            );
            let _ = fs::remove_file(&bundle);
            stored = encrypted?;
            manifest.bundles.insert(
                seq,
                BundleRecord {
                    seq,
                    full,
                    digest: stored.digest.clone(),
                    chunks: stored.chunks,
                },
            );
            manifest.seqfloor = seq;
            allocated = Some((seq, full));
        }

        let preserved = preserved_entries(&p.tree().entries, true);
        let (commit, manifest_digest) = build_commit(
            self.vault,
            &manifest,
            &self.cfg.recipients,
            &stored,
            &preserved,
            Some(&p.tree().commit),
        )?;

        // Memory before the push (see the module comment): PENDING until the
        // push is acknowledged.
        let mut pin_bound = pin_base.clone();
        if let Some((seq, _)) = allocated {
            pin_bound.pending.insert(seq, stored.digest.clone());
            self.vault.save_pin(&pin_bound)?;
        }

        match self.vault.push_commit(&commit, &p.tree().branch, None)? {
            PushOutcome::Accepted => {
                // Acknowledged: our own binding, and every pending number
                // this generation's seqfloor just burned, become CONFIRMED.
                let mut acked = pin_bound.clone();
                pinstore::confirm_acked(&mut acked, manifest.seqfloor);
                let pin = advanced_pin(&acked, &manifest, &manifest_digest);
                self.vault
                    .save_pin(&pin)
                    .map_err(WriteError::AckedButPinNotSaved)?;
                Ok(Attempt::Done(PushReport {
                    results,
                    written: Some(Written {
                        counter,
                        allocated,
                        attempts: self.attempt,
                        initialized: false,
                    }),
                }))
            }
            PushOutcome::Rejected(summary) => {
                // §8.5 definitive: a ref-level rejection proves the write did
                // not land, so the binding is withdrawn before the retry.
                if allocated.is_some() {
                    restore_pin(self.vault, p.prev_pin(), &m.vault_id)?;
                }
                Ok(Attempt::Rejected(summary))
            }
            PushOutcome::Indeterminate(summary) => {
                // §8.5: no ref-level verdict, so the update may have landed.
                // The binding stays PENDING exactly as saved; the next read
                // settles it, and §8.4 allocation skips the number in the
                // meantime.
                Ok(Attempt::Indeterminate(summary))
            }
        }
    }
}

/// §5/M4: refuse to write when this device would encrypt to FEWER
/// recipients than the vault already has.
///
/// age takes only recipient strings, so a device whose `sealed.recipients`
/// is short — a stale config, a half-finished device setup — writes
/// perfectly valid files that the other devices simply cannot open. Nothing
/// detects that at write time, and the vault keeps working for the writer,
/// so it surfaces on someone else's next sync as "age decryption failed".
/// Kotlin has had this guard; this is the port of it.
///
/// Counting stanzas is a lower bound on "who can read this" (one key could
/// hold several stanzas in principle), which is the safe direction: we only
/// ever refuse when we are strictly smaller.
pub(crate) fn check_recipient_shrink(
    vault: &VaultRepo,
    p: &Prepared,
    cfg: &WriterConfig,
) -> Result<(), WriteError> {
    if cfg.allow_recipient_shrink {
        return Ok(());
    }
    let Some(oid) = p.tree().files.get(crate::MANIFEST_FILE) else {
        return Ok(());
    };
    let Some(have) = crypt::recipient_count(&vault.read_blob(oid)?) else {
        return Ok(()); // not an age header we recognize: nothing to compare
    };
    if cfg.recipients.len() < have {
        return Err(WriteError::RecipientShrink {
            vault: have,
            ours: cfg.recipients.len(),
        });
    }
    Ok(())
}

/// §8.2 for every update: non-forced updates need `old` (the manifest
/// value) to be an ancestor of `new`; `old` absent locally → refuse and say
/// "fetch first"; forced updates and new refs go through unconditionally;
/// deletions need no check. Unchanged refs are ok no-ops.
fn check_updates(
    source: &Path,
    m: &Manifest,
    resolved: &[Resolved],
) -> Result<(Vec<RefResult>, Vec<Applied>), WriteError> {
    let mut results = Vec::with_capacity(resolved.len());
    let mut applied = Vec::new();
    for r in resolved {
        let old = m.refs.get(&r.dst);
        let error: Option<String> = match (&r.new, old) {
            (None, None) => None,
            (None, Some(_)) => {
                applied.push(Applied {
                    dst: r.dst.clone(),
                    new: None,
                });
                None
            }
            (Some(new), None) => {
                applied.push(Applied {
                    dst: r.dst.clone(),
                    new: Some(new.clone()),
                });
                None
            }
            (Some((sha, _)), Some(old)) if sha == old => None,
            (Some(new), Some(_)) if r.force => {
                applied.push(Applied {
                    dst: r.dst.clone(),
                    new: Some(new.clone()),
                });
                None
            }
            (Some((sha, _)), Some(old)) => {
                if !vaultrepo::object_exists(source, old)? {
                    Some(format!(
                        "fetch first: the vault has {} at {old}, which this repository does not have",
                        r.dst
                    ))
                } else {
                    match srcrepo::is_ancestor(source, old, sha) {
                        Ok(true) => {
                            applied.push(Applied {
                                dst: r.dst.clone(),
                                new: r.new.clone(),
                            });
                            None
                        }
                        Ok(false) => Some(format!(
                            "non-fast-forward: {old} (the vault's {}) is not an ancestor of {sha}; fetch and merge, or force",
                            r.dst
                        )),
                        Err(e) => Some(format!(
                            "cannot verify that {old} is an ancestor of {sha}: {e}"
                        )),
                    }
                }
            }
        };
        results.push(RefResult {
            dst: r.dst.clone(),
            error,
        });
    }
    Ok((results, applied))
}

/// The manifest HEAD symref for a generation whose current HEAD names no
/// listed ref (initialization, or the HEAD ref was deleted). Documented
/// rule (§8 preamble asks for the source repository's HEAD, else a
/// deterministic, documented pick): the source HEAD's symref target if it
/// is among the refs; else `refs/heads/main` if present; else the
/// lexicographically first `refs/heads/*`; else no HEAD line.
pub(crate) fn pick_head(
    source_head: Option<&str>,
    refs: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(h) = source_head {
        if refs.contains_key(h) {
            return Some(h.to_owned());
        }
    }
    if refs.contains_key("refs/heads/main") {
        return Some("refs/heads/main".into());
    }
    refs.keys().find(|k| k.starts_with("refs/heads/")).cloned()
}

/// §3 on tree rewrites: keep entries outside the grammar (writers SHOULD
/// preserve them), DROP bundle-shaped non-canonical names (writers MUST),
/// and never carry the manifest or `sealed-format` (rewritten). Canonical bundle
/// blobs are kept iff `keep_bundles` (a push keeps the generation's
/// bundles; compaction keeps none). A canonical name on a non-blob entry is
/// a decoy in the spec-owned namespace and is dropped too.
pub(crate) fn preserved_entries(entries: &[TreeEntry], keep_bundles: bool) -> Vec<TreeEntry> {
    let mut out = Vec::new();
    for e in entries {
        let keep = match std::str::from_utf8(&e.name) {
            Err(_) => true, // cannot match any grammar: outside it
            Ok(name) => match names::classify(name) {
                NameClass::Canonical(_) => keep_bundles && e.kind == "blob",
                NameClass::BundleShapedNonCanonical => false,
                NameClass::NonGrammar => {
                    // Both are rewritten from scratch on every generation, so
                    // carrying them would duplicate them. `refs.age` is v1's
                    // manifest: dropping it is deliberate, not incidental (§3).
                    name != crate::MANIFEST_FILE
                        && name != crate::LEGACY_MANIFEST_FILE
                        && name != crate::FORMAT_HINT_FILE
                }
            },
        };
        if keep {
            out.push(e.clone());
        }
    }
    out
}

/// §8.4/§9.3: the tree (`sealed-format`, `sealed-manifest.age`, the bundle's file(s),
/// preserved entries) and ONE commit — the unit of atomicity.
pub(crate) fn build_commit(
    vault: &VaultRepo,
    manifest: &Manifest,
    recipients: &[Recipient],
    stored: &Stored,
    preserved: &[TreeEntry],
    parent: Option<&str>,
) -> Result<(String, String), WriteError> {
    let text = manifest.to_text()?;
    let cipher = crypt::encrypt(recipients, text.as_bytes())?;
    let manifest_digest = sha256_hex(&cipher);

    let mut entries = preserved.to_vec();
    let hint = format!("{FORMAT_VERSION}\n");
    entries.push(TreeEntry::blob(
        crate::FORMAT_HINT_FILE,
        &vault.write_blob(hint.as_bytes())?,
    ));
    entries.push(TreeEntry::blob(
        crate::MANIFEST_FILE,
        &vault.write_blob(&cipher)?,
    ));
    for (name, oid) in &stored.blobs {
        entries.push(TreeEntry::blob(name, oid));
    }
    let tree = vault.write_tree(&entries)?;
    let parents: Vec<&str> = parent.into_iter().collect();
    let commit = vault.commit_tree(&tree, &parents)?;
    Ok((commit, manifest_digest))
}

/// The pin after an acknowledged write: the new generation's counter and
/// twin digest, seqfloor never lower than before, memory as `bound` has it.
pub(crate) fn advanced_pin(bound: &Pin, manifest: &Manifest, manifest_digest: &str) -> Pin {
    Pin {
        vault_id: manifest.vault_id.clone(),
        counter: manifest.counter,
        manifest_digest: manifest_digest.to_owned(),
        format: manifest.format,
        object_format: manifest.object_format,
        seqfloor: bound.seqfloor.max(manifest.seqfloor),
        sequence_memory: bound.sequence_memory.clone(),
        pending: bound.pending.clone(),
    }
}

/// Put the vault's pin back to what the attempt started from. `prev ==
/// None` means the repository held no pin for the vault at all (through
/// any URL), so the pending binding was its first record: remove it.
pub(crate) fn restore_pin(
    vault: &VaultRepo,
    prev: Option<&Pin>,
    vault_id: &str,
) -> Result<(), WriteError> {
    match prev {
        Some(pin) => vault.save_pin(pin)?,
        None => vault.pins()?.remove_vault(vault_id)?,
    }
    Ok(())
}

/// §7.2: a random vault identity, at least 128 bits, lowercase hex. Drawn
/// from the same CSPRNG the crypto already relies on: a freshly generated
/// X25519 secret, hashed — 256 bits, dependency-free.
fn fresh_vault_id() -> String {
    let secret = Identity::generate();
    sha256_hex(secret.to_string().expose_secret().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(names: &[&str]) -> BTreeMap<String, String> {
        names
            .iter()
            .map(|n| (n.to_string(), "0".repeat(40)))
            .collect()
    }

    #[test]
    fn head_pick_rule() {
        let r = refs(&["refs/heads/dev", "refs/heads/main", "refs/tags/v1"]);
        assert_eq!(
            pick_head(Some("refs/heads/dev"), &r).as_deref(),
            Some("refs/heads/dev")
        );
        assert_eq!(
            pick_head(Some("refs/heads/absent"), &r).as_deref(),
            Some("refs/heads/main")
        );
        let no_main = refs(&["refs/heads/zed", "refs/heads/apple", "refs/tags/v1"]);
        assert_eq!(
            pick_head(None, &no_main).as_deref(),
            Some("refs/heads/apple")
        );
        assert_eq!(pick_head(None, &refs(&["refs/tags/v1"])), None);
        assert_eq!(pick_head(Some("refs/heads/x"), &BTreeMap::new()), None);
    }

    #[test]
    fn preservation_follows_section_3() {
        let e = |name: &[u8], kind: &str| TreeEntry {
            mode: "100644".into(),
            kind: kind.into(),
            oid: "x".into(),
            name: name.to_vec(),
        };
        let entries = vec![
            e(b"sealed-manifest.age", "blob"), // rewritten every generation
            e(b"refs.age", "blob"),            // v1's manifest: dropped, not kept
            e(b"sealed-format", "blob"),
            e(b"1-full.bundle.age", "blob"),
            e(b"2.bundle.age.0", "blob"),
            e(b"03.bundle.age", "blob"),     // non-canonical: dropped
            e(b"4-FULL.bundle.age", "blob"), // case decoy: dropped
            e(b"5.bundle.age", "tree"),      // canonical name on a tree: dropped
            e(b"future.dat", "blob"),        // unknown: preserved
            e(b"subdir", "tree"),            // unknown: preserved
            e(b"bad\xff", "blob"),           // non-UTF-8: preserved
        ];
        let kept: Vec<Vec<u8>> = preserved_entries(&entries, true)
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            kept,
            vec![
                b"1-full.bundle.age".to_vec(),
                b"2.bundle.age.0".to_vec(),
                b"future.dat".to_vec(),
                b"subdir".to_vec(),
                b"bad\xff".to_vec(),
            ]
        );
        let compacted: Vec<Vec<u8>> = preserved_entries(&entries, false)
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            compacted,
            vec![
                b"future.dat".to_vec(),
                b"subdir".to_vec(),
                b"bad\xff".to_vec()
            ]
        );
    }

    #[test]
    fn vault_ids_are_fresh_and_well_formed() {
        let a = fresh_vault_id();
        let b = fresh_vault_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
