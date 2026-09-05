//! The per-(local repository, vault) pin — §7.4's trust-on-first-use memory —
//! and the reader acceptance battery, plus the §8.4 write-side allocation
//! guard. The battery's semantics follow the normative formal model
//! (`spec/sealed_v2.qnt`: `accepts`, `doRead`, `doPush`).
//!
//! Storage (`PinStore`), under `<GIT_DIR>/sealed`:
//!
//! ```text
//! lock                        the repository-wide §6.1 lock (vaultrepo.rs)
//! urls/<sha256(url)>/vault    the vault identity this URL is bound to
//! urls/<sha256(url)>/url      the URL itself (for messages only)
//! urls/<sha256(url)>/...      mirror and scratch space (vaultrepo.rs)
//! vaults/<vault-id>/pin.json  ONE pin per vault, shared by every URL
//! <sha256(url)>/pin/pin.json  the 0.1.0 layout: one pin per URL, migrated
//! ```
//!
//! Why two keys. The pin is keyed by VAULT identity because every URL that
//! reaches one vault — an SSH and an HTTPS spelling, a path with and
//! without a trailing slash — must share one memory: with a pin per URL, a
//! host could replay an old generation through whichever URL had the
//! older memory (§7.4). But a pin looked up by the manifest's OWN vault id
//! would let a substituted vault at a familiar URL simply meet a fresh
//! pin, which is what the vault identity check exists to refuse. So each
//! URL additionally keeps a durable association with the vault identity
//! first seen through it, checked before any pin is consulted.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::json::Json;
use crate::manifest::{Manifest, ObjectFormat};
use crate::sha256_hex;

const PIN_FILE: &str = "pin.json";
const URLS_DIR: &str = "urls";
const VAULTS_DIR: &str = "vaults";
/// Per-URL: the vault identity this URL is bound to (`<hex>\n`).
const ASSOCIATION_FILE: &str = "vault";
/// Per-URL: the URL spelling itself, so messages can name it.
const URL_FILE: &str = "url";
/// The 0.1.0 layout kept the pin in a `pin` subdirectory of the URL's
/// state directory, which sat directly under the root.
const LEGACY_PIN_SUBDIR: &str = "pin";

/// §7.4: everything this device remembers about one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Pinned on first contact; any later difference is INVALID.
    pub vault_id: String,
    /// Highest counter ever accepted.
    pub counter: u64,
    /// SHA-256 (lowercase hex) of the manifest ciphertext behind `counter` —
    /// the twin check's witness.
    pub manifest_digest: String,
    /// §7.4: format is monotone; a lower `format` is INVALID.
    pub format: u64,
    /// §7.4: objectformat is equality-pinned.
    pub object_format: ObjectFormat,
    /// §7.4: monotone nondecreasing.
    pub seqfloor: u64,
    /// §7.4 sequence memory, CONFIRMED half: every (sequence number ->
    /// bundle ciphertext digest) binding ever accepted. One learned from a
    /// manifest lands here only once its bundle is applied; this device's
    /// OWN writes land here on acknowledgement, including the numbers their
    /// `seqfloor` burned — those name no published bundle at all, and §7.4
    /// note 7e says why that cannot lose objects. Never pruned. Doubles as
    /// the applied-bundle record of §6 steps 4-5.
    pub sequence_memory: BTreeMap<u64, String>,
    /// §7.4 sequence memory, PENDING half: a (sequence number -> bundle
    /// ciphertext digest) binding this device wrote down before a push whose
    /// outcome it never learned (a dropped connection, a lost status
    /// report). It says nothing about the vault — the host may never have
    /// taken that write — so it takes NO part in the reader's rebinding
    /// check. It binds the number for THIS device only: §8.4 allocation
    /// skips it. That is what keeps a lost acknowledgement from ever
    /// re-binding a number to different content, without wedging the writer
    /// the way refusing the number outright did.
    pub pending: BTreeMap<u64, String>,
}

/// The fate of this device's PENDING bindings, judged against a manifest
/// that just passed the battery (§8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingResolution {
    /// The published line binds the number to OUR ciphertext: the push
    /// landed after all. Confirmed — it moves into the sequence memory.
    pub promoted: BTreeMap<u64, String>,
    /// Still ahead of the published `seqfloor`: the fate is still unknown.
    pub pending: BTreeMap<u64, String>,
}

#[derive(Debug)]
pub enum PinError {
    /// §7.4: `vault` differs from the pinned identity (whole-vault
    /// substitution).
    VaultMismatch { pinned: String, seen: String },
    /// §7.4: counter lower than the highest previously seen.
    Rollback { pinned: u64, seen: u64 },
    /// §7.4: equal counter, different manifest ciphertext (a forked twin).
    Twin { counter: u64 },
    /// §7.4: `format` lower than the pinned format — same error family as
    /// rollback.
    FormatRegression { pinned: u64, seen: u64 },
    /// §7.4: objectformat changed after first sight.
    ObjectFormatChanged {
        pinned: ObjectFormat,
        seen: ObjectFormat,
    },
    /// §7.4: seqfloor decreased.
    SeqfloorRegression { pinned: u64, seen: u64 },
    /// §7.4: a manifest binds a remembered sequence number to a different
    /// digest — same error family as rollback.
    SequenceRebound { seq: u64 },
    /// §7.4: a pinned reader sees an empty vault (no manifest at all) —
    /// refusing this stops rollback-via-reinitialization.
    EmptyVaultWithPin,
    /// §8.4 allocation guard: the writer would allocate a sequence number
    /// already in its memory; the fetched base predates this device's own
    /// history. Refuse and refetch.
    AllocationCollision { seq: u64 },
    /// §8.4: allocation ran off the end of the sequence space while
    /// skipping this device's own pending bindings.
    SequenceExhausted,
    /// Two security records for the same vault disagree (the 0.1.0
    /// per-URL pins being merged, §7.4): this repository saw two different
    /// histories of one vault through two URLs. Nothing is changed.
    Incompatible { vault_id: String, detail: String },
    /// Pin file unreadable/unwritable.
    Io(String),
    /// Pin file exists but does not parse as a pin record.
    Corrupt(String),
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PinError::VaultMismatch { pinned, seen } => write!(
                f,
                "vault identity changed (pinned {pinned}, manifest says {seen}): this is not the vault this repository was paired with"
            ),
            PinError::Rollback { pinned, seen } => write!(
                f,
                "vault rolled back: manifest counter {seen} is below the last accepted counter {pinned}"
            ),
            PinError::Twin { counter } => write!(
                f,
                "vault forked: a different manifest with the already-seen counter {counter}"
            ),
            PinError::FormatRegression { pinned, seen } => write!(
                f,
                "vault format regressed from {pinned} to {seen}: proof of a fork or rollback"
            ),
            PinError::ObjectFormatChanged { pinned, seen } => write!(
                f,
                "vault objectformat changed from {} to {}",
                pinned.as_str(),
                seen.as_str()
            ),
            PinError::SeqfloorRegression { pinned, seen } => write!(
                f,
                "vault seqfloor regressed from {pinned} to {seen}"
            ),
            PinError::SequenceRebound { seq } => write!(
                f,
                "sequence number {seq} is bound to a different bundle than this device accepted before"
            ),
            PinError::EmptyVaultWithPin => write!(
                f,
                "the remote presents an empty vault, but this repository has pinned state for it"
            ),
            PinError::AllocationCollision { seq } => write!(
                f,
                "refusing to allocate sequence number {seq}: this device has already seen it; the fetched vault state is stale — fetch again"
            ),
            PinError::SequenceExhausted => write!(
                f,
                "the vault's sequence space is exhausted"
            ),
            PinError::Incompatible { vault_id, detail } => write!(
                f,
                "the security records this repository kept for vault {vault_id} under two remote URLs disagree ({detail}). Two URLs of one vault must share one memory, but these two saw different histories: a rolled-back or forked vault was served through one of them, or the records are corrupt. Nothing was changed. Decide which URL saw the honest history, then discard the other's record with `git-remote-sealed forget --yes <that-url>`"
            ),
            PinError::Io(e) => write!(f, "pin store I/O error: {e}"),
            PinError::Corrupt(e) => write!(f, "pin store is corrupt: {e}"),
        }
    }
}

impl std::error::Error for PinError {}

/// §7.4: run the full acceptance battery for one manifest read, and produce
/// the advanced pin the caller MUST persist on acceptance. `prev == None`
/// means first contact (trust on first use).
///
/// `manifest_ciphertext_digest` is the SHA-256 hex of the `sealed-manifest.age`
/// ciphertext as fetched (the twin check compares ciphertexts).
pub fn validate_and_advance(
    prev: Option<&Pin>,
    manifest: &Manifest,
    manifest_ciphertext_digest: &str,
) -> Result<Pin, PinError> {
    if let Some(pin) = prev {
        // §7.4 vault identity: pinned on first contact, equality forever.
        if pin.vault_id != manifest.vault_id {
            return Err(PinError::VaultMismatch {
                pinned: pin.vault_id.clone(),
                seen: manifest.vault_id.clone(),
            });
        }
        // §7.4 counter monotonicity + twin check (model: `accepts`).
        if manifest.counter < pin.counter {
            return Err(PinError::Rollback {
                pinned: pin.counter,
                seen: manifest.counter,
            });
        }
        if manifest.counter == pin.counter && manifest_ciphertext_digest != pin.manifest_digest {
            return Err(PinError::Twin {
                counter: manifest.counter,
            });
        }
        // §7.4 format monotone.
        if manifest.format < pin.format {
            return Err(PinError::FormatRegression {
                pinned: pin.format,
                seen: manifest.format,
            });
        }
        // §7.4 objectformat equality.
        if manifest.object_format != pin.object_format {
            return Err(PinError::ObjectFormatChanged {
                pinned: pin.object_format,
                seen: manifest.object_format,
            });
        }
        // §7.4 seqfloor monotone nondecreasing.
        if manifest.seqfloor < pin.seqfloor {
            return Err(PinError::SeqfloorRegression {
                pinned: pin.seqfloor,
                seen: manifest.seqfloor,
            });
        }
        // §7.4 sequence memory: re-binding a remembered sequence number is a
        // hard error (model: PIN_SEQDIGESTS conjunct of `accepts`).
        for (seq, record) in &manifest.bundles {
            if let Some(remembered) = pin.sequence_memory.get(seq) {
                if *remembered != record.digest {
                    return Err(PinError::SequenceRebound { seq: *seq });
                }
            }
        }
    }

    // Accepted: advance (model: doRead's pin'/seen' updates — the seqfloor
    // max() is an identity here given the monotonicity check above, and the
    // memory is unioned, never replaced).
    let mut sequence_memory = prev.map(|p| p.sequence_memory.clone()).unwrap_or_default();
    for (seq, record) in &manifest.bundles {
        sequence_memory.insert(*seq, record.digest.clone());
    }
    // §8.4: a pending binding the published line confirms is already in
    // `sequence_memory` (the loop above listed it); the rest either drop out
    // or stay pending.
    let resolution = resolve_pending(prev, manifest);
    Ok(Pin {
        vault_id: manifest.vault_id.clone(),
        counter: manifest.counter,
        manifest_digest: manifest_ciphertext_digest.to_owned(),
        format: manifest.format,
        object_format: manifest.object_format,
        seqfloor: prev.map_or(manifest.seqfloor, |p| p.seqfloor.max(manifest.seqfloor)),
        sequence_memory,
        pending: resolution.pending,
    })
}

/// §8.4: judge this device's PENDING bindings against a manifest that just
/// passed the battery.
///
/// - The manifest binds the number to our own ciphertext -> the push landed
///   (however the transport ended): CONFIRM it.
/// - The published `seqfloor` has reached the number without binding it to
///   us -> our write is not in this line, and the number is burned for every
///   writer by that same `seqfloor`: forget it.
/// - The number is still above `seqfloor` -> nobody has published it; the
///   fate of our write is still unknown. Keep it pending, so §8.4 allocation
///   keeps skipping it.
pub fn resolve_pending(prev: Option<&Pin>, manifest: &Manifest) -> PendingResolution {
    let mut promoted = BTreeMap::new();
    let mut pending = BTreeMap::new();
    if let Some(prev) = prev {
        for (seq, digest) in &prev.pending {
            match manifest.bundles.get(seq) {
                Some(record) if record.digest == *digest => {
                    promoted.insert(*seq, digest.clone());
                }
                _ if manifest.seqfloor >= *seq => {}
                _ => {
                    pending.insert(*seq, digest.clone());
                }
            }
        }
    }
    PendingResolution { promoted, pending }
}

/// §8.4: on acknowledgment, every PENDING binding at or below the `seqfloor`
/// this device just published becomes CONFIRMED.
///
/// Our own new bundle is one of them — the manifest binds it to our digest.
/// The rest are numbers `allocate_from` skipped, and publishing this
/// `seqfloor` has now burned them: no honest continuation of this line can
/// ever bind one. The generation we just wrote does not list them (its bundle
/// list is the base's, whose every sequence is at or below a `seqfloor` lower
/// than these, plus our own); no ancestor lists them for the same reason; and
/// every later writer allocates above a `seqfloor` that is already past them.
/// A concurrent writer that had taken one would have shown it in our own
/// base, where the read settled it instead. So from here a manifest that
/// binds one of these numbers to anything else is a fork, and the device gets
/// the full §7.4 rebinding check back — the guess has become an observation.
pub fn confirm_acked(pin: &mut Pin, published_seqfloor: u64) {
    let burned: Vec<u64> = pin
        .pending
        .keys()
        .copied()
        .filter(|seq| *seq <= published_seqfloor)
        .collect();
    for seq in burned {
        if let Some(digest) = pin.pending.remove(&seq) {
            pin.sequence_memory.insert(seq, digest);
        }
    }
}

/// §8.4 allocation: the lowest sequence number at or above `first` that this
/// device has not already bound.
///
/// `first` is `seqfloor + 1`. A CONFIRMED binding there is not a race: it is
/// proof that the base we fetched predates our own acknowledged history (the
/// host replayed a state we have already moved past), so we refuse and ask
/// for a refetch — the §8.4 guard, unchanged. A PENDING binding is a
/// different situation: we published, or tried to, and never learned the
/// outcome. Re-binding that number would be the sequence reuse the guard
/// exists to stop, and refusing it would wedge the writer for good (an
/// everyday dropped push). So we leave the number unpublished and take the
/// next one; the published `seqfloor` then burns it for every writer.
pub fn allocate_from(
    memory: &BTreeMap<u64, String>,
    pending: &BTreeMap<u64, String>,
    first: u64,
) -> Result<u64, PinError> {
    let mut seq = first;
    loop {
        if memory.contains_key(&seq) {
            return Err(PinError::AllocationCollision { seq });
        }
        if !pending.contains_key(&seq) {
            return Ok(seq);
        }
        seq = seq
            .checked_add(1)
            .filter(|s| *s <= crate::names::MAX_SEQ)
            .ok_or(PinError::SequenceExhausted)?;
    }
}

/// §7.4 (last paragraph): a pinned reader MUST treat an empty vault — no
/// manifest at all — as an error. Call when the remote presents no
/// `sealed-manifest.age`. `pinned` is true when this repository holds a
/// pin for the vault the URL is bound to, or the URL is bound to a vault
/// at all (a binding whose pin is gone still says a vault lived here).
pub fn check_empty_vault(pinned: bool) -> Result<(), PinError> {
    if pinned {
        Err(PinError::EmptyVaultWithPin)
    } else {
        Ok(())
    }
}

/// §8.4 allocation guard (write side of the sequence memory): a writer MUST
/// NOT allocate a sequence number present in its memory.
pub fn check_allocation(pin: &Pin, seq: u64) -> Result<(), PinError> {
    if pin.sequence_memory.contains_key(&seq) {
        return Err(PinError::AllocationCollision { seq });
    }
    Ok(())
}

// --- storage ---

/// The state key of a remote URL: `sha256(url)`, lowercase hex. Keyed by
/// the spelling, deliberately: normalizing URLs cannot make `ssh://` and
/// `https://` spellings of one vault coincide, which is why the pin is
/// keyed by vault identity instead (module comment).
pub fn url_key(url: &str) -> String {
    sha256_hex(url.as_bytes())
}

/// What `forget_url` did (§7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forgotten {
    /// The vault identity the URL was bound to, if any.
    pub vault_id: Option<String>,
    /// The vault's pin and sequence memory were discarded: no other URL of
    /// this repository was bound to it.
    pub pin_removed: bool,
    /// The pin was KEPT, because these other URLs (spellings where known,
    /// state keys otherwise) are still bound to the vault.
    pub kept_for: Vec<String>,
}

/// This repository's pins and URL bindings, rooted at `<GIT_DIR>/sealed`.
/// Every method assumes the caller holds the repository-wide lock
/// (`VaultRepo`), except the read-only `load_for_url` that `info` uses.
pub struct PinStore {
    root: PathBuf,
}

impl PinStore {
    pub fn new(root: &Path) -> PinStore {
        PinStore {
            root: root.to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<root>/urls/<key>` — the per-URL state directory.
    pub fn url_dir(&self, url: &str) -> PathBuf {
        self.url_dir_by_key(&url_key(url))
    }

    fn url_dir_by_key(&self, key: &str) -> PathBuf {
        self.root.join(URLS_DIR).join(key)
    }

    /// `<root>/vaults/<vault-id>` — where the shared pin lives.
    pub fn vault_dir(&self, vault_id: &str) -> PathBuf {
        self.root.join(VAULTS_DIR).join(vault_id)
    }

    /// The 0.1.0 state directory of this URL.
    fn legacy_dir(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }

    /// §7.4: the vault identity this URL is bound to. `Ok(None)` means no
    /// pin was ever saved through this URL. A binding that does not parse
    /// is an error, never first contact (fail-closed).
    pub fn association(&self, url: &str) -> Result<Option<String>, PinError> {
        self.association_by_key(&url_key(url))
    }

    fn association_by_key(&self, key: &str) -> Result<Option<String>, PinError> {
        let path = self.url_dir_by_key(key).join(ASSOCIATION_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(PinError::Io(format!("{}: {e}", path.display()))),
        };
        let id = text.trim_end_matches('\n');
        if !crate::manifest::is_vault_id(id) {
            return Err(PinError::Corrupt(format!(
                "{}: not a vault identity: {id:?}",
                path.display()
            )));
        }
        Ok(Some(id.to_owned()))
    }

    /// Bind `key` to `vault_id`, durably, and remember the spelling when
    /// known. A different existing binding is a bug in the caller (the
    /// reader checks the binding before it can reach a save): refuse.
    fn associate(&self, key: &str, vault_id: &str, url: Option<&str>) -> Result<(), PinError> {
        match self.association_by_key(key)? {
            Some(bound) if bound != vault_id => {
                return Err(PinError::VaultMismatch {
                    pinned: bound,
                    seen: vault_id.to_owned(),
                });
            }
            Some(_) => {}
            None => {
                let path = self.url_dir_by_key(key).join(ASSOCIATION_FILE);
                crate::durable::write_file(&path, format!("{vault_id}\n").as_bytes())
                    .map_err(|e| PinError::Io(format!("{}: {e}", path.display())))?;
            }
        }
        if let Some(url) = url {
            let path = self.url_dir_by_key(key).join(URL_FILE);
            if !path.exists() {
                // Diagnostics only: the association is what carries the
                // security meaning, so this write is best effort.
                let _ = fs::write(&path, format!("{url}\n"));
            }
        }
        Ok(())
    }

    /// The shared pin of a vault. `Ok(None)` means this repository has no
    /// memory of that vault through any URL.
    pub fn load_vault(&self, vault_id: &str) -> Result<Option<Pin>, PinError> {
        if !crate::manifest::is_vault_id(vault_id) {
            return Err(PinError::Corrupt(format!(
                "not a vault identity: {vault_id:?}"
            )));
        }
        let pin = load(&self.vault_dir(vault_id))?;
        if let Some(pin) = &pin {
            if pin.vault_id != vault_id {
                return Err(PinError::Corrupt(format!(
                    "{} holds a pin for vault {}",
                    self.vault_dir(vault_id).display(),
                    pin.vault_id
                )));
            }
        }
        Ok(pin)
    }

    /// The pin a URL is bound to, read straight from the files (no lock, no
    /// migration): what `info` shows. Falls back to the 0.1.0 per-URL pin
    /// so an upgraded repository shows its memory before its first
    /// operation migrates it.
    pub fn load_for_url(&self, url: &str) -> Result<Option<Pin>, PinError> {
        let key = url_key(url);
        match self.association_by_key(&key)? {
            Some(vault_id) => self.load_vault(&vault_id),
            None => load(&self.legacy_dir(&key).join(LEGACY_PIN_SUBDIR)),
        }
    }

    /// Persist `pin` as the vault's shared pin, reached through `url`:
    /// bind the URL first (durably), then save the pin before returning.
    /// Writers must not upload until this succeeds (§8.4's pending
    /// binding).
    pub fn save(&self, url: &str, pin: &Pin) -> Result<(), PinError> {
        self.associate(&url_key(url), &pin.vault_id, Some(url))?;
        save(&self.vault_dir(&pin.vault_id), pin)
    }

    /// Delete a vault's pin file (a writer withdrawing a first-contact
    /// binding after a definitive rejection). Absence is not an error.
    pub fn remove_vault(&self, vault_id: &str) -> Result<(), PinError> {
        remove(&self.vault_dir(vault_id))
    }

    /// Every URL bound to `vault_id`: the spelling where known, else the
    /// state key.
    pub fn urls_of_vault(&self, vault_id: &str) -> Result<Vec<String>, PinError> {
        let urls = self.root.join(URLS_DIR);
        let entries = match fs::read_dir(&urls) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(PinError::Io(format!("{}: {e}", urls.display()))),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| PinError::Io(format!("{}: {e}", urls.display())))?;
            let key = entry.file_name().to_string_lossy().into_owned();
            if self.association_by_key(&key)?.as_deref() != Some(vault_id) {
                continue;
            }
            let spelling = fs::read_to_string(entry.path().join(URL_FILE))
                .ok()
                .map(|t| t.trim_end_matches('\n').to_owned())
                .filter(|t| !t.is_empty());
            out.push(spelling.unwrap_or(key));
        }
        out.sort();
        Ok(out)
    }

    /// §7.5 `forget` for one URL: discard its binding, mirror and scratch
    /// space, its 0.1.0 state directory if one is still there, and the
    /// vault's pin — but ONLY when no other URL of this repository is
    /// bound to that vault. A partial discard must never weaken what
    /// another URL still relies on; §7.4's per-vault lookup means the
    /// legitimate use (a vault re-created at this URL, with a new
    /// identity) is never blocked by keeping it.
    pub fn forget_url(&self, url: &str) -> Result<Forgotten, PinError> {
        let key = url_key(url);
        // A binding that fails to parse still names no vault we can act on;
        // the URL's state goes regardless.
        let vault_id = self.association_by_key(&key).ok().flatten();
        remove_tree(&self.url_dir_by_key(&key))?;
        remove_tree(&self.legacy_dir(&key))?;
        let mut forgotten = Forgotten {
            vault_id: vault_id.clone(),
            pin_removed: false,
            kept_for: Vec::new(),
        };
        if let Some(vault_id) = vault_id {
            let others = self.urls_of_vault(&vault_id)?;
            if others.is_empty() {
                remove_tree(&self.vault_dir(&vault_id))?;
                forgotten.pin_removed = true;
            } else {
                forgotten.kept_for = others;
            }
        }
        Ok(forgotten)
    }

    /// Discard the 0.1.0 state directory of `url` WITHOUT merging its pin
    /// — `forget` before migration, so a record the user wants gone can
    /// never block the migration of the others.
    pub fn discard_legacy(&self, url: &str) -> Result<(), PinError> {
        remove_tree(&self.legacy_dir(&url_key(url)))
    }

    /// Bring 0.1.0 state up to this layout. Each per-URL pin is merged
    /// into its vault's shared pin (`merge`: every confirmed binding of
    /// every record survives — picking the record with the highest counter
    /// would discard security memory), the URL is bound to that vault, and
    /// the old directory is removed. Idempotent: a crash midway leaves
    /// records that merge again to the same result. Records that
    /// contradict each other stop the migration (`PinError::Incompatible`)
    /// with nothing changed for that vault.
    pub fn migrate_legacy(&self) -> Result<(), PinError> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(PinError::Io(format!("{}: {e}", self.root.display()))),
        };
        let mut legacy: Vec<String> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| PinError::Io(format!("{}: {e}", self.root.display())))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_key =
                name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if is_key && entry.path().is_dir() {
                legacy.push(name);
            }
        }
        legacy.sort();
        for key in legacy {
            let dir = self.legacy_dir(&key);
            let pin_dir = dir.join(LEGACY_PIN_SUBDIR);
            let pin = load(&pin_dir).map_err(|e| match e {
                PinError::Corrupt(detail) => {
                    PinError::Corrupt(format!("{}: {detail}", pin_dir.join(PIN_FILE).display()))
                }
                e => e,
            })?;
            if let Some(pin) = pin {
                let merged = match self.load_vault(&pin.vault_id)? {
                    Some(shared) => merge(&shared, &pin)?,
                    None => pin.clone(),
                };
                save(&self.vault_dir(&pin.vault_id), &merged)?;
                self.associate(&key, &pin.vault_id, None)?;
            }
            remove_tree(&dir)?;
        }
        Ok(())
    }
}

/// §7.4: two records of ONE vault, as one. Everything either record is
/// evidence for, the result is evidence for:
///
/// - counter and twin digest: the higher counter's; an equal counter with
///   a different digest is a forked twin seen through two URLs, and the
///   records are incompatible;
/// - format and seqfloor: the maximum (both monotone);
/// - objectformat: must agree;
/// - confirmed bindings: the union; one number bound to two digests is a
///   rebinding, and the records are incompatible;
/// - pending bindings: settled against the merged confirmed half by §7.4's
///   rule — a number the other record CONFIRMED to the same digest is
///   confirmed (the push landed); one it confirmed to a different digest
///   drops out (another writer took the number: not evidence, §7.4 note
///   7g); the rest stay pending for the next accepted read to settle. A
///   number both records left pending with different digests keeps the
///   lexically smaller one: a pending entry only makes allocation skip the
///   number, which either digest does equally.
pub fn merge(a: &Pin, b: &Pin) -> Result<Pin, PinError> {
    let incompatible = |detail: String| PinError::Incompatible {
        vault_id: a.vault_id.clone(),
        detail,
    };
    if a.vault_id != b.vault_id {
        return Err(incompatible(format!(
            "vault {} versus vault {}",
            a.vault_id, b.vault_id
        )));
    }
    if a.object_format != b.object_format {
        return Err(incompatible(format!(
            "objectformat {} versus {}",
            a.object_format.as_str(),
            b.object_format.as_str()
        )));
    }
    let (counter, manifest_digest) = match a.counter.cmp(&b.counter) {
        std::cmp::Ordering::Greater => (a.counter, a.manifest_digest.clone()),
        std::cmp::Ordering::Less => (b.counter, b.manifest_digest.clone()),
        std::cmp::Ordering::Equal if a.manifest_digest == b.manifest_digest => {
            (a.counter, a.manifest_digest.clone())
        }
        std::cmp::Ordering::Equal => {
            return Err(incompatible(format!(
                "two different manifests at counter {}",
                a.counter
            )));
        }
    };
    let mut sequence_memory = a.sequence_memory.clone();
    for (seq, digest) in &b.sequence_memory {
        match sequence_memory.get(seq) {
            Some(known) if known != digest => {
                return Err(incompatible(format!(
                    "sequence number {seq} bound to two different bundles"
                )));
            }
            _ => {
                sequence_memory.insert(*seq, digest.clone());
            }
        }
    }
    let mut pending = BTreeMap::new();
    for (seq, digest) in a.pending.iter().chain(&b.pending) {
        match sequence_memory.get(seq) {
            Some(known) if known == digest => {}
            Some(_) => {}
            None => {
                pending
                    .entry(*seq)
                    .and_modify(|held: &mut String| {
                        if digest < held {
                            *held = digest.clone();
                        }
                    })
                    .or_insert_with(|| digest.clone());
            }
        }
    }
    Ok(Pin {
        vault_id: a.vault_id.clone(),
        counter,
        manifest_digest,
        format: a.format.max(b.format),
        object_format: a.object_format,
        seqfloor: a.seqfloor.max(b.seqfloor),
        sequence_memory,
        pending,
    })
}

fn remove_tree(dir: &Path) -> Result<(), PinError> {
    match fs::remove_dir_all(dir) {
        Ok(()) => {
            let parent = dir.parent().unwrap_or(Path::new("."));
            crate::durable::sync_dir(parent)
                .map_err(|e| PinError::Io(format!("sync {}: {e}", parent.display())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PinError::Io(format!("{}: {e}", dir.display()))),
    }
}

/// Load the pin file in `dir`. `Ok(None)` means no pin file.
pub fn load(dir: &Path) -> Result<Option<Pin>, PinError> {
    let path = dir.join(PIN_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PinError::Io(format!("{}: {e}", path.display()))),
    };
    let json = Json::parse(&text).map_err(|e| PinError::Corrupt(e.to_string()))?;
    let pin = pin_from_json(&json)?;
    Ok(Some(pin))
}

/// Persist the pin file in `dir` before returning: save the temporary
/// file's contents, atomically rename it, then save the directory entry.
pub fn save(dir: &Path, pin: &Pin) -> Result<(), PinError> {
    save_with_sync(dir, pin, fs::File::sync_all)
}

fn save_with_sync(
    dir: &Path,
    pin: &Pin,
    sync: impl Fn(&fs::File) -> std::io::Result<()>,
) -> Result<(), PinError> {
    let path = dir.join(PIN_FILE);
    crate::durable::write_file_with_sync(&path, pin_to_json(pin).render().as_bytes(), sync)
        .map_err(|e| PinError::Io(format!("{}: {e}", path.display())))
}

/// Delete the pin file in `dir`. Absence is not an error.
pub fn remove(dir: &Path) -> Result<(), PinError> {
    crate::durable::remove_file(&dir.join(PIN_FILE))
        .map_err(|e| PinError::Io(format!("{}: {e}", dir.join(PIN_FILE).display())))
}

fn pin_to_json(pin: &Pin) -> Json {
    Json::Obj(vec![
        ("vault".into(), Json::Str(pin.vault_id.clone())),
        ("counter".into(), Json::Num(pin.counter)),
        (
            "manifest_digest".into(),
            Json::Str(pin.manifest_digest.clone()),
        ),
        ("format".into(), Json::Num(pin.format)),
        (
            "objectformat".into(),
            Json::Str(pin.object_format.as_str().into()),
        ),
        ("seqfloor".into(), Json::Num(pin.seqfloor)),
        (
            "sequence_memory".into(),
            Json::Obj(
                pin.sequence_memory
                    .iter()
                    .map(|(seq, digest)| (seq.to_string(), Json::Str(digest.clone())))
                    .collect(),
            ),
        ),
        (
            "pending".into(),
            Json::Obj(
                pin.pending
                    .iter()
                    .map(|(seq, digest)| (seq.to_string(), Json::Str(digest.clone())))
                    .collect(),
            ),
        ),
    ])
}

fn pin_from_json(json: &Json) -> Result<Pin, PinError> {
    let field = |key: &str| {
        json.get(key)
            .ok_or_else(|| PinError::Corrupt(format!("missing field {key:?}")))
    };
    let str_field = |key: &str| {
        field(key)?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| PinError::Corrupt(format!("field {key:?} is not a string")))
    };
    let num_field = |key: &str| {
        field(key)?
            .as_num()
            .ok_or_else(|| PinError::Corrupt(format!("field {key:?} is not a number")))
    };

    let vault_id = str_field("vault")?;
    // The identity names a directory (`vaults/<id>`): only §7.2's grammar
    // may ever reach a path.
    if !crate::manifest::is_vault_id(&vault_id) {
        return Err(PinError::Corrupt(format!(
            "bad vault identity {vault_id:?}"
        )));
    }
    let object_format = ObjectFormat::from_str_exact(&str_field("objectformat")?)
        .ok_or_else(|| PinError::Corrupt("unknown objectformat".into()))?;
    let sequence_memory = seq_map(field("sequence_memory")?, "sequence_memory")?;
    // A pin written before §8.4 grew its pending half has no `pending` key.
    let pending = match json.get("pending") {
        Some(value) => seq_map(value, "pending")?,
        None => BTreeMap::new(),
    };

    Ok(Pin {
        vault_id,
        counter: num_field("counter")?,
        manifest_digest: str_field("manifest_digest")?,
        format: num_field("format")?,
        object_format,
        seqfloor: num_field("seqfloor")?,
        sequence_memory,
        pending,
    })
}

/// A `{ "<seq>": "<digest>" }` object, as both halves of the memory are
/// stored.
fn seq_map(value: &Json, what: &str) -> Result<BTreeMap<u64, String>, PinError> {
    let Json::Obj(fields) = value else {
        return Err(PinError::Corrupt(format!("{what} is not an object")));
    };
    let mut out = BTreeMap::new();
    for (key, value) in fields {
        let seq = crate::names::parse_canonical(key)
            .ok_or_else(|| PinError::Corrupt(format!("bad sequence key {key:?} in {what}")))?;
        let digest = value
            .as_str()
            .ok_or_else(|| PinError::Corrupt(format!("digest for seq {seq} is not a string")))?;
        if out.insert(seq, digest.to_owned()).is_some() {
            return Err(PinError::Corrupt(format!("duplicate sequence key {seq}")));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{BundleRecord, ObjectFormat};
    use std::collections::BTreeMap;

    const D_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const D_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CIPHER_1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const CIPHER_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const VAULT: &str = "3f9a6c0e6d1b4b0d9a4f2e7c8b5a1d02";

    fn manifest(counter: u64, seqfloor: u64, bundles: &[(u64, bool, &str)]) -> Manifest {
        Manifest {
            format: 2,
            object_format: ObjectFormat::Sha1,
            vault_id: VAULT.into(),
            counter,
            seqfloor,
            bundles: bundles
                .iter()
                .map(|(seq, full, digest)| {
                    (
                        *seq,
                        BundleRecord {
                            seq: *seq,
                            full: *full,
                            digest: (*digest).into(),
                            chunks: None,
                        },
                    )
                })
                .collect(),
            head: None,
            refs: BTreeMap::new(),
        }
    }

    fn first_contact() -> Pin {
        let m = manifest(2, 2, &[(1, true, D_A), (2, false, D_B)]);
        validate_and_advance(None, &m, CIPHER_1).expect("first contact must pin")
    }

    #[test]
    fn first_contact_pins_everything() {
        let pin = first_contact();
        assert_eq!(pin.vault_id, VAULT);
        assert_eq!(pin.counter, 2);
        assert_eq!(pin.manifest_digest, CIPHER_1);
        assert_eq!(pin.format, 2);
        assert_eq!(pin.object_format, ObjectFormat::Sha1);
        assert_eq!(pin.seqfloor, 2);
        assert_eq!(pin.sequence_memory[&1], D_A);
        assert_eq!(pin.sequence_memory[&2], D_B);
    }

    #[test]
    fn same_manifest_is_re_accepted() {
        let pin = first_contact();
        let m = manifest(2, 2, &[(1, true, D_A), (2, false, D_B)]);
        let again = validate_and_advance(Some(&pin), &m, CIPHER_1).expect("idempotent read");
        assert_eq!(again, pin);
    }

    #[test]
    fn rollback_rejected() {
        // §7.4: counter lower than the highest previously seen.
        let pin = first_contact();
        let m = manifest(1, 1, &[(1, true, D_A)]);
        assert!(matches!(
            validate_and_advance(Some(&pin), &m, CIPHER_2),
            Err(PinError::Rollback { pinned: 2, seen: 1 })
        ));
    }

    #[test]
    fn twin_rejected() {
        // §7.4: equal counter, different ciphertext — a forked twin.
        let pin = first_contact();
        let m = manifest(2, 2, &[(1, true, D_A), (2, false, D_B)]);
        assert!(matches!(
            validate_and_advance(Some(&pin), &m, CIPHER_2),
            Err(PinError::Twin { counter: 2 })
        ));
    }

    #[test]
    fn seqfloor_regression_rejected() {
        // §7.4: monotone nondecreasing — the fork-hop's intermediate state.
        let pin = first_contact();
        let m = manifest(3, 1, &[(1, true, D_A)]);
        assert!(matches!(
            validate_and_advance(Some(&pin), &m, CIPHER_2),
            Err(PinError::SeqfloorRegression { pinned: 2, seen: 1 })
        ));
    }

    #[test]
    fn sequence_rebinding_rejected() {
        // §7.4 sequence memory; the formal model's headline finding: the
        // caught-up fork passes counter AND seqfloor, only this rule stops it.
        let pin = first_contact();
        let m = manifest(4, 2, &[(1, true, D_A), (2, false, CIPHER_2)]);
        assert!(matches!(
            validate_and_advance(Some(&pin), &m, CIPHER_2),
            Err(PinError::SequenceRebound { seq: 2 })
        ));
    }

    #[test]
    fn format_regression_rejected() {
        // §7.4: format is monotone; regression with an advancing counter is
        // proof of a fork. (A pinned future format also makes this reader
        // refuse anything it can parse, which is fail-closed.)
        let mut pin = first_contact();
        pin.format = 3;
        let m = manifest(5, 2, &[(1, true, D_A), (2, false, D_B)]);
        assert!(matches!(
            validate_and_advance(Some(&pin), &m, CIPHER_2),
            Err(PinError::FormatRegression { pinned: 3, seen: 2 })
        ));
    }

    #[test]
    fn objectformat_change_rejected() {
        let mut pin = first_contact();
        pin.object_format = ObjectFormat::Sha256;
        let m = manifest(5, 2, &[(1, true, D_A), (2, false, D_B)]);
        assert!(matches!(
            validate_and_advance(Some(&pin), &m, CIPHER_2),
            Err(PinError::ObjectFormatChanged { .. })
        ));
    }

    #[test]
    fn vault_substitution_rejected() {
        let pin = first_contact();
        let mut m = manifest(9, 9, &[]);
        m.vault_id = "00000000000000000000000000000000".into();
        assert!(matches!(
            validate_and_advance(Some(&pin), &m, CIPHER_2),
            Err(PinError::VaultMismatch { .. })
        ));
    }

    #[test]
    fn memory_is_unioned_never_replaced() {
        // A compacted generation lists only the new -full bundle; the old
        // bindings must survive (entries are never pruned, §7.4).
        let pin = first_contact();
        let compacted = manifest(3, 3, &[(3, true, CIPHER_2)]);
        let advanced =
            validate_and_advance(Some(&pin), &compacted, CIPHER_2).expect("compaction accepted");
        assert_eq!(advanced.sequence_memory.len(), 3);
        assert_eq!(advanced.sequence_memory[&1], D_A);
        assert_eq!(advanced.sequence_memory[&3], CIPHER_2);
    }

    #[test]
    fn empty_vault_with_pin_rejected() {
        // §7.4: laundering a rollback through re-initialization.
        let pin = first_contact();
        let _ = pin;
        assert!(matches!(
            check_empty_vault(true),
            Err(PinError::EmptyVaultWithPin)
        ));
        check_empty_vault(false).expect("true first contact is fine");
    }

    #[test]
    fn allocation_guard_refuses_remembered_seqs() {
        // §8.4: the write side of the sequence memory.
        let pin = first_contact();
        assert!(matches!(
            check_allocation(&pin, 2),
            Err(PinError::AllocationCollision { seq: 2 })
        ));
        check_allocation(&pin, 3).expect("fresh seq allocates");
    }

    #[test]
    fn allocation_skips_a_pending_binding_and_still_refuses_a_confirmed_one() {
        // §8.4. A CONFIRMED number proves the base we fetched predates our
        // own acknowledged history: refuse and refetch. A PENDING one is our
        // own write of unknown fate: re-binding it would be the reuse the
        // guard exists to stop, and refusing it forever is what used to wedge
        // the writer after a single dropped push. So it is skipped.
        let mut pin = first_contact();
        assert!(matches!(
            allocate_from(&pin.sequence_memory, &pin.pending, 2),
            Err(PinError::AllocationCollision { seq: 2 })
        ));
        assert_eq!(
            allocate_from(&pin.sequence_memory, &pin.pending, 3).expect("free"),
            3
        );
        pin.pending.insert(3, D_A.into());
        pin.pending.insert(4, D_B.into());
        assert_eq!(
            allocate_from(&pin.sequence_memory, &pin.pending, 3).expect("skips both"),
            5
        );
    }

    #[test]
    fn an_acknowledged_push_confirms_the_numbers_it_burned() {
        // §8.4: publishing a seqfloor past a skipped number burns it — no
        // honest continuation of this line can bind it — so the pending
        // guess becomes a confirmed observation, and the §7.4 rebinding
        // check covers it again.
        let mut pin = first_contact();
        pin.pending.insert(3, D_A.into());
        pin.pending.insert(9, D_B.into());

        confirm_acked(&mut pin, 4); // we published seqfloor 4, skipping 3
        assert_eq!(pin.sequence_memory.get(&3), Some(&D_A.to_string()));
        assert_eq!(
            pin.pending.keys().copied().collect::<Vec<_>>(),
            vec![9],
            "9 is above the seqfloor we published: still a guess"
        );

        // Confirmed means the guard refuses it, and a rebinding is INVALID.
        assert!(matches!(
            allocate_from(&pin.sequence_memory, &pin.pending, 3),
            Err(PinError::AllocationCollision { seq: 3 })
        ));
        let m = manifest(3, 4, &[(1, true, D_A), (3, false, D_B)]);
        assert!(matches!(
            validate_and_advance(Some(&pin), &m, CIPHER_2),
            Err(PinError::SequenceRebound { seq: 3 })
        ));
    }

    #[test]
    fn a_pending_binding_the_vault_confirms_is_promoted() {
        // The lost-acknowledgement case (H2): the push did land, the report
        // was lost. The next read finds the number bound to OUR ciphertext.
        let mut pin = first_contact();
        pin.sequence_memory.remove(&2);
        pin.pending.insert(2, D_B.into());
        let m = manifest(3, 2, &[(1, true, D_A), (2, false, D_B)]);

        let r = resolve_pending(Some(&pin), &m);
        assert_eq!(r.promoted.get(&2), Some(&D_B.to_string()));
        assert!(r.pending.is_empty());

        let next = validate_and_advance(Some(&pin), &m, CIPHER_2).expect("accepted");
        assert_eq!(next.sequence_memory.get(&2), Some(&D_B.to_string()));
        assert!(next.pending.is_empty());
    }

    #[test]
    fn a_pending_binding_the_published_line_passed_is_forgotten() {
        // `seqfloor` has reached the number without binding it to us: our
        // write is not in this line, and that same `seqfloor` burns the
        // number for every writer. Nothing left to remember.
        let mut pin = first_contact();
        pin.pending.insert(3, D_A.into());
        let m = manifest(3, 4, &[(1, true, D_A), (2, false, D_B), (4, false, D_B)]);
        let r = resolve_pending(Some(&pin), &m);
        assert!(r.promoted.is_empty());
        assert!(r.pending.is_empty(), "{:?}", r.pending);
    }

    #[test]
    fn a_pending_binding_ahead_of_seqfloor_stays_pending_and_is_not_fork_evidence() {
        let mut pin = first_contact();
        pin.pending.insert(3, D_A.into());
        let m = manifest(3, 2, &[(1, true, D_A), (2, false, D_B)]);
        assert_eq!(
            resolve_pending(Some(&pin), &m).pending.get(&3),
            Some(&D_A.to_string())
        );

        // A manifest binding 3 to a DIFFERENT bundle is not a fork: we never
        // learned that our own write landed, so another writer taking the
        // number is an ordinary race. Only the confirmed half is evidence.
        let m = manifest(4, 3, &[(1, true, D_A), (2, false, D_B), (3, false, D_B)]);
        let next = validate_and_advance(Some(&pin), &m, CIPHER_2).expect("accepted");
        assert!(next.pending.is_empty());
    }

    #[test]
    fn a_pin_written_before_the_pending_half_still_loads() {
        let dir = std::env::temp_dir().join(format!("sealed-rs-pinold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(
            dir.join(PIN_FILE),
            format!(
                "{{\"vault\":\"{VAULT}\",\"counter\":2,\"manifest_digest\":\"{CIPHER_1}\",                 \"format\":2,\"objectformat\":\"sha1\",\"seqfloor\":2,                 \"sequence_memory\":{{\"1\":\"{D_A}\"}}}}"
            ),
        )
        .expect("write");
        let pin = load(&dir).expect("readable").expect("pinned");
        assert_eq!(pin.counter, 2);
        assert!(pin.pending.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_load_round_trip() {
        let root = std::env::temp_dir().join(format!("sealed-rs-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("state").join("pin");
        let mut pin = first_contact();
        pin.sequence_memory.insert((1 << 63) - 1, D_B.into());
        pin.pending.insert(7, D_A.into());
        pin.counter = (1 << 63) - 1;

        assert_eq!(load(&dir).expect("readable"), None);
        save(&dir, &pin).expect("writable");
        assert_eq!(load(&dir).expect("readable"), Some(pin));
        remove(&dir).expect("removable");
        assert_eq!(load(&dir).expect("readable"), None);
        remove(&dir).expect("absence is fine");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn failed_sync_never_reports_a_successful_pin_save() {
        let dir = std::env::temp_dir().join(format!("sealed-rs-pinsync-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let old = first_contact();
        let mut pending = old.clone();
        pending.pending.insert(3, D_A.into());

        for fail_directory in [false, true] {
            save(&dir, &old).expect("initial pin");
            let result = save_with_sync(&dir, &pending, |file| {
                if file.metadata()?.is_dir() == fail_directory {
                    Err(std::io::Error::other("injected disk sync failure"))
                } else {
                    file.sync_all()
                }
            });
            assert!(matches!(result, Err(PinError::Io(_))));
            // Failure before rename preserves the old pin. Failure after
            // rename may expose the new pin, but must still stop the push:
            // its directory entry has not been confirmed durable.
            let visible = if fail_directory { &pending } else { &old };
            assert_eq!(load(&dir).expect("valid pin").as_ref(), Some(visible));

            // A leftover temporary file or an uncertain rename must not
            // prevent the next attempt from saving the binding.
            save(&dir, &pending).expect("retry");
            assert_eq!(load(&dir).expect("saved pin"), Some(pending.clone()));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    const URL_A: &str = "git@host:me/vault.git";
    const URL_B: &str = "https://host/me/vault.git";
    const OTHER_VAULT: &str = "00000000000000000000000000000000";

    fn store(tag: &str) -> PinStore {
        let root = std::env::temp_dir().join(format!("sealed-rs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        PinStore::new(&root)
    }

    #[test]
    fn one_pin_per_vault_shared_by_every_url() {
        // §7.4: a pin saved through one spelling is the pin every other
        // spelling of that vault meets — and each spelling is bound to the
        // vault it first saw.
        let s = store("pinshared");
        let pin = first_contact();
        assert_eq!(s.association(URL_A).expect("readable"), None);
        assert_eq!(s.load_vault(VAULT).expect("readable"), None);

        s.save(URL_A, &pin).expect("save via A");
        assert_eq!(s.association(URL_A).expect("bound"), Some(VAULT.into()));
        assert_eq!(s.association(URL_B).expect("unbound"), None);
        assert_eq!(s.load_vault(VAULT).expect("readable"), Some(pin.clone()));
        assert_eq!(s.load_for_url(URL_A).expect("readable"), Some(pin.clone()));
        assert_eq!(s.load_for_url(URL_B).expect("readable"), None);

        let mut stronger = pin.clone();
        stronger.counter = 7;
        s.save(URL_B, &stronger).expect("save via B");
        assert_eq!(s.load_for_url(URL_A).expect("readable"), Some(stronger));
        assert_eq!(
            s.urls_of_vault(VAULT).expect("scan"),
            vec![URL_A.to_string(), URL_B.to_string()]
        );

        // A URL never switches vaults, not even by a buggy caller.
        let mut other = pin.clone();
        other.vault_id = OTHER_VAULT.into();
        assert!(matches!(
            s.save(URL_A, &other),
            Err(PinError::VaultMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(s.root());
    }

    #[test]
    fn forget_keeps_the_pin_another_url_still_relies_on() {
        // §7.5: a partial discard must not weaken what another spelling
        // still relies on. Only the last bound URL takes the pin with it.
        let s = store("pinforget");
        let pin = first_contact();
        s.save(URL_A, &pin).expect("save via A");
        s.save(URL_B, &pin).expect("save via B");

        let f = s.forget_url(URL_A).expect("forget A");
        assert_eq!(f.vault_id.as_deref(), Some(VAULT));
        assert!(!f.pin_removed);
        assert_eq!(f.kept_for, vec![URL_B.to_string()]);
        assert!(!s.url_dir(URL_A).exists());
        assert_eq!(s.association(URL_A).expect("unbound"), None);
        assert_eq!(s.load_vault(VAULT).expect("kept"), Some(pin.clone()));

        let f = s.forget_url(URL_B).expect("forget B");
        assert!(f.pin_removed);
        assert!(f.kept_for.is_empty());
        assert_eq!(s.load_vault(VAULT).expect("gone"), None);

        // Forgetting a URL nothing was ever saved through is fine.
        let f = s.forget_url(URL_A).expect("forget again");
        assert_eq!(f.vault_id, None);
        let _ = std::fs::remove_dir_all(s.root());
    }

    #[test]
    fn merge_keeps_every_confirmed_binding_and_settles_pending_ones() {
        // Two 0.1.0 per-URL records of one vault. Taking the higher counter
        // alone would drop A's bindings for 1 and 2 (B saw the vault only
        // after a compaction listed just 3).
        let a = first_contact(); // counter 2, seqfloor 2, memory {1, 2}
        let mut b = first_contact();
        b.counter = 5;
        b.manifest_digest = CIPHER_2.into();
        b.seqfloor = 3;
        b.sequence_memory = [(3, CIPHER_2.to_string())].into_iter().collect();
        // A's pushes of unknown fate: 3 (B confirmed it to OUR digest),
        // 4 (B confirmed it to another writer's), 5 (nobody knows yet).
        let mut a = a;
        a.pending.insert(3, CIPHER_2.into());
        a.pending.insert(4, D_A.into());
        a.pending.insert(5, D_B.into());
        b.sequence_memory.insert(4, D_B.into());

        let m = merge(&a, &b).expect("compatible");
        assert_eq!((m.counter, m.manifest_digest.as_str()), (5, CIPHER_2));
        assert_eq!(m.seqfloor, 3);
        assert_eq!(
            m.sequence_memory.keys().copied().collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(m.sequence_memory[&1], D_A);
        assert_eq!(
            m.sequence_memory[&4], D_B,
            "the other writer's, as B saw it"
        );
        assert_eq!(
            m.pending,
            [(5, D_B.to_string())].into_iter().collect(),
            "3 was confirmed, 4 dropped as not ours, 5 still unknown"
        );
        // Order does not matter.
        assert_eq!(merge(&b, &a).expect("compatible"), m);

        // Two pending guesses at one number keep one of them: either makes
        // allocation skip the number, which is all a pending entry does.
        let mut c = first_contact();
        c.pending.insert(5, D_A.into());
        assert_eq!(merge(&a, &c).expect("compatible").pending[&5], D_A);
    }

    #[test]
    fn merge_refuses_records_that_contradict_each_other() {
        let a = first_contact();
        let mut twin = first_contact();
        twin.manifest_digest = CIPHER_2.into();
        assert!(matches!(
            merge(&a, &twin),
            Err(PinError::Incompatible { detail, .. }) if detail.contains("counter 2")
        ));
        let mut rebound = first_contact();
        rebound.counter = 9;
        rebound.sequence_memory.insert(2, D_A.into());
        assert!(matches!(
            merge(&a, &rebound),
            Err(PinError::Incompatible { detail, .. }) if detail.contains("sequence number 2")
        ));
        let mut of = first_contact();
        of.object_format = ObjectFormat::Sha256;
        assert!(matches!(merge(&a, &of), Err(PinError::Incompatible { .. })));
    }

    #[test]
    fn legacy_per_url_pins_migrate_into_one_shared_pin() {
        // The 0.1.0 layout: `<root>/<sha256(url)>/pin/pin.json` per URL.
        let s = store("pinmigrate");
        let weak = first_contact(); // counter 2, memory {1, 2}
        let mut strong = first_contact();
        strong.counter = 5;
        strong.manifest_digest = CIPHER_2.into();
        strong.seqfloor = 3;
        strong.sequence_memory = [(3, CIPHER_2.to_string())].into_iter().collect();
        let mut other = first_contact();
        other.vault_id = OTHER_VAULT.into();
        let legacy = |url: &str| s.root().join(url_key(url)).join(LEGACY_PIN_SUBDIR);
        save(&legacy(URL_A), &weak).expect("save");
        save(&legacy(URL_B), &strong).expect("save");
        save(&legacy("other"), &other).expect("save");
        std::fs::create_dir_all(s.root().join(url_key("mirror-only")).join("mirror.git"))
            .expect("mkdir");

        s.migrate_legacy().expect("migrates");
        let shared = s.load_vault(VAULT).expect("readable").expect("migrated");
        assert_eq!(shared.counter, 5);
        assert_eq!(
            shared.sequence_memory.keys().copied().collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the weaker record's bindings survive"
        );
        assert_eq!(s.association(URL_A).expect("bound"), Some(VAULT.into()));
        assert_eq!(s.association(URL_B).expect("bound"), Some(VAULT.into()));
        assert_eq!(
            s.association("other").expect("bound"),
            Some(OTHER_VAULT.into())
        );
        assert_eq!(s.load_vault(OTHER_VAULT).expect("readable"), Some(other));
        for url in [URL_A, URL_B, "other", "mirror-only"] {
            assert!(!s.root().join(url_key(url)).exists(), "{url} dir removed");
        }
        // Running again is a no-op.
        s.migrate_legacy().expect("idempotent");
        assert_eq!(s.load_vault(VAULT).expect("readable"), Some(shared));
        let _ = std::fs::remove_dir_all(s.root());
    }

    #[test]
    fn migration_stops_on_contradicting_records_and_changes_nothing() {
        let s = store("pinmigrate-conflict");
        let a = first_contact();
        let mut twin = first_contact();
        twin.manifest_digest = CIPHER_2.into();
        let legacy = |url: &str| s.root().join(url_key(url)).join(LEGACY_PIN_SUBDIR);
        save(&legacy(URL_A), &a).expect("save");
        save(&legacy(URL_B), &twin).expect("save");

        assert!(matches!(
            s.migrate_legacy(),
            Err(PinError::Incompatible { .. })
        ));
        // The record processed first (state-key order) was merged, having
        // nothing to disagree with; the other was left in place, so the
        // migration can be re-run after the user discards one of them.
        let left: Vec<&str> = [URL_A, URL_B]
            .into_iter()
            .filter(|u| legacy(u).join(PIN_FILE).is_file())
            .collect();
        assert_eq!(left.len(), 1, "exactly one record still waits");
        s.discard_legacy(left[0]).expect("discard");
        s.migrate_legacy().expect("now consistent");
        let shared = s.load_vault(VAULT).expect("readable").expect("migrated");
        assert_eq!(shared.counter, 2);
        assert_eq!(
            s.association(URL_A).is_ok_and(|b| b.is_some()),
            left[0] != URL_A
        );
        let _ = std::fs::remove_dir_all(s.root());
    }

    #[test]
    fn a_malformed_association_is_an_error_not_first_contact() {
        let s = store("pinassoc");
        let path = s.url_dir(URL_A).join(ASSOCIATION_FILE);
        std::fs::create_dir_all(s.url_dir(URL_A)).expect("mkdir");
        std::fs::write(&path, "../escape\n").expect("write");
        assert!(matches!(s.association(URL_A), Err(PinError::Corrupt(_))));
        let _ = std::fs::remove_dir_all(s.root());
    }

    #[test]
    fn corrupt_pin_file_is_an_error_not_first_contact() {
        // A truncated pin must never silently reset TOFU state.
        let dir = std::env::temp_dir().join(format!("sealed-rs-pincorrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(PIN_FILE), "{\"vault\":").expect("write");
        assert!(matches!(load(&dir), Err(PinError::Corrupt(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
