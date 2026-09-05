//! The per-(local repository, vault) pin — §7.4's trust-on-first-use memory —
//! and the reader acceptance battery, plus the §8.4 write-side allocation
//! guard. The battery's semantics follow the normative formal model
//! (`spec/sealed_v2.qnt`: `accepts`, `doRead`, `doPush`).
//!
//! Storage: one JSON file (`pin.json`) in a caller-supplied directory. The
//! caller MUST supply a directory unique to the (local repository, remote)
//! pair — keying by the manifest's own vault id would let a whole-vault
//! substitution start a fresh pin, which is exactly what §7.4's vault
//! identity check exists to refuse.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::json::Json;
use crate::manifest::{Manifest, ObjectFormat};

const PIN_FILE: &str = "pin.json";

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
/// `sealed-manifest.age`.
pub fn check_empty_vault(prev: Option<&Pin>) -> Result<(), PinError> {
    match prev {
        Some(_) => Err(PinError::EmptyVaultWithPin),
        None => Ok(()),
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

/// Load the pin for the (repository, vault) this directory stands for.
/// `Ok(None)` means first contact.
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

/// §7.4: pins are per (repository, VAULT), not per URL spelling. State
/// directories are keyed by URL (so a substituted vault served at the same
/// URL meets that URL's pin), but a vault reached through a NEW spelling of
/// its URL MUST still meet the strongest pin this repository holds for that
/// vault identity — otherwise respelling a remote would reset rollback
/// protection. `sealed_root` is the directory holding every state dir
/// (`<GIT_DIR>/sealed`); "strongest" is the highest counter. A corrupt
/// sibling pin is an error, not a silent skip (fail-closed).
pub fn find_by_vault_id(sealed_root: &Path, vault_id: &str) -> Result<Option<Pin>, PinError> {
    let entries = match fs::read_dir(sealed_root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PinError::Io(format!("{}: {e}", sealed_root.display()))),
    };
    let mut best: Option<Pin> = None;
    for entry in entries {
        let entry = entry.map_err(|e| PinError::Io(format!("{}: {e}", sealed_root.display())))?;
        let Some(pin) = load(&entry.path().join("pin"))? else {
            continue;
        };
        if pin.vault_id != vault_id {
            continue;
        }
        if best.as_ref().is_none_or(|b| pin.counter > b.counter) {
            best = Some(pin);
        }
    }
    Ok(best)
}

/// Persist the pin (write-then-rename, so a crash never leaves a truncated
/// pin — §7.4 makes this file normative validation input).
pub fn save(dir: &Path, pin: &Pin) -> Result<(), PinError> {
    fs::create_dir_all(dir).map_err(|e| PinError::Io(format!("{}: {e}", dir.display())))?;
    let tmp = dir.join(format!("{PIN_FILE}.tmp"));
    let path = dir.join(PIN_FILE);
    fs::write(&tmp, pin_to_json(pin).render())
        .map_err(|e| PinError::Io(format!("{}: {e}", tmp.display())))?;
    fs::rename(&tmp, &path).map_err(|e| PinError::Io(format!("{}: {e}", path.display())))?;
    Ok(())
}

/// Delete the pin file (a writer withdrawing a binding after a definitive
/// rejection when no pin existed before; §7.5 `forget` removes the whole
/// state directory instead). Absence is not an error.
pub fn remove(dir: &Path) -> Result<(), PinError> {
    let path = dir.join(PIN_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PinError::Io(format!("{}: {e}", path.display()))),
    }
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

    let object_format = ObjectFormat::from_str_exact(&str_field("objectformat")?)
        .ok_or_else(|| PinError::Corrupt("unknown objectformat".into()))?;
    let sequence_memory = seq_map(field("sequence_memory")?, "sequence_memory")?;
    // A pin written before §8.4 grew its pending half has no `pending` key.
    let pending = match json.get("pending") {
        Some(value) => seq_map(value, "pending")?,
        None => BTreeMap::new(),
    };

    Ok(Pin {
        vault_id: str_field("vault")?,
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
        assert!(matches!(
            check_empty_vault(Some(&pin)),
            Err(PinError::EmptyVaultWithPin)
        ));
        check_empty_vault(None).expect("true first contact is fine");
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
        let dir = std::env::temp_dir().join(format!("sealed-rs-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_by_vault_id_adopts_the_strongest_sibling_pin() {
        // §7.4: per (repository, vault) — a respelled URL must inherit the
        // protection the repository already holds for that vault.
        let root = std::env::temp_dir().join(format!("sealed-rs-siblings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let weak = first_contact(); // counter 2
        let mut strong = first_contact();
        strong.counter = 5;
        let mut other = first_contact();
        other.vault_id = "00000000000000000000000000000000".into();
        other.counter = 9;
        save(&root.join("url-a").join("pin"), &weak).expect("save");
        save(&root.join("url-b").join("pin"), &strong).expect("save");
        save(&root.join("url-c").join("pin"), &other).expect("save");

        let found = find_by_vault_id(&root, VAULT).expect("scan");
        assert_eq!(found.map(|p| p.counter), Some(5));
        assert_eq!(
            find_by_vault_id(&root, "ffffffffffffffffffffffffffffffff").expect("scan"),
            None
        );
        assert_eq!(
            find_by_vault_id(&root.join("absent"), VAULT).expect("scan"),
            None
        );
        let _ = std::fs::remove_dir_all(&root);
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
