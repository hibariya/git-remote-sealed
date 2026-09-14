//! §9 compaction: a validated read AND apply (so every manifest sha exists
//! locally — the precondition), ONE `-full` bundle of every manifest ref at
//! `seqfloor + 1` under the §8.4 allocation guard, a tree of only that
//! bundle's file(s) + the rewritten manifest + `sealed-format` + preserved
//! unknown entries, a single PARENTLESS commit, and a compare-and-swap push
//! against the tip observed in step 1; rejection restarts (bounded). A
//! vault whose refs were all deleted compacts into a manifest-only
//! generation (empty bundle list, empty refs, `seqfloor` UNCHANGED,
//! counter + 1, no allocation).
//!
//! Pin persistence follows `writer.rs`: the read's pin is persisted by
//! `apply` (those bundles really were applied), the new binding PENDING
//! before the push, and the advanced pin — with that binding confirmed —
//! after the acknowledgement. §8.4's pending half matters most here: a
//! compaction is one big upload, so an interrupted one used to wedge the
//! vault permanently, and the v1 -> v2 migration IS a compaction.
//!
//! A compaction cannot re-publish a pending bundle the way it might a
//! whole generation: §4.1 requires the LOWEST listed sequence number to
//! carry `-full`, and the compacted list holds exactly one bundle. So it
//! does what §8.4 allocation does everywhere — leaves the pending number
//! unpublished and takes the next one. The new `seqfloor` burns it.
//!
//! Changing the recipient set is a compaction too (§9.1 `enroll` /
//! `revoke`: the rewritten manifest carries the new set and everything is
//! encrypted to it), and so is the upgrade of a pre-recipient vault (§9.2:
//! the manifest gains its `recipient` lines). `SetChange` selects which.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use age::x25519::{Identity, Recipient};

use crate::bundling::{self, BundleSpec, Stored};
use crate::manifest::{BundleRecord, Manifest, MAX_COUNTER};
use crate::names::{BundleName, MAX_SEQ};
use crate::pinstore;
use crate::reader::{self, Inspection, Prepared};
use crate::vaultrepo::{PushOutcome, VaultRepo};
use crate::writer::{
    self, advanced_pin, build_commit, preserved_entries, WriteError, WriterConfig, MAX_ATTEMPTS,
    MAX_INDETERMINATE_ATTEMPTS,
};
use crate::FORMAT_VERSION;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactReport {
    pub counter: u64,
    /// The `-full` bundle's sequence number; `None` for a zero-ref
    /// (manifest-only) compaction.
    pub allocated: Option<u64>,
    pub attempts: usize,
    /// The recipient set the new generation declares and is encrypted to.
    pub recipients: BTreeSet<String>,
}

/// What a compaction does to the recipient set.
#[derive(Debug, Clone)]
pub enum SetChange {
    /// Plain §9: the manifest's set, unchanged.
    Keep,
    /// §9.1: set ∪ {key}.
    Enroll(Recipient),
    /// §9.1: set \ {key}; removing one of this device's own recipients
    /// needs `yes` (the device loses read access to the result).
    Revoke { key: Recipient, yes: bool },
    /// §9.2: a pre-recipient vault gains `recipient` lines = this device's
    /// configured set (`WriterConfig::upgrade_set`), whose size must equal
    /// the manifest ciphertext's X25519 stanza count; `yes` accepts the
    /// set when that count cannot be determined.
    Upgrade { yes: bool },
}

/// The result of `compact`: a new generation, or nothing to do (an
/// `enroll` of a key already in the set, a `revoke` of one not in it, an
/// `upgrade` of a vault that already records its set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compaction {
    Done(CompactReport),
    NothingToDo { recipients: BTreeSet<String> },
}

/// §9: compact the vault from the repository at `source_git_dir`, with the
/// recipient set changed per `change`.
pub fn compact(
    vault: &VaultRepo,
    source_git_dir: &Path,
    identities: &[Identity],
    cfg: &WriterConfig,
    change: &SetChange,
) -> Result<Compaction, WriteError> {
    let local_format = writer::preflight(source_git_dir)?;
    let mut last = String::new();
    let mut unreported = 0usize;
    for attempt in 1..=MAX_ATTEMPTS {
        // §9.1: fetch, record the tip T, validate and apply as in §6.
        let p = match reader::inspect(vault, identities)? {
            Inspection::Empty => return Err(WriteError::EmptyVault),
            Inspection::Vault(p) => p,
        };
        // The set the new generation declares and is encrypted to. Decided
        // per attempt: a retry reads a newer manifest, whose set may differ.
        let recipients = match new_set(&p, cfg, change)? {
            Some(set) => set,
            None => {
                return Ok(Compaction::NothingToDo {
                    recipients: p.manifest().recipients.clone(),
                })
            }
        };
        let declared: BTreeSet<String> = recipients.iter().map(ToString::to_string).collect();
        let m = p.manifest();
        if local_format != m.object_format.as_str() {
            return Err(WriteError::ObjectFormatMismatch {
                vault: m.object_format,
                local: local_format.clone(),
            });
        }
        // Applying persists the read's pin (every listed bundle is now
        // applied) and asserts every manifest sha exists locally (§6.6) —
        // §9's precondition.
        reader::apply(vault, source_git_dir, identities, &p)?;
        let tip = p.tree().commit.clone();
        let branch = p.tree().branch.clone();

        let counter = m
            .counter
            .checked_add(1)
            .filter(|c| *c <= MAX_COUNTER)
            .ok_or(WriteError::CounterExhausted)?;
        let mut manifest = Manifest {
            format: FORMAT_VERSION,
            object_format: m.object_format,
            vault_id: m.vault_id.clone(),
            counter,
            seqfloor: m.seqfloor,
            recipients: declared.clone(),
            bundles: Default::default(),
            // Documented choice: a manifest-only generation carries no HEAD
            // line (there is no ref for it to name).
            head: None,
            refs: Default::default(),
        };
        // §8.4: `apply` already persisted the read's pin, whose pending half
        // `validate_and_advance` settled against this manifest.
        let pin_base = p.next_pin().clone();
        let scratch = vault.scratch_dir()?;
        let mut stored = Stored {
            digest: String::new(),
            chunks: None,
            blobs: Vec::new(),
        };
        let mut allocated: Option<u64> = None;

        if !m.refs.is_empty() {
            // §9.2: one -full bundle of every manifest ref, real names and a
            // HEAD entry, at seqfloor + 1 under the allocation guard.
            let first = m
                .seqfloor
                .checked_add(1)
                .filter(|s| *s <= MAX_SEQ)
                .ok_or(WriteError::SequenceExhausted)?;
            let seq = pinstore::allocate_from(&pin_base.sequence_memory, &pin_base.pending, first)?;
            let refs: Vec<(String, String)> =
                m.refs.iter().map(|(n, s)| (n.clone(), s.clone())).collect();
            let bundle = bundling::create(
                source_git_dir,
                m.object_format,
                &scratch,
                &BundleSpec {
                    refs: &refs,
                    head: m.head.as_deref(),
                    excludes: &[],
                },
            )?;
            let name = BundleName::new(seq, true, None)?;
            let encrypted = bundling::encrypt_and_store(
                vault,
                &bundle,
                &recipients,
                name,
                cfg.chunk_bytes,
                &scratch,
            );
            let _ = fs::remove_file(&bundle);
            stored = encrypted?;
            manifest.bundles.insert(
                seq,
                BundleRecord {
                    seq,
                    full: true,
                    digest: stored.digest.clone(),
                    chunks: stored.chunks,
                },
            );
            manifest.seqfloor = seq;
            manifest.refs = m.refs.clone();
            manifest.head = m.head.clone();
            allocated = Some(seq);
        }

        // §9.3: only the new bundle's files, the manifest, sealed-format,
        // preserved unknown entries; a single parentless commit.
        let preserved = preserved_entries(&p.tree().entries, false);
        let (commit, manifest_digest) =
            build_commit(vault, &manifest, &recipients, &stored, &preserved, None)?;

        let mut pin_bound = pin_base.clone();
        if let Some(seq) = allocated {
            pin_bound.pending.insert(seq, stored.digest.clone());
            vault.save_pin(&pin_bound)?;
        }

        // §9.4: compare-and-swap against T; never a plain force.
        match vault.push_commit(&commit, &branch, Some(&tip))? {
            PushOutcome::Accepted => {
                let mut acked = pin_bound.clone();
                pinstore::confirm_acked(&mut acked, manifest.seqfloor);
                let pin = advanced_pin(&acked, &manifest, &manifest_digest);
                vault
                    .save_pin(&pin)
                    .map_err(WriteError::AckedButPinNotSaved)?;
                return Ok(Compaction::Done(CompactReport {
                    counter,
                    allocated,
                    attempts: attempt,
                    recipients: declared,
                }));
            }
            PushOutcome::Rejected(summary) => {
                // §8.5 definitive: withdraw the binding before the retry.
                if allocated.is_some() {
                    vault.save_pin(&pin_base)?;
                }
                last = summary;
            }
            PushOutcome::Indeterminate(summary) => {
                // §8.5: no ref-level verdict — the compaction may have
                // landed. Keep the binding PENDING; the next read settles
                // it. L5: each such attempt costs a sequence number, and a
                // compaction is the biggest upload there is, so retrying
                // into the same dropped connection is the worst place to
                // spend them. Stop and report the unknown outcome.
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

/// The recipient set the new generation gets, or `None` when the change
/// is already in effect. Every branch runs §7.3's read-only rule first: a
/// manifest with unknown lines is not rewritten by anyone.
fn new_set(
    p: &Prepared,
    cfg: &WriterConfig,
    change: &SetChange,
) -> Result<Option<Vec<Recipient>>, WriteError> {
    let m = p.manifest();
    if let SetChange::Upgrade { yes } = change {
        if p.writer_must_be_read_only() {
            return Err(WriteError::ReadOnlyVault);
        }
        // §9.2: idempotent — a vault that records its set is left alone.
        if !m.is_pre_recipient() {
            return Ok(None);
        }
        let set = cfg.upgrade_set();
        let would_record: Vec<String> = set.iter().map(ToString::to_string).collect();
        match p.manifest_stanzas() {
            // The count can be determined: it MUST equal the set's size,
            // smaller and larger alike.
            Some(h) if h.other == 0 => {
                if set.len() != h.x25519 {
                    return Err(WriteError::UpgradeCountMismatch {
                        would_record,
                        stanzas: h.x25519,
                    });
                }
            }
            // Non-X25519 stanzas: the size cannot be checked; the user
            // confirms the set explicitly.
            Some(h) if !*yes => {
                return Err(WriteError::UpgradeCountUnknown {
                    would_record,
                    stanzas: h,
                });
            }
            // No readable header at all. Impossible for a manifest that
            // just decrypted, but §9.2 says "cannot be determined" means
            // confirm, not proceed.
            None if !*yes => {
                return Err(WriteError::UpgradeCountUnknown {
                    would_record,
                    stanzas: crate::crypt::HeaderStanzas {
                        x25519: 0,
                        other: 0,
                    },
                });
            }
            _ => {}
        }
        return Ok(Some(set));
    }

    // Keep / Enroll / Revoke: the vault must be writable at all (which
    // refuses a pre-recipient vault — the only write it takes is Upgrade).
    let current = writer::writable_set(p, cfg)?;
    let mut set: BTreeSet<String> = m.recipients.clone();
    match change {
        SetChange::Keep => {}
        SetChange::Enroll(key) => {
            if !set.insert(key.to_string()) {
                return Ok(None);
            }
        }
        SetChange::Revoke { key, yes } => {
            let key_s = key.to_string();
            if !set.remove(&key_s) {
                return Ok(None);
            }
            // §9.1: the new set MUST be non-empty.
            if set.is_empty() {
                return Err(WriteError::EmptyRecipientSet);
            }
            // §9.1: removing the writer's own recipient is allowed, but
            // implementations SHOULD require explicit confirmation.
            let own = cfg.own_recipients.iter().any(|r| r.to_string() == key_s);
            if own && !*yes {
                return Err(WriteError::RevokeOwnKeyNeedsYes { key: key_s });
            }
        }
        SetChange::Upgrade { .. } => unreachable!("handled above"),
    }
    // The legacy list is judged against the set this generation declares.
    writer::check_legacy_config(&set, cfg)?;
    // Rebuild in the set's (bytewise) order from parsed recipients: the
    // manifest's own members were parsed by `writable_set`, the change's
    // key is already a `Recipient`.
    let mut by_string: std::collections::BTreeMap<String, Recipient> =
        current.into_iter().map(|r| (r.to_string(), r)).collect();
    if let SetChange::Enroll(key) = change {
        by_string.insert(key.to_string(), key.clone());
    }
    Ok(Some(
        set.iter()
            .map(|s| by_string.remove(s).expect("every member was parsed"))
            .collect(),
    ))
}
