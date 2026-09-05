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

use std::fs;
use std::path::Path;

use age::x25519::Identity;

use crate::bundling::{self, BundleSpec, Stored};
use crate::manifest::{BundleRecord, Manifest, MAX_COUNTER};
use crate::names::{BundleName, MAX_SEQ};
use crate::pinstore;
use crate::reader::{self, Inspection};
use crate::vaultrepo::{PushOutcome, VaultRepo};
use crate::writer::{
    self, advanced_pin, build_commit, check_recipient_shrink, preserved_entries, WriteError,
    WriterConfig, MAX_ATTEMPTS, MAX_INDETERMINATE_ATTEMPTS,
};
use crate::FORMAT_VERSION;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactReport {
    pub counter: u64,
    /// The `-full` bundle's sequence number; `None` for a zero-ref
    /// (manifest-only) compaction.
    pub allocated: Option<u64>,
    pub attempts: usize,
}

/// §9: compact the vault from the repository at `source_git_dir`.
pub fn compact(
    vault: &VaultRepo,
    source_git_dir: &Path,
    identities: &[Identity],
    cfg: &WriterConfig,
) -> Result<CompactReport, WriteError> {
    let local_format = writer::preflight(source_git_dir)?;
    let mut last = String::new();
    let mut unreported = 0usize;
    for attempt in 1..=MAX_ATTEMPTS {
        // §9.1: fetch, record the tip T, validate and apply as in §6.
        let p = match reader::inspect(vault, identities)? {
            Inspection::Empty => return Err(WriteError::EmptyVault),
            Inspection::Vault(p) => p,
        };
        if p.writer_must_be_read_only() {
            return Err(WriteError::ReadOnlyVault);
        }
        check_recipient_shrink(vault, &p, cfg)?;
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
                &cfg.recipients,
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
            build_commit(vault, &manifest, &cfg.recipients, &stored, &preserved, None)?;

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
                return Ok(CompactReport {
                    counter,
                    allocated,
                    attempts: attempt,
                });
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
