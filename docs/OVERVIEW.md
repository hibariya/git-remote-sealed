# How a sealed vault works

Your local repository is ordinary Git. The remote stores encrypted Git
bundles and an encrypted index called the **manifest**.
This page is an explanation, not a specification: [FORMAT.md](FORMAT.md)
defines the rules, and its §2 defines which rules the Quint model governs.

## What the remote holds

A small vault after two pushes might have these files on its vault branch:

```text
sealed-format           format version, stored as plain text
sealed-manifest.age     encrypted index of refs and bundles
1-full.bundle.age       encrypted initial snapshot
2.bundle.age            encrypted objects added by the second push
```

Each push updates the vault branch with one commit. The source repository's
branch names and commit history are inside the encrypted files; the vault's
own branch is a container for them.

A bundle holds Git objects, such as commits, trees, and file contents.
The first bundle provides a starting point. Later bundles can depend on
objects in earlier bundles. Large encrypted bundles can be split into
numbered parts, such as `2.bundle.age.0` and `2.bundle.age.1`.

The manifest tells a reader which bundles to use and what refs to report.
Its main fields are:

| Field | Purpose |
| --- | --- |
| `vault` | Identifies this vault across different URLs |
| `counter` | Counts manifest generations |
| `seqfloor` | Tracks the sequence-number floor used for new bundles |
| `bundle` lines | Name the bundles, their ciphertext digests, and any part counts |
| Ref lines and HEAD | Describe the source repository's current refs and default branch |

The complete manifest shape is in [FORMAT.md §7](FORMAT.md#7-the-manifest-sealed-manifestage).

## Pushing a change

The helper reads and validates the current vault, then checks the requested
ref updates. It builds a bundle when needed, encrypts it, and updates the
manifest. The bundle and manifest travel together in one vault commit.
If another writer wins the race, the helper reads again and retries the
checks against that newer state.

For example, after the initial push, a new commit can go into bundle 2.
Deleting a branch can update just the manifest, with no new bundle.
Bundle numbers therefore do not equal push counts, and interrupted pushes
can leave gaps in the numbering.

## Fetching a change

The helper checks the manifest against its saved security memory and
checks the vault files against the manifest. For each bundle it needs to
apply, it joins any parts in numeric order, checks the ciphertext digest,
decrypts the bundle, and imports its objects. Git then updates local refs
from the refs the helper reports.

Already-applied bundles can be skipped. If Git has removed required local
objects, the helper restores them from the bundles.

## Remembering what was accepted

Each local repository keeps one **pin** per vault. It remembers the
accepted counter, manifest digest, and sequence bindings. Different URLs
for the same vault share that memory, while each URL also remembers which
vault it belongs to.

For example, after accepting counter 3 through an SSH URL, the repository
rejects counter 2 through an HTTPS URL for the same vault. A new device
with no saved pin cannot detect that kind of rollback on first contact.
Pins also do not detect every fork served to different devices; see the
[security limits](FORMAT.md#10-security-considerations).

## Compacting a vault

Compaction replaces the bundle chain with one full snapshot of the current
manifest refs. It replaces the vault branch with a parentless commit, but
only if the branch still has the tip observed at the start. A concurrent
push makes it retry. Bundle numbering continues after compaction.

Adding a recipient changes encryption for future files. Compact on a
device that can read the existing history before cloning with the new key.
Compaction makes that snapshot readable with the new key too.

If all refs were deleted, compaction leaves a manifest with no bundles.
Compaction does not guarantee erasure of copies retained by the host.

For recovery without the helper, follow
[Appendix A](FORMAT.md#appendix-a-disaster-recovery-with-stock-tools).
For the reasons behind individual rules, read the [design notes](DESIGN-NOTES.md).
