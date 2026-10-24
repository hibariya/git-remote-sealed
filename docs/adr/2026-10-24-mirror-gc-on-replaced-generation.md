# The mirror is gc'd when a compaction replaces the vault's generation

- Status: Accepted
- Date: 2026-10-24
- Sources: measurement of a real repository's mirror on 2026-10-24 (330 MB, of which 246 MB unreachable: three old `-full` bundles of 71–82 MB and one replaced 11 MB bundle)

## Context
Each repository keeps a bare mirror of the vault under `<GIT_DIR>/sealed/urls/<hash>/mirror.git`. A compaction (`compact`, `enroll`, `revoke`, `upgrade`) force-pushes a parentless commit (§9). On the host the old generation is gone, but the mirror keeps it, because nothing ran gc there.
Ciphertext never deltas or compresses, so each replaced generation stays at full size: one full copy of the repository per compaction, forever. Git's own `gc --auto` does not help: it counts loose objects and packs, and the old generations sit in a few packs.
Ordinary pushes add no garbage. Vault commits form a chain, so earlier manifests and bundles stay reachable until the next compaction.

## Decision
- When the mirror ref moves to a commit whose history does not contain the previous tip, the generation was replaced. The mirror then runs `git gc --prune=now` (with reflog expiry `now`).
- The check runs in two places: in every fetch, which catches a compaction made by another repository, and right after this repository's own accepted compaction push.
- It is safe because it runs under the §6.1 lock, and the mirror holds nothing that its ref does not reach.
- A failed gc prints a warning and never fails the operation.

## Alternatives
- gc on a schedule or on every operation: most runs would find nothing, and each one rewrites the whole mirror.
- A size safety net (gc when the mirror is much larger than the live tree): the only other garbage is rare leftovers, and the next compaction removes them anyway.
- Hooking the user's `git gc` / `git maintenance`: git has no post-gc hook, `pre-auto-gc` needs a hook installed in every repository, and the mirror is a separate repository that the user's gc never visits.
- Tuning `gc.autoPackLimit` in the mirror: nearly every fetch would then repack everything.

## Consequences
- The first fetch after a compaction takes longer: it rewrites one generation (about 100 MB for a repository with photos).
- Repositories that already hold old generations are cleaned at their next compaction, not before.
