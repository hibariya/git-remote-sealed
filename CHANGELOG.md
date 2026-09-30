# Changelog

## 0.3.2 — a security fix for rejected pushes

A push rejected because the vault changed underneath it no longer
forgets what its read had confirmed. Before, a host that rewrites its
branch could use such a rejection to get a forked vault accepted: one
that binds a sequence number this device had already confirmed to
different content, which FORMAT.md §7.4 says must be refused. It takes
a malicious host and a particular race between two devices, but it
broke a guarantee the format makes, so upgrade if you do not trust
your host. The fork is now refused with "vault forked: a different
manifest with the already-seen counter N".

Nothing else changes: vaults, pins and commands are the same as in
0.3.1, and devices on either version can share a vault. A device still
on 0.3.1 stays exposed until it upgrades.

The formal models:

- `spec/sealed_v2.qnt` is now `spec/protocol_core.qnt`.
- A second model, `spec/protocol.qnt`, is written from the code and
  covers more of it: recipients, URL bindings, and every outcome of a
  push. It found this bug. `spec/README.md` describes both models;
  `spec.sh` still checks only `protocol_core.qnt`.

## 0.3.1 — fixes from a review of 0.3.0

The declared-vs-actual recipient check:

- A vault whose manifest declares a different set than it is encrypted
  to can be repaired: `git-remote-sealed compact --repair` rewrites it
  encrypted to the declared set. Before, every command refused such a
  vault, including the ones the error told you to run.
- The check now compares recipient stanzas by type. A stanza of a type
  no `recipient` line declares (a plugin key) is a mismatch; before,
  only the X25519 count was compared and an extra plugin stanza passed.
- The check runs after the rollback and vault-identity checks, so a
  replayed generation is reported as a rollback, not as a writer bug.

`upgrade --yes` now records a set smaller than the vault is encrypted
to, for a lost device, and says which count it dropped. Before, a
0.2.x user who had lost a device had no way to upgrade: every other
write was refused until the upgrade, and the upgrade refused the
smaller set. A larger set is still refused.

The old `sealed.recipients` setting:

- The first push to a new vault, refused because a leftover (usually
  global) `sealed.recipients` named another device, now says what to
  do: remove the entry, push, then `enroll` the key. README says in
  which order to upgrade old vaults and delete the setting.
- `revoke <key>` no longer fails when `sealed.recipients` still names
  that key. It proceeds and asks you to remove the entry.
- The "ignored since 0.3.0" warning prints once per command, not once
  per retry.
- A leftover `sealed.allow-recipient-shrink` gets a warning naming
  `revoke` as its replacement, instead of being ignored in silence.

Command-line:

- `info` prints the identity, this device's key and the pin before it
  contacts the vault, so the key to enroll elsewhere shows even when the
  remote is unreachable or another command holds the lock.
- The "written before recipients were recorded" refusal names every
  write it applies to (push, enroll, revoke, compact), not only push.
- A flag a command does not take (`info --yes`, `compact --yes`) is a
  usage error again.

## 0.3.0 — recipients are recorded in the vault

The set of keys a vault is encrypted to now lives inside the encrypted
manifest, as `recipient` lines. Every device learns the full set when
it reads the vault, so per-device recipient lists are gone. Readers
check that the manifest's age header agrees with what it declares.

New commands:

    git-remote-sealed enroll <age1...>   add a key and compact, so the
                                         whole history becomes readable
    git-remote-sealed revoke <age1...>   remove a key and compact
                                         (--yes to remove this device's own)
    git-remote-sealed upgrade            bring an existing vault up to
                                         what this version writes

`info` prints the recipients the vault records, this device marked.

Removed configuration:

    sealed.recipients              replaced by enroll/revoke
    sealed.allow-recipient-shrink  replaced by revoke

Upgrading an existing vault:
Run `git-remote-sealed upgrade` once per vault, from any device that
can read it. Reads work without it; a push to a not-yet-upgraded vault
is refused and tells you to run it. The recorded set is this device's
identity plus `sealed.recipients`, and it must match the number of keys
the vault is already encrypted to. A mismatch is refused with both
counts, so a stale global entry cannot be sealed in by accident.
Afterwards remove `sealed.recipients`; a key listed there but not in
the vault is refused on write, use `enroll` instead.

Mixed versions:
A vault written by 0.3.0 still reads on 0.2.x (clone and fetch work),
but 0.2.x refuses to push to it, as the format requires for unknown
manifest lines. Upgrade each device before it pushes again.

Format:
Still format 2. `recipient` is a 2.x line-type extension; see
FORMAT.md §5, §7.2, §9.1, §9.2 and Appendix B.

## 0.2.1

See the release notes on GitHub for 0.2.1 and earlier.
