# Changelog

## Unreleased

Fixes from a review of 0.3.0.

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

Command-line: a flag a command does not take (`info --yes`,
`compact --yes`) is a usage error again.

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
