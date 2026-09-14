A sealed vault written by the RELEASED git-remote-sealed 0.2.1 (tag v0.2.1,
built in the repo's shell container on 2026-09-14), before the manifest
declared its recipient set: its manifest has no `recipient` line (FORMAT.md
§5 "pre-recipient"), and its files are encrypted to two X25519 keys —
identity-a's, which wrote it, and identity-b's, which 0.2.1 took from
`git config sealed.recipients`. Both identities are throwaway test keys
generated for this fixture; they protect nothing.

  vault.bundle            `git bundle create vault.bundle refs/heads/main`
                          of the vault repository; restore it with
                          `git init --bare -b main v.git &&
                           git -C v.git fetch vault.bundle +refs/heads/main:refs/heads/main`
  identity-a.txt          the writer's age identity (recipient stanza 1)
  identity-b.txt          the second recipient's identity (stanza 2)
  expected-manifest.txt   the decrypted sealed-manifest.age, verbatim
  expected-refs.txt       the source repository's refs at the last push

History: push of `main` (1-full.bundle.age) -> a second commit and an
annotated tag v1 pushed together (2.bundle.age). Used by
tests/recipients_e2e.rs for §5/§8 (a push to a pre-recipient vault is
refused, reads work) and §9.2 (`upgrade`: equal count succeeds, smaller
and larger are refused, idempotent).
