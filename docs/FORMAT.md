# Sealed Vault Format, version 2

This document specifies the on-remote format used by `git-remote-sealed`:
an end-to-end encrypted git remote ("vault") built from git bundles and
age encryption. It is written so that an independent implementation can be
built from this document alone, with no reference to any existing code.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
RFC 2119. Grammars are ABNF (RFC 5234); string literals in them are
case-sensitive (RFC 7405 `%s` semantics), and hex is lowercase throughout
this format. A reference of the form §N.M names item M of section N's
numbered list when no subsection heading N.M exists.

## 1. Overview

A **vault** stores the complete history of a **source repository** on a
**host**: whatever git remote holds it, from a hosting service down to a
plain directory. The host cannot read what it stores — file contents,
filenames, ref names and commit metadata are all encrypted — and sees only
how many files there are, how large they are, and when pushes happen (§10
lists the full declared leakage).

Design goals, in priority order:

1. **Recoverable with stock tools.** A vault MUST be fully restorable
   using only `git` and `age`, with no implementation of this spec
   present (see Appendix A).
2. **No custom cryptography or containers.** All serialization is the
   git bundle format; all encryption is the age format. This spec defines
   only naming, ordering, and bookkeeping.
3. **Dumb host, semi-trusted.** The vault needs nothing from its host
   beyond ordinary git hosting (or even just a directory). Assume the
   host reads everything; it MAY also be actively malicious. Readers
   MUST detect — though not necessarily repair — file deletion,
   substitution, reintroduction of compacted-away files, whole-vault
   swaps, rollback to an older state, and re-binding of a sequence
   number this device has already observed. One timing caveat:
   substitution of an *already-applied* bundle is detected at latest
   when that bundle is next read (§6.4).

## 2. The formal companion model

The dynamic, safety-critical rules of this format are additionally
specified as a machine-checked model: `spec/sealed_v2.qnt` (Quint;
verified with Apalache — bounds and results in `spec/README.md`).

**Authority split.** For the rules listed below, the model is normative:
if this document and the model are ever found to disagree, the model
wins and this document has a bug. For everything else — grammars, bytes,
git and age mechanics — the model is deliberately silent, and this
document alone governs. Silence in the model is never permission.

| Rule (this document) | Model construct |
|---|---|
| Reader acceptance battery: counter monotonicity, twin check, seqfloor monotonicity, sequence→digest stability (§7.4) | `accepts`; invariants `inv_p2_guardMonotone`, `inv_p3_neverReuse` |
| Allocation rule and allocation guard (§8.4) | `doPush` / `doCompactCommit` guards |
| Compare-and-swap compaction; durability of acknowledged pushes (§9) | `doCompactStart`/`doCompactCommit`; `inv_p4_durability` |
| `-full` rooting after empty-list generations (§4.1, §9) | `doCompactCommitEmpty`; `inv_p_rooting` |
| Apply order and prerequisite closure (§4.3, §6) | `inv_p5_prereqClosure` |
| File-set acceptance exactness (§6.7) | `acceptFiles`; `inv_p1_acceptExactness` |
| What `forget` forfeits (§7.5) | the forget demonstration runs (`rollbackRefusedWithoutForgetTest` / `forgetForfeitsRollbackProtectionTest`) |
| One pin per vault identity, shared by every URL alias (§7.4) | `SHARED_PIN`; negative control `neg_alias` (`staleAliasAcceptsRollbackTest`, `staleAliasAcceptsReboundSequenceTest`) |

The model also carries this format's threat model in executable form:
its negative-control configurations demonstrate the concrete attacks
each rule exists to stop. The model's cryptographic assumptions are
stated in its header and restated here in §10.

## 3. The vault container

**In brief** (non-normative). One git branch holds everything: an unencrypted
version marker, the encrypted manifest, and encrypted bundle files. Each push
appends one commit; compaction replaces the branch's history outright. Files
this spec does not define are ignored on read and kept on write, so later
versions can add some.

A vault is an ordinary git repository. All data lives in the tree of a
single branch. Writers append commits to this branch; compaction (§9)
replaces its history entirely.

**Branch selection.** Implementations MUST use the remote's default branch
(remote HEAD) when the remote is non-empty, and MUST use `main` when
initializing an empty remote. (Without a fixed rule, two devices with
different local defaults would silently create two divergent vaults in one
repository.) A remote HEAD counts as usable only when the server advertises
its symref target and that branch exists. If the remote is non-empty but has
no usable HEAD, use `main` if a branch of that name exists, else the
lexicographically first branch. A non-empty remote with no branch at all has
no vault branch: readers MUST fail loudly rather than guess.

The tree root contains only:

| File | Encrypted | Purpose |
|---|---|---|
| `sealed-format` | no | format version marker (a hint; see below) |
| `sealed-manifest.age` | yes | the manifest (§7) — the authoritative index |
| bundle files (§4) | yes | git bundles carrying the objects |

`sealed-format` MUST contain the ASCII decimal version number followed by a
single LF: currently `2`, spelled canonically (no leading zeros). It is the
only unencrypted, unauthenticated file, so treat it as a *hint*, not an
authority.

**Version selection MUST come from the manifest's `format` line alone.** The
hint MAY fast-fail an operation, but it MUST NOT select parsing or validation
semantics — it is host-controlled. Readers MUST refuse versions they do not
support, and MUST fail if the hint and the manifest disagree. (That check
necessarily runs after the manifest is decrypted, §6 step 3; §6 step 2 checks
only the hint's grammar and that its version is supported.)

A vault tree without `sealed-format` is invalid — the file is host-controlled,
so its absence is indistinguishable from deletion: fail loudly.

A committed tree holding neither `sealed-manifest.age` nor any bundle file,
whatever else it holds, is an *empty vault* for §7.4's purposes. A tree
holding `sealed-format` and `sealed-manifest.age` but no bundles is **valid**
— see zero-ref compaction, §9.

A tree that contains bundle files but no `sealed-manifest.age` is
**invalid**: readers MUST fail loudly and writers MUST NOT push against
it. [3a]

**Unknown and non-canonical tree entries.** Readers MUST ignore tree entries
not matching this spec's grammar; writers SHOULD preserve such entries. This
is the forward-compatibility mechanism for minor additions.

There is one carve-out: an entry that is **bundle-shaped but non-canonical** —
it matches the bundle-name pattern *compared case-insensitively* but is not a
canonical name (§4.1: leading zeros, an out-of-bound number, or wrong letter
case). Readers MUST ignore it. [3b] Writers MUST NOT preserve it: they MUST
drop it on any tree rewrite, compaction included. [3c]

**Object formats.** Version 2 supports SHA-1 and SHA-256 source repositories.
The vault-wide object format is declared by the manifest's `objectformat` line
(§7.2), fixed when the vault is initialized and immutable for the vault's
lifetime. Bundle payload version follows it strictly (§4.3). The vault
repository *itself* is host-default (any object format); only the source
repository's format matters here.

**Notes to §3.** Background; nothing here adds a rule.

**3a.** Without this rule, deleting one file would make the vault read as
empty. The next innocent writer would then rebuild a manifest containing only
its own refs — turning one deleted file into propagating ref loss.

**3b.** The bundle namespace is owned by this spec, so such a name can only be
a decoy or corruption, never a future extension. A hard error would let a
malicious host wedge every operation with one planted file, since reading
precedes every write and every repair.

**3c.** So host-planted decoys cannot ride the preservation rule across
compaction's history rewrite, or poison the recovery procedure indefinitely.

## 4. Bundle files

### 4.1 Naming grammar

```abnf
name     = seq ["-full"] ".bundle.age" [chunk]
seq      = nzdigit *DIGIT          ; canonical decimal, no leading zeros
chunk    = "." chunknum
chunknum = "0" / (nzdigit *DIGIT)  ; canonical decimal, no leading zeros
nzdigit  = %x31-39                 ; 1-9
```

Value bounds, both anti-abuse parser rules (the host controls
filenames) and type-fixing rules for implementations:

- `seq` value ≥ 1 and ≤ 2^63−1 (this fixes the integer type for ports,
  identically to `counter`, §7.2; the bound is unreachable in practice).
- `chunknum` at most 7 digits (< 10^7), one shared bound with the
  manifest's chunk count (§7.2).

A bundle-shaped name violating canonical form or these bounds is not a
valid bundle name — see §3's carve-out. [4a]

- `seq` is strictly increasing across the life of the vault, starting
  at 1. A sequence number MUST never be reused, even after compaction.
  Allocation is governed by `seqfloor` (§7.2) and the allocation guard
  (§8.4). Writers MUST fail with a clear error if the sequence space is
  exhausted (the escape is compacting into a fresh vault).
- The **logical name** is the name without any chunk suffix.
  **Apply order is ascending numeric value of `seq`.** Nothing in this
  format depends on the string order of names.
- `-full` marks a **complete snapshot**: the bundle MUST have zero
  prerequisites AND contain every ref of its manifest generation.
  A push MUST label its bundle `-full` if and only if the pre-push
  manifest generation's bundle list is empty (this covers vault
  initialization, where no manifest exists yet, and the first push
  after a zero-ref compaction, §9); compaction bundles are always
  `-full`. A push into a generation with a nonempty bundle list MUST
  NOT be labeled `-full`, even when it happens to have zero
  prerequisites. [4b]

**Notes to §4.1.** Background; nothing here adds a rule.

**4a.** Canonical form is load-bearing: it gives every logical value exactly
one spelling. Together with §7.2's rule that no two `bundle` lines share a
sequence number (with or without `-full`), every sequence number resolves to
at most one tree entry.

**4b.** Appendix A's recovery relies on this rule: "start from the highest
`-full`" is only sound if `-full` always means the whole vault, and if every
generation with bundles is rooted in one.

### 4.2 Chunking

A writer MAY split one logical file's ciphertext into parts at arbitrary
byte boundaries. The reason this exists: hosts impose per-file size
limits. Parts are named with chunk suffixes contiguous from zero:
`.0`, `.1`, `.2`, ...

Whether a logical file is chunked, and into how many parts, is recorded
in the manifest's `bundle` line (§7.2). The expected file set is derived
from the manifest — see §6.7; no width or contiguity inference from the
tree survives from earlier versions of this format.

If any part exists, a file with the bare logical name MUST NOT exist
(this also follows from §6.7's exhaustive set rule).

The chunk threshold is writer-local policy, not part of the format;
readers MUST handle chunked and unchunked files regardless of size. The
manifest's `bundle` line records the digest of the *logical*
(reassembled) ciphertext. One deployment SHOULD: **a vault with a
JGit-on-Android device among its recipients SHOULD be written with
chunks ≤ 4 MiB by every device** — that platform's large-blob read path
is fragile, and with unbounded chunk counts small chunks cost nothing.

### 4.3 Bundle contents

Each decrypted file is a git bundle subject to:

- **Payload version follows the vault's object format, strictly both
  ways:** header `# v2 git bundle` iff `objectformat sha1`; header
  `# v3 git bundle` with capability `@object-format=sha256` iff
  `objectformat sha256`. Readers MUST verify the header line of every
  decrypted bundle and fail loudly on anything else — a v3 bundle in a
  sha1 vault is an error, not a tolerance. [4c]
- **Prerequisite closure:** all of a bundle's prerequisite commits MUST
  be contained in the union of bundles with strictly lower sequence
  numbers *that appear in the same manifest generation* (§7). Applying
  the manifest's bundles in apply order never fails a prerequisite
  check.
- **Real ref names:** header refs MUST use the true destination ref
  names (`refs/heads/...`, `refs/tags/...`), never temporary or
  internal names. [4d]
- **HEAD entry:** a bundle SHOULD additionally list `HEAD` (with the
  sha of the manifest head ref, §7) whenever that ref is among its
  refs, so that stock `git clone <bundle>` checks out the right branch
  during disaster recovery.
- Bundle header ref values are **informative only**. The manifest is
  the sole authority for which refs exist and what they point to.
  (Bundles accumulate stale ref claims — e.g. pre-rebase tips — by
  design.)

**Notes to §4.3.** Background; nothing here adds a rule.

**4c.** Why not v3 everywhere: Appendix A wants the widest stock-git
compatibility, and v2 bundles are readable by every git that can run the
recipe at all.

**4d.** git records whatever names it is given at creation time, so a writer
that bundles via temporary refs must rewrite the header afterwards. That is
possible because the header is plain text, terminated by the first blank line;
the binary packfile follows it.

## 5. Encryption

Every encrypted file is a binary age v1 file (`age-encryption.org/v1`)
encrypted to the vault's **recipient set** — one or more age recipients.
X25519 recipients are the baseline; implementations MAY support other
recipient types (passphrase, plugins). All files SHOULD be encrypted to
the same recipient set; adding a recipient takes effect for files
written afterwards (re-encrypting history requires compaction).

Decryption requires a corresponding **identity** (secret key). This version
defines **no write-only algorithm**: §8 requires reading the manifest, and
that needs an identity. [5a]

There is no deterministic-encryption requirement anywhere in this
format.

**Notes to §5.** Background; nothing here adds a rule.

**5a.** In principle the recipient/identity split allows an asymmetry: a
device holding only recipients could *write* backups without ever being able
to read the vault. Treat write-only operation as a possible future profile,
not something to implement from this document.

## 6. Reader algorithm (fetch / restore)

1. Obtain the current **committed tree** of the vault branch. The
   branch may have been force-updated by a compaction, so readers that
   maintain a local mirror MUST reset it to the remote state, never
   merge. They MUST NOT let untracked local files (e.g. leftovers of an
   interrupted write) masquerade as vault content. Concurrent
   operations of one local repository that share a mirror, or the pin
   and memory state of §7.4 — which every URL alias of a vault shares —
   MUST be serialized (e.g. with a lock), whichever URL each of them
   uses; otherwise one operation's cleanup can delete another
   operation's not-yet-committed bundle, publishing a manifest that
   references a missing file, or two operations can each advance the
   pin from a stale copy. One lock per local repository is sufficient
   and has no lock order to get wrong. A local mirror MUST be created in the vault
   repository's own object format, learned from the remote's advertised
   object ids — it is independent of the manifest's `objectformat`
   (§3). Before applying, readers MUST refuse a destination repository
   whose object format differs from `objectformat`. An EMPTY remote
   advertises no object ids: a writer initializing a vault creates the
   mirror in the source repository's object format and, if the remote
   refuses the push at the transport level (a hash-algorithm mismatch —
   not a machine-readable ref rejection, which is a concurrent-writer
   race), recreates the mirror in the other format once.
2. Check `sealed-format` (§3).
3. Decrypt and validate the manifest (§7), including the
   trust-on-first-use checks (§7.4). Bundles present with no manifest
   is a hard error (§3).
4. Verify the tree against the manifest: the set of grammar-matching
   tree files MUST equal the **expected file set** (§6.7) exactly.
   Extra files (e.g. resurrected pre-compaction ciphertexts) and
   missing files are both hard errors. Each reassembled ciphertext MUST
   match its recorded digest **before it is decrypted and applied**.
   The per-vault sequence memory (§7.4) records each (sequence →
   digest) binding; implementations thereby skip re-verifying files
   whose binding they have already verified and applied — and §7.4
   makes re-binding a remembered sequence a hard error, so the skip is
   sound.
5. For each listed bundle not yet applied, in ascending numeric
   sequence order: reassemble chunks (§4.2, parts `.0` upward), verify
   the digest, decrypt, verify the bundle header line (§4.3), and
   apply. [6a] Applying only adds objects; it
   MUST NOT update any repository refs. Application is idempotent.
   Implementations MAY skip bundles recorded as applied in the
   sequence memory, but MUST re-apply when a required object turns out
   to be absent — a local `git gc` can prune unbundled objects that no
   ref reached, and a stale skip must not wedge the reader.
6. Report exactly the manifest's refs (and its HEAD symref) as the
   remote's refs. Every listed sha MUST now exist locally; a missing
   object after re-application means a corrupt or incomplete vault and
   MUST be a loud error.

**Notes to §6.** Background; nothing here adds a rule.

**6a.** For example `git bundle verify` followed by `git bundle unbundle`:
`unbundle` alone performs no prerequisite check, and `verify` is what asserts
§4.3's promise.

### 6.7 The expected file set

Given a validated manifest, the expected file set is total and exact:

```
expected(manifest) =
  union over each `bundle NAME DIGEST [COUNT]` line of:
    if COUNT absent:  { NAME }
    else:             { NAME "." i  |  0 <= i <= COUNT-1 }
```

The set of grammar-matching tree entries MUST equal `expected(manifest)`
exactly (non-grammar and carved-out entries per §3 are outside the
comparison). This single rule makes bare-name-plus-parts, extra parts,
missing parts, and manifest-says-whole/tree-has-parts the same hard
error, with no separate contiguity checks.

## 7. The manifest (`sealed-manifest.age`)

### 7.1 Shape

Decrypted content is UTF-8 text, LF line endings. Example:

```
format 2
objectformat sha1
vault 3f9a6c0e6d1b4b0d9a4f2e7c8b5a1d02
counter 42
seqfloor 8
bundle 7-full.bundle.age 9f2c...64-hex-sha256...ab 87
bundle 8.bundle.age 11d4...64-hex-sha256...09
@refs/heads/main HEAD
1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b refs/heads/main
```

**Validation is two-pass, defined over the whole decrypted text**: the
singleton lines (`format`, `objectformat`, `vault`, `counter`,
`seqfloor`) are located first; every other line is then judged with
their values in hand. Line order is not significant; writers SHOULD
sort refs by name and bundles by sequence for reproducibility.

Tokens are separated by exactly one SP. Every numeric value in the
manifest uses the canonical decimal spelling of §4.1 (no leading
zeros). Empty lines are invalid — a future extension is a line *type*
and has a first token; an empty line has none. The final LF is the last
line's terminator (readers accept its absence).

### 7.2 Lines

- `format <n>` — the format version, REQUIRED, exactly once. MUST match
  `sealed-format` (§3). Version selection comes from this line alone.
- `objectformat sha1` / `objectformat sha256` — REQUIRED, exactly once.
  Fixed at vault initialization; a manifest generation that changes it
  is INVALID (enforced via the pin, §7.4).
- `vault <hex>` — a random vault identity (at least 128 bits, generated
  when the vault is initialized, never changed), REQUIRED, exactly
  once. Spelling: lowercase hex, an even number of digits (it names a
  byte string), at least 32 of them. Comparison is string equality.
- `counter <n>` — a monotonic write counter, REQUIRED, exactly once,
  value ≥ 1 (the vault-initializing write is generation 1).
  Writers MUST increment it on **every** manifest write (pushes with
  and without bundles, and compaction). Readers and writers MUST
  support values up to at least 2^63−1 (this fixes the integer type
  for ports; the bound is unreachable in practice).
- `seqfloor <n>` — REQUIRED, exactly once: the highest sequence number
  ever allocated in this vault. Grammar and bounds as `seq` (§4.1);
  zero is invalid (the vault-initializing push allocates sequence 1,
  so no legal generation precedes the first allocation). Invariants:
  `seqfloor` ≥ every sequence in the bundle list (readers MUST assert
  this; the host cannot forge the manifest, so a violation means a
  buggy writer); monotone nondecreasing across generations (§7.4).
  Because `seqfloor` survives an empty bundle list, numbering can
  never restart (see zero-ref compaction, §9).
- `bundle <logical-name> <sha256-hex> [<count>]` — one line per logical
  bundle in the tree, with the SHA-256 of its (reassembled) ciphertext.
  This list is the authority for which bundle files exist (§6.7).
  `count` present ⇔ the file is chunked into parts `.0` … `.(count−1)`;
  absent ⇔ stored whole. Count grammar: canonical decimal, value ≥ 2,
  at most 7 digits (the shared bound of §4.1 — count 1 would create a
  duplicate representation of a whole file and is invalid). No two
  `bundle` lines may share a sequence number, regardless of `-full`
  labeling. **Both arities (3 and 4 tokens) are frozen shapes; any
  other arity is INVALID.** Readers MUST additionally assert that a
  nonempty bundle list carries the `-full` label at its LOWEST sequence
  number — the recovery root Appendix A starts from (like the
  `seqfloor` assertion, a violation means a buggy writer; the model's
  `inv_p_rooting` is the abstract form).
- `@<refname> HEAD` — zero or one: the HEAD symref target. It SHOULD
  name a ref present in the manifest; readers report the symref as
  given even when it names no listed ref (the consumer then sees a
  dangling HEAD, which is the honest outcome). The `@` prefix is
  reserved for this line type: an `@`-prefixed line not matching it is
  INVALID, and future versions never add `@`-prefixed line types.
- `<sha-hex> <refname>` — the refs. The sha is 40 hex iff
  `objectformat sha1`, 64 hex iff `sha256`. **Both widths are reserved
  ref-line shapes in every manifest**: the width that disagrees with
  the declared object format is INVALID, never an unknown line.
  (Otherwise a parser would route the "wrong" width to the ignore
  path — the silent-ref-drop failure this rule exists to prevent.)
  Reserved means lowercase hex exactly; an uppercase near-miss is an
  unknown token and takes §7.3's path (ignored on read, writers go
  read-only — fail-safe against a buggy writer, and the manifest is
  authenticated so no host reaches it). A refname is a nonempty token
  of bytes above 0x20, excluding 0x7F — it cannot contain the SP
  delimiter; git's own refname rules bind writers upstream. For
  annotated tags the sha is the tag object, not the peeled commit.

### 7.3 Extensibility

Readers MUST ignore lines whose first token they do not recognize. [7a] The
rule applies only to
*unrecognized first tokens*. A line whose first token IS recognized —
including a 40- or 64-hex object id — but which does not match its
grammar (arity included) is **invalid**. Duplicates of at-most-once
lines (`format`, `objectformat`, `vault`, `counter`, `seqfloor`, the
HEAD symref, a given refname, a given logical bundle name) are invalid
too.

**Future 2.x extensions add new line types; they never extend existing
ones.** [7b]

Ignoring on *read* is not enough. A writer MUST refuse to write — that is,
become read-only — when the manifest it read contained any line whose first
token it does not recognize. This makes a 2.0 tool read-only against a 2.1
vault, which is the safe outcome. [7c]

**Notes to §7.3.** Background; nothing here adds a rule.

**7a.** This is safe because producing a manifest ciphertext that decrypts at
all requires knowing a vault recipient (§5, §10), which the host does not, so
the host cannot inject lines. It is how future 2.x versions add fields without
breaking deployed readers.

**7b.** Arity errors on recognized tokens fail parsing outright, which would
brick deployed readers instead of degrading them; new line types degrade them
to read-only via the next rule, which is the intended failure mode.

**7c.** A writer regenerates the manifest from the fields it knows, so a
writer that does not understand an extension line would silently delete that
line on its next push.

### 7.4 Trust on first use, and the per-vault memory

Per (local repository, vault), readers MUST maintain a **pin** — their
memory of the vault — and MUST validate every manifest against it.
The pin is **one per vault identity**, shared by every remote URL
through which the repository reaches that vault: an SSH and an HTTPS
spelling, a path with and without a trailing slash, any alias at all.
Keying the pin by URL is INVALID, even with a fallback to another
URL's pin on first contact: two URLs that each hold a pin stop sharing
what they learn, and a host can then replay an old generation through
the URL whose memory is older. [7h] URL normalization is not a
substitute — no rewriting makes two transports one string — so the key
MUST be the vault identity the manifest declares.

Keying by the manifest's own identity has a hole of its own: a
substituted vault served at a familiar URL would simply meet a fresh
pin. So each remote URL MUST additionally keep a durable **binding** to
the vault identity first pinned through it, and a manifest whose
`vault` differs from the URL's binding is INVALID — checked BEFORE any
pin is looked up by that manifest's identity. A URL with no binding
yet is bound on the first pin saved through it, and until then meets
whatever pin the repository already holds for the manifest's vault
identity (a respelled remote must not reset rollback protection). A
bound URL that presents an *empty* vault is treated as the pinned
reader below treats one. The checks:

- **vault identity**: pinned on first contact; a manifest whose `vault`
  differs is INVALID (whole-vault substitution).
- **counter**: a manifest whose `counter` is lower than the highest
  previously seen is INVALID (rollback). Readers MUST additionally
  pin a digest of the manifest ciphertext and reject a manifest whose
  counter *equals* the pinned value but whose content differs — a
  forked twin (a losing concurrent push's genuine commit, replayed by
  the host). [7d]
- **format**: monotone. A manifest whose `format` is lower than the
  pinned format is INVALID regardless of counter — same error family
  as rollback. A vault never legally downgrades, so a format
  regression with an advancing counter is proof of a fork.
- **objectformat**: equality. Once seen, any change is INVALID.
- **seqfloor**: monotone nondecreasing. (This detects fork-hops that
  counter pinning provably misses; the model's negative controls carry
  the concrete attack.)
- **sequence memory**: the pin records every (sequence number → bundle
  ciphertext digest) binding this device has ever accepted **and
  applied** (§6 step 5), together with the bindings of its own writes
  (§8.4). Implementations MUST persist a binding **learned from a
  manifest** only after the bundle it names has been applied; a read
  that stops after step 4 (a listing-only session) MUST NOT record
  bindings — otherwise a never-applied bundle whose objects are
  interior history would be skipped forever, because step 5's re-apply
  trigger sees only missing ref tips. A device's OWN bindings are
  exempt from that rule: the objects are its own and already in its
  repository, so no skip can lose them. [7e] A manifest that binds a
  remembered sequence number to a **different** digest is INVALID —
  same error family as rollback.
  Entries are never pruned. [7f] This memory doubles as the
  applied-bundle record §6 steps 4–5 consult; it is normative validation
  input, never a discardable optimization.

  The memory has two halves, and only the first is evidence about the
  vault:

  - **confirmed** — bindings from a manifest that passed this battery,
    and the device's own writes that were acknowledged (§8.4): both the
    bundle such a write published and the numbers its `seqfloor`
    burned. The rebinding rule above applies to these.
  - **pending** — a binding the device wrote down before one of its own
    pushes and never learned the outcome of (§8.4 binding timing).
    Nobody may have taken that write, so a pending entry is NOT
    evidence about the vault and MUST NOT make a manifest INVALID: a
    manifest binding a *pending* number to a different digest is an
    ordinary race with another writer, not a fork. A pending entry
    binds the number for its own device only, through §8.4 allocation.
    What this costs is stated plainly. [7g]

  Every accepted read settles the pending half against the manifest:
  a number the manifest binds to the device's own digest becomes
  **confirmed** (the push did land, whatever the transport said); a
  number the manifest's `seqfloor` has reached without binding it to
  the device drops out (the write is not in this line, and that same
  `seqfloor` burns the number for every writer); a number still above
  `seqfloor` stays pending.

  A device's own acknowledged write settles it the other way. When a
  writer publishes a generation whose `seqfloor` reaches a number it
  was holding pending, that number becomes **confirmed** — see §8.4's
  binding timing, which explains why the number can no longer be bound
  legitimately in this line, and why that turns the guess into an
  observation.

A pinned reader MUST also treat an *empty* vault (no manifest at all)
as an error; otherwise a host could serve an empty tree to reset the
pin, laundering a rollback through re-initialization. (A manifest-only
generation — empty *bundle list* — is not an empty vault and is valid,
§9.)

**Notes to §7.4.** Background; nothing here adds a rule.

**7d.** The twin check is a MUST, not a SHOULD: the formal model's proofs
assume it unconditionally.

**7e.** Two kinds of own binding reach the memory, and neither can lose
objects the way an unapplied manifest binding could. The bundle a write
published is applied by construction — the writer built it from its own
repository. A number the writer's `seqfloor` burned was never published at
all, so no bundle exists to apply and none ever can (§8.4 note 8e); that
entry exists only to restore the rebinding check over the number.

**7f.** Each entry is a few dozen bytes per allocated sequence number,
forever, and pruning would reopen exactly the window this rule closes.

**7g. What the pending half costs, stated plainly.** A number that goes
pending and then drops out unconfirmed leaves this device's memory without
ever having been evidence, so a fork that binds that number to different
content is not caught *by this device, by this check*. That is not a choice
between safe and unsafe but between two failure modes the writer cannot tell
apart: its write may have landed and been forked away, or may never have
landed and the number legitimately taken by another writer. Treating the
hypothesis as evidence refuses the second case too — an ordinary two-writer
race after a dropped connection — and leaves §7.5 `forget`, which ACCEPTS
real attacks, as the only way out.

The exposure is bounded in time, not permanent. It lasts only until this
device's next acknowledged write, which confirms the number by burning it
(§8.4). Before that, the ambiguity is genuine — a concurrent writer really may
be allocating the same number from the same base at that moment. After it, the
full rebinding check applies again. Detection also survives elsewhere
throughout: the counter, twin and `seqfloor` checks are unaffected, and any
device that read the landed generation holds the binding CONFIRMED and still
refuses the fork. In the formal model this limit is not an exception to
`inv_p3_neverReuse` but a consequence of it: giving up a pending binding
drops the device's own unconfirmed claim along with it (`forgetOwn`), so
one sequence number never carries two claims.

**7h.** The divergence is silent because every check passes against the
pin it is run against: through URL A the repository saved counter 2,
through URL B counter 3, and a replay of counter 2 through A meets A's
pin at counter 2 — equal counter, same manifest, accepted. The device's
view of the vault has gone backwards with nothing firing. With one pin
the same replay is a rollback. The model's `neg_alias` configuration
carries this and its sequence-rebinding form (`spec/README.md`).
Merging per-URL pins into the one pin, for implementations that once
kept them, MUST keep every confirmed binding of every record — taking
the record with the highest counter discards memory — and MUST fail on
records that contradict each other (an equal counter with a different
manifest digest, a number bound to two digests, a different
objectformat): those are a fork or rollback already observed, not a
tie to break.

### 7.5 Discarding the pin

Implementations SHOULD make deliberate vault re-creation recoverable by
telling the user how to discard the pin — with wording that warns
against doing so while under attack, since these errors fire precisely
when the host is misbehaving. Discarding the pin forfeits every
protection in §7.4 until the next successful read re-establishes it:
the formal model's `forget` run pair demonstrates the forfeit exactly.
The legitimate use is a vault deliberately deleted and re-created at
the same URL; when the new vault can live at a new URL instead, no
discard is needed anywhere (a new vault has a new identity, and pins
are per vault). A discard is scoped to one URL: it removes that URL's
binding (§7.4), and the vault's pin only when no other URL of the
repository is still bound to that vault identity. That never blocks
the legitimate use, since a re-created vault carries a new identity
and the unbound URL meets it as first contact — and it means an
attacker cannot be helped by a partial discard: every URL still bound
keeps the whole memory.

## 8. Writer algorithm (push)

Writers MUST operate only from a complete repository whose object
format equals the vault's `objectformat`: a writer MUST refuse a
shallow or partial/promisor repository [8a], and MUST refuse a source
repository of the other object format. The initial HEAD symref of a
freshly initialized vault SHOULD be taken from the source repository's
HEAD;
implementations that cannot do that MUST pick deterministically and
document the rule.

1. Fetch the vault branch; validate and read the manifest as in
   §6.1–6.4 (an empty vault — no manifest, no bundles — reads as no
   refs).
2. For each ref update `old → new`, where `old` is the manifest value:
   non-forced updates MUST be refused unless `old` is an ancestor of
   `new`. A writer that does not have `old` locally cannot verify
   this, so it MUST refuse and tell the user to fetch first. Forced
   updates and new refs are applied unconditionally. Deletions remove
   the manifest entry and need no bundle.
3. Create one bundle containing the pushed tips, excluding history
   reachable from any pre-update manifest sha present in the writer's
   repository. (This satisfies §4.3's prerequisite-closure rule.) git
   may refuse because the bundle would be empty — every object is
   already in the vault, as in a deletion-only or ref-move-only push.
   In that case proceed without a bundle: a manifest-only update is
   valid. For implementations whose bundle writer has no such refusal,
   the semantic rule is: the bundle MAY be omitted **only when every
   updated ref's new sha names an object already contained in the
   current manifest generation's bundles**. For an annotated tag, that
   object is the tag object itself, not its target commit. Counting
   new *commits* is NOT a valid emptiness test: a tag-only push has
   zero new commits but still needs its tag object shipped. Detecting
   git's refusal by parsing its (localized) message is NOT acceptable
   (§8.5's rationale); apply the semantic rule with plumbing instead
   (e.g. `git rev-list <new> --not <excludes>` for commit tips). An
   implementation MAY conservatively ship a bundle whenever it cannot
   cheaply prove containment — a redundant bundle is harmless.
4. When step 3 produced no bundle, nothing is allocated: the manifest
   write updates refs, HEAD, and counter only, and `seqfloor` is
   carried unchanged. Otherwise, allocate a sequence number,
   starting at `seqfloor + 1`. **Allocation guard:** a writer MUST NOT
   bind a sequence number present in its sequence memory (§7.4) to new
   content. The two halves of that memory call for different handling:

   - A **confirmed** entry at `seqfloor + 1` proves the base the writer
     fetched predates this device's own history — for example, its own
     acknowledged push replayed away by the host — so it MUST refuse
     and instruct a refetch rather than proceed. [8b]
   - A **pending** entry is this device's own write of unknown fate.
     The writer MUST NOT bind that number to new content, and MUST NOT
     refuse it either. [8c] Instead the writer
     leaves the number unpublished and allocates the next one,
     repeating until it reaches a number in neither half. The
     `seqfloor` it then publishes burns the skipped number for every
     writer. Gaps are legal: §4.1 sets no contiguity requirement, only
     `seqfloor` ≥ every listed sequence and `-full` at the lowest
     listed one.

   Then: encrypt; record the ciphertext digest; chunk if over
   threshold; write the manifest with updated refs, HEAD, bundle list,
   incremented counter, and updated `seqfloor`; commit all of it as
   **one commit**; push the vault branch (non-forced). Label the
   bundle per §4.1's `-full` rule. **Binding timing:** a writer MUST
   record its own (sequence → digest) binding as PENDING in the
   sequence memory
   BEFORE it learns the push's outcome, and MUST keep it unless the
   push was definitively rejected (§8.5) — the vault-initializing
   write is the one exception, having no pin to record into [8d] —
   a lost acknowledgment must never lead to re-allocating the number
   (the model's crash-lag case). On acknowledgment the binding becomes
   CONFIRMED: its own bundle is applied by construction. **So does every
   number this device was holding pending at or below the `seqfloor` it
   just published**: publishing that `seqfloor` burns them, so the writer
   MAY promote them to confirmed and get the §7.4 rebinding check back.
   [8e] A binding whose acknowledgment never arrived and that no later
   write has burned is settled by §7.4's rule on the first accepted read.
   The base manifest's bundles were read, not applied,
   and are NOT recorded by a push (§7.4). The rest of the pin (counter,
   twin digest, `seqfloor`) advances only after the acknowledgment. If
   the manifest's HEAD symref names a ref this push deletes, the writer
   re-picks deterministically and documents the rule (e.g. the source
   HEAD if pushed, else `refs/heads/main`, else the first branch, else
   no HEAD line).
5. If the vault push is rejected (another writer won the race),
   discard the local vault state and retry from step 1 — including
   re-running the checks in step 2 against the new manifest. Rejection
   detection MUST NOT depend on human-readable (localized) git output;
   use a machine-readable mode such as `git push --porcelain`.

   **Definitive rejection.** Only a *ref-level* rejection reported by
   the remote is definitive — proof that the update did not land, and
   the only outcome that may withdraw the §8.4 binding. A push that
   ends without such a verdict is NOT definitive: the connection
   dropped, the process was killed, the credential expired mid-upload,
   or the remote took the update and its status report was lost. git
   reports the last as `[remote failure] (remote failed to report
   status)` and flags it `!`, exactly like a rejection, so the flag
   alone MUST NOT decide. The update MAY have landed, so the binding
   stays pending. Implementations MUST classify from the
   machine-readable status, MUST treat a status they do not recognize
   as non-definitive, and SHOULD retry — a later read settles the
   binding (§7.4) — rather than fail hard on an outcome that is merely
   unknown. Reading a lost status report as a rejection re-binds the
   number to fresh ciphertext, which is the crash-lagged-writer attack
   §8.4 exists to stop.

A single vault commit is the unit of atomicity: bundles and the
manifest describing them MUST land together.

Writer hygiene — vault commits MUST NOT carry identifying metadata:

- Implementations MUST set fixed author/committer names and a fixed
  timestamp (e.g. the Unix epoch, UTC).
- They MUST NOT sign vault commits, tags, **or pushes**. A signature
  identifies the writer to the host — and that includes a push
  certificate, which a malicious host can solicit simply by
  advertising push-cert support.
- They MUST disable all content transformation in the vault
  repository: line-ending conversion, filters, hooks. Each of these
  overrides MUST beat any user-level git configuration or environment,
  **and any attributes file carried in the vault's own tree** — the
  tree is host-writable, and a planted `.gitattributes` must not be
  able to re-enable transformation.

Unconverted bytes are load-bearing: age ciphertexts are binary, and a
small manifest can pass git's text heuristic, so an inherited
`autocrlf` setting silently corrupts it.

**Notes to §8.** Background; nothing here adds a rule.

**8a.** git bundles cannot represent a shallow boundary, and `git bundle
create` does not reliably error on one — it can emit a bundle whose history
cannot be reconstructed, while reporting success.

**8b.** Fail-closed: a host that keeps serving the stale state wedges this
writer; it never causes a sequence reuse. The model's verifier found the
attack this guard closes.

**8c.** An unreported push is an everyday event on a mobile connection, and
refusing would wedge every later push and compaction — with §7.5 `forget`,
which ACCEPTS the attacks this format defends against, as the only escape.

**8d.** Why initialization is exempt: creating a pin just to hold the
pending binding would break the retry. §7.4 requires a pinned reader to
refuse an empty vault, so a pin holding nothing but a pending binding
would turn a genuinely empty remote into a hard error on the second
attempt. Nothing is lost by the exemption — there is no pinned state to
protect, and a re-attempt after an unreported initialization meets a
branch that now exists, which the non-forced push refuses.

**8e.** Why publishing the `seqfloor` burns them: the generation just written
does not list them (its bundle list is the base's, whose sequences all sit at
or below a lower `seqfloor`, plus the writer's own), no ancestor lists them
for the same reason, and every later writer allocates above a `seqfloor`
already past them. A concurrent writer that had taken one would have shown it
in this writer's own base, where §7.4 settled it instead. From that point a
manifest binding one of these numbers to anything else is a fork — which is
what keeps the exposure §7.4 describes down to the window before the next
acknowledged write.

## 9. Compaction

Purpose: bound chain length, and make deletions and rewritten history
*actually disappear* from the host.

A writer whose repository contains every manifest sha MAY compact:

1. Fetch the vault branch and record its current tip `T`; validate and
   apply as in §6.
2. Create one `-full` bundle containing every manifest ref (with real
   names and a HEAD entry, §4.3), at a sequence number allocated by
   §8.4 (`seqfloor + 1`, skipping this device's pending bindings).
   Compaction cannot re-publish a pending bundle even in principle:
   §4.1 requires the LOWEST listed sequence number to carry `-full`,
   and the compacted list holds exactly one bundle. Skipping is
   therefore the only handling available here — which matters, because
   a compaction is one large upload and so the operation most likely to
   end without a verdict.
3. Build a tree containing only that bundle's file(s), the rewritten
   manifest (same refs, new bundle list, incremented counter, updated
   `seqfloor`), `sealed-format`, and any preserved unknown entries
   (§3 — erasing those would defeat the forward-compatibility rule;
   bundle-shaped non-canonical entries are dropped, also §3). Commit
   it as a **single parentless commit**. [9a]
4. Replace the vault branch with that commit using a
   **compare-and-swap push against `T`** (e.g.
   `git push --force-with-lease=<branch>:<T>`). A plain force-push is
   forbidden: it would silently erase a concurrent push that landed —
   and was acknowledged to its writer — after step 1. On rejection,
   restart from step 1.

**Zero-ref compaction.** A vault whose refs were all deleted MAY be
compacted into a **manifest-only generation**: the tree holds only
`sealed-format`, the rewritten manifest (empty bundle list, empty
refs, incremented counter, `seqfloor` UNCHANGED), and preserved
unknown entries; there is no bundle, and no sequence number is
allocated. Steps 1 and 4 apply unchanged. Because `seqfloor` is
preserved, numbering never restarts; the next push into such a
generation is labeled `-full` per §4.1 and is a complete,
prerequisite-free snapshot by construction — recovery is re-rooted.
An intentionally emptied vault recovers to nothing, by design.

Readers are already required (§6.1) to tolerate the force-update.
The host may internally retain unreachable objects for a while after
compaction. That retention is outside this format's control — which is
precisely why §6.4 forbids applying resurrected files.

**Notes to §9.** Background; nothing here adds a rule.

**9a.** Why parentless: a normal commit would keep every pruned ciphertext
file reachable in the vault's own git history, so deleted content would never
leave the host.

## 10. Security considerations

- **What the host sees:** the number of logical bundles, their
  ciphertext sizes, and their chunk boundaries; the timing and
  frequency of pushes and compactions; which pushes carried no new
  bundle (a deletion or ref-move); the size of `sealed-manifest.age` and its
  per-push deltas — age adds no padding, so refname-length changes
  show through; the lifetime push *attempt* count, via sequence numbers —
  §8.4 allocation skips a number whose fate the writer never learned, so
  the gaps reveal how often a device's pushes went unreported, and
  `seqfloor` carries that count forward even to a different host — and
  the `counter` trend implied by push frequency; and age header metadata
  (recipient count, recipient types, plugin names), including when the
  recipient set changes. Vault commits carry no identifying author or
  timezone data when §8's hygiene rule is followed. Traffic analysis
  of all of the above is out of scope.
- **Integrity:** each age file authenticates its whole plaintext on
  decryption — against tampering by anyone who does not know a vault
  recipient. age provides **no sender authentication**: encrypting
  needs only a recipient string, so anyone who learns one can produce
  valid ciphertexts, and files carry no per-writer signature.
  Knowledge of a recipient is therefore effectively the write
  capability. Recipients are far lower-stakes than identities, but
  they are not public keys to publish: share them only among a vault's
  own devices.
  The manifest's bundle list, digests, and chunk counts bind the file
  set; the vault identity binds files to their vault; the counter
  orders manifest generations; the sequence memory binds every
  observed number to one ciphertext forever; git object hashing and
  bundle prerequisite checks verify the reassembled history. A
  tampered, truncated, reordered, resurrected, cross-vault-
  substituted, rolled-back, or sequence-rebound state fails one of
  these checks. Rollback and re-binding detection are
  trust-on-first-use per device (§7.4), so a *new* device
  bootstrapping from a rolled-back vault cannot know better. One
  attack no per-device pin can catch: a host serving *different
  devices* diverging vault states that each advance forever (a fork).
  Detecting that requires comparing state across devices out of band;
  §7.4's twin, seqfloor, and sequence-memory checks narrow it to
  forks built from states genuine writers produced and the host
  actually possesses — and make any fork that ever re-binds a
  **confirmed** sequence number detectable on this device. A number
  this device left *pending* and then dropped unconfirmed (§7.4) is
  the documented exception: the writer cannot distinguish "my write
  landed and was forked away" from "my write never landed and someone
  else took the number", so it does not refuse on that basis. Any
  device that read the landed generation holds the binding confirmed
  and still refuses the fork.
- **Formal grounding:** the reader/writer rules above are
  machine-checked at stated bounds (§2, `spec/README.md`), under
  these cryptographic assumptions: age ciphertexts cannot be created
  or opened without a recipient/identity, and the SHA-256 digest binds
  ciphertext content perfectly.
- **Key loss is unrecoverable** by design. Deployments SHOULD encrypt
  to at least two recipients, one of them an offline recovery key.
- **Key distribution is out of scope.** How identities reach devices
  (QR, password manager, hardware token via age plugins) is a client
  concern.

## Appendix A. Disaster recovery with stock tools

Given the vault files and an identity `key.txt`: start from the `-full`
bundle with the **highest** sequence number (an uncompacted vault has
only `1-full`), then apply every incremental with a higher sequence,
**in ascending numeric order** — the listing order of `ls` is NOT
numeric order for unpadded names; compare the numbers themselves.
`git pull` is deliberately avoided: it merges, which breaks on
force-pushed history and restores only one branch. The incremental
refspec is `+refs/*:refs/*`, not just heads and tags. A repository may
hold `refs/notes/*`, `refs/replace/*`, or other refs whose objects are
unreachable from any branch; a heads/tags-only fetch would silently
drop them.

```sh
# If chunked (parts .0 .1 .2 ...): reassemble each logical file first.
# Run this ONLY for a name that has a ".0" part — on a whole (unchunked)
# file the loop runs zero times and `> "$n"` truncates it to empty.
# Count-free POSIX loop — works everywhere, needs no part count:
n=7-full.bundle.age
i=0; while [ -f "$n.$i" ]; do cat "$n.$i"; i=$((i+1)); done > "$n"
# (GNU coreutils only: `cat $(ls -v $n.*)` is equivalent. Do NOT use it
# on BSD/macOS — their `ls -v` means something unrelated and misorders
# silently. The bare glob `cat $n.*` misorders past .9 on every system.)

# highest full bundle -> a bare repository, then map ALL of its refs in
age -d -i key.txt 7-full.bundle.age > full.bundle
git clone --bare full.bundle recovered.git                 # sets HEAD
git -C recovered.git fetch ../full.bundle '+refs/*:refs/*' # notes/replace/etc.

# each later bundle, in ascending numeric order
age -d -i key.txt 8.bundle.age > inc.bundle
git -C recovered.git fetch ../inc.bundle '+refs/*:refs/*'

# working tree
git clone recovered.git restored
```

If reassembly or decryption fails, suspect part order or a missing part
before suspecting corruption — a wrong concatenation order cannot be
silent (age's chunked MAC fails loudly), and a missing part fails the
final-chunk check. The authoritative diagnostic is the manifest: you
hold the key, and `sealed-manifest.age` is tiny — decrypt it; each
`bundle` line gives the exact expected parts (`.0` … `.(count−1)`) and
the SHA-256 of the reassembled ciphertext.

The result reflects the bundles' embedded ref claims, which can lag the
manifest (a branch deleted since the last compaction may reappear; a
rewritten branch's old tip may linger). For an exact-refs restore,
additionally decrypt `sealed-manifest.age` and apply its ref lines with
`git update-ref` (and delete refs it does not list).

An intentionally emptied vault (all refs deleted, then compacted, §9)
contains no bundles and recovers to nothing — that is not damage.

**Adversarial-host recovery (paranoid variant).** The recipe above
scans filenames and trusts the highest `-full`. A malicious host could
exploit that: it could plant a higher-numbered `-full` from a different
vault, or resurrect pre-compaction files. If that is a concern, do not
trust the filenames. Decrypt `sealed-manifest.age` first and use **only** its
`bundle` list: the listed names, their exact part sets, and their
digests (verify with `sha256sum` after reassembly) — the manifest is
encrypted to your keys, so the host cannot have forged it. Refuse any
extra or missing file, apply exactly those bundles, and set the refs
from the manifest's ref lines. In particular, if `sealed-manifest.age` decrypts
to a `vault` id you do not expect, stop: you are holding files from
two different vaults — both possibly your own — and would recover the
wrong one. For a routine recovery from your own storage, the simple
recipe is almost always what you want.

## Appendix B. Version history

- **2** (2026-09-02): the first published version. SHA-1 and SHA-256
  source repositories via the `objectformat` line, with strict
  bundle-version mapping; unpadded, value-bounded sequence and chunk
  numbers, apply order defined numerically, canonical form (no leading
  zeros) required, with the read-tolerant/write-strict rule for near-miss
  names; chunk counts on `bundle` lines and the expected-file-set rule
  (§6.7); the `seqfloor` line; `-full` keyed to bundle-list emptiness;
  zero-ref compaction (manifest-only generations); trust-on-first-use
  pinning of vault identity, counter, manifest-ciphertext digest, format,
  objectformat and `seqfloor`, plus the normative **sequence memory**
  (seq→digest, read- and write-side) — the last found by the formal
  model, which this version carries as the normative companion for the
  protocol core (§2).
- **Errata** (2026-09-05): §7.4 allowed pins keyed by remote URL with a
  per-vault fallback on first contact. Once two URLs of one vault each
  held a pin, their memories diverged and a host could replay an old
  generation through the staler URL (note 7h; the model's `neg_alias`
  control). The pin is now one per vault identity, each URL keeps a
  durable binding to its vault, §6.1's serialization spans every URL of
  a repository, and §7.5's discard is scoped by binding. Reader-local
  state only: no wire-format change.
- **Errata** (2026-09-04), from an adversarial review of the changes made
  after the previous one: §7.4's
  persist-after-apply rule contradicted §8.4's burn rule, which confirms
  numbers whose bundles were never published — the rule is now scoped to
  bindings learned from a manifest, with note 7e covering the writer's
  own (M1); §8.4's binding-timing MUST now states the initialization
  exception both implementations always had, with note 8d for why a pin
  cannot be created there (L4); §10 said sequence numbers leak the
  lifetime push count, but since allocation skips unreported numbers they
  leak the *attempt* count (L5). No wire-format change.
- **Appendix A errata** (2026-09-03): the incremental-apply commands used
  a bundle path relative to the current directory while running under
  `git -C recovered.git`, which resolved it inside `recovered.git` and
  failed; corrected to `../full.bundle` / `../inc.bundle`. Added a
  warning that the chunk-reassembly loop must be run only for chunked
  names (its `> "$n"` truncates a whole file). No normative change —
  the recovery procedure is not part of the wire format; found by the
  Rust reference's test that executes Appendix A verbatim.
