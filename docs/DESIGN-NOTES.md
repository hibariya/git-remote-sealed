# Design notes

These are the background explanations and version history moved from
[FORMAT.md](FORMAT.md), with their wording preserved. Section numbers and
§ references below refer to FORMAT.md. These notes explain the rules;
FORMAT.md §2 still defines the authority split with the Quint model.
Notes 7d and 7h remain in FORMAT.md because they state requirements.

<a id="section-3"></a>

## Notes for §3

<a id="note-3a"></a>

**3a.** Without this rule, deleting one file would make the vault read as
empty. The next innocent writer would then rebuild a manifest containing only
its own refs — turning one deleted file into propagating ref loss.

<a id="note-3b"></a>

**3b.** The bundle namespace is owned by this spec, so such a name can only be
a decoy or corruption, never a future extension. A hard error would let a
malicious host wedge every operation with one planted file, since reading
precedes every write and every repair.

<a id="note-3c"></a>

**3c.** So host-planted decoys cannot ride the preservation rule across
compaction's history rewrite, or poison the recovery procedure indefinitely.

<a id="section-4-1"></a>

## Notes for §4.1

<a id="note-4a"></a>

**4a.** Canonical form is load-bearing: it gives every logical value exactly
one spelling. Together with §7.2's rule that no two `bundle` lines share a
sequence number (with or without `-full`), every sequence number resolves to
at most one tree entry.

<a id="note-4b"></a>

**4b.** Appendix A's recovery relies on this rule: "start from the highest
`-full`" is only sound if `-full` always means the whole vault, and if every
generation with bundles is rooted in one.

<a id="section-4-3"></a>

## Notes for §4.3

<a id="note-4c"></a>

**4c.** Why not v3 everywhere: Appendix A wants the widest stock-git
compatibility, and v2 bundles are readable by every git that can run the
recipe at all.

<a id="note-4d"></a>

**4d.** git records whatever names it is given at creation time, so a writer
that bundles via temporary refs must rewrite the header afterwards. That is
possible because the header is plain text, terminated by the first blank line;
the binary packfile follows it.

<a id="section-5"></a>

## Notes for §5

<a id="note-5a"></a>

**5a.** In principle the recipient/identity split allows an asymmetry: a
device holding only recipients could *write* backups without ever being able
to read the vault. Treat write-only operation as a possible future profile,
not something to implement from this document.

<a id="section-6"></a>

## Notes for §6

<a id="note-6a"></a>

**6a.** For example `git bundle verify` followed by `git bundle unbundle`:
`unbundle` alone performs no prerequisite check, and `verify` is what asserts
§4.3's promise.

<a id="section-7-3"></a>

## Notes for §7.3

<a id="note-7a"></a>

**7a.** This is safe because producing a manifest ciphertext that decrypts at
all requires knowing a vault recipient (§5, §10), which the host does not, so
the host cannot inject lines. It is how future 2.x versions add fields without
breaking deployed readers.

<a id="note-7b"></a>

**7b.** Arity errors on recognized tokens fail parsing outright, which would
brick deployed readers instead of degrading them; new line types degrade them
to read-only via the next rule, which is the intended failure mode.

<a id="note-7c"></a>

**7c.** A writer regenerates the manifest from the fields it knows, so a
writer that does not understand an extension line would silently delete that
line on its next push.

<a id="section-7-4"></a>

## Notes for §7.4

<a id="note-7e"></a>

**7e.** Two kinds of own binding reach the memory, and neither can lose
objects the way an unapplied manifest binding could. The bundle a write
published is applied by construction — the writer built it from its own
repository. A number the writer's `seqfloor` burned was never published at
all, so no bundle exists to apply and none ever can (§8.4 note 8e); that
entry exists only to restore the rebinding check over the number.

<a id="note-7f"></a>

**7f.** Each entry is a few dozen bytes per allocated sequence number,
forever, and pruning would reopen exactly the window this rule closes.

<a id="note-7g"></a>

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

<a id="section-8"></a>

## Notes for §8

<a id="note-8a"></a>

**8a.** git bundles cannot represent a shallow boundary, and `git bundle
create` does not reliably error on one — it can emit a bundle whose history
cannot be reconstructed, while reporting success.

<a id="note-8b"></a>

**8b.** Fail-closed: a host that keeps serving the stale state wedges this
writer; it never causes a sequence reuse. The model's verifier found the
attack this guard closes.

<a id="note-8c"></a>

**8c.** An unreported push is an everyday event on a mobile connection, and
refusing would wedge every later push and compaction — with §7.5 `forget`,
which ACCEPTS the attacks this format defends against, as the only escape.

<a id="note-8d"></a>

**8d.** Why initialization is exempt: creating a pin just to hold the
pending binding would break the retry. §7.4 requires a pinned reader to
refuse an empty vault, so a pin holding nothing but a pending binding
would turn a genuinely empty remote into a hard error on the second
attempt. Nothing is lost by the exemption — there is no pinned state to
protect, and a re-attempt after an unreported initialization meets a
branch that now exists, which the non-forced push refuses.

<a id="note-8e"></a>

**8e.** Why publishing the `seqfloor` burns them: the generation just written
does not list them (its bundle list is the base's, whose sequences all sit at
or below a lower `seqfloor`, plus the writer's own), no ancestor lists them
for the same reason, and every later writer allocates above a `seqfloor`
already past them. A concurrent writer that had taken one would have shown it
in this writer's own base, where §7.4 settled it instead. From that point a
manifest binding one of these numbers to anything else is a fork — which is
what keeps the exposure §7.4 describes down to the window before the next
acknowledged write.

<a id="section-9"></a>

## Notes for §9

<a id="note-9a"></a>

**9a.** Why parentless: a normal commit would keep every pruned ciphertext
file reachable in the vault's own git history, so deleted content would never
leave the host.

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
