# Formal models — sealed vault format v2 (Quint)

Two machine-checked models of the protocol rules in `docs/FORMAT.md` §4–§9, built
independently of each other:

| | `protocol_core.qnt` | `protocol.qnt` |
|---|---|---|
| Built from | the format plan and FORMAT.md | `src/` and `docs/`, without reading `protocol_core.qnt` |
| Scope | pins, sequence allocation, compaction, `forget`: the steady state, devices pinned from genesis | all of that, plus vault init, commits and refs, recipients (enroll / revoke), URL → vault bindings, the three push outcomes, and the pin handling of `writer.rs` / `reader.rs` / `compact.rs` |
| Checked by | `quint verify` (Apalache) to a stated depth, plus simulation | sampled `quint run` only |
| Run by | `spec.sh`, and CI | the commands in its section below |
| Tests / controls | configuration modules in the same file | `protocol_test.qnt`, `protocol_controls.qnt` |

`protocol_core.qnt` is smaller and proved more thoroughly: exhaustively up to its
depth, where `protocol.qnt` samples. It also models two things `protocol.qnt`
leaves out: a host that acknowledges pushes falsely, and file-set exactness (P1).
`protocol.qnt` covers more of the protocol and is closer to the code. That is how it
found a defect `protocol_core.qnt` cannot reach, because that model has no rejected
pushes: after a rejected push, `writer.rs` forgot a sequence binding it had just
confirmed, and a malicious host could then get a rebinding of that number accepted.
It is fixed, with a Rust regression test (finding 1 under `protocol.qnt`).
FORMAT.md §2 names `protocol_core.qnt` as the normative companion model.

`basicSpells.qnt` is the Quint standard helper library used by `protocol.qnt`,
copied unchanged from the Quint LLM kit's examples. `warm.qnt` only warms the
container's Quint cache (`Dockerfile`).

Run them:

```sh
./spec/spec.sh                      # protocol_core.qnt, fast lane: ~15s of compute
./spec/spec.sh --full               # + the absence proofs

podman compose run --rm spec        # the same, needing no host toolchain
podman compose run --rm spec-full
```

`spec.sh` is the only definition of what checking `protocol_core.qnt` means — CI
calls it too. The fast lane runs on every push; `--full` adds the symbolic
absence proofs, which take from ~40 minutes upward (see "Why these
bounds") and stay manual. `protocol.qnt` is not in `spec.sh` yet; its commands are
in its section below.

## protocol_core.qnt

A model of the v2 steady-state protocol: devices pinned from genesis, against the
adversary `docs/FORMAT.md` §1 and §10 describe. This section maps the model to that
spec and records what the model has found.

### What is modeled

One vault. The **host is the adversary**: it keeps every generation any
genuine writer ever produced and may serve any of them to any device
(rollback, fork), and may acknowledge any push (fork creation); it cannot
forge or open ciphertexts. Devices are established (pinned from genesis)
and run the v2 acceptance battery on every read. Writer actions: bundle
push, manifest-only push, two-phase compaction (observe, then
compare-and-swap commit), crash between acknowledged push and pin update
(the T9 lag window).

**URL aliases.** A device reaches the vault through one of `ALIASES` —
spellings of the remote URL that the host serves identically. Where a
device keeps its pin is a *slot*: `(device, alias)` with one pin per
URL, or `(device, "*")` with the one pin per vault that FORMAT.md §7.4
requires (`SHARED_PIN`). Every read, push and compaction names the
alias it goes through and consults that slot's pin and memory. P3's
witness (`trusted`) stays per DEVICE: however many URLs it uses, one
local repository holds the objects — so two slots that disagree are one
device contradicting itself, and P3 is what catches it. The URL →
vault-identity binding of §7.4 is not modeled: the model has one vault,
and substitution is a format-level (identity) check, not a protocol one.

### Configurations

| Module | Pins | Host | Purpose |
|---|---|---|---|
| `neg_nopin` | counter+digest only | malicious | negative control: review round 1's fork-hop must violate P3 |
| `neg_sfonly` | + seqfloor (plan rev 2) | malicious | **the model's finding: still violates P3** (see below) |
| `neg_alias` | full set, but one pin PER URL ALIAS | malicious, 2 devices, 2 aliases | negative control: the 0.1.0 alias bug — a stale alias accepts a rollback, and P3 falls (see below) |
| `full` | + seq→digest memory, one pin per device | malicious, 3 devices, 2 aliases | scripted attack tests + 10k-trace simulation (all invariants incl. P1) |
| `full2` | + seq→digest memory | malicious, 2 devices, 1 alias | symbolic proof of P2/P3/P5 (depth: see "Why these bounds") |
| `honest` | full | honest git | P4 (CAS durability) proved at depth 5 + simulation |
| `neg_force` | full | honest, force-push compact | negative control: §8's CAS rule is load-bearing |

Negative controls run before the proofs (`spec.sh`) and double as
calibration: the
scripted violations are at most 6 steps (the alias one takes 4), and
the verifier demonstrably finds them at depth 6 in seconds. The absence proofs run below the
deepest known attack (6 steps), so the 6-step attack class is covered by
these controls plus the deterministic guard tests, not by the symbolic
proof (see "Why these bounds").

#### Why these bounds (measured, not chosen)

Symbolic checking cost grows ~10–60× per depth level here. The 3-device
instance stalls Z3 around depth 5–6, and even the 2-device instance
wedges at level 6 (observed: 13h on one instance, no progress).

**Removing P3's carve-out (2026-09-05) raised this cost.** An invariant
with an exception is cheap to discharge — any candidate violation can be
explained by the exception — and the unweakened `inv_p3_neverReuse` has
to establish that one sequence number never carries two claims at all.
Measured on the same machine:

| model | depth 4 | depth 5 |
|---|---|---|
| weakened P3 (`admitted`), before | not measured | ~3.5h |
| unweakened P3 | **39 min, NoError** | ≥7h32m, no result |

Depth 5 has been attempted twice on a 20-core laptop and completed
neither time: 9h15m with `forgetOwn` written as a fold of set filters,
then 7h32m after rewriting it as a single filter (identical set, far less
nesting — that rewrite is what the depth-4 figure is for). Neither run
printed an outcome; both were abandoned. Note that the second was killed
rather than failing, and its wrapper reported exit 0 — the only reliable
signal is Apalache's own `The outcome is: NoError` line, so check for
that rather than the exit status.

The proved depth for `full2` is therefore **4**. So the claims are,
precisely:

- **Proved (Apalache): P2/P3/P5 hold for two devices up to 4 steps
  under the full adversary; P4 likewise for the honest host at 5.**
- **The 6-step attack class** (the deepest known attacks) is covered by
  the negative controls — the verifier demonstrably FINDS all known
  6-step attacks at depth 6 in seconds — and by the deterministic
  scenario tests showing the full pin set refuses each of them.
- **Beyond that**: 10,000 random traces × 12 steps × 3 devices per
  config. P1's powerset is simulator-cheap but symbolically
  intractable, so it lives in the simulation stage only.

A machine with more patience than a laptop can raise the proof depth by
passing `--depth` to `spec.sh`; nothing else changes.

**The proof configurations use one alias, without loss of generality.**
With `SHARED_PIN` every alias maps to the same slot, so a second alias
adds a nondeterministic choice that changes no state; it would only
cost the symbolic verifier branching. The two-alias behaviour is
exercised where it can differ — `neg_alias` (the verifier finds the
attack) and `full` (scripted refusals plus the 10k-trace simulation
with both aliases in `step`). Both depth-4 proofs were re-run after
the alias change (2026-09-06): `full2` NoError in ~40 min, `honest` in
~25 min.

### Properties

- **P1** `inv_p1_acceptExactness` — the file-acceptance predicate
  (set-equality + digest match) admits exactly the manifest's file set;
  no chimera assembled from other genuine bundles passes.
- **P2** `inv_p2_guardMonotone` — acceptance implies monotone
  observations (counter, seqfloor). The stronger "only descendants are
  accepted" is deliberately absent: it is FALSE under a malicious host —
  the fork admission FORMAT.md §9 already makes — and the model can
  exhibit the fork trace. Per-device pins narrow forks; they cannot
  eliminate them.
- **P3** `inv_p3_neverReuse` — the crown: along one device's accepted
  history, a sequence number is never bound to two different contents.
  The applied-bundle cache's skip-without-rehash and resurrected-file
  detection both lean on this. It holds with **no exception**, and the
  pending half is what lets it. A pending binding is a hypothesis, not
  an observation — the writer cannot tell whether its write landed and
  was forked away or never landed and the number was legitimately taken
  — so it does not filter reads. Making it filter reads is what wedged
  a writer permanently after any unreported push (FORMAT.md §8.4's
  pending half). When such a binding is given up, the device also drops
  its own never-confirmed bundle from the witness set (`forgetOwn`),
  exactly as the implementations do: they delete the pending entry and
  keep nothing. So the witness set never holds two claims at one number
  and P3 needs no carve-out.
  What the device gives up is stated in FORMAT.md §7.4 note 7g: a fork
  that re-binds a number it dropped unconfirmed is not caught by that
  device, by that check. Its own next acknowledged push ends the window
  by burning the number (`burnedBy`), and any device that read the
  landed generation holds the binding CONFIRMED and still refuses the
  fork. `pendingDroppedIsForgottenNotCarvedOutTest` walks it.

  An earlier revision carved the class out instead, in a variable
  `admitted` bounded by `inv_p3_holeIsPendingOnly`. That was weaker in
  two ways the 2026-09-04 review found: the bound did not actually say
  "pending only" (it was satisfied by any number the device had merely
  read), and `admitted` never shrank, so P3 grew weaker the longer a run
  went. Both are gone.
- **P4** `inv_p4_durability` — honest host: an acknowledged push is never
  erased by a concurrent compaction (the §8 CAS argument).
- **P5** `inv_p5_prereqClosure` — ascending numeric apply order never
  misses a prerequisite.
- **Recovery rooting** `inv_p_rooting` — every generation with a
  nonempty bundle list has a prerequisite-free bundle at its lowest
  sequence number: the complete snapshot the Appendix A recovery starts
  from. Guards plan rev 2's rekeyed `-full` rule, including the
  zero-ref-compaction (manifest-only generation) path, whose numbering
  survival is demonstrated by `emptyVaultKeepsNumberingTest`.
- **`forget`** is modeled but excluded from the nondeterministic step:
  with the pin and memory wiped, rollback acceptance is the *expected*
  outcome. The run pair `rollbackRefusedWithoutForgetTest` /
  `forgetForfeitsRollbackProtectionTest` is the helper's warning text,
  made formal.
- **P7** — canonical representation is grammar-level, not temporal; it is
  enforced in the spec text (read-tolerant / write-strict) and does not
  appear in this state model.

### THE FINDING (2026-08-24): plan rev 2's pin set does not deliver P3

`neg_sfonly.seqfloorPinInsufficientTest`, confirmed by the verifier:

The seqfloor pin rejects the fork-hop's *intermediate* low-seqfloor state
(review round 1's F2 trace) — but not its successor. A fork line that
re-allocates an already-observed sequence number reaches an **equal**
seqfloor, and with a higher counter the acceptance battery passes:

```
gen0 ──push(bundle, crash-lag)──▶ fork A: counter 2, seqfloor 2, seq2=cA   ◀── victim pins this
  └──manifest-only ×2──▶ counter 3, seqfloor 1   (REJECTED by seqfloor pin — F2's fix works here)
       └──push(bundle)──▶ counter 4, seqfloor 2, seq2=cB   (ACCEPTED: 4>2, 2≥2 — P3 violated)
```

Root cause: seqfloor equality cannot distinguish "the allocation I saw"
from "a re-allocation that caught up".

**And the verifier then found a second, shorter variant on its own**
(`neg_*::selfReuseAfterCrashTest`, distilled from an Apalache
counterexample against the first fix attempt): no second fork line is
needed. A writer whose push crash-lagged its pin, re-served its own
pre-push state by the host, **re-allocates the same sequence number
itself** — two steps, one device. A read-side guard alone cannot catch
it, because the conflict is created by the device's own write.

The fix the model validates (`full` config) is therefore two-sided
**seq→digest memory**: a device remembers every
(sequence number → ciphertext digest) binding it has ever accepted, and

1. **read side** — rejects any manifest that rebinds a CONFIRMED
   sequence number to a different digest;
2. **write side** — refuses to *allocate* a sequence number confirmed
   in its memory (a collision proves the served base predates the
   device's own history; refuse and refetch — fail-closed), and SKIPS
   one it holds only as pending (see P3 above: refusing there wedges
   the writer, and skipping cannot reuse the number).

In implementation terms this is the applied-bundle cache, extended with
digests and **promoted from optimization to normative validation
input**. The seqfloor pin stays: it is what keeps acceptance monotone in
allocation state; the digest memory closes what it cannot see.

Status: model-level finding; needs owner adjudication into plan rev 3
before the FORMAT.md rewrite.

### THE SECOND FINDING (2026-09-05): a pin per URL alias is not a pin

The 0.1.0 implementation keyed pin *storage* by remote URL, consulting a
sibling URL's pin only when the URL had none of its own. `neg_alias` is
that design: every pin rule on, one slot per `(device, alias)`.

```
w ──push via A──▶ gen1: counter 2        pin(w,A) = gen1
w ──push via B──▶ gen2: counter 3        pin(w,B) = gen2
host replays gen1 via A                  accepted: pin(w,A) is still at counter 2
```

`staleAliasAcceptsRollbackTest` is that trace; nothing in the battery
fires, because every check runs against the pin the read goes through
and that pin is simply old. The P3 form needs a second writer:

```
w ──push via A──▶ gen1: seq2 = c1        seen(w,A) = {2 -> c1}
z ──push from gen0──▶ gen2: seq2 = c2    (z's fork)
z ──push──▶ gen3: counter 3, sf 3
host serves gen3 to w via B              accepted: seen(w,B) has no 2
```

`staleAliasAcceptsReboundSequenceTest` walks it, and the verifier finds
it unaided at depth 6 (`spec.sh`'s control loop) — four steps. With
`SHARED_PIN` (`full`) both are refused:
`sharedPinRefusesRollbackThroughStaleAliasTest`,
`sharedPinRefusesReboundThroughOtherAliasTest`. FORMAT.md §7.4 now
requires one pin per vault identity plus a durable URL → vault binding
(the binding is outside this model, see "What is modeled").

### Model abstractions the spec refines

- The model has no recipients: encryption is abstracted to "cannot be
  created or opened without a key" (FORMAT.md §10). The `recipient`
  manifest lines (§5, §7.2), the declared-vs-actual count check, and
  the set-changing and upgrade compactions (§9.1, §9.2) are outside
  the model. What those compactions inherit — the CAS against the
  observed tip, `-full` at the lowest sequence, the allocation rules —
  is the ordinary compaction the model does cover.
- The model has no read-without-apply: `doRead` accepts AND applies in
  one step, so its `seen` memory records a generation's bindings on
  every read, and `doPush` (which starts from a read) binds the base's
  bundles too. FORMAT.md §7.4/§8.4 refine this for real implementations,
  where listing and pushing read without applying: only *applied*
  bindings are recorded, a listing-only read records nothing, and a
  writer records only its OWN new binding — before it learns the push
  outcome (the `crash=true` lag window is exactly why). The refinement
  is **weaker, not stronger**: it records a SUBSET of what the model
  records at read time (a listing-only read records nothing, so a
  binding the model would remember can go unremembered), while
  recording the same thing at write time. Every acceptance the model
  refuses, the refinement also refuses; but the refinement accepts some
  the model would refuse. Read the green results accordingly — they
  bound the model, and the implementation is at most that strong.
- Both refinements above — recipients, and reading without applying —
  are modelled in `protocol.qnt` (below), as are the URL → vault binding
  and vault substitution that "What is modeled" leaves out.

## protocol.qnt

A model of the protocol derived from the implementation. Where it and the code or
docs disagree, treat that as a question to investigate, not as a verdict.

| File | Contents |
|---|---|
| `protocol.qnt` | the parameterized model (`module protocol`) plus instances `protocol_honest`, `protocol_malicious`, `protocol_malicious3` |
| `protocol_controls.qnt` | five negative controls, each reverting one rule |
| `protocol_test.qnt` | scenario tests: concrete executions from the design notes |

### Shape

The devices coordinate through shared state, not messages. The only thing they share
is the host's vault branch, which moves by compare-and-swap. So this is plain Quint
with a `DeviceId -> Device` map (no Choreo).

- **Host**: every vault commit it ever received, landed or not (`host.gens`), and the
  branch `tip`. A push lands iff its base is the tip; a compaction iff the tip is still
  the `T` it read. A **malicious** host (`HONEST_HOST = false`) may also set the tip to
  any commit it holds, or empty it. Replay, rollback, forks and whole-vault substitution
  all follow from that one power.
- **Generation**: an abstract manifest. `vault`, `counter`, `seqfloor`, `bundles: seq ->
  {digest, full}`, `refs`, `recipients`, plus the write's `base` and a ghost `lineage`.
- **Device**: its repository's objects, `URL -> vault` bindings, and pins keyed by
  vault identity. Each pin holds counter, twin digest, seqfloor, and CONFIRMED and
  PENDING sequence memory: `pinstore::Pin` minus format/objectformat.
- State is five variables, each a record: `host`, `devices`, `objs`, `nextId`, `ghost`.
  `ghost` is bookkeeping for properties and witnesses; the protocol never reads it.
- **Objects**: commits with parents and ancestor sets. A bundle is `{contents,
  prereqs, recipients}`. A fresh digest per encryption stands for §10's cryptographic
  assumption: the host can replay ciphertext but never forge it.

**Granularity.** A write is two steps, split where the design is subtle:

1. `startPush` / `startCompact`: read, run the §7.4 battery, check the update,
   allocate, and save the PENDING binding.
2. `deliver`: the upload arrives (or doesn't) and lands (or doesn't). The writer then
   sees **Acked**, **Rejected** (ref-level, definitive) or **Indeterminate** (a lost
   status report, a dropped connection).

Everything within a step is atomic. That's sound because the §6.1 lock allows at most
one operation per repository at a time.

### What it covers

The actions are:

- `commit`
- `startPush`: vault initialization (`writer::attempt_init`) and incremental pushes
  (`attempt_incremental`, one ref update, forced or not)
- `deliver`
- `fetch`: `reader::inspect` + `reader::apply`
- `startCompact`: `compact::compact` with `Keep`, `Enroll`, `Revoke`; includes zero-ref
  compaction
- `forget`: `PinStore::forget_url`
- `rewind`: the malicious host

Invariants. `safety` is their conjunction; the honest-only ones are `HONEST_HOST
implies …`:

| Invariant | Rule | Host |
|---|---|---|
| `inv_seqfloorCoversBundles` | §7.2 seqfloor ≥ every listed number | both |
| `inv_rootedAtLowest` | §4.1 `-full` exactly at the lowest listed number | both |
| `inv_prereqClosure` | §4.3 prerequisites carried by lower-numbered bundles | both |
| `inv_refsClosed` | §6.6 bundles carry the whole history of every ref | both |
| `inv_oneSetPerGeneration` | §5 every file of a generation encrypted to its set | both |
| `inv_setChangesOnlyByCompaction` | §5 / §9.1 | both |
| `inv_repoConnected` | local repository never has a commit without its ancestors | both |
| `inv_confirmedMeansApplied` | §7.4 / 7e confirmed binding ⇒ objects present | both |
| `inv_confirmedWithinSeqfloor` | confirmed numbers ≤ pin seqfloor | both |
| `inv_memoryNeverRebound` | §7.4 one confirmed digest per number | both |
| `inv_noTwinPinned` | §7.4 twin check | both |
| `inv_noRollbackAccepted` | §7.4 counter check over *accepted* generations | both |
| `inv_readsNeverBreak` | §6 an accepted manifest always applies | both |
| `inv_noNumberRebound` | §8.4 / 8c a number is never re-bound while its earlier binding may have landed | both |
| `inv_ackedDurable` | §9.4 acknowledged writes stay in the branch lineage | honest |
| `inv_viewOnTruth` | every pin points at a generation that was on the branch | honest |
| `inv_lineConsistent` | the branch binds each number to one ciphertext | honest |

Witnesses (`w_*`) confirm that every action and every refusal is reachable. Counts
from `--max-steps=30 --max-samples=20000`, as traces reaching it (honest / malicious):

| Witness | Honest | Malicious |
|---|---|---|
| `w_committed` | 19999 | 20000 |
| `w_rewound` | 0 (not allowed) | 19878 |
| `w_vaultInitialized` | 19998 | 19996 |
| `w_pushSent` / `w_pushAcked` | 17042 / 8029 | 12899 / 2590 |
| `w_rejected` / `w_lostAck` | 1614 / 11962 | 6574 / 11504 |
| `w_readAccepted` / `w_notARecipient` | 19157 / 19751 | 15851 / 18836 |
| `w_nonFastForward` | 3087 | 1567 |
| `w_compacted` / `w_zeroRefCompaction` / `w_fullAfterEmpty` | 6950 / 696 / 160 | 2177 / 116 / 7 |
| `w_enrolledReads` / `w_revokedLockedOut` | 1904 / 4949 | 432 / 9271 |
| `w_forgot` | 17407 | 13843 |
| `w_pendingHeld` / `w_pendingSkipped` | 14574 / 6953 | 8887 / 1885 |
| `w_rollbackRefused` / `w_twinRefused` | 0 / 0 | 2195 / 39 |
| `w_seqfloorRefused` / `w_reboundRefused` | 0 / 0 | 1 / 1 |
| `w_vaultSwapRefused` / `w_emptyWithPinRefused` | 0 / 0 | 875 / 6597 |
| `w_staleBaseRefused` | 0 | 0 (unreachable, finding 2) |

An honest host never replays, so the battery never refuses under it. Seqfloor
regression and sequence rebound need deliberate forks, and random runs rarely build
them, so scenario tests cover them (`forkSeqfloorRefusedTest`, `forkReboundRefusedTest`).

```
quint run protocol.qnt --main=<instance> --max-steps=30 --max-samples=20000 --witnesses <every w_* name>
```

### Recorded runs (quint 0.32.0)

Run from `spec/`:

```
quint run protocol.qnt --main=protocol_honest     --max-steps=40 --max-samples=50000 --invariant=safety   [ok]
quint run protocol.qnt --main=protocol_malicious  --max-steps=40 --max-samples=50000 --invariant=safety   [ok]
quint run protocol.qnt --main=protocol_malicious3 --max-steps=50 --max-samples=20000 --invariant=safety   [ok]
```

`protocol_malicious` is clean in 20 of 20 runs of 50,000 traces with finding 1's
fix. Before the fix it violated `inv_memoryNeverRebound` in 10 of the same 20; its
first recorded runs had happened to miss it.

Negative controls. Each must fail; each did within 20000 samples × 30 steps:

| Module | Reverts | Violates |
|---|---|---|
| `ctl_indetAsReject` | §8.5 a lost status read as rejection | `inv_noNumberRebound` |
| `ctl_blindForce` | §9.4 compaction without CAS | `inv_ackedDurable` |
| `ctl_pinPerUrl` | §7.4 / 7h pins keyed by URL | `inv_noRollbackAccepted` |
| `ctl_setByPush` | §9.1 set change by plain push | `inv_oneSetPerGeneration` |
| `ctl_pushRecordsBase` | §7.4 / 7e push records the base's bindings unapplied | `inv_confirmedMeansApplied` |

```
quint run protocol_controls.qnt --main=<module> --max-steps=30 --max-samples=20000 --invariant=<invariant>
```

Scenario tests, all passing:

```
M='^(crashLag|forgetForfeits|alias|twin|fork|revoked|zeroRef|rejectedPush|compactionLoses|blindForce|lostAck|staleAlias).*Test$'
quint test protocol_test.qnt --main=attacks_test --match="$M"
    crashLagSkipsPendingTest, forgetForfeitsRollbackProtectionTest, aliasSharesThePinTest,
    twinRefusedTest, forkReboundRefusedTest, forkSeqfloorRefusedTest,
    forkWithoutReboundIsAcceptedTest, rejectedPushKeepsItsConfirmationTest,
    revokedCannotReadTest, zeroRefCompactionReRootsTest
quint test protocol_test.qnt --main=honest_test        --match="$M"   # compactionLosesToConcurrentPushTest
quint test protocol_test.qnt --main=blindForce_test    --match="$M"   # blindForceErasesAckedPushTest
quint test protocol_test.qnt --main=indetAsReject_test --match="$M"   # lostAckReboundsTheNumberTest
quint test protocol_test.qnt --main=pinPerUrl_test     --match="$M"   # staleAliasAcceptsRollbackTest
```

A plain `--match='Test$'` would also run basicSpells' own tests; `$M` selects only these.

### Findings

1. **Defect, fixed: a rejected push forgot a binding its read confirmed.**
   `writer::attempt_incremental` builds `pin_bound` on `p.next_pin()` and saves it
   before pushing. Along the way, `resolve_pending` *confirms* any pending number the
   base binds to this device's own digest ("it is ours and applied by construction, so
   it joins the memory even here"). On a definitive rejection, the old code called
   `restore_pin` to go back to `p.prev_pin()`, the pin from *before* that read. That
   discarded the confirmation and made the number pending again, and the next accepted
   read dropped it without a check, as it does any pending number. §7.4 says a
   confirmed binding is never pruned, and §10 says a fork that re-binds a confirmed
   number is detectable on this device. Neither held after this path.

   The trace (`rejectedPushKeepsItsConfirmationTest`, 15 steps, malicious host):
   1. A and B compact concurrently from one base, both at seq 3; B lands. A's upload
      reaches the host and loses the CAS, but A never hears the verdict, so it holds
      seq 3 → its own digest as pending.
   2. The host moves its branch to A's losing commit. A pushes on it, and the read
      confirms seq 3 → A's digest.
   3. That push is rejected. The old code reverted the confirmation here.
   4. The host serves B's generation, which binds seq 3 to B's digest and is a twin of
      A's (same counter). The old code accepted it: neither the twin check nor the
      sequence check fired, because the restored pin remembered neither.

   **The fix:** on rejection, `writer.rs` now saves `pin_base` — this read's pin minus
   the new binding — as `compact.rs` already did, and `restore_pin` is gone. Step 4
   is now refused as a twin. The model follows the fixed code. Evidence:
   - `tests/write_e2e.rs::a_rejected_push_keeps_what_its_read_confirmed` runs the
     same attack against the real binary (a lost acknowledgement, a twin from a second
     clone, the branch moved between `list for-push` and `push`). It failed on the old
     code (the retry pushed on the twin) and passes on the new.
   - The Quint scenario test above now expects the refusal, and 20 runs of 50,000
     malicious-host traces find nothing (10 of 20 failed before).

   Saving `pin_base` also keeps the base's counter, twin digest and seqfloor after a
   rejection. The code already saved those before pushing, and they only make the pin
   stricter. A first-contact push that is rejected now leaves a pin behind instead of
   none; the vault is non-empty there, so note 8d's reason for creating no pin (vault
   initialization) does not apply.

   Related, and not a defect: rollback protection covers only generations a device
   applied or had acknowledged. A manifest-only push that lands with a lost status
   report saves nothing, so the device can be rolled back past its own write; that
   matches §8.4. **`inv_noRollbackAccepted` was narrowed to accepted generations after
   the first malicious-host run** — it originally also counted a push's pre-saved
   base — and that is the only invariant adjusted after a violation.
2. **The §8.4 CONFIRMED-collision guard (note 8b) is unreachable** given the battery's
   seqfloor check. A proof sketch, by induction over the paths into `confirmed`:
   - `advance` adds the bindings a generation lists, all ≤ its seqfloor, and the pin's
     seqfloor becomes at least that.
   - `confirmAcked` promotes pending numbers ≤ the published seqfloor, and
     `advancedPin` then takes that seqfloor.
   - A push's `promoted` entries are listed in the base, so they are ≤ its seqfloor,
     which the pin already matched or passed.
   - A restore goes back to an earlier pin, which held the property.
   - Init binds 1 with seqfloor 1.

   So confirmed ≤ the pin's seqfloor (`inv_confirmedWithinSeqfloor`, also checked by
   sampling). A base that passes the battery has seqfloor ≥ the pin's, so `seqfloor + 1`
   is never confirmed. The guard is defence in depth; the pending-skip branch is the
   one that does the work.
3. **Rule 7e is defence in depth here.** With `PUSH_RECORDS_BASE`, the memory stops
   meaning "applied" (`inv_confirmedMeansApplied` fails). But every read still succeeds
   and every repository stays connected, because `reader::apply` re-applies skipped
   bundles when a `bundle verify` fails or a ref tip is missing. This model has no
   `git gc`, which is where 7e is expected to matter.
4. **The pending half matters only against a host that replays.** Under an honest host,
   `INDET_AS_REJECT` violates nothing. The crash-lag attack needs the host to serve the
   pre-push state after the push landed.
5. **§10's fork limit, concretely.** In `forkWithoutReboundIsAcceptedTest`, B's line
   skips a number through an ordinary pending skip and keeps seqfloor ahead. A then
   accepts it and silently loses its own acknowledged generation. This is the
   documented exception ("forks built from states genuine writers produced"), reached
   from honest writer behaviour.

### What it does NOT cover

- Grammars, bytes, names, chunking, the `sealed-format` hint, `format` /
  `objectformat` (constants here), and the §6.7 file-set check. A tampered file set is
  refused before anything is applied, so it cannot change state in this abstraction.
  `protocol_core.qnt`'s P1 checks the acceptance predicate itself.
- The declared-vs-actual stanza check and `compact --repair` (writer bugs, not
  protocol). The §9.2 upgrade of pre-recipient vaults, and legacy pin migration and
  `merge`.
- `git gc` pruning, annotated tags, merge commits, HEAD selection, and more than one
  ref update per push.
- Retry bounds (`MAX_ATTEMPTS`, `MAX_INDETERMINATE_ATTEMPTS`): each attempt is its own
  `startPush`.
- A host that lies in its verdicts. Verdicts are truthful except that any of them may
  be lost. A host that reports a rejection and later publishes that commit can fork the
  line; per-device detection then rests on the twin and sequence checks.
  `protocol_core.qnt` does let the host acknowledge any push.
- Crashes between the two pin saves inside one step. A pin save is atomic
  (`durable::write_file`).
- Liveness. Every property here is a safety property, checked by sampled `quint run`
  (no `quint verify`).

### Correspondence map

```
protocol.qnt  battery / advance / promoted / stillPending /
              confirmAcked / allocate / pinFor / withPin     ↔ src/pinstore.rs
              inspect / applyGen / fetch                     ↔ src/reader.rs
              initWrite / incrementalWrite / checkUpdate /
              bundleFor / deliver (verdicts, pin_base)       ↔ src/writer.rs, src/vaultrepo.rs (PushOutcome)
              startCompact / compactWrite / newSet           ↔ src/compact.rs
              forget                                         ↔ src/pinstore.rs (forget_url)
              rules                                          ↔ docs/FORMAT.md §4–§9, docs/DESIGN-NOTES.md
```

When those files change, update this model and re-run the commands above first. If the
model turns out to be wrong, discuss it before editing it to match the code.

## Honest limits

Apalache checks `protocol_core.qnt`'s invariants up to the configured depth
against the modeled adversary. `protocol.qnt`'s are only sampled, so a green run
there means no violation was found, not that none exists. Both models complement
the review rounds and the cross-implementation tests; neither replaces them, and
neither shows that an implementation matches its model.
