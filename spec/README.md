# Formal model — sealed vault format v2 (Quint / Apalache)

A machine-checked model of the v2 steady-state protocol:
`sealed_v2.qnt`. The scope is the format's steady state — devices pinned
from genesis — against the adversary
`docs/FORMAT.md` §1 and §10 describe. This README maps the
model to that spec and records what the model has found.

Run it:

```sh
./spec/spec.sh                      # fast lane: ~15s of compute
./spec/spec.sh --full               # + the absence proofs

podman compose run --rm spec        # the same, needing no host toolchain
podman compose run --rm spec-full
```

`spec.sh` is the only definition of what checking the model means — CI
calls it too. The fast lane runs on every push; `--full` adds the symbolic
absence proofs, which take from ~40 minutes upward (see "Why these
bounds") and stay manual.

## What is modeled

One vault. The **host is the adversary**: it keeps every generation any
genuine writer ever produced and may serve any of them to any device
(rollback, fork), and may acknowledge any push (fork creation); it cannot
forge or open ciphertexts. Devices are established (pinned from genesis)
and run the v2 acceptance battery on every read. Writer actions: bundle
push, manifest-only push, two-phase compaction (observe, then
compare-and-swap commit), crash between acknowledged push and pin update
(the T9 lag window).

## Configurations

| Module | Pins | Host | Purpose |
|---|---|---|---|
| `neg_nopin` | counter+digest only | malicious | negative control: review round 1's fork-hop must violate P3 |
| `neg_sfonly` | + seqfloor (plan rev 2) | malicious | **the model's finding: still violates P3** (see below) |
| `full` | + seq→digest memory | malicious, 3 devices | scripted attack tests + 10k-trace simulation (all invariants incl. P1) |
| `full2` | + seq→digest memory | malicious, 2 devices | symbolic proof of P2/P3/P5 (depth: see "Why these bounds") |
| `honest` | full | honest git | P4 (CAS durability) proved at depth 5 + simulation |
| `neg_force` | full | honest, force-push compact | negative control: §8's CAS rule is load-bearing |

Negative controls run before the proofs (`spec.sh`) and double as
calibration: the
scripted violations are exactly 6 steps, and the verifier demonstrably
finds them at depth 6 in seconds. The absence proofs run below the
deepest known attack (6 steps), so the 6-step attack class is covered by
these controls plus the deterministic guard tests, not by the symbolic
proof (see "Why these bounds").

### Why these bounds (measured, not chosen)

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

## Properties

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

## THE FINDING (2026-08-24): plan rev 2's pin set does not deliver P3

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

## Model abstractions the spec refines

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

## Honest limits

Apalache checks these invariants up to the configured depth against the
modeled adversary. It complements the review rounds and the
cross-implementation tests; it does not replace them, and it says nothing
about implementations diverging from the spec.
