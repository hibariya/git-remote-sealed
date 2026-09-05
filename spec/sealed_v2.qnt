// Sealed vault format v2 — steady-state protocol model.
//
// Scope: v2 only, no migration, devices pinned from genesis.
//
// The HOST is the adversary. It keeps every snapshot genuine writers ever
// made, may serve any of them (rollback, fork), and may acknowledge any
// push. It cannot forge or open ciphertexts. That is why a bundle's
// `content` is just a fresh id: equal content means byte-identical, and a
// served file either matches its manifest digest or is refused.
//
// Model -> spec:
//   Gen                one manifest generation and its genuine file set
//   Gen.id             the manifest ciphertext digest
//   Gen.parent         the generation its writer built on
//   tip                the honest host's branch tip
//   pin                the §7.4 TOFU pin
//   seen               CONFIRMED seq -> digest memory (§7.4)
//   pend               PENDING seq -> digest memory (§8.4)
//   trusted            everything a device ever accepted (P3's witness)
//   doPush crash=true  the push is acked but the pin never moves (T9)
// For concrete values, run with --verbosity=3.
//
// The flags exist to show which rule stops which attack. A model that
// cannot rediscover the known attacks proves nothing, so each has a
// negative control below.
//   PIN_SEQFLOOR   the seqfloor pin
//   PIN_SEQDIGESTS the seq -> digest memory (both halves)
//   HONEST_HOST    host follows git semantics (tip + CAS)
//   CAS_COMPACT    compaction uses compare-and-swap
//
// Properties (P = the plan doc's checklist). Each invariant carries its own
// reasoning at the bottom of the module.
//   P1 authenticity of acceptance  inv_p1_acceptExactness  (simulator only)
//   P2 pin sufficiency             inv_p2_guardMonotone    (weakened on purpose)
//   P3 never-reuse                 inv_p3_neverReuse
//   P4 durability                  inv_p4_durability       (honest host only)
//   P5 apply-order soundness       inv_p5_prereqClosure
//   P6 WITHDRAWN — migration is out of formal scope (owner, 2026-08-23)
// Unnumbered: inv_seqfloorCoversBundles, inv_p_rooting.

module sealed_v2 {
  const PIN_SEQFLOOR: bool
  const PIN_SEQDIGESTS: bool
  const HONEST_HOST: bool
  const CAS_COMPACT: bool
  const MAX_GENS: int
  const DEVICES: Set[str]

  type Bundle = { seq: int, content: int, prereqs: Set[int] }
  type Gen = { id: int, parent: int, counter: int, seqfloor: int, bundles: Set[Bundle] }
  type Pin = { counter: int, genId: int, seqfloor: int }

  // every generation a genuine writer produced, by id
  var store: int -> Gen

  // the honest host's branch tip
  var tip: int

  // next fresh id; doubles as fresh bundle content
  var nextId: int

  // the §7.4 TOFU pin, per device
  var pin: str -> Pin

  // §7.4 CONFIRMED memory: seq -> content this device has evidence for.
  // Only this half filters reads.
  var seen: str -> (int -> int)

  // §8.4 PENDING memory: a binding written before one of this device's own
  // pushes, whose outcome it never learned. Nobody may have taken that
  // write, so it is a guess, not evidence — `accepts` ignores it. It binds
  // the number for this device alone, through allocation.
  var pend: str -> (int -> int)

  // every bundle a device ever accepted — P3's witness
  var trusted: str -> Set[Bundle]

  // generations whose push was acknowledged to its writer (P4)
  var acked: Set[int]

  // the generation a compaction observed at its start
  var compactObs: str -> int

  // is a compaction between its start and commit/abort?
  var compactInFlight: str -> bool

  pure def seqsOf(bs: Set[Bundle]): Set[int] = bs.map(b => b.seq)
  pure def maxInt(a: int, b: int): int = if (a > b) a else b
  pure def bindAll(m: int -> int, bs: Set[Bundle]): int -> int =
    bs.fold(m, (acc, b) => acc.put(b.seq, b.content))

  // §7.4: what stays PENDING after reading generation g. A number g binds to
  // our own content is confirmed instead (bindAll puts it in `seen`); a
  // number g's seqfloor has passed without binding it to us is given up.
  pure def settle(pending: int -> int, g: Gen): int -> int =
    pending.keys()
      .filter(s => and {
        g.seqfloor < s,
        not(g.bundles.exists(b => b.seq == s and b.content == pending.get(s))),
      })
      .mapBy(s => pending.get(s))

  // The numbers `settle` gives up. The device cannot tell whether its write
  // landed and was forked away, or never landed and another writer took the
  // number — so it keeps no evidence either way. P3 carves these out.
  pure def unconfirmedDrops(pending: int -> int, g: Gen): Set[int] =
    pending.keys().filter(s => and {
      g.seqfloor >= s,
      not(g.bundles.exists(b => b.seq == s and b.content == pending.get(s))),
    })

  // A binding the device gives up on stops being a claim about anything,
  // so its own never-confirmed bundle leaves the P3 witness set with it —
  // exactly what the implementations do (they drop the pending entry and
  // keep nothing). The device still holds the objects, but it holds no
  // seq -> content claim, and that is what lets P3 stay unweakened.
  // One filter, not a fold of filters: `s` ranges over unconfirmedDrops,
  // which is a subset of pending.keys(), so `pending.get(s)` is always
  // defined. The fold this replaces was semantically identical but nested a
  // set filter per dropped key, which the symbolic verifier found very
  // expensive (see spec/README.md, "Cost").
  pure def forgetOwn(ts: Set[Bundle], pending: int -> int, g: Gen): Set[Bundle] =
    ts.filter(b => not(unconfirmedDrops(pending, g)
      .exists(s => s == b.seq and pending.get(s) == b.content)))

  // §8.4: the PENDING numbers this generation's seqfloor BURNS. Once we
  // publish that seqfloor, nothing in this line can bind them any more: the
  // generation does not list them, no ancestor does (their sequences sit
  // below a lower seqfloor), and every later writer allocates above it. A
  // writer that had taken one would have shown it in our own base. So the
  // guess becomes evidence — which is what bounds P3's carve-out in time.
  pure def burnedBy(pending: int -> int, floor: int): int -> int =
    pending.keys().filter(s => s <= floor).mapBy(s => pending.get(s))
  pure def stillAbove(pending: int -> int, floor: int): int -> int =
    pending.keys().filter(s => s > floor).mapBy(s => pending.get(s))
  pure def mergeMap(a: int -> int, b: int -> int): int -> int =
    b.keys().fold(a, (acc, k) => acc.put(k, b.get(k)))

  // §8.4 allocation: `first`, skipping numbers this device left PENDING.
  // Rebinding one would be a reuse; refusing one would wedge the writer
  // after any unreported push. MAX_GENS bounds the fold.
  pure def allocFrom(pending: int -> int, first: int, tries: int): int =
    1.to(tries).fold(first, (acc, _i) =>
      if (pending.keys().contains(acc)) acc + 1 else acc)

  // The v2 reader acceptance battery, minus file checks (modeled in P1):
  // counter monotone with twin check; seqfloor monotone; seq->digest stable.
  def accepts(d: str, g: Gen): bool = and {
    or {
      g.counter > pin.get(d).counter,
      and { g.counter == pin.get(d).counter, g.id == pin.get(d).genId },
    },
    PIN_SEQFLOOR implies (g.seqfloor >= pin.get(d).seqfloor),
    PIN_SEQDIGESTS implies g.bundles.forall(b =>
      seen.get(d).keys().contains(b.seq) implies (seen.get(d).get(b.seq) == b.content)),
  }

  pure val genesisBundle: Bundle = { seq: 1, content: 0, prereqs: Set() }
  pure val genesis: Gen =
    { id: 0, parent: -1, counter: 1, seqfloor: 1, bundles: Set(genesisBundle) }

  action init = all {
    store' = Map(0 -> genesis),
    tip' = 0,
    nextId' = 1,
    pin' = DEVICES.mapBy(d => { counter: 1, genId: 0, seqfloor: 1 }),
    seen' = DEVICES.mapBy(d => bindAll(Map(), genesis.bundles)),
    pend' = DEVICES.mapBy(d => Map()),
    trusted' = DEVICES.mapBy(d => Set(genesisBundle)),
    acked' = Set(0),
    compactObs' = DEVICES.mapBy(d => 0),
    compactInFlight' = DEVICES.mapBy(d => false),
  }

  // Device d fetches; the host serves generation gid (malicious: any genuine
  // one; honest: the tip). Accepting updates pin, seen, trusted.
  action doRead(d: str, gid: int): bool = all {
    HONEST_HOST implies (gid == tip),
    accepts(d, store.get(gid)),
    pin' = pin.set(d, {
      counter: store.get(gid).counter,
      genId: gid,
      seqfloor: maxInt(pin.get(d).seqfloor, store.get(gid).seqfloor) }),
    seen' = seen.set(d, bindAll(seen.get(d), store.get(gid).bundles)),
    pend' = pend.set(d, settle(pend.get(d), store.get(gid))),
    trusted' = trusted.set(d, forgetOwn(trusted.get(d), pend.get(d), store.get(gid))
      .union(store.get(gid).bundles)),
    store' = store, tip' = tip, nextId' = nextId, acked' = acked,
    compactObs' = compactObs, compactInFlight' = compactInFlight,
  }

  // Device d pushes on top of served generation baseId (a push is a
  // validated fetch plus one commit). withBundle=false is a manifest-only
  // push: a ref move or delete, so seqfloor and bundles do not change.
  // crash=true is the T9 window — acknowledged, but the pin never moved.
  action doPush(d: str, baseId: int, withBundle: bool, crash: bool): bool = {
    val base = store.get(baseId)
    // With PIN_SEQDIGESTS off there is no memory at all, so no skipping.
    // The reallocation negative controls below depend on that.
    val settled = settle(pend.get(d), base)
    val newSeq =
      if (PIN_SEQDIGESTS) allocFrom(settled, base.seqfloor + 1, MAX_GENS)
      else base.seqfloor + 1
    val newBundles =
      if (withBundle)
        base.bundles.union(Set({ seq: newSeq, content: nextId, prereqs: seqsOf(base.bundles) }))
      else base.bundles
    val g = { id: nextId, parent: baseId, counter: base.counter + 1,
              seqfloor: if (withBundle) newSeq else base.seqfloor, bundles: newBundles }
    all {
      nextId < MAX_GENS,
      accepts(d, base),
      // §8.4 guard, found by the verifier: never allocate a CONFIRMED
      // number. A collision proves the served base predates this device's
      // own history — its own acknowledged push replayed by the host, say —
      // so refuse and refetch. (A PENDING number is skipped, not refused.)
      (PIN_SEQDIGESTS and withBundle) implies
        not(seen.get(d).keys().contains(newSeq)),
      HONEST_HOST implies (baseId == tip),   // non-forced push == CAS on the tip
      store' = store.put(nextId, g),
      tip' = if (baseId == tip) nextId else tip,
      nextId' = nextId + 1,
      acked' = acked.union(Set(nextId)),
      pin' = if (crash) pin
             else pin.set(d, { counter: g.counter, genId: g.id, seqfloor: g.seqfloor }),
      // §8.4 binding timing: the device's own binding is PENDING until the
      // push is acknowledged to it, which under crash=true never happens.
      // An acknowledged push also confirms whatever its seqfloor burned.
      seen' = seen.set(d,
        if (crash) bindAll(seen.get(d), base.bundles)
        else mergeMap(bindAll(seen.get(d), newBundles), burnedBy(settled, g.seqfloor))),
      pend' = pend.set(d,
        if (crash) (if (withBundle) settled.put(newSeq, nextId) else settled)
        else stillAbove(settled, g.seqfloor)),
      trusted' = trusted.set(d, forgetOwn(trusted.get(d), pend.get(d), base).union(newBundles)),
      compactObs' = compactObs, compactInFlight' = compactInFlight,
    }
  }

  // Two phases, so the observe/commit race of §8 is reachable: start
  // records the observed tip, commit compare-and-swaps against it.
  action doCompactStart(d: str, obsId: int): bool = all {
    not(compactInFlight.get(d)),
    HONEST_HOST implies (obsId == tip),
    accepts(d, store.get(obsId)),
    compactObs' = compactObs.set(d, obsId),
    compactInFlight' = compactInFlight.set(d, true),
    pin' = pin.set(d, {
      counter: store.get(obsId).counter,
      genId: obsId,
      seqfloor: maxInt(pin.get(d).seqfloor, store.get(obsId).seqfloor) }),
    seen' = seen.set(d, bindAll(seen.get(d), store.get(obsId).bundles)),
    pend' = pend.set(d, settle(pend.get(d), store.get(obsId))),
    trusted' = trusted.set(d, forgetOwn(trusted.get(d), pend.get(d), store.get(obsId))
      .union(store.get(obsId).bundles)),
    store' = store, tip' = tip, nextId' = nextId, acked' = acked,
  }

  action doCompactCommit(d: str, crash: bool): bool = {
    val base = store.get(compactObs.get(d))
    // §9.2 allocates by §8.4. Compaction can only SKIP a pending number,
    // never re-publish it: §4.1 wants `-full` at the lowest listed number,
    // and a compacted list holds exactly one bundle.
    val settled = settle(pend.get(d), base)
    val newSeq =
      if (PIN_SEQDIGESTS) allocFrom(settled, base.seqfloor + 1, MAX_GENS)
      else base.seqfloor + 1
    val g = { id: nextId, parent: compactObs.get(d), counter: base.counter + 1,
              seqfloor: newSeq,
              bundles: Set({ seq: newSeq, content: nextId, prereqs: Set() }) }
    all {
      compactInFlight.get(d),
      nextId < MAX_GENS,
      // Same allocation guard as doPush: compaction allocates too.
      PIN_SEQDIGESTS implies not(seen.get(d).keys().contains(newSeq)),
      // §8 step 4: compare-and-swap, never plain force. CAS_COMPACT=false is
      // the negative control that shows the rule is load-bearing.
      (HONEST_HOST and CAS_COMPACT) implies (tip == compactObs.get(d)),
      store' = store.put(nextId, g),
      tip' = nextId,                      // compaction replaces the branch
      nextId' = nextId + 1,
      acked' = acked.union(Set(nextId)),
      pin' = if (crash) pin
             else pin.set(d, { counter: g.counter, genId: g.id, seqfloor: g.seqfloor }),
      seen' = seen.set(d,
        if (crash) seen.get(d)
        else mergeMap(bindAll(seen.get(d), g.bundles), burnedBy(settled, g.seqfloor))),
      pend' = pend.set(d,
        if (crash) settled.put(newSeq, nextId) else stillAbove(settled, g.seqfloor)),
      trusted' = trusted.set(d, forgetOwn(trusted.get(d), pend.get(d), base).union(g.bundles)),
      compactObs' = compactObs, compactInFlight' = compactInFlight.set(d, false),
    }
  }

  action doCompactAbort(d: str): bool = all {
    compactInFlight.get(d),
    compactInFlight' = compactInFlight.set(d, false),
    store' = store, tip' = tip, nextId' = nextId, pin' = pin, seen' = seen,
    pend' = pend,
    trusted' = trusted, acked' = acked, compactObs' = compactObs,
  }

  // Zero-ref compaction: every ref was deleted, so the replacement
  // generation is manifest-only. seqfloor is PRESERVED, so numbering can
  // never restart. The next bundle push into it has no prerequisites, which
  // makes it a complete snapshot and re-roots recovery (inv_p_rooting).
  action doCompactCommitEmpty(d: str, crash: bool): bool = {
    val base = store.get(compactObs.get(d))
    val g = { id: nextId, parent: compactObs.get(d), counter: base.counter + 1,
              seqfloor: base.seqfloor, bundles: Set() }
    all {
      compactInFlight.get(d),
      nextId < MAX_GENS,
      (HONEST_HOST and CAS_COMPACT) implies (tip == compactObs.get(d)),
      store' = store.put(nextId, g),
      tip' = nextId,
      nextId' = nextId + 1,
      acked' = acked.union(Set(nextId)),
      pin' = if (crash) pin
             else pin.set(d, { counter: g.counter, genId: g.id, seqfloor: g.seqfloor }),
      seen' = seen, pend' = pend.set(d, settle(pend.get(d), base)),
      trusted' = trusted.set(d, forgetOwn(trusted.get(d), pend.get(d), base)),
      compactObs' = compactObs, compactInFlight' = compactInFlight.set(d, false),
    }
  }

  // `forget` wipes the pin and both halves of the memory. Modeled to show
  // what it forfeits, not to bless it — and kept OUT of `step`: with the
  // protections gone, accepting a rollback is the expected outcome, which
  // would make the safety invariants refutable for the wrong reason.
  action doForget(d: str): bool = all {
    pin' = pin.set(d, { counter: 0, genId: -1, seqfloor: 0 }),
    seen' = seen.set(d, Map()),
    pend' = pend.set(d, Map()),
    store' = store, tip' = tip, nextId' = nextId, trusted' = trusted,
    acked' = acked, compactObs' = compactObs, compactInFlight' = compactInFlight,
  }

  // --- nondeterministic step for model checking ---

  action read = { nondet d = DEVICES.oneOf()
                  nondet gid = store.keys().oneOf()
                  doRead(d, gid) }
  action push = { nondet d = DEVICES.oneOf()
                  nondet baseId = store.keys().oneOf()
                  nondet wb = Set(true, false).oneOf()
                  nondet cr = Set(true, false).oneOf()
                  doPush(d, baseId, wb, cr) }
  action compactStart = { nondet d = DEVICES.oneOf()
                          nondet obsId = store.keys().oneOf()
                          doCompactStart(d, obsId) }
  action compactCommit = { nondet d = DEVICES.oneOf()
                           nondet cr = Set(true, false).oneOf()
                           doCompactCommit(d, cr) }
  action compactAbort = { nondet d = DEVICES.oneOf()
                          doCompactAbort(d) }
  action compactCommitEmpty = { nondet d = DEVICES.oneOf()
                                nondet cr = Set(true, false).oneOf()
                                doCompactCommitEmpty(d, cr) }
  action step = any { read, push, compactStart, compactCommit,
                      compactCommitEmpty, compactAbort }

  // --- invariants (the P-properties of the plan) ---

  // P1: the reader's file check admits exactly the manifest's file set — no
  // chimera assembled from other genuine bundles passes. Checked over every
  // subset of every bundle a malicious host could serve.
  pure def acceptFiles(g: Gen, files: Set[Bundle]): bool = and {
    seqsOf(files) == seqsOf(g.bundles),
    files.forall(f => g.bundles.exists(b => b.seq == f.seq and b.content == f.content)),
  }
  val allBundles = store.keys().fold(Set(), (acc, id) => acc.union(store.get(id).bundles))
  val inv_p1_acceptExactness = store.keys().forall(id => {
    val g = store.get(id)
    allBundles.powerset().forall(f => acceptFiles(g, f) implies (f == g.bundles))
  })

  // P2: acceptance implies monotone observations. The stronger "only
  // descendants are accepted" is deliberately absent — it is FALSE under a
  // malicious host (§9 admits forks), and the neg_* runs below are exactly
  // such fork acceptances.
  val inv_p2_guardMonotone = DEVICES.forall(d => store.keys().forall(gid => {
    val g = store.get(gid)
    accepts(d, g) implies and {
      g.counter >= pin.get(d).counter,
      PIN_SEQFLOOR implies (g.seqfloor >= pin.get(d).seqfloor),
    }
  }))

  // P3, the crown: along one device's accepted history, a sequence number is
  // never bound to two different contents. The applied-bundle cache's
  // skip-without-rehash leans on this.
  //
  // It holds with NO exception, and the pending half is why it can. A
  // binding the device left PENDING and then gave up unconfirmed was a
  // guess, not evidence: the device cannot tell "my write landed and was
  // forked away" from "my write never landed and another writer took the
  // number". Letting guesses filter reads would refuse the second case too —
  // an ordinary two-writer race after a dropped connection, i.e. the H1
  // wedge, escapable only by `forget`, which accepts real attacks. So the
  // device accepts the other binding AND forgets its own claim (`forgetOwn`),
  // which is exactly what the implementations do. Nothing is carved out of
  // P3; the witness set simply never holds two claims at one number.
  //
  // What the device gives up is stated in FORMAT.md §7.4 note 7g: a fork
  // that re-binds a number it dropped unconfirmed is not caught BY THIS
  // DEVICE, BY THIS CHECK. Its own next acknowledged push ends that window
  // by burning the number (`burnedBy`), and any device that read the landed
  // generation holds the binding CONFIRMED and still refuses the fork.
  val inv_p3_neverReuse = DEVICES.forall(d =>
    trusted.get(d).forall(b1 => trusted.get(d).forall(b2 =>
      (b1.seq == b2.seq) implies (b1.content == b2.content))))

  // P4 (honest host): an acknowledged push is never erased. Compaction
  // links its parent to the generation it compacted, so staying an ancestor
  // of the tip is the same as still being contained.
  val ancestorsOfTip =
    0.to(MAX_GENS).fold(Set(tip), (acc, _i) =>
      acc.union(acc.map(x => store.get(x).parent).filter(x => x >= 0)))
  val inv_p4_durability = acked.subseteq(ancestorsOfTip)

  // P5: a bundle's prerequisites always sit at lower sequence numbers in
  // the same generation, so ascending apply order never misses one.
  val inv_p5_prereqClosure = store.keys().forall(id => {
    val g = store.get(id)
    g.bundles.forall(b => b.prereqs.subseteq(seqsOf(g.bundles).filter(s => s < b.seq)))
  })

  // Readers must assert this: seqfloor covers every listed bundle.
  val inv_seqfloorCoversBundles = store.keys().forall(id => {
    val g = store.get(id)
    g.bundles.forall(b => store.get(id).seqfloor >= b.seq)
  })

  // Recovery rooting (§4.1's `-full` rule): every generation with a
  // nonempty bundle list has a prerequisite-free bundle at its LOWEST
  // sequence number. Appendix A's "start from the highest -full" recipe
  // depends on it, and zero-ref compaction is why it needs checking.
  val inv_p_rooting = store.keys().forall(id => {
    val g = store.get(id)
    (g.bundles != Set()) implies g.bundles.exists(b => and {
      b.prereqs == Set(),
      g.bundles.forall(b2 => b.seq <= b2.seq),
    })
  })

  // P1 stays OUT of the verifier sets: its powerset is cheap to simulate
  // but intractable symbolically (a depth-10 Apalache run sat 5 hours with
  // no progress). `quint run --invariant=inv_p1_acceptExactness` covers it.
  val inv_core_malicious = and {
    inv_p2_guardMonotone, inv_p3_neverReuse,
    inv_p5_prereqClosure, inv_seqfloorCoversBundles, inv_p_rooting,
  }
  val inv_core_honest = and { inv_core_malicious, inv_p4_durability }

  val inv_all_malicious = and { inv_core_malicious, inv_p1_acceptExactness }
  val inv_all_honest = and { inv_core_honest, inv_p1_acceptExactness }
}

// ===========================================================================
// Configurations. Negative controls FIRST: a model that cannot rediscover
// the known attacks is too weak for its green results to mean anything.
// ===========================================================================

// Review round 1's fork-hop (R2-F2), no pins beyond v1: must violate P3.
module neg_nopin {
  import sealed_v2(
    PIN_SEQFLOOR = false, PIN_SEQDIGESTS = false,
    HONEST_HOST = false, CAS_COMPACT = true,
    MAX_GENS = 6, DEVICES = Set("w", "y")).* from "./sealed_v2"

  // w's push crash-lags its pin; the host then lets w build a second line
  // from genesis that re-allocates seq 2. y accepts the fork.
  run forkHopFindsP3ViolationTest =
    init
      .then(doPush("w", 0, true, true))      // gen1: fork A, seq2=cA; pin lag
      .then(doRead("y", 1))                  // y pins A (counter 2, sf 2)
      .then(doPush("w", 0, false, false))    // gen2: fork B, counter 2, sf 1
      .then(doPush("w", 2, false, false))    // gen3: counter 3, sf 1
      .then(doPush("w", 3, true, false))     // gen4: counter 4, sf 2, seq2=cB
      .then(doRead("y", 4))                  // ACCEPTED: counter 4 > 2
      .expect(not(inv_p3_neverReuse))
}

// Counter + digest + seqfloor: the fork-hop's intermediate low-seqfloor
// state is refused, but the state AFTER the fork re-allocates reaches an
// equal seqfloor and is still accepted. P3 falls. This is the model's
// finding against plan rev 2 (see README).
module neg_sfonly {
  import sealed_v2(
    PIN_SEQFLOOR = true, PIN_SEQDIGESTS = false,
    HONEST_HOST = false, CAS_COMPACT = true,
    MAX_GENS = 6, DEVICES = Set("w", "y")).* from "./sealed_v2"

  run intermediateHopRejectedTest =
    init
      .then(doPush("w", 0, true, true))
      .then(doRead("y", 1))
      .then(doPush("w", 0, false, false))
      .then(doPush("w", 2, false, false))
      .then(doRead("y", 3))                  // sf 1 < pinned 2: must be refused
      .fail()

  run seqfloorPinInsufficientTest =
    init
      .then(doPush("w", 0, true, true))      // fork A: seq2=cA, sf 2
      .then(doRead("y", 1))                  // y pinned: counter 2, sf 2
      .then(doPush("w", 0, false, false))    // fork B ...
      .then(doPush("w", 2, false, false))
      .then(doPush("w", 3, true, false))     // gen4: counter 4, sf 2, seq2=cB
      .then(doRead("y", 4))                  // sf 2 >= 2, counter 4 > 2: accepted
      .expect(not(inv_p3_neverReuse))

  // The verifier's own discovery (2026-08-24): no second fork line needed.
  // One device, two steps — a crash-lagged writer re-served its own
  // pre-push state re-allocates the same seq itself.
  run selfReuseAfterCrashTest =
    init
      .then(doPush("w", 0, true, true))      // seq2=cA acked; pin lags
      .then(doPush("w", 0, true, false))     // host re-serves gen0: seq2=cB
      .expect(not(inv_p3_neverReuse))
}

// The full pin set: seqfloor plus the two-sided seq->digest memory. Every
// known reuse construction must now fail, and P3 verifies at depth. Three
// devices, because the read-side guard needs two independent writers racing
// the same allocation from one base.
module full {
  import sealed_v2(
    PIN_SEQFLOOR = true, PIN_SEQDIGESTS = true,
    HONEST_HOST = false, CAS_COMPACT = true,
    MAX_GENS = 6, DEVICES = Set("w", "y", "z")).* from "./sealed_v2"

  // The fork writer above can no longer re-allocate seq2: its own
  // crash-lagged push left seq2 PENDING, so allocation skips to seq3. The
  // push still SUCCEEDS. Refusing it instead — the rule before the pending
  // half existed — wedged the writer for good after any unreported push.
  run forkWriterReallocationSkippedTest =
    init
      .then(doPush("w", 0, true, true))      // gen1: seq2=c1 acked, pin lags
      .then(doRead("y", 1))
      .then(doPush("w", 0, false, false))
      .then(doPush("w", 2, false, false))
      .then(doPush("w", 3, true, false))     // gen4: allocates seq3, NOT seq2
      .expect(and {
        store.get(4).bundles.exists(b => b.seq == 3),
        not(store.get(4).seqfloor == 2),
        inv_p3_neverReuse,
      })

  // Read-side guard: two writers race seq2 from genesis, each genuinely
  // unaware. The device that accepted one line must refuse the other as
  // soon as it rebinds a remembered seq.
  run reboundManifestRefusedOnReadTest =
    init
      .then(doPush("w", 0, true, false))     // w's line: seq2=cA
      .then(doRead("y", 1))                  // y remembers seq2->cA
      .then(doPush("z", 0, true, false))     // z's line: seq2=cB (z saw no cA)
      .then(doPush("z", 2, true, false))     // counter outruns y's pin
      .then(doRead("y", 3))                  // rebinds seq2: refused
      .fail()

  // The single-device variant: this device's own acknowledged push replayed
  // away by the host. It must not rebind seq2, and must not stop working.
  run selfReuseSkippedTest =
    init
      .then(doPush("w", 0, true, true))      // seq2=c1 acked, pin lags
      .then(doPush("w", 0, true, false))     // skips seq2, allocates seq3
      .expect(and {
        store.get(2).bundles.exists(b => b.seq == 3 and b.content == 2),
        not(store.get(2).bundles.exists(b => b.seq == 2 and b.content == 2)),
        inv_p3_neverReuse,
      })

  // §7.4: a read settles the pending half. Here the lost acknowledgment is
  // recovered — the line binds seq2 to OUR content, so it becomes CONFIRMED.
  run pendingConfirmedByALaterReadTest =
    init
      .then(doPush("w", 0, true, true))      // seq2=c1 acked, never learned
      .expect(pend.get("w") == Map(2 -> 1))
      .then(doRead("w", 1))
      .expect(and {
        pend.get("w") == Map(),
        seen.get("w").get(2) == 1,
      })

  // §8.4: the device's OWN next acknowledged push settles the guess the
  // other way. It skipped seq2 and published seqfloor 3, which burns seq2 —
  // so seq2 becomes CONFIRMED without ever having been published. This is
  // what keeps P3's exception down to the window before that push.
  run anAcknowledgedPushConfirmsWhatItBurnedTest =
    init
      .then(doPush("w", 0, true, true))      // seq2=c1, never learned
      .then(doPush("w", 0, true, false))     // skips seq2, publishes seqfloor 3
      .expect(and {
        pend.get("w") == Map(),
        seen.get("w").get(2) == 1,           // burned -> confirmed
        inv_p3_neverReuse,
      })

  // P3's limit, shown rather than hidden — and it is only the window BEFORE
  // w's next acknowledged push. Inside it another writer binds the number
  // from the same base, and w cannot tell that from a host forking away its
  // own lost push. w accepts z's binding and FORGETS its own guess, so P3
  // needs no carve-out to survive: the witness set ends up holding only
  // z's content at seq 2.
  run pendingDroppedIsForgottenNotCarvedOutTest =
    init
      .then(doPush("w", 0, true, true))       // gen1: seq2=c1, never learned
      .then(doPush("z", 0, true, false))      // gen2: z takes seq2 = c2
      .expect(pend.get("w") == Map(2 -> 1))
      .then(doRead("w", 2))                   // w cannot refuse this
      .expect(and {
        pend.get("w") == Map(),
        seen.get("w").get(2) == 2,            // z's bundle, not w's own c1
        trusted.get("w").filter(b => b.seq == 2).map(b => b.content) == Set(2),
        inv_p3_neverReuse,
      })

  // Delete every ref, then compact: the result is a manifest-only
  // generation. Numbering survives it, and the next push is a
  // prerequisite-free complete snapshot that re-roots recovery.
  run emptyVaultKeepsNumberingTest =
    init
      .then(doPush("w", 0, true, false))          // gen1: counter 2, sf 2, seq2
      .then(doCompactStart("w", 1))
      .then(doCompactCommitEmpty("w", false))     // gen2: counter 3, sf 2, no bundles
      .then(doPush("w", 2, true, false))          // gen3: allocates seq 3, prereq-free
      .expect(and {
        store.get(3).bundles.exists(b => b.seq == 3 and b.prereqs == Set()),
        inv_p3_neverReuse,
        inv_p_rooting,
      })

  // `forget` forfeits rollback protection — cmd_forget's warning, made
  // formal. The same rollback, with and without the wipe:
  run rollbackRefusedWithoutForgetTest =
    init
      .then(doPush("w", 0, true, false))
      .then(doRead("y", 1))
      .then(doRead("y", 0))                       // rollback: refused
      .fail()

  run forgetForfeitsRollbackProtectionTest =
    init
      .then(doPush("w", 0, true, false))
      .then(doRead("y", 1))
      .then(doForget("y"))
      .then(doRead("y", 0))                       // same rollback: ACCEPTED
      .expect(pin.get("y").counter == 1)          // y is back at genesis
}

// `full` with two devices, for the SYMBOLIC verifier only: three devices
// stall Z3 around depth 5-6 (measured: 13h, no progress). What only three
// devices reach — the read-side guard against two independent writers — is
// covered by full's scripted scenario and the randomized simulation.
module full2 {
  import sealed_v2(
    PIN_SEQFLOOR = true, PIN_SEQDIGESTS = true,
    HONEST_HOST = false, CAS_COMPACT = true,
    MAX_GENS = 6, DEVICES = Set("w", "y")).* from "./sealed_v2"
}

// Honest host, CAS compaction: P4 must hold.
module honest {
  import sealed_v2(
    PIN_SEQFLOOR = true, PIN_SEQDIGESTS = true,
    HONEST_HOST = true, CAS_COMPACT = true,
    MAX_GENS = 6, DEVICES = Set("w", "y")).* from "./sealed_v2"

  run casCompactRetriesTest =
    init
      .then(doCompactStart("w", 0))
      .then(doPush("y", 0, true, false))     // tip moves under the compaction
      .then(doCompactCommit("w", false))     // CAS must refuse
      .fail()
}

// Honest host, plain-force compaction (§8 forbids it): the same
// interleaving now erases an acknowledged push. P4's negative control.
module neg_force {
  import sealed_v2(
    PIN_SEQFLOOR = true, PIN_SEQDIGESTS = true,
    HONEST_HOST = true, CAS_COMPACT = false,
    MAX_GENS = 6, DEVICES = Set("w", "y")).* from "./sealed_v2"

  run forcePushErasesAckedPushTest =
    init
      .then(doCompactStart("w", 0))
      .then(doPush("y", 0, true, false))     // acked to y
      .then(doCompactCommit("w", false))     // force-push replaces the branch
      .expect(not(inv_p4_durability))
}
