// -*- mode: Bluespec; -*-
// A model of the git-remote-sealed protocol, derived from src/ and docs/ and
// written independently of protocol_core.qnt. It covers more of the protocol than
// that model, but is checked by sampled simulation only. Scope, results and
// findings are in README.md.
module protocol {
  import basicSpells.* from "./basicSpells"

  // ---------------------------------------------------------------------
  // Parameters
  // ---------------------------------------------------------------------

  const DEVICES: Set[str]   // local repositories, each with its own age identity
  const URLS: Set[str]      // aliases of the one host vault (e.g. ssh / https)
  const REFS: Set[str]      // source ref names
  const MAX_COMMITS: int    // bound on source commits created
  const HONEST_HOST: bool   // false: the host may rewrite its branch to anything it holds

  // Negative controls: each one reverts a single rule the code/docs rely on.
  const INDET_AS_REJECT: bool      // §8.5: treat a lost status report as a rejection
  const COMPACT_BLIND_FORCE: bool  // §9.4: plain force-push instead of CAS against T
  const PIN_PER_URL: bool          // §7.4/7h: pins keyed by URL (with first-contact fallback)
  const SET_CHANGE_BY_PUSH: bool   // §9.1: enroll/revoke by a plain push, not a compaction
  const PUSH_RECORDS_BASE: bool    // §7.4/7e: a push records the base's bindings unapplied

  // ---------------------------------------------------------------------
  // Types
  // ---------------------------------------------------------------------

  type DeviceId = str
  type Url = str
  type RefName = str
  type Commit = int    // a git commit id; content-addressed, so a global table
  type Seq = int       // bundle sequence number (§4.1)
  type Digest = int    // SHA-256 of one bundle ciphertext; fresh per encryption (§10)
  type GenId = int     // one manifest generation = SHA-256 of its ciphertext; 0 = none
  type VaultId = int   // the manifest's `vault` line

  // One `bundle` line of a manifest (chunking and names abstracted away).
  type BundleLine = { digest: Digest, full: bool }

  type GenKind = Init | Push | Compaction

  // A manifest generation, plus the vault commit that carries it.
  type Gen = {
    vault: VaultId,
    counter: int,
    seqfloor: int,
    bundles: Seq -> BundleLine,
    refs: RefName -> Commit,
    recipients: Set[DeviceId],  // the `recipient` lines: whom every file is encrypted to
    kind: GenKind,
    base: GenId,                // the tip this write was built on (push parent / CAS `T`)
    lineage: Set[GenId],        // ghost: every generation this one builds on, transitively
  }

  // What the host knows about one bundle ciphertext: what it decrypts to.
  type BundleInfo = {
    contents: Set[Commit],      // objects the bundle carries
    prereqs: Set[Commit],       // commits it requires to already exist
    recipients: Set[DeviceId],  // the set it was encrypted to
  }

  // §7.4: a device's memory of one vault.
  type Pin = {
    vault: VaultId,
    counter: int,
    digest: GenId,              // the twin-check witness
    seqfloor: int,
    confirmed: Seq -> Digest,   // accepted-and-applied, or own acknowledged writes
    pending: Seq -> Digest,     // own writes of unknown fate (§8.4 binding timing)
  }

  // Pins are keyed by vault identity; the PIN_PER_URL control keys them by URL too.
  type PinKey = { url: Url, vault: VaultId }

  // What the device does to its pin when a verdict arrives.
  type OnReject =
    | KeepPin                    // nothing was saved before the push
    | SavePin(Pin)               // the write's pin_base: withdraw only the new binding

  // A write in flight: step 1 done (read, checks, allocation, PENDING saved),
  // waiting for the host to take it and for the verdict to come back.
  type Upload = {
    url: Url,
    genId: GenId,
    gen: Gen,
    alloc: Seq,                  // 0 = no bundle allocated
    bound: Pin,                  // pin to advance on acknowledgement
    onReject: OnReject,
  }

  type Op = Idle | Uploading(Upload)

  type Device = {
    repo: Set[Commit],           // objects in the local repository
    bindings: Url -> VaultId,    // §7.4: URL -> vault first pinned through it
    pins: PinKey -> Pin,
    op: Op,
  }

  type Reason =
    | EmptyWithPin | CannotDecrypt | VaultMismatch | Rollback | Twin
    | SeqfloorRegression | SequenceRebound | AllocationCollision
    | FetchFirst | NonFastForward | MissingObject | CorruptBundle
    | CannotDecryptBundle | NothingToDo | EmptyVault | EmptySet

  type Verdict = Acked | Rejected | Indeterminate

  // The last thing that happened: the observable result the CLI would print.
  type Event =
    | NoEvent
    | Accepted({ dev: DeviceId, gen: GenId })
    | Refused({ dev: DeviceId, reason: Reason })
    | Sent({ dev: DeviceId, gen: GenId, kind: GenKind })
    | Outcome({ dev: DeviceId, gen: GenId, verdict: Verdict, landed: bool })
    | Forgot({ dev: DeviceId, url: Url })
    | Rewound({ tip: GenId })

  // Ghost: one bundle allocation by a device, and what really happened to it.
  type UploadFate = InFlight | Landed | NotLanded
  type AllocRecord = { dev: DeviceId, vault: VaultId, seq: Seq, digest: Digest, fate: UploadFate }


  // A generation a device has pinned (the pin's twin witness pointed at it).
  type Seen = { vault: VaultId, gen: GenId, counter: int }

  // Ghost bookkeeping, never read by the protocol.
  type Ghost = {
    lastEvent: Event,
    acked: Set[GenId],                              // generations acknowledged to their writer
    allocs: Set[AllocRecord],                       // every bundle allocation ever made
    seen: DeviceId -> Set[Seen],                    // generations each device accepted (applied or acked)
    memoryLog: DeviceId -> Set[(VaultId, Seq, Digest)], // every CONFIRMED binding ever held
    rolledBack: bool,                               // a device accepted an older generation
  }

  // The result of §6 steps 1-4 (reader::inspect).
  type Inspection =
    | IEmpty
    | IRefused(Reason)
    | IVault({ genId: GenId, gen: Gen, prev: Option[Pin], nextPin: Pin })

  type ApplyResult = ApplyOk(Set[Commit]) | ApplyFail(Reason)

  // What a compaction does to the recipient set (compact::SetChange, minus repair/upgrade).
  type SetChange = Keep | Enroll(DeviceId) | Revoke(DeviceId)

  type Objects = {
    parents: Commit -> Set[Commit],
    history: Commit -> Set[Commit],   // ancestors, including the commit itself
    bundles: Digest -> BundleInfo,    // every bundle ciphertext ever made
  }

  type Host = {
    gens: GenId -> Gen,   // every vault commit it ever received, landed or not
    tip: GenId,           // the vault branch; 0 = empty
  }

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------

  var host: Host
  var devices: DeviceId -> Device
  var objs: Objects               // content-addressed: commit ancestry, bundle ciphertexts
  var nextId: int                 // fresh ids for commits, digests, generations, vaults
  var ghost: Ghost

  // ---------------------------------------------------------------------
  // Functional layer: small helpers
  // ---------------------------------------------------------------------

  pure def reach(history: Commit -> Set[Commit], tips: Set[Commit]): Set[Commit] =
    tips.fold(Set(), (acc, c) => acc.union(history.get(c)))

  pure def minOf(s: Set[int]): int =
    s.fold(s.fold(0, (a, x) => if (x > a) x else a), (a, x) => if (x < a) x else a)

  pure def restrict(m: Seq -> Digest, ks: Set[Seq]): Seq -> Digest = ks.mapBy(k => m.get(k))

  pure def mergeMap(m: Seq -> Digest, extra: Seq -> Digest): Seq -> Digest =
    extra.keys().fold(m, (acc, k) => acc.put(k, extra.get(k)))

  pure def digestsOf(g: Gen): Seq -> Digest = g.bundles.keys().mapBy(s => g.bundles.get(s).digest)

  pure def confirmedOf(p: Option[Pin]): Seq -> Digest =
    match p { | Some(x) => x.confirmed | None => Map() }

  pure def pendingOf(p: Option[Pin]): Seq -> Digest =
    match p { | Some(x) => x.pending | None => Map() }

  // ---------------------------------------------------------------------
  // Functional layer: the pin (pinstore.rs)
  // ---------------------------------------------------------------------

  // PinStore keys pins by vault identity; the PIN_PER_URL control keys them by URL.
  pure def keyOf(url: Url, vault: VaultId): PinKey =
    if (PIN_PER_URL) { url: url, vault: vault } else { url: "", vault: vault }

  // The pin a read through `url` runs against (reader::inspect_with).
  // Under PIN_PER_URL, first contact through a URL falls back to another URL's pin
  // (the pre-2026-09-05 errata behaviour).
  pure def pinFor(d: Device, url: Url, vault: VaultId): Option[Pin] = {
    val k = keyOf(url, vault)
    if (d.pins.has(k)) Some(d.pins.get(k))
    else d.pins.keys().filter(x => x.vault == vault).fold(None, (acc, x) => Some(d.pins.get(x)))
  }

  // PinStore::save: bind the URL on first save, then store the pin.
  pure def withPin(d: Device, url: Url, p: Pin): Device = {
    ...d,
    bindings: if (d.bindings.has(url)) d.bindings else d.bindings.put(url, p.vault),
    pins: d.pins.put(keyOf(url, p.vault), p),
  }

  pure def hasPinFor(d: Device, vault: VaultId): bool = d.pins.keys().exists(k => k.vault == vault)

  // pinstore::validate_and_advance, the refusal half (§7.4 battery).
  pure def battery(prev: Option[Pin], g: Gen, gid: GenId): Option[Reason] =
    match prev {
      | None => None
      | Some(p) =>
        if (p.vault != g.vault) Some(VaultMismatch)
        else if (g.counter < p.counter) Some(Rollback)
        else if (g.counter == p.counter and gid != p.digest) Some(Twin)
        else if (g.seqfloor < p.seqfloor) Some(SeqfloorRegression)
        else if (g.bundles.keys().exists(s => p.confirmed.has(s) and p.confirmed.get(s) != g.bundles.get(s).digest))
          Some(SequenceRebound)
        else None
    }

  // pinstore::resolve_pending: confirm what the line binds to our digest, drop what
  // its seqfloor passed, keep the rest pending.
  pure def promoted(pending: Seq -> Digest, g: Gen): Seq -> Digest =
    restrict(pending, pending.keys().filter(s => g.bundles.has(s) and g.bundles.get(s).digest == pending.get(s)))

  pure def stillPending(pending: Seq -> Digest, g: Gen): Seq -> Digest =
    restrict(pending, pending.keys().filter(s =>
      not(g.bundles.has(s) and g.bundles.get(s).digest == pending.get(s)) and s > g.seqfloor))

  // pinstore::validate_and_advance, the acceptance half. Records EVERY listed binding:
  // callers persist it only after applying (reader::apply) — §7.4 "accepted and applied".
  pure def advance(prev: Option[Pin], g: Gen, gid: GenId): Pin = {
    vault: g.vault,
    counter: g.counter,
    digest: gid,
    seqfloor: match prev { | Some(p) => if (p.seqfloor > g.seqfloor) p.seqfloor else g.seqfloor | None => g.seqfloor },
    confirmed: mergeMap(confirmedOf(prev), digestsOf(g)),
    pending: stillPending(pendingOf(prev), g),
  }

  // pinstore::confirm_acked: an acknowledged write burns every pending number at or
  // below the seqfloor it published.
  pure def confirmAcked(p: Pin, publishedSeqfloor: int): Pin = {
    val burned = p.pending.keys().filter(s => s <= publishedSeqfloor)
    { ...p,
      confirmed: mergeMap(p.confirmed, restrict(p.pending, burned)),
      pending: restrict(p.pending, p.pending.keys().exclude(burned)) }
  }

  // writer::advanced_pin: the pin after an acknowledged write of `g`.
  pure def advancedPin(bound: Pin, g: Gen, gid: GenId): Pin = {
    ...bound,
    vault: g.vault,
    counter: g.counter,
    digest: gid,
    seqfloor: if (bound.seqfloor > g.seqfloor) bound.seqfloor else g.seqfloor,
  }

  // pinstore::allocate_from: the lowest number >= first this device has not bound.
  // A CONFIRMED hit on the way is a stale base (§8.4 guard, refuse); PENDING is skipped.
  pure def allocate(confirmed: Seq -> Digest, pending: Seq -> Digest, first: Seq): Option[Seq] = {
    val chosen = minOf(first.to(first + pending.keys().size()).filter(s => not(pending.has(s))))
    if (first.to(chosen).exists(s => confirmed.has(s))) None else Some(chosen)
  }

  // ---------------------------------------------------------------------
  // Functional layer: reading (reader.rs)
  // ---------------------------------------------------------------------

  // §6 steps 1-4: empty-vault rule, decrypt, URL binding, pin battery.
  pure def inspect(dev: DeviceId, d: Device, url: Url, h: Host): Inspection = {
    val bound = d.bindings.has(url)
    if (h.tip == 0) { if (bound) IRefused(EmptyWithPin) else IEmpty }
    else {
      val g = h.gens.get(h.tip)
      if (not(g.recipients.contains(dev))) IRefused(CannotDecrypt)
      else if (bound and d.bindings.get(url) != g.vault) IRefused(VaultMismatch)
      else {
        val prev = pinFor(d, url, g.vault)
        match battery(prev, g, h.tip) {
          | Some(r) => IRefused(r)
          | None => IVault({ genId: h.tip, gen: g, prev: prev, nextPin: advance(prev, g, h.tip) })
        }
      }
    }
  }

  // Bundles `ss` of `g` verify (git bundle verify) when applied in ascending order on `repo`.
  pure def verifies(o: Objects, g: Gen, ss: Set[Seq], repo: Set[Commit]): bool =
    ss.forall(s => {
      val below = ss.filter(t => t < s).fold(repo, (acc, t) => acc.union(o.bundles.get(g.bundles.get(t).digest).contents))
      o.bundles.get(g.bundles.get(s).digest).prereqs.subseteq(below)
    })

  pure def decryptable(o: Objects, g: Gen, ss: Set[Seq], dev: DeviceId): bool =
    ss.forall(s => o.bundles.get(g.bundles.get(s).digest).recipients.contains(dev))

  pure def unpack(o: Objects, g: Gen, ss: Set[Seq], repo: Set[Commit]): Set[Commit] =
    ss.fold(repo, (acc, s) => acc.union(o.bundles.get(g.bundles.get(s).digest).contents))

  // §6 steps 5-6 (reader::apply): skip bundles the memory says were applied; when a
  // verify fails or a ref tip is missing, re-apply the skipped ones; still missing is loud.
  pure def applyGen(o: Objects, g: Gen, remembered: Seq -> Digest, repo: Set[Commit], dev: DeviceId): ApplyResult = {
    val listed = g.bundles.keys()
    val fresh = listed.filter(s => not(remembered.has(s) and remembered.get(s) == g.bundles.get(s).digest))
    val tips = g.refs.keys().map(r => g.refs.get(r))
    val fast = unpack(o, g, fresh, repo)
    val full = unpack(o, g, listed, repo)
    if (not(decryptable(o, g, fresh, dev))) ApplyFail(CannotDecryptBundle)
    else if (verifies(o, g, fresh, repo) and tips.subseteq(fast)) ApplyOk(fast)
    else if (not(decryptable(o, g, listed, dev))) ApplyFail(CannotDecryptBundle)
    else if (not(verifies(o, g, listed, repo))) ApplyFail(CorruptBundle)
    else if (not(tips.subseteq(full))) ApplyFail(MissingObject)
    else ApplyOk(full)
  }

  // ---------------------------------------------------------------------
  // Functional layer: writing (writer.rs, compact.rs)
  // ---------------------------------------------------------------------

  // §8 step 2 (writer::check_updates) for one update of `ref` to `nv` (None = delete).
  pure def checkUpdate(o: Objects, refs: RefName -> Commit, repo: Set[Commit],
                       ref: RefName, nv: Option[Commit], force: bool): Option[Reason] =
    match nv {
      | None => if (refs.has(ref)) None else Some(NothingToDo)
      | Some(c) =>
        if (refs.has(ref) and refs.get(ref) == c) Some(NothingToDo)
        else if (not(refs.has(ref)) or force) None
        else if (not(repo.contains(refs.get(ref)))) Some(FetchFirst)
        else if (not(o.history.get(c).contains(refs.get(ref)))) Some(NonFastForward)
        else None
    }

  pure def updatedRefs(refs: RefName -> Commit, ref: RefName, nv: Option[Commit]): RefName -> Commit =
    match nv {
      | None => refs.keys().exclude(Set(ref)).mapBy(r => refs.get(r))
      | Some(c) => refs.put(ref, c)
    }

  // §8 step 3: one bundle of the pushed tips, excluding history reachable from any
  // pre-update manifest sha this repository has. Prereqs are the excluded parents.
  pure def bundleFor(o: Objects, tips: Set[Commit], excludes: Set[Commit], encryptedTo: Set[DeviceId]): BundleInfo = {
    val excluded = reach(o.history, excludes)
    val contents = reach(o.history, tips).exclude(excluded)
    { contents: contents,
      prereqs: contents.fold(Set(), (acc, c) => acc.union(o.parents.get(c))).intersect(excluded),
      recipients: encryptedTo }
  }

  pure def newSet(current: Set[DeviceId], change: SetChange): Option[Set[DeviceId]] =
    match change {
      | Keep => Some(current)
      | Enroll(e) => if (current.contains(e)) None else Some(current.union(Set(e)))
      | Revoke(e) => if (current.contains(e)) Some(current.exclude(Set(e))) else None
    }

  // ---------------------------------------------------------------------
  // Functional layer: ghost bookkeeping
  // ---------------------------------------------------------------------

  // Record a pin save. `acceptance` marks saves that accept a generation (reads, acks),
  // as opposed to a writer withdrawing its binding after a rejection.
  pure def logPin(gh: Ghost, dev: DeviceId, p: Pin, acceptance: bool): Ghost = {
    val older = gh.seen.get(dev).exists(x => x.vault == p.vault and x.counter > p.counter)
    { ...gh,
      seen: if (acceptance) gh.seen.put(dev, gh.seen.get(dev).union(Set({ vault: p.vault, gen: p.digest, counter: p.counter })))
            else gh.seen,
      memoryLog: gh.memoryLog.put(dev, gh.memoryLog.get(dev).union(p.confirmed.keys().map(s => (p.vault, s, p.confirmed.get(s))))),
      rolledBack: gh.rolledBack or (acceptance and older) }
  }

  // A device's memory of `vault` is gone (forget, or a withdrawn first contact).
  pure def unlog(gh: Ghost, dev: DeviceId, vault: VaultId): Ghost = {
    ...gh,
    seen: gh.seen.put(dev, gh.seen.get(dev).filter(x => x.vault != vault)),
    memoryLog: gh.memoryLog.put(dev, gh.memoryLog.get(dev).filter(x => x._1 != vault)),
    allocs: gh.allocs.filter(a => not(a.dev == dev and a.vault == vault)),
  }

  // ---------------------------------------------------------------------
  // State machine
  // ---------------------------------------------------------------------

  action init = all {
    host' = { gens: Map(), tip: 0 },
    devices' = DEVICES.mapBy(_ => { repo: Set(), bindings: Map(), pins: Map(), op: Idle }),
    objs' = { parents: Map(), history: Map(), bundles: Map() },
    nextId' = 1,
    ghost' = { lastEvent: NoEvent, acked: Set(), allocs: Set(),
               seen: DEVICES.mapBy(_ => Set()), memoryLog: DEVICES.mapBy(_ => Set()),
               rolledBack: false },
  }

  // A command that stops with an error: nothing changes but what the user is told.
  action refuse(dev: DeviceId, r: Reason): bool = all {
    host' = host, devices' = devices, objs' = objs, nextId' = nextId,
    ghost' = { ...ghost, lastEvent: Refused({ dev: dev, reason: r }) },
  }

  // A branch that cannot fire (the command has nothing to do and writes nothing).
  action disabled: bool = all {
    false,
    host' = host, devices' = devices, objs' = objs, nextId' = nextId, ghost' = ghost,
  }

  // The user commits in the source repository (one parent, or a new root).
  action commit(dev: DeviceId, parent: Option[Commit]): bool = {
    val d = devices.get(dev)
    val c = nextId
    val ps = match parent { | Some(p) => Set(p) | None => Set() }
    all {
      objs.parents.keys().size() < MAX_COMMITS,
      ps.subseteq(d.repo),
      host' = host,
      devices' = devices.put(dev, { ...d, repo: d.repo.union(Set(c)) }),
      objs' = { ...objs, parents: objs.parents.put(c, ps),
                history: objs.history.put(c, reach(objs.history, ps).union(Set(c))) },
      nextId' = nextId + 1,
      ghost' = ghost,
    }
  }

  // Step 1 of a write, shared by push and compaction: register the new bundle (if
  // any), save the PENDING binding when there is one, and go in flight.
  action send(dev: DeviceId, d: Device, up: Upload, info: BundleInfo, digest: Digest, ids: int): bool = {
    val saved = up.alloc > 0 and up.onReject != KeepPin
    all {
      host' = host,
      devices' = devices.put(dev, { ...(if (saved) withPin(d, up.url, up.bound) else d), op: Uploading(up) }),
      objs' = if (up.alloc > 0) { ...objs, bundles: objs.bundles.put(digest, info) } else objs,
      nextId' = nextId + ids,
      ghost' = {
        val g1 = if (saved) logPin(ghost, dev, up.bound, false) else ghost
        { ...g1,
          lastEvent: Sent({ dev: dev, gen: up.genId, kind: up.gen.kind }),
          allocs: if (up.alloc > 0)
                    g1.allocs.union(Set({ dev: dev, vault: up.gen.vault, seq: up.alloc, digest: digest, fate: InFlight }))
                  else g1.allocs }
      },
    }
  }

  // §8 against an empty remote: initialize the vault (writer::attempt_init).
  // Nothing is bound before the push (note 8d).
  action initWrite(dev: DeviceId, d: Device, url: Url, ref: RefName, c: Commit): bool = {
    val digest = nextId
    val genId = nextId + 1
    val vault = nextId + 2
    val gen = { vault: vault, counter: 1, seqfloor: 1,
                bundles: Map(1 -> { digest: digest, full: true }), refs: Map(ref -> c),
                recipients: Set(dev), kind: Init, base: 0, lineage: Set() }
    val bound = { vault: vault, counter: 1, digest: genId, seqfloor: 1,
                  confirmed: Map(1 -> digest), pending: Map() }
    send(dev, d, { url: url, genId: genId, gen: gen, alloc: 1, bound: bound, onReject: KeepPin },
         bundleFor(objs, Set(c), Set(), Set(dev)), digest, 3)
  }

  // §8 steps 2-4 against an existing vault (writer::attempt_incremental).
  action incrementalWrite(dev: DeviceId, d: Device, url: Url, ref: RefName, nv: Option[Commit],
                          force: bool, genId: GenId, g: Gen, prev: Option[Pin], nextPin: Pin): bool = {
    val tips = match nv { | Some(c) => Set(c) | None => Set() }
    val info = bundleFor(objs, tips, g.refs.keys().map(r => g.refs.get(r)).intersect(d.repo), g.recipients)
    val needsBundle = info.contents != Set()
    // The pin the write builds on: the battery's result, but with this device's own
    // memory only — the base's bundles were read, not applied (§7.4).
    val base = { ...nextPin,
                 confirmed: if (PUSH_RECORDS_BASE) nextPin.confirmed
                            else mergeMap(confirmedOf(prev), promoted(pendingOf(prev), g)),
                 pending: stillPending(pendingOf(prev), g) }
    val seq = if (needsBundle) allocate(base.confirmed, base.pending, g.seqfloor + 1) else Some(0)
    match checkUpdate(objs, g.refs, d.repo, ref, nv, force) {
      | Some(r) => if (r == NothingToDo) disabled else refuse(dev, r)
      | None => match seq {
        | None => refuse(dev, AllocationCollision)
        | Some(s) => {
          val digest = nextId
          val newId = if (needsBundle) nextId + 1 else nextId
          val gen = { ...g,
                      counter: g.counter + 1,
                      seqfloor: if (needsBundle) s else g.seqfloor,
                      bundles: if (needsBundle) g.bundles.put(s, { digest: digest, full: g.bundles.keys() == Set() })
                               else g.bundles,
                      refs: updatedRefs(g.refs, ref, nv),
                      kind: Push, base: genId, lineage: g.lineage.union(Set(genId)) }
          val bound = if (needsBundle) { ...base, pending: base.pending.put(s, digest) } else base
          send(dev, d, { url: url, genId: newId, gen: gen, alloc: s, bound: bound,
                         onReject: if (needsBundle) SavePin(base) else KeepPin },
               info, digest, if (needsBundle) 2 else 1)
        }
      }
    }
  }

  // `git push` through `url`: one ref update, possibly forced.
  action startPush(dev: DeviceId, url: Url, ref: RefName, nv: Option[Commit], force: bool): bool = {
    val d = devices.get(dev)
    all {
      d.op == Idle,
      match inspect(dev, d, url, host) {
        | IEmpty => match nv {
          | Some(c) => initWrite(dev, d, url, ref, c)
          | None => disabled   // deleting on an empty vault writes nothing
        }
        | IRefused(r) => refuse(dev, r)
        | IVault(v) => incrementalWrite(dev, d, url, ref, nv, force, v.genId, v.gen, v.prev, v.nextPin)
      },
    }
  }

  // The host takes the upload (or it never arrives), lands it iff the branch is where
  // the writer left it, and a verdict reaches the writer — or does not (§8.5).
  action deliver(dev: DeviceId, arrived: bool, verdict: Verdict): bool = {
    val d = devices.get(dev)
    match d.op {
      | Idle => disabled
      | Uploading(up) => {
        val casOk = if (up.gen.kind == Compaction and COMPACT_BLIND_FORCE) true else host.tip == up.gen.base
        val landed = arrived and casOk
        val possible = if (landed) Set(Acked, Indeterminate)
                       else if (arrived) Set(Rejected, Indeterminate)
                       else Set(Indeterminate)
        val believed = if (verdict == Indeterminate and INDET_AS_REJECT) Rejected else verdict
        val idle = { ...d, op: Idle }
        val ackPin = advancedPin(confirmAcked(up.bound, up.gen.seqfloor), up.gen, up.genId)
        val fated = { ...ghost,
                      lastEvent: Outcome({ dev: dev, gen: up.genId, verdict: verdict, landed: landed }),
                      allocs: ghost.allocs.map(a =>
                        if (a.dev == dev and a.seq == up.alloc and a.vault == up.gen.vault and a.fate == InFlight)
                          { ...a, fate: if (landed) Landed else NotLanded }
                        else a) }
        all {
          possible.contains(verdict),
          host' = { gens: if (arrived) host.gens.put(up.genId, up.gen) else host.gens,
                    tip: if (landed) up.genId else host.tip },
          objs' = objs,
          nextId' = nextId,
          if (believed == Acked) all {
            devices' = devices.put(dev, withPin(idle, up.url, ackPin)),
            ghost' = { ...logPin(fated, dev, ackPin, true), acked: fated.acked.union(Set(up.genId)) },
          } else if (believed == Rejected) {
            match up.onReject {
              | KeepPin => all { devices' = devices.put(dev, idle), ghost' = fated }
              | SavePin(x) => all {
                devices' = devices.put(dev, withPin(idle, up.url, x)),
                ghost' = logPin(fated, dev, x, false),
              }
            }
          } else all {
            // Indeterminate: the PENDING binding stays exactly as saved.
            devices' = devices.put(dev, idle),
            ghost' = fated,
          },
        }
      }
    }
  }

  // `git fetch` through `url`: §6 end to end; the pin is persisted only after apply.
  action fetch(dev: DeviceId, url: Url): bool = {
    val d = devices.get(dev)
    all {
      d.op == Idle,
      match inspect(dev, d, url, host) {
        | IEmpty => disabled   // an empty vault reads as no refs: nothing changes
        | IRefused(r) => refuse(dev, r)
        | IVault(v) => match applyGen(objs, v.gen, confirmedOf(v.prev), d.repo, dev) {
          | ApplyFail(r) => refuse(dev, r)
          | ApplyOk(repo) => all {
            host' = host,
            devices' = devices.put(dev, withPin({ ...d, repo: repo }, url, v.nextPin)),
            objs' = objs,
            nextId' = nextId,
            ghost' = { ...logPin(ghost, dev, v.nextPin, true), lastEvent: Accepted({ dev: dev, gen: v.genId }) },
          }
        }
      },
    }
  }

  // §9 compaction through `url` (compact::compact): read AND apply (persisting the
  // read's pin), one `-full` bundle of every ref at an allocated number — or, with no
  // refs, a manifest-only generation — to be CAS-pushed against the tip just read.
  // §9.1: enroll/revoke are compactions whose manifest carries the new set.
  action startCompact(dev: DeviceId, url: Url, change: SetChange): bool = {
    val d = devices.get(dev)
    all {
      d.op == Idle,
      match inspect(dev, d, url, host) {
        | IEmpty => disabled   // `compact` on an empty vault: an error, nothing to see
        | IRefused(r) => refuse(dev, r)
        | IVault(v) => match newSet(v.gen.recipients, change) {
          | None => disabled   // the change is already in effect: nothing written
          | Some(newRecipients) =>
            if (newRecipients == Set()) refuse(dev, EmptySet)
            else match applyGen(objs, v.gen, confirmedOf(v.prev), d.repo, dev) {
              | ApplyFail(r) => refuse(dev, r)
              | ApplyOk(repo) => compactWrite(dev, withPin({ ...d, repo: repo }, url, v.nextPin),
                                              url, change, newRecipients, v.genId, v.gen, v.nextPin)
            }
        }
      },
    }
  }

  action compactWrite(dev: DeviceId, d: Device, url: Url, change: SetChange, newRecipients: Set[DeviceId],
                      genId: GenId, g: Gen, pinBase: Pin): bool = {
    val readGhost = logPin(ghost, dev, pinBase, true)
    val hasRefs = g.refs.keys() != Set()
    val byPush = SET_CHANGE_BY_PUSH and change != Keep
    val seq = if (hasRefs and not(byPush)) allocate(pinBase.confirmed, pinBase.pending, g.seqfloor + 1) else Some(0)
    match seq {
      | None => all {
        // allocation refused after the read was applied and persisted
        host' = host, devices' = devices.put(dev, d), objs' = objs, nextId' = nextId,
        ghost' = { ...readGhost, lastEvent: Refused({ dev: dev, reason: AllocationCollision }) },
      }
      | Some(s) => {
        val digest = nextId
        val newId = if (s > 0) nextId + 1 else nextId
        val info = { contents: reach(objs.history, g.refs.keys().map(r => g.refs.get(r))),
                     prereqs: Set(), recipients: newRecipients }
        val gen = if (byPush)
                    // Negative control: the set changes by a manifest-only push; the
                    // bundles stay encrypted to the old set.
                    { ...g, counter: g.counter + 1, recipients: newRecipients, kind: Push,
                      base: genId, lineage: g.lineage.union(Set(genId)) }
                  else
                    { ...g, counter: g.counter + 1,
                      seqfloor: if (s > 0) s else g.seqfloor,
                      bundles: if (s > 0) Map(s -> { digest: digest, full: true }) else Map(),
                      refs: if (s > 0) g.refs else Map(),
                      recipients: newRecipients, kind: Compaction,
                      base: genId, lineage: g.lineage.union(Set(genId)) }
        val bound = if (s > 0) { ...pinBase, pending: pinBase.pending.put(s, digest) } else pinBase
        all {
          host' = host,
          devices' = devices.put(dev, { ...(if (s > 0) withPin(d, url, bound) else d),
                                        op: Uploading({ url: url, genId: newId, gen: gen, alloc: s, bound: bound,
                                                        onReject: if (s > 0) SavePin(pinBase) else KeepPin }) }),
          objs' = if (s > 0) { ...objs, bundles: objs.bundles.put(digest, info) } else objs,
          nextId' = if (s > 0) nextId + 2 else nextId + 1,
          ghost' = {
            val g1 = if (s > 0) logPin(readGhost, dev, bound, false) else readGhost
            { ...g1,
              lastEvent: Sent({ dev: dev, gen: newId, kind: gen.kind }),
              allocs: if (s > 0)
                        g1.allocs.union(Set({ dev: dev, vault: g.vault, seq: s, digest: digest, fate: InFlight }))
                      else g1.allocs }
          },
        }
      }
    }
  }

  // §7.5 `forget` for one URL (PinStore::forget_url): drop its binding; drop the
  // vault's pin only when no other URL of this repository is bound to that vault.
  action forget(dev: DeviceId, url: Url): bool = {
    val d = devices.get(dev)
    val vault = d.bindings.get(url)
    val bindings = d.bindings.keys().exclude(Set(url)).mapBy(u => d.bindings.get(u))
    val othersBound = bindings.keys().exists(u => bindings.get(u) == vault)
    val pins = if (not(othersBound)) d.pins.keys().filter(k => k.vault != vault).mapBy(k => d.pins.get(k))
               else d.pins.keys().exclude(Set({ url: url, vault: vault })).mapBy(k => d.pins.get(k))
    val after = { ...d, bindings: bindings, pins: pins }
    all {
      d.op == Idle,
      d.bindings.has(url),
      host' = host,
      devices' = devices.put(dev, after),
      objs' = objs,
      nextId' = nextId,
      ghost' = { ...(if (hasPinFor(after, vault)) ghost else unlog(ghost, dev, vault)),
                 lastEvent: Forgot({ dev: dev, url: url }) },
    }
  }

  // A malicious host rewrites its branch to any vault commit it holds, or empties it.
  // Every other attack in the threat model is a consequence: replay, rollback, fork
  // (serving different tips at different times), whole-vault substitution.
  action rewind(t: GenId): bool = all {
    not(HONEST_HOST),
    t == 0 or host.gens.has(t),
    t != host.tip,
    host' = { ...host, tip: t },
    devices' = devices, objs' = objs, nextId' = nextId,
    ghost' = { ...ghost, lastEvent: Rewound({ tip: t }) },
  }

  action step = {
    nondet dev = DEVICES.oneOf()
    nondet url = URLS.oneOf()
    nondet ref = REFS.oneOf()
    nondet force = Set(true, false).oneOf()
    nondet arrived = Set(true, false).oneOf()
    nondet verdict = Set(Acked, Rejected, Indeterminate).oneOf()
    val repo = devices.get(dev).repo
    nondet parent = Set(None).union(repo.map(c => Some(c))).oneOf()
    nondet nv = Set(None).union(repo.map(c => Some(c))).oneOf()
    nondet other = DEVICES.oneOf()
    nondet change = Set(Keep, Enroll(other), Revoke(other)).oneOf()
    nondet t = host.gens.keys().union(Set(0)).oneOf()
    any {
      commit(dev, parent),
      startPush(dev, url, ref, nv, force),
      deliver(dev, arrived, verdict),
      fetch(dev, url),
      startCompact(dev, url, change),
      forget(dev, url),
      rewind(t),
    }
  }

  // ---------------------------------------------------------------------
  // Witnesses (reachability; pass to `quint run --witnesses`)
  // ---------------------------------------------------------------------

  pure def isSent(e: Event, k: GenKind): bool = match e { | Sent(x) => x.kind == k | _ => false }
  pure def isOutcome(e: Event, v: Verdict, l: bool): bool =
    match e { | Outcome(x) => x.verdict == v and x.landed == l | _ => false }
  pure def isRefused(e: Event, r: Reason): bool = match e { | Refused(x) => x.reason == r | _ => false }
  pure def isAccepted(e: Event): bool = match e { | Accepted(_) => true | _ => false }

  val w_committed: bool = objs.parents.keys().size() >= 2
  val w_rewound: bool = match ghost.lastEvent { | Rewound(_) => true | _ => false }
  val w_vaultInitialized: bool = host.tip != 0
  val w_pushSent: bool = isSent(ghost.lastEvent, Push)
  val w_pushAcked: bool = isOutcome(ghost.lastEvent, Acked, true) and host.gens.get(host.tip).kind == Push
  val w_rejected: bool = isOutcome(ghost.lastEvent, Rejected, false)
  val w_lostAck: bool = isOutcome(ghost.lastEvent, Indeterminate, true)
  val w_readAccepted: bool = isAccepted(ghost.lastEvent)
  val w_notARecipient: bool = isRefused(ghost.lastEvent, CannotDecrypt)
  val w_nonFastForward: bool = isRefused(ghost.lastEvent, NonFastForward)
  val w_compacted: bool = isOutcome(ghost.lastEvent, Acked, true) and host.gens.get(host.tip).kind == Compaction
  val w_enrolledReads: bool = match ghost.lastEvent {
    | Accepted(x) => not(host.gens.values().exists(g => g.kind == Init and g.recipients.contains(x.dev)))
    | _ => false }
  val w_zeroRefCompaction: bool = host.tip != 0 and host.gens.get(host.tip).kind == Compaction
                                  and host.gens.get(host.tip).bundles.keys() == Set()
  // §4.1: the first push after a zero-ref compaction is labelled -full.
  val w_fullAfterEmpty: bool = host.gens.values().exists(g => g.kind == Push and
                                 host.gens.get(g.base).bundles.keys() == Set() and
                                 g.bundles.keys().exists(s => g.bundles.get(s).full))
  val w_forgot: bool = match ghost.lastEvent { | Forgot(_) => true | _ => false }
  val w_revokedLockedOut: bool = isRefused(ghost.lastEvent, CannotDecrypt) and match ghost.lastEvent {
    | Refused(x) => host.gens.values().exists(g => g.recipients.contains(x.dev)) | _ => false }
  // Each check of the §7.4 battery fires (malicious host).
  val w_rollbackRefused: bool = isRefused(ghost.lastEvent, Rollback)
  val w_twinRefused: bool = isRefused(ghost.lastEvent, Twin)
  val w_seqfloorRefused: bool = isRefused(ghost.lastEvent, SeqfloorRegression)
  val w_reboundRefused: bool = isRefused(ghost.lastEvent, SequenceRebound)
  val w_vaultSwapRefused: bool = isRefused(ghost.lastEvent, VaultMismatch)
  val w_emptyWithPinRefused: bool = isRefused(ghost.lastEvent, EmptyWithPin)
  val w_staleBaseRefused: bool = isRefused(ghost.lastEvent, AllocationCollision)
  // §8.4: a push skipped a pending number (its allocation is above seqfloor + 1).
  val w_pendingSkipped: bool = match ghost.lastEvent {
    | Sent(x) => x.kind != Init and host.gens.has(host.tip) and ghost.allocs.exists(a =>
        a.fate == InFlight and a.seq > host.gens.get(host.tip).seqfloor + 1)
    | _ => false }
  val w_pendingHeld: bool = DEVICES.exists(d => devices.get(d).pins.keys().exists(k =>
    devices.get(d).pins.get(k).pending.keys().size() > 0 and devices.get(d).op == Idle))

  // ---------------------------------------------------------------------
  // Invariants
  // ---------------------------------------------------------------------

  def gen(id: GenId): Gen = host.gens.get(id)
  def contentsOf(g: Gen, ss: Set[Seq]): Set[Commit] =
    ss.fold(Set(), (acc, s) => acc.union(objs.bundles.get(g.bundles.get(s).digest).contents))
  // Every generation that has ever been on the branch under an honest host.
  val truth: Set[GenId] = if (host.tip == 0) Set() else gen(host.tip).lineage.union(Set(host.tip))

  // --- every generation any writer produced (both host modes) ---

  // §7.2: seqfloor >= every listed sequence number, and numbers start at 1.
  val inv_seqfloorCoversBundles: bool = host.gens.values().forall(g =>
    g.bundles.keys().forall(s => 1 <= s and s <= g.seqfloor))

  // §4.1 / §7.2: a nonempty bundle list is -full at its lowest number, and only there.
  val inv_rootedAtLowest: bool = host.gens.values().forall(g =>
    g.bundles.keys().forall(s => g.bundles.get(s).full iff s == minOf(g.bundles.keys())))

  // §4.3: every bundle's prerequisites are carried by lower-numbered bundles of the
  // same generation, so applying in ascending order never fails a prerequisite check.
  val inv_prereqClosure: bool = host.gens.values().forall(g =>
    g.bundles.keys().forall(s =>
      objs.bundles.get(g.bundles.get(s).digest).prereqs.subseteq(contentsOf(g, g.bundles.keys().filter(t => t < s)))))

  // §6.6: the bundles of a generation carry the whole history of every ref it lists.
  val inv_refsClosed: bool = host.gens.values().forall(g =>
    g.refs.keys().forall(r => objs.history.get(g.refs.get(r)).subseteq(contentsOf(g, g.bundles.keys()))))

  // §5: every file of a generation is encrypted to exactly its recipient set.
  val inv_oneSetPerGeneration: bool = host.gens.values().forall(g =>
    g.recipients != Set() and
    g.bundles.keys().forall(s => objs.bundles.get(g.bundles.get(s).digest).recipients == g.recipients))

  // §5 / §9.1: a push carries its base's set unchanged; only a compaction changes it.
  val inv_setChangesOnlyByCompaction: bool = host.gens.values().forall(g =>
    g.kind == Push implies g.recipients == gen(g.base).recipients)

  // --- every device (both host modes) ---

  // The local repository never has a commit without its ancestors.
  val inv_repoConnected: bool = DEVICES.forall(d =>
    devices.get(d).repo.forall(c => objs.history.get(c).subseteq(devices.get(d).repo)))

  // §7.4 / 7e: a CONFIRMED binding means its bundle's objects are in the repository —
  // which is what makes reader::apply's skip sound.
  val inv_confirmedMeansApplied: bool = DEVICES.forall(d => {
    val dv = devices.get(d)
    dv.pins.keys().forall(k => {
      val p = dv.pins.get(k)
      p.confirmed.keys().forall(s => objs.bundles.get(p.confirmed.get(s)).contents.subseteq(dv.repo))
    })
  })

  // Every CONFIRMED number is at or below the pin's seqfloor, and every PENDING one
  // above the seqfloor of the generation it was allocated on. With the battery's
  // seqfloor check this makes the §8.4 guard's CONFIRMED branch (8b) unreachable:
  // a base that passed has seqfloor >= pin.seqfloor >= every confirmed number.
  val inv_confirmedWithinSeqfloor: bool = DEVICES.forall(d => {
    val dv = devices.get(d)
    dv.pins.keys().forall(k => dv.pins.get(k).confirmed.keys().forall(s => s <= dv.pins.get(k).seqfloor))
  })

  // §7.4: a device never holds two CONFIRMED digests for one number (reset by forget).
  val inv_memoryNeverRebound: bool = DEVICES.forall(d =>
    ghost.memoryLog.get(d).forall(a => ghost.memoryLog.get(d).forall(b =>
      (a._1 == b._1 and a._2 == b._2) implies a._3 == b._3)))

  // §7.4 twin check: a device never pins two generations of one vault with one counter.
  val inv_noTwinPinned: bool = DEVICES.forall(d =>
    ghost.seen.get(d).forall(a => ghost.seen.get(d).forall(b =>
      (a.vault == b.vault and a.counter == b.counter) implies a.gen == b.gen)))

  // §7.4 counter check: a device never accepts a generation older than one it accepted.
  val inv_noRollbackAccepted: bool = not(ghost.rolledBack)

  // §6: an accepted manifest always applies: nothing missing, nothing undecryptable.
  val inv_readsNeverBreak: bool = match ghost.lastEvent {
    | Refused(x) => not(Set(MissingObject, CorruptBundle, CannotDecryptBundle).contains(x.reason))
    | _ => true
  }

  // §8.4 / 8c: a device never binds one number to new content while an earlier binding
  // of it may have landed — the crash-lagged writer (lost acknowledgement).
  val inv_noNumberRebound: bool = ghost.allocs.forall(a => ghost.allocs.forall(b =>
    (a.dev == b.dev and a.vault == b.vault and a.seq == b.seq and a.digest != b.digest)
      implies (a.fate == NotLanded or b.fate == NotLanded)))

  // --- honest host only ---

  // §9.4: an acknowledged write is never erased: it stays in the branch's lineage.
  val inv_ackedDurable: bool = HONEST_HOST implies ghost.acked.subseteq(truth)

  // Every device's memory points at a generation that really was on the branch.
  val inv_viewOnTruth: bool = HONEST_HOST implies DEVICES.forall(d =>
    devices.get(d).pins.keys().forall(k => truth.contains(devices.get(d).pins.get(k).digest)))

  // The branch's history binds every sequence number to one ciphertext.
  val inv_lineConsistent: bool = HONEST_HOST implies truth.forall(a => truth.forall(b =>
    gen(a).bundles.keys().intersect(gen(b).bundles.keys()).forall(s =>
      gen(a).bundles.get(s).digest == gen(b).bundles.get(s).digest)))

  val safety: bool = and {
    inv_seqfloorCoversBundles, inv_rootedAtLowest, inv_prereqClosure, inv_refsClosed,
    inv_oneSetPerGeneration, inv_setChangesOnlyByCompaction,
    inv_repoConnected, inv_confirmedMeansApplied, inv_confirmedWithinSeqfloor, inv_memoryNeverRebound, inv_noTwinPinned,
    inv_noRollbackAccepted, inv_readsNeverBreak, inv_noNumberRebound,
    inv_ackedDurable, inv_viewOnTruth, inv_lineConsistent,
  }
}

module protocol_honest {
  import protocol(
    DEVICES = Set("A", "B"), URLS = Set("ssh", "https"), REFS = Set("main", "dev"),
    MAX_COMMITS = 4, HONEST_HOST = true,
    INDET_AS_REJECT = false, COMPACT_BLIND_FORCE = false, PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false, PUSH_RECORDS_BASE = false
  ).*
}

module protocol_malicious {
  import protocol(
    DEVICES = Set("A", "B"), URLS = Set("ssh", "https"), REFS = Set("main", "dev"),
    MAX_COMMITS = 4, HONEST_HOST = false,
    INDET_AS_REJECT = false, COMPACT_BLIND_FORCE = false, PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false, PUSH_RECORDS_BASE = false
  ).*
}

module protocol_malicious3 {
  import protocol(
    DEVICES = Set("A", "B", "C"), URLS = Set("ssh", "https"), REFS = Set("main", "dev"),
    MAX_COMMITS = 5, HONEST_HOST = false,
    INDET_AS_REJECT = false, COMPACT_BLIND_FORCE = false, PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false, PUSH_RECORDS_BASE = false
  ).*
}
