// Scenario tests: each is one concrete execution from the design notes, replayed
// step by step. Run with `quint test protocol_test.qnt --main=<module>`.
//
// Fresh ids are handed out by `nextId` in order: a commit takes one; a vault
// initialization takes three (digest, generation, vault); a write with a bundle takes
// two (digest, generation); a write without one takes one (generation).

// The malicious-host instance: the attacks the rules exist to stop.
module attacks_test {
  import protocol(
    DEVICES = Set("A", "B"), URLS = Set("ssh", "https"), REFS = Set("main", "dev"),
    MAX_COMMITS = 4, HONEST_HOST = false,
    INDET_AS_REJECT = false, COMPACT_BLIND_FORCE = false, PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false, PUSH_RECORDS_BASE = false
  ).* from "./protocol"
  import basicSpells.* from "./basicSpells"

  pure def refusedWith(e: Event, r: Reason): bool = match e { | Refused(x) => x.reason == r | _ => false }
  pure def acceptedGen(e: Event, g: GenId): bool = match e { | Accepted(x) => x.gen == g | _ => false }

  // A initializes the vault (commit 1, digest 2, generation 3, vault 4) and it is acked.
  action initialized = init
    .then(commit("A", None))
    .then(startPush("A", "ssh", "main", Some(1), false))
    .then(deliver("A", true, Acked))

  // §8.4 / 8c, the crash-lagged writer: A's push of sequence 2 lands but the status
  // report is lost; the host replays the pre-push state; A's next push must not
  // bind 2 to new content. It skips the pending number and takes 3.
  run crashLagSkipsPendingTest =
    initialized
      .then(commit("A", Some(1)))                                 // commit 5
      .then(startPush("A", "ssh", "main", Some(5), false))        // digest 6, generation 7, seq 2
      .then(deliver("A", true, Indeterminate))                    // landed, verdict lost
      .expect(host.tip == 7 and devices.get("A").pins.get({ url: "", vault: 4 }).pending == Map(2 -> 6))
      .then(rewind(3))                                            // host replays generation 3
      .then(startPush("A", "ssh", "dev", Some(5), false))         // digest 8, generation 9
      .expect(ghost.allocs.exists(a => a.seq == 3 and a.digest == 8) and inv_noNumberRebound)

  // §7.4 rollback check, and §7.5: forget forfeits it.
  run forgetForfeitsRollbackProtectionTest =
    initialized
      .then(commit("A", Some(1)))                                 // commit 5
      .then(startPush("A", "ssh", "main", Some(5), false))        // generation 7, counter 2
      .then(deliver("A", true, Acked))
      .then(rewind(3))                                            // replay counter 1
      .then(fetch("A", "ssh"))
      .expect(refusedWith(ghost.lastEvent, Rollback))
      .then(forget("A", "ssh"))
      .then(fetch("A", "ssh"))
      .expect(acceptedGen(ghost.lastEvent, 3))                    // the rollback is accepted

  // §7.4 / 7h: one pin per vault, shared by every URL. A reads through https, pushes
  // through ssh; a replay of the old generation through https is still a rollback.
  run aliasSharesThePinTest =
    initialized
      .then(fetch("A", "https"))                                  // https bound to vault 4
      .then(commit("A", Some(1)))
      .then(startPush("A", "ssh", "main", Some(5), false))        // generation 7, counter 2
      .then(deliver("A", true, Acked))
      .then(rewind(3))
      .then(fetch("A", "https"))
      .expect(refusedWith(ghost.lastEvent, Rollback))

  // §7.4 twin check: a losing concurrent push's genuine commit, replayed by the host.
  // A enrolls B; both push on generation 6; B lands, A is rejected; the host then
  // serves A's rejected commit (same counter as B's) to B.
  run twinRefusedTest =
    initialized
      .then(startCompact("A", "ssh", Enroll("B")))                // digest 5, generation 6, seq 2
      .then(deliver("A", true, Acked))
      .then(fetch("B", "ssh"))
      .then(commit("B", Some(1)))                                 // commit 7
      .then(startPush("B", "ssh", "main", Some(7), false))        // digest 8, generation 9
      .then(commit("A", Some(1)))                                 // commit 10
      .then(startPush("A", "ssh", "dev", Some(10), false))        // digest 11, generation 12
      .then(deliver("B", true, Acked))
      .then(deliver("A", true, Rejected))
      .then(rewind(12))
      .then(fetch("B", "ssh"))
      .expect(refusedWith(ghost.lastEvent, Twin))

  // A fork the host builds from genuine states. A enrolls B (generation 6, seq 2);
  // B reads it; A pushes seq 3 (generation 9) and is acked; the host rewinds to 6
  // and lets B, who never saw 9, build its own line on it.
  action forked = initialized
    .then(startCompact("A", "ssh", Enroll("B")))                  // digest 5, generation 6
    .then(deliver("A", true, Acked))
    .then(fetch("B", "ssh"))
    .then(commit("A", Some(1)))                                   // commit 7
    .then(startPush("A", "ssh", "main", Some(7), false))          // digest 8, generation 9, seq 3
    .then(deliver("A", true, Acked))
    .then(rewind(6))

  // §7.4 sequence memory: B binds seq 3 to its own content and moves on (counter 4);
  // A, who confirmed seq 3 -> digest 8, refuses the fork — counter alone would pass.
  run forkReboundRefusedTest =
    forked
      .then(commit("B", Some(1)))                                 // commit 10
      .then(startPush("B", "ssh", "main", Some(10), false))       // digest 11, generation 12, seq 3
      .then(deliver("B", true, Acked))
      .then(startPush("B", "ssh", "dev", Some(10), false))        // generation 13, no bundle
      .then(deliver("B", true, Acked))
      .then(fetch("A", "ssh"))
      .expect(refusedWith(ghost.lastEvent, SequenceRebound))

  // §7.4 seqfloor: B's line advances by manifest-only pushes (no numbers); counter
  // overtakes A's pin but seqfloor stays behind it: the fork-hop counters miss.
  run forkSeqfloorRefusedTest =
    forked
      .then(startPush("B", "ssh", "dev", Some(1), false))         // generation 10, counter 3
      .then(deliver("B", true, Acked))
      .then(startPush("B", "ssh", "dev", None, false))            // generation 11, counter 4
      .then(deliver("B", true, Acked))
      .then(fetch("A", "ssh"))
      .expect(refusedWith(ghost.lastEvent, SeqfloorRegression))

  // §10's documented limit: a fork that never re-binds a confirmed number and keeps
  // seqfloor ahead is accepted. Here B's line skips past seq 3 via its own pending
  // number, so A's view silently drops generation 9.
  run forkWithoutReboundIsAcceptedTest =
    forked
      .then(commit("B", Some(1)))                                 // commit 10
      .then(startPush("B", "ssh", "main", Some(10), false))       // digest 11, generation 12, seq 3
      .then(deliver("B", false, Indeterminate))                   // never arrived: 3 stays pending
      .then(startPush("B", "ssh", "dev", Some(10), false))        // digest 13, generation 14, seq 4
      .then(deliver("B", true, Acked))
      .then(startPush("B", "ssh", "main", Some(10), false))       // generation 15, counter 4, no bundle
      .then(deliver("B", true, Acked))
      .then(fetch("A", "ssh"))
      .expect(acceptedGen(ghost.lastEvent, 15) and not(host.gens.get(15).lineage.contains(9)))

  // Found by simulation (then fixed in writer.rs): a rejected push must keep what
  // its read confirmed. A and B compact concurrently from generation 6, both at
  // seq 3; B lands. The host then publishes A's losing commit (generation 8), A
  // pushes on it — the read confirms seq 3 -> A's digest 7 — and that push is
  // rejected. The writer keeps that read's pin, so B's generation 10 (seq 3 ->
  // digest 9, a twin of 8) is refused. Going back to the pin from BEFORE the read
  // (the old writer::restore_pin) made seq 3 pending again and accepted it.
  run rejectedPushKeepsItsConfirmationTest =
    initialized
      .then(startCompact("A", "ssh", Enroll("B")))                // digest 5, generation 6, seq 2
      .then(deliver("A", true, Acked))
      .then(fetch("B", "ssh"))
      .then(startCompact("A", "ssh", Keep))                       // digest 7, generation 8, seq 3
      .then(startCompact("B", "ssh", Keep))                       // digest 9, generation 10, seq 3
      .then(deliver("B", true, Acked))                            // tip 10
      .then(deliver("A", true, Indeterminate))                    // arrived, lost the CAS
      .then(rewind(8))                                            // host publishes A's commit
      .then(commit("A", Some(1)))                                 // commit 11
      .then(startPush("A", "ssh", "main", Some(11), false))       // base 8: confirms 3 -> 7
      .expect(devices.get("A").pins.get({ url: "", vault: 4 }).confirmed.get(3) == 7)
      .then(rewind(10))
      .then(deliver("A", true, Rejected))                         // keeps the read's pin
      .expect(devices.get("A").pins.get({ url: "", vault: 4 }).confirmed.get(3) == 7)
      .then(fetch("A", "ssh"))
      .expect(refusedWith(ghost.lastEvent, Twin) and inv_memoryNeverRebound)

  // §9.1: revoke is a compaction; the revoked device cannot read the result.
  run revokedCannotReadTest =
    initialized
      .then(startCompact("A", "ssh", Enroll("B")))                // generation 6
      .then(deliver("A", true, Acked))
      .then(fetch("B", "ssh"))
      .expect(acceptedGen(ghost.lastEvent, 6))
      .then(startCompact("A", "ssh", Revoke("B")))                // digest 7, generation 8
      .then(deliver("A", true, Acked))
      .then(fetch("B", "ssh"))
      .expect(refusedWith(ghost.lastEvent, CannotDecrypt))

  // §4.1 / §9 zero-ref compaction: all refs deleted, compacted to a manifest-only
  // generation with seqfloor kept; the next push is -full at a fresh number.
  run zeroRefCompactionReRootsTest =
    initialized
      .then(startPush("A", "ssh", "main", None, false))           // generation 5, no bundle
      .then(deliver("A", true, Acked))
      .then(startCompact("A", "ssh", Keep))                       // generation 6, no bundle
      .then(deliver("A", true, Acked))
      .expect(host.gens.get(6).bundles == Map() and host.gens.get(6).seqfloor == 1)
      .then(commit("A", None))                                    // commit 7, a new root
      .then(startPush("A", "ssh", "main", Some(7), false))        // digest 8, generation 9
      .then(deliver("A", true, Acked))
      .expect(host.gens.get(9).bundles == Map(2 -> { digest: 8, full: true }))
}

// The honest-host instance: concurrency between honest writers.
module honest_test {
  import protocol(
    DEVICES = Set("A", "B"), URLS = Set("ssh", "https"), REFS = Set("main", "dev"),
    MAX_COMMITS = 4, HONEST_HOST = true,
    INDET_AS_REJECT = false, COMPACT_BLIND_FORCE = false, PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false, PUSH_RECORDS_BASE = false
  ).* from "./protocol"
  import basicSpells.* from "./basicSpells"

  // §9.4: a compaction racing an acknowledged push loses the CAS and retries; the
  // push survives.
  run compactionLosesToConcurrentPushTest =
    init
      .then(commit("A", None))                                    // commit 1
      .then(startPush("A", "ssh", "main", Some(1), false))        // generation 3, vault 4
      .then(deliver("A", true, Acked))
      .then(startCompact("A", "ssh", Enroll("B")))                // generation 6
      .then(deliver("A", true, Acked))
      .then(fetch("B", "ssh"))
      .then(commit("B", Some(1)))                                 // commit 7
      .then(startPush("B", "ssh", "main", Some(7), false))        // generation 9, T = 6
      .then(startCompact("A", "ssh", Keep))                       // generation 11, T = 6
      .then(deliver("B", true, Acked))
      .then(deliver("A", true, Rejected))
      .expect(host.tip == 9 and ghost.acked.contains(9) and inv_ackedDurable)
}

// The same race with compaction by plain force-push: the acknowledged push is erased.
module blindForce_test {
  import protocol(
    DEVICES = Set("A", "B"), URLS = Set("ssh", "https"), REFS = Set("main", "dev"),
    MAX_COMMITS = 4, HONEST_HOST = true,
    INDET_AS_REJECT = false, COMPACT_BLIND_FORCE = true, PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false, PUSH_RECORDS_BASE = false
  ).* from "./protocol"
  import basicSpells.* from "./basicSpells"

  run blindForceErasesAckedPushTest =
    init
      .then(commit("A", None))
      .then(startPush("A", "ssh", "main", Some(1), false))
      .then(deliver("A", true, Acked))
      .then(startCompact("A", "ssh", Enroll("B")))
      .then(deliver("A", true, Acked))
      .then(fetch("B", "ssh"))
      .then(commit("B", Some(1)))
      .then(startPush("B", "ssh", "main", Some(7), false))        // generation 9
      .then(startCompact("A", "ssh", Keep))                       // generation 11
      .then(deliver("B", true, Acked))
      .then(deliver("A", true, Acked))                            // lands over B's push
      .expect(host.tip == 11 and not(inv_ackedDurable))
}

// The crash-lag scenario with a lost status report read as a rejection.
module indetAsReject_test {
  import protocol(
    DEVICES = Set("A", "B"), URLS = Set("ssh", "https"), REFS = Set("main", "dev"),
    MAX_COMMITS = 4, HONEST_HOST = false,
    INDET_AS_REJECT = true, COMPACT_BLIND_FORCE = false, PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false, PUSH_RECORDS_BASE = false
  ).* from "./protocol"
  import basicSpells.* from "./basicSpells"

  run lostAckReboundsTheNumberTest =
    init
      .then(commit("A", None))
      .then(startPush("A", "ssh", "main", Some(1), false))
      .then(deliver("A", true, Acked))
      .then(commit("A", Some(1)))
      .then(startPush("A", "ssh", "main", Some(5), false))        // seq 2 -> digest 6
      .then(deliver("A", true, Indeterminate))                    // landed; A withdraws
      .then(rewind(3))
      .then(startPush("A", "ssh", "dev", Some(5), false))         // seq 2 -> digest 8
      .expect(ghost.allocs.exists(a => a.seq == 2 and a.digest == 8) and not(inv_noNumberRebound))
}

// §7.4 / 7h with pins keyed by URL: the replay through the staler URL is accepted.
module pinPerUrl_test {
  import protocol(
    DEVICES = Set("A", "B"), URLS = Set("ssh", "https"), REFS = Set("main", "dev"),
    MAX_COMMITS = 4, HONEST_HOST = false,
    INDET_AS_REJECT = false, COMPACT_BLIND_FORCE = false, PIN_PER_URL = true,
    SET_CHANGE_BY_PUSH = false, PUSH_RECORDS_BASE = false
  ).* from "./protocol"
  import basicSpells.* from "./basicSpells"

  run staleAliasAcceptsRollbackTest =
    init
      .then(commit("A", None))
      .then(startPush("A", "ssh", "main", Some(1), false))
      .then(deliver("A", true, Acked))
      .then(fetch("A", "https"))
      .then(commit("A", Some(1)))
      .then(startPush("A", "ssh", "main", Some(5), false))
      .then(deliver("A", true, Acked))
      .then(rewind(3))
      .then(fetch("A", "https"))
      .expect(not(inv_noRollbackAccepted))
}
