// Negative controls: each module reverts ONE rule and must violate the named
// invariant (see README.md for the recorded runs).

// §8.5: a lost status report read as a rejection -> expect `inv_noNumberRebound` to fail.
module ctl_indetAsReject {
  import protocol(
    DEVICES = Set("A", "B"),
    URLS = Set("ssh", "https"),
    REFS = Set("main", "dev"),
    MAX_COMMITS = 4,
    HONEST_HOST = false,
    INDET_AS_REJECT = true,
    COMPACT_BLIND_FORCE = false,
    PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false,
    PUSH_RECORDS_BASE = false
  ).* from "./protocol"
}

// §9.4: compaction by plain force-push, no CAS against T -> expect `inv_ackedDurable` to fail.
module ctl_blindForce {
  import protocol(
    DEVICES = Set("A", "B"),
    URLS = Set("ssh", "https"),
    REFS = Set("main", "dev"),
    MAX_COMMITS = 4,
    HONEST_HOST = true,
    INDET_AS_REJECT = false,
    COMPACT_BLIND_FORCE = true,
    PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false,
    PUSH_RECORDS_BASE = false
  ).* from "./protocol"
}

// §7.4 / 7h: pins keyed by URL -> expect `inv_noRollbackAccepted` to fail.
module ctl_pinPerUrl {
  import protocol(
    DEVICES = Set("A", "B"),
    URLS = Set("ssh", "https"),
    REFS = Set("main", "dev"),
    MAX_COMMITS = 4,
    HONEST_HOST = false,
    INDET_AS_REJECT = false,
    COMPACT_BLIND_FORCE = false,
    PIN_PER_URL = true,
    SET_CHANGE_BY_PUSH = false,
    PUSH_RECORDS_BASE = false
  ).* from "./protocol"
}

// §9.1: enroll/revoke by a plain push -> expect `inv_oneSetPerGeneration` to fail.
module ctl_setByPush {
  import protocol(
    DEVICES = Set("A", "B"),
    URLS = Set("ssh", "https"),
    REFS = Set("main", "dev"),
    MAX_COMMITS = 4,
    HONEST_HOST = true,
    INDET_AS_REJECT = false,
    COMPACT_BLIND_FORCE = false,
    PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = true,
    PUSH_RECORDS_BASE = false
  ).* from "./protocol"
}

// §7.4 / 7e: a push records the base's bindings without applying them -> expect `inv_confirmedMeansApplied` to fail.
module ctl_pushRecordsBase {
  import protocol(
    DEVICES = Set("A", "B"),
    URLS = Set("ssh", "https"),
    REFS = Set("main", "dev"),
    MAX_COMMITS = 4,
    HONEST_HOST = true,
    INDET_AS_REJECT = false,
    COMPACT_BLIND_FORCE = false,
    PIN_PER_URL = false,
    SET_CHANGE_BY_PUSH = false,
    PUSH_RECORDS_BASE = true
  ).* from "./protocol"
}
