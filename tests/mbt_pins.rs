//! Model-based test of the pin layer (`src/pinstore.rs`) against the Quint
//! model `spec/protocol.qnt`, with quint-connect.
//!
//! quint-connect runs `quint run` on the model, then replays every trace
//! here step by step. Each step's ghost `call` (a `PinCall` in the model)
//! says what that step asked of the pin layer — the generation it was
//! served, the number it allocated, the verdict its push got — and what the
//! model decided. The driver asks the REAL code the same question: a real
//! `PinStore` in a scratch directory per device, `validate_and_advance`,
//! `WritePins`. It fails on the first step where the code decides otherwise
//! (a refusal with a different reason, a different number), and after every
//! step it compares each device's URL bindings and pins with the model's.
//!
//! Everything outside the pin layer (git, bundles, the host) comes from the
//! model as input, so this checks exactly the §7.4/§8.4 decisions — the
//! code where the rejected-push bug of 0.3.1 lived.
//!
//! It needs `quint` on PATH, so it is `#[ignore]`d: a run that silently
//! skips would look green while checking nothing. Run it with
//!
//! ```text
//! cargo test --locked --test mbt_pins -- --ignored
//! ```
//!
//! `QUINT_SEED=<n>` reproduces a failing run; `QUINT_VERBOSE=1` prints the
//! steps.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, bail, ensure};
use quint_connect::*;
use sealed::manifest::{BundleRecord, Manifest, ObjectFormat};
use sealed::pinstore::{self, Pin, PinError, PinStore, WritePins};
use serde::Deserialize;

// --- the model's values, as the trace carries them ---

/// The parts of a model `Gen` the pin layer reads (serde skips the rest).
#[derive(Deserialize, Debug, Clone)]
struct Gen {
    vault: u64,
    counter: u64,
    seqfloor: u64,
    bundles: BTreeMap<u64, BundleLine>,
}

#[derive(Deserialize, Debug, Clone)]
struct BundleLine {
    digest: u64,
    full: bool,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
enum Reason {
    EmptyWithPin,
    CannotDecrypt,
    VaultMismatch,
    Rollback,
    Twin,
    SeqfloorRegression,
    SequenceRebound,
    AllocationCollision,
    FetchFirst,
    NonFastForward,
    MissingObject,
    CorruptBundle,
    CannotDecryptBundle,
    NothingToDo,
    EmptyVault,
    EmptySet,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "tag", content = "value")]
enum ReadResult {
    ReadOk,
    ReadErr(Reason),
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(tag = "tag", content = "value")]
enum Verdict {
    Acked,
    Rejected,
    Indeterminate,
}

/// A model `Pin`, and what the driver turns a real `Pin` into.
#[derive(Deserialize, Debug, PartialEq, Eq)]
struct ModelPin {
    vault: u64,
    counter: u64,
    digest: u64,
    seqfloor: u64,
    confirmed: BTreeMap<u64, u64>,
    pending: BTreeMap<u64, u64>,
}

/// The model keys pins by `{ url, vault }`; `url` is "" for the one pin per
/// vault the code keeps.
#[derive(Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PinKey {
    url: String,
    vault: u64,
}

/// What is compared after every step: each device's bindings and pins.
#[derive(Deserialize, Debug, PartialEq, Eq)]
struct DevicePins {
    bindings: BTreeMap<String, u64>,
    pins: BTreeMap<PinKey, ModelPin>,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(transparent)]
struct Devices(BTreeMap<String, DevicePins>);

// --- ids: the model's small integers, the code's hex strings ---

fn digest_hex(n: u64) -> String {
    format!("{n:064x}")
}

fn vault_hex(n: u64) -> String {
    format!("{n:032x}")
}

fn from_hex(s: &str) -> anyhow::Result<u64> {
    u64::from_str_radix(s, 16).map_err(|e| anyhow!("not a model id: {s:?}: {e}"))
}

fn manifest(g: &Gen) -> Manifest {
    Manifest {
        format: 2,
        object_format: ObjectFormat::Sha1,
        vault_id: vault_hex(g.vault),
        counter: g.counter,
        seqfloor: g.seqfloor,
        recipients: Default::default(),
        bundles: g
            .bundles
            .iter()
            .map(|(seq, line)| {
                let record = BundleRecord {
                    seq: *seq,
                    full: line.full,
                    digest: digest_hex(line.digest),
                    chunks: None,
                };
                (*seq, record)
            })
            .collect(),
        head: None,
        refs: BTreeMap::new(),
    }
}

fn model_pin(pin: &Pin) -> anyhow::Result<ModelPin> {
    let ids = |m: &BTreeMap<u64, String>| -> anyhow::Result<BTreeMap<u64, u64>> {
        m.iter().map(|(seq, d)| Ok((*seq, from_hex(d)?))).collect()
    };
    Ok(ModelPin {
        vault: from_hex(&pin.vault_id)?,
        counter: pin.counter,
        digest: from_hex(&pin.manifest_digest)?,
        seqfloor: pin.seqfloor,
        confirmed: ids(&pin.sequence_memory)?,
        pending: ids(&pin.pending)?,
    })
}

/// The model's name for a refusal the code reports.
fn reason(e: &PinError) -> anyhow::Result<Reason> {
    Ok(match e {
        PinError::VaultMismatch { .. } => Reason::VaultMismatch,
        PinError::Rollback { .. } => Reason::Rollback,
        PinError::Twin { .. } => Reason::Twin,
        PinError::SeqfloorRegression { .. } => Reason::SeqfloorRegression,
        PinError::SequenceRebound { .. } => Reason::SequenceRebound,
        PinError::EmptyVaultWithPin => Reason::EmptyWithPin,
        PinError::AllocationCollision { .. } => Reason::AllocationCollision,
        other => bail!("the pin layer failed outside the model: {other}"),
    })
}

// --- the driver ---

/// Which instance of the model is run: its variables are named after it.
trait Instance {
    const DEVICES: &'static [&'static str];
    const URLS: &'static [&'static str];
    const STATE: Path;
    const CALL: Path;
}

/// A write between its first step and its verdict.
enum InFlight {
    Init {
        url: String,
        written: Manifest,
        manifest_digest: String,
        bundle_digest: String,
    },
    Write {
        url: String,
        pins: WritePins,
        written: Manifest,
        manifest_digest: String,
    },
}

struct PinDriver<I> {
    root: PathBuf,
    stores: BTreeMap<String, PinStore>,
    /// Every vault id seen, to enumerate the pins a store holds.
    vaults: BTreeSet<u64>,
    in_flight: BTreeMap<String, InFlight>,
    instance: PhantomData<I>,
}

static RUNS: AtomicUsize = AtomicUsize::new(0);

impl<I: Instance> PinDriver<I> {
    fn new() -> Self {
        PinDriver {
            root: PathBuf::new(),
            stores: BTreeMap::new(),
            vaults: BTreeSet::new(),
            in_flight: BTreeMap::new(),
            instance: PhantomData,
        }
    }

    /// Every trace starts here: fresh, empty pin stores.
    fn begin(&mut self) -> Result {
        if !self.root.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.root);
        }
        let run = RUNS.fetch_add(1, Ordering::Relaxed);
        self.root = std::env::temp_dir().join(format!("sealed-mbt-{}-{run}", std::process::id()));
        fs::create_dir_all(&self.root)?;
        self.stores = I::DEVICES
            .iter()
            .map(|d| (d.to_string(), PinStore::new(&self.root.join(d))))
            .collect();
        self.vaults.clear();
        self.in_flight.clear();
        Ok(())
    }

    fn store(&self, dev: &str) -> anyhow::Result<&PinStore> {
        self.stores
            .get(dev)
            .ok_or_else(|| anyhow!("unknown device {dev}"))
    }

    /// §7.4: the battery a read through `url` runs, as the reader runs it.
    /// The outer error is a failure outside the model; the inner one is a
    /// refusal the model can name.
    fn battery(
        &self,
        dev: &str,
        url: &str,
        id: u64,
        g: &Gen,
    ) -> anyhow::Result<std::result::Result<Passed, Reason>> {
        let store = self.store(dev)?;
        let m = manifest(g);
        let read = store.pin_for_read(url, &m.vault_id).and_then(|prev| {
            pinstore::validate_and_advance(prev.as_ref(), &m, &digest_hex(id))
                .map(|next| (prev, next))
        });
        Ok(match read {
            Ok((prev, next)) => Ok(Passed { prev, next, m }),
            Err(e) => Err(reason(&e)?),
        })
    }

    fn noop(&mut self) {}

    fn read_empty(&mut self, dev: String, url: String) -> Result {
        let got = self.store(&dev)?.check_empty_at(&url);
        match got {
            Err(PinError::EmptyVaultWithPin) => Ok(()),
            other => {
                bail!("{dev} via {url}: the model refused an empty vault, the code said {other:?}")
            }
        }
    }

    fn read(
        &mut self,
        dev: String,
        url: String,
        served_id: u64,
        served: Gen,
        result: ReadResult,
        applied: bool,
    ) -> Result {
        self.vaults.insert(served.vault);
        match (self.battery(&dev, &url, served_id, &served)?, result) {
            (Ok(Passed { next, .. }), ReadResult::ReadOk) => {
                if applied {
                    self.store(&dev)?.save(&url, &next)?;
                }
                Ok(())
            }
            (Err(got), ReadResult::ReadErr(want)) => {
                ensure!(
                    got == want,
                    "{dev} reading {served_id}: model {want:?}, code {got:?}"
                );
                Ok(())
            }
            (got, want) => bail!("{dev} reading {served_id}: model {want:?}, code {got:?}"),
        }
    }

    fn init_start(
        &mut self,
        dev: String,
        url: String,
        digest: u64,
        written_id: u64,
        written: Gen,
    ) -> Result {
        self.store(&dev)?.check_empty_at(&url)?;
        self.vaults.insert(written.vault);
        self.in_flight.insert(
            dev,
            InFlight::Init {
                url,
                written: manifest(&written),
                manifest_digest: digest_hex(written_id),
                bundle_digest: digest_hex(digest),
            },
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_start(
        &mut self,
        dev: String,
        url: String,
        compaction: bool,
        served_id: u64,
        served: Gen,
        alloc: i64,
        digest: u64,
        written_id: u64,
        written: Gen,
    ) -> Result {
        self.vaults.insert(served.vault);
        let Passed { prev, next, m } = match self.battery(&dev, &url, served_id, &served)? {
            Ok(passed) => passed,
            Err(r) => bail!(
                "{dev} writing on {served_id}: the model's read passed, the code refused {r:?}"
            ),
        };
        let store = self.store(&dev)?;
        let mut pins = if compaction {
            // compact.rs applies its read, which persists the read's pin.
            store.save(&url, &next)?;
            WritePins::for_compaction(&next)
        } else {
            WritePins::for_push(prev.as_ref(), &next, &m)
        };
        if alloc != 0 {
            let got = pins.allocate(served.seqfloor + 1);
            if alloc < 0 {
                ensure!(
                    matches!(got, Err(PinError::AllocationCollision { .. })),
                    "{dev} writing on {served_id}: the model refused the allocation, the code said {got:?}"
                );
                return Ok(());
            }
            let seq = got?;
            ensure!(
                seq as i64 == alloc,
                "{dev} writing on {served_id}: the model allocated {alloc}, the code {seq}"
            );
            pins.bind(seq, &digest_hex(digest));
        }
        if let Some(pin) = pins.before_push() {
            store.save(&url, &pin)?;
        }
        self.in_flight.insert(
            dev,
            InFlight::Write {
                url,
                pins,
                written: manifest(&written),
                manifest_digest: digest_hex(written_id),
            },
        );
        Ok(())
    }

    fn deliver(&mut self, dev: String, verdict: Verdict) -> Result {
        let flight = self
            .in_flight
            .remove(&dev)
            .ok_or_else(|| anyhow!("{dev}: a verdict with no write in flight"))?;
        let store = self.store(&dev)?;
        match (flight, verdict) {
            (
                InFlight::Init {
                    url,
                    written,
                    manifest_digest,
                    bundle_digest,
                },
                Verdict::Acked,
            ) => store.save(
                &url,
                &pinstore::initialized_pin(&written, &manifest_digest, &bundle_digest),
            )?,
            (InFlight::Init { .. }, _) => {}
            (
                InFlight::Write {
                    url,
                    pins,
                    written,
                    manifest_digest,
                },
                Verdict::Acked,
            ) => store.save(&url, &pins.on_ack(&written, &manifest_digest))?,
            (InFlight::Write { url, pins, .. }, Verdict::Rejected) => {
                if let Some(pin) = pins.on_reject() {
                    store.save(&url, &pin)?;
                }
            }
            (InFlight::Write { .. }, Verdict::Indeterminate) => {}
        }
        Ok(())
    }

    fn forget(&mut self, dev: String, url: String) -> Result {
        self.store(&dev)?.forget_url(&url)?;
        Ok(())
    }
}

/// A read that passed the battery: the pin it ran against, the pin it
/// produced, and the manifest read.
#[derive(Debug)]
struct Passed {
    prev: Option<Pin>,
    next: Pin,
    m: Manifest,
}

impl<I: Instance> Driver for PinDriver<I> {
    type State = Devices;

    fn config() -> Config {
        Config {
            state: I::STATE,
            nondet: I::CALL,
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            Begin => self.begin()?,
            Noop => self.noop(),
            ReadEmpty(dev, url) => self.read_empty(dev, url)?,
            Read(dev, url, served_id, served, result, applied) =>
                self.read(dev, url, served_id, served, result, applied)?,
            InitStart(dev, url, digest, written_id, written) =>
                self.init_start(dev, url, digest, written_id, written)?,
            WriteStart(dev, url, compaction, served_id, served, alloc, digest, written_id, written) =>
                self.write_start(dev, url, compaction, served_id, served, alloc, digest, written_id, written)?,
            Deliver(dev, verdict) => self.deliver(dev, verdict)?,
            Forget(dev, url) => self.forget(dev, url)?,
        })
    }
}

impl<I: Instance> State<PinDriver<I>> for Devices {
    fn from_driver(driver: &PinDriver<I>) -> Result<Self> {
        let mut devices = BTreeMap::new();
        for (dev, store) in &driver.stores {
            let mut bindings = BTreeMap::new();
            for url in I::URLS {
                if let Some(vault) = store.association(url)? {
                    bindings.insert(url.to_string(), from_hex(&vault)?);
                }
            }
            let mut pins = BTreeMap::new();
            for vault in &driver.vaults {
                if let Some(pin) = store.load_vault(&vault_hex(*vault))? {
                    let key = PinKey {
                        url: String::new(),
                        vault: *vault,
                    };
                    pins.insert(key, model_pin(&pin)?);
                }
            }
            devices.insert(dev.clone(), DevicePins { bindings, pins });
        }
        Ok(Devices(devices))
    }
}

// --- the instances ---

struct Malicious;

impl Instance for Malicious {
    const DEVICES: &'static [&'static str] = &["A", "B"];
    const URLS: &'static [&'static str] = &["ssh", "https"];
    const STATE: Path = &["protocol_malicious::protocol::devices"];
    const CALL: Path = &["protocol_malicious::protocol::ghost", "call"];
}

struct Honest;

impl Instance for Honest {
    const DEVICES: &'static [&'static str] = &["A", "B"];
    const URLS: &'static [&'static str] = &["ssh", "https"];
    const STATE: Path = &["protocol_honest::protocol::devices"];
    const CALL: Path = &["protocol_honest::protocol::ghost", "call"];
}

struct Attacks;

impl Instance for Attacks {
    const DEVICES: &'static [&'static str] = &["A", "B"];
    const URLS: &'static [&'static str] = &["ssh", "https"];
    const STATE: Path = &["attacks_test::protocol::devices"];
    const CALL: Path = &["attacks_test::protocol::ghost", "call"];
}

struct HonestScenario;

impl Instance for HonestScenario {
    const DEVICES: &'static [&'static str] = &["A", "B"];
    const URLS: &'static [&'static str] = &["ssh", "https"];
    const STATE: Path = &["honest_test::protocol::devices"];
    const CALL: Path = &["honest_test::protocol::ghost", "call"];
}

/// One scripted scenario of `spec/protocol_test.qnt`, replayed step by step.
/// Random traces rarely build the forks behind some refusals (seqfloor,
/// sequence rebinding); these reach them every time.
macro_rules! scenario {
    ($name:ident, $instance:ty, $main:literal, $test:literal) => {
        #[quint_test(spec = "spec/protocol_test.qnt", main = $main, test = $test, max_samples = 1)]
        #[ignore = "needs quint on PATH; run with --ignored"]
        fn $name() -> impl Driver {
            PinDriver::<$instance>::new()
        }
    };
}

scenario!(
    crash_lag_skips_pending,
    Attacks,
    "attacks_test",
    "crashLagSkipsPendingTest"
);
scenario!(
    forget_forfeits_rollback_protection,
    Attacks,
    "attacks_test",
    "forgetForfeitsRollbackProtectionTest"
);
scenario!(
    alias_shares_the_pin,
    Attacks,
    "attacks_test",
    "aliasSharesThePinTest"
);
scenario!(twin_refused, Attacks, "attacks_test", "twinRefusedTest");
scenario!(
    fork_rebound_refused,
    Attacks,
    "attacks_test",
    "forkReboundRefusedTest"
);
scenario!(
    fork_seqfloor_refused,
    Attacks,
    "attacks_test",
    "forkSeqfloorRefusedTest"
);
scenario!(
    fork_without_rebound_is_accepted,
    Attacks,
    "attacks_test",
    "forkWithoutReboundIsAcceptedTest"
);
scenario!(
    rejected_push_keeps_its_confirmation,
    Attacks,
    "attacks_test",
    "rejectedPushKeepsItsConfirmationTest"
);
scenario!(
    revoked_cannot_read,
    Attacks,
    "attacks_test",
    "revokedCannotReadTest"
);
scenario!(
    zero_ref_compaction_re_roots,
    Attacks,
    "attacks_test",
    "zeroRefCompactionReRootsTest"
);
scenario!(
    compaction_loses_to_concurrent_push,
    HonestScenario,
    "honest_test",
    "compactionLosesToConcurrentPushTest"
);

/// The hostile host: replays, forks, empties, rejects — where the pin rules
/// do their work.
#[quint_run(
    spec = "spec/protocol.qnt",
    main = "protocol_malicious",
    max_samples = 300,
    max_steps = 30
)]
#[ignore = "needs quint on PATH; run with --ignored"]
fn pins_follow_the_model_under_a_malicious_host() -> impl Driver {
    PinDriver::<Malicious>::new()
}

#[quint_run(
    spec = "spec/protocol.qnt",
    main = "protocol_honest",
    max_samples = 100,
    max_steps = 30
)]
#[ignore = "needs quint on PATH; run with --ignored"]
fn pins_follow_the_model_under_an_honest_host() -> impl Driver {
    PinDriver::<Honest>::new()
}
