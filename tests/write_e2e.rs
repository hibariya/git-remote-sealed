//! End-to-end tests for the write side: REAL `git push sealed::<path>`
//! driving the built `git-remote-sealed` binary writes the vault, and the
//! same binary (via `git clone`/`git fetch`) reads it back — Rust writes,
//! Rust reads. The vault's manifest is decrypted and inspected directly for
//! the §7/§8/§9 bookkeeping claims (counter, seqfloor, bundle list, chunk
//! counts, -full labeling, refs, HEAD). Where git would make a check itself
//! before the helper sees it (§8.2 non-fast-forward), or where a race needs
//! interleaving (two writers), the helper protocol is driven by hand.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use age::x25519::Identity;
use common::*;
use sealed::manifest::{Manifest, ObjectFormat};
use sealed::{crypt, pinstore};

/// One vault remote plus the identity every source/clone in the test uses.
struct Lab {
    scratch: PathBuf,
    identity: Identity,
    id_file: PathBuf,
    remote: VaultRemote,
}

impl Lab {
    fn new(tag: &str) -> Lab {
        Lab::with_remote_format(tag, "sha1")
    }

    fn with_remote_format(tag: &str, format: &str) -> Lab {
        let scratch = scratch(tag);
        let identity = Identity::generate();
        let id_file = identity_file(&scratch, &identity);
        let remote = VaultRemote::init_with_format(scratch.join("vault.git"), format);
        Lab {
            scratch,
            identity,
            id_file,
            remote,
        }
    }

    /// A fresh sha1 source repository with `origin` = the vault.
    fn source(&self, name: &str) -> SourceRepo {
        let src = SourceRepo::init(self.scratch.join(name), "sha1");
        src.add_remote("origin", &self.remote.sealed_url());
        src
    }

    fn push(&self, repo: &Path, args: &[&str]) -> Output {
        let mut full = vec!["push", "-q", "origin"];
        full.extend_from_slice(args);
        sealed_git(repo, &full, &self.id_file, &[])
    }

    fn push_ok(&self, repo: &Path, args: &[&str]) {
        let out = self.push(repo, args);
        assert_ok(&out, &format!("git push origin {}", args.join(" ")));
    }

    fn clone(&self, name: &str) -> (PathBuf, Output) {
        let dest = self.scratch.join(name);
        let output = sealed_git(
            &self.scratch,
            &["clone", "-q", &self.remote.sealed_url(), name],
            &self.id_file,
            &[],
        );
        (dest, output)
    }

    fn clone_ok(&self, name: &str) -> PathBuf {
        let (dest, out) = self.clone(name);
        assert_ok(&out, "git clone sealed::");
        dest
    }

    fn fetch(&self, repo: &Path) -> Output {
        sealed_git(repo, &["fetch", "-q", "origin"], &self.id_file, &[])
    }

    fn manifest(&self) -> Manifest {
        self.remote.manifest("main", &self.identity)
    }

    fn files(&self) -> Vec<String> {
        self.remote.files("main")
    }

    fn helper(&self, repo: &Path) -> HelperProc {
        HelperProc::spawn(repo, &self.id_file, &self.remote.sealed_url())
    }
}

fn rev(repo: &Path, r: &str) -> String {
    git(repo, &["rev-parse", "--verify", r]).trim().to_owned()
}

fn show(repo: &Path, rev: &str, path: &str) -> String {
    git(repo, &["show", &format!("{rev}:{path}")])
}

fn seqs(m: &Manifest) -> Vec<(u64, bool, Option<u64>)> {
    m.bundles
        .values()
        .map(|b| (b.seq, b.full, b.chunks))
        .collect()
}

#[test]
fn init_push_then_clone_round_trips() {
    // (a) Rust writes a vault into an empty remote; Rust reads it back.
    let lab = Lab::new("w-init");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "hello\n", "first");
    let c2 = src.commit_file("note.md", "hello world\n", "second");
    let tag = src.annotated_tag("v1");
    lab.push_ok(&src.dir, &["main", "v1"]);

    // §3/§7.2/§4.1: generation 1, sequence 1, -full, fresh vault id, HEAD
    // from the source repository, refs exactly as pushed (tag = tag object).
    let m = lab.manifest();
    assert_eq!(m.counter, 1);
    assert_eq!(m.seqfloor, 1);
    assert_eq!(seqs(&m), vec![(1, true, None)]);
    assert_eq!(m.object_format, ObjectFormat::Sha1);
    assert_eq!(m.vault_id.len(), 64);
    assert_eq!(m.head.as_deref(), Some("refs/heads/main"));
    assert_eq!(m.refs["refs/heads/main"], c2);
    assert_eq!(m.refs["refs/tags/v1"], tag);
    assert_eq!(
        lab.files(),
        vec!["1-full.bundle.age", "sealed-format", "sealed-manifest.age"]
    );
    assert_eq!(lab.remote.file_bytes("main", "sealed-format"), b"2\n");

    // §8 hygiene: fixed identity, epoch timestamp, no signature.
    let ident = git(
        &lab.remote.dir,
        &[
            "log",
            "-1",
            "--format=%an|%ae|%at|%cn|%ce|%ct|%G?",
            "refs/heads/main",
        ],
    );
    assert_eq!(
        ident.trim(),
        "sealed|sealed@invalid|0|sealed|sealed@invalid|0|N"
    );

    let dest = lab.clone_ok("clone");
    assert_eq!(
        git(&dest, &["symbolic-ref", "HEAD"]).trim(),
        "refs/heads/main"
    );
    assert_eq!(rev(&dest, "refs/heads/main"), c2);
    assert_eq!(rev(&dest, "refs/tags/v1"), tag);
    assert_eq!(show(&dest, "HEAD", "note.md"), "hello world\n");
    assert_eq!(show(&dest, "HEAD~1", "note.md"), "hello\n");
    assert_eq!(rev(&dest, "HEAD~1"), c1);
    git(&dest, &["fsck", "--strict"]);

    // The writer's pin records generation 1 and its own binding.
    let pin = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");
    assert_eq!(pin.counter, 1);
    assert_eq!(pin.seqfloor, 1);
    assert_eq!(pin.sequence_memory[&1], m.bundles[&1].digest);
}

#[test]
fn init_into_an_empty_sha256_vault_repository() {
    // §3: the vault repository is host-default; an EMPTY sha256 remote
    // advertises nothing to learn that from, so the writer finds the mirror
    // format by trial (documented choice in writer.rs).
    let lab = Lab::with_remote_format("w-init256", "sha256");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "hello\n", "first");
    lab.push_ok(&src.dir, &["main"]);

    let mirror = state_dir(&src.dir).join("mirror.git");
    assert_eq!(
        git(&mirror, &["rev-parse", "--show-object-format"]).trim(),
        "sha256"
    );
    assert_eq!(lab.remote.tip("main").len(), 64);
    let m = lab.manifest();
    assert_eq!(m.object_format, ObjectFormat::Sha1, "the SOURCE is sha1");
    assert_eq!(m.refs["refs/heads/main"], c1);

    let dest = lab.clone_ok("clone");
    assert_eq!(rev(&dest, "refs/heads/main"), c1);
}

#[test]
fn incremental_push_is_sequence_2_not_full() {
    // (b)
    let lab = Lab::new("w-incr");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let dest = lab.clone_ok("clone");

    let c2 = src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);

    let m = lab.manifest();
    assert_eq!(m.counter, 2);
    assert_eq!(m.seqfloor, 2);
    assert_eq!(seqs(&m), vec![(1, true, None), (2, false, None)]);
    assert_eq!(m.refs["refs/heads/main"], c2);
    assert_eq!(
        lab.files(),
        vec![
            "1-full.bundle.age",
            "2.bundle.age",
            "sealed-format",
            "sealed-manifest.age"
        ]
    );
    // The vault branch grew by one commit (no history rewrite on push).
    assert_eq!(lab.remote.commit_count("main"), 2);

    // An existing clone fetches only the increment; a fresh clone sees all.
    assert_ok(&lab.fetch(&dest), "incremental fetch");
    assert_eq!(rev(&dest, "refs/remotes/origin/main"), c2);
    let fresh = lab.clone_ok("fresh");
    assert_eq!(show(&fresh, "HEAD", "note.md"), "two\n");
    assert_eq!(show(&fresh, "HEAD~1", "note.md"), "one\n");
}

#[test]
fn manifest_only_pushes_allocate_nothing() {
    // (c) deletions and ref moves within existing history: counter
    // advances, seqfloor and the bundle list do not, no file changes.
    let lab = Lab::new("w-manifest-only");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    git(&src.dir, &["branch", "side"]);
    let c2 = src.commit_file("note.md", "two\n", "second");
    src.annotated_tag("v1");
    lab.push_ok(&src.dir, &["main", "side", "v1"]);
    let before = lab.manifest();
    assert_eq!((before.counter, before.seqfloor), (1, 1));
    let files_before = lab.files();

    // Delete a tag.
    lab.push_ok(&src.dir, &[":refs/tags/v1"]);
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (2, 1));
    assert_eq!(seqs(&m), seqs(&before));
    assert!(!m.refs.contains_key("refs/tags/v1"));
    assert_eq!(lab.files(), files_before);

    // Delete a branch.
    lab.push_ok(&src.dir, &[":refs/heads/side"]);
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (3, 1));
    assert!(!m.refs.contains_key("refs/heads/side"));
    assert_eq!(lab.files(), files_before);

    // Force-move main back to an older commit already in the vault.
    let spec = format!("+{c1}:refs/heads/main");
    lab.push_ok(&src.dir, &[&spec]);
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (4, 1));
    assert_eq!(m.refs["refs/heads/main"], c1);
    assert_eq!(seqs(&m), seqs(&before));
    assert_eq!(lab.files(), files_before);

    // §6.6: a reader reports exactly the manifest — main at c1, no tag,
    // no side branch — although the bundle still claims c2.
    let dest = lab.clone_ok("clone");
    assert_eq!(rev(&dest, "refs/heads/main"), c1);
    assert!(git_try(&dest, &["rev-parse", "--verify", "refs/tags/v1"]).is_none());
    assert!(git_try(
        &dest,
        &["rev-parse", "--verify", "refs/remotes/origin/side"]
    )
    .is_none());
    assert_ne!(c1, c2);
}

#[test]
fn annotated_tag_only_push_ships_the_tag_object() {
    // (d) §8.3 caveat: zero new commits, but the tag object must travel.
    let lab = Lab::new("w-tag-only");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);

    let tag = src.annotated_tag("v2");
    lab.push_ok(&src.dir, &["v2"]);
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (2, 2));
    assert_eq!(seqs(&m), vec![(1, true, None), (2, false, None)]);
    assert_eq!(m.refs["refs/tags/v2"], tag);
    assert!(lab.files().contains(&"2.bundle.age".to_string()));

    let dest = lab.clone_ok("clone");
    assert_eq!(rev(&dest, "refs/tags/v2"), tag);
    assert_eq!(git(&dest, &["cat-file", "-t", &tag]).trim(), "tag");
    assert_eq!(rev(&dest, "refs/tags/v2^{commit}"), c1);
}

#[test]
fn non_fast_forward_refused_and_force_accepted() {
    // (e) Through git: git's own client-side check rejects a non-ff push
    // before the helper sees it; --force goes through. Through the helper
    // protocol by hand: §8.2's "fetch first" and non-ff refusals are the
    // writer's own.
    let lab = Lab::new("w-nonff");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    let c2 = src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    let other = lab.clone_ok("other");

    // Rewrite history in src: c2 -> c2'.
    git(&src.dir, &["reset", "-q", "--hard", "HEAD~1"]);
    let c2b = src.commit_file("note.md", "two, rewritten\n", "second'");
    assert_ne!(c2, c2b);
    let out = lab.push(&src.dir, &["main"]);
    assert!(
        !out.status.success(),
        "git must refuse a non-fast-forward push"
    );
    assert_eq!(lab.manifest().refs["refs/heads/main"], c2);
    lab.push_ok(&src.dir, &["--force", "main"]);
    let m = lab.manifest();
    assert_eq!(m.refs["refs/heads/main"], c2b);
    assert_eq!(m.counter, 2);

    // `other` still has main at c2 (it never fetched c2') and commits on it.
    fs::write(other.join("note.md"), "three\n").expect("write");
    git(&other, &["add", "note.md"]);
    git(&other, &["commit", "-q", "-m", "third"]);
    let c3 = rev(&other, "HEAD");

    // §8.2: old (c2') is absent locally -> refuse, tell the user to fetch.
    let mut h = lab.helper(&other);
    h.send("capabilities\n");
    h.read_block();
    h.send("list for-push\n");
    let listing = h.read_block();
    assert!(listing
        .iter()
        .any(|l| l == &format!("{c2b} refs/heads/main")));
    h.send("push refs/heads/main:refs/heads/main\n\n");
    let status = h.read_block();
    assert_eq!(status.len(), 1);
    assert!(
        status[0].starts_with("error refs/heads/main fetch first:"),
        "{status:?}"
    );
    let (ok, _) = h.finish();
    assert!(ok);
    assert_eq!(lab.manifest().counter, 2, "nothing written");

    // After fetching, old is present but not an ancestor -> non-ff refusal.
    assert_ok(&lab.fetch(&other), "fetch");
    let mut h = lab.helper(&other);
    h.send("capabilities\nlist for-push\n");
    h.read_block();
    h.read_block();
    h.send("push refs/heads/main:refs/heads/main\n\n");
    let status = h.read_block();
    assert!(
        status[0].starts_with("error refs/heads/main non-fast-forward:"),
        "{status:?}"
    );
    h.finish();
    assert_eq!(lab.manifest().counter, 2, "nothing written");

    // Forced: applied unconditionally.
    let mut h = lab.helper(&other);
    h.send("capabilities\nlist for-push\n");
    h.read_block();
    h.read_block();
    h.send("push +refs/heads/main:refs/heads/main\n\n");
    let status = h.read_block();
    assert_eq!(status, vec!["ok refs/heads/main".to_string()]);
    let (ok, stderr) = h.finish();
    assert!(ok, "{stderr}");
    let m = lab.manifest();
    assert_eq!(m.refs["refs/heads/main"], c3);
    assert_eq!((m.counter, m.seqfloor), (3, 3));
}

#[test]
fn concurrent_writers_loser_retries_with_a_fresh_sequence_number() {
    // (f) Two clones push different branches. B's helper reads the vault
    // (`list for-push`), then A's push lands, then B pushes: B's first
    // attempt is rejected by the vault branch update, B re-reads, and
    // succeeds at seqfloor + 1 of the NEW generation.
    let lab = Lab::new("w-race");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let a = lab.clone_ok("a");
    let b = lab.clone_ok("b");
    for (repo, name) in [(&a, "a"), (&b, "b")] {
        git(repo, &["checkout", "-q", "-b", name]);
        fs::write(repo.join(format!("{name}.md")), name).expect("write");
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", name]);
    }
    let ca = rev(&a, "refs/heads/a");
    let cb = rev(&b, "refs/heads/b");

    let mut h = lab.helper(&b);
    h.send("capabilities\nlist for-push\n");
    h.read_block();
    let listing = h.read_block();
    assert!(listing
        .iter()
        .any(|l| l == &format!("{c1} refs/heads/main")));

    // A wins the race while B holds a stale read.
    lab.push_ok(&a, &["a"]);
    assert_eq!(lab.manifest().counter, 2);

    h.send("push refs/heads/b:refs/heads/b\n\n");
    let status = h.read_block();
    assert_eq!(status, vec!["ok refs/heads/b".to_string()]);
    let (ok, stderr) = h.finish();
    assert!(ok, "{stderr}");

    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (3, 3));
    assert_eq!(
        seqs(&m),
        vec![(1, true, None), (2, false, None), (3, false, None)]
    );
    assert_eq!(m.refs["refs/heads/a"], ca);
    assert_eq!(m.refs["refs/heads/b"], cb);
    assert_eq!(m.refs["refs/heads/main"], c1);

    // B's memory: 1 (applied at clone), 3 (its own). Never 2 — the rejected
    // attempt's binding was withdrawn before the retry.
    let pin = pinstore::load(&pin_dir(&b))
        .expect("readable")
        .expect("pinned");
    let keys: Vec<u64> = pin.sequence_memory.keys().copied().collect();
    assert_eq!(keys, vec![1, 3]);
    assert_eq!(pin.counter, 3);

    let third = lab.clone_ok("third");
    assert_eq!(rev(&third, "refs/remotes/origin/a"), ca);
    assert_eq!(rev(&third, "refs/remotes/origin/b"), cb);
    git(&third, &["fsck", "--strict"]);
}

#[test]
fn compaction_produces_one_full_bundle_and_drops_old_files() {
    // (g)
    let lab = Lab::new("w-compact");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let old_clone = lab.clone_ok("old");
    let c2 = src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    git(&src.dir, &["checkout", "-q", "-b", "dev"]);
    src.commit_file("dev.md", "dev\n", "dev");
    lab.push_ok(&src.dir, &["dev"]);
    git(&src.dir, &["checkout", "-q", "main"]);
    let tag = src.annotated_tag("v1");
    lab.push_ok(&src.dir, &["v1"]);
    lab.push_ok(&src.dir, &[":refs/heads/dev"]);
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (5, 4));
    assert_eq!(m.bundles.len(), 4);

    let out = cli(&src.dir, &lab.id_file, &["compact", "origin"]);
    assert_ok(&out, "git-remote-sealed compact");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("sequence 5"), "{text}");

    // §9: one -full bundle at seqfloor + 1, same refs, counter + 1, a
    // single parentless commit, old files gone.
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (6, 5));
    assert_eq!(seqs(&m), vec![(5, true, None)]);
    assert_eq!(m.refs.len(), 2);
    assert_eq!(m.refs["refs/heads/main"], c2);
    assert_eq!(m.refs["refs/tags/v1"], tag);
    assert_eq!(m.head.as_deref(), Some("refs/heads/main"));
    assert_eq!(
        lab.files(),
        vec!["5-full.bundle.age", "sealed-format", "sealed-manifest.age"]
    );
    assert_eq!(lab.remote.commit_count("main"), 1);

    // A clone from before the compaction fetches across the history
    // rewrite (§6.1 reset, §7.4 monotonicity), and a third clone reads
    // everything from the single bundle.
    assert_ok(&lab.fetch(&old_clone), "fetch after compaction");
    assert_eq!(rev(&old_clone, "refs/remotes/origin/main"), c2);
    let third = lab.clone_ok("third");
    assert_eq!(rev(&third, "refs/heads/main"), c2);
    assert_eq!(rev(&third, "refs/tags/v1"), tag);
    assert!(git_try(
        &third,
        &["rev-parse", "--verify", "refs/remotes/origin/dev"]
    )
    .is_none());
    assert_eq!(show(&third, "HEAD~1", "note.md"), "one\n");
    git(&third, &["fsck", "--strict"]);
}

#[test]
fn zero_ref_compaction_then_the_next_push_is_full() {
    // (h)
    let lab = Lab::new("w-zero");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    lab.push_ok(&src.dir, &[":refs/heads/main"]);
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (2, 1));
    assert!(m.refs.is_empty());
    assert_eq!(m.bundles.len(), 1);

    let out = cli(&src.dir, &lab.id_file, &["compact"]);
    assert_ok(&out, "zero-ref compaction");
    assert!(String::from_utf8_lossy(&out.stdout).contains("zero refs"));

    // §9: manifest-only generation — no bundle, no allocation, seqfloor
    // UNCHANGED, counter + 1.
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (3, 1));
    assert!(m.bundles.is_empty());
    assert!(m.refs.is_empty());
    assert_eq!(m.head, None);
    assert_eq!(lab.files(), vec!["sealed-format", "sealed-manifest.age"]);
    assert_eq!(lab.remote.commit_count("main"), 1);

    // A reader sees no refs; not an error (manifest-only is valid).
    let empty = lab.clone_ok("empty");
    assert!(git_try(&empty, &["rev-parse", "--verify", "HEAD"]).is_none());

    // §4.1: the next push into an empty bundle list is -full, at a fresh
    // sequence number (numbering never restarts).
    lab.push_ok(&src.dir, &["main"]);
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (4, 2));
    assert_eq!(seqs(&m), vec![(2, true, None)]);
    assert_eq!(m.refs["refs/heads/main"], c1);
    assert_eq!(m.head.as_deref(), Some("refs/heads/main"));
    let dest = lab.clone_ok("clone");
    assert_eq!(rev(&dest, "refs/heads/main"), c1);
    assert_ok(&lab.fetch(&empty), "the empty clone catches up");
    assert_eq!(rev(&empty, "refs/remotes/origin/main"), c1);
}

#[test]
fn an_interrupted_push_skips_its_pending_number_and_then_confirms_it() {
    // H1. A push whose outcome was never reported — a dropped connection, a
    // killed process, a credential that expired mid-upload — leaves the
    // §8.4 binding PENDING. The retry must do neither of the two things that
    // used to happen: re-bind the number to different ciphertext (the reuse
    // the guard exists to stop), or refuse it forever (which wedged every
    // later push AND compaction, with `forget` the only escape). It takes
    // the next number instead, and the published `seqfloor` burns the
    // pending one for every writer.
    let lab = Lab::new("w-pending-skip");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    assert_eq!((lab.manifest().counter, lab.manifest().seqfloor), (1, 1));

    // The interrupted attempt: sequence 2 was written down before the push,
    // and the push never landed.
    let mut pin = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");
    pin.pending.insert(2, "0".repeat(64));
    pinstore::save(&pin_dir(&src.dir), &pin).expect("save");

    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);

    let m = lab.manifest();
    assert_eq!(
        (m.counter, m.seqfloor),
        (2, 3),
        "sequence 2 is skipped, never rebound"
    );
    assert_eq!(seqs(&m), vec![(1, true, None), (3, false, None)]);

    // §8.4: publishing seqfloor 3 BURNED sequence 2 — no honest continuation
    // of this line can ever bind it — so the guess becomes an observation and
    // moves to the confirmed memory. The blind window is only between the
    // failed push and this one.
    let pin = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");
    assert!(pin.sequence_memory.contains_key(&3), "our own bundle");
    assert_eq!(
        pin.sequence_memory.get(&2),
        Some(&"0".repeat(64)),
        "the burned number is confirmed, not forgotten"
    );
    assert!(pin.pending.is_empty(), "pending: {:?}", pin.pending);

    // And a full §7.4 rebinding check applies to it again: the allocation
    // guard now refuses 2 outright rather than skipping it.
    assert!(matches!(
        pinstore::allocate_from(&pin.sequence_memory, &pin.pending, 2),
        Err(pinstore::PinError::AllocationCollision { seq: 2 })
    ));

    src.commit_file("note.md", "three\n", "third");
    lab.push_ok(&src.dir, &["main"]);
    assert_eq!(lab.manifest().seqfloor, 4);

    let dest = lab.clone_ok("check");
    assert_eq!(
        fs::read_to_string(dest.join("note.md")).expect("note"),
        "three\n"
    );
}

#[test]
fn a_lost_acknowledgement_is_settled_by_the_next_read() {
    // H2. `[remote failure] (remote failed to report status)` means the
    // update MAY have landed, so the binding stays pending. Here it did
    // land: the next read finds the number bound to our OWN ciphertext and
    // confirms it. (Reading that summary as a rejection is what withdrew the
    // binding and re-bound the number to fresh ciphertext — the exact
    // crash-lagged-writer attack §8.4 exists to stop.)
    let lab = Lab::new("w-pending-promote");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    let digest2 = lab.manifest().bundles[&2].digest.clone();

    // Rewind the pin to the moment the acknowledgement was lost: generation
    // 1 pinned, sequence 2 bound but only PENDING.
    let mut pin = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");
    pin.counter = 1;
    pin.seqfloor = 1;
    pin.sequence_memory.remove(&2);
    pin.pending.insert(2, digest2.clone());
    pinstore::save(&pin_dir(&src.dir), &pin).expect("save");

    src.commit_file("note.md", "three\n", "third");
    lab.push_ok(&src.dir, &["main"]);

    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (3, 3));
    let pin = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");
    assert_eq!(
        pin.sequence_memory.get(&2),
        Some(&digest2),
        "confirmed, not re-allocated"
    );
    assert!(pin.pending.is_empty());
}

#[test]
fn an_interrupted_compaction_skips_its_pending_number() {
    // H1 where it hurts most: a compaction is one big upload, and the
    // v1 -> v2 migration IS a compaction. §4.1 forbids re-publishing the
    // leftover bundle here (the lowest listed sequence must carry `-full`),
    // so compaction skips the number like every other allocation.
    let lab = Lab::new("w-pending-compact");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);

    let mut pin = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");
    pin.pending.insert(3, "0".repeat(64));
    pinstore::save(&pin_dir(&src.dir), &pin).expect("save");

    let out = cli(&src.dir, &lab.id_file, &["compact", "origin"]);
    assert_ok(&out, "git-remote-sealed compact");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("sequence 4"), "{text}");
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (3, 4));
    assert_eq!(seqs(&m), vec![(4, true, None)]);

    let dest = lab.clone_ok("after");
    assert_eq!(
        fs::read_to_string(dest.join("note.md")).expect("note"),
        "two\n"
    );
}

#[test]
fn allocation_guard_refuses_a_replayed_base() {
    // (i) The host rolls the vault back to the pre-push commit. With the
    // pin advanced, the counter check refuses; in the crash window the
    // formal model calls T9 (binding persisted, push acknowledged, pin not
    // yet advanced — reachable here, since the writer persists the binding
    // before the push), the §8.4 allocation guard is what refuses. Either
    // way the sequence number is never reused.
    let lab = Lab::new("w-guard");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let gen1 = lab.remote.tip("main");
    let pre = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");

    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    let gen2 = lab.remote.tip("main");
    let post = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");
    assert_eq!(post.counter, 2);
    assert!(post.sequence_memory.contains_key(&2));

    // Case 1: pin fully advanced — the rollback itself is refused.
    lab.remote.set_branch("main", &gen1);
    src.commit_file("note.md", "three\n", "third");
    let out = lab.push(&src.dir, &["main"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("vault rolled back: manifest counter 1 is below the last accepted counter 2"),
        "stderr: {err}"
    );
    assert_eq!(lab.remote.tip("main"), gen1, "nothing was pushed");

    // Case 2: the T9 window — memory has sequence 2, the pin still says
    // generation 1. The battery passes; the guard must catch it.
    let mut lagged = pre.clone();
    lagged.sequence_memory = post.sequence_memory.clone();
    pinstore::save(&pin_dir(&src.dir), &lagged).expect("save");
    let out = lab.push(&src.dir, &["main"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("refusing to allocate sequence number 2"),
        "stderr: {err}"
    );
    assert_eq!(lab.remote.tip("main"), gen1, "nothing was pushed");
    assert_eq!(lab.manifest().counter, 1);

    // The host serves the real tip again: the push goes through at 3.
    lab.remote.set_branch("main", &gen2);
    pinstore::save(&pin_dir(&src.dir), &post).expect("save");
    lab.push_ok(&src.dir, &["main"]);
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (3, 3));
}

#[test]
fn chunked_push_round_trips() {
    // (j) §4.2: sealed.chunk-mb=1 and a >2 MiB incompressible file.
    let lab = Lab::new("w-chunk");
    let src = lab.source("src");
    git(&src.dir, &["config", "sealed.chunk-mb", "1"]);
    let blob = noise(5 * 1024 * 1024 / 2, 0x5eed);
    fs::write(src.dir.join("big.bin"), &blob).expect("write");
    git(&src.dir, &["add", "big.bin"]);
    git(&src.dir, &["commit", "-q", "-m", "big"]);
    let c1 = rev(&src.dir, "HEAD");
    lab.push_ok(&src.dir, &["main"]);

    let m = lab.manifest();
    assert_eq!(m.bundles[&1].chunks, Some(3));
    assert_eq!(
        lab.files(),
        vec![
            "1-full.bundle.age.0",
            "1-full.bundle.age.1",
            "1-full.bundle.age.2",
            "sealed-format",
            "sealed-manifest.age"
        ]
    );
    // Parts are cut at the threshold: the first two are exactly 1 MiB.
    assert_eq!(
        lab.remote.file_bytes("main", "1-full.bundle.age.0").len(),
        1024 * 1024
    );

    let dest = lab.clone_ok("clone");
    assert_eq!(rev(&dest, "refs/heads/main"), c1);
    assert_eq!(fs::read(dest.join("big.bin")).expect("read"), blob);
    git(&dest, &["fsck", "--strict"]);
}

#[test]
fn extra_recipient_can_clone() {
    // (k) §5: files are encrypted to the recipient set = own + extras.
    let lab = Lab::new("w-recipients");
    let second = Identity::generate();
    let second_file = lab.scratch.join("second.txt");
    fs::write(
        &second_file,
        format!(
            "{}\n",
            age::secrecy::ExposeSecret::expose_secret(&second.to_string())
        ),
    )
    .expect("write");
    let stranger = Identity::generate();
    let stranger_file = lab.scratch.join("stranger.txt");
    fs::write(
        &stranger_file,
        format!(
            "{}\n",
            age::secrecy::ExposeSecret::expose_secret(&stranger.to_string())
        ),
    )
    .expect("write");

    let src = lab.source("src");
    git(
        &src.dir,
        &[
            "config",
            "sealed.recipients",
            &second.to_public().to_string(),
        ],
    );
    let c1 = src.commit_file("note.md", "shared\n", "first");
    lab.push_ok(&src.dir, &["main"]);

    let dest = lab.scratch.join("second-clone");
    let out = sealed_git(
        &lab.scratch,
        &["clone", "-q", &lab.remote.sealed_url(), "second-clone"],
        &second_file,
        &[],
    );
    assert_ok(&out, "clone with the second identity");
    assert_eq!(rev(&dest, "refs/heads/main"), c1);

    let out = sealed_git(
        &lab.scratch,
        &["clone", "-q", &lab.remote.sealed_url(), "stranger-clone"],
        &stranger_file,
        &[],
    );
    assert!(!out.status.success(), "a stranger cannot decrypt");
    assert!(stderr_of(&out).contains("age decryption failed"));
}

#[test]
fn info_prints_recipients_and_forget_needs_yes() {
    // (l)
    let lab = Lab::new("w-info-forget");
    let extra = Identity::generate().to_public().to_string();
    let src = lab.source("src");
    git(&src.dir, &["config", "sealed.recipients", &extra]);
    let own = lab.identity.to_public().to_string();

    let out = cli(&src.dir, &lab.id_file, &["info", "origin"]);
    assert_ok(&out, "info");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!("recipient:  {own} (this device)")),
        "{text}"
    );
    assert!(
        text.contains(&format!("extra:      {extra} (sealed.recipients)")),
        "{text}"
    );
    assert!(
        text.contains(&format!("join:       {own} {extra}")),
        "{text}"
    );
    assert!(text.contains(&lab.remote.sealed_url()), "{text}");
    // Without an argument, the single sealed:: remote is found.
    let out = cli(&src.dir, &lab.id_file, &["info"]);
    assert_ok(&out, "info without argument");

    // A clone pinned at generation 2 refuses a rollback to generation 1...
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let gen1 = lab.remote.tip("main");
    let dest = lab.clone_ok("clone");
    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    assert_ok(&lab.fetch(&dest), "fetch generation 2");
    lab.remote.set_branch("main", &gen1);
    let out = lab.fetch(&dest);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("vault rolled back"));

    // ...`forget` without --yes warns and refuses, leaving the pin...
    let out = cli(&dest, &lab.id_file, &["forget", "origin"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("forget refused"), "{err}");
    assert!(err.contains("ACCEPTS the attack"), "{err}");
    assert!(pin_dir(&dest).join("pin.json").is_file());

    // ...and with --yes the pin is gone and the rollback is ACCEPTED: this
    // is the forfeit §7.5 warns about (the formal model's
    // forgetForfeitsRollbackProtectionTest).
    let state = state_dir(&dest);
    let pin = pin_dir(&dest);
    let out = cli(&dest, &lab.id_file, &["forget", "--yes", "origin"]);
    assert_ok(&out, "forget --yes");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("forgot the pin, sequence memory, and mirror"),
        "{text}"
    );
    assert!(
        !pin.exists(),
        "the vault's pin is gone: no other URL used it"
    );
    assert!(
        !state.exists(),
        "mirror, scratch and vault binding are gone"
    );
    assert_ok(
        &lab.fetch(&dest),
        "the rolled-back vault is accepted after forget",
    );
    assert_eq!(rev(&dest, "refs/remotes/origin/main"), c1);
}

#[test]
fn shallow_source_is_refused() {
    // §8 preamble.
    let lab = Lab::new("w-shallow");
    let plain = SourceRepo::init(lab.scratch.join("plain"), "sha1");
    plain.commit_file("note.md", "one\n", "first");
    plain.commit_file("note.md", "two\n", "second");
    let shallow = lab.scratch.join("shallow");
    let url = format!("file://{}", plain.dir.display());
    git(
        &lab.scratch,
        &["clone", "-q", "--depth", "1", &url, "shallow"],
    );
    git(
        &shallow,
        &["remote", "add", "vault", &lab.remote.sealed_url()],
    );
    let out = sealed_git(
        &shallow,
        &["push", "-q", "vault", "main"],
        &lab.id_file,
        &[],
    );
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("shallow"), "{}", stderr_of(&out));
    assert!(git_try(
        &lab.remote.dir,
        &["rev-parse", "--verify", "refs/heads/main"]
    )
    .is_none());
}

#[test]
fn unknown_manifest_line_makes_the_writer_read_only() {
    // §7.3: a 2.x extension line — reads still work, writes are refused.
    let lab = Lab::new("w-readonly");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);

    // A newer tool's generation: the same refs and bundles, counter + 1,
    // plus a line of a type this version does not know.
    let mut files: Vec<(String, Vec<u8>)> = lab
        .files()
        .into_iter()
        .map(|n| (n.clone(), lab.remote.file_bytes("main", &n)))
        .collect();
    let mut newer = lab.manifest();
    newer.counter += 1;
    let plain = newer.to_text().expect("serializable") + "chunkweights 1 heavy\n";
    let cipher = crypt::encrypt(&[lab.identity.to_public()], plain.as_bytes()).expect("encrypt");
    for (name, bytes) in files.iter_mut() {
        if name == "sealed-manifest.age" {
            *bytes = cipher.clone();
        }
    }
    lab.remote.commit(&files, "main");

    let dest = lab.clone_ok("clone");
    assert_eq!(rev(&dest, "refs/heads/main"), c1);

    src.commit_file("note.md", "two\n", "second");
    let out = lab.push(&src.dir, &["main"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("refusing to write (read-only)"), "{err}");
    assert_eq!(lab.manifest().refs["refs/heads/main"], c1);
}

#[test]
fn pushes_through_two_aliases_share_one_pin() {
    // §7.4/§8.4 on the write side: a push through a second spelling of the
    // vault URL binds its sequence number in the SAME pin the first
    // spelling advanced, so the allocation guard and the rollback check
    // see both histories as one.
    let lab = Lab::new("w-alias");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let gen1 = lab.remote.tip("main");

    let alias = format!("{}/", lab.remote.sealed_url());
    src.add_remote("alias", &alias);
    src.commit_file("note.md", "two\n", "second");
    let out = sealed_git(
        &src.dir,
        &["push", "-q", "alias", "main"],
        &lab.id_file,
        &[],
    );
    assert_ok(&out, "push through the alias");
    let m = lab.manifest();
    assert_eq!((m.counter, m.seqfloor), (2, 2));

    // One pin, bound through both spellings, holding both writes.
    let pin = pinstore::load(&pin_dir(&src.dir))
        .expect("readable")
        .expect("pinned");
    assert_eq!(pin.counter, 2);
    assert_eq!(
        pin.sequence_memory.keys().copied().collect::<Vec<_>>(),
        vec![1, 2]
    );
    let urls = fs::read_dir(sealed_root(&src.dir).join("urls"))
        .expect("urls")
        .count();
    assert_eq!(urls, 2);

    // The host replays generation 1 to origin, whose memory a per-URL pin
    // would have left at counter 1: the push is refused as a rollback.
    lab.remote.set_branch("main", &gen1);
    src.commit_file("note.md", "three\n", "third");
    let out = lab.push(&src.dir, &["main"]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out)
            .contains("vault rolled back: manifest counter 1 is below the last accepted counter 2"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(lab.remote.tip("main"), gen1, "nothing was pushed");
}
