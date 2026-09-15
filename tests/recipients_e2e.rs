//! Claim-backed end-to-end tests for the recipient set declared in the
//! manifest (§5, §7.2 `recipient`, §8 "Recipient set", §9.1, §9.2): Rust
//! writes the vaults through REAL `git push` and the `enroll` / `revoke` /
//! `upgrade` subcommands, and the checks run through real `git clone` /
//! `git fetch` driving the built binary, hand-planted vault commits, and a
//! committed vault written by the released 0.2.1 code
//! (`tests/fixtures/pre-recipient-vault/`).

mod common;

use std::path::Path;

use age::x25519::Identity;
use common::*;
use sealed::manifest::{BundleRecord, Manifest, ObjectFormat};

fn rev(repo: &Path, r: &str) -> String {
    git(repo, &["rev-parse", "--verify", r]).trim().to_owned()
}

fn hand_manifest(
    vault_id: &str,
    bundle: BundleRecord,
    main: &str,
    recipients: &[String],
) -> Manifest {
    Manifest {
        format: 2,
        object_format: ObjectFormat::Sha1,
        vault_id: vault_id.to_owned(),
        counter: 1,
        seqfloor: 1,
        recipients: recipients.iter().cloned().collect(),
        bundles: [(bundle.seq, bundle)].into_iter().collect(),
        head: Some("refs/heads/main".into()),
        refs: [("refs/heads/main".to_owned(), main.to_owned())]
            .into_iter()
            .collect(),
    }
}

// ===================== §5 declared vs. actual =====================

#[test]
fn manifest_encrypted_to_more_keys_than_it_declares_is_refused_on_read() {
    // §5: "more [stanzas] means an undeclared key can [read] — either way a
    // buggy or misconfigured writer"; readers MUST treat it as INVALID and
    // say it is not an attack. Three keys, two declared.
    let scratch = scratch("r-declared");
    let ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let id_file = identity_file(&scratch, &ids[0]);
    let remote = VaultRemote::init(scratch.join("vault.git"));
    let src = SourceRepo::init(scratch.join("src"), "sha1");
    let c1 = src.commit_file("note.md", "one\n", "first");
    let bundle = src.bundle(&scratch.join("b1.bundle"), &["HEAD", "--all"]);

    let three: Vec<_> = ids.iter().map(Identity::to_public).collect();
    let declared: Vec<String> = three[..2].iter().map(ToString::to_string).collect();
    let mut files = Vec::new();
    add_hint(&mut files);
    let rec = add_bundle(&mut files, &three[0], 1, true, &bundle, None);
    let m = hand_manifest(&"ef".repeat(16), rec, &c1, &declared);
    add_manifest_to(&mut files, &three, &m);
    remote.commit(&files, "main");

    let out = sealed_git(
        &scratch,
        &["clone", "-q", &remote.sealed_url(), "clone"],
        &id_file,
        &[],
    );
    assert!(!out.status.success(), "the mismatch must be refused");
    let err = stderr_of(&out);
    assert!(
        err.contains("declares 2 recipient(s) but its ciphertext is encrypted to 3 X25519 key(s)"),
        "{err}"
    );
    assert!(err.contains("an undeclared key can read it"), "{err}");
    assert!(err.contains("not an attack"), "{err}");

    // The same generation declaring all three reads fine.
    let all: Vec<String> = three.iter().map(ToString::to_string).collect();
    let mut files = Vec::new();
    add_hint(&mut files);
    let rec = add_bundle(&mut files, &three[0], 1, true, &bundle, None);
    let m = hand_manifest(&"ef".repeat(16), rec, &c1, &all);
    add_manifest_to(&mut files, &three, &m);
    let fixed = VaultRemote::init(scratch.join("fixed.git"));
    fixed.commit(&files, "main");
    let out = sealed_git(
        &scratch,
        &["clone", "-q", &fixed.sealed_url(), "fixed"],
        &id_file,
        &[],
    );
    assert_ok(&out, "clone of the consistent generation");
    assert_eq!(rev(&scratch.join("fixed"), "refs/heads/main"), c1);
}

// ===================== §9.1 enroll / revoke =====================

fn stranger_file(lab: &Lab, name: &str) -> (Identity, std::path::PathBuf) {
    let id = Identity::generate();
    let file = identity_file_named(&lab.scratch, name, &id);
    (id, file)
}

fn seqs(m: &Manifest) -> Vec<(u64, bool)> {
    m.bundles.values().map(|b| (b.seq, b.full)).collect()
}

#[test]
fn enroll_makes_the_whole_history_readable_by_the_new_key_alone() {
    // README "Adding a device" / §9.1: adding a recipient
    // is a compaction encrypted to the new set, "so a device added this
    // way reads the whole history from its first fetch" — a fresh clone
    // holding ONLY the second identity gets every commit.
    let lab = Lab::new("r-enroll");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let c2 = src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    assert_eq!(seqs(&lab.manifest()), vec![(1, true), (2, false)]);

    let (second, second_file) = stranger_file(&lab, "second.txt");
    // Before enrolment the key opens nothing.
    let (_, out) = lab.clone_with(&second_file, "too-early");
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("age decryption failed"));

    let text = lab.enroll_ok(&src.dir, &second.to_public());
    assert!(
        text.contains(&format!("enrolled {}", second.to_public())),
        "{text}"
    );
    assert!(text.contains("encrypted to 2 recipient(s)"), "{text}");
    assert!(text.contains("one -full bundle at sequence 3"), "{text}");
    let m = lab.manifest();
    assert_eq!(seqs(&m), vec![(3, true)], "§9.1: a compaction");
    assert_eq!(m.counter, 3);
    assert_eq!(
        m.recipients,
        [&lab.identity, &second]
            .iter()
            .map(|i| i.to_public().to_string())
            .collect()
    );
    assert_eq!(lab.remote.commit_count("main"), 1, "parentless (§9.3)");

    let (dest, out) = lab.clone_with(&second_file, "second-clone");
    assert_ok(&out, "clone with only the enrolled identity");
    assert_eq!(rev(&dest, "refs/heads/main"), c2);
    assert_eq!(rev(&dest, "HEAD~1"), c1);
    git(&dest, &["fsck", "--strict"]);

    // The enrolled device can push; the original still reads it (§8: the
    // set travels in the manifest, nothing was configured anywhere).
    let c3 = SourceRepo { dir: dest.clone() }.commit_file("note.md", "three\n", "third");
    let out = sealed_git(&dest, &["push", "-q", "origin", "main"], &second_file, &[]);
    assert_ok(&out, "push from the enrolled device");
    assert_ok(&lab.fetch(&src.dir), "original device fetches");
    assert_eq!(rev(&src.dir, "refs/remotes/origin/main"), c3);
}

#[test]
fn enroll_is_idempotent() {
    // A key already in the set: say so, write nothing.
    let lab = Lab::new("r-enroll-twice");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let (second, _) = stranger_file(&lab, "second.txt");
    lab.enroll_ok(&src.dir, &second.to_public());
    let tip = lab.remote.tip("main");
    let text = lab.enroll_ok(&src.dir, &second.to_public());
    assert!(
        text.contains(&format!("{} is already a recipient", second.to_public())),
        "{text}"
    );
    assert!(text.contains("nothing to do"), "{text}");
    assert_eq!(lab.remote.tip("main"), tip, "no generation was written");
    assert_eq!(lab.manifest().counter, 2);

    // Not a recipient at all: refused before any vault work.
    let out = cli(
        &src.dir,
        &lab.id_file,
        &["enroll", "AGE-SECRET-KEY-1NOPE", "origin"],
    );
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("is not an age recipient"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(lab.remote.tip("main"), tip);
}

#[test]
fn revoke_locks_the_removed_key_out_of_the_new_snapshot() {
    // §9.1: removal is a compaction encrypted to set \ {key}; the revoked
    // identity cannot open the new generation (what it already fetched it
    // keeps — "removal is not erasure"). The result MUST be non-empty, and
    // removing this device's own key needs explicit confirmation.
    let lab = Lab::new("r-revoke");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let (second, second_file) = stranger_file(&lab, "second.txt");
    lab.enroll_ok(&src.dir, &second.to_public());
    let (dest, out) = lab.clone_with(&second_file, "second-clone");
    assert_ok(&out, "clone as the second device");

    // Revoking the last remaining key is refused (needs --yes for own key
    // first; even with it the empty result is refused).
    let own = lab.identity.to_public().to_string();
    let out = cli(&src.dir, &lab.id_file, &["revoke", &own, "origin"]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains(&format!("revoke --yes {own}")),
        "{}",
        stderr_of(&out)
    );

    let text = lab.cli_ok(
        &src.dir,
        &["revoke", &second.to_public().to_string(), "origin"],
    );
    assert!(text.contains("revoked"), "{text}");
    assert!(text.contains("encrypted to 1 recipient(s)"), "{text}");
    let m = lab.manifest();
    assert_eq!(seqs(&m), vec![(3, true)]);
    assert_eq!(m.recipients.iter().collect::<Vec<_>>(), vec![&own]);
    assert_eq!(
        sealed::crypt::recipient_count(&lab.remote.file_bytes("main", "3-full.bundle.age")),
        Some(1)
    );
    // The revoked device keeps what it fetched, cannot read the new snapshot.
    assert_eq!(rev(&dest, "refs/heads/main"), c1);
    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    let out = sealed_git(&dest, &["fetch", "-q", "origin"], &second_file, &[]);
    assert!(
        !out.status.success(),
        "the revoked key cannot open the vault"
    );
    assert!(
        stderr_of(&out).contains("age decryption failed"),
        "{}",
        stderr_of(&out)
    );

    // Revoke to empty: refused whatever the confirmation.
    let out = cli(&src.dir, &lab.id_file, &["revoke", "--yes", &own, "origin"]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("must keep at least one key"),
        "{}",
        stderr_of(&out)
    );
    // A key that is not in the set: nothing to do.
    let text = lab.cli_ok(
        &src.dir,
        &["revoke", &second.to_public().to_string(), "origin"],
    );
    assert!(text.contains("is not a recipient"), "{text}");
    assert_eq!(lab.manifest().counter, 4);

    // Own key, with another present: --yes required, then this device is out.
    lab.enroll_ok(&src.dir, &second.to_public());
    let out = cli(&src.dir, &lab.id_file, &["revoke", &own, "origin"]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("this device's own recipient"),
        "{}",
        stderr_of(&out)
    );
    let text = lab.cli_ok(&src.dir, &["revoke", "--yes", &own, "origin"]);
    assert!(text.contains("encrypted to 1 recipient(s)"), "{text}");
    assert!(
        !lab.fetch(&src.dir).status.success(),
        "this device lost read access"
    );
    let out = sealed_git(&dest, &["fetch", "-q", "origin"], &second_file, &[]);
    assert_ok(&out, "the remaining key reads the new snapshot");
}

// ===================== §5/§8: a pre-recipient vault =====================

/// The 0.2.1-written vault fixture, restored into a scratch directory with
/// its two identities.
struct Fixture021 {
    scratch: std::path::PathBuf,
    remote: VaultRemote,
    id_a: std::path::PathBuf,
    id_b: std::path::PathBuf,
    key_a: String,
    key_b: String,
    refs: Vec<(String, String)>,
}

impl Fixture021 {
    fn restore(tag: &str) -> Fixture021 {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pre-recipient-vault");
        let scratch = scratch(tag);
        let remote = VaultRemote::init(scratch.join("vault.git"));
        let bundle = src.join("vault.bundle");
        git(
            &remote.dir,
            &[
                "fetch",
                "-q",
                bundle.to_str().expect("utf-8"),
                "+refs/heads/main:refs/heads/main",
            ],
        );
        let id_a = scratch.join("identity-a.txt");
        let id_b = scratch.join("identity-b.txt");
        std::fs::copy(src.join("identity-a.txt"), &id_a).expect("copy");
        std::fs::copy(src.join("identity-b.txt"), &id_b).expect("copy");
        let key_of = |p: &Path| {
            std::fs::read_to_string(p)
                .expect("identity")
                .lines()
                .find_map(|l| l.strip_prefix("# public key: "))
                .expect("public key comment")
                .to_owned()
        };
        let refs = std::fs::read_to_string(src.join("expected-refs.txt"))
            .expect("refs")
            .lines()
            .filter_map(|l| l.split_once(' '))
            .map(|(s, n)| (n.to_owned(), s.to_owned()))
            .collect();
        Fixture021 {
            key_a: key_of(&id_a),
            key_b: key_of(&id_b),
            scratch,
            remote,
            id_a,
            id_b,
            refs,
        }
    }

    fn clone_as(&self, id: &Path, name: &str) -> std::process::Output {
        sealed_git(
            &self.scratch,
            &["clone", "-q", &self.remote.sealed_url(), name],
            id,
            &[],
        )
    }

    fn clone_ok(&self, id: &Path, name: &str) -> std::path::PathBuf {
        assert_ok(&self.clone_as(id, name), "clone of the 0.2.1 vault");
        let dest = self.scratch.join(name);
        for (name, sha) in &self.refs {
            let local = name.replace("refs/heads/", "refs/remotes/origin/");
            assert_eq!(rev(&dest, &local), *sha, "{name}");
        }
        dest
    }

    fn manifest(&self) -> Manifest {
        let identity = sealed::settings::parse_identity_file(
            &std::fs::read_to_string(&self.id_a).expect("identity"),
        )
        .expect("parses")
        .remove(0);
        self.remote.manifest("main", &identity)
    }
}

#[test]
fn a_zero_two_one_vault_reads_but_refuses_pushes_until_upgraded() {
    // §5/§8: "A writer MUST NOT push to such a vault; the only write
    // allowed against it is the upgrade of §9.2 ... Readers handle it as
    // any other manifest." The refusal shows the set this device would
    // record, both counts, and the command to run.
    let fx = Fixture021::restore("r-021-push");
    assert!(fx.manifest().is_pre_recipient());
    let dest = fx.clone_ok(&fx.id_a, "clone-a");
    fx.clone_ok(&fx.id_b, "clone-b");
    let tip = fx.remote.tip("main");

    let src = SourceRepo { dir: dest.clone() };
    src.commit_file("note.md", "three\n", "third");
    let out = sealed_git(&dest, &["push", "-q", "origin", "main"], &fx.id_a, &[]);
    assert!(!out.status.success(), "a push must be refused");
    let err = stderr_of(&out);
    assert!(
        err.contains("written before recipients were recorded"),
        "{err}"
    );
    assert!(err.contains("`git-remote-sealed upgrade`"), "{err}");
    assert!(err.contains("would record 1 recipient(s)"), "{err}");
    assert!(err.contains(&fx.key_a), "{err}");
    assert!(err.contains("encrypted to 2 X25519 key(s)"), "{err}");
    assert_eq!(fx.remote.tip("main"), tip, "nothing was written");

    // With the legacy list configured, the would-be set shows both keys.
    git(&dest, &["config", "sealed.recipients", &fx.key_b]);
    let out = sealed_git(&dest, &["push", "-q", "origin", "main"], &fx.id_a, &[]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("would record 2 recipient(s)"), "{err}");
    assert!(err.contains(&fx.key_b), "{err}");

    // §9.1's verbs are writes too: refused the same way. Only `upgrade` fits.
    for args in [
        vec!["enroll", &fx.key_b, "origin"],
        vec!["revoke", "--yes", &fx.key_b, "origin"],
        vec!["compact", "origin"],
    ] {
        let out = cli(&dest, &fx.id_a, &args);
        assert!(!out.status.success(), "{args:?}");
        assert!(
            stderr_of(&out).contains("`git-remote-sealed upgrade`"),
            "{args:?}: {}",
            stderr_of(&out)
        );
    }
    assert_eq!(fx.remote.tip("main"), tip);
    // `info` says what is (not) recorded.
    let out = cli(&dest, &fx.id_a, &["info", "origin"]);
    assert_ok(&out, "info");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(
            "recipients: not recorded in this vault yet (run `git-remote-sealed upgrade`)"
        ),
        "{text}"
    );
    // Reads keep working throughout.
    assert_ok(
        &sealed_git(&dest, &["fetch", "-q", "origin"], &fx.id_a, &[]),
        "fetch",
    );
}

#[test]
fn hand_built_pre_recipient_generation_is_refused_for_writes_only() {
    // The same rule against a manifest this test writes itself (no
    // `recipient` line at all), so the claim does not rest on the fixture.
    let scratch = scratch("r-pre-hand");
    let identity = Identity::generate();
    let id_file = identity_file(&scratch, &identity);
    let remote = VaultRemote::init(scratch.join("vault.git"));
    let src = SourceRepo::init(scratch.join("src"), "sha1");
    let c1 = src.commit_file("note.md", "one\n", "first");
    let bundle = src.bundle(&scratch.join("b1.bundle"), &["HEAD", "--all"]);
    let mut files = Vec::new();
    add_hint(&mut files);
    let rec = add_bundle(&mut files, &identity.to_public(), 1, true, &bundle, None);
    let m = hand_manifest(&"1f".repeat(16), rec, &c1, &[]);
    assert!(m.is_pre_recipient());
    add_manifest(&mut files, &identity.to_public(), &m);
    remote.commit(&files, "main");

    src.add_remote("origin", &remote.sealed_url());
    src.commit_file("note.md", "two\n", "second");
    let out = sealed_git(&src.dir, &["push", "-q", "origin", "main"], &id_file, &[]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("`git-remote-sealed upgrade`"), "{err}");
    assert!(err.contains("encrypted to 1 X25519 key(s)"), "{err}");
    let out = sealed_git(
        &scratch,
        &["clone", "-q", &remote.sealed_url(), "clone"],
        &id_file,
        &[],
    );
    assert_ok(&out, "clone");
    assert_eq!(rev(&scratch.join("clone"), "refs/heads/main"), c1);
}

// ===================== §9.2 upgrade =====================

#[test]
fn upgrade_records_a_matching_set_then_pushes_resume() {
    // §9.2: the recorded set = own identities' recipients + the legacy
    // `sealed.recipients`; its size MUST equal the manifest ciphertext's
    // X25519 stanza count (2 here); the upgrade is a compaction (a zero-ref
    // vault would become manifest-only); idempotent afterwards. The keys
    // are printed in full.
    let fx = Fixture021::restore("r-021-upgrade");
    let dest = fx.clone_ok(&fx.id_a, "clone-a");
    git(&dest, &["config", "sealed.recipients", &fx.key_b]);
    let out = cli(&dest, &fx.id_a, &["upgrade", "origin"]);
    assert_ok(&out, "upgrade");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("upgraded"), "{text}");
    assert!(text.contains("encrypted to 2 recipient(s)"), "{text}");
    assert!(
        text.contains(&format!("{} (this device)", fx.key_a)),
        "{text}"
    );
    assert!(text.contains(&fx.key_b), "{text}");
    assert!(text.contains("one -full bundle at sequence 3"), "{text}");

    let m = fx.manifest();
    let mut expected = vec![fx.key_a.clone(), fx.key_b.clone()];
    expected.sort();
    assert_eq!(m.recipients.iter().cloned().collect::<Vec<_>>(), expected);
    assert_eq!(seqs(&m), vec![(3, true)]);
    assert_eq!(m.counter, 3);
    assert_eq!(m.refs.len(), 2);
    for (name, sha) in &fx.refs {
        assert_eq!(m.refs[name], *sha);
    }
    assert_eq!(fx.remote.commit_count("main"), 1);

    // Idempotent.
    let out = cli(&dest, &fx.id_a, &["upgrade", "origin"]);
    assert_ok(&out, "second upgrade");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("already records 2 recipients; nothing to do"),
        "{text}"
    );
    assert_eq!(fx.manifest().counter, 3);

    // A later push works; the stale legacy list (all in the manifest) only
    // warns.
    let src = SourceRepo { dir: dest.clone() };
    let c3 = src.commit_file("note.md", "three\n", "third");
    let out = sealed_git(&dest, &["push", "-q", "origin", "main"], &fx.id_a, &[]);
    assert_ok(&out, "push after the upgrade");
    assert!(
        stderr_of(&out).contains("sealed.recipients is ignored since 0.3.0"),
        "{}",
        stderr_of(&out)
    );
    let m = fx.manifest();
    assert_eq!(m.refs["refs/heads/main"], c3);
    assert_eq!(seqs(&m), vec![(3, true), (4, false)]);
    assert_eq!(m.recipients.len(), 2, "carried unchanged (§8)");
    // ...and a device holding only the second key reads all of it.
    let out = fx.clone_as(&fx.id_b, "clone-b");
    assert_ok(&out, "clone as b after the upgrade");
    assert_eq!(rev(&fx.scratch.join("clone-b"), "refs/heads/main"), c3);
    let out = cli(&fx.scratch.join("clone-b"), &fx.id_b, &["info"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!("recipients: {} (this device)", fx.key_b)),
        "{text}"
    );
}

#[test]
fn upgrade_refuses_a_smaller_set_reporting_both_counts() {
    // §9.2: "A smaller set would lock out a current reader."
    let fx = Fixture021::restore("r-021-smaller");
    let dest = fx.clone_ok(&fx.id_a, "clone-a");
    let tip = fx.remote.tip("main");
    let out = cli(&dest, &fx.id_a, &["upgrade", "origin"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("would record 1 recipient(s)"), "{err}");
    assert!(err.contains(&fx.key_a), "{err}");
    assert!(err.contains("encrypted to 2 X25519 key(s)"), "{err}");
    assert!(err.contains("lock out a current reader"), "{err}");
    assert_eq!(fx.remote.tip("main"), tip);
    assert!(fx.manifest().is_pre_recipient());
}

#[test]
fn upgrade_refuses_a_larger_set_reporting_both_counts() {
    // §9.2: "a larger set is just as invalid — it is almost always a stale
    // configuration, and recording it would make the mistake the vault's
    // truth."
    let fx = Fixture021::restore("r-021-larger");
    let dest = fx.clone_ok(&fx.id_a, "clone-a");
    let stale = Identity::generate().to_public().to_string();
    git(&dest, &["config", "--add", "sealed.recipients", &fx.key_b]);
    git(&dest, &["config", "--add", "sealed.recipients", &stale]);
    let tip = fx.remote.tip("main");
    let out = cli(&dest, &fx.id_a, &["upgrade", "origin"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("would record 3 recipient(s)"), "{err}");
    assert!(err.contains(&stale), "{err}");
    assert!(err.contains("encrypted to 2 X25519 key(s)"), "{err}");
    assert!(err.contains("stale global entry"), "{err}");
    assert!(
        err.contains("git config --show-origin --get-all sealed.recipients"),
        "{err}"
    );
    assert_eq!(fx.remote.tip("main"), tip);
    assert!(fx.manifest().is_pre_recipient());
}

#[test]
fn zero_ref_pre_recipient_vault_upgrades_to_a_manifest_only_generation() {
    // §9.2: "(a zero-ref vault upgrades to a manifest-only generation)".
    let scratch = scratch("r-upgrade-zero");
    let identity = Identity::generate();
    let id_file = identity_file(&scratch, &identity);
    let remote = VaultRemote::init(scratch.join("vault.git"));
    let mut files = Vec::new();
    add_hint(&mut files);
    let m = Manifest {
        format: 2,
        object_format: ObjectFormat::Sha1,
        vault_id: "2e".repeat(16),
        counter: 5,
        seqfloor: 3,
        recipients: Default::default(),
        bundles: Default::default(),
        head: None,
        refs: Default::default(),
    };
    add_manifest(&mut files, &identity.to_public(), &m);
    remote.commit(&files, "main");
    let src = SourceRepo::init(scratch.join("src"), "sha1");
    src.add_remote("origin", &remote.sealed_url());

    let out = cli(&src.dir, &id_file, &["upgrade", "origin"]);
    assert_ok(&out, "upgrade of a zero-ref vault");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("manifest-only generation"), "{text}");
    let m = remote.manifest("main", &identity);
    assert_eq!(
        m.recipients.iter().collect::<Vec<_>>(),
        vec![&identity.to_public().to_string()]
    );
    assert!(m.bundles.is_empty() && m.refs.is_empty());
    assert_eq!((m.counter, m.seqfloor), (6, 3), "seqfloor UNCHANGED");
    assert_eq!(
        remote.files("main"),
        vec!["sealed-format", "sealed-manifest.age"]
    );

    // The next push re-roots it (§4.1) and carries the set.
    let c1 = src.commit_file("note.md", "one\n", "first");
    let out = sealed_git(&src.dir, &["push", "-q", "origin", "main"], &id_file, &[]);
    assert_ok(&out, "push after the upgrade");
    let m = remote.manifest("main", &identity);
    assert_eq!(seqs(&m), vec![(4, true)]);
    assert_eq!(m.refs["refs/heads/main"], c1);
    assert_eq!(m.recipients.len(), 1);
}

// ===================== the legacy config after 0.3.0 =====================

#[test]
fn stale_sealed_recipients_warns_when_covered_and_refuses_when_not() {
    // `sealed.recipients` is no input any more. A list the manifest covers
    // earns a warning and the write proceeds; a key the manifest lacks is
    // refused with the way forward (enroll it, or remove it from config).
    let lab = Lab::new("r-stale");
    let src = lab.source("src");
    let (second, _) = stranger_file(&lab, "second.txt");
    let (third, _) = stranger_file(&lab, "third.txt");

    // Even the initializing push: a configured key that would NOT be in
    // the declared (own-only) set is refused rather than silently dropped.
    src.commit_file("note.md", "one\n", "first");
    git(
        &src.dir,
        &[
            "config",
            "sealed.recipients",
            &second.to_public().to_string(),
        ],
    );
    let out = lab.push(&src.dir, &["main"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("is not a recipient of this vault"), "{err}");
    assert!(
        err.contains(&format!(
            "run `git-remote-sealed enroll {}`",
            second.to_public()
        )),
        "{err}"
    );
    assert!(err.contains("remove it from config"), "{err}");
    git(&src.dir, &["config", "--unset", "sealed.recipients"]);
    lab.push_ok(&src.dir, &["main"]);
    lab.enroll_ok(&src.dir, &second.to_public());

    // All configured keys are in the manifest: warn, proceed.
    git(
        &src.dir,
        &[
            "config",
            "sealed.recipients",
            &second.to_public().to_string(),
        ],
    );
    let c2 = src.commit_file("note.md", "two\n", "second");
    let out = lab.push(&src.dir, &["main"]);
    assert_ok(&out, "push with a covered legacy list");
    let err = stderr_of(&out);
    assert!(
        err.contains("warning: sealed.recipients is ignored since 0.3.0"),
        "{err}"
    );
    assert!(err.contains("enroll"), "{err}");
    assert!(err.contains("remove it from config"), "{err}");
    assert_eq!(lab.manifest().refs["refs/heads/main"], c2);
    assert_eq!(
        lab.manifest().recipients.len(),
        2,
        "the config added nothing"
    );

    // A key the manifest lacks: refused, nothing written — for pushes and
    // for compaction alike.
    git(
        &src.dir,
        &[
            "config",
            "--add",
            "sealed.recipients",
            &third.to_public().to_string(),
        ],
    );
    let tip = lab.remote.tip("main");
    src.commit_file("note.md", "three\n", "third");
    let out = lab.push(&src.dir, &["main"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains(&format!(
            "names {}, which is not a recipient of this vault",
            third.to_public()
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "run `git-remote-sealed enroll {}`",
            third.to_public()
        )),
        "{err}"
    );
    let out = cli(&src.dir, &lab.id_file, &["compact", "origin"]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("not a recipient of this vault"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(lab.remote.tip("main"), tip);

    // `enroll` is the way: afterwards the list is covered again.
    lab.enroll_ok(&src.dir, &third.to_public());
    let out = lab.push(&src.dir, &["main"]);
    assert_ok(&out, "push once the key is enrolled");
    assert!(stderr_of(&out).contains("warning: sealed.recipients is ignored"));
    assert_eq!(lab.manifest().recipients.len(), 3);
}
