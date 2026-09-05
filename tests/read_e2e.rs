//! End-to-end tests for the read side: vault git repositories built by hand
//! from the library modules plus real `git bundle` output, then read back
//! by REAL `git clone sealed::<path>` / `git fetch` driving the built
//! `git-remote-sealed` binary (PATH + SEALED_IDENTITY), with negatives for
//! the §6 checks that only a real vault exercises.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Output;

use age::x25519::Identity;
use common::*;
use sealed::manifest::{self, BundleRecord, Manifest, ObjectFormat};
use sealed::vaultrepo::{self, VaultRepo};
use sealed::{reader, sha256_hex};

type Files = Vec<(String, Vec<u8>)>;

/// A source repository with two commits and one annotated tag, bundled as
/// `1-full` (commit 1) and `2` (commit 2 + tag, prerequisite commit 1), plus
/// the vault file sets for a one-bundle and a two-bundle generation.
struct Fixture {
    scratch: PathBuf,
    identity: Identity,
    id_file: PathBuf,
    remote: VaultRemote,
    of: ObjectFormat,
    vault_id: String,
    c1: String,
    c2: String,
    tag: String,
    b1: BundleRecord,
    b2: BundleRecord,
    /// `sealed-format` + bundle 1.
    gen1: Files,
    /// `sealed-format` + bundles 1 and 2.
    gen2: Files,
}

fn fixture(tag: &str, of: ObjectFormat, full_parts: Option<usize>, big: bool) -> Fixture {
    let scratch = scratch(tag);
    let identity = Identity::generate();
    let recipient = identity.to_public();
    let id_file = identity_file(&scratch, &identity);

    let src = SourceRepo::init(scratch.join("src"), of.as_str());
    let first = if big {
        // Enough ciphertext for many chunks with distinct content.
        (0u64..2000)
            .map(|i| format!("line {i}: {}\n", sha256_hex(&i.to_le_bytes())))
            .collect::<String>()
    } else {
        "hello\n".to_owned()
    };
    let c1 = src.commit_file("note.md", &first, "first");
    let b1 = src.bundle(&scratch.join("b1.bundle"), &["HEAD", "--all"]);
    let c2 = src.commit_file("note.md", "hello world\n", "second");
    git(&src.dir, &["tag", "-a", "v1", "-m", "v1"]);
    let tag_sha = src.rev("refs/tags/v1");
    let exclude = format!("^{c1}");
    let b2 = src.bundle(&scratch.join("b2.bundle"), &["HEAD", "--all", &exclude]);
    // §4.3: payload version follows the object format, strictly.
    manifest::verify_bundle_header(&b1, of).expect("git bundle matches the object format");
    manifest::verify_bundle_header(&b2, of).expect("git bundle matches the object format");

    let mut gen1: Files = Vec::new();
    add_hint(&mut gen1);
    let rec1 = add_bundle(&mut gen1, &recipient, 1, true, &b1, full_parts);
    let mut gen2 = gen1.clone();
    let rec2 = add_bundle(&mut gen2, &recipient, 2, false, &b2, None);

    Fixture {
        remote: VaultRemote::init(scratch.join("vault.git")),
        vault_id: sha256_hex(recipient.to_string().as_bytes()),
        scratch,
        identity,
        id_file,
        of,
        c1,
        c2,
        tag: tag_sha,
        b1: rec1,
        b2: rec2,
        gen1,
        gen2,
    }
}

impl Fixture {
    fn manifest(
        &self,
        counter: u64,
        seqfloor: u64,
        bundles: &[&BundleRecord],
        refs: &[(&str, &str)],
    ) -> Manifest {
        Manifest {
            format: 2,
            object_format: self.of,
            vault_id: self.vault_id.clone(),
            counter,
            seqfloor,
            bundles: bundles.iter().map(|r| (r.seq, (*r).clone())).collect(),
            head: Some("refs/heads/main".into()),
            refs: refs
                .iter()
                .map(|(n, s)| (n.to_string(), s.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    /// Generation 1: counter 1, seqfloor 1, main at commit 1.
    fn manifest_gen1(&self) -> Manifest {
        self.manifest(1, 1, &[&self.b1], &[("refs/heads/main", &self.c1)])
    }

    /// Generation 2: counter 2, seqfloor 2, main at commit 2 plus the tag.
    fn manifest_gen2(&self) -> Manifest {
        self.manifest(
            2,
            2,
            &[&self.b1, &self.b2],
            &[("refs/heads/main", &self.c2), ("refs/tags/v1", &self.tag)],
        )
    }

    fn with_manifest(&self, files: &Files, m: &Manifest) -> Files {
        let mut out = files.clone();
        add_manifest(&mut out, &self.identity.to_public(), m);
        out
    }

    fn clone_to(&self, name: &str, env: &[(&str, &str)]) -> (PathBuf, Output) {
        let dest = self.scratch.join(name);
        let output = sealed_git(
            &self.scratch,
            &["clone", "-q", &self.remote.sealed_url(), name],
            &self.id_file,
            env,
        );
        (dest, output)
    }

    fn fetch_in(&self, dest: &std::path::Path) -> Output {
        sealed_git(dest, &["fetch", "-q", "origin"], &self.id_file, &[])
    }
}

fn file_content(dest: &std::path::Path, rev: &str, path: &str) -> String {
    git(dest, &["show", &format!("{rev}:{path}")])
}

fn has_file(files: &Files, name: &str) -> bool {
    files.iter().any(|(n, _)| n == name)
}

#[test]
fn clone_sha1_vault_with_a_chunked_full_bundle() {
    let fx = fixture("clone-sha1", ObjectFormat::Sha1, Some(3), false);
    let files = fx.with_manifest(&fx.gen2, &fx.manifest_gen2());
    // §4.2: parts .0/.1/.2, count 3 in the manifest, no bare name.
    assert!(has_file(&files, "1-full.bundle.age.0"));
    assert!(has_file(&files, "1-full.bundle.age.2"));
    assert!(!has_file(&files, "1-full.bundle.age"));
    assert_eq!(fx.b1.chunks, Some(3));
    fx.remote.commit(&files, "main");

    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "git clone sealed::");

    // §6.6: exactly the manifest's refs and HEAD symref.
    assert_eq!(
        git(&dest, &["symbolic-ref", "HEAD"]).trim(),
        "refs/heads/main"
    );
    assert_eq!(git(&dest, &["rev-parse", "refs/heads/main"]).trim(), fx.c2);
    assert_eq!(git(&dest, &["rev-parse", "refs/tags/v1"]).trim(), fx.tag);
    assert_eq!(file_content(&dest, "HEAD", "note.md"), "hello world\n");
    assert_eq!(file_content(&dest, "HEAD~1", "note.md"), "hello\n");
    git(&dest, &["fsck", "--strict"]);

    // The local state landed under <GIT_DIR>/sealed/: one lock for the
    // repository, per-URL mirror and vault binding, and the pin under the
    // VAULT's identity (shared by every URL of that vault, §7.4).
    let root = sealed_root(&dest);
    assert!(root.join("lock").is_file());
    let state = state_dir(&dest);
    assert!(state.join("mirror.git").join("HEAD").is_file());
    assert_eq!(
        fs::read_to_string(state.join("vault")).expect("vault binding"),
        format!("{}\n", fx.vault_id)
    );
    let pin = pin_dir(&dest);
    assert_eq!(pin.file_name().unwrap().to_str().unwrap(), fx.vault_id);
    assert!(pin.join("pin.json").is_file());

    // A second fetch takes the sequence-memory skip path and still succeeds.
    assert_ok(&fx.fetch_in(&dest), "second fetch");
    assert_eq!(
        git(&dest, &["rev-parse", "refs/remotes/origin/main"]).trim(),
        fx.c2
    );
}

#[test]
fn twelve_part_bundle_reassembles_in_numeric_part_order() {
    // §4.1/§6.5: parts .0 .. .11 — string order would put .10 and .11
    // before .2, so a lexical reassembly cannot pass the digest check.
    let fx = fixture("twelve", ObjectFormat::Sha1, Some(12), true);
    let files = fx.with_manifest(&fx.gen2, &fx.manifest_gen2());
    assert!(has_file(&files, "1-full.bundle.age.10"));
    assert!(has_file(&files, "1-full.bundle.age.11"));
    assert!(!has_file(&files, "1-full.bundle.age.12"));
    fx.remote.commit(&files, "main");

    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "git clone sealed::");
    assert_eq!(git(&dest, &["rev-parse", "refs/heads/main"]).trim(), fx.c2);
    assert!(file_content(&dest, "HEAD~1", "note.md").starts_with("line 0: "));
    git(&dest, &["fsck", "--strict"]);
}

#[test]
fn tampered_chunk_fails_the_digest_check_before_decryption() {
    let fx = fixture("tampered", ObjectFormat::Sha1, Some(12), true);
    let mut files = fx.with_manifest(&fx.gen2, &fx.manifest_gen2());
    let part = files
        .iter_mut()
        .find(|(n, _)| n == "1-full.bundle.age.7")
        .expect("part exists");
    part.1[0] ^= 0x01;
    fx.remote.commit(&files, "main");

    let (dest, out) = fx.clone_to("clone", &[]);
    assert!(!out.status.success(), "tampered chunk must fail the clone");
    let err = stderr_of(&out);
    assert!(
        err.contains(
            "1-full.bundle.age: reassembled ciphertext does not match its manifest digest"
        ),
        "stderr: {err}"
    );
    assert!(
        !dest.join(".git").exists(),
        "git cleans up the failed clone"
    );
}

#[test]
fn missing_chunk_fails_the_file_set_equality() {
    let fx = fixture("missing", ObjectFormat::Sha1, Some(12), true);
    let mut files = fx.with_manifest(&fx.gen2, &fx.manifest_gen2());
    files.retain(|(n, _)| n != "1-full.bundle.age.10");
    fx.remote.commit(&files, "main");

    let (_, out) = fx.clone_to("clone", &[]);
    assert!(!out.status.success(), "missing chunk must fail the clone");
    let err = stderr_of(&out);
    assert!(
        err.contains("missing a manifest-listed bundle file: 1-full.bundle.age.10"),
        "stderr: {err}"
    );
}

#[test]
fn incremental_fetch_then_rollback_is_refused() {
    let fx = fixture("rollback", ObjectFormat::Sha1, None, false);
    let gen1 = fx
        .remote
        .commit(&fx.with_manifest(&fx.gen1, &fx.manifest_gen1()), "main");

    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "clone at generation 1");
    assert_eq!(git(&dest, &["rev-parse", "refs/heads/main"]).trim(), fx.c1);
    assert!(git_try(&dest, &["rev-parse", "--verify", "refs/tags/v1"]).is_none());

    // The vault advances: bundle 2 lands (sequence 1 is remembered and
    // skipped; sequence 2 is applied).
    let gen2 = fx
        .remote
        .commit(&fx.with_manifest(&fx.gen2, &fx.manifest_gen2()), "main");
    assert_ok(&fx.fetch_in(&dest), "incremental fetch");
    assert_eq!(
        git(&dest, &["rev-parse", "refs/remotes/origin/main"]).trim(),
        fx.c2
    );
    assert_eq!(git(&dest, &["rev-parse", "refs/tags/v1"]).trim(), fx.tag);
    assert_eq!(
        file_content(&dest, "refs/remotes/origin/main", "note.md"),
        "hello world\n"
    );

    // §7.4: the host serves the older (genuine) commit again — a rollback.
    fx.remote.set_branch("main", &gen1);
    let out = fx.fetch_in(&dest);
    assert!(!out.status.success(), "rollback must be refused");
    let err = stderr_of(&out);
    assert!(
        err.contains("vault rolled back: manifest counter 1 is below the last accepted counter 2"),
        "stderr: {err}"
    );

    // Back on the real tip, reads resume.
    fx.remote.set_branch("main", &gen2);
    assert_ok(&fx.fetch_in(&dest), "fetch after the host recovers");
}

#[test]
fn sha256_vault_round_trip() {
    // §3/§4.3: sha256 source, v3 bundle with @object-format=sha256, 64-hex
    // refs in the manifest. The vault repository itself stays sha1
    // (host-default, §3).
    let fx = fixture("sha256", ObjectFormat::Sha256, Some(2), false);
    assert_eq!(fx.c2.len(), 64);
    let files = fx.with_manifest(&fx.gen2, &fx.manifest_gen2());
    fx.remote.commit(&files, "main");

    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "git clone sealed:: (sha256)");
    assert_eq!(
        git(&dest, &["rev-parse", "--show-object-format"]).trim(),
        "sha256"
    );
    assert_eq!(
        git(&dest, &["symbolic-ref", "HEAD"]).trim(),
        "refs/heads/main"
    );
    assert_eq!(git(&dest, &["rev-parse", "refs/heads/main"]).trim(), fx.c2);
    assert_eq!(git(&dest, &["rev-parse", "refs/tags/v1"]).trim(), fx.tag);
    assert_eq!(file_content(&dest, "HEAD", "note.md"), "hello world\n");
    git(&dest, &["fsck", "--strict"]);
}

#[test]
fn skipped_bundles_are_reapplied_when_objects_went_missing() {
    // §6.5: a local gc can prune unbundled objects no ref reached; a stale
    // skip must not wedge the reader. Library-level so no refs ever get set
    // (the helper's caller, git, is what sets them).
    let fx = fixture("reapply", ObjectFormat::Sha1, Some(2), false);
    fx.remote
        .commit(&fx.with_manifest(&fx.gen2, &fx.manifest_gen2()), "main");

    let dest = fx.scratch.join("dest");
    fs::create_dir_all(&dest).expect("mkdir dest");
    git(&dest, &["init", "-q", "-b", "main"]);
    let git_dir = fs::canonicalize(dest.join(".git")).expect("git dir");
    let ids = std::slice::from_ref(&fx.identity);

    {
        let vault = VaultRepo::open(&git_dir, &fx.remote.url()).expect("open");
        let out = reader::fetch_and_report(&vault, &git_dir, ids).expect("first read");
        assert_eq!(out.refs["refs/heads/main"], fx.c2);
        assert_eq!(out.head.as_deref(), Some("refs/heads/main"));
        assert_eq!(out.object_format, Some(ObjectFormat::Sha1));
        assert!(!out.writer_must_be_read_only);
    }
    assert!(vaultrepo::object_exists(&git_dir, &fx.c2).expect("cat-file"));

    // Nothing references the unbundled objects: gc prunes them all.
    git(&dest, &["gc", "-q", "--prune=now"]);
    assert!(!vaultrepo::object_exists(&git_dir, &fx.c2).expect("cat-file"));

    let vault = VaultRepo::open(&git_dir, &fx.remote.url()).expect("open");
    let out = reader::fetch_and_report(&vault, &git_dir, ids).expect("re-apply after gc");
    assert_eq!(out.refs["refs/tags/v1"], fx.tag);
    assert!(vaultrepo::object_exists(&git_dir, &fx.c2).expect("cat-file"));
    assert!(vaultrepo::object_exists(&git_dir, &fx.tag).expect("cat-file"));
}

#[test]
fn new_incremental_restores_pruned_cached_prerequisites() {
    let fx = fixture("reapply-prerequisite", ObjectFormat::Sha1, Some(2), false);
    fx.remote
        .commit(&fx.with_manifest(&fx.gen1, &fx.manifest_gen1()), "main");
    let dest = SourceRepo::init(fx.scratch.join("dest"), "sha1");
    let git_dir = fs::canonicalize(dest.dir.join(".git")).expect("git dir");
    let ids = std::slice::from_ref(&fx.identity);
    let vault = VaultRepo::open(&git_dir, &fx.remote.url()).expect("open");
    reader::fetch_and_report(&vault, &git_dir, ids).expect("first read");

    // Unbundle imports objects without refs, as happens for unselected
    // branches in a single-branch clone. GC can remove these objects.
    git(&dest.dir, &["gc", "-q", "--prune=now"]);
    assert!(!vaultrepo::object_exists(&git_dir, &fx.c1).expect("cat-file"));
    fx.remote
        .commit(&fx.with_manifest(&fx.gen2, &fx.manifest_gen2()), "main");

    let out = reader::fetch_and_report(&vault, &git_dir, ids).expect("incremental after gc");
    assert_eq!(out.refs["refs/heads/main"], fx.c2);
    assert!(vaultrepo::object_exists(&git_dir, &fx.c1).expect("prerequisite restored"));
    assert!(vaultrepo::object_exists(&git_dir, &fx.c2).expect("new commit imported"));
    git(&dest.dir, &["fsck", "--strict"]);
}

#[test]
fn hint_version_mismatch_is_refused() {
    // §3: a host-controlled `sealed-format` that disagrees fast-fails; it
    // never selects semantics (the manifest is still a valid v2 one).
    let fx = fixture("hint", ObjectFormat::Sha1, None, false);
    let mut files = fx.with_manifest(&fx.gen1, &fx.manifest_gen1());
    for (name, bytes) in files.iter_mut() {
        if name == "sealed-format" {
            *bytes = b"3\n".to_vec();
        }
    }
    fx.remote.commit(&files, "main");
    let (_, out) = fx.clone_to("clone", &[]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("unsupported vault format '3'"),
        "stderr: {err}"
    );
}

#[test]
fn a_version_1_vault_is_refused_rather_than_read_as_empty() {
    // §3: version 1 keeps its manifest under a different name, and its
    // 8-digit bundle names are non-canonical here — so a v1 tree holds
    // nothing this reader recognizes. Without the legacy check it would read
    // as an EMPTY vault, and a fresh clone would then initialize a new vault
    // over a real one. The `sealed-format` hint cannot save us: it is
    // checked only after the manifest has been located.
    let fx = fixture("v1vault", ObjectFormat::Sha1, None, false);
    let legacy: Files = vec![
        ("sealed-format".into(), b"1\n".to_vec()),
        ("refs.age".into(), b"a version 1 manifest".to_vec()),
        (
            "00000001-full.bundle.age".into(),
            b"a version 1 bundle".to_vec(),
        ),
    ];
    fx.remote.commit(&legacy, "main");
    let (_, out) = fx.clone_to("clone", &[]);
    assert!(!out.status.success(), "a v1 vault must not read as empty");
    let err = stderr_of(&out);
    assert!(err.contains("version 1 sealed vault"), "stderr: {err}");
}

#[test]
fn bundles_without_a_manifest_are_a_hard_error() {
    // §3: one deleted file must not make the vault read as empty.
    let fx = fixture("nomanifest", ObjectFormat::Sha1, None, false);
    fx.remote.commit(&fx.gen1, "main");
    let (_, out) = fx.clone_to("clone", &[]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("bundle files but no sealed-manifest.age"),
        "stderr: {err}"
    );
}

#[test]
fn empty_remote_reads_as_no_refs() {
    // §8.1: an empty vault (no manifest, no bundles) reads as no refs — a
    // first-contact reader gets an empty clone, not an error.
    let fx = fixture("empty", ObjectFormat::Sha1, None, false);
    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "clone of an empty vault");
    assert!(dest.join(".git").is_dir());
    assert!(git_try(&dest, &["rev-parse", "--verify", "HEAD"]).is_none());
}

#[test]
fn respelled_remote_url_inherits_rollback_protection() {
    // §7.4: pins are per (repository, VAULT), not per URL spelling. A
    // rollback served through a never-before-used spelling of the same
    // remote must be refused just like through the original one.
    let fx = fixture("respell", ObjectFormat::Sha1, None, false);
    let gen1 = fx
        .remote
        .commit(&fx.with_manifest(&fx.gen1, &fx.manifest_gen1()), "main");
    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "clone at generation 1");
    fx.remote
        .commit(&fx.with_manifest(&fx.gen2, &fx.manifest_gen2()), "main");
    assert_ok(&fx.fetch_in(&dest), "fetch to generation 2");

    // Roll the host back, then fetch through a respelled URL (trailing
    // slash): a fresh state dir for this spelling, no pin of its own.
    fx.remote.set_branch("main", &gen1);
    let respelled = format!("{}/", fx.remote.sealed_url());
    let out = sealed_git(&dest, &["fetch", "-q", &respelled], &fx.id_file, &[]);
    assert!(
        !out.status.success(),
        "rollback via a respelled URL must be refused"
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("vault rolled back: manifest counter 1 is below the last accepted counter 2"),
        "stderr: {err}"
    );
}

/// A second remote of `dest` naming the same vault through another
/// spelling of its URL (a trailing slash: enough to get a different state
/// key, which is all an SSH-versus-HTTPS pair would add).
fn add_alias(fx: &Fixture, dest: &std::path::Path) -> String {
    let alias = format!("{}/", fx.remote.sealed_url());
    git(dest, &["remote", "add", "alias", &alias]);
    alias
}

fn fetch_remote(fx: &Fixture, dest: &std::path::Path, remote: &str) -> Output {
    sealed_git(dest, &["fetch", "-q", remote], &fx.id_file, &[])
}

#[test]
fn rollback_through_an_alias_that_has_its_own_history_is_refused() {
    // The regression: two URLs of one vault, EACH of which has already
    // saved a pin. With a pin per URL, the memories diverge as soon as the
    // URLs are used at different times, and a host can replay an old
    // generation through the URL whose memory is older. §7.4: one pin per
    // (repository, vault), whichever URL it is reached through.
    let fx = fixture("alias-rollback", ObjectFormat::Sha1, None, false);
    let gen1 = fx
        .remote
        .commit(&fx.with_manifest(&fx.gen1, &fx.manifest_gen1()), "main");

    // Counter 1 through `origin`: origin's memory says 1.
    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "clone at generation 1 through origin");
    // Counter 2 through `alias`: alias's memory says 2.
    let alias_url = add_alias(&fx, &dest);
    fx.remote
        .commit(&fx.with_manifest(&fx.gen2, &fx.manifest_gen2()), "main");
    assert_ok(
        &fetch_remote(&fx, &dest, "alias"),
        "fetch generation 2 through alias",
    );
    assert_eq!(rev_of(&dest, "refs/remotes/alias/main"), fx.c2);

    // One vault, two URLs, ONE pin.
    let urls: Vec<_> = fs::read_dir(sealed_root(&dest).join("urls"))
        .expect("urls")
        .map(|e| e.expect("dirent").path())
        .collect();
    assert_eq!(urls.len(), 2, "one state dir per URL spelling");
    for url_dir in &urls {
        assert_eq!(
            fs::read_to_string(url_dir.join("vault")).expect("bound"),
            format!("{}\n", fx.vault_id)
        );
    }
    let pin = sealed::pinstore::load(&pin_dir(&dest))
        .expect("readable")
        .expect("pinned");
    assert_eq!(pin.counter, 2);

    // The host replays counter 1 through origin, whose own memory (had it
    // one) would still say 1. It must be refused.
    fx.remote.set_branch("main", &gen1);
    let out = fetch_remote(&fx, &dest, "origin");
    assert!(
        !out.status.success(),
        "rollback through the older alias must be refused"
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("vault rolled back: manifest counter 1 is below the last accepted counter 2"),
        "stderr: {err}"
    );

    // `info` knows the pin is shared...
    let out = cli(&dest, &fx.id_file, &["info", "origin"]);
    assert_ok(&out, "info");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!(
            "shared:     pin also used through {}",
            &alias_url["sealed::".len()..]
        )),
        "{text}"
    );

    // ...and `forget` of ONE alias keeps it: origin still refuses the
    // rollback. Only forgetting the last URL discards the pin (§7.5).
    let out = cli(&dest, &fx.id_file, &["forget", "--yes", "alias"]);
    assert_ok(&out, "forget alias");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("are KEPT"), "{text}");
    assert!(pin_dir(&dest).join("pin.json").is_file());
    let out = fetch_remote(&fx, &dest, "origin");
    assert!(
        !out.status.success(),
        "the kept pin still refuses the rollback"
    );
    assert!(stderr_of(&out).contains("vault rolled back"));

    let out = cli(&dest, &fx.id_file, &["forget", "--yes", "origin"]);
    assert_ok(&out, "forget origin");
    assert!(String::from_utf8_lossy(&out.stdout).contains("forgot the pin"));
    assert!(!sealed_root(&dest)
        .join("vaults")
        .join(&fx.vault_id)
        .exists());
    assert_ok(
        &fetch_remote(&fx, &dest, "origin"),
        "with every URL forgotten, the rolled-back vault is accepted (§7.5's forfeit)",
    );
}

fn rev_of(dest: &std::path::Path, r: &str) -> String {
    git(dest, &["rev-parse", "--verify", r]).trim().to_owned()
}

#[test]
fn a_bound_url_never_switches_vaults_even_to_a_vault_this_repository_trusts() {
    // §7.4 vault identity. A pin looked up by the manifest's OWN vault id
    // would let a substituted vault meet a fresh pin (or, worse, a pin the
    // repository legitimately holds for that other vault through another
    // URL). The URL's durable binding to the vault it first served is what
    // stops both.
    let fx = fixture("alias-subst", ObjectFormat::Sha1, None, false);
    fx.remote
        .commit(&fx.with_manifest(&fx.gen1, &fx.manifest_gen1()), "main");
    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "clone: origin is now bound to the vault");

    // Another vault of the same person: same key, same objects even, but
    // its own identity and a higher counter.
    let other_id = "0".repeat(32);
    let mut other = fx.manifest_gen2();
    other.vault_id = other_id.clone();
    other.counter = 9;
    let other_files = fx.with_manifest(&fx.gen2, &other);

    // (1) Nobody has ever seen the other vault: served at origin, it meets
    // origin's binding, not a fresh pin.
    fx.remote.commit(&other_files, "main");
    let out = fetch_remote(&fx, &dest, "origin");
    assert!(!out.status.success(), "a substituted vault must be refused");
    let err = stderr_of(&out);
    assert!(
        err.contains(&format!(
            "vault identity changed (pinned {}, manifest says {other_id})",
            fx.vault_id
        )),
        "stderr: {err}"
    );
    assert!(
        !sealed_root(&dest).join("vaults").join(&other_id).exists(),
        "no pin was started for the substitute"
    );

    // (2) The other vault IS one this repository trusts: reached through
    // its own URL, it pins normally...
    let second = VaultRemote::init(fx.scratch.join("vault2.git"));
    second.commit(&other_files, "main");
    git(&dest, &["remote", "add", "second", &second.sealed_url()]);
    assert_ok(
        &fetch_remote(&fx, &dest, "second"),
        "the other vault through its own URL",
    );
    assert!(sealed_root(&dest)
        .join("vaults")
        .join(&other_id)
        .join("pin.json")
        .is_file());

    // ...but served at origin it is still refused: origin is bound to the
    // first vault, and the other vault's (perfectly valid) pin is never
    // consulted for it.
    let out = fetch_remote(&fx, &dest, "origin");
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("vault identity changed"),
        "{}",
        stderr_of(&out)
    );
}

/// Write a 0.1.0-layout pin for `url` under `root`: `<sha256(url)>/pin/pin.json`.
fn write_legacy_pin(root: &std::path::Path, url: &str, pin: &sealed::pinstore::Pin) {
    let dir = root.join(sealed::pinstore::url_key(url)).join("pin");
    sealed::pinstore::save(&dir, pin).expect("legacy pin");
    // The old layout kept the mirror and lock beside the pin.
    fs::create_dir_all(root.join(sealed::pinstore::url_key(url)).join("mirror.git"))
        .expect("legacy mirror");
}

fn cipher_digest(files: &Files, name: &str) -> String {
    let (_, bytes) = files.iter().find(|(n, _)| n == name).expect("file");
    sha256_hex(bytes)
}

#[test]
fn per_url_pins_of_an_upgraded_repository_merge_into_one_shared_pin() {
    // A repository written by 0.1.0 holds one pin per URL. Its first
    // operation merges them: every confirmed binding survives (picking the
    // highest counter would drop the other URL's memory), both URLs come
    // out bound to the vault, and the old directories are gone.
    let fx = fixture("alias-migrate", ObjectFormat::Sha1, None, false);
    let files1 = fx.with_manifest(&fx.gen1, &fx.manifest_gen1());
    let files2 = fx.with_manifest(&fx.gen2, &fx.manifest_gen2());
    let gen1 = fx.remote.commit(&files1, "main");
    let gen2 = fx.remote.commit(&files2, "main");

    let dest = SourceRepo::init(fx.scratch.join("dest"), "sha1").dir;
    git(&dest, &["remote", "add", "origin", &fx.remote.sealed_url()]);
    let alias_url = add_alias(&fx, &dest);
    let url_a = fx.remote.url();
    let url_b = &alias_url["sealed::".len()..];

    // origin saw generation 1; alias saw generation 2 but (hand-made, as a
    // record could be after a compaction) remembers only bundle 2.
    let base = sealed::pinstore::Pin {
        vault_id: fx.vault_id.clone(),
        counter: 1,
        manifest_digest: cipher_digest(&files1, "sealed-manifest.age"),
        format: 2,
        object_format: ObjectFormat::Sha1,
        seqfloor: 1,
        sequence_memory: [(1, fx.b1.digest.clone())].into_iter().collect(),
        pending: BTreeMap::new(),
    };
    let mut newer = base.clone();
    newer.counter = 2;
    newer.manifest_digest = cipher_digest(&files2, "sealed-manifest.age");
    newer.seqfloor = 2;
    newer.sequence_memory = [(2, fx.b2.digest.clone())].into_iter().collect();
    let root = sealed_root(&dest);
    write_legacy_pin(&root, &url_a, &base);
    write_legacy_pin(&root, url_b, &newer);

    assert_ok(
        &fetch_remote(&fx, &dest, "origin"),
        "first fetch after the upgrade",
    );
    assert_eq!(rev_of(&dest, "refs/remotes/origin/main"), fx.c2);
    for url in [url_a.as_str(), url_b] {
        assert!(
            !root.join(sealed::pinstore::url_key(url)).exists(),
            "legacy state dir of {url} removed"
        );
        assert_eq!(
            fs::read_to_string(
                root.join("urls")
                    .join(sealed::pinstore::url_key(url))
                    .join("vault")
            )
            .expect("bound"),
            format!("{}\n", fx.vault_id)
        );
    }
    let pin = sealed::pinstore::load(&pin_dir(&dest))
        .expect("readable")
        .expect("one shared pin");
    assert_eq!((pin.counter, pin.seqfloor), (2, 2));
    assert_eq!(
        pin.sequence_memory.keys().copied().collect::<Vec<_>>(),
        vec![1, 2],
        "origin's binding for 1 and alias's for 2 both survive"
    );

    // origin's own 0.1.0 pin would have accepted generation 1 again.
    fx.remote.set_branch("main", &gen1);
    let out = fetch_remote(&fx, &dest, "origin");
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("vault rolled back"),
        "{}",
        stderr_of(&out)
    );

    // alias's own 0.1.0 pin knew nothing about sequence 1: a generation
    // that re-binds it (counter 3, so it passes every other check) would
    // have gone through. The merged memory refuses it.
    fx.remote.set_branch("main", &gen2);
    let mut rebound: Files = Vec::new();
    add_hint(&mut rebound);
    let b1 = fx.b1.clone();
    let plain = std::fs::read(fx.scratch.join("b1.bundle")).expect("bundle 1");
    let rec1 = add_bundle(
        &mut rebound,
        &fx.identity.to_public(),
        1,
        true,
        &plain,
        None,
    );
    assert_ne!(
        rec1.digest, b1.digest,
        "age is randomized: a fresh ciphertext"
    );
    let plain2 = std::fs::read(fx.scratch.join("b2.bundle")).expect("bundle 2");
    let rec2 = add_bundle(
        &mut rebound,
        &fx.identity.to_public(),
        2,
        false,
        &plain2,
        None,
    );
    let m = fx.manifest(
        3,
        2,
        &[&rec1, &rec2],
        &[("refs/heads/main", &fx.c2), ("refs/tags/v1", &fx.tag)],
    );
    fx.remote.commit(&fx.with_manifest(&rebound, &m), "main");
    let out = fetch_remote(&fx, &dest, "alias");
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("sequence number 1 is bound to a different bundle"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn contradicting_per_url_pins_stop_every_operation_until_one_is_discarded() {
    // Two 0.1.0 records that cannot both be true (same counter, different
    // manifests: a forked twin seen through two URLs). Merging them would
    // have to pick one; instead every operation fails, nothing is changed,
    // and `forget` of the record the user distrusts lets the rest migrate.
    let fx = fixture("alias-conflict", ObjectFormat::Sha1, None, false);
    let files1 = fx.with_manifest(&fx.gen1, &fx.manifest_gen1());
    fx.remote.commit(&files1, "main");
    let dest = SourceRepo::init(fx.scratch.join("dest"), "sha1").dir;
    git(&dest, &["remote", "add", "origin", &fx.remote.sealed_url()]);
    let alias_url = add_alias(&fx, &dest);
    let url_b = &alias_url["sealed::".len()..];

    let honest = sealed::pinstore::Pin {
        vault_id: fx.vault_id.clone(),
        counter: 1,
        manifest_digest: cipher_digest(&files1, "sealed-manifest.age"),
        format: 2,
        object_format: ObjectFormat::Sha1,
        seqfloor: 1,
        sequence_memory: [(1, fx.b1.digest.clone())].into_iter().collect(),
        pending: BTreeMap::new(),
    };
    let mut twin = honest.clone();
    twin.manifest_digest = "f".repeat(64);
    let root = sealed_root(&dest);
    write_legacy_pin(&root, &fx.remote.url(), &honest);
    write_legacy_pin(&root, url_b, &twin);

    let out = fetch_remote(&fx, &dest, "origin");
    assert!(
        !out.status.success(),
        "contradicting records must not be merged"
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("disagree (two different manifests at counter 1)"),
        "{err}"
    );
    assert!(err.contains("git-remote-sealed forget --yes"), "{err}");
    let bound = |url: &str| {
        sealed_root(&dest)
            .join("urls")
            .join(sealed::pinstore::url_key(url))
            .join("vault")
            .exists()
    };
    assert!(
        !(bound(url_b) && bound(&fx.remote.url())),
        "at most one record was merged (state-key order decides which)"
    );

    // The user trusts origin: discard the alias's record (its state key
    // is what identifies it; the record is never merged, §7.5).
    let out = cli(&dest, &fx.id_file, &["forget", "--yes", "alias"]);
    assert_ok(&out, "forget the distrusted record");
    assert_ok(&fetch_remote(&fx, &dest, "origin"), "migration completes");
    assert_eq!(rev_of(&dest, "refs/remotes/origin/main"), fx.c1);
    let pin = sealed::pinstore::load(&pin_dir(&dest))
        .expect("readable")
        .expect("pinned");
    assert_eq!(pin.manifest_digest, honest.manifest_digest);
}

#[test]
fn operations_through_different_aliases_are_serialized_by_one_lock() {
    // §6.1: two URLs of one vault share a pin, so their operations must be
    // serialized against each other — one repository-wide lock, taken
    // whichever URL is used. (Two locks, one per URL, would leave the
    // shared pin unprotected; per-URL locks taken in URL order would be a
    // lock-order hazard for nothing.)
    use std::sync::mpsc;
    use std::time::Duration;

    let fx = fixture("alias-lock", ObjectFormat::Sha1, None, false);
    fx.remote
        .commit(&fx.with_manifest(&fx.gen2, &fx.manifest_gen2()), "main");
    let (dest, out) = fx.clone_to("clone", &[]);
    assert_ok(&out, "clone");
    let alias_url = add_alias(&fx, &dest);
    let git_dir = fs::canonicalize(dest.join(".git")).expect("git dir");

    // Library level: opening the vault through B blocks while A is open.
    let held = VaultRepo::open(&git_dir, &fx.remote.url()).expect("open through A");
    let (tx, rx) = mpsc::channel();
    let git_dir_b = git_dir.clone();
    let url_b = alias_url["sealed::".len()..].to_owned();
    let waiter = std::thread::spawn(move || {
        let opened = VaultRepo::open(&git_dir_b, &url_b).expect("open through B");
        tx.send(()).expect("report");
        drop(opened);
    });
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "B must wait for A's lock"
    );
    drop(held);
    rx.recv_timeout(Duration::from_secs(30))
        .expect("B proceeds once A releases the lock");
    waiter.join().expect("waiter thread");

    // Process level: real fetches through both aliases at once, repeatedly.
    // Every one succeeds, and the shared pin ends up consistent.
    let mut threads = Vec::new();
    for remote in ["origin", "alias"] {
        let dest = dest.clone();
        let id_file = fx.id_file.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..4 {
                let out = sealed_git(&dest, &["fetch", "-q", remote], &id_file, &[]);
                assert_ok(&out, &format!("concurrent fetch through {remote}"));
            }
        }));
    }
    for t in threads {
        t.join().expect("fetch thread");
    }
    let pin = sealed::pinstore::load(&pin_dir(&dest))
        .expect("readable")
        .expect("pinned");
    assert_eq!(pin.counter, 2);
    assert_eq!(pin.sequence_memory.len(), 2);
    assert_eq!(rev_of(&dest, "refs/remotes/alias/main"), fx.c2);
}
