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

    // The per-(repository, remote) state landed under <GIT_DIR>/sealed/.
    let state = dest.join(".git").join("sealed");
    let entries: Vec<_> = fs::read_dir(&state).expect("state dir").collect();
    assert_eq!(entries.len(), 1, "one remote, one state dir");
    let state = entries[0].as_ref().expect("dirent").path();
    assert!(state.join("pin").join("pin.json").is_file());
    assert!(state.join("mirror.git").join("HEAD").is_file());
    assert!(state.join("lock").is_file());

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
