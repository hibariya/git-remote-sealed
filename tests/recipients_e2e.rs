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
