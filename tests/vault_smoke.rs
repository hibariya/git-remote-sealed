//! End-to-end smoke test for the harness shape: build a sha1 vault directory
//! by hand out of the library modules plus real `git bundle` output, then
//! read it back through every §6 reader check the skeleton implements.
//!
//! This is NOT the remote-helper protocol — no push/fetch logic, no vault
//! git repository; the vault is a plain directory here.

mod common;

use std::fs;

use age::x25519::Identity;
use common::{git, scratch};
use sealed::manifest::{self, BundleRecord, Manifest, ObjectFormat};
use sealed::names::{BundleName, NameClass};
use sealed::{crypt, pinstore, sha256_hex};

#[test]
fn sha1_vault_round_trip() {
    let scratch = scratch("smoke");

    // --- a sha1 source repository with one commit ---
    let src = scratch.join("src");
    fs::create_dir_all(&src).expect("mkdir src");
    git(&src, &["init", "-q", "-b", "main", "--object-format=sha1"]);
    fs::write(src.join("note.md"), "hello sealed\n").expect("write note");
    git(&src, &["add", "note.md"]);
    git(&src, &["commit", "-q", "-m", "first"]);
    let head_sha = git(&src, &["rev-parse", "HEAD"]).trim().to_owned();
    let head_ref = git(&src, &["symbolic-ref", "HEAD"]).trim().to_owned();
    assert_eq!(head_ref, "refs/heads/main");
    assert_eq!(head_sha.len(), 40);

    // --- one -full bundle via real git (§4.3: real ref names + HEAD entry) ---
    let plain_bundle = scratch.join("plain.bundle");
    git(
        &src,
        &[
            "bundle",
            "create",
            plain_bundle.to_str().expect("utf-8 path"),
            "HEAD",
            "--all",
        ],
    );
    let bundle_bytes = fs::read(&plain_bundle).expect("read bundle");
    // §4.3: header `# v2 git bundle` iff objectformat sha1.
    manifest::verify_bundle_header(&bundle_bytes, ObjectFormat::Sha1)
        .expect("git produced a v2 bundle for a sha1 repo");

    // --- encrypt and lay out the vault directory by hand ---
    let identity = Identity::generate();
    let recipient = identity.to_public();
    let ciphertext = crypt::encrypt(&[recipient], &bundle_bytes).expect("encrypt bundle");
    let bundle_digest = sha256_hex(&ciphertext);

    // §4.1: the vault-initializing push allocates sequence 1; §4.1's rule
    // labels it -full (empty pre-push bundle list).
    let bundle_name = BundleName::new(1, true, None).expect("canonical name");
    assert_eq!(bundle_name.to_string(), "1-full.bundle.age");

    let vault_dir = scratch.join("vault");
    fs::create_dir_all(&vault_dir).expect("mkdir vault");
    // §3: ASCII decimal version + a single LF.
    fs::write(vault_dir.join("sealed-format"), "2\n").expect("write sealed-format");
    fs::write(vault_dir.join(bundle_name.to_string()), &ciphertext).expect("write bundle");

    // §7.2: random vault identity, >= 128 bits. Derived (not random) here to
    // keep the test dependency-free; uniqueness is not what this test checks.
    let vault_id = sha256_hex(identity.to_public().to_string().as_bytes());
    let manifest = Manifest {
        format: 2,
        object_format: ObjectFormat::Sha1,
        vault_id,
        counter: 1,
        seqfloor: 1,
        bundles: [(
            1,
            BundleRecord {
                seq: 1,
                full: true,
                digest: bundle_digest.clone(),
                chunks: None,
            },
        )]
        .into_iter()
        .collect(),
        head: Some(head_ref.clone()),
        refs: [(head_ref.clone(), head_sha.clone())].into_iter().collect(),
    };
    let manifest_text = manifest.to_text().expect("serializable manifest");
    let manifest_cipher = crypt::encrypt(&[identity.to_public()], manifest_text.as_bytes())
        .expect("encrypt manifest");
    fs::write(vault_dir.join("sealed-manifest.age"), &manifest_cipher)
        .expect("write sealed-manifest.age");

    // ====================== read it all back (§6) ======================

    // §6.2: check sealed-format (the hint).
    let hint = fs::read(vault_dir.join("sealed-format")).expect("sealed-format present");
    assert_eq!(hint, b"2\n");

    // §6.3: decrypt and validate the manifest...
    let fetched_cipher =
        fs::read(vault_dir.join("sealed-manifest.age")).expect("sealed-manifest.age present");
    let fetched_text = crypt::decrypt(std::slice::from_ref(&identity), &fetched_cipher)
        .expect("manifest decrypts");
    let parsed = manifest::parse(&fetched_text).expect("manifest validates");
    assert!(!parsed.writer_must_be_read_only);
    let read_manifest = parsed.manifest;
    assert_eq!(read_manifest, manifest);
    // §3: the hint MUST match the manifest's format line.
    assert_eq!(format!("{}\n", read_manifest.format).as_bytes(), &hint[..]);

    // ...including the §7.4 trust-on-first-use battery, persisted and reloaded.
    let pin_dir = scratch.join("pins").join("remote-a");
    let manifest_cipher_digest = sha256_hex(&fetched_cipher);
    let prev = pinstore::load(&pin_dir).expect("pin store readable");
    assert_eq!(prev, None, "first contact");
    let pin =
        pinstore::validate_and_advance(prev.as_ref(), &read_manifest, &manifest_cipher_digest)
            .expect("first contact pins");
    pinstore::save(&pin_dir, &pin).expect("pin persisted");
    let reloaded = pinstore::load(&pin_dir).expect("pin store readable");
    assert_eq!(reloaded, Some(pin.clone()));
    // A second read of the same state passes the battery.
    pinstore::validate_and_advance(reloaded.as_ref(), &read_manifest, &manifest_cipher_digest)
        .expect("idempotent re-read");
    assert_eq!(pin.sequence_memory[&1], bundle_digest);

    // §6.4/§6.7: the tree must equal the expected file set exactly.
    let tree_names: Vec<String> = fs::read_dir(&vault_dir)
        .expect("list vault")
        .map(|e| {
            e.expect("dirent")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    read_manifest
        .check_tree_files(tree_names.iter().map(String::as_str))
        .expect("tree matches the manifest");

    // ...and a planted extra canonical file is a hard error.
    fs::write(vault_dir.join("2.bundle.age"), b"decoy").expect("plant decoy");
    let planted: Vec<String> = fs::read_dir(&vault_dir)
        .expect("list vault")
        .map(|e| {
            e.expect("dirent")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(read_manifest
        .check_tree_files(planted.iter().map(String::as_str))
        .is_err());
    fs::remove_file(vault_dir.join("2.bundle.age")).expect("remove decoy");

    // §6.5: reassemble (whole file here), verify the digest BEFORE decrypting.
    let listed = &read_manifest.bundles[&1];
    let logical = listed.logical_name().expect("canonical");
    assert!(matches!(
        sealed::names::classify(&logical.to_string()),
        NameClass::Canonical(_)
    ));
    let stored = fs::read(vault_dir.join(logical.to_string())).expect("bundle file present");
    assert_eq!(sha256_hex(&stored), listed.digest, "§6.4 digest check");

    // Decrypt, verify the header line, hand to git.
    let recovered = crypt::decrypt(std::slice::from_ref(&identity), &stored).expect("decrypts");
    manifest::verify_bundle_header(&recovered, read_manifest.object_format)
        .expect("§4.3 header check");
    assert_eq!(recovered, bundle_bytes);
    let recovered_bundle = scratch.join("recovered.bundle");
    fs::write(&recovered_bundle, &recovered).expect("write recovered bundle");

    // §6.5: apply — `git bundle verify` + unbundle into a fresh repository.
    let reader_repo = scratch.join("reader");
    fs::create_dir_all(&reader_repo).expect("mkdir reader");
    git(&reader_repo, &["init", "-q", "-b", "main"]);
    git(
        &reader_repo,
        &[
            "bundle",
            "verify",
            "-q",
            recovered_bundle.to_str().expect("utf-8 path"),
        ],
    );
    git(
        &reader_repo,
        &[
            "bundle",
            "unbundle",
            recovered_bundle.to_str().expect("utf-8 path"),
        ],
    );

    // §6.6: every manifest-listed sha MUST now exist locally.
    for (refname, sha) in &read_manifest.refs {
        git(&reader_repo, &["cat-file", "-e", sha]);
        assert_eq!(refname, "refs/heads/main");
    }

    let _ = fs::remove_dir_all(&scratch);
}
