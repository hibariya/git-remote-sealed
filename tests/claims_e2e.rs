//! Claim-backed end-to-end tests: every claim FORMAT.md and README.md make
//! that `read_e2e.rs` / `write_e2e.rs` do not already exercise. Rust writes
//! the vaults through REAL `git push`; the checks run through real `git
//! clone` / `git fetch` driving the built binary, through hand-planted vault
//! commits (an adversarial host), and — for the headline claim — through
//! FORMAT.md's own Appendix A recipe executed with stock `sh`, `git` and
//! `age` (see `tests/common/appendix_a.rs`).

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519::Identity;
use common::appendix_a as recipe;
use common::*;
use sealed::manifest::{self, BundleRecord, Manifest, ObjectFormat};
use sealed::{crypt, sha256_hex};

const MIB: usize = 1024 * 1024;

fn rev(repo: &Path, r: &str) -> String {
    git(repo, &["rev-parse", "--verify", r]).trim().to_owned()
}

fn symref(repo: &Path) -> String {
    git(repo, &["symbolic-ref", "HEAD"]).trim().to_owned()
}

/// refname -> sha for every ref except remote-tracking ones (a source
/// repository's `git push` updates `refs/remotes/origin/*`, which is not
/// vault content).
fn refs_of(repo: &Path) -> BTreeMap<String, String> {
    git(repo, &["for-each-ref", "--format=%(objectname) %(refname)"])
        .lines()
        .filter_map(|l| l.split_once(' '))
        .filter(|(_, name)| !name.starts_with("refs/remotes/"))
        .map(|(sha, name)| (name.to_owned(), sha.to_owned()))
        .collect()
}

fn tree_listing(repo: &Path, rev: &str) -> String {
    git(repo, &["ls-tree", "-r", rev])
}

fn seqs(m: &Manifest) -> Vec<(u64, bool, Option<u64>)> {
    m.bundles
        .values()
        .map(|b| (b.seq, b.full, b.chunks))
        .collect()
}

/// The vault files the way a recovering human obtains them: a plain
/// `git clone` of the vault repository, the identity file beside them.
fn vault_files_dir(lab: &Lab, name: &str) -> PathBuf {
    let dir = lab.scratch.join(name);
    git(&lab.scratch, &["clone", "-q", &lab.remote.url(), name]);
    fs::copy(&lab.id_file, dir.join("key.txt")).expect("copy identity");
    dir
}

/// Run Appendix A end to end in `files`; returns the generated script.
fn run_appendix_a(files: &Path) -> String {
    let rec = recipe::recipe();
    let listing = recipe::list_vault_dir(files);
    let script = recipe::instantiate(&rec, &listing).expect("a -full bundle exists");
    recipe::run_sh_ok(files, &script);
    script
}

/// Appendix A's exact-refs paragraph, with stock tools: "decrypt `sealed-manifest.age`
/// and apply its ref lines with `git update-ref` (and delete refs it does
/// not list)" — plus the HEAD symref line.
fn exact_refs_restore(files: &Path) {
    let text = String::from_utf8(recipe::age_decrypt(files, "sealed-manifest.age"))
        .expect("UTF-8 manifest");
    let recovered = files.join("recovered.git");
    let mut listed = BTreeSet::new();
    for line in text.lines() {
        let Some((first, second)) = line.split_once(' ') else {
            continue;
        };
        if second == "HEAD" && first.starts_with('@') {
            git(&recovered, &["symbolic-ref", "HEAD", &first[1..]]);
        } else if first.len() >= 40 && first.chars().all(|c| c.is_ascii_hexdigit()) {
            git(&recovered, &["update-ref", second, first]);
            listed.insert(second.to_owned());
        }
    }
    for name in refs_of(&recovered).keys() {
        if !listed.contains(name) {
            git(&recovered, &["update-ref", "-d", name]);
        }
    }
}

fn manifest_lines<'a>(text: &'a str, first_token: &str) -> Vec<&'a str> {
    text.lines()
        .filter(|l| l.split(' ').next() == Some(first_token))
        .collect()
}

fn hand_manifest(
    of: ObjectFormat,
    vault_id: &str,
    counter: u64,
    seqfloor: u64,
    bundles: &[BundleRecord],
    refs: &[(&str, &str)],
    head: Option<&str>,
) -> Manifest {
    Manifest {
        format: 2,
        object_format: of,
        vault_id: vault_id.to_owned(),
        counter,
        seqfloor,
        bundles: bundles.iter().map(|b| (b.seq, b.clone())).collect(),
        head: head.map(str::to_owned),
        refs: refs
            .iter()
            .map(|(n, s)| (n.to_string(), s.to_string()))
            .collect(),
    }
}

fn blob_line(remote: &VaultRemote, name: &str, bytes: &[u8]) -> String {
    format!("100644 blob {}\t{name}", remote.store_blob(bytes))
}

// ===================== 1. Appendix A, literally =====================

#[test]
fn appendix_a_recovers_a_chunked_compacted_vault_with_stock_tools() {
    // §1 goal 1 / Appendix A: a Rust-written vault — chunked past ten parts
    // (cross-decade suffixes), compacted, then pushed to again — restored
    // with nothing but sh, git and age running the spec's own commands.
    let lab = Lab::new("c-appendix");
    let src = lab.source("src");
    git(&src.dir, &["config", "sealed.chunk-mb", "1"]);
    let c1 = src.commit_file("note.md", "one\n", "first");
    // refs/replace/*: an orphan commit (same tree) replaces c1 — objects
    // unreachable from any branch, which Appendix A promises to carry.
    let tree1 = rev(&src.dir, "HEAD^{tree}");
    let alt = git(&src.dir, &["commit-tree", &tree1, "-m", "alt"])
        .trim()
        .to_owned();
    git(&src.dir, &["replace", &c1, &alt]);
    let big = noise(10 * MIB + MIB / 2, 0xa11ce);
    fs::write(src.dir.join("big.bin"), &big).expect("write");
    git(&src.dir, &["add", "big.bin"]);
    git(&src.dir, &["commit", "-q", "-m", "big"]);
    let c2 = rev(&src.dir, "HEAD");
    git(&src.dir, &["branch", "side"]);
    let v1 = src.annotated_tag("v1");
    git(&src.dir, &["tag", "light"]);
    git(&src.dir, &["notes", "add", "-m", "a note", "HEAD"]);
    lab.push_ok(
        &src.dir,
        &[
            "main",
            "side",
            "v1",
            "light",
            "refs/notes/*:refs/notes/*",
            "refs/replace/*:refs/replace/*",
        ],
    );
    let m = lab.manifest();
    let parts = m.bundles[&1].chunks.expect("chunked");
    assert!(
        parts > 10,
        "cross-decade chunk suffixes wanted, got {parts}"
    );
    // §7.2: the chunk count in the manifest vs the tree.
    let in_tree = lab
        .files()
        .iter()
        .filter(|n| n.starts_with("1-full.bundle.age."))
        .count();
    assert_eq!(in_tree as u64, parts);
    assert!(lab.files().contains(&"1-full.bundle.age.10".to_string()));
    assert_eq!(m.refs[&format!("refs/replace/{c1}")], alt);
    assert!(m.refs.contains_key("refs/notes/commits"));

    // A second generation, then compaction folds both into one -full.
    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    let text = lab.compact_ok(&src.dir);
    assert!(text.contains("sequence 3"), "{text}");
    let m = lab.manifest();
    assert_eq!(m.bundles.len(), 1);
    assert!(m.bundles[&3].full && m.bundles[&3].chunks.expect("chunked") > 10);

    // A later incremental push: more noise (chunked into 2), a new tag, and
    // a branch deletion (manifest-only; the -full's header still claims it).
    let more = noise(MIB + MIB / 2, 0xb0b);
    fs::write(src.dir.join("more.bin"), &more).expect("write");
    git(&src.dir, &["add", "more.bin"]);
    git(&src.dir, &["commit", "-q", "-m", "more"]);
    let c4 = rev(&src.dir, "HEAD");
    let v2 = src.annotated_tag("v2");
    lab.push_ok(&src.dir, &["main", "v2", ":refs/heads/side"]);
    git(&src.dir, &["branch", "-D", "side"]);
    let m = lab.manifest();
    assert_eq!(m.bundles[&4].chunks, Some(2));
    assert!(!m.refs.contains_key("refs/heads/side"));
    assert_eq!(m.refs["refs/tags/v2"], v2);

    // ---- the recipe ----
    let files = vault_files_dir(&lab, "files");
    let listing = recipe::list_vault_dir(&files);
    assert_eq!(
        listing.highest_full.as_ref().map(|(_, n)| n.as_str()),
        Some("3-full.bundle.age")
    );
    assert_eq!(listing.incrementals, vec![(4, "4.bundle.age".to_owned())]);
    assert_eq!(listing.chunked.len(), 2, "both logical files are chunked");
    let script = run_appendix_a(&files);
    assert!(
        script.contains("age -d -i key.txt 3-full.bundle.age"),
        "{script}"
    );
    assert!(
        script.contains("age -d -i key.txt 4.bundle.age"),
        "{script}"
    );

    let recovered = files.join("recovered.git");
    let expected = refs_of(&src.dir);
    assert!(expected.contains_key("refs/notes/commits"));
    assert!(expected.contains_key(&format!("refs/replace/{c1}")));
    let got = refs_of(&recovered);
    for (name, sha) in &expected {
        assert_eq!(got.get(name), Some(sha), "{name} after the simple recipe");
    }
    assert_eq!(symref(&recovered), "refs/heads/main");
    git(&recovered, &["fsck", "--strict"]);
    // "The result reflects the bundles' embedded ref claims, which can lag
    // the manifest (a branch deleted since the last compaction may
    // reappear)": `side` is back, at the tip the -full bundle recorded.
    assert_eq!(got.get("refs/heads/side"), Some(&c2));
    assert_eq!(got["refs/tags/v1"], v1);

    let restored = files.join("restored");
    assert_eq!(rev(&restored, "HEAD"), c4);
    assert_eq!(fs::read(restored.join("big.bin")).expect("read"), big);
    assert_eq!(fs::read(restored.join("more.bin")).expect("read"), more);
    assert_eq!(
        tree_listing(&restored, "HEAD"),
        tree_listing(&src.dir, "refs/heads/main")
    );

    // The exact-refs restore paragraph removes the stale claim.
    exact_refs_restore(&files);
    assert_eq!(refs_of(&recovered), expected);
    assert_eq!(symref(&recovered), "refs/heads/main");
}

#[test]
fn appendix_a_paranoid_variant_checks_digests_and_stops_on_a_foreign_vault_id() {
    // Appendix A, "Adversarial-host recovery (paranoid variant)": trust
    // only the decrypted manifest — its bundle list, exact part sets, and
    // digests (`sha256sum` after reassembly) — and stop on an unexpected
    // `vault` id.
    let lab = Lab::new("c-paranoid");
    let src = lab.source("src");
    git(&src.dir, &["config", "sealed.chunk-mb", "1"]);
    let blob = noise(MIB + MIB / 5, 0x7a7a);
    fs::write(src.dir.join("blob.bin"), &blob).expect("write");
    git(&src.dir, &["add", "blob.bin"]);
    git(&src.dir, &["commit", "-q", "-m", "blob"]);
    src.commit_file("note.md", "x\n", "note");
    lab.push_ok(&src.dir, &["main"]);
    let expected_id = lab.manifest().vault_id.clone();

    let files = vault_files_dir(&lab, "files");
    let present_before = recipe::list_vault_dir(&files).canonical_names;
    run_appendix_a(&files); // reassembles the chunked -full as a side effect
    assert_eq!(rev(&files.join("restored"), "HEAD"), rev(&src.dir, "main"));

    let text =
        String::from_utf8(recipe::age_decrypt(&files, "sealed-manifest.age")).expect("UTF-8");
    let vault_line = manifest_lines(&text, "vault");
    assert_eq!(vault_line, vec![format!("vault {expected_id}").as_str()]);

    // Manifest-driven file set + digests, with stock tools only.
    let mut expected_files = BTreeSet::new();
    for line in manifest_lines(&text, "bundle") {
        let toks: Vec<&str> = line.split(' ').collect();
        assert!(toks.len() == 3 || toks.len() == 4, "{line}");
        let (name, digest) = (toks[1], toks[2]);
        match toks.get(3) {
            None => {
                expected_files.insert(name.to_owned());
            }
            Some(count) => {
                let count: u64 = count.parse().expect("count");
                assert!(count >= 2);
                for i in 0..count {
                    expected_files.insert(format!("{name}.{i}"));
                }
            }
        }
        // After reassembly the logical file exists: verify it.
        assert_eq!(recipe::sha256sum(&files, name), digest, "{name}");
    }
    assert_eq!(
        present_before, expected_files,
        "refuse any extra or missing file"
    );

    // Two vaults of one owner: the other's sealed-manifest.age DOES decrypt with this
    // key, and names a different vault — the stop condition.
    let other = Lab::sharing_identity("c-paranoid-other", &lab);
    let other_src = other.source("src");
    other_src.commit_file("note.md", "other\n", "first");
    other.push_ok(&other_src.dir, &["main"]);
    let other_files = vault_files_dir(&other, "files");
    let other_text =
        String::from_utf8(recipe::age_decrypt(&other_files, "sealed-manifest.age")).expect("UTF-8");
    let other_id = manifest_lines(&other_text, "vault")[0]
        .split(' ')
        .nth(1)
        .expect("id")
        .to_owned();
    assert_ne!(
        other_id, expected_id,
        "a human following the recipe stops here"
    );
}

#[test]
fn appendix_a_emptied_vault_recovers_to_nothing_then_fully() {
    // §9 / Appendix A: "An intentionally emptied vault (all refs deleted,
    // then compacted) contains no bundles and recovers to nothing — that is
    // not damage." Then a push re-roots it and recovery works again.
    let lab = Lab::new("c-emptied");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    lab.push_ok(&src.dir, &[":refs/heads/main"]);
    lab.compact_ok(&src.dir);
    assert_eq!(lab.files(), vec!["sealed-format", "sealed-manifest.age"]);

    let files = vault_files_dir(&lab, "files");
    let rec = recipe::recipe();
    let listing = recipe::list_vault_dir(&files);
    assert!(listing.canonical_names.is_empty());
    assert!(
        recipe::instantiate(&rec, &listing).is_none(),
        "nothing to recover"
    );
    let text =
        String::from_utf8(recipe::age_decrypt(&files, "sealed-manifest.age")).expect("UTF-8");
    assert!(manifest_lines(&text, "bundle").is_empty());
    assert!(!text.lines().any(|l| l.starts_with('@')), "{text}");
    assert!(
        !text
            .lines()
            .any(|l| l.split(' ').next().is_some_and(|t| t.len() == 40)),
        "no ref lines: {text}"
    );

    lab.push_ok(&src.dir, &["main"]);
    assert_eq!(seqs(&lab.manifest()), vec![(2, true, None)]);
    let files = vault_files_dir(&lab, "files-after");
    run_appendix_a(&files);
    let recovered = files.join("recovered.git");
    assert_eq!(rev(&recovered, "refs/heads/main"), c1);
    assert_eq!(symref(&recovered), "refs/heads/main");
    assert_eq!(rev(&files.join("restored"), "HEAD"), c1);
}

#[test]
fn appendix_a_propagates_a_non_main_head_symref() {
    // §4.3 HEAD entry: "so that stock `git clone <bundle>` checks out the
    // right branch during disaster recovery" — with the source HEAD on a
    // branch that is not `main`.
    let lab = Lab::new("c-head");
    let src = lab.source_on("src", "sha1", "devel");
    let c1 = src.commit_file("note.md", "one\n", "first");
    git(&src.dir, &["branch", "main"]);
    let c2 = src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["devel", "main"]);
    assert_eq!(lab.manifest().head.as_deref(), Some("refs/heads/devel"));

    let dest = lab.clone_ok("clone");
    assert_eq!(symref(&dest), "refs/heads/devel");

    let files = vault_files_dir(&lab, "files");
    run_appendix_a(&files);
    let recovered = files.join("recovered.git");
    assert_eq!(symref(&recovered), "refs/heads/devel");
    assert_eq!(rev(&recovered, "refs/heads/main"), c1);
    let restored = files.join("restored");
    assert_eq!(symref(&restored), "refs/heads/devel");
    assert_eq!(rev(&restored, "HEAD"), c2);
}

#[test]
fn sha256_source_pushes_clones_compacts_and_recovers() {
    // §3 object formats through the WRITER (read_e2e covers a hand-built
    // sha256 vault): v3 bundle header with the capability, 64-hex refs,
    // compaction, and the stock-tools recovery on a sha256 vault.
    let lab = Lab::new("c-sha256");
    let src = lab.source_on("src", "sha256", "main");
    let c1 = src.commit_file("note.md", "one\n", "first");
    let tag = src.annotated_tag("v1");
    assert_eq!(c1.len(), 64);
    lab.push_ok(&src.dir, &["main", "v1"]);
    let m = lab.manifest();
    assert_eq!(m.object_format, ObjectFormat::Sha256);
    assert_eq!(m.refs["refs/heads/main"], c1);
    let plain = crypt::decrypt(
        std::slice::from_ref(&lab.identity),
        &lab.remote.file_bytes("main", "1-full.bundle.age"),
    )
    .expect("decrypts");
    manifest::verify_bundle_header(&plain, ObjectFormat::Sha256).expect("§4.3 v3 + capability");
    assert!(plain.starts_with(b"# v3 git bundle\n@object-format=sha256\n"));

    let dest = lab.clone_ok("clone");
    assert_eq!(
        git(&dest, &["rev-parse", "--show-object-format"]).trim(),
        "sha256"
    );
    assert_eq!(rev(&dest, "refs/tags/v1"), tag);

    let c2 = src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    lab.compact_ok(&src.dir);
    let m = lab.manifest();
    assert_eq!(seqs(&m), vec![(3, true, None)]);
    assert_eq!(m.refs["refs/heads/main"], c2);
    assert_ok(&lab.fetch(&dest), "fetch across compaction");
    assert_eq!(rev(&dest, "refs/remotes/origin/main"), c2);

    let files = vault_files_dir(&lab, "files");
    run_appendix_a(&files);
    let recovered = files.join("recovered.git");
    assert_eq!(
        git(&recovered, &["rev-parse", "--show-object-format"]).trim(),
        "sha256"
    );
    assert_eq!(rev(&recovered, "refs/heads/main"), c2);
    assert_eq!(rev(&recovered, "refs/tags/v1"), tag);
    assert_eq!(rev(&files.join("restored"), "HEAD"), c2);
}

// ===================== 2. Adversarial host =====================

#[test]
fn twin_fork_with_equal_counter_is_refused() {
    // §7.4 twin check: two manifests with the SAME counter and different
    // content; a device pinned on one is served the other.
    let lab = Lab::new("c-twin");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let gen1 = lab.remote.tip("main");
    let dest = lab.clone_ok("clone");
    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    assert_ok(&lab.fetch(&dest), "pinned at generation 2");

    // The twin: a losing concurrent push's genuine commit (counter 2, same
    // bundle files, main at c1) replayed by the host on top of generation 1.
    let mut files = lab.remote.blob_files("main");
    let mut twin = lab.manifest();
    assert_eq!(twin.counter, 2);
    twin.refs.insert("refs/heads/main".into(), c1.clone());
    files.retain(|(n, _)| n != "sealed-manifest.age");
    add_manifest(&mut files, &lab.identity.to_public(), &twin);
    lab.remote.set_branch("main", &gen1);
    lab.remote.commit(&files, "main");

    let out = lab.fetch(&dest);
    assert!(!out.status.success(), "the twin must be refused");
    assert!(
        stderr_of(&out)
            .contains("vault forked: a different manifest with the already-seen counter 2"),
        "stderr: {}",
        stderr_of(&out)
    );
    // The writer that produced generation 2 refuses it too.
    src.commit_file("note.md", "three\n", "third");
    let out = lab.push(&src.dir, &["main"]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("vault forked"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn resurrected_pre_compaction_file_is_refused() {
    // §6.4 / §9: "reintroduction of compacted-away files" — the host keeps
    // an old ciphertext and puts it back after a compaction.
    let lab = Lab::new("c-resurrect");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let old = lab.remote.file_bytes("main", "1-full.bundle.age");
    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    lab.compact_ok(&src.dir);
    assert_eq!(
        lab.files(),
        vec!["3-full.bundle.age", "sealed-format", "sealed-manifest.age"]
    );

    let mut lines = lab.remote.tree_lines("main");
    lines.push(blob_line(&lab.remote, "1-full.bundle.age", &old));
    lab.remote.commit_lines(&lines, "main");

    let expected = "vault tree has a bundle file the manifest does not list: 1-full.bundle.age";
    let (_, out) = lab.clone("fresh");
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains(expected), "{}", stderr_of(&out));
    let out = lab.fetch(&src.dir);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains(expected), "{}", stderr_of(&out));
}

#[test]
fn decoys_are_ignored_on_read_and_stripped_on_every_rewrite() {
    // §3 carve-out: bundle-shaped non-canonical entries (leading zero, wrong
    // letter case) are ignored by readers and dropped on any tree rewrite;
    // a genuinely unknown file and a subtree are preserved.
    let lab = Lab::new("c-decoys");
    let src = lab.source("src");
    let c1 = src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);

    let sub = lab
        .remote
        .store_tree(&[blob_line(&lab.remote, "x.txt", b"x\n")]);
    let planted = ["07.bundle.age", "999-FULL.bundle.age", "future.dat", "ext"];
    let plant = |lab: &Lab| {
        let mut lines = lab.remote.tree_lines("main");
        lines.retain(|l| !planted.contains(&l.split('\t').nth(1).expect("name")));
        lines.push(blob_line(&lab.remote, "07.bundle.age", b"decoy"));
        lines.push(blob_line(&lab.remote, "999-FULL.bundle.age", b"decoy"));
        lines.push(blob_line(&lab.remote, "future.dat", b"future\n"));
        lines.push(format!("040000 tree {sub}\text"));
        lab.remote.commit_lines(&lines, "main");
    };
    plant(&lab);
    assert!(lab.files().contains(&"07.bundle.age".to_string()));
    assert!(lab.files().contains(&"999-FULL.bundle.age".to_string()));
    let dest = lab.clone_ok("clone");
    assert_eq!(rev(&dest, "refs/heads/main"), c1);

    let surviving = |lab: &Lab, bundle: &str| {
        let lines = lab.remote.tree_lines("main");
        let names: Vec<String> = lines
            .iter()
            .map(|l| l.split('\t').nth(1).expect("name").to_owned())
            .collect();
        assert!(
            lines
                .iter()
                .any(|l| l == &format!("040000 tree {sub}\text")),
            "subtree preserved verbatim: {lines:?}"
        );
        assert_eq!(lab.remote.file_bytes("main", "future.dat"), b"future\n");
        assert_eq!(
            names,
            vec![
                bundle,
                "ext",
                "future.dat",
                "sealed-format",
                "sealed-manifest.age"
            ]
        );
    };

    // §3: "on any tree rewrite" — a push rewrites the tree.
    let c2 = src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    let names = lab.remote.files("main");
    assert!(!names
        .iter()
        .any(|n| n.contains("07.") || n.contains("FULL")));
    assert!(names.contains(&"future.dat".to_string()));

    // Planted again, then compaction strips them while the history rewrite
    // preserves the unknown file and the subtree.
    plant(&lab);
    lab.compact_ok(&src.dir);
    surviving(&lab, "3-full.bundle.age");
    assert_eq!(lab.remote.commit_count("main"), 1);
    let third = lab.clone_ok("third");
    assert_eq!(rev(&third, "refs/heads/main"), c2);
}

#[test]
fn hint_version_1_over_a_v2_tree_is_refused() {
    // §3 / Appendix A "old-tool symptom" in reverse: a host misreporting
    // `sealed-format` as 1 over a v2 tree is refused as unsupported — the
    // hint fast-fails, and never selects v1 semantics.
    let lab = Lab::new("c-hint1");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let mut files = lab.remote.blob_files("main");
    files.retain(|(n, _)| n != "sealed-format");
    files.push(("sealed-format".into(), b"1\n".to_vec()));
    lab.remote.commit(&files, "main");
    let (_, out) = lab.clone("clone");
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("unsupported vault format '1'"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn sequence_rebinding_is_refused_by_the_memory() {
    // §7.4 sequence memory: a manifest that binds a remembered sequence
    // number to a different ciphertext is invalid on this device (a fresh
    // device, with no memory, cannot know better — §10).
    let lab = Lab::new("c-rebind");
    let src = lab.source("src");
    src.commit_file("note.md", "one\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    let c2 = src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    let dest = lab.clone_ok("clone");

    let plain = crypt::decrypt(
        std::slice::from_ref(&lab.identity),
        &lab.remote.file_bytes("main", "2.bundle.age"),
    )
    .expect("decrypts");
    let rebound = crypt::encrypt(&[lab.identity.to_public()], &plain).expect("encrypt");
    let mut m = lab.manifest();
    m.counter += 1;
    m.bundles.get_mut(&2).expect("sequence 2").digest = sha256_hex(&rebound);
    let mut files = lab.remote.blob_files("main");
    files.retain(|(n, _)| n != "sealed-manifest.age" && n != "2.bundle.age");
    files.push(("2.bundle.age".into(), rebound));
    add_manifest(&mut files, &lab.identity.to_public(), &m);
    lab.remote.commit(&files, "main");

    let out = lab.fetch(&dest);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains(
            "sequence number 2 is bound to a different bundle than this device accepted before"
        ),
        "{}",
        stderr_of(&out)
    );
    let fresh = lab.clone_ok("fresh");
    assert_eq!(rev(&fresh, "refs/heads/main"), c2);
}

// ===================== 3. What the host sees =====================

#[test]
fn host_sees_no_source_names_contents_or_refnames() {
    // §1 / §10: "not file contents, not filenames, not ref names, not commit
    // metadata". Every object in the vault repository and every ref and
    // tree-entry name is searched for distinctive tokens from the source.
    let tokens = [
        "zebrafish",
        "purple-octopus",
        "wombat",
        "kumquat",
        "marmoset",
    ];
    let lab = Lab::new("c-host");
    let src = lab.source("src");
    src.commit_file(
        "zebrafish-ledger.md",
        "PURPLE-OCTOPUS-4711 is the secret\n",
        "Commit message: WOMBAT-TELEGRAM",
    );
    git(&src.dir, &["branch", "kumquat-harvest"]);
    git(
        &src.dir,
        &["tag", "-a", "marmoset-release", "-m", "Marmoset"],
    );
    lab.push_ok(&src.dir, &["main", "kumquat-harvest", "marmoset-release"]);
    src.commit_file(
        "zebrafish-ledger.md",
        "PURPLE-OCTOPUS-4712\n",
        "WOMBAT again",
    );
    lab.push_ok(&src.dir, &["main"]);

    let dump = |repo: &Path| -> Vec<u8> {
        let mut bytes = git_cmd(repo, &["cat-file", "--batch-all-objects", "--batch"])
            .output()
            .expect("git")
            .stdout;
        bytes.extend(git(repo, &["for-each-ref"]).into_bytes());
        for commit in git(repo, &["rev-list", "--all"]).lines() {
            bytes.extend(git(repo, &["ls-tree", "-r", commit]).into_bytes());
        }
        bytes.to_ascii_lowercase()
    };
    let contains =
        |hay: &[u8], needle: &str| hay.windows(needle.len()).any(|w| w == needle.as_bytes());

    // Positive control: the search finds the tokens where they DO exist.
    let source_dump = dump(&src.dir);
    for t in tokens {
        assert!(contains(&source_dump, t), "control: {t} in the source dump");
    }
    let vault_dump = dump(&lab.remote.dir);
    assert!(vault_dump.len() > 1000, "the vault holds objects");
    for t in tokens {
        assert!(!contains(&vault_dump, t), "the host can see {t:?}");
    }
    // Only what §10 declares: the vault branch, the bundle files by name.
    assert_eq!(
        git(&lab.remote.dir, &["for-each-ref", "--format=%(refname)"]).trim(),
        "refs/heads/main"
    );
}

// ===================== 4. Ref-shape and branch-selection edges =====================

/// A hand-built generation 1 (one `-full` bundle of `bundle_bytes`, main
/// at `main_sha`) committed on `branch` of `remote`.
fn hand_generation(
    remote: &VaultRemote,
    identity: &Identity,
    branch: &str,
    bundle_bytes: &[u8],
    main_sha: &str,
    vault_id: &str,
) {
    let mut files = Vec::new();
    add_hint(&mut files);
    let rec = add_bundle(
        &mut files,
        &identity.to_public(),
        1,
        true,
        bundle_bytes,
        None,
    );
    let m = hand_manifest(
        ObjectFormat::Sha1,
        vault_id,
        1,
        1,
        &[rec],
        &[("refs/heads/main", main_sha)],
        Some("refs/heads/main"),
    );
    add_manifest(&mut files, &identity.to_public(), &m);
    remote.commit(&files, branch);
}

#[test]
fn pushes_follow_the_remote_head_to_a_non_main_branch() {
    // §3: a non-empty remote's default branch (remote HEAD) is the vault
    // branch — here `trunk`, never `main`.
    let scratch = scratch("c-trunk");
    let identity = Identity::generate();
    let id_file = identity_file(&scratch, &identity);
    let remote = VaultRemote::init_named(scratch.join("vault.git"), "sha1", "trunk");
    let src = SourceRepo::init(scratch.join("src"), "sha1");
    let c1 = src.commit_file("note.md", "one\n", "first");
    let b1 = src.bundle(&scratch.join("b1.bundle"), &["HEAD", "--all"]);
    hand_generation(&remote, &identity, "trunk", &b1, &c1, &"ab".repeat(16));

    src.add_remote("origin", &remote.sealed_url());
    let c2 = src.commit_file("note.md", "two\n", "second");
    let out = sealed_git(&src.dir, &["push", "-q", "origin", "main"], &id_file, &[]);
    assert_ok(&out, "push to a trunk-rooted vault");
    assert_eq!(remote.commit_count("trunk"), 2);
    assert!(git_try(&remote.dir, &["rev-parse", "--verify", "refs/heads/main"]).is_none());
    let m = remote.manifest("trunk", &identity);
    assert_eq!(m.refs["refs/heads/main"], c2);
    assert_eq!(seqs(&m), vec![(1, true, None), (2, false, None)]);

    let out = sealed_git(
        &scratch,
        &["clone", "-q", &remote.sealed_url(), "clone"],
        &id_file,
        &[],
    );
    assert_ok(&out, "clone");
    assert_eq!(rev(&scratch.join("clone"), "refs/heads/main"), c2);
}

#[test]
fn dangling_remote_head_falls_back_to_main_then_the_first_branch() {
    // §3: "If the remote is non-empty but has no usable HEAD (unset or
    // dangling): use `main` if a branch of that name exists, else the
    // lexicographically first branch."
    let scratch = scratch("c-dangling");
    let identity = Identity::generate();
    let id_file = identity_file(&scratch, &identity);
    let remote = VaultRemote::init_named(scratch.join("vault.git"), "sha1", "gone");
    let src = SourceRepo::init(scratch.join("src"), "sha1");
    let mut shas = Vec::new();
    let mut bundles = Vec::new();
    for i in 1..=3 {
        shas.push(src.commit_file("note.md", &format!("{i}\n"), &format!("c{i}")));
        bundles.push(src.bundle(&scratch.join(format!("b{i}.bundle")), &["HEAD", "--all"]));
    }
    // Two branches, neither `main`: `apple` sorts before `zed`.
    hand_generation(
        &remote,
        &identity,
        "zed",
        &bundles[0],
        &shas[0],
        &"01".repeat(16),
    );
    hand_generation(
        &remote,
        &identity,
        "apple",
        &bundles[1],
        &shas[1],
        &"02".repeat(16),
    );
    let clone = |name: &str| -> PathBuf {
        let out = sealed_git(
            &scratch,
            &["clone", "-q", &remote.sealed_url(), name],
            &id_file,
            &[],
        );
        assert_ok(&out, "clone");
        scratch.join(name)
    };
    assert_eq!(
        rev(&clone("first"), "refs/heads/main"),
        shas[1],
        "apple, not zed"
    );

    // Now `main` exists: it wins over the alphabet.
    hand_generation(
        &remote,
        &identity,
        "main",
        &bundles[2],
        &shas[2],
        &"03".repeat(16),
    );
    assert_eq!(rev(&clone("second"), "refs/heads/main"), shas[2]);
}

// ===================== 5. Multi-recipient =====================

#[test]
fn three_recipients_can_each_clone() {
    // §5: the recipient set is own + every `sealed.recipients` value.
    let lab = Lab::new("c-three");
    let second = Identity::generate();
    let third = Identity::generate();
    let second_file = identity_file_named(&lab.scratch, "second.txt", &second);
    let third_file = identity_file_named(&lab.scratch, "third.txt", &third);
    let src = lab.source("src");
    git(
        &src.dir,
        &[
            "config",
            "--add",
            "sealed.recipients",
            &second.to_public().to_string(),
        ],
    );
    git(
        &src.dir,
        &[
            "config",
            "--add",
            "sealed.recipients",
            &third.to_public().to_string(),
        ],
    );
    let c1 = src.commit_file("note.md", "shared by three\n", "first");
    lab.push_ok(&src.dir, &["main"]);
    src.commit_file("note.md", "and again\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    let c2 = rev(&src.dir, "HEAD");

    for (name, file) in [
        ("own", lab.id_file.clone()),
        ("second", second_file),
        ("third", third_file),
    ] {
        let (dest, out) = lab.clone_with(&file, name);
        assert_ok(&out, &format!("clone as {name}"));
        assert_eq!(rev(&dest, "refs/heads/main"), c2);
        assert_eq!(rev(&dest, "HEAD~1"), c1);
    }
    let out = cli(&src.dir, &lab.id_file, &["info", "origin"]);
    assert_ok(&out, "info");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(&second.to_public().to_string()), "{text}");
    assert!(text.contains(&third.to_public().to_string()), "{text}");
}

// ===================== 6. Wrong-format bundle header =====================

#[test]
fn wrong_bundle_header_version_is_refused_both_ways() {
    // §4.3: "a v3 bundle in a sha1 vault is an error, not a tolerance" —
    // and the mirror image.
    let scratch = scratch("c-header");
    let identity = Identity::generate();
    let id_file = identity_file(&scratch, &identity);
    let recipient = identity.to_public();

    let src256 = SourceRepo::init(scratch.join("src256"), "sha256");
    let c256 = src256.commit_file("note.md", "one\n", "first");
    let v3 = src256.bundle(&scratch.join("v3.bundle"), &["HEAD", "--all"]);
    let src1 = SourceRepo::init(scratch.join("src1"), "sha1");
    let c1 = src1.commit_file("note.md", "one\n", "first");
    let v2 = src1.bundle(&scratch.join("v2.bundle"), &["HEAD", "--all"]);

    let cases: [(&str, ObjectFormat, &[u8], String, &str); 2] = [
        // manifest says sha1, plaintext is a v3 bundle; a 40-hex ref line.
        (
            "sha1-v3",
            ObjectFormat::Sha1,
            &v3,
            c256[..40].to_owned(),
            "\"# v3 git bundle\"",
        ),
        // manifest says sha256, plaintext is a v2 bundle; a 64-hex ref line.
        (
            "sha256-v2",
            ObjectFormat::Sha256,
            &v2,
            format!("{c1}{}", "0".repeat(24)),
            "\"# v2 git bundle\"",
        ),
    ];
    for (tag, of, bundle, sha, expected) in cases {
        let remote = VaultRemote::init(scratch.join(format!("{tag}.git")));
        let mut files = Vec::new();
        add_hint(&mut files);
        let rec = add_bundle(&mut files, &recipient, 1, true, bundle, None);
        let m = hand_manifest(
            of,
            &"cd".repeat(16),
            1,
            1,
            &[rec],
            &[("refs/heads/main", &sha)],
            Some("refs/heads/main"),
        );
        add_manifest(&mut files, &recipient, &m);
        remote.commit(&files, "main");
        let out = sealed_git(
            &scratch,
            &["clone", "-q", &remote.sealed_url(), tag],
            &id_file,
            &[],
        );
        assert!(!out.status.success(), "{tag}: clone must fail");
        let err = stderr_of(&out);
        assert!(
            err.contains("bundle header does not match the vault object format")
                && err.contains(expected),
            "{tag}: {err}"
        );
    }
}

// ===================== 7. Interop fixture =====================

/// Recursive copy of a directory tree (the bare vault repository).
fn write_fixture(lab: &Lab, src: &SourceRepo, out: &Path) {
    let dir = out.join("rust-v2-sha1");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("fixture dir");
    git(
        &dir,
        &["clone", "-q", "--mirror", &lab.remote.url(), "vault.git"],
    );
    fs::copy(&lab.id_file, dir.join("identity.txt")).expect("identity");
    let refs = refs_of(&src.dir)
        .iter()
        .map(|(n, s)| format!("{s} {n}\n"))
        .collect::<String>();
    fs::write(dir.join("expected-refs.txt"), refs).expect("refs");
    fs::write(
        dir.join("expected-head.txt"),
        format!("{}\n", symref(&src.dir)),
    )
    .expect("head");
    fs::write(
        dir.join("expected-tree.txt"),
        tree_listing(&src.dir, "refs/heads/main"),
    )
    .expect("tree");
    fs::write(
        dir.join("expected-manifest.txt"),
        lab.manifest().to_text().expect("serializable"),
    )
    .expect("manifest");
    fs::write(
        dir.join("README.txt"),
        "sealed vault format v2 interop fixture, written by sealed-rs (tests/claims_e2e.rs).\n\
         vault.git/            the vault repository exactly as a host holds it (bare mirror)\n\
         identity.txt          the age identity every file is encrypted to (comment lines + secret)\n\
         expected-refs.txt     `<sha> <refname>` the manifest lists (= the source's refs)\n\
         expected-head.txt     the manifest HEAD symref target\n\
         expected-tree.txt     `git ls-tree -r` of refs/heads/main in the source\n\
         expected-manifest.txt the decrypted sealed-manifest.age, verbatim\n\
         History: push (chunked 1 MiB parts, notes, annotated tag) -> compaction -> incremental\n\
         push (lightweight tag); read it with any v2 implementation + identity.txt.\n",
    )
    .expect("readme");
}

#[test]
fn interop_fixture_round_trips_and_is_exported_on_request() {
    // A small canonical Rust-written vault (sha1, chunked, compacted +
    // incremental, tags + notes). With SEALED_FIXTURE_OUT set it is copied
    // out for the Kotlin port's interop tests (layout: README.md).
    let lab = Lab::new("c-fixture");
    let src = lab.source("src");
    git(&src.dir, &["config", "sealed.chunk-mb", "1"]);
    src.commit_file("note.md", "one\n", "first");
    git(&src.dir, &["notes", "add", "-m", "fixture note", "HEAD"]);
    let blob = noise(MIB + MIB / 5, 0xf1f);
    fs::write(src.dir.join("blob.bin"), &blob).expect("write");
    git(&src.dir, &["add", "blob.bin"]);
    git(&src.dir, &["commit", "-q", "-m", "blob"]);
    let v1 = src.annotated_tag("v1");
    lab.push_ok(&src.dir, &["main", "v1", "refs/notes/*:refs/notes/*"]);
    src.commit_file("note.md", "two\n", "second");
    lab.push_ok(&src.dir, &["main"]);
    lab.compact_ok(&src.dir);
    let c4 = src.commit_file("note.md", "three\n", "third");
    git(&src.dir, &["tag", "light"]);
    lab.push_ok(&src.dir, &["main", "light"]);

    let m = lab.manifest();
    assert_eq!(seqs(&m), vec![(3, true, Some(2)), (4, false, None)]);
    assert_eq!(m.refs["refs/tags/v1"], v1);
    assert_eq!(m.refs["refs/tags/light"], c4);
    assert!(m.refs.contains_key("refs/notes/commits"));
    let dest = lab.clone_ok("clone");
    assert_eq!(rev(&dest, "refs/heads/main"), c4);
    assert_eq!(fs::read(dest.join("blob.bin")).expect("read"), blob);
    assert_eq!(refs_of(&src.dir).len(), 4);

    if let Some(out) = std::env::var_os("SEALED_FIXTURE_OUT") {
        write_fixture(&lab, &src, Path::new(&out));
        let dir = Path::new(&out).join("rust-v2-sha1");
        assert!(dir.join("vault.git").join("HEAD").is_file());
        assert_eq!(
            VaultRemote {
                dir: dir.join("vault.git")
            }
            .files("main"),
            lab.files()
        );
        let secret = fs::read_to_string(dir.join("identity.txt")).expect("identity");
        assert!(secret.contains(lab.identity.to_string().expose_secret()));
    }
}
