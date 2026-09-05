//! Shared helpers for the integration tests: hermetic git invocation,
//! scratch directories, a hand-built source repository, a hand-built vault
//! remote (bare git repository written with plumbing — no checkout, so no
//! transformation can touch the ciphertexts), chunking, and running real
//! `git` against the built `git-remote-sealed` binary.
//!
//! Each integration-test binary compiles this module separately and uses
//! only part of it, hence the dead-code allowance.
#![allow(dead_code)]

pub mod appendix_a;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Duration;

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use sealed::manifest::{self, BundleRecord, Manifest};
use sealed::names::BundleName;
use sealed::{crypt, sha256_hex};

/// Keep every git invocation independent of the host's configuration and
/// identity (author/committer fixed; no system or global config).
pub const HERMETIC_ENV: &[(&str, &str)] = &[
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_AUTHOR_NAME", "sealed"),
    ("GIT_AUTHOR_EMAIL", "sealed@invalid"),
    ("GIT_COMMITTER_NAME", "sealed"),
    ("GIT_COMMITTER_EMAIL", "sealed@invalid"),
    ("GIT_AUTHOR_DATE", "1970-01-01T00:00:00Z"),
    ("GIT_COMMITTER_DATE", "1970-01-01T00:00:00Z"),
];

pub fn git_cmd(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).args(args);
    for (k, v) in HERMETIC_ENV {
        cmd.env(k, v);
    }
    cmd
}

/// Run git, asserting success; returns stdout.
pub fn git(dir: &Path, args: &[&str]) -> String {
    let output = git_cmd(dir, args).output().expect("git must be runnable");
    assert_ok(
        &output,
        &format!("git -C {} {}", dir.display(), args.join(" ")),
    );
    String::from_utf8(output.stdout).expect("git output is UTF-8")
}

/// Run git, returning stdout only on success.
pub fn git_try(dir: &Path, args: &[&str]) -> Option<String> {
    let output = git_cmd(dir, args).output().expect("git must be runnable");
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).expect("git output is UTF-8"))
}

/// Run git with bytes on stdin, asserting success; returns stdout.
pub fn git_stdin(dir: &Path, args: &[&str], input: &[u8]) -> String {
    let mut child = git_cmd(dir, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("git must be runnable");
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(input)
        .expect("write stdin");
    let output = child.wait_with_output().expect("git exits");
    assert_ok(
        &output,
        &format!("git -C {} {}", dir.display(), args.join(" ")),
    );
    String::from_utf8(output.stdout).expect("git output is UTF-8")
}

pub fn assert_ok(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

pub fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A fresh scratch directory, unique per (process, tag) so tests in one
/// binary can run in parallel.
pub fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sealed-rs-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

// --- the source repository (what gets backed up) ---

pub struct SourceRepo {
    pub dir: PathBuf,
}

impl SourceRepo {
    pub fn init(dir: PathBuf, object_format: &str) -> SourceRepo {
        SourceRepo::init_on(dir, object_format, "main")
    }

    /// A source repository whose initial (HEAD) branch is `branch`.
    pub fn init_on(dir: PathBuf, object_format: &str, branch: &str) -> SourceRepo {
        fs::create_dir_all(&dir).expect("mkdir src");
        let flag = format!("--object-format={object_format}");
        git(&dir, &["init", "-q", "-b", branch, &flag]);
        SourceRepo { dir }
    }

    /// Write `name`, commit it, return the commit id.
    pub fn commit_file(&self, name: &str, content: &str, message: &str) -> String {
        fs::write(self.dir.join(name), content).expect("write file");
        git(&self.dir, &["add", name]);
        git(&self.dir, &["commit", "-q", "-m", message]);
        self.rev("HEAD")
    }

    pub fn rev(&self, rev: &str) -> String {
        git(&self.dir, &["rev-parse", "--verify", rev])
            .trim()
            .to_owned()
    }

    /// `git remote add <name> <url>`.
    pub fn add_remote(&self, name: &str, url: &str) {
        git(&self.dir, &["remote", "add", name, url]);
    }

    /// An annotated tag on HEAD; returns the tag object id.
    pub fn annotated_tag(&self, name: &str) -> String {
        git(&self.dir, &["tag", "-a", name, "-m", name]);
        self.rev(&format!("refs/tags/{name}"))
    }

    /// `git bundle create <path> <revs...>`; returns the bundle bytes.
    pub fn bundle(&self, path: &Path, revs: &[&str]) -> Vec<u8> {
        let mut args = vec!["bundle", "create", path.to_str().expect("utf-8 path")];
        args.extend_from_slice(revs);
        git(&self.dir, &args);
        fs::read(path).expect("read bundle")
    }
}

// --- the vault remote (§3: an ordinary git repository) ---

pub struct VaultRemote {
    pub dir: PathBuf,
}

impl VaultRemote {
    /// A bare repository whose HEAD points at `main` (§3 branch selection
    /// takes the remote HEAD).
    pub fn init(dir: PathBuf) -> VaultRemote {
        VaultRemote::init_with_format(dir, "sha1")
    }

    /// §3: the vault repository is host-default — any object format.
    pub fn init_with_format(dir: PathBuf, object_format: &str) -> VaultRemote {
        VaultRemote::init_named(dir, object_format, "main")
    }

    /// A bare repository whose HEAD symref names `branch` — which need
    /// never be created (a dangling HEAD, §3's fallback chain).
    pub fn init_named(dir: PathBuf, object_format: &str, branch: &str) -> VaultRemote {
        fs::create_dir_all(&dir).expect("mkdir vault");
        let flag = format!("--object-format={object_format}");
        git(&dir, &["init", "-q", "--bare", "-b", branch, &flag]);
        VaultRemote { dir }
    }

    /// Raw `ls-tree` lines of the branch's root tree, in mktree's input
    /// shape (`<mode> SP <type> SP <oid> TAB <name>`), every entry kind.
    pub fn tree_lines(&self, branch: &str) -> Vec<String> {
        git(&self.dir, &["ls-tree", &format!("refs/heads/{branch}")])
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Store a blob in the vault repository; returns its object id.
    pub fn store_blob(&self, bytes: &[u8]) -> String {
        git_stdin(&self.dir, &["hash-object", "-w", "--stdin"], bytes)
            .trim()
            .to_owned()
    }

    /// Build a subtree from mktree lines; returns its tree id.
    pub fn store_tree(&self, lines: &[String]) -> String {
        let input = lines.iter().map(|l| format!("{l}\n")).collect::<String>();
        git_stdin(&self.dir, &["mktree"], input.as_bytes())
            .trim()
            .to_owned()
    }

    /// Commit a root tree given as raw mktree lines (parent = the branch's
    /// current tip, if any). Lets a test plant subtrees, decoys, or old
    /// blobs exactly as a host would. Returns the commit id.
    pub fn commit_lines(&self, lines: &[String], branch: &str) -> String {
        let tree = self.store_tree(lines);
        let full_ref = format!("refs/heads/{branch}");
        let parent = git_try(&self.dir, &["rev-parse", "--verify", "--quiet", &full_ref]);
        let mut args = vec!["commit-tree", tree.as_str(), "-m", "vault"];
        let parent = parent.map(|p| p.trim().to_owned());
        if let Some(p) = &parent {
            args.push("-p");
            args.push(p);
        }
        let commit = git(&self.dir, &args).trim().to_owned();
        self.set_branch(branch, &commit);
        commit
    }

    /// The vault branch's current tip.
    pub fn tip(&self, branch: &str) -> String {
        git(
            &self.dir,
            &["rev-parse", "--verify", &format!("refs/heads/{branch}")],
        )
        .trim()
        .to_owned()
    }

    /// Root tree file names of the vault branch, sorted.
    pub fn files(&self, branch: &str) -> Vec<String> {
        let mut names: Vec<String> = git(
            &self.dir,
            &["ls-tree", "--name-only", &format!("refs/heads/{branch}")],
        )
        .lines()
        .map(str::to_owned)
        .collect();
        names.sort();
        names
    }

    /// Raw bytes of one root tree blob.
    pub fn file_bytes(&self, branch: &str, name: &str) -> Vec<u8> {
        let spec = format!("refs/heads/{branch}:{name}");
        let output = git_cmd(&self.dir, &["cat-file", "blob", &spec])
            .output()
            .expect("git must be runnable");
        assert_ok(&output, &format!("cat-file blob {spec}"));
        output.stdout
    }

    /// Decrypt and parse the manifest on the vault branch.
    pub fn manifest(&self, branch: &str, identity: &Identity) -> Manifest {
        let cipher = self.file_bytes(branch, "sealed-manifest.age");
        let plain =
            crypt::decrypt(std::slice::from_ref(identity), &cipher).expect("manifest decrypts");
        manifest::parse(&plain).expect("manifest parses").manifest
    }

    /// Length of the vault branch's history (compaction leaves 1).
    pub fn commit_count(&self, branch: &str) -> u64 {
        git(
            &self.dir,
            &["rev-list", "--count", &format!("refs/heads/{branch}")],
        )
        .trim()
        .parse()
        .expect("count")
    }

    /// Commit `files` as the root tree of `branch` (parent = the branch's
    /// current tip, if any), via plumbing only. Returns the commit id.
    pub fn commit(&self, files: &[(String, Vec<u8>)], branch: &str) -> String {
        let lines: Vec<String> = files
            .iter()
            .map(|(name, bytes)| format!("100644 blob {}\t{name}", self.store_blob(bytes)))
            .collect();
        self.commit_lines(&lines, branch)
    }

    /// The current root tree as (name, bytes) pairs — blobs only — so a
    /// test can edit one file and recommit the rest unchanged.
    pub fn blob_files(&self, branch: &str) -> Vec<(String, Vec<u8>)> {
        self.files(branch)
            .into_iter()
            .map(|n| {
                let bytes = self.file_bytes(branch, &n);
                (n, bytes)
            })
            .collect()
    }

    /// Point `branch` at `commit` (used to simulate a host rollback).
    pub fn set_branch(&self, branch: &str, commit: &str) {
        let full_ref = format!("refs/heads/{branch}");
        git(&self.dir, &["update-ref", &full_ref, commit]);
    }

    /// The path git will hand the helper (after stripping `sealed::`).
    pub fn url(&self) -> String {
        self.dir.to_str().expect("utf-8 path").to_owned()
    }

    pub fn sealed_url(&self) -> String {
        format!("sealed::{}", self.url())
    }
}

// --- vault file construction ---

/// §3: the ASCII decimal version plus a single LF.
pub fn add_hint(files: &mut Vec<(String, Vec<u8>)>) {
    files.push(("sealed-format".into(), b"2\n".to_vec()));
}

/// §4.2: split ciphertext into `n` nonempty parts at uneven, arbitrary
/// byte boundaries (nothing in the format depends on where the cuts are).
pub fn chunk(cipher: &[u8], n: usize) -> Vec<Vec<u8>> {
    assert!(
        n >= 2 && cipher.len() >= n * 8,
        "payload too small to chunk"
    );
    let mut cuts = vec![0usize];
    for i in 1..n {
        cuts.push(cipher.len() * i / n + (i * 13) % 7);
    }
    cuts.push(cipher.len());
    cuts.windows(2)
        .map(|w| cipher[w[0]..w[1]].to_vec())
        .collect()
}

/// Encrypt a bundle, lay it out whole or in `parts` chunks, and return its
/// manifest record (digest of the *logical* ciphertext, §4.2).
pub fn add_bundle(
    files: &mut Vec<(String, Vec<u8>)>,
    recipient: &Recipient,
    seq: u64,
    full: bool,
    plaintext: &[u8],
    parts: Option<usize>,
) -> BundleRecord {
    let cipher =
        crypt::encrypt(std::slice::from_ref(recipient), plaintext).expect("encrypt bundle");
    let name = BundleName::new(seq, full, None).expect("canonical");
    match parts {
        None => files.push((name.to_string(), cipher.clone())),
        Some(n) => {
            for (i, part) in chunk(&cipher, n).into_iter().enumerate() {
                let part_name = name.part(i as u64).expect("part name");
                files.push((part_name.to_string(), part));
            }
        }
    }
    BundleRecord {
        seq,
        full,
        digest: sha256_hex(&cipher),
        chunks: parts.map(|n| n as u64),
    }
}

/// Serialize (validated by re-parse) and encrypt the manifest as `sealed-manifest.age`.
pub fn add_manifest(files: &mut Vec<(String, Vec<u8>)>, recipient: &Recipient, m: &Manifest) {
    let text = m.to_text().expect("serializable manifest");
    let cipher =
        crypt::encrypt(std::slice::from_ref(recipient), text.as_bytes()).expect("encrypt manifest");
    files.push(("sealed-manifest.age".into(), cipher));
}

/// Write an age identity file (with the comment lines a real one carries).
pub fn identity_file(dir: &Path, identity: &Identity) -> PathBuf {
    identity_file_named(dir, "key.txt", identity)
}

/// As `identity_file`, under a chosen file name (several identities in one
/// scratch directory).
pub fn identity_file_named(dir: &Path, name: &str, identity: &Identity) -> PathBuf {
    let path = dir.join(name);
    let text = format!(
        "# created: by the sealed-rs tests\n# public key: {}\n{}\n",
        identity.to_public(),
        identity.to_string().expose_secret()
    );
    fs::write(&path, text).expect("write identity file");
    path
}

// --- driving real git through the built helper ---

/// The directory holding the freshly built `git-remote-sealed`.
pub fn helper_bin_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_git-remote-sealed"))
        .parent()
        .expect("binary has a parent dir")
        .to_path_buf()
}

fn path_with_helper() -> String {
    format!(
        "{}:{}",
        helper_bin_dir().display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// Run git so that `sealed::` URLs resolve to the built helper, with
/// `SEALED_IDENTITY` set. Returns the raw output for the caller to judge.
pub fn sealed_git(
    cwd: &Path,
    args: &[&str],
    identity: &Path,
    extra_env: &[(&str, &str)],
) -> Output {
    let mut cmd = git_cmd(cwd, args);
    cmd.env("PATH", path_with_helper())
        .env("SEALED_IDENTITY", identity);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("git must be runnable")
}

/// Run the binary's subcommands (`info`, `forget`, `compact`) inside `cwd`.
pub fn cli(cwd: &Path, identity: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_git-remote-sealed"));
    cmd.args(args)
        .current_dir(cwd)
        .env("PATH", path_with_helper())
        .env("SEALED_IDENTITY", identity);
    for (k, v) in HERMETIC_ENV {
        cmd.env(k, v);
    }
    cmd.output().expect("binary must be runnable")
}

/// The state directory the helper keeps for the single remote of `repo`
/// (`<GIT_DIR>/sealed/<hash>`), and its pin directory.
pub fn state_dir(repo: &Path) -> PathBuf {
    let root = repo.join(".git").join("sealed");
    let mut entries: Vec<PathBuf> = fs::read_dir(&root)
        .expect("state root")
        .map(|e| e.expect("dirent").path())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "one remote, one state dir under {}",
        root.display()
    );
    entries.remove(0)
}

pub fn pin_dir(repo: &Path) -> PathBuf {
    state_dir(repo).join("pin")
}

/// Deterministic incompressible bytes (xorshift), for chunking tests.
pub fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// A `git-remote-sealed` process driven by hand over the helper protocol,
/// so a test can interleave other work between `list for-push` and `push`
/// (the concurrent-writer race, and §8.2 checks git would otherwise make
/// itself before the helper sees them).
pub struct HelperProc {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Option<JoinHandle<String>>,
}

impl HelperProc {
    pub fn spawn(repo: &Path, identity: &Path, sealed_url: &str) -> HelperProc {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_git-remote-sealed"));
        cmd.args(["origin", sealed_url])
            .current_dir(repo)
            .env("GIT_DIR", repo.join(".git"))
            .env("SEALED_IDENTITY", identity)
            .env("PATH", path_with_helper())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in HERMETIC_ENV {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("helper must be runnable");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let stderr_thread = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            text
        });
        HelperProc {
            child,
            stdin: Some(stdin.expect("piped")),
            lines: rx,
            stderr: Some(stderr_thread),
        }
    }

    pub fn send(&mut self, text: &str) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        stdin.write_all(text.as_bytes()).expect("write to helper");
        stdin.flush().expect("flush to helper");
    }

    /// Lines up to (excluding) the next empty line.
    pub fn read_block(&self) -> Vec<String> {
        let mut block = Vec::new();
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(120))
                .expect("helper answered within the timeout");
            if line.is_empty() {
                return block;
            }
            block.push(line);
        }
    }

    /// Close stdin, wait; returns (success, stderr).
    pub fn finish(mut self) -> (bool, String) {
        drop(self.stdin.take());
        let status = self.child.wait().expect("helper exits");
        let stderr = self
            .stderr
            .take()
            .expect("stderr thread")
            .join()
            .expect("stderr thread joins");
        (status.success(), stderr)
    }
}

// --- a vault + identity lab for Rust-writes-Rust-reads scenarios ---

/// One vault remote plus the identity every source/clone in the test uses
/// (the shape `tests/write_e2e.rs` grew; shared here for the claims suite).
pub struct Lab {
    pub scratch: PathBuf,
    pub identity: Identity,
    pub id_file: PathBuf,
    pub remote: VaultRemote,
}

impl Lab {
    pub fn new(tag: &str) -> Lab {
        Lab::with_remote_format(tag, "sha1")
    }

    pub fn with_remote_format(tag: &str, format: &str) -> Lab {
        Lab::build(tag, format, Identity::generate())
    }

    /// A second vault owned by the SAME identity as `other` (two vaults of
    /// one person — Appendix A's paranoid variant).
    pub fn sharing_identity(tag: &str, other: &Lab) -> Lab {
        use std::str::FromStr;
        let secret = other.identity.to_string();
        let identity = Identity::from_str(secret.expose_secret()).expect("re-parse identity");
        Lab::build(tag, "sha1", identity)
    }

    fn build(tag: &str, format: &str, identity: Identity) -> Lab {
        let scratch = scratch(tag);
        let id_file = identity_file(&scratch, &identity);
        let remote = VaultRemote::init_with_format(scratch.join("vault.git"), format);
        Lab {
            scratch,
            identity,
            id_file,
            remote,
        }
    }

    /// A fresh sha1 source repository (HEAD = main) with `origin` = the vault.
    pub fn source(&self, name: &str) -> SourceRepo {
        self.source_on(name, "sha1", "main")
    }

    pub fn source_on(&self, name: &str, object_format: &str, branch: &str) -> SourceRepo {
        let src = SourceRepo::init_on(self.scratch.join(name), object_format, branch);
        src.add_remote("origin", &self.remote.sealed_url());
        src
    }

    pub fn push(&self, repo: &Path, args: &[&str]) -> Output {
        let mut full = vec!["push", "-q", "origin"];
        full.extend_from_slice(args);
        sealed_git(repo, &full, &self.id_file, &[])
    }

    pub fn push_ok(&self, repo: &Path, args: &[&str]) {
        let out = self.push(repo, args);
        assert_ok(&out, &format!("git push origin {}", args.join(" ")));
    }

    pub fn clone(&self, name: &str) -> (PathBuf, Output) {
        self.clone_with(&self.id_file, name)
    }

    /// Clone with a chosen identity file (another recipient, a stranger).
    pub fn clone_with(&self, id_file: &Path, name: &str) -> (PathBuf, Output) {
        let dest = self.scratch.join(name);
        let output = sealed_git(
            &self.scratch,
            &["clone", "-q", &self.remote.sealed_url(), name],
            id_file,
            &[],
        );
        (dest, output)
    }

    pub fn clone_ok(&self, name: &str) -> PathBuf {
        let (dest, out) = self.clone(name);
        assert_ok(&out, "git clone sealed::");
        dest
    }

    pub fn fetch(&self, repo: &Path) -> Output {
        sealed_git(repo, &["fetch", "-q", "origin"], &self.id_file, &[])
    }

    pub fn compact_ok(&self, repo: &Path) -> String {
        let out = cli(repo, &self.id_file, &["compact", "origin"]);
        assert_ok(&out, "git-remote-sealed compact");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    pub fn manifest(&self) -> Manifest {
        self.remote.manifest("main", &self.identity)
    }

    pub fn files(&self) -> Vec<String> {
        self.remote.files("main")
    }
}
