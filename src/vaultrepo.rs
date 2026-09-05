//! The vault as a git repository: §3 (container, branch selection), §6.1
//! (mirror reset, serialization), and the write-side plumbing of §8/§9
//! (blobs, trees, commits written into the mirror with hash-object/mktree/
//! commit-tree — never a worktree — and the porcelain push) — everything
//! that talks to `git` about the *vault* side, plus the small plumbing
//! wrappers the reader needs against the caller's repository.
//!
//! git is shelled out to (`std::process::Command`), never linked — that is
//! FORMAT.md's design (§1 goal 1: recoverable with stock tools; this
//! implementation exercises the same stock surface).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::sha256_hex;

/// §8 writer hygiene: fixed author/committer and a fixed timestamp (the
/// Unix epoch, UTC) on every vault commit. Set as environment for every git
/// invocation this crate makes, so no code path can forget it.
const HYGIENE_ENV: &[(&str, &str)] = &[
    ("GIT_AUTHOR_NAME", "sealed"),
    ("GIT_AUTHOR_EMAIL", "sealed@invalid"),
    ("GIT_COMMITTER_NAME", "sealed"),
    ("GIT_COMMITTER_EMAIL", "sealed@invalid"),
    ("GIT_AUTHOR_DATE", "1970-01-01T00:00:00Z"),
    ("GIT_COMMITTER_DATE", "1970-01-01T00:00:00Z"),
];

/// The mirror's local name for the fetched vault branch. Fixed so branch
/// renames on the remote never leave stale local branches to misread.
const MIRROR_REF: &str = "refs/sealed/fetched";

#[derive(Debug)]
pub enum GitError {
    /// git itself could not be started.
    Spawn(String),
    /// A git command exited non-zero.
    Command { what: String, detail: String },
    /// A git command succeeded but printed something this code cannot use.
    BadOutput { what: String, detail: String },
    /// §3 branch selection dead end: the remote has refs, but no branch at
    /// all — there is no vault branch to read. (Documented choice: §3's
    /// fallback chain assumes at least one branch exists; a branchless
    /// non-empty remote is outside it, so we fail loudly.)
    NoBranches,
    /// Filesystem trouble around the mirror/lock/scratch state.
    Io(String),
    /// A vault push was refused without git's porcelain saying which ref
    /// was rejected — a transport or repository-level failure, not a
    /// concurrent-writer race (those come back as `PushOutcome::Rejected`).
    PushFailed(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::Spawn(e) => write!(f, "cannot run git: {e}"),
            GitError::Command { what, detail } => write!(f, "git {what} failed: {detail}"),
            GitError::BadOutput { what, detail } => {
                write!(f, "unexpected git {what} output: {detail}")
            }
            GitError::NoBranches => write!(
                f,
                "the remote has refs but no branch: there is no vault branch to read"
            ),
            GitError::Io(e) => write!(f, "vault state I/O error: {e}"),
            GitError::PushFailed(e) => write!(f, "vault push failed: {e}"),
        }
    }
}

impl std::error::Error for GitError {}

/// The committed tree of the vault branch (§6.1: the *committed* tree only —
/// reading via `ls-tree`/`cat-file` on a bare mirror means no untracked file
/// and no worktree state can masquerade as vault content).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultTree {
    /// The vault branch's commit id on the remote (as fetched).
    pub commit: String,
    /// The vault branch (§3 selection), as a full refname — the writer
    /// pushes back to exactly this ref.
    pub branch: String,
    /// Root tree blobs: file name -> blob object id. Non-blob entries
    /// (subtrees, gitlinks) and non-UTF-8 names are omitted — such names
    /// cannot be vault files, and §3 has readers ignore entries outside the
    /// spec's grammar.
    pub files: BTreeMap<String, String>,
    /// Every root tree entry as git listed it, names as raw bytes. Writers
    /// SHOULD preserve entries outside the grammar (§3), which means
    /// carrying them — mode, type, and all — into the rewritten tree.
    pub entries: Vec<TreeEntry>,
}

/// One root tree entry, exactly as `ls-tree` reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: String,
    /// `blob`, `tree`, or `commit` (gitlink).
    pub kind: String,
    pub oid: String,
    /// Raw name bytes: the host controls filenames (§4.1), so a preserved
    /// entry need not be UTF-8.
    pub name: Vec<u8>,
}

impl TreeEntry {
    /// A regular (non-executable) blob entry — what the writer creates.
    pub fn blob(name: &str, oid: &str) -> TreeEntry {
        TreeEntry {
            mode: "100644".into(),
            kind: "blob".into(),
            oid: oid.to_owned(),
            name: name.as_bytes().to_vec(),
        }
    }
}

/// What a vault push came back with (§8.5 / §9.4): accepted, or rejected
/// by the ref update — another writer won the race (or, for compaction's
/// compare-and-swap, the tip moved) — in which case the caller retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    Accepted,
    /// A REF-LEVEL rejection: the remote reported, in machine-readable
    /// form, that it did not take this update. §8.5's "definitive" — the
    /// only outcome that proves the write did not land. git's porcelain
    /// summary is carried for the message, e.g. `[rejected] (fetch first)`,
    /// `[rejected] (stale info)`, `[remote rejected] (pre-receive hook
    /// declined)`.
    Rejected(String),
    /// The push ended without a ref-level verdict — `[remote failure]
    /// (remote failed to report status)`, or a summary this version does
    /// not know. The update MAY have landed. §8.4: NOT a definitive
    /// rejection, so the sequence binding stays pending.
    Indeterminate(String),
}

/// One vault remote plus this repository's local state for it: bare mirror,
/// pin directory, scratch space, and the §6.1 lock — all under
/// `<GIT_DIR>/sealed/<sha256-of-remote-url>/`.
pub struct VaultRepo {
    url: String,
    base: PathBuf,
    mirror: PathBuf,
    /// §6.1: concurrent operations sharing one local mirror MUST be
    /// serialized. Held (OS advisory lock) for this value's whole lifetime;
    /// released when the file is dropped.
    _lock: fs::File,
}

/// Where the state for `(local repository, remote url)` lives. Keyed by the
/// *URL*, not the manifest's vault id: the pin directory must be stable
/// across whole-vault substitution, or §7.4's identity check could be
/// laundered away by the substitute starting a fresh pin (see pinstore.rs).
pub fn state_dir(git_dir: &Path, url: &str) -> PathBuf {
    git_dir.join("sealed").join(sha256_hex(url.as_bytes()))
}

/// The pin directory for a (repository, remote) pair, without opening the
/// vault. `info` reports the pin and must not take the §6.1 lock or touch
/// the network to do it.
pub fn pin_dir_for(git_dir: &Path, url: &str) -> PathBuf {
    state_dir(git_dir, url).join("pin")
}

impl VaultRepo {
    /// Open (creating if needed) the local state for this remote and take
    /// the §6.1 lock. Blocks until the lock is available.
    pub fn open(git_dir: &Path, url: &str) -> Result<VaultRepo, GitError> {
        let base = state_dir(git_dir, url);
        fs::create_dir_all(&base).map_err(|e| GitError::Io(format!("{}: {e}", base.display())))?;

        let lock_path = base.join("lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| GitError::Io(format!("{}: {e}", lock_path.display())))?;
        // §6.1: serialize all operations on one mirror. One lock per state
        // dir also serializes the pin file and scratch space that live here.
        lock.lock()
            .map_err(|e| GitError::Io(format!("{}: {e}", lock_path.display())))?;

        let mirror = base.join("mirror.git");
        Ok(VaultRepo {
            url: url.to_owned(),
            base,
            mirror,
            _lock: lock,
        })
    }

    /// Create the bare mirror on first use. §3: the vault repository is
    /// host-default (any object format), so the mirror must match whatever
    /// the remote actually uses — learned from the width of the object ids
    /// `ls-remote` returned — rather than this process's default (which
    /// `GIT_DEFAULT_HASH` could have set to anything).
    fn ensure_mirror(&self, remote_oid_width: usize) -> Result<(), GitError> {
        let format = if remote_oid_width == 64 {
            "sha256"
        } else {
            "sha1"
        };
        self.ensure_mirror_with_format(format)
    }

    /// Create the bare mirror in `format` (`sha1`/`sha256`) unless it
    /// exists. The writer's vault-initialization path uses this directly:
    /// an EMPTY remote advertises no object ids to learn the format from
    /// (documented choice in `writer.rs`).
    pub fn ensure_mirror_with_format(&self, format: &str) -> Result<(), GitError> {
        if self.mirror_exists() {
            return Ok(());
        }
        fs::create_dir_all(&self.mirror)
            .map_err(|e| GitError::Io(format!("{}: {e}", self.mirror.display())))?;
        let flag = format!("--object-format={format}");
        self.git(&["init", "--quiet", "--bare", &flag], "init mirror")
            .map(|_| ())
    }

    pub fn mirror_exists(&self) -> bool {
        self.mirror.join("HEAD").exists()
    }

    /// Delete the mirror (the writer discards a mirror created in a format
    /// the remote turned out not to speak). The pin is untouched.
    pub fn discard_mirror(&self) -> Result<(), GitError> {
        match fs::remove_dir_all(&self.mirror) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(GitError::Io(format!("{}: {e}", self.mirror.display()))),
        }
    }

    /// The mirror's object format (`sha1`/`sha256`).
    pub fn mirror_object_format(&self) -> Result<String, GitError> {
        Ok(self
            .git(
                &["rev-parse", "--show-object-format"],
                "rev-parse --show-object-format",
            )?
            .trim()
            .to_owned())
    }

    /// The remote URL this state stands for.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// `<GIT_DIR>/sealed/<hash>` — the whole state directory (§7.5 `forget`
    /// removes it).
    pub fn state_dir(&self) -> &Path {
        &self.base
    }

    /// The directory pinstore should use for this (repository, remote) pair.
    pub fn pin_dir(&self) -> PathBuf {
        self.base.join("pin")
    }

    /// `<GIT_DIR>/sealed` — every remote's state dir lives here; §7.4's
    /// per-vault pin lookup scans it (`pinstore::find_by_vault_id`).
    pub fn sealed_root(&self) -> PathBuf {
        self.base
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.base.clone())
    }

    /// Scratch space for reassembly/decryption temp files. Lives under the
    /// locked state dir, so the §6.1 lock covers it too.
    pub fn scratch_dir(&self) -> Result<PathBuf, GitError> {
        let dir = self.base.join("scratch");
        fs::create_dir_all(&dir).map_err(|e| GitError::Io(format!("{}: {e}", dir.display())))?;
        Ok(dir)
    }

    /// §6.1: fetch the current committed tree of the vault branch.
    /// `Ok(None)` means the remote is empty (no refs at all) — §8.1's
    /// "empty vault reads as no refs" case, subject to §7.4's
    /// empty-vault-with-pin refusal (the caller's job).
    pub fn fetch(&self) -> Result<Option<VaultTree>, GitError> {
        // Learn the remote's refs and HEAD symref in one round trip.
        let listing = self.git(&["ls-remote", "--symref", &self.url], "ls-remote")?;
        let remote = parse_ls_remote(&listing);
        if remote.is_empty() {
            return Ok(None);
        }
        let branch = select_branch(remote.head_target.as_deref(), &remote.branches)?;
        self.ensure_mirror(remote.oid_width)?;

        // §6.1: reset the mirror to the remote state, never merge — the
        // forced refspec makes the fetch a reset (compaction force-updates
        // the branch, §9, and readers MUST tolerate that).
        let refspec = format!("+{branch}:{MIRROR_REF}");
        self.git(
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                &self.url,
                &refspec,
            ],
            "fetch",
        )?;

        let commit = self
            .git(&["rev-parse", "--verify", MIRROR_REF], "rev-parse")?
            .trim()
            .to_owned();

        // §6.1: the *committed* tree. `ls-tree` of the fetched commit reads
        // only tracked content; -z so host-chosen names (the host controls
        // filenames, §4.1) arrive unquoted.
        let raw = self.git_bytes(&["ls-tree", "-z", &commit], "ls-tree")?;
        let entries = parse_ls_tree(&raw).map_err(|detail| GitError::BadOutput {
            what: "ls-tree".into(),
            detail,
        })?;
        let files = blob_files(&entries);
        Ok(Some(VaultTree {
            commit,
            branch,
            files,
            entries,
        }))
    }

    // --- write side (§8/§9): plumbing only, never a worktree ---

    /// Store a blob in the mirror from a stream (`hash-object -w --stdin
    /// --no-filters`): bundle ciphertexts are large and never held whole.
    /// `--no-filters` plus the hygiene flags of `git_command_in` keep every
    /// byte as given (§8: unconverted bytes are load-bearing).
    pub fn write_blob_stream(&self, input: &mut dyn Read) -> Result<String, GitError> {
        let mut child = self
            .git_command(&["hash-object", "-w", "--stdin", "--no-filters"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        let mut stdin = child.stdin.take().expect("stdin was piped");
        let copy = std::io::copy(input, &mut stdin);
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        copy.map_err(|e| GitError::Io(format!("feeding hash-object: {e}")))?;
        if !output.status.success() {
            return Err(GitError::Command {
                what: "hash-object".into(),
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        parse_oid(&output.stdout, "hash-object")
    }

    /// Store a small blob (the manifest, `sealed-format`).
    pub fn write_blob(&self, bytes: &[u8]) -> Result<String, GitError> {
        let mut cursor = std::io::Cursor::new(bytes);
        self.write_blob_stream(&mut cursor)
    }

    /// Build a root tree from entries (`mktree -z`; git sorts them).
    pub fn write_tree(&self, entries: &[TreeEntry]) -> Result<String, GitError> {
        let mut input = Vec::new();
        for e in entries {
            input.extend_from_slice(e.mode.as_bytes());
            input.push(b' ');
            input.extend_from_slice(e.kind.as_bytes());
            input.push(b' ');
            input.extend_from_slice(e.oid.as_bytes());
            input.push(b'\t');
            input.extend_from_slice(&e.name);
            input.push(0);
        }
        let out = self.git_with_stdin(&["mktree", "-z"], &input, "mktree")?;
        parse_oid(&out, "mktree")
    }

    /// Commit a tree (`commit-tree`), with the §8 hygiene: fixed identity
    /// and epoch timestamp (environment set by `git_command_in`), no
    /// signature (`commit.gpgsign=false` there too), a fixed message, and
    /// `parents` exactly as given — empty for vault initialization and for
    /// compaction's single parentless commit (§9.3).
    pub fn commit_tree(&self, tree: &str, parents: &[&str]) -> Result<String, GitError> {
        let mut args = vec!["commit-tree", tree, "-m", "vault"];
        for p in parents {
            args.push("-p");
            args.push(p);
        }
        let out = self.git_bytes(&args, "commit-tree")?;
        parse_oid(&out, "commit-tree")
    }

    /// Push `commit` to `branch` on the remote. Non-forced unless `lease`
    /// is given, in which case it is compaction's compare-and-swap (§9.4:
    /// `--force-with-lease=<branch>:<observed tip>` — never a plain force).
    /// Rejection detection uses `--porcelain` only (§8.5: never the
    /// localized human output): the `!` flag on our ref's line.
    pub fn push_commit(
        &self,
        commit: &str,
        branch: &str,
        lease: Option<&str>,
    ) -> Result<PushOutcome, GitError> {
        let refspec = format!("{commit}:{branch}");
        let lease_flag = lease.map(|t| format!("--force-with-lease={branch}:{t}"));
        // No `--quiet`: it suppresses the porcelain ref lines too.
        let mut args = vec![
            "push",
            "--porcelain",
            // §8: never sign pushes (a push certificate identifies the
            // writer); never run hooks (the mirror's hooks dir is already
            // pinned to /dev/null, this is belt and braces).
            "--no-signed",
            "--no-verify",
        ];
        if let Some(flag) = &lease_flag {
            args.push(flag);
        }
        args.push(&self.url);
        args.push(&refspec);
        let output = self
            .git_command(&args)
            .output()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        match parse_push_porcelain(&stdout, branch) {
            Some(outcome) => Ok(outcome),
            None if output.status.success() => Err(GitError::BadOutput {
                what: "push --porcelain".into(),
                detail: format!("no status line for {branch}: {stdout:?}"),
            }),
            None => Err(GitError::PushFailed(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            )),
        }
    }

    fn git_with_stdin(&self, args: &[&str], input: &[u8], what: &str) -> Result<Vec<u8>, GitError> {
        let mut child = self
            .git_command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        let mut stdin = child.stdin.take().expect("stdin was piped");
        let written = stdin.write_all(input);
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        written.map_err(|e| GitError::Io(format!("feeding {what}: {e}")))?;
        if !output.status.success() {
            return Err(GitError::Command {
                what: what.into(),
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(output.stdout)
    }

    /// Read one blob whole (manifest, `sealed-format` — the small files).
    pub fn read_blob(&self, oid: &str) -> Result<Vec<u8>, GitError> {
        self.git_bytes(&["cat-file", "blob", oid], "cat-file blob")
    }

    /// Stream one blob into `sink` (chunk reassembly, §6.5 — bundles are
    /// large, so they are never held in memory whole).
    pub fn stream_blob(&self, oid: &str, sink: &mut dyn Write) -> Result<u64, GitError> {
        let mut child = self
            .git_command(&["cat-file", "blob", oid])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        let mut stdout = child.stdout.take().expect("stdout was piped");
        let copied = std::io::copy(&mut stdout, sink)
            .map_err(|e| GitError::Io(format!("streaming blob {oid}: {e}")))?;
        drop(stdout);
        let output = child
            .wait_with_output()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        if !output.status.success() {
            return Err(GitError::Command {
                what: format!("cat-file blob {oid}"),
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(copied)
    }

    /// Run git against the mirror, expecting success; returns stdout as text.
    fn git(&self, args: &[&str], what: &str) -> Result<String, GitError> {
        let bytes = self.git_bytes(args, what)?;
        String::from_utf8(bytes).map_err(|_| GitError::BadOutput {
            what: what.into(),
            detail: "not UTF-8".into(),
        })
    }

    fn git_bytes(&self, args: &[&str], what: &str) -> Result<Vec<u8>, GitError> {
        let output = self
            .git_command(args)
            .output()
            .map_err(|e| GitError::Spawn(e.to_string()))?;
        if !output.status.success() {
            return Err(GitError::Command {
                what: what.into(),
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(output.stdout)
    }

    fn git_command(&self, args: &[&str]) -> Command {
        git_command_in(&self.mirror, args)
    }
}

/// A git invocation against an explicit repository, with the environment
/// git set for *our* process scrubbed off (git runs remote helpers with
/// GIT_DIR pointing at the caller's repo; without scrubbing, every mirror
/// command would silently operate on the caller's repository instead).
///
/// §8 writer hygiene, applied to EVERY invocation (reads included — the
/// flags are harmless there and no write path can then forget them):
/// - transformation off: line-ending conversion, the attributes machinery
///   (so a `.gitattributes` planted in the host-writable vault tree cannot
///   re-enable filters), hooks — each as a command-line `-c`, which beats
///   user-level configuration and the environment;
/// - no signatures on commits, tags, or pushes (`*.gpgsign=false`);
/// - fixed author/committer identity and the epoch timestamp (`HYGIENE_ENV`).
pub(crate) fn git_command_in(git_dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("--git-dir")
        .arg(git_dir)
        .arg("-c")
        .arg("core.autocrlf=false")
        .arg("-c")
        .arg("core.eol=lf")
        .arg("-c")
        .arg("core.attributesFile=/dev/null")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-c")
        .arg("tag.gpgsign=false")
        .arg("-c")
        .arg("push.gpgsign=false")
        .arg("-c")
        .arg("advice.defaultBranchName=false")
        .args(args)
        .envs(HYGIENE_ENV.iter().copied())
        .env_remove("GIT_DIR")
        .env_remove("GIT_DEFAULT_HASH")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_NAMESPACE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES");
    cmd
}

pub(crate) fn run_in(git_dir: &Path, args: &[&str], what: &str) -> Result<String, GitError> {
    let output = git_command_in(git_dir, args)
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    if !output.status.success() {
        return Err(GitError::Command {
            what: what.into(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The caller repository's object format (`rev-parse --show-object-format`).
pub fn repo_object_format(git_dir: &Path) -> Result<String, GitError> {
    Ok(run_in(
        git_dir,
        &["rev-parse", "--show-object-format"],
        "rev-parse --show-object-format",
    )?
    .trim()
    .to_owned())
}

/// Does this object exist in the caller's repository? (§6.6's final check;
/// also the §6.5 re-apply trigger.)
pub fn object_exists(git_dir: &Path, oid: &str) -> Result<bool, GitError> {
    let status = git_command_in(git_dir, &["cat-file", "-e", oid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    Ok(status.success())
}

/// §4.3/§6.5: `git bundle verify` then `git bundle unbundle` into the
/// caller's repository. Applying only adds objects — unbundle never touches
/// refs (§6.5: reporting refs is the manifest's job, and git sets the
/// caller's refs itself after a helper fetch). Verify first: §4.3 promises
/// apply order never fails a prerequisite check, so a verify failure means a
/// corrupt vault and deserves its own loud error before objects land.
pub fn apply_bundle(git_dir: &Path, bundle: &Path) -> Result<(), GitError> {
    let path = bundle
        .to_str()
        .ok_or_else(|| GitError::Io(format!("bundle path {} is not UTF-8", bundle.display())))?;
    run_in(
        git_dir,
        &["bundle", "verify", "--quiet", path],
        "bundle verify",
    )?;
    run_in(git_dir, &["bundle", "unbundle", path], "bundle unbundle")?;
    Ok(())
}

// --- parsing helpers (pure, unit-tested) ---

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RemoteListing {
    /// `ref: <target>\tHEAD` from `ls-remote --symref`, when advertised.
    pub(crate) head_target: Option<String>,
    /// Full refnames under `refs/heads/`.
    pub(crate) branches: BTreeSet<String>,
    /// Any ref at all (branches, tags, HEAD, ...).
    pub(crate) any_ref: bool,
    /// Width of the object ids advertised (40 = sha1, 64 = sha256).
    pub(crate) oid_width: usize,
}

impl RemoteListing {
    pub(crate) fn is_empty(&self) -> bool {
        !self.any_ref
    }
}

pub(crate) fn parse_ls_remote(listing: &str) -> RemoteListing {
    let mut out = RemoteListing::default();
    for line in listing.lines() {
        let Some((left, name)) = line.split_once('\t') else {
            continue;
        };
        if let Some(target) = left.strip_prefix("ref: ") {
            if name == "HEAD" {
                out.head_target = Some(target.to_owned());
            }
            continue;
        }
        out.any_ref = true;
        out.oid_width = left.len();
        if name.starts_with("refs/heads/") {
            out.branches.insert(name.to_owned());
        }
    }
    out
}

/// §3 branch selection for a NON-EMPTY remote: the remote's default branch
/// (remote HEAD) when usable; otherwise `main` if it exists, else the
/// lexicographically first branch. (Documented choice: a HEAD whose symref
/// target the server does not advertise, or that names a branch absent from
/// the listing — dangling — counts as "no usable HEAD".)
pub(crate) fn select_branch(
    head_target: Option<&str>,
    branches: &BTreeSet<String>,
) -> Result<String, GitError> {
    if let Some(target) = head_target {
        if branches.contains(target) {
            return Ok(target.to_owned());
        }
    }
    let main = "refs/heads/main";
    if branches.contains(main) {
        return Ok(main.to_owned());
    }
    // BTreeSet iterates in lexicographic (byte) order.
    branches.iter().next().cloned().ok_or(GitError::NoBranches)
}

/// Parse `ls-tree -z` output: entries `<mode> SP <type> SP <oid> TAB <name> NUL`,
/// every entry kept verbatim (writers preserve unknown entries, §3).
fn parse_ls_tree(raw: &[u8]) -> Result<Vec<TreeEntry>, String> {
    let mut entries = Vec::new();
    for entry in raw.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let tab = entry
            .iter()
            .position(|b| *b == b'\t')
            .ok_or_else(|| "entry without TAB".to_owned())?;
        let meta = std::str::from_utf8(&entry[..tab]).map_err(|_| "non-UTF-8 metadata")?;
        let mut it = meta.split(' ');
        let mode = it.next().ok_or("missing mode")?;
        let kind = it.next().ok_or("missing type")?;
        let oid = it.next().ok_or("missing oid")?;
        entries.push(TreeEntry {
            mode: mode.to_owned(),
            kind: kind.to_owned(),
            oid: oid.to_owned(),
            name: entry[tab + 1..].to_vec(),
        });
    }
    Ok(entries)
}

/// The blob view of a tree (see [`VaultTree::files`]): blobs with UTF-8
/// names only — anything else cannot match a grammar of this spec, so the
/// reader never needs it (§3: readers ignore entries outside the grammar).
fn blob_files(entries: &[TreeEntry]) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    for e in entries {
        if e.kind != "blob" {
            continue;
        }
        if let Ok(name) = std::str::from_utf8(&e.name) {
            files.insert(name.to_owned(), e.oid.clone());
        }
    }
    files
}

fn parse_oid(out: &[u8], what: &str) -> Result<String, GitError> {
    let text = String::from_utf8_lossy(out);
    let oid = text.trim();
    let is_hex = !oid.is_empty() && oid.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_hex || (oid.len() != 40 && oid.len() != 64) {
        return Err(GitError::BadOutput {
            what: what.into(),
            detail: format!("expected an object id, got {oid:?}"),
        });
    }
    Ok(oid.to_owned())
}

/// Read `git push --porcelain` output for the line about `branch`
/// (`<flag> TAB <from>:<to> TAB <summary>`). Every flag other than `!`
/// (` ` fast-forward, `+` forced, `*` new, `=` up to date) means the remote
/// now holds our commit. `None` when no line names the branch.
///
/// §8.5: a `!` is only *definitive* when the remote actually reported a
/// ref-level rejection. git also flags `!` for `[remote failure] (remote
/// failed to report status)` — the update may well have landed, the report
/// was simply lost — and reading that as "did not land" is what let a
/// writer re-bind a sequence number to different content. Porcelain
/// summaries are not localized, so matching them is machine-readable in
/// §8.5's sense; anything unrecognized is treated as indeterminate
/// (fail-closed: the binding is kept).
pub(crate) fn parse_push_porcelain(stdout: &str, branch: &str) -> Option<PushOutcome> {
    for line in stdout.lines() {
        let mut parts = line.splitn(3, '\t');
        let flag = parts.next()?;
        let (Some(refspec), Some(summary)) = (parts.next(), parts.next()) else {
            continue;
        };
        let to = refspec.rsplit_once(':').map_or(refspec, |(_, to)| to);
        if to != branch {
            continue;
        }
        if flag != "!" {
            return Some(PushOutcome::Accepted);
        }
        let definitive =
            summary.starts_with("[rejected") || summary.starts_with("[remote rejected");
        return Some(if definitive {
            PushOutcome::Rejected(summary.to_owned())
        } else {
            PushOutcome::Indeterminate(summary.to_owned())
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn porcelain_separates_a_ref_rejection_from_a_lost_status_report() {
        // §8.5: only a REF-LEVEL rejection proves the write did not land.
        // git flags `!` for both, so the summary is what separates them —
        // reading `[remote failure]` as "rejected" is what let a writer
        // withdraw its binding and re-bind the number to fresh ciphertext.
        let line = |flag: &str, summary: &str| format!("{flag}\tabc:refs/heads/main\t{summary}\n");

        for summary in [
            "[rejected] (non-fast-forward)",
            "[rejected] (stale info)",
            "[remote rejected] (pre-receive hook declined)",
        ] {
            assert!(
                matches!(
                    parse_push_porcelain(&line("!", summary), "refs/heads/main"),
                    Some(PushOutcome::Rejected(_))
                ),
                "{summary} is definitive"
            );
        }

        for summary in [
            "[remote failure] (remote failed to report status)",
            "[no match]",
            "[something this version has never seen]",
        ] {
            assert!(
                matches!(
                    parse_push_porcelain(&line("!", summary), "refs/heads/main"),
                    Some(PushOutcome::Indeterminate(_))
                ),
                "{summary} is not definitive"
            );
        }

        for flag in [" ", "+", "*", "="] {
            assert!(matches!(
                parse_push_porcelain(&line(flag, "[up to date]"), "refs/heads/main"),
                Some(PushOutcome::Accepted)
            ));
        }
        assert!(parse_push_porcelain(&line("!", "[rejected]"), "refs/heads/other").is_none());
    }

    #[test]
    fn ls_remote_parses_symref_branches_and_emptiness() {
        let listing = "ref: refs/heads/trunk\tHEAD\n\
                       aaaa\tHEAD\n\
                       aaaa\trefs/heads/trunk\n\
                       bbbb\trefs/heads/main\n\
                       cccc\trefs/tags/v1\n";
        let remote = parse_ls_remote(listing);
        assert!(!remote.is_empty());
        assert_eq!(remote.head_target.as_deref(), Some("refs/heads/trunk"));
        assert_eq!(remote.branches.len(), 2);
        assert_eq!(remote.oid_width, 4);

        assert!(parse_ls_remote("").is_empty());
    }

    #[test]
    fn branch_selection_follows_the_spec_chain() {
        let branches: BTreeSet<String> = ["refs/heads/apple", "refs/heads/main", "refs/heads/zed"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        // §3: remote HEAD when non-empty (and usable).
        assert_eq!(
            select_branch(Some("refs/heads/zed"), &branches).expect("selected"),
            "refs/heads/zed"
        );
        // §3: no usable HEAD -> `main` if it exists...
        assert_eq!(
            select_branch(None, &branches).expect("selected"),
            "refs/heads/main"
        );
        // dangling HEAD counts as unusable.
        assert_eq!(
            select_branch(Some("refs/heads/gone"), &branches).expect("selected"),
            "refs/heads/main"
        );
        // ...else the lexicographically first branch.
        let no_main: BTreeSet<String> = ["refs/heads/zed", "refs/heads/apple"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            select_branch(None, &no_main).expect("selected"),
            "refs/heads/apple"
        );
        // No branches at all: a loud dead end, not a guess.
        assert!(matches!(
            select_branch(None, &BTreeSet::new()),
            Err(GitError::NoBranches)
        ));
    }

    #[test]
    fn ls_tree_keeps_every_entry_but_files_are_blobs_only() {
        let raw = b"100644 blob aaaa\trefs.age\0\
                    040000 tree bbbb\tsubdir\0\
                    100644 blob cccc\t1-full.bundle.age\0\
                    100644 blob dddd\tbad\xff\0";
        let entries = parse_ls_tree(raw).expect("parses");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[1].kind, "tree");
        assert_eq!(entries[3].name, b"bad\xff");
        let files = blob_files(&entries);
        assert_eq!(files.len(), 2);
        assert_eq!(files["refs.age"], "aaaa");
        assert_eq!(files["1-full.bundle.age"], "cccc");
    }

    #[test]
    fn push_porcelain_flags() {
        let b = "refs/heads/main";
        let rejected = "To /x\n!\tabc:refs/heads/main\t[rejected] (fetch first)\nDone\n";
        assert_eq!(
            parse_push_porcelain(rejected, b),
            Some(PushOutcome::Rejected("[rejected] (fetch first)".into()))
        );
        let stale = "!\tabc:refs/heads/main\t[rejected] (stale info)\n";
        assert!(matches!(
            parse_push_porcelain(stale, b),
            Some(PushOutcome::Rejected(_))
        ));
        for ok in [
            " \tabc:refs/heads/main\t1234567..89abcde\n",
            "+\tabc:refs/heads/main\t1234567...89abcde (forced update)\n",
            "*\tabc:refs/heads/main\t[new branch]\n",
        ] {
            assert_eq!(parse_push_porcelain(ok, b), Some(PushOutcome::Accepted));
        }
        // The line about another ref does not count.
        assert_eq!(
            parse_push_porcelain("*\tabc:refs/heads/other\t[new branch]\n", b),
            None
        );
        assert_eq!(parse_push_porcelain("", b), None);
    }

    #[test]
    fn oid_parsing_rejects_non_ids() {
        assert!(parse_oid(b"0123456789abcdef0123456789abcdef01234567\n", "x").is_ok());
        assert!(parse_oid(b"nope\n", "x").is_err());
        assert!(parse_oid(b"", "x").is_err());
    }
}
