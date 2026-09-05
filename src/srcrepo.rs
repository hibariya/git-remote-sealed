//! Queries against the *source* repository (the caller's repository git is
//! driving the helper for): what the §8 writer needs to check ref updates,
//! refuse unsuitable repositories, and find the objects to bundle. Every
//! call is a git subprocess with the hygiene of `vaultrepo::git_command_in`.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::vaultrepo::{git_command_in, run_in, GitError};

/// `rev-parse --verify` of a revision expression (a full refname, `HEAD`,
/// or a raw object id as git hands them to the helper). `Ok(None)` when it
/// names nothing. For an annotated tag ref this is the tag object, not the
/// peeled commit (§7.2).
pub fn resolve(git_dir: &Path, rev: &str) -> Result<Option<String>, GitError> {
    let output = git_command_in(
        git_dir,
        &["rev-parse", "--verify", "--quiet", "--end-of-options", rev],
    )
    .output()
    .map_err(|e| GitError::Spawn(e.to_string()))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_owned(),
    ))
}

/// `cat-file -t`: `commit`, `tag`, `tree`, or `blob`; `Ok(None)` if absent.
pub fn object_type(git_dir: &Path, oid: &str) -> Result<Option<String>, GitError> {
    let output = git_command_in(git_dir, &["cat-file", "-t", oid])
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_owned(),
    ))
}

/// §8.2: is `old` an ancestor of `new`? (`merge-base --is-ancestor`; both
/// are peeled to commits by git, so tag objects work.) An error means git
/// could not answer — e.g. one side is not commit-ish — which the caller
/// treats as "cannot verify".
pub fn is_ancestor(git_dir: &Path, old: &str, new: &str) -> Result<bool, GitError> {
    let output = git_command_in(git_dir, &["merge-base", "--is-ancestor", old, new])
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(GitError::Command {
            what: "merge-base --is-ancestor".into(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
    }
}

/// §8.3's emptiness question for a commit tip: does `commit` reach any
/// commit not reachable from `excludes`? (`rev-list -n 1 <commit> --not
/// <excludes>`.) Only meaningful for commits — a tag object always needs
/// shipping (§8.3: "a tag-only push has zero new commits but still needs
/// its tag object shipped"), which the caller decides by object type.
pub fn has_new_commits(
    git_dir: &Path,
    commit: &str,
    excludes: &[String],
) -> Result<bool, GitError> {
    let mut args = vec!["rev-list", "-n", "1", commit];
    if !excludes.is_empty() {
        args.push("--not");
        for e in excludes {
            args.push(e);
        }
    }
    let out = run_in(git_dir, &args, "rev-list")?;
    Ok(!out.trim().is_empty())
}

/// §8 preamble: writers MUST refuse a shallow repository.
pub fn is_shallow(git_dir: &Path) -> Result<bool, GitError> {
    Ok(run_in(
        git_dir,
        &["rev-parse", "--is-shallow-repository"],
        "rev-parse --is-shallow-repository",
    )?
    .trim()
        == "true")
}

/// §8 preamble: writers MUST refuse a partial/promisor repository. Any of:
/// `extensions.partialClone`, a `remote.<x>.promisor` setting, or a
/// promisor pack in the object store.
pub fn is_partial(git_dir: &Path) -> Result<bool, GitError> {
    if config_get(git_dir, "extensions.partialclone")?.is_some() {
        return Ok(true);
    }
    if !config_get_regexp(git_dir, r"^remote\..*\.promisor$")?.is_empty() {
        return Ok(true);
    }
    let pack_dir = objects_dir(git_dir)?.join("pack");
    if let Ok(entries) = std::fs::read_dir(pack_dir) {
        for entry in entries.flatten() {
            if entry
                .path()
                .extension()
                .is_some_and(|ext| ext == "promisor")
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The source repository's `HEAD` symref target, if HEAD is symbolic (§8
/// preamble: the initial vault HEAD SHOULD come from here).
pub fn head_symref(git_dir: &Path) -> Result<Option<String>, GitError> {
    let output = git_command_in(git_dir, &["symbolic-ref", "--quiet", "HEAD"])
        .stderr(Stdio::null())
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_owned(),
    ))
}

/// The object directory (absolute), for the bundling repository's
/// alternates file. `--git-path` follows worktrees to the common dir.
pub fn objects_dir(git_dir: &Path) -> Result<PathBuf, GitError> {
    let raw = run_in(
        git_dir,
        &["rev-parse", "--git-path", "objects"],
        "rev-parse --git-path objects",
    )?;
    let path = PathBuf::from(raw.trim());
    Ok(if path.is_absolute() {
        path
    } else {
        git_dir.join(path)
    })
}

/// `git config --get <key>`; `Ok(None)` when unset.
pub fn config_get(git_dir: &Path, key: &str) -> Result<Option<String>, GitError> {
    let output = git_command_in(git_dir, &["config", "--get", key])
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    match output.status.code() {
        Some(0) => Ok(Some(
            String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_owned(),
        )),
        Some(1) => Ok(None),
        _ => Err(GitError::Command {
            what: format!("config --get {key}"),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
    }
}

/// `git config --get-all <key>`; empty when unset.
pub fn config_get_all(git_dir: &Path, key: &str) -> Result<Vec<String>, GitError> {
    let output = git_command_in(git_dir, &["config", "--get-all", key])
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    match output.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect()),
        Some(1) => Ok(Vec::new()),
        _ => Err(GitError::Command {
            what: format!("config --get-all {key}"),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
    }
}

fn config_get_regexp(git_dir: &Path, pattern: &str) -> Result<Vec<String>, GitError> {
    let output = git_command_in(git_dir, &["config", "--get-regexp", pattern])
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    match output.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect()),
        Some(1) => Ok(Vec::new()),
        _ => Err(GitError::Command {
            what: format!("config --get-regexp {pattern}"),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
    }
}

/// `git remote get-url <name>`; `Ok(None)` when no such remote.
pub fn remote_url(git_dir: &Path, name: &str) -> Result<Option<String>, GitError> {
    let output = git_command_in(git_dir, &["remote", "get-url", "--", name])
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_owned(),
    ))
}

/// `git remote`: every configured remote name.
pub fn remote_names(git_dir: &Path) -> Result<Vec<String>, GitError> {
    Ok(run_in(git_dir, &["remote"], "remote")?
        .lines()
        .map(str::to_owned)
        .collect())
}
