//! Per-repository settings the helper and the subcommands share: which
//! repository we are driven for, the age identity (§5: decryption needs
//! one), the recipient set writes encrypt to (§5), and the writer-local
//! chunk threshold (§4.2).
//!
//! Sources, in order:
//! - identity: `SEALED_IDENTITY` (path to an age identity file), else
//!   `git config sealed.identity`;
//! - extra recipients: every value of `git config --get-all
//!   sealed.recipients`, each split on whitespace (space or newline), each
//!   an `age1…` X25519 recipient;
//! - chunk threshold: `git config sealed.chunk-mb`, default 4 (§4.2's
//!   SHOULD for JGit-on-Android recipients; with unbounded chunk counts
//!   small chunks cost nothing, so the safe value is the default).

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::x25519::{Identity, Recipient};

use crate::srcrepo;
use crate::vaultrepo::GitError;

/// Default chunk threshold in MiB (§4.2).
pub const DEFAULT_CHUNK_MB: u64 = 4;

#[derive(Debug)]
pub enum SettingsError {
    /// Could not resolve the repository we are driven for.
    NoGitDir(String),
    /// No identity source: neither `SEALED_IDENTITY` nor `sealed.identity`.
    NoIdentity,
    /// The identity file exists but yields no usable age identity.
    BadIdentityFile {
        path: String,
        detail: String,
    },
    /// `sealed.recipients` holds a token that is not an age X25519 recipient.
    BadRecipient {
        token: String,
        detail: String,
    },
    /// `sealed.chunk-mb` is not a positive integer.
    BadChunkMb(String),
    Git(GitError),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SettingsError::NoGitDir(e) => {
                write!(f, "cannot determine the local repository: {e}")
            }
            SettingsError::NoIdentity => write!(
                f,
                "no age identity: set SEALED_IDENTITY to an identity file path, \
                 or `git config sealed.identity <path>`"
            ),
            SettingsError::BadIdentityFile { path, detail } => {
                write!(f, "identity file {path}: {detail}")
            }
            SettingsError::BadRecipient { token, detail } => write!(
                f,
                "sealed.recipients entry {token:?} is not an age recipient: {detail}"
            ),
            SettingsError::BadChunkMb(v) => write!(
                f,
                "sealed.chunk-mb must be a positive integer (MiB), got {v:?}"
            ),
            SettingsError::Git(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SettingsError {}

impl From<GitError> for SettingsError {
    fn from(e: GitError) -> Self {
        SettingsError::Git(e)
    }
}

/// Everything resolved from the environment and the repository's config.
pub struct Settings {
    pub git_dir: PathBuf,
    pub identity_path: PathBuf,
    pub identities: Vec<Identity>,
    /// `sealed.recipients`, validated, in config order (duplicates kept
    /// out of the recipient set by `recipient_set`).
    pub extra_recipients: Vec<Recipient>,
    /// Writer-local chunk threshold in bytes (§4.2).
    pub chunk_bytes: u64,
    /// `sealed.allow-recipient-shrink`: write even when this device has
    /// fewer recipients than the vault (§5/M4). Off unless set true.
    pub allow_recipient_shrink: bool,
}

impl Settings {
    /// Resolve for the repository git is driving us for (or the one the
    /// current directory is in).
    pub fn load() -> Result<Settings, SettingsError> {
        let git_dir = resolve_git_dir()?;
        Settings::load_for(git_dir)
    }

    pub fn load_for(git_dir: PathBuf) -> Result<Settings, SettingsError> {
        let identity_path = identity_path(&git_dir)?;
        let text = std::fs::read_to_string(&identity_path).map_err(|e| {
            SettingsError::BadIdentityFile {
                path: identity_path.display().to_string(),
                detail: e.to_string(),
            }
        })?;
        let identities =
            parse_identity_file(&text).map_err(|detail| SettingsError::BadIdentityFile {
                path: identity_path.display().to_string(),
                detail,
            })?;

        let mut extra_recipients = Vec::new();
        for value in srcrepo::config_get_all(&git_dir, "sealed.recipients")? {
            for token in value.split_whitespace() {
                let r =
                    Recipient::from_str(token).map_err(|detail| SettingsError::BadRecipient {
                        token: token.to_owned(),
                        detail: detail.to_string(),
                    })?;
                extra_recipients.push(r);
            }
        }

        let chunk_mb = match srcrepo::config_get(&git_dir, "sealed.chunk-mb")? {
            None => DEFAULT_CHUNK_MB,
            Some(v) => v
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|n| *n >= 1)
                .ok_or(SettingsError::BadChunkMb(v))?,
        };

        let allow_recipient_shrink = matches!(srcrepo::config_get(&git_dir, "sealed.allow-recipient-shrink")?,
                Some(v) if matches!(v.trim(), "true" | "1" | "yes" | "on"));

        Ok(Settings {
            git_dir,
            identity_path,
            identities,
            extra_recipients,
            chunk_bytes: chunk_mb.saturating_mul(1024 * 1024),
            allow_recipient_shrink,
        })
    }

    /// The recipients this device's own identities correspond to.
    pub fn own_recipients(&self) -> Vec<Recipient> {
        self.identities.iter().map(Identity::to_public).collect()
    }

    /// §5: the recipient set writes encrypt to — own recipients plus the
    /// configured extras, deduplicated, own first.
    pub fn recipient_set(&self) -> Vec<Recipient> {
        let mut seen = std::collections::BTreeSet::new();
        let mut set = Vec::new();
        for r in self
            .own_recipients()
            .into_iter()
            .chain(self.extra_recipients.iter().cloned())
        {
            if seen.insert(r.to_string()) {
                set.push(r);
            }
        }
        set
    }
}

/// The repository git is driving this helper for: GIT_DIR (git sets it when
/// invoking remote helpers), else `git rev-parse` from the working directory.
pub fn resolve_git_dir() -> Result<PathBuf, SettingsError> {
    let raw = match std::env::var_os("GIT_DIR") {
        Some(d) => PathBuf::from(d),
        None => {
            let output = std::process::Command::new("git")
                .args(["rev-parse", "--absolute-git-dir"])
                .output()
                .map_err(|e| SettingsError::NoGitDir(e.to_string()))?;
            if !output.status.success() {
                return Err(SettingsError::NoGitDir(
                    String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                ));
            }
            PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
        }
    };
    // GIT_DIR may be relative (e.g. `.git`); state paths must survive our
    // subprocesses running elsewhere.
    std::fs::canonicalize(&raw).map_err(|e| SettingsError::NoGitDir(format!("{raw:?}: {e}")))
}

fn identity_path(git_dir: &Path) -> Result<PathBuf, SettingsError> {
    if let Some(p) = std::env::var_os("SEALED_IDENTITY") {
        return Ok(PathBuf::from(p));
    }
    match srcrepo::config_get(git_dir, "sealed.identity")? {
        Some(p) => Ok(PathBuf::from(p.trim())),
        None => Err(SettingsError::NoIdentity),
    }
}

/// Parse an age identity file: `#` comment lines and blank lines are
/// ignored; every remaining line must be an age X25519 secret key.
pub fn parse_identity_file(text: &str) -> Result<Vec<Identity>, String> {
    let mut identities = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let id = Identity::from_str(line)
            .map_err(|e| format!("line is not an age X25519 secret key: {e}"))?;
        identities.push(id);
    }
    if identities.is_empty() {
        return Err("no identity in file".into());
    }
    Ok(identities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_file_parsing_skips_comments_and_blanks() {
        let id = Identity::generate();
        use age::secrecy::ExposeSecret;
        let text = format!(
            "# created: today\n\
             \n\
             # public key: {}\n\
             {}\n",
            id.to_public(),
            id.to_string().expose_secret()
        );
        let parsed = parse_identity_file(&text).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].to_public().to_string(),
            id.to_public().to_string()
        );
    }

    #[test]
    fn identity_file_with_no_keys_is_an_error() {
        assert!(parse_identity_file("# only comments\n").is_err());
        assert!(parse_identity_file("").is_err());
        assert!(parse_identity_file("not-a-key\n").is_err());
    }

    #[test]
    fn recipient_set_is_own_plus_extras_deduplicated() {
        let own = Identity::generate();
        let other = Identity::generate();
        let settings = Settings {
            git_dir: PathBuf::from("/nonexistent"),
            identity_path: PathBuf::from("/nonexistent/key.txt"),
            identities: vec![own.clone()],
            extra_recipients: vec![other.to_public(), own.to_public(), other.to_public()],
            chunk_bytes: 1,
            allow_recipient_shrink: false,
        };
        let set: Vec<String> = settings
            .recipient_set()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            set,
            vec![own.to_public().to_string(), other.to_public().to_string()]
        );
    }
}
