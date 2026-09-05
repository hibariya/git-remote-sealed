//! User-facing subcommands of the `git-remote-sealed` binary, run inside a
//! repository:
//!
//! - `info [<remote-or-url>]` — read-only, offline: the vault URL, the
//!   identity file, this device's recipient(s), the extras from
//!   `sealed.recipients`, and the join line for a new device;
//! - `forget --yes [<remote-or-url>]` — §7.5: discard this repository's pin,
//!   sequence memory, and mirror for that remote. Without `--yes` it prints
//!   the warning (forgetting under attack accepts the attack) and refuses;
//! - `compact [<remote-or-url>]` — §9.
//!
//! A remote is named by its git remote name (resolved with `git remote
//! get-url`) or given as a `sealed::<url>` URL. With no argument, the one
//! `sealed::` remote of the repository is used.

use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::compact;
use crate::helper::strip_scheme;
use crate::settings::{Settings, SettingsError};
use crate::srcrepo;
use crate::vaultrepo::{GitError, VaultRepo};
use crate::writer::{WriteError, WriterConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Info { remote: Option<String> },
    Forget { yes: bool, remote: Option<String> },
    Compact { remote: Option<String> },
}

#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Settings(SettingsError),
    Git(GitError),
    Write(WriteError),
    /// No (or more than one) `sealed::` remote to pick, or the argument
    /// names neither a remote nor a `sealed::` URL.
    NoSealedRemote(String),
    /// §7.5: `forget` without `--yes`.
    ForgetRefused {
        remote: String,
    },
    Io(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(u) => write!(f, "{u}"),
            CliError::Settings(e) => write!(f, "{e}"),
            CliError::Git(e) => write!(f, "{e}"),
            CliError::Write(e) => write!(f, "{e}"),
            CliError::NoSealedRemote(e) => write!(f, "{e}"),
            CliError::ForgetRefused { remote } => write!(
                f,
                "forget refused: this would discard the pin and sequence memory for {remote}.\n\
                 Those are what detect a rolled-back, forked, or substituted vault. The errors\n\
                 that make people reach for `forget` fire exactly when the host is misbehaving:\n\
                 forgetting while under attack ACCEPTS the attack, and every protection is gone\n\
                 until the next successful read re-establishes it.\n\
                 Only do this for a vault you deliberately deleted and re-created at the same\n\
                 URL (a new vault at a new URL needs no forget). To proceed:\n\
                 \x20   git-remote-sealed forget --yes {remote}"
            ),
            CliError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<SettingsError> for CliError {
    fn from(e: SettingsError) -> Self {
        CliError::Settings(e)
    }
}
impl From<GitError> for CliError {
    fn from(e: GitError) -> Self {
        CliError::Git(e)
    }
}
impl From<WriteError> for CliError {
    fn from(e: WriteError) -> Self {
        CliError::Write(e)
    }
}

pub const USAGE: &str = "usage: git-remote-sealed <remote> <url>            (invoked by git)\n\
       git-remote-sealed info [<remote-or-url>]\n\
       git-remote-sealed forget --yes [<remote-or-url>]\n\
       git-remote-sealed compact [<remote-or-url>]";

/// Recognize a subcommand invocation. `None` = not a subcommand (git's
/// `<remote> <url>` form). A remote literally named `info`, `forget`, or
/// `compact` cannot be driven by git through this binary (documented
/// limitation).
pub fn parse_args(args: &[String]) -> Option<Result<Command, CliError>> {
    let (name, rest) = args.split_first()?;
    let cmd = match name.as_str() {
        "info" => match rest {
            [] => Ok(Command::Info { remote: None }),
            [r] => Ok(Command::Info {
                remote: Some(r.clone()),
            }),
            _ => Err(CliError::Usage(USAGE.into())),
        },
        "forget" => {
            let mut yes = false;
            let mut remote = None;
            for a in rest {
                if a == "--yes" {
                    yes = true;
                } else if remote.is_none() && !a.starts_with('-') {
                    remote = Some(a.clone());
                } else {
                    return Some(Err(CliError::Usage(USAGE.into())));
                }
            }
            Ok(Command::Forget { yes, remote })
        }
        "compact" => match rest {
            [] => Ok(Command::Compact { remote: None }),
            [r] => Ok(Command::Compact {
                remote: Some(r.clone()),
            }),
            _ => Err(CliError::Usage(USAGE.into())),
        },
        _ => return None,
    };
    Some(cmd)
}

pub fn run(cmd: Command, out: &mut dyn Write) -> Result<(), CliError> {
    match cmd {
        Command::Info { remote } => info(remote.as_deref(), out),
        Command::Forget { yes, remote } => forget(yes, remote.as_deref(), out),
        Command::Compact { remote } => run_compact(remote.as_deref(), out),
    }
}

/// `(label, url-without-scheme)` for the remote argument.
fn resolve_remote(git_dir: &Path, arg: Option<&str>) -> Result<(String, String), CliError> {
    match arg {
        Some(a) => {
            if let Some(url) = srcrepo::remote_url(git_dir, a)? {
                if !url.starts_with("sealed::") {
                    return Err(CliError::NoSealedRemote(format!(
                        "remote {a} is not a sealed:: remote (its URL is {url})"
                    )));
                }
                return Ok((format!("{a} ({url})"), strip_scheme(&url).to_owned()));
            }
            if a.starts_with("sealed::") {
                return Ok((a.to_owned(), strip_scheme(a).to_owned()));
            }
            Err(CliError::NoSealedRemote(format!(
                "{a:?} is neither a remote of this repository nor a sealed:: URL"
            )))
        }
        None => {
            let mut sealed = Vec::new();
            for name in srcrepo::remote_names(git_dir)? {
                if let Some(url) = srcrepo::remote_url(git_dir, &name)? {
                    if url.starts_with("sealed::") {
                        sealed.push((name, url));
                    }
                }
            }
            match sealed.as_slice() {
                [(name, url)] => Ok((format!("{name} ({url})"), strip_scheme(url).to_owned())),
                [] => Err(CliError::NoSealedRemote(
                    "this repository has no sealed:: remote; name one, or give a sealed:: URL"
                        .into(),
                )),
                many => Err(CliError::NoSealedRemote(format!(
                    "this repository has several sealed:: remotes ({}); name one",
                    many.iter()
                        .map(|(n, _)| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))),
            }
        }
    }
}

fn info(remote: Option<&str>, out: &mut dyn Write) -> Result<(), CliError> {
    let settings = Settings::load()?;
    let (label, url) = resolve_remote(&settings.git_dir, remote)?;
    let own: Vec<String> = settings
        .own_recipients()
        .iter()
        .map(ToString::to_string)
        .collect();
    let extras: Vec<String> = settings
        .extra_recipients
        .iter()
        .map(ToString::to_string)
        .collect();
    let join: Vec<String> = settings
        .recipient_set()
        .iter()
        .map(ToString::to_string)
        .collect();

    let mut text = String::new();
    text.push_str(&format!("vault:      {label}\n"));
    text.push_str(&format!(
        "identity:   {}\n",
        settings.identity_path.display()
    ));
    for r in &own {
        text.push_str(&format!("recipient:  {r} (this device)\n"));
    }
    if extras.is_empty() {
        text.push_str("extra:      none (git config sealed.recipients)\n");
    }
    for r in &extras {
        text.push_str(&format!("extra:      {r} (sealed.recipients)\n"));
    }
    // §7.4 (M7): what this device remembers about the vault. Appendix A's
    // recovery checks ask a human to compare the vault id, and the rollback
    // story asks them to compare the counter — neither is actionable without
    // a reference value to compare AGAINST, which is what this prints. Read
    // straight from the pin file: no network, no identity, no lock, so `info`
    // still works on a vault this device cannot currently reach.
    match crate::pinstore::load(&crate::vaultrepo::pin_dir_for(&settings.git_dir, &url)) {
        Ok(Some(pin)) => {
            text.push_str(&format!("vault id:   {}\n", pin.vault_id));
            text.push_str(&format!(
                "pinned:     counter {}, seqfloor {}, format {}, objectformat {}\n",
                pin.counter,
                pin.seqfloor,
                pin.format,
                pin.object_format.as_str()
            ));
            text.push_str(&format!(
                "memory:     {} confirmed sequence binding(s){}\n",
                pin.sequence_memory.len(),
                if pin.pending.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", {} pending ({})",
                        pin.pending.len(),
                        pin.pending
                            .keys()
                            .map(u64::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            ));
        }
        Ok(None) => text.push_str("vault id:   (not yet seen from this repository)\n"),
        Err(e) => text.push_str(&format!("vault id:   (pin unreadable: {e})\n")),
    }
    text.push_str(&format!("join:       {}\n", join.join(" ")));
    text.push_str(
        "            On a new device, after it has its own identity, run there:\n\
         \x20             git config sealed.recipients \"<the join line above>\"\n\
         \x20           then add the new device's recipient to sealed.recipients here.\n",
    );
    out.write_all(text.as_bytes())
        .map_err(|e| CliError::Io(e.to_string()))
}

fn forget(yes: bool, remote: Option<&str>, out: &mut dyn Write) -> Result<(), CliError> {
    let git_dir = crate::settings::resolve_git_dir()?;
    let (label, url) = resolve_remote(&git_dir, remote)?;
    if !yes {
        return Err(CliError::ForgetRefused { remote: label });
    }
    // Take the §6.1 lock first so no concurrent operation is mid-write.
    let vault = VaultRepo::open(&git_dir, &url)?;
    let state = vault.state_dir().to_path_buf();
    for sub in ["pin", "mirror.git", "scratch"] {
        let path = state.join(sub);
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CliError::Io(format!("{}: {e}", path.display()))),
        }
    }
    drop(vault);
    // The directory (and its lock file) may be held by a waiter; best effort.
    let _ = std::fs::remove_dir_all(&state);
    writeln!(
        out,
        "forgot the pin, sequence memory, and mirror for {label}\n\
         ({}).\n\
         Rollback, fork, and substitution protection for this vault is gone until the\n\
         next successful read re-establishes it.",
        state.display()
    )
    .map_err(|e| CliError::Io(e.to_string()))
}

fn run_compact(remote: Option<&str>, out: &mut dyn Write) -> Result<(), CliError> {
    let settings = Settings::load()?;
    let (label, url) = resolve_remote(&settings.git_dir, remote)?;
    let vault = VaultRepo::open(&settings.git_dir, &url)?;
    let cfg = WriterConfig {
        recipients: settings.recipient_set(),
        chunk_bytes: settings.chunk_bytes,
        allow_recipient_shrink: settings.allow_recipient_shrink,
    };
    let report = compact::compact(&vault, &settings.git_dir, &settings.identities, &cfg)?;
    match report.allocated {
        Some(seq) => writeln!(
            out,
            "compacted {label}: one -full bundle at sequence {seq}, counter {} (attempt {})",
            report.counter, report.attempts
        ),
        None => writeln!(
            out,
            "compacted {label}: zero refs, manifest-only generation, counter {} (attempt {})",
            report.counter, report.attempts
        ),
    }
    .map_err(|e| CliError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn subcommands_parse_and_helper_form_does_not() {
        assert!(parse_args(&args(&["origin", "sealed::/x"])).is_none());
        assert!(parse_args(&args(&[])).is_none());
        assert_eq!(
            parse_args(&args(&["info"])).map(Result::ok),
            Some(Some(Command::Info { remote: None }))
        );
        assert_eq!(
            parse_args(&args(&["forget", "--yes", "origin"])).map(Result::ok),
            Some(Some(Command::Forget {
                yes: true,
                remote: Some("origin".into())
            }))
        );
        assert_eq!(
            parse_args(&args(&["forget"])).map(Result::ok),
            Some(Some(Command::Forget {
                yes: false,
                remote: None
            }))
        );
        assert_eq!(
            parse_args(&args(&["compact", "sealed::/v"])).map(Result::ok),
            Some(Some(Command::Compact {
                remote: Some("sealed::/v".into())
            }))
        );
        assert!(matches!(
            parse_args(&args(&["info", "a", "b"])),
            Some(Err(CliError::Usage(_)))
        ));
        assert!(matches!(
            parse_args(&args(&["forget", "--no"])),
            Some(Err(CliError::Usage(_)))
        ));
    }
}
