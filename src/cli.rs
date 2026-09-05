//! User-facing subcommands of the `git-remote-sealed` binary, run inside a
//! repository:
//!
//! - `info [<remote-or-url>]` — read-only, offline: the vault URL, the
//!   identity file, this device's recipient(s), the extras from
//!   `sealed.recipients`, and the join line for a new device;
//! - `forget --yes [<remote-or-url>]` — §7.5: discard this repository's
//!   mirror and vault binding for that remote, and the vault's pin and
//!   sequence memory unless another remote URL of this repository is still
//!   bound to the same vault (the pin is shared per vault, §7.4). Without
//!   `--yes` it prints the warning (forgetting under attack accepts the
//!   attack) and refuses;
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
use crate::pinstore::{PinError, PinStore};
use crate::settings::{Settings, SettingsError};
use crate::srcrepo;
use crate::vaultrepo::{self, GitError, VaultRepo};
use crate::writer::{WriteError, WriterConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Info {
        remote: Option<String>,
    },
    Forget {
        yes: bool,
        remote: Option<String>,
    },
    Compact {
        remote: Option<String>,
    },
    /// `--version` / `-V`. Prints the tool version AND the format version,
    /// because "which helper is on this PATH" is a question about the
    /// FORMAT first: a helper speaking version 1 against a version 2 vault
    /// is a real failure mode, and the two version numbers move
    /// independently.
    Version,
    /// `--help` / `-h`. Without this the flag falls through to git's
    /// `<remote> <url>` form, is taken for a remote NAME, and the user gets
    /// an error about age identities — an answer to a question nobody asked.
    Help,
}

#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Settings(SettingsError),
    Git(GitError),
    Write(WriteError),
    Pin(PinError),
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
            CliError::Pin(e) => write!(f, "{e}"),
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
impl From<PinError> for CliError {
    fn from(e: PinError) -> Self {
        CliError::Pin(e)
    }
}

pub const USAGE: &str = "usage: git-remote-sealed <remote> <url>            (invoked by git)\n\
       git-remote-sealed info [<remote-or-url>]\n\
       git-remote-sealed forget --yes [<remote-or-url>]\n\
       git-remote-sealed compact [<remote-or-url>]\n\
       git-remote-sealed --version | --help";

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
        // Before the `<remote> <url>` fallthrough: git never invokes a
        // remote helper with these, and a vault URL cannot look like one.
        "--version" | "-V" if rest.is_empty() => Ok(Command::Version),
        "--help" | "-h" if rest.is_empty() => Ok(Command::Help),
        _ => return None,
    };
    Some(cmd)
}

pub fn run(cmd: Command, out: &mut dyn Write) -> Result<(), CliError> {
    match cmd {
        Command::Info { remote } => info(remote.as_deref(), out),
        Command::Forget { yes, remote } => forget(yes, remote.as_deref(), out),
        Command::Compact { remote } => run_compact(remote.as_deref(), out),
        Command::Version => writeln!(
            out,
            "git-remote-sealed {} (sealed vault format {})",
            env!("CARGO_PKG_VERSION"),
            crate::FORMAT_VERSION
        )
        .map_err(|e| CliError::Io(e.to_string())),
        // Asked for, so it is not an error: stdout and exit 0. A usage
        // MISTAKE still goes to stderr and exits non-zero, via CliError.
        Command::Help => writeln!(out, "{USAGE}").map_err(|e| CliError::Io(e.to_string())),
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
    let pins = PinStore::new(&vaultrepo::sealed_root(&settings.git_dir));
    match pins.load_for_url(&url) {
        Ok(Some(pin)) => {
            text.push_str(&format!("vault id:   {}\n", pin.vault_id));
            // The pin is per vault: every other URL bound to it shares it.
            let others: Vec<String> = pins
                .urls_of_vault(&pin.vault_id)
                .unwrap_or_default()
                .into_iter()
                .filter(|u| *u != url)
                .collect();
            if !others.is_empty() {
                text.push_str(&format!(
                    "shared:     pin also used through {}\n",
                    others.join(", ")
                ));
            }
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
         \x20           then add the new device's recipient to sealed.recipients here\n\
         \x20           and run `git-remote-sealed compact` here before cloning there.\n\
         \x20           Compaction encrypts the existing history to the new key too.\n",
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
    // Forget BEFORE migrating 0.1.0 records, never through the migration:
    // the record the user distrusts may be the one that already merged,
    // or the one that could not — either way it goes now, unmerged, and
    // a migration that failed on it can succeed afterwards.
    let pins = PinStore::new(&vaultrepo::sealed_root(&git_dir));
    pins.discard_legacy(&url)?;
    let forgotten = pins.forget_url(&url)?;
    let migration = pins.migrate_legacy();
    drop(vault);
    if let Err(e) = migration {
        writeln!(out, "note: {e}").map_err(|e| CliError::Io(e.to_string()))?;
    }
    match (&forgotten.vault_id, forgotten.pin_removed) {
        (Some(vault_id), true) => writeln!(
            out,
            "forgot the pin, sequence memory, and mirror for {label}\n\
             (vault {vault_id}, {}).\n\
             Rollback, fork, and substitution protection for this vault is gone until the\n\
             next successful read re-establishes it.",
            state.display()
        ),
        (Some(vault_id), false) => writeln!(
            out,
            "forgot the mirror and the vault binding for {label}\n\
             ({}).\n\
             The pin and sequence memory for vault {vault_id} are KEPT: this repository\n\
             still reaches that vault through {}.\n\
             They protect every URL of the vault; forget those URLs too only if the vault\n\
             was deliberately re-created.",
            state.display(),
            forgotten.kept_for.join(", ")
        ),
        (None, _) => writeln!(
            out,
            "forgot the mirror for {label} ({}); this repository held no pin for it.",
            state.display()
        ),
    }
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

    #[test]
    fn version_and_help_are_commands_not_remote_names() {
        // Without this, both fall through to git's `<remote> <url>` form,
        // are read as a remote NAME, and answer with an error about age
        // identities — the first thing a new user types, answered wrongly.
        let mut out = Vec::new();
        run(Command::Version, &mut out).expect("version");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
        // The FORMAT version is the load-bearing half: a helper speaking
        // version 1 at a version 2 vault is a real failure mode.
        assert!(
            text.contains(&format!("format {}", crate::FORMAT_VERSION)),
            "{text}"
        );

        for a in [["--version"], ["-V"]] {
            assert!(
                matches!(parse_args(&args(&a)), Some(Ok(Command::Version))),
                "{a:?}"
            );
        }
        for a in [["--help"], ["-h"]] {
            assert!(
                matches!(parse_args(&args(&a)), Some(Ok(Command::Help))),
                "{a:?}"
            );
        }

        // Only bare. `--version` with an argument is not a version request,
        // and must not shadow a URL that happens to start with a dash.
        assert!(parse_args(&args(&["--version", "x"])).is_none());
        assert!(parse_args(&args(&["--help", "x"])).is_none());
    }

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
