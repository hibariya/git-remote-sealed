//! User-facing subcommands of the `git-remote-sealed` binary, run inside a
//! repository:
//!
//! - `info [<remote-or-url>]` — read-only: the vault URL, the identity
//!   file, this device's recipient(s), what the pin remembers, and the
//!   recipient set the vault's manifest declares (a listing-only read, §6
//!   steps 1–4, which persists nothing);
//! - `enroll <age1…> [<remote-or-url>]` — §9.1: add a recipient and compact,
//!   so the whole history is readable by it;
//! - `revoke [--yes] <age1…> [<remote-or-url>]` — §9.1: remove a recipient
//!   and compact; `--yes` is required to remove this device's own key;
//! - `upgrade [--yes] [<remote-or-url>]` — §9.2: record the recipient set
//!   in a vault written before the manifest declared one; `--yes` accepts
//!   the set when the ciphertext's recipient count cannot be determined;
//! - `forget --yes [<remote-or-url>]` — §7.5: discard this repository's
//!   mirror and vault binding for that remote, and the vault's pin and
//!   sequence memory unless another remote URL of this repository is still
//!   bound to the same vault (the pin is shared per vault, §7.4). Without
//!   `--yes` it prints the warning (forgetting under attack accepts the
//!   attack) and refuses;
//! - `compact [--repair] [<remote-or-url>]` — §9; `--repair` reads through
//!   a §5 declared-vs-actual mismatch so the rewrite fixes it.
//!
//! A remote is named by its git remote name (resolved with `git remote
//! get-url`) or given as a `sealed::<url>` URL. With no argument, the one
//! `sealed::` remote of the repository is used.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use age::x25519::Recipient;

use crate::compact::{self, Compaction, SetChange};
use crate::helper::strip_scheme;
use crate::pinstore::{PinError, PinStore};
use crate::reader::{self, Inspection};
use crate::settings::{Settings, SettingsError};
use crate::srcrepo;
use crate::vaultrepo::{self, GitError, VaultRepo};
use crate::writer::WriteError;

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
        /// §5 repair: read through a declared-vs-actual mismatch and
        /// rewrite the vault encrypted to the declared set.
        repair: bool,
        remote: Option<String>,
    },
    Enroll {
        key: String,
        remote: Option<String>,
    },
    Revoke {
        key: String,
        yes: bool,
        remote: Option<String>,
    },
    Upgrade {
        yes: bool,
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
    /// `enroll`/`revoke` with something that is not an age recipient.
    BadRecipient {
        token: String,
        detail: String,
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
            CliError::BadRecipient { token, detail } => write!(
                f,
                "{token:?} is not an age recipient ({detail}); expected the PUBLIC half of a key, `age1...`"
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
       git-remote-sealed enroll <age1...> [<remote-or-url>]\n\
       git-remote-sealed revoke [--yes] <age1...> [<remote-or-url>]\n\
       git-remote-sealed upgrade [--yes] [<remote-or-url>]\n\
       git-remote-sealed compact [--repair] [<remote-or-url>]\n\
       git-remote-sealed forget --yes [<remote-or-url>]\n\
       git-remote-sealed --version | --help\n\
\n\
  info      show the identity, the pin, and the recipients the vault records\n\
  enroll    add a recipient (a device or a recovery key, its PUBLIC age1... half)\n\
            and compact, so the whole history becomes readable by it\n\
  revoke    remove a recipient and compact (--yes to remove this device's own)\n\
  upgrade   record the recipient set in a vault written before 0.3.0; it must\n\
            match the number of keys the vault is encrypted to (--yes when\n\
            that number cannot be determined)\n\
  compact   rewrite the vault as one snapshot; deleted history leaves the host\n\
            (--repair: also when the vault is encrypted to a different set\n\
            than its manifest declares, which every other command refuses)\n\
  forget    discard this repository's memory of the vault (read the warning)\n\
\n\
  The identity comes from SEALED_IDENTITY or `git config sealed.identity`.\n\
  Recipients live in the vault's manifest, not in config; the first push\n\
  declares this device's key, `enroll` adds the others.";

/// Recognize a subcommand invocation. `None` = not a subcommand (git's
/// `<remote> <url>` form). A remote literally named like a subcommand
/// cannot be driven by git through this binary (documented limitation).
pub fn parse_args(args: &[String]) -> Option<Result<Command, CliError>> {
    let (name, rest) = args.split_first()?;
    let cmd = match name.as_str() {
        "info" => positional(rest, 0, 1, &[]).map(|p| Command::Info {
            remote: p.remote(0),
        }),
        "forget" => positional(rest, 0, 1, &[YES]).map(|p| Command::Forget {
            yes: p.has(YES),
            remote: p.remote(0),
        }),
        "compact" => positional(rest, 0, 1, &[REPAIR]).map(|p| Command::Compact {
            repair: p.has(REPAIR),
            remote: p.remote(0),
        }),
        "enroll" => positional(rest, 1, 2, &[]).map(|p| Command::Enroll {
            key: p.args[0].clone(),
            remote: p.remote(1),
        }),
        "revoke" => positional(rest, 1, 2, &[YES]).map(|p| Command::Revoke {
            key: p.args[0].clone(),
            yes: p.has(YES),
            remote: p.remote(1),
        }),
        "upgrade" => positional(rest, 0, 1, &[YES]).map(|p| Command::Upgrade {
            yes: p.has(YES),
            remote: p.remote(0),
        }),
        // Before the `<remote> <url>` fallthrough: git never invokes a
        // remote helper with these, and a vault URL cannot look like one.
        "--version" | "-V" if rest.is_empty() => Ok(Command::Version),
        "--help" | "-h" if rest.is_empty() => Ok(Command::Help),
        _ => return None,
    };
    Some(cmd)
}

const YES: &str = "--yes";
const REPAIR: &str = "--repair";

/// A verb's parsed arguments: the flags seen and the positional ones.
struct Parsed {
    flags: BTreeSet<String>,
    args: Vec<String>,
}

impl Parsed {
    fn has(&self, flag: &str) -> bool {
        self.flags.contains(flag)
    }

    /// The optional remote: the positional argument at `index`.
    fn remote(&self, index: usize) -> Option<String> {
        self.args.get(index).cloned()
    }
}

/// The verb's `flags` anywhere, plus `min..=max` positional arguments;
/// anything else — a flag the verb does not take included — is a usage
/// error, so that `info --yes` is refused rather than silently obeyed.
fn positional(rest: &[String], min: usize, max: usize, flags: &[&str]) -> Result<Parsed, CliError> {
    let mut parsed = Parsed {
        flags: BTreeSet::new(),
        args: Vec::new(),
    };
    for a in rest {
        if flags.contains(&a.as_str()) {
            parsed.flags.insert(a.clone());
        } else if a.starts_with('-') {
            return Err(CliError::Usage(USAGE.into()));
        } else {
            parsed.args.push(a.clone());
        }
    }
    if parsed.args.len() < min || parsed.args.len() > max {
        return Err(CliError::Usage(USAGE.into()));
    }
    Ok(parsed)
}

pub fn run(cmd: Command, out: &mut dyn Write) -> Result<(), CliError> {
    match cmd {
        Command::Info { remote } => info(remote.as_deref(), out),
        Command::Forget { yes, remote } => forget(yes, remote.as_deref(), out),
        Command::Compact { repair, remote } => {
            change_set(remote.as_deref(), SetChange::Keep { repair }, out)
        }
        Command::Enroll { key, remote } => {
            let key = parse_recipient(&key)?;
            change_set(remote.as_deref(), SetChange::Enroll(key), out)
        }
        Command::Revoke { key, yes, remote } => {
            let key = parse_recipient(&key)?;
            change_set(remote.as_deref(), SetChange::Revoke { key, yes }, out)
        }
        Command::Upgrade { yes, remote } => {
            change_set(remote.as_deref(), SetChange::Upgrade { yes }, out)
        }
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

    let mut text = String::new();
    text.push_str(&format!("vault:      {label}\n"));
    text.push_str(&format!(
        "identity:   {}\n",
        settings.identity_path.display()
    ));
    for r in &own {
        text.push_str(&format!("recipient:  {r} (this device)\n"));
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
    // §5: the recipient set is whatever the vault's manifest declares —
    // read from the vault (steps 1–4 only: nothing is applied or pinned).
    // A vault this device cannot reach right now still gets the rest.
    match declared_recipients(&settings, &url) {
        Ok(Some(set)) if set.is_empty() => text.push_str(
            "recipients: not recorded in this vault yet (run `git-remote-sealed upgrade`)\n",
        ),
        Ok(Some(set)) => {
            for r in &set {
                let mark = if own.contains(r) {
                    " (this device)"
                } else {
                    ""
                };
                text.push_str(&format!("recipients: {r}{mark}\n"));
            }
        }
        Ok(None) => text.push_str(
            "recipients: (vault not initialized yet: the first push declares this device's key)\n",
        ),
        Err(e) => text.push_str(&format!("recipients: (vault unreadable: {e})\n")),
    }
    text.push_str(
        "            To add a device: run `git-remote-sealed enroll <its age1... key>` here,\n\
         \x20           then clone there. Keys never move between devices; the new device's\n\
         \x20           own `git-remote-sealed info` shows the key to enroll.\n",
    );
    out.write_all(text.as_bytes())
        .map_err(|e| CliError::Io(e.to_string()))
}

/// The recipient set the vault's manifest declares (`None` = empty vault).
fn declared_recipients(
    settings: &Settings,
    url: &str,
) -> Result<Option<BTreeSet<String>>, CliError> {
    let vault = VaultRepo::open(&settings.git_dir, url)?;
    match reader::inspect(&vault, &settings.identities).map_err(WriteError::Read)? {
        Inspection::Empty => Ok(None),
        Inspection::Vault(p) => Ok(Some(p.manifest().recipients.clone())),
    }
}

fn parse_recipient(token: &str) -> Result<Recipient, CliError> {
    Recipient::from_str(token).map_err(|detail| CliError::BadRecipient {
        token: token.to_owned(),
        detail: detail.to_string(),
    })
}

/// `compact`, `enroll`, `revoke`, `upgrade`: a compaction (§9), with the
/// set changed per `change` (§9.1, §9.2), reported with the recorded keys
/// in full — they are what the other devices must be able to see in
/// `info`.
fn change_set(
    remote: Option<&str>,
    change: SetChange,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let settings = Settings::load()?;
    let (label, url) = resolve_remote(&settings.git_dir, remote)?;
    let vault = VaultRepo::open(&settings.git_dir, &url)?;
    let cfg = settings.writer_config();
    let outcome = compact::compact(
        &vault,
        &settings.git_dir,
        &settings.identities,
        &cfg,
        &change,
    )?;
    let own: BTreeSet<String> = cfg.own_recipients.iter().map(ToString::to_string).collect();
    let listing = |set: &BTreeSet<String>| -> String {
        set.iter()
            .map(|r| {
                let mark = if own.contains(r) {
                    " (this device)"
                } else {
                    ""
                };
                format!("    {r}{mark}\n")
            })
            .collect()
    };
    let text = match (&change, outcome) {
        (SetChange::Enroll(key), Compaction::NothingToDo { recipients }) => format!(
            "{key} is already a recipient of {label}; nothing to do.\nrecipients ({}):\n{}",
            recipients.len(),
            listing(&recipients)
        ),
        (SetChange::Revoke { key, .. }, Compaction::NothingToDo { recipients }) => format!(
            "{key} is not a recipient of {label}; nothing to do.\nrecipients ({}):\n{}",
            recipients.len(),
            listing(&recipients)
        ),
        (SetChange::Upgrade { .. }, Compaction::NothingToDo { recipients }) => format!(
            "{label} already records {} recipients; nothing to do.\nrecipients:\n{}",
            recipients.len(),
            listing(&recipients)
        ),
        (SetChange::Keep { .. }, Compaction::NothingToDo { .. }) => {
            unreachable!("Keep always compacts")
        }
        (change, Compaction::Done(report)) => {
            let what = match change {
                SetChange::Enroll(key) => format!("enrolled {key} in {label}"),
                SetChange::Revoke { key, .. } => format!(
                    "revoked {key} from {label}\n\
                     (not erasure: earlier generations the host may retain stay readable by it, \
                     and it keeps whatever it already fetched)"
                ),
                SetChange::Upgrade { .. } => {
                    format!("upgraded {label}: its manifest now records its recipients")
                }
                SetChange::Keep { .. } => match &report.repaired {
                    Some(m) => format!(
                        "compacted and repaired {label}: {m}, so every file is now re-encrypted to the declared set"
                    ),
                    None => format!("compacted {label}"),
                },
            };
            let how = match report.allocated {
                Some(seq) => format!("one -full bundle at sequence {seq}"),
                None => "zero refs, manifest-only generation".to_owned(),
            };
            format!(
                "{what}.\nThe vault is now encrypted to {} recipient(s):\n{}\
                 (compacted: {how}, counter {}, attempt {})\n",
                report.recipients.len(),
                listing(&report.recipients),
                report.counter,
                report.attempts
            )
        }
    };
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
                repair: false,
                remote: Some("sealed::/v".into())
            }))
        );
        assert_eq!(
            parse_args(&args(&["compact", "--repair"])).map(Result::ok),
            Some(Some(Command::Compact {
                repair: true,
                remote: None
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
        // A flag a verb does not take is a usage error, not silently
        // accepted: USAGE lists these verbs without it.
        for a in [
            &["info", "--yes"][..],
            &["compact", "--yes"],
            &["enroll", "age1x", "--yes"],
            &["upgrade", "--repair"],
            &["revoke", "age1x", "--repair"],
            &["forget", "--repair"],
        ] {
            assert!(
                matches!(parse_args(&args(a)), Some(Err(CliError::Usage(_)))),
                "{a:?}"
            );
        }
    }

    #[test]
    fn recipient_verbs_parse() {
        let key = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        assert_eq!(
            parse_args(&args(&["enroll", key])).map(Result::ok),
            Some(Some(Command::Enroll {
                key: key.into(),
                remote: None
            }))
        );
        assert_eq!(
            parse_args(&args(&["enroll", key, "origin"])).map(Result::ok),
            Some(Some(Command::Enroll {
                key: key.into(),
                remote: Some("origin".into())
            }))
        );
        assert_eq!(
            parse_args(&args(&["revoke", "--yes", key])).map(Result::ok),
            Some(Some(Command::Revoke {
                key: key.into(),
                yes: true,
                remote: None
            }))
        );
        assert_eq!(
            parse_args(&args(&["revoke", key, "origin", "--yes"])).map(Result::ok),
            Some(Some(Command::Revoke {
                key: key.into(),
                yes: true,
                remote: Some("origin".into())
            }))
        );
        assert_eq!(
            parse_args(&args(&["upgrade"])).map(Result::ok),
            Some(Some(Command::Upgrade {
                yes: false,
                remote: None
            }))
        );
        assert_eq!(
            parse_args(&args(&["upgrade", "--yes", "sealed::/v"])).map(Result::ok),
            Some(Some(Command::Upgrade {
                yes: true,
                remote: Some("sealed::/v".into())
            }))
        );
        // The key is required, and only one remote fits.
        assert!(matches!(
            parse_args(&args(&["enroll"])),
            Some(Err(CliError::Usage(_)))
        ));
        assert!(matches!(
            parse_args(&args(&["revoke", key, "a", "b"])),
            Some(Err(CliError::Usage(_)))
        ));
        // Not a recipient: refused at run time, before any vault work.
        let mut out = Vec::new();
        assert!(matches!(
            run(
                Command::Enroll {
                    key: "AGE-SECRET-KEY-1NOTPUBLIC".into(),
                    remote: None
                },
                &mut out
            ),
            Err(CliError::BadRecipient { .. })
        ));
        // Help names every verb.
        for verb in ["enroll", "revoke", "upgrade", "compact", "forget", "info"] {
            assert!(
                USAGE.contains(&format!("git-remote-sealed {verb}")),
                "{verb}"
            );
        }
    }
}
