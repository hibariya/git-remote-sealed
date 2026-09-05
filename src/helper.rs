//! The git remote-helper protocol. git invokes `git-remote-sealed <remote>
//! <url>` for `sealed::<url>` remotes and speaks a line protocol on
//! stdin/stdout (gitremote-helpers(7)):
//!
//! - `capabilities` -> `fetch`, `push`, `option`, `object-format` (the last
//!   so a sha256 vault's 64-hex refs travel with their algorithm).
//! - `option <name> <value>` -> `ok` for the options we accept (and ignore),
//!   `unsupported` otherwise (git then refuses e.g. `--dry-run` itself).
//! - `list` / `list for-push` -> the manifest's refs plus its `@<ref> HEAD`
//!   symref line (§6.6: report exactly the manifest's refs).
//! - `fetch <sha> <name>` batch -> run the §6 pipeline; git sets refs itself
//!   afterwards (§6.5: applying never updates refs).
//! - `push [+]<src>:<dst>` batch -> run the §8 writer once for the whole
//!   batch; answer `ok <dst>` / `error <dst> <reason>` per ref.
//!
//! `list` runs §6 steps 1-4 (`reader::inspect`); `fetch` runs steps 5-6
//! (`reader::apply`); `push` reuses the `list for-push` inspection for its
//! first attempt and re-inspects on retries (§8.5). The vault handle — with
//! its §6.1 lock — is held from the first command that needs it until the
//! helper exits.

use std::fmt;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use age::x25519::Identity;

use crate::reader::{self, Inspection, ReadError};
use crate::settings::{Settings, SettingsError};
use crate::vaultrepo::{GitError, VaultRepo};
use crate::writer::{self, RefUpdate, WriteError, WriterConfig};

#[derive(Debug)]
pub enum HelperError {
    Usage,
    Settings(SettingsError),
    Read(ReadError),
    Write(WriteError),
    Git(GitError),
    /// A protocol command this helper does not implement.
    UnknownCommand(String),
    /// A `push` line git sent that is not `[+]<src>:<dst>`.
    BadPushLine(String),
    Io(String),
}

impl fmt::Display for HelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HelperError::Usage => write!(f, "{}", crate::cli::USAGE),
            HelperError::Settings(e) => write!(f, "{e}"),
            HelperError::Read(e) => write!(f, "{e}"),
            HelperError::Write(e) => write!(f, "{e}"),
            HelperError::Git(e) => write!(f, "{e}"),
            HelperError::UnknownCommand(c) => {
                write!(f, "unsupported remote-helper command {c:?}")
            }
            HelperError::BadPushLine(l) => write!(f, "malformed push line {l:?}"),
            HelperError::Io(e) => write!(f, "helper I/O error: {e}"),
        }
    }
}

impl std::error::Error for HelperError {}

impl From<ReadError> for HelperError {
    fn from(e: ReadError) -> Self {
        HelperError::Read(e)
    }
}
impl From<WriteError> for HelperError {
    fn from(e: WriteError) -> Self {
        HelperError::Write(e)
    }
}
impl From<GitError> for HelperError {
    fn from(e: GitError) -> Self {
        HelperError::Git(e)
    }
}
impl From<SettingsError> for HelperError {
    fn from(e: SettingsError) -> Self {
        HelperError::Settings(e)
    }
}

/// Entry point for the binary: resolve environment, then serve stdio.
pub fn run(remote: &str, url: &str) -> Result<(), HelperError> {
    let _ = remote; // the remote name plays no protocol role
    let url = strip_scheme(url);
    let settings = Settings::load()?;
    let mut session = Session::new(url.to_owned(), settings);

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(&mut session, stdin.lock(), stdout.lock())
}

/// git hands the helper the URL with the `sealed::` prefix already removed —
/// but be tolerant if a caller (or an alias) passes it whole.
pub fn strip_scheme(url: &str) -> &str {
    url.strip_prefix("sealed::").unwrap_or(url)
}

/// One helper invocation's state. The vault handle (and the §6.1 lock it
/// holds) and the pipeline phases are created lazily on the first command
/// that needs them, then reused.
pub struct Session {
    url: String,
    git_dir: PathBuf,
    identities: Vec<Identity>,
    writer_config: WriterConfig,
    /// `option object-format` was requested: emit `:object-format` in list.
    report_object_format: bool,
    vault: Option<VaultRepo>,
    inspection: Option<Inspection>,
    applied: bool,
}

impl Session {
    pub fn new(url: String, settings: Settings) -> Session {
        let writer_config = WriterConfig {
            recipients: settings.recipient_set(),
            chunk_bytes: settings.chunk_bytes,
            allow_recipient_shrink: settings.allow_recipient_shrink,
        };
        Session {
            url,
            git_dir: settings.git_dir,
            identities: settings.identities,
            writer_config,
            report_object_format: false,
            vault: None,
            inspection: None,
            applied: false,
        }
    }

    /// A session with no identity and no vault — enough for the commands
    /// git sends before touching the vault (tests).
    pub fn detached(url: String, git_dir: PathBuf) -> Session {
        Session {
            url,
            git_dir,
            identities: Vec::new(),
            writer_config: WriterConfig {
                recipients: Vec::new(),
                chunk_bytes: 1,
                allow_recipient_shrink: false,
            },
            report_object_format: false,
            vault: None,
            inspection: None,
            applied: false,
        }
    }

    fn vault(&mut self) -> Result<&VaultRepo, HelperError> {
        if self.vault.is_none() {
            self.vault = Some(VaultRepo::open(&self.git_dir, &self.url)?);
        }
        Ok(self.vault.as_ref().expect("just set"))
    }

    /// §6 steps 1-4, once.
    fn inspection(&mut self) -> Result<&Inspection, HelperError> {
        if self.inspection.is_none() {
            let identities = std::mem::take(&mut self.identities);
            let result = reader::inspect(self.vault()?, &identities);
            self.identities = identities;
            self.inspection = Some(result?);
        }
        Ok(self.inspection.as_ref().expect("just set"))
    }

    /// §6 steps 5-6, once.
    fn apply(&mut self) -> Result<(), HelperError> {
        if self.applied {
            return Ok(());
        }
        self.inspection()?;
        let identities = std::mem::take(&mut self.identities);
        let inspection = self.inspection.take().expect("inspected above");
        let git_dir = self.git_dir.clone();
        let result = match &inspection {
            Inspection::Empty => Ok(()),
            Inspection::Vault(prepared) => match self.vault() {
                Ok(vault) => {
                    reader::apply(vault, &git_dir, &identities, prepared).map_err(HelperError::from)
                }
                Err(e) => Err(e),
            },
        };
        self.inspection = Some(inspection);
        self.identities = identities;
        result?;
        self.applied = true;
        Ok(())
    }

    /// §8 for one push batch. The inspection `list for-push` did (if any)
    /// serves the first attempt; afterwards the session's view of the vault
    /// is stale, so it is dropped.
    fn push(&mut self, updates: &[RefUpdate]) -> Result<writer::PushReport, HelperError> {
        let identities = std::mem::take(&mut self.identities);
        let first = self.inspection.take();
        self.applied = false;
        let result = match self.vault() {
            Ok(_) => {
                let vault = self.vault.as_ref().expect("just opened");
                writer::push(
                    vault,
                    &self.git_dir,
                    &identities,
                    &self.writer_config,
                    updates,
                    first,
                )
                .map_err(HelperError::from)
            }
            Err(e) => Err(e),
        };
        self.identities = identities;
        result
    }
}

/// The stdio protocol loop, separated from process wiring for testability.
pub fn serve<R: BufRead, W: Write>(
    session: &mut Session,
    input: R,
    mut output: W,
) -> Result<(), HelperError> {
    let mut lines = input.lines();
    while let Some(line) = lines.next() {
        let line = line.map_err(|e| HelperError::Io(e.to_string()))?;
        let mut words = line.split(' ');
        match words.next().unwrap_or("") {
            // A blank line outside a batch ends the conversation politely.
            "" => break,
            "capabilities" => {
                write_all(&mut output, "fetch\npush\noption\nobject-format\n\n")?;
            }
            "option" => {
                // Accepted and ignored: verbosity/progress tune output this
                // helper does not produce; object-format arms the `:object-
                // format` line below. Everything else is `unsupported` —
                // including `cas` (git's --force-with-lease), `dry-run`,
                // `atomic`, and `push-option`, which git then refuses itself.
                let reply = match words.next().unwrap_or("") {
                    "verbosity" | "progress" => "ok",
                    "object-format" => {
                        session.report_object_format = true;
                        "ok"
                    }
                    _ => "unsupported",
                };
                write_all(&mut output, &format!("{reply}\n"))?;
            }
            "list" => {
                // `list` and `list for-push` answer the same way: the
                // manifest is the sole authority for what refs exist.
                let report = session.report_object_format;
                let out = session.inspection()?.outcome();
                let mut listing = String::new();
                if report {
                    if let Some(of) = out.object_format {
                        listing.push_str(&format!(":object-format {}\n", of.as_str()));
                    }
                }
                // §6.6: exactly the manifest's refs, plus its HEAD symref.
                for (refname, sha) in &out.refs {
                    listing.push_str(&format!("{sha} {refname}\n"));
                }
                if let Some(head) = &out.head {
                    listing.push_str(&format!("@{head} HEAD\n"));
                }
                listing.push('\n');
                write_all(&mut output, &listing)?;
            }
            "fetch" => {
                // Consume the whole batch (more `fetch` lines up to a blank
                // line): the §6 pipeline applies every listed bundle at
                // once, so the individual requests carry no information.
                for batch_line in lines.by_ref() {
                    let batch_line = batch_line.map_err(|e| HelperError::Io(e.to_string()))?;
                    if batch_line.is_empty() {
                        break;
                    }
                    if !batch_line.starts_with("fetch ") {
                        return Err(HelperError::UnknownCommand(batch_line));
                    }
                }
                session.apply()?;
                write_all(&mut output, "\n")?;
            }
            "push" => {
                // The whole batch is one §8 push: one bundle, one commit.
                let mut updates = vec![parse_push_line(&line)?];
                for batch_line in lines.by_ref() {
                    let batch_line = batch_line.map_err(|e| HelperError::Io(e.to_string()))?;
                    if batch_line.is_empty() {
                        break;
                    }
                    updates.push(parse_push_line(&batch_line)?);
                }
                let mut status = String::new();
                match session.push(&updates) {
                    Ok(report) => {
                        for r in &report.results {
                            match &r.error {
                                None => status.push_str(&format!("ok {}\n", r.dst)),
                                Some(why) => {
                                    status.push_str(&format!("error {} {}\n", r.dst, one_line(why)))
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // A whole-push failure: every ref is reported as
                        // failed with the reason, and the full text goes to
                        // stderr (git relays it verbatim).
                        eprintln!("git-remote-sealed: {e}");
                        let why = one_line(&e.to_string());
                        for u in &updates {
                            status.push_str(&format!("error {} {why}\n", u.dst));
                        }
                    }
                }
                status.push('\n');
                write_all(&mut output, &status)?;
            }
            _ => return Err(HelperError::UnknownCommand(line.clone())),
        }
        output.flush().map_err(|e| HelperError::Io(e.to_string()))?;
    }
    Ok(())
}

/// `push [+]<src>:<dst>`; an empty `<src>` deletes `<dst>`.
pub(crate) fn parse_push_line(line: &str) -> Result<RefUpdate, HelperError> {
    let bad = || HelperError::BadPushLine(line.to_owned());
    let spec = line.strip_prefix("push ").ok_or_else(bad)?;
    let (force, spec) = match spec.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, spec),
    };
    // A refname cannot contain ':', so the first one splits src from dst.
    let (src, dst) = spec.split_once(':').ok_or_else(bad)?;
    if dst.is_empty() {
        return Err(bad());
    }
    Ok(RefUpdate {
        dst: dst.to_owned(),
        src: if src.is_empty() {
            None
        } else {
            Some(src.to_owned())
        },
        force,
    })
}

/// Status lines are one line each.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn write_all<W: Write>(output: &mut W, text: &str) -> Result<(), HelperError> {
    output
        .write_all(text.as_bytes())
        .map_err(|e| HelperError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_prefix_is_stripped_tolerantly() {
        assert_eq!(strip_scheme("sealed::/tmp/vault.git"), "/tmp/vault.git");
        assert_eq!(strip_scheme("/tmp/vault.git"), "/tmp/vault.git");
        assert_eq!(strip_scheme("sealed::https://host/x"), "https://host/x");
    }

    #[test]
    fn options_answer_before_any_vault_work() {
        // capabilities/option must not touch the vault (git sends them
        // first, even for URLs that turn out unreachable).
        let mut session = Session::detached("/nonexistent".into(), PathBuf::from("/nonexistent"));
        let input = b"capabilities\noption verbosity 1\noption progress true\noption depth 3\noption cas x:y\n";
        let mut out = Vec::new();
        serve(&mut session, &input[..], &mut out).expect("serves");
        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            "fetch\npush\noption\nobject-format\n\nok\nok\nunsupported\nunsupported\n"
        );
    }

    #[test]
    fn push_lines_parse_per_gitremote_helpers() {
        assert_eq!(
            parse_push_line("push refs/heads/main:refs/heads/main").expect("parses"),
            RefUpdate {
                dst: "refs/heads/main".into(),
                src: Some("refs/heads/main".into()),
                force: false
            }
        );
        assert_eq!(
            parse_push_line("push +HEAD:refs/heads/main").expect("parses"),
            RefUpdate {
                dst: "refs/heads/main".into(),
                src: Some("HEAD".into()),
                force: true
            }
        );
        assert_eq!(
            parse_push_line("push :refs/tags/v1").expect("parses"),
            RefUpdate {
                dst: "refs/tags/v1".into(),
                src: None,
                force: false
            }
        );
        assert!(parse_push_line("push refs/heads/main").is_err());
        assert!(parse_push_line("push a:").is_err());
        assert!(parse_push_line("pull a:b").is_err());
    }

    #[test]
    fn status_reasons_are_one_line() {
        assert_eq!(one_line("a\nb  c\n"), "a b c");
    }
}
