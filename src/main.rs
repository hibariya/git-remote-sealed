//! `git-remote-sealed` — the remote helper binary. git invokes it as
//! `git-remote-sealed <remote-name> <url>` for `sealed::<url>` remotes and
//! speaks the helper protocol on stdin/stdout (see `helper.rs`). Run by a
//! person, it also serves the subcommands `info`, `forget`, and `compact`
//! (see `cli.rs`).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if let Some(parsed) = sealed::cli::parse_args(&args) {
        let outcome = parsed.and_then(|cmd| {
            let stdout = std::io::stdout();
            sealed::cli::run(cmd, &mut stdout.lock())
        });
        return match outcome {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("git-remote-sealed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let (remote, url) = match args.as_slice() {
        [remote, url] => (remote.as_str(), url.as_str()),
        // git also allows a single argument (the URL doubles as the name).
        [url] => (url.as_str(), url.as_str()),
        _ => {
            eprintln!("{}", sealed::helper::HelperError::Usage);
            return ExitCode::FAILURE;
        }
    };
    match sealed::helper::run(remote, url) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // git relays helper stderr to the user verbatim.
            eprintln!("git-remote-sealed: {e}");
            ExitCode::FAILURE
        }
    }
}
