//! FORMAT.md Appendix A ("Disaster recovery with stock tools"), executed
//! LITERALLY: the `sh` code block is extracted from the spec file at test
//! time, its example bundle names are swapped for the names a real vault
//! holds, and the result runs under `/bin/sh` with the stock `git` and
//! `age` binaries — no code of this crate touches the recovery. If the
//! block cannot be found, has a shape this expander does not understand,
//! or any command fails, the test fails: doc drift fails CI by design.
//!
//! How the block is read (the only assumptions made about its shape):
//! - it names exactly one `-full` bundle and exactly one incremental
//!   bundle (grammar of §4.1, judged by `sealed::names::classify`) — those
//!   two names are the placeholders;
//! - it is split into paragraphs at blank lines;
//! - a paragraph naming the incremental placeholder is repeated once per
//!   incremental with a higher sequence than the highest `-full`, in
//!   ascending numeric order;
//! - a paragraph naming the `-full` placeholder and running `age -d` is
//!   the root step, run once for the highest `-full`;
//! - a paragraph naming the `-full` placeholder without `age -d` is the
//!   chunk reassembly, run once per CHUNKED logical file (the spec's "if
//!   chunked" — the loop's `> "$n"` would truncate an unchunked file);
//! - any other paragraph runs once, verbatim.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sealed::names::{self, NameClass};

use super::{assert_ok, HERMETIC_ENV};

/// `docs/FORMAT.md`: `SEALED_SPEC` if set, else found by walking up from
/// the crate directory. Both layouts are tried at each level —
/// `docs/FORMAT.md` here, and the `docs/architecture/` the spec lived
/// under while it was vendored from a monorepo — so a checkout of either
/// shape finds its own spec rather than silently testing against none.
pub fn spec_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SEALED_SPEC") {
        return PathBuf::from(p);
    }
    let mut dir = Some(Path::new(env!("CARGO_MANIFEST_DIR")));
    while let Some(d) = dir {
        for candidate in [
            d.join("docs").join("FORMAT.md"),
            d.join("docs").join("architecture").join("FORMAT.md"),
        ] {
            if candidate.is_file() {
                return candidate;
            }
        }
        dir = d.parent();
    }
    panic!(
        "FORMAT.md not found above {} (set SEALED_SPEC)",
        env!("CARGO_MANIFEST_DIR")
    );
}

/// The recipe as the spec prints it, plus the two example names it uses.
pub struct Recipe {
    pub text: String,
    pub full_placeholder: String,
    pub inc_placeholder: String,
}

/// Every ```sh block under "## Appendix A", concatenated in order.
pub fn appendix_a_shell_blocks() -> String {
    let path = spec_path();
    let spec =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let start = spec
        .find("\n## Appendix A")
        .expect("FORMAT.md has a '## Appendix A' heading");
    let section = &spec[start + 1..];
    let end = section[3..]
        .find("\n## ")
        .map(|i| i + 3)
        .unwrap_or(section.len());
    let section = &section[..end];

    let mut out = String::new();
    let mut in_block = false;
    for line in section.lines() {
        if !in_block {
            if line.trim_end() == "```sh" {
                in_block = true;
            }
        } else if line.trim_end() == "```" {
            in_block = false;
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(!in_block, "unterminated code block in Appendix A");
    assert!(
        !out.trim().is_empty(),
        "no ```sh code block under Appendix A in {}",
        path.display()
    );
    out
}

pub fn recipe() -> Recipe {
    let text = appendix_a_shell_blocks();
    let mut fulls = BTreeSet::new();
    let mut incs = BTreeSet::new();
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    {
        if let NameClass::Canonical(name) = names::classify(token) {
            if name.chunk().is_some() {
                continue;
            }
            if name.is_full() {
                fulls.insert(token.to_owned());
            } else {
                incs.insert(token.to_owned());
            }
        }
    }
    assert_eq!(
        fulls.len(),
        1,
        "the recipe must name exactly one -full example bundle: {fulls:?}"
    );
    assert_eq!(
        incs.len(),
        1,
        "the recipe must name exactly one incremental example bundle: {incs:?}"
    );
    Recipe {
        text,
        full_placeholder: fulls.into_iter().next().expect("one"),
        inc_placeholder: incs.into_iter().next().expect("one"),
    }
}

/// What a recovering human sees in the directory of vault files, judged
/// by file NAME alone (the simple recipe trusts names): `(seq, name)`.
pub struct Listing {
    /// Logical files stored in parts (`name.0` exists), ascending.
    pub chunked: Vec<(u64, String)>,
    /// The `-full` bundle with the highest sequence number, if any.
    pub highest_full: Option<(u64, String)>,
    /// Incrementals with a higher sequence than `highest_full`, ascending.
    pub incrementals: Vec<(u64, String)>,
    /// Every canonical (grammar-matching) file name present, as found.
    pub canonical_names: BTreeSet<String>,
}

pub fn list_vault_dir(dir: &Path) -> Listing {
    let mut canonical_names = BTreeSet::new();
    let mut logical: BTreeSet<(u64, bool, String)> = BTreeSet::new();
    let mut chunked: BTreeSet<(u64, String)> = BTreeSet::new();
    for entry in fs::read_dir(dir).expect("list vault dir") {
        let entry = entry.expect("dirent");
        if !entry.file_type().expect("file type").is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let NameClass::Canonical(parsed) = names::classify(&name) {
            canonical_names.insert(name.clone());
            let base = parsed.logical();
            logical.insert((base.seq(), base.is_full(), base.to_string()));
            if parsed.chunk().is_some() {
                chunked.insert((base.seq(), base.to_string()));
            }
        }
    }
    let highest_full = logical
        .iter()
        .filter(|(_, full, _)| *full)
        .max_by_key(|(seq, _, _)| *seq)
        .map(|(seq, _, name)| (*seq, name.clone()));
    let incrementals = match &highest_full {
        None => Vec::new(),
        Some((root, _)) => logical
            .iter()
            .filter(|(seq, full, _)| !*full && *seq > *root)
            .map(|(seq, _, name)| (*seq, name.clone()))
            .collect(),
    };
    Listing {
        chunked: chunked.into_iter().collect(),
        highest_full,
        incrementals,
        canonical_names,
    }
}

/// The recipe instantiated for `listing`; `None` when there is no `-full`
/// bundle at all (an intentionally emptied vault "recovers to nothing").
pub fn instantiate(recipe: &Recipe, listing: &Listing) -> Option<String> {
    let (_, full_name) = listing.highest_full.as_ref()?;
    let mut blocks = vec![String::from(
        "# Generated from FORMAT.md Appendix A by tests/common/appendix_a.rs;\n\
         # only the example bundle names were substituted.",
    )];
    for paragraph in recipe.text.split("\n\n") {
        let paragraph = paragraph.trim_matches('\n');
        if paragraph.trim().is_empty() {
            continue;
        }
        let has_full = paragraph.contains(&recipe.full_placeholder);
        let has_inc = paragraph.contains(&recipe.inc_placeholder);
        if has_inc {
            for (_, name) in &listing.incrementals {
                blocks.push(paragraph.replace(&recipe.inc_placeholder, name));
            }
        } else if has_full && paragraph.contains("age -d") {
            blocks.push(paragraph.replace(&recipe.full_placeholder, full_name));
        } else if has_full {
            for (_, name) in &listing.chunked {
                blocks.push(paragraph.replace(&recipe.full_placeholder, name));
            }
        } else {
            blocks.push(paragraph.to_owned());
        }
    }
    Some(blocks.join("\n\n") + "\n")
}

/// Run `script` with `/bin/sh -eu` inside `dir` (hermetic git env).
pub fn run_sh(dir: &Path, script: &str) -> Output {
    let path = dir.join("recipe.sh");
    fs::write(&path, script).expect("write recipe.sh");
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-eu", "recipe.sh"]).current_dir(dir);
    for (k, v) in HERMETIC_ENV {
        cmd.env(k, v);
    }
    cmd.output().expect("/bin/sh must be runnable")
}

pub fn run_sh_ok(dir: &Path, script: &str) {
    let out = run_sh(dir, script);
    if !out.status.success() {
        // Diagnostics for a failed run: what the directory held, and what
        // git itself thinks of the decrypted root bundle.
        let diag = run_sh(
            dir,
            "ls -la; env | grep -i '^git' || true; head -c 200 full.bundle | od -c | head -12; \
             git bundle verify full.bundle; git bundle list-heads full.bundle",
        );
        panic!(
            "Appendix A recipe:\n{script}\nfailed:\n{}{}\n--- diagnostics ---\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&diag.stdout),
            String::from_utf8_lossy(&diag.stderr),
        );
    }
}

/// `age -d -i key.txt <file>` with the stock age binary, inside `dir`.
pub fn age_decrypt(dir: &Path, file: &str) -> Vec<u8> {
    let out = Command::new("age")
        .args(["-d", "-i", "key.txt", file])
        .current_dir(dir)
        .output()
        .expect("the age CLI must be installed (Dockerfile)");
    assert_ok(&out, &format!("age -d -i key.txt {file}"));
    out.stdout
}

/// `sha256sum <file>` (coreutils) inside `dir`, lowercase hex.
pub fn sha256sum(dir: &Path, file: &str) -> String {
    let out = Command::new("sha256sum")
        .arg(file)
        .current_dir(dir)
        .output()
        .expect("sha256sum must be runnable");
    assert_ok(&out, &format!("sha256sum {file}"));
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("digest")
        .to_owned()
}
