//! Making one vault bundle file (§4, §8.3, §9.2): `git bundle create` with
//! the real destination ref names, then age encryption streamed to a
//! scratch file with the SHA-256 of the ciphertext computed on the way, then
//! storage in the mirror whole or as chunk parts (§4.2).
//!
//! **Real ref names without a header rewrite.** §4.3 requires header refs to
//! use the true destination names and notes that a writer bundling via
//! temporary refs must rewrite the header. This implementation avoids the
//! rewrite: it bundles from a throwaway bare repository whose object store
//! is the source repository's (an `objects/info/alternates` line) and whose
//! refs are exactly `<destination name> -> <sha>`. git then records the
//! right names itself, the caller's own refs are never touched, and the
//! scratch repository is deleted afterwards. The header is still checked
//! after creation (§4.3 self-check) so a bug here can never ship a bundle
//! with foreign names.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use age::x25519::Recipient;

use crate::crypt::{self, CryptError};
use crate::manifest::{self, ManifestError, ObjectFormat};
use crate::names::{BundleName, NameError, MAX_CHUNK_DIGITS};
use crate::srcrepo;
use crate::vaultrepo::{git_command_in, run_in, GitError, VaultRepo};
use crate::HashingWriter;

#[derive(Debug)]
pub enum BundleError {
    Git(GitError),
    Crypt(CryptError),
    /// §4.3 self-check: the bundle git wrote does not look like what was
    /// asked for (wrong header, a foreign ref name, prerequisites where none
    /// were allowed).
    Header(String),
    /// §4.2/§7.2: the ciphertext would need 10^7 or more parts at the
    /// configured threshold.
    TooManyChunks {
        parts: u64,
    },
    Name(NameError),
    Io(String),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::Git(e) => write!(f, "{e}"),
            BundleError::Crypt(e) => write!(f, "{e}"),
            BundleError::Header(e) => write!(f, "bundle header self-check failed: {e}"),
            BundleError::TooManyChunks { parts } => write!(
                f,
                "the bundle would need {parts} chunk parts; the format allows fewer than 10^7 — raise sealed.chunk-mb"
            ),
            BundleError::Name(e) => write!(f, "{e}"),
            BundleError::Io(e) => write!(f, "bundling I/O error: {e}"),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<GitError> for BundleError {
    fn from(e: GitError) -> Self {
        BundleError::Git(e)
    }
}
impl From<CryptError> for BundleError {
    fn from(e: CryptError) -> Self {
        BundleError::Crypt(e)
    }
}
impl From<NameError> for BundleError {
    fn from(e: NameError) -> Self {
        BundleError::Name(e)
    }
}
impl From<ManifestError> for BundleError {
    fn from(e: ManifestError) -> Self {
        BundleError::Header(e.to_string())
    }
}

/// What to bundle.
pub struct BundleSpec<'a> {
    /// Destination ref name -> object id, exactly as the manifest will
    /// record them (§4.3: real names).
    pub refs: &'a [(String, String)],
    /// The manifest HEAD symref target: when it is among `refs`, the bundle
    /// also lists `HEAD` (§4.3 SHOULD) so a stock `git clone <bundle>`
    /// checks out the right branch.
    pub head: Option<&'a str>,
    /// Commit-ish object ids whose history is excluded (§8.3: every
    /// pre-update manifest sha present locally). Empty for a `-full`
    /// bundle (§4.1: zero prerequisites).
    pub excludes: &'a [String],
}

/// Create the plaintext bundle in `scratch`; returns its path. The caller
/// deletes it after encryption.
pub fn create(
    source_git_dir: &Path,
    of: ObjectFormat,
    scratch: &Path,
    spec: &BundleSpec<'_>,
) -> Result<PathBuf, BundleError> {
    let tmp = scratch.join("bundle-src.git");
    let out = scratch.join("plain.bundle");
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::remove_file(&out);

    let result = create_in(source_git_dir, of, &tmp, &out, spec);
    // The scratch repository holds no objects of its own (alternates), so
    // deleting it loses nothing; leaving it would let a later `ls-tree`-
    // style listing of scratch confuse a human.
    let _ = fs::remove_dir_all(&tmp);
    result?;
    Ok(out)
}

fn create_in(
    source_git_dir: &Path,
    of: ObjectFormat,
    tmp: &Path,
    out: &Path,
    spec: &BundleSpec<'_>,
) -> Result<(), BundleError> {
    let tmp_str = tmp
        .to_str()
        .ok_or_else(|| BundleError::Io(format!("scratch path {} is not UTF-8", tmp.display())))?;
    let out_str = out
        .to_str()
        .ok_or_else(|| BundleError::Io(format!("scratch path {} is not UTF-8", out.display())))?;

    // The scratch repository MUST share the source's object format: bundle
    // payload version follows it (§4.3), and alternates only make sense
    // within one format.
    let flag = format!("--object-format={}", of.as_str());
    let output = std::process::Command::new("git")
        .args(["init", "--quiet", "--bare", "-b", "main", &flag, tmp_str])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_DEFAULT_HASH")
        .output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    if !output.status.success() {
        return Err(GitError::Command {
            what: "init bundling repository".into(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }
        .into());
    }
    let objects = srcrepo::objects_dir(source_git_dir)?;
    let alternates = tmp.join("objects").join("info").join("alternates");
    fs::create_dir_all(alternates.parent().unwrap_or(tmp))
        .map_err(|e| BundleError::Io(format!("{}: {e}", alternates.display())))?;
    fs::write(&alternates, format!("{}\n", objects.display()))
        .map_err(|e| BundleError::Io(format!("{}: {e}", alternates.display())))?;

    // Refs under their real destination names (§4.3).
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (name, sha) in spec.refs {
        run_in(tmp, &["update-ref", "--no-deref", name, sha], "update-ref")?;
        names.insert(name.clone());
    }
    let mut revs = String::new();
    if let Some(head) = spec.head {
        if names.contains(head) {
            run_in(tmp, &["symbolic-ref", "HEAD", head], "symbolic-ref")?;
            revs.push_str("HEAD\n");
            names.insert("HEAD".into());
        }
    }
    for (name, _) in spec.refs {
        revs.push_str(name);
        revs.push('\n');
    }
    for ex in spec.excludes {
        revs.push('^');
        revs.push_str(ex);
        revs.push('\n');
    }

    // `--stdin`: ref names and exclusions never hit the command-line limit.
    let mut child = git_command_in(tmp, &["bundle", "create", "--quiet", out_str, "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let written = stdin.write_all(revs.as_bytes());
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|e| GitError::Spawn(e.to_string()))?;
    written.map_err(|e| BundleError::Io(format!("feeding bundle create: {e}")))?;
    if !output.status.success() {
        return Err(GitError::Command {
            what: "bundle create".into(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }
        .into());
    }

    // §4.3 self-check on what git actually wrote.
    let header = read_prefix(out, 1 << 20)?;
    check_header(&header, of, &names, spec.excludes.is_empty())?;
    Ok(())
}

/// §4.3 self-check: header line for the object format; every ref name in
/// the header is one we asked for (git may omit a requested ref whose tip
/// is excluded — those entries are informative anyway); and no
/// prerequisites when none were allowed (`-full`, §4.1).
pub(crate) fn check_header(
    plaintext: &[u8],
    of: ObjectFormat,
    allowed_names: &BTreeSet<String>,
    forbid_prerequisites: bool,
) -> Result<(), BundleError> {
    manifest::verify_bundle_header(plaintext, of)?;
    for line in plaintext.split(|b| *b == b'\n').skip(1) {
        if line.is_empty() {
            break; // end of the header; the pack follows
        }
        if line[0] == b'@' {
            continue; // v3 capability
        }
        if line[0] == b'-' {
            if forbid_prerequisites {
                return Err(BundleError::Header(
                    "a -full bundle must have zero prerequisites".into(),
                ));
            }
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let Some((_, name)) = text.split_once(' ') else {
            return Err(BundleError::Header(format!("malformed ref line {text:?}")));
        };
        if !allowed_names.contains(name) {
            return Err(BundleError::Header(format!(
                "ref {name:?} is not a destination name of this push"
            )));
        }
    }
    Ok(())
}

/// The stored, encrypted form of one logical bundle (§7.2's `bundle` line
/// plus the tree entries it stands for).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// SHA-256 of the logical (whole) ciphertext.
    pub digest: String,
    /// `Some(count)` iff chunked (§4.2), count >= 2.
    pub chunks: Option<u64>,
    /// Tree file name -> blob id in the mirror: the bare logical name, or
    /// the parts `.0` .. `.(count-1)`.
    pub blobs: Vec<(String, String)>,
}

/// Encrypt `plain_bundle` to `recipients` (§5), record the ciphertext
/// digest, and store it in the mirror as `name` — whole if at most
/// `chunk_bytes`, else in parts of `chunk_bytes` (§4.2: the threshold is
/// writer-local; cuts at arbitrary byte boundaries are fine, the manifest
/// records the count). Nothing is held in memory whole.
pub fn encrypt_and_store(
    vault: &VaultRepo,
    plain_bundle: &Path,
    recipients: &[Recipient],
    name: BundleName,
    chunk_bytes: u64,
    scratch: &Path,
) -> Result<Stored, BundleError> {
    let cipher_path = scratch.join("cipher.tmp");
    let result = encrypt_and_store_in(
        vault,
        plain_bundle,
        recipients,
        name,
        chunk_bytes,
        &cipher_path,
    );
    let _ = fs::remove_file(&cipher_path);
    result
}

fn encrypt_and_store_in(
    vault: &VaultRepo,
    plain_bundle: &Path,
    recipients: &[Recipient],
    name: BundleName,
    chunk_bytes: u64,
    cipher_path: &Path,
) -> Result<Stored, BundleError> {
    let plain = fs::File::open(plain_bundle)
        .map_err(|e| BundleError::Io(format!("{}: {e}", plain_bundle.display())))?;
    let cipher_file = fs::File::create(cipher_path)
        .map_err(|e| BundleError::Io(format!("{}: {e}", cipher_path.display())))?;
    let sink = HashingWriter::new(cipher_file);
    let (_, sink) = crypt::encrypt_stream(recipients, std::io::BufReader::new(plain), sink)?;
    let (digest, mut file) = sink.finish();
    file.flush()
        .map_err(|e| BundleError::Io(format!("{}: {e}", cipher_path.display())))?;
    let size = file
        .metadata()
        .map_err(|e| BundleError::Io(format!("{}: {e}", cipher_path.display())))?
        .len();
    drop(file);

    let chunk_bytes = chunk_bytes.max(1);
    let parts = if size > chunk_bytes {
        size.div_ceil(chunk_bytes)
    } else {
        1
    };
    if parts >= 10u64.pow(MAX_CHUNK_DIGITS as u32) {
        return Err(BundleError::TooManyChunks { parts });
    }

    let mut blobs = Vec::new();
    if parts == 1 {
        let mut whole = fs::File::open(cipher_path)
            .map_err(|e| BundleError::Io(format!("{}: {e}", cipher_path.display())))?;
        let oid = vault.write_blob_stream(&mut whole)?;
        blobs.push((name.to_string(), oid));
        return Ok(Stored {
            digest,
            chunks: None,
            blobs,
        });
    }
    for i in 0..parts {
        let mut file = fs::File::open(cipher_path)
            .map_err(|e| BundleError::Io(format!("{}: {e}", cipher_path.display())))?;
        file.seek(SeekFrom::Start(i * chunk_bytes))
            .map_err(|e| BundleError::Io(format!("{}: {e}", cipher_path.display())))?;
        let mut part = file.take(chunk_bytes);
        let oid = vault.write_blob_stream(&mut part)?;
        blobs.push((name.part(i)?.to_string(), oid));
    }
    Ok(Stored {
        digest,
        chunks: Some(parts),
        blobs,
    })
}

fn read_prefix(path: &Path, limit: usize) -> Result<Vec<u8>, BundleError> {
    let file =
        fs::File::open(path).map_err(|e| BundleError::Io(format!("{}: {e}", path.display())))?;
    let mut buf = Vec::with_capacity(limit.min(64 * 1024));
    file.take(limit as u64)
        .read_to_end(&mut buf)
        .map_err(|e| BundleError::Io(format!("{}: {e}", path.display())))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn header_check_accepts_real_names_and_head() {
        let plain = b"# v2 git bundle\n\
                      -1111111111111111111111111111111111111111 msg\n\
                      2222222222222222222222222222222222222222 HEAD\n\
                      2222222222222222222222222222222222222222 refs/heads/main\n\
                      \nPACK...";
        check_header(
            plain,
            ObjectFormat::Sha1,
            &names(&["HEAD", "refs/heads/main"]),
            false,
        )
        .expect("real names pass");
    }

    #[test]
    fn header_check_rejects_foreign_names_and_prerequisites_in_full() {
        let foreign = b"# v2 git bundle\n\
                        2222222222222222222222222222222222222222 refs/sealed-tmp/x\n\n";
        assert!(check_header(
            foreign,
            ObjectFormat::Sha1,
            &names(&["refs/heads/main"]),
            false
        )
        .is_err());

        let with_prereq = b"# v2 git bundle\n\
                            -1111111111111111111111111111111111111111 msg\n\
                            2222222222222222222222222222222222222222 refs/heads/main\n\n";
        assert!(check_header(
            with_prereq,
            ObjectFormat::Sha1,
            &names(&["refs/heads/main"]),
            true
        )
        .is_err());
        check_header(
            with_prereq,
            ObjectFormat::Sha1,
            &names(&["refs/heads/main"]),
            false,
        )
        .expect("prerequisites are fine for an incremental bundle");

        // §4.3: header version must follow the object format.
        assert!(check_header(
            with_prereq,
            ObjectFormat::Sha256,
            &names(&["refs/heads/main"]),
            false
        )
        .is_err());
    }

    #[test]
    fn header_check_tolerates_v3_capabilities() {
        let v3 = b"# v3 git bundle\n\
                   @object-format=sha256\n\
                   2222222222222222222222222222222222222222222222222222222222222222 refs/heads/main\n\n";
        check_header(v3, ObjectFormat::Sha256, &names(&["refs/heads/main"]), true)
            .expect("v3 passes");
    }
}
