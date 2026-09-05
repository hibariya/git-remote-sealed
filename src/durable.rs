//! Filesystem operations for security state that must survive a restart.

use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;

pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// Create directories from the top down, saving each directory entry
/// before creating its children. Sync the parent even when `dir` exists:
/// a previous attempt may have created it but failed to sync its parent.
pub(crate) fn create_dir_all(dir: &Path) -> io::Result<()> {
    let parent = dir.parent().map(|p| {
        if p.as_os_str().is_empty() {
            Path::new(".")
        } else {
            p
        }
    });
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let Some(parent) = parent else {
                return Err(e);
            };
            create_dir_all(parent)?;
            match fs::create_dir(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => {}
                Err(e) => return Err(e),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => {}
        Err(e) => return Err(e),
    }
    match parent {
        Some(parent) => sync_dir(parent),
        None => Ok(()),
    }
}

/// Write `bytes` to `path` so that the file is either the old content or
/// the new one after a crash, never a mix: write a temporary file, sync
/// its contents, rename it over the destination, then sync the directory
/// entry. The parent directory is created (durably) if needed.
pub(crate) fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_file_with_sync(path, bytes, fs::File::sync_all)
}

/// `write_file` with the sync step injectable (tests simulate a failing
/// disk). `sync` is called once for the temporary file and once for the
/// directory.
pub(crate) fn write_file_with_sync(
    path: &Path,
    bytes: &[u8],
    sync: impl Fn(&fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("path has no file name"))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    let mut file = fs::File::create(&tmp)?;
    file.write_all(bytes)?;
    sync(&file)?;
    drop(file);
    fs::rename(&tmp, path)?;
    let directory = fs::File::open(dir)?;
    sync(&directory)
}

/// Remove a file and sync its directory entry. Absence is not an error.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_dir(path.parent().unwrap_or(Path::new("."))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
