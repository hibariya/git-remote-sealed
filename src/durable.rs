//! Filesystem operations for security state that must survive a restart.

use std::fs;
use std::io;
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
