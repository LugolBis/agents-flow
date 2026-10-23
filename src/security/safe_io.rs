//! Safe write primitives: EXCLUSIVE creation (`O_CREAT|O_EXCL|O_NOFOLLOW`, `CREATE_NEW|FILE_FLAG_OPEN_REPARSE_POINT` on Windows)
//! and ATOMIC replacement (temp file in the same directory + rename) after re-checking that the target is still the same regular file.
use crate::error::{SecResult, SecurityError};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Fault injection used by `verify` to prove that an interrupted write leaves the original intact.
static FAIL_REPLACE: AtomicBool = AtomicBool::new(false);

pub fn set_fail_replace(on: bool) {
    FAIL_REPLACE.store(on, Ordering::SeqCst);
}

fn open_new(path: &Path, mode: u32) -> std::io::Result<fs::File> {
    let mut oponer = OpenOptions::new();
    oponer.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oponer
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let _ = mode;
        oponer.custom_flags(0x0020_0000 /* FILE_FLAG_OPEN_REPARSE_POINT */);
    }

    oponer.open(path)
}

pub fn create_exclusive(path: &Path, data: &[u8], mode: u32) -> SecResult<()> {
    if let Some(path) = path.parent() {
        fs::create_dir_all(path).map_err(|_| {
            SecurityError::path(
                "create_failed",
                "parent folder creation impossible (OSError)",
            )
        })?;
    }

    let mut file = open_new(path, mode).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            SecurityError::path("already_exists", "the file already exist : no overwrite")
        } else {
            SecurityError::path("create_failed", "creation impossible (OSError)")
        }
    })?;

    if let Err(_) = file.write_all(data).and_then(|_| file.flush()) {
        drop(file);
        let _ = fs::remove_file(path); // clean up a file WE just created and left incomplete
        return Err(SecurityError::path(
            "create_failed",
            "failed to write (OSError)",
        ));
    }
    Ok(())
}

/// (device, inode) on Unix; file index on Windows. Fails unless `path` is a regular file (checked with lstat: no link following).
pub struct FileIdentity(#[cfg(unix)] (u64, u64), #[cfg(not(unix))] same_file::Handle);

impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

pub fn file_identity(path: &Path) -> SecResult<FileIdentity> {
    let meta_data = fs::symlink_metadata(path)
        .map_err(|_| SecurityError::path("not_found", "file not found"))?;
    if !meta_data.file_type().is_file() {
        return Err(SecurityError::path(
            "not_regular_file",
            "only a regular file could be modified",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileIdentity((meta_data.dev(), meta_data.ino())))
    }
    #[cfg(not(unix))]
    {
        same_file::Handle::from_path(path)
            .map(FileIdentity)
            .map_err(|_| SecurityError::path("not_found", "file not found"))
    }
}

pub fn replace_atomic(path: &Path, data: &[u8], expected: &FileIdentity) -> SecResult<()> {
    let changed = || {
        SecurityError::path(
            "changed_during_operation",
            "the file changed during the operation : abort",
        )
    };

    if file_identity(path)? != *expected {
        return Err(changed());
    }

    let orig_perm = fs::symlink_metadata(path)
        .map(|meta_data| meta_data.permissions())
        .map_err(|_| changed())?;

    let dir = path.parent().ok_or_else(changed)?;
    let tmp = dir.join(format!(".sc-tmp-{}", crate::util::hex_token(6)));

    let result = (|| -> SecResult<()> {
        let mut file = open_new(&tmp, 0o600)
            .map_err(|_| SecurityError::path("create_failed", "cretaion impossible (OSError)"))?;

        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|_| SecurityError::path("create_failed", "writing impossible (OSError)"))?;
        drop(file);

        fs::set_permissions(&tmp, orig_perm).map_err(|_| {
            SecurityError::path("create_failed", "permissions impossibles (OSError)")
        })?;

        if FAIL_REPLACE.load(Ordering::SeqCst) {
            return Err(SecurityError::path("simulated_crash", "simulated crash"));
        }

        if file_identity(path)? != *expected {
            return Err(changed());
        }

        fs::rename(&tmp, path)
            .map_err(|_| SecurityError::path("replace_failed", "replacement impossible (OSError)"))
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exclusive_never_overwrites_and_atomic_replace() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/a.txt");
        create_exclusive(&p, b"1", 0o644).unwrap();
        assert_eq!(
            create_exclusive(&p, b"2", 0o644).unwrap_err().code,
            "already_exists"
        );
        assert_eq!(fs::read(&p).unwrap(), b"1");
        let id = file_identity(&p).unwrap();
        replace_atomic(&p, b"3", &id).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"3");
        let id = file_identity(&p).unwrap();
        set_fail_replace(true);
        assert!(replace_atomic(&p, b"4", &id).is_err());
        set_fail_replace(false);
        assert_eq!(fs::read(&p).unwrap(), b"3");
        assert!(fs::read_dir(p.parent().unwrap()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".sc-tmp")));
    }
}
