//! Removes what interrupted backups left in the backup folders.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Where every service's backups live
const ROOT: &str = "/opt/backups";

/// A work folder untouched this long is a leftover
const QUIET_FOR: Duration = Duration::from_secs(60 * 60);

fn root() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_BACKUP_ROOT").unwrap_or_else(|_| ROOT.to_string()))
}

fn lock_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_LOCK_DIR").unwrap_or_else(|_| crate::install::host::lock::DIRECTORY.to_string()),
    )
}

/// Removes quiet `.work-*` folders of services not backing up
pub fn sweep() -> Vec<PathBuf> {
    let Ok(services) = std::fs::read_dir(root()) else { return Vec::new() };
    let mut removed = Vec::new();
    for service in services.flatten().filter(|entry| entry.path().is_dir()) {
        let name = service.file_name().to_string_lossy().into_owned();
        let Some(_held) = hold_lock(&lock_dir().join(format!("backup-{name}.lock"))) else { continue };
        for work in leftovers(&service.path(), SystemTime::now()) {
            if std::fs::remove_dir_all(&work).is_ok() {
                removed.push(work);
            }
        }
    }
    removed
}

/// Holds the backup lock; None while a run has it
fn hold_lock(path: &Path) -> Option<Option<std::fs::File>> {
    let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) else { return Some(None) };
    // SAFETY: flock(2) on a descriptor this function owns.
    let taken = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0;
    (!taken).then_some(Some(file))
}

/// The service folder's work folders nothing wrote to lately
fn leftovers(service: &Path, now: SystemTime) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(service) else { return Vec::new() };
    entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".work-"))
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && !path.is_symlink())
        .filter(|path| newest_change(path).is_some_and(|at| now.duration_since(at).unwrap_or_default() >= QUIET_FOR))
        .collect()
}

/// The latest change in a folder, two levels deep
fn newest_change(path: &Path) -> Option<SystemTime> {
    let mut newest = std::fs::metadata(path).ok()?.modified().ok()?;
    for entry in std::fs::read_dir(path).ok()?.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        newest = newest.max(meta.modified().unwrap_or(newest));
        if meta.is_dir() {
            for inner in std::fs::read_dir(entry.path()).into_iter().flatten().flatten() {
                if let Ok(at) = inner.metadata().and_then(|m| m.modified()) {
                    newest = newest.max(at);
                }
            }
        }
    }
    Some(newest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-leftovers-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn only_quiet_work_folders_are_leftovers() {
        let service = scratch("quiet");
        std::fs::create_dir_all(service.join(".work-abc/gryonixnexus-db")).unwrap();
        std::fs::create_dir_all(service.join("incoming")).unwrap();
        std::fs::write(service.join("immich-1.tar.gz"), b"x").unwrap();
        let later = SystemTime::now() + QUIET_FOR + Duration::from_secs(5);
        assert_eq!(leftovers(&service, later), vec![service.join(".work-abc")]);
        assert!(leftovers(&service, SystemTime::now()).is_empty(), "a running backup writes here");
        let _ = std::fs::remove_dir_all(&service);
    }

    #[test]
    fn a_taken_lock_keeps_the_folder() {
        let dir = scratch("lock");
        let path = dir.join("backup-immich.lock");
        let first = std::fs::File::create(&path).unwrap();
        // SAFETY: flock(2) on a descriptor the test owns.
        assert_eq!(unsafe { libc::flock(first.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        assert!(hold_lock(&path).is_none(), "a running backup's lock was taken");
        drop(first);
        assert!(hold_lock(&path).is_some());
        assert!(hold_lock(&dir.join("backup-none.lock")).is_some(), "no lock file means no run");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
