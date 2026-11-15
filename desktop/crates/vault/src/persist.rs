//! On-disk persistence for vault v1 (VAULT-003, ADR-004 §8).
//!
//! [`VaultFile`] owns an [`UnlockedVault`] together with:
//!
//! - an exclusive advisory lock on the sidecar `<vault_path>.lock` (`Busy` if
//!   held elsewhere; the lock file is empty and is never deleted);
//! - `baseline_digest = SHA-256(file)` taken at open/save; every save re-reads
//!   the target first and refuses with `Conflict` if it changed or vanished;
//! - the save sequence of ADR-004 §8.2: temp file in the same directory
//!   (`create_new`, 0600, no symlink follow) → write → fsync → `.bak` via its
//!   own temp + fsync + rename → atomic rename onto the target → directory
//!   fsync. Before the target rename the previous file is untouched; after
//!   it, a failed directory fsync yields `DurabilityUncertain` and the session
//!   refuses further writes until reopened.
//!
//! Platform status: Unix (Linux) is implemented and tested. On Windows the
//! same code uses `std::fs::rename` (`MoveFileExW` without
//! `MOVEFILE_WRITE_THROUGH`) and no directory flush, so ADR-004 durability is
//! **not** claimed there; it is untested and needs a reviewed shim.
//!
//! Network/FUSE/cloud-sync folders are not supported for durability.

use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{VaultError, VaultResult};
use crate::format::{KdfParams, MAX_FILE_BYTES};
use crate::session::UnlockedVault;

/// Steps of the save sequence, used for error reporting and fault injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    WriteTemp,
    SyncTemp,
    WriteBackup,
    SyncBackup,
    ReplaceBackup,
    ReplaceTarget,
    SyncDirectory,
}

impl Stage {
    const fn name(self) -> &'static str {
        match self {
            Self::WriteTemp => "write temp",
            Self::SyncTemp => "fsync temp",
            Self::WriteBackup => "write backup",
            Self::SyncBackup => "fsync backup",
            Self::ReplaceBackup => "replace backup",
            Self::ReplaceTarget => "replace target",
            Self::SyncDirectory => "fsync directory",
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only fault: (stage, crash). `crash = true` simulates the process
    /// dying at that stage: no cleanup runs, temp files stay behind.
    static FAULT: std::cell::Cell<Option<(Stage, bool)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_fault(fault: Option<(Stage, bool)>) {
    FAULT.with(|cell| cell.set(fault));
}

fn inject(stage: Stage) -> io::Result<()> {
    #[cfg(test)]
    {
        if let Some((faulty, _)) = FAULT.with(std::cell::Cell::get) {
            if faulty == stage {
                return Err(io::Error::new(io::ErrorKind::StorageFull, "injected"));
            }
        }
    }
    let _ = stage;
    Ok(())
}

fn crash_mode() -> bool {
    #[cfg(test)]
    {
        FAULT
            .with(std::cell::Cell::get)
            .is_some_and(|(_, crash)| crash)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Removes a temp file after a failed save, unless a crash is simulated.
fn discard(path: &Path) {
    if !crash_mode() {
        let _ = fs::remove_file(path);
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Paths derived from the vault path; all live in the same directory.
struct Paths {
    target: PathBuf,
    dir: PathBuf,
    name: String,
    bak: PathBuf,
    lock: PathBuf,
}

impl Paths {
    fn new(path: &Path) -> VaultResult<Self> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or(VaultError::InvalidInput("vault file name"))?
            .to_owned();
        let dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        Ok(Self {
            target: path.to_path_buf(),
            bak: dir.join(format!("{name}.bak")),
            lock: dir.join(format!("{name}.lock")),
            dir,
            name,
        })
    }

    fn temp_prefix(&self) -> String {
        format!(".{}.tmp-", self.name)
    }

    fn bak_temp_prefix(&self) -> String {
        format!(".{}.bak.tmp-", self.name)
    }

    fn random_path(&self, prefix: &str) -> VaultResult<PathBuf> {
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).map_err(|_| VaultError::Random)?;
        Ok(self.dir.join(format!("{prefix}{}", hex(&suffix))))
    }
}

/// Applies "no symlink follow" and owner-only permissions where available.
fn harden(options: &mut OpenOptions, nonblocking: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = libc::O_NOFOLLOW;
        if nonblocking {
            // A FIFO swapped in for the vault must not block the open.
            flags |= libc::O_NONBLOCK;
        }
        options.custom_flags(flags).mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open a link itself, then reject it.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let _ = nonblocking;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (options, nonblocking);
    }
}

fn is_symlink_error(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

fn open_error(error: &io::Error) -> VaultError {
    if is_symlink_error(error) {
        return VaultError::Unavailable("symlink not allowed");
    }
    match error.kind() {
        io::ErrorKind::NotFound => VaultError::NotFound,
        io::ErrorKind::PermissionDenied => VaultError::Unavailable("permission denied"),
        io::ErrorKind::ReadOnlyFilesystem => VaultError::Unavailable("read-only filesystem"),
        _ => VaultError::Unavailable("open failed"),
    }
}

fn write_error(error: &io::Error, stage: Stage) -> VaultError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => VaultError::Unavailable("permission denied"),
        io::ErrorKind::ReadOnlyFilesystem => VaultError::Unavailable("read-only filesystem"),
        _ => VaultError::Io(stage.name()),
    }
}

/// Rejects symlinks/reparse points and non-regular files without opening.
fn check_regular(path: &Path) -> VaultResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| open_error(&error))?;
    if metadata.file_type().is_symlink() {
        return Err(VaultError::Unavailable("symlink not allowed"));
    }
    if !metadata.is_file() {
        return Err(VaultError::Unavailable("not a regular file"));
    }
    Ok(())
}

fn check_opened(file: &File) -> VaultResult<fs::Metadata> {
    let metadata = file
        .metadata()
        .map_err(|_| VaultError::Unavailable("metadata"))?;
    if metadata.file_type().is_symlink() {
        return Err(VaultError::Unavailable("symlink not allowed"));
    }
    if !metadata.is_file() {
        return Err(VaultError::Unavailable("not a regular file"));
    }
    Ok(metadata)
}

/// Reads a whole vault file without following links and within v1 limits.
fn read_vault_file(path: &Path) -> VaultResult<Vec<u8>> {
    check_regular(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    harden(&mut options, true);
    let file = options.open(path).map_err(|error| open_error(&error))?;
    let metadata = check_opened(&file)?;
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(VaultError::ResourceLimit("file length"));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::Unavailable("read failed"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(VaultError::ResourceLimit("file length"));
    }
    Ok(bytes)
}

/// Creates `path` exclusively, writes `bytes` and fsyncs it.
fn write_new(path: &Path, bytes: &[u8], write: Stage, sync: Stage) -> VaultResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    harden(&mut options, false);
    let mut file = options
        .open(path)
        .map_err(|error| write_error(&error, write))?;
    if let Err(error) = inject(write) {
        // Simulate a torn write: only part of the data reaches the temp file.
        let _ = file.write_all(&bytes[..bytes.len() / 2]);
        return Err(write_error(&error, write));
    }
    file.write_all(bytes)
        .map_err(|error| write_error(&error, write))?;
    inject(sync)
        .and_then(|()| file.sync_all())
        .map_err(|error| write_error(&error, sync))
}

fn sync_directory(dir: &Path) -> io::Result<()> {
    inject(Stage::SyncDirectory)?;
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Windows: directory handles cannot be fsynced this way; durability
        // is not claimed on Windows until a reviewed write-through shim.
        let _ = dir;
        Ok(())
    }
}

fn acquire_lock(path: &Path) -> VaultResult<File> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(VaultError::Unavailable("symlink not allowed"));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(VaultError::Unavailable("not a regular file"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(open_error(&error)),
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    harden(&mut options, true);
    let file = options
        .open(path)
        .map_err(|error| match open_error(&error) {
            // A missing directory makes the lock path unopenable.
            VaultError::NotFound => VaultError::Unavailable("directory not found"),
            other => other,
        })?;
    check_opened(&file)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(VaultError::Busy),
        Err(TryLockError::Error(_)) => Err(VaultError::Unavailable("lock failed")),
    }
}

/// Result of removing stale temp files left by an interrupted save.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Stale temp files removed.
    pub removed: usize,
    /// Stale temp files that could not be removed (they hold only ciphertext).
    pub failed: usize,
}

fn cleanup_stale(paths: &Paths) -> CleanupReport {
    let mut report = CleanupReport::default();
    let Ok(entries) = fs::read_dir(&paths.dir) else {
        return report;
    };
    let temp_prefix = paths.temp_prefix();
    let bak_prefix = paths.bak_temp_prefix();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.starts_with(&temp_prefix) || name.starts_with(&bak_prefix)) {
            continue;
        }
        let path = entry.path();
        let regular = fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file());
        if regular && fs::remove_file(&path).is_ok() {
            report.removed += 1;
        } else {
            report.failed += 1;
        }
    }
    report
}

/// Which bytes the managed `.bak` receives during a save.
#[derive(Clone, Copy)]
enum Backup {
    /// Normal save: the previous file (one prior version).
    Previous,
    /// Password change: the new ciphertext, so `.bak` never keeps the old
    /// password after a successful change (ADR-004 §8.4).
    New,
}

/// An unlocked vault bound to a locked file on disk.
pub struct VaultFile {
    paths: Paths,
    _lock: File,
    baseline: [u8; 32],
    vault: UnlockedVault,
    poisoned: bool,
    cleanup: CleanupReport,
}

impl VaultFile {
    /// Creates a new empty vault file. Never overwrites an existing path.
    ///
    /// The existence check and the final rename run while the sidecar lock
    /// is held; a process that ignores the lock could still race it.
    pub fn create(path: impl AsRef<Path>, password: &[u8], params: KdfParams) -> VaultResult<Self> {
        let paths = Paths::new(path.as_ref())?;
        let lock = acquire_lock(&paths.lock)?;
        let cleanup = cleanup_stale(&paths);
        match fs::symlink_metadata(&paths.target) {
            Ok(_) => return Err(VaultError::AlreadyExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(open_error(&error)),
        }

        let vault = UnlockedVault::create(password, params)?;
        let bytes = vault.seal()?;
        let temp = paths.random_path(&paths.temp_prefix())?;
        if let Err(error) = write_new(&temp, &bytes, Stage::WriteTemp, Stage::SyncTemp) {
            discard(&temp);
            return Err(error);
        }
        if let Err(error) =
            inject(Stage::ReplaceTarget).and_then(|()| fs::rename(&temp, &paths.target))
        {
            discard(&temp);
            return Err(write_error(&error, Stage::ReplaceTarget));
        }
        sync_directory(&paths.dir).map_err(|_| VaultError::DurabilityUncertain)?;

        Ok(Self {
            paths,
            _lock: lock,
            baseline: digest(&bytes),
            vault,
            poisoned: false,
            cleanup,
        })
    }

    /// Locks, reads and unlocks an existing vault file.
    ///
    /// No error path creates or rewrites the vault.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> VaultResult<Self> {
        let paths = Paths::new(path.as_ref())?;
        let lock = acquire_lock(&paths.lock)?;
        let cleanup = cleanup_stale(&paths);
        let bytes = read_vault_file(&paths.target)?;
        let vault = UnlockedVault::unlock(password, &bytes)?;
        Ok(Self {
            paths,
            _lock: lock,
            baseline: digest(&bytes),
            vault,
            poisoned: false,
            cleanup,
        })
    }

    /// The decrypted vault.
    pub fn vault(&self) -> &UnlockedVault {
        &self.vault
    }

    /// Mutable access for CRUD; changes reach disk only on [`save`](Self::save).
    pub fn vault_mut(&mut self) -> &mut UnlockedVault {
        &mut self.vault
    }

    /// Path of the vault file.
    pub fn path(&self) -> &Path {
        &self.paths.target
    }

    /// Stale temp files handled when this session acquired the lock.
    pub fn cleanup_report(&self) -> CleanupReport {
        self.cleanup
    }

    /// Re-encrypts with a fresh nonce and atomically replaces the file.
    pub fn save(&mut self) -> VaultResult<()> {
        let bytes = self.vault.seal()?;
        self.commit(&bytes, Backup::Previous)
    }

    /// Changes the password (or upgrades KDF params) and saves.
    ///
    /// The session switches to the new key only after the target has been
    /// replaced. If the save fails earlier, the file and the session keep the
    /// old password; `.bak` may already hold the new ciphertext (ADR-004 §8.4,
    /// interrupted change).
    pub fn change_password(
        &mut self,
        current: &[u8],
        new: &[u8],
        params: KdfParams,
    ) -> VaultResult<()> {
        let rekey = self.vault.prepare_rekey(current, new, params)?;
        let bytes = self.vault.seal_rekeyed(&rekey)?;
        match self.commit(&bytes, Backup::New) {
            Ok(()) => {
                self.vault.apply_rekey(rekey);
                Ok(())
            }
            Err(VaultError::DurabilityUncertain) => {
                // Target already holds the new password; keep memory in step.
                self.vault.apply_rekey(rekey);
                Err(VaultError::DurabilityUncertain)
            }
            Err(error) => Err(error),
        }
    }

    /// Releases the lock; key material and records are zeroized.
    pub fn close(self) {
        drop(self);
    }

    fn commit(&mut self, bytes: &[u8], backup: Backup) -> VaultResult<()> {
        if self.poisoned {
            return Err(VaultError::Unavailable("reopen required"));
        }

        // 1. Lost-update protection: the file must be exactly what we opened.
        let current = match read_vault_file(&self.paths.target) {
            Ok(current) => current,
            Err(VaultError::NotFound) => return Err(VaultError::Conflict),
            Err(error) => return Err(error),
        };
        if digest(&current) != self.baseline {
            return Err(VaultError::Conflict);
        }

        // 2. New file next to the target.
        let temp = self.paths.random_path(&self.paths.temp_prefix())?;
        if let Err(error) = write_new(&temp, bytes, Stage::WriteTemp, Stage::SyncTemp) {
            discard(&temp);
            return Err(error);
        }

        // 3. Managed backup via its own temp file.
        let backup_bytes = match backup {
            Backup::Previous => &current[..],
            Backup::New => bytes,
        };
        let bak_temp = self.paths.random_path(&self.paths.bak_temp_prefix())?;
        if let Err(error) = write_new(
            &bak_temp,
            backup_bytes,
            Stage::WriteBackup,
            Stage::SyncBackup,
        ) {
            discard(&bak_temp);
            discard(&temp);
            return Err(error);
        }
        if let Err(error) =
            inject(Stage::ReplaceBackup).and_then(|()| fs::rename(&bak_temp, &self.paths.bak))
        {
            discard(&bak_temp);
            discard(&temp);
            return Err(write_error(&error, Stage::ReplaceBackup));
        }

        // 4. Atomic replace of the target.
        if let Err(error) =
            inject(Stage::ReplaceTarget).and_then(|()| fs::rename(&temp, &self.paths.target))
        {
            discard(&temp);
            return Err(write_error(&error, Stage::ReplaceTarget));
        }

        // 5. Persist the directory entries; failure after replace is reported.
        if sync_directory(&self.paths.dir).is_err() {
            self.poisoned = true;
            return Err(VaultError::DurabilityUncertain);
        }
        self.baseline = digest(bytes);
        Ok(())
    }
}

impl fmt::Debug for VaultFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultFile")
            .field("vault", &self.vault)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
