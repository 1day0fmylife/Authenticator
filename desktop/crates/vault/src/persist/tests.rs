//! Failure-path tests for VAULT-003.
//!
//! Faults are injected per save stage (`set_fault`). `crash = false` is an
//! I/O error with normal cleanup; `crash = true` simulates the process dying
//! at that stage (no cleanup, temp files remain) followed by a reopen. These
//! are simulations on Linux/tmpfs, not real power-loss tests.

use super::*;
use crate::crypto::open;
use crate::format::{OtpRecord, MIN_M_COST_KIB, MIN_P_COST, MIN_T_COST};
use otp_core::{Algorithm, Digits};

const PASSWORD: &[u8] = b"correct horse battery staple";
const NEW_PASSWORD: &[u8] = b"a different test passphrase";

const ALL_STAGES: [Stage; 7] = [
    Stage::WriteTemp,
    Stage::SyncTemp,
    Stage::WriteBackup,
    Stage::SyncBackup,
    Stage::ReplaceBackup,
    Stage::ReplaceTarget,
    Stage::SyncDirectory,
];

fn params() -> KdfParams {
    KdfParams::new(MIN_M_COST_KIB, MIN_T_COST, MIN_P_COST).expect("params")
}

fn record(counter: u64) -> OtpRecord {
    OtpRecord::hotp(
        Algorithm::Sha1,
        Digits::Six,
        counter,
        b"persist-test-secret".to_vec(),
        "Example".to_owned(),
        format!("user{counter}@example.test"),
    )
    .expect("record")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).expect("random");
        let path = std::env::temp_dir().join(format!("vault-test-{}", hex(&suffix)));
        fs::create_dir(&path).expect("create temp dir");
        Self(path)
    }

    fn vault(&self) -> PathBuf {
        self.0.join("test.avault")
    }

    fn temp_files(&self) -> Vec<String> {
        fs::read_dir(&self.0)
            .expect("read dir")
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.contains(".tmp-"))
            .collect()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn record_count(path: &Path, password: &[u8]) -> usize {
    open(password, &fs::read(path).expect("read"))
        .expect("open")
        .len()
}

/// Vault with one record saved once, so a `.bak` already exists.
fn prepared(dir: &TempDir) -> VaultFile {
    let mut file = VaultFile::create(dir.vault(), PASSWORD, params()).expect("create");
    file.vault_mut().add(record(1)).expect("add");
    file.save().expect("first save");
    file
}

#[test]
fn create_open_round_trip_and_backup_rotation() {
    let dir = TempDir::new();
    let mut file = VaultFile::create(dir.vault(), PASSWORD, params()).expect("create");
    let created = fs::read(dir.vault()).expect("read created");
    assert!(!dir.0.join("test.avault.bak").exists(), "no .bak on create");

    file.vault_mut().add(record(1)).expect("add");
    file.save().expect("save 1");
    let first = fs::read(dir.vault()).expect("read first");
    assert_eq!(
        fs::read(dir.0.join("test.avault.bak")).expect("bak"),
        created
    );

    file.vault_mut().add(record(2)).expect("add");
    file.save().expect("save 2");
    assert_eq!(fs::read(dir.0.join("test.avault.bak")).expect("bak"), first);
    assert!(dir.temp_files().is_empty());
    file.close();

    let reopened = VaultFile::open(dir.vault(), PASSWORD).expect("open");
    assert_eq!(reopened.vault().len(), 2);
    assert_eq!(reopened.cleanup_report(), CleanupReport::default());
}

#[cfg(unix)]
#[test]
fn files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let _file = prepared(&dir);
    for name in ["test.avault", "test.avault.bak", "test.avault.lock"] {
        let mode = fs::metadata(dir.0.join(name))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

#[test]
fn create_never_overwrites() {
    let dir = TempDir::new();
    fs::write(dir.vault(), b"existing user data").expect("write");
    assert_eq!(
        VaultFile::create(dir.vault(), PASSWORD, params()).map(|_| ()),
        Err(VaultError::AlreadyExists)
    );
    assert_eq!(fs::read(dir.vault()).expect("read"), b"existing user data");
}

#[test]
fn open_errors_never_create_or_modify_a_vault() {
    let dir = TempDir::new();
    assert_eq!(
        VaultFile::open(dir.vault(), PASSWORD).map(|_| ()),
        Err(VaultError::NotFound)
    );
    assert!(!dir.vault().exists());

    let file = prepared(&dir);
    let bytes = fs::read(dir.vault()).expect("read");
    file.close();
    assert_eq!(
        VaultFile::open(dir.vault(), b"wrong password").map(|_| ()),
        Err(VaultError::AuthenticationFailed)
    );
    assert_eq!(fs::read(dir.vault()).expect("read"), bytes);

    fs::write(dir.vault(), vec![0x41; 200]).expect("corrupt");
    assert!(matches!(
        VaultFile::open(dir.vault(), PASSWORD).map(|_| ()),
        Err(VaultError::Corrupt(_))
    ));
    assert_eq!(fs::read(dir.vault()).expect("read"), vec![0x41; 200]);

    assert_eq!(
        VaultFile::open(dir.0.join("missing-dir").join("x.avault"), PASSWORD).map(|_| ()),
        Err(VaultError::Unavailable("directory not found"))
    );
}

#[test]
fn oversized_file_is_rejected_without_reading() {
    let dir = TempDir::new();
    let file = File::create(dir.vault()).expect("create");
    file.set_len(MAX_FILE_BYTES as u64 + 1).expect("sparse");
    drop(file);
    assert_eq!(
        VaultFile::open(dir.vault(), PASSWORD).map(|_| ()),
        Err(VaultError::ResourceLimit("file length"))
    );
}

#[test]
fn directory_in_place_of_vault_is_rejected() {
    let dir = TempDir::new();
    fs::create_dir(dir.vault()).expect("mkdir");
    assert_eq!(
        VaultFile::open(dir.vault(), PASSWORD).map(|_| ()),
        Err(VaultError::Unavailable("not a regular file"))
    );
}

#[cfg(unix)]
#[test]
fn symlinks_are_rejected() {
    let dir = TempDir::new();
    let file = prepared(&dir);
    file.close();

    let link = dir.0.join("link.avault");
    std::os::unix::fs::symlink(dir.vault(), &link).expect("symlink");
    assert_eq!(
        VaultFile::open(&link, PASSWORD).map(|_| ()),
        Err(VaultError::Unavailable("symlink not allowed"))
    );

    // A planted lock symlink must not be followed either.
    let other = TempDir::new();
    fs::copy(dir.vault(), other.vault()).expect("copy");
    std::os::unix::fs::symlink(dir.0.join("elsewhere"), other.0.join("test.avault.lock"))
        .expect("lock symlink");
    assert_eq!(
        VaultFile::open(other.vault(), PASSWORD).map(|_| ()),
        Err(VaultError::Unavailable("symlink not allowed"))
    );
    assert!(!dir.0.join("elsewhere").exists());
}

#[cfg(unix)]
#[test]
fn fifo_in_place_of_vault_does_not_block() {
    let dir = TempDir::new();
    let status = std::process::Command::new("mkfifo")
        .arg(dir.vault())
        .status();
    if !status.is_ok_and(|status| status.success()) {
        eprintln!("mkfifo unavailable; skipped");
        return;
    }
    assert_eq!(
        VaultFile::open(dir.vault(), PASSWORD).map(|_| ()),
        Err(VaultError::Unavailable("not a regular file"))
    );
}

#[test]
fn second_session_is_busy() {
    let dir = TempDir::new();
    let first = prepared(&dir);
    assert_eq!(
        VaultFile::open(dir.vault(), PASSWORD).map(|_| ()),
        Err(VaultError::Busy)
    );
    first.close();
    assert!(VaultFile::open(dir.vault(), PASSWORD).is_ok());
}

#[test]
fn external_change_is_a_conflict_and_is_not_overwritten() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);

    // Another writer that ignores the lock replaces the file.
    let mut other = UnlockedVault::create(PASSWORD, params()).expect("other");
    other.add(record(99)).expect("add");
    let external = other.seal().expect("seal");
    fs::write(dir.vault(), &external).expect("external write");

    file.vault_mut().add(record(2)).expect("add");
    assert_eq!(file.save(), Err(VaultError::Conflict));
    assert_eq!(fs::read(dir.vault()).expect("read"), external);

    fs::remove_file(dir.vault()).expect("remove");
    assert_eq!(file.save(), Err(VaultError::Conflict));
    assert!(!dir.vault().exists(), "a vanished vault is not recreated");
    assert!(dir.temp_files().is_empty());
}

#[test]
fn injected_faults_keep_previous_or_new_file_whole() {
    for crash in [false, true] {
        for stage in ALL_STAGES {
            let dir = TempDir::new();
            let mut file = prepared(&dir);
            let old = fs::read(dir.vault()).expect("old");
            let old_bak = fs::read(dir.0.join("test.avault.bak")).expect("old bak");

            file.vault_mut().add(record(2)).expect("add");
            set_fault(Some((stage, crash)));
            let result = file.save();
            set_fault(None);

            let label = format!("{stage:?} crash={crash}");
            let bak = fs::read(dir.0.join("test.avault.bak")).expect("bak");
            if stage == Stage::SyncDirectory {
                assert_eq!(result, Err(VaultError::DurabilityUncertain), "{label}");
                assert_eq!(record_count(&dir.vault(), PASSWORD), 2, "{label}");
                assert_eq!(bak, old, "{label}: .bak is the previous version");
                assert_eq!(
                    file.save(),
                    Err(VaultError::Unavailable("reopen required")),
                    "{label}"
                );
            } else {
                assert_eq!(result, Err(VaultError::Io(stage.name())), "{label}");
                assert_eq!(fs::read(dir.vault()).expect("target"), old, "{label}");
                let replaced_bak = matches!(stage, Stage::ReplaceTarget);
                assert_eq!(&bak, if replaced_bak { &old } else { &old_bak }, "{label}");
            }
            // Whatever happened, the managed .bak is a complete vault.
            assert!(open(PASSWORD, &bak).is_ok(), "{label}");

            if crash {
                drop(file);
                let reopened = VaultFile::open(dir.vault(), PASSWORD).expect("reopen");
                let expected = if stage == Stage::SyncDirectory { 2 } else { 1 };
                assert_eq!(reopened.vault().len(), expected, "{label}");
                assert!(dir.temp_files().is_empty(), "{label}: cleanup after crash");
            } else {
                assert!(dir.temp_files().is_empty(), "{label}: temp left behind");
                if stage != Stage::SyncDirectory {
                    // The same session can retry successfully.
                    file.save().expect("retry");
                    assert_eq!(record_count(&dir.vault(), PASSWORD), 2, "{label}");
                }
            }
        }
    }
}

#[test]
fn crash_leftovers_are_reported_and_removed_on_open() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    file.vault_mut().add(record(2)).expect("add");
    set_fault(Some((Stage::ReplaceBackup, true)));
    let _ = file.save();
    set_fault(None);
    drop(file);
    assert_eq!(dir.temp_files().len(), 2, "temp + bak temp left by crash");

    // Unrelated files with similar names are never touched.
    fs::write(dir.0.join(".other.avault.tmp-keep"), b"x").expect("write");
    let reopened = VaultFile::open(dir.vault(), PASSWORD).expect("open");
    assert_eq!(
        reopened.cleanup_report(),
        CleanupReport {
            removed: 2,
            failed: 0
        }
    );
    assert_eq!(dir.temp_files(), vec![".other.avault.tmp-keep".to_owned()]);
}

#[test]
fn password_change_rewrites_target_and_backup() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    file.change_password(PASSWORD, NEW_PASSWORD, params())
        .expect("change");

    let target = fs::read(dir.vault()).expect("target");
    let bak = fs::read(dir.0.join("test.avault.bak")).expect("bak");
    assert_eq!(target, bak, ".bak holds the new ciphertext");
    assert_eq!(
        open(PASSWORD, &bak).map(|_| ()),
        Err(VaultError::AuthenticationFailed),
        "old password must not open the managed backup"
    );
    file.save().expect("save with new key");
    file.close();
    assert!(VaultFile::open(dir.vault(), NEW_PASSWORD).is_ok());
}

#[test]
fn interrupted_password_change_keeps_old_password() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    set_fault(Some((Stage::ReplaceTarget, false)));
    let result = file.change_password(PASSWORD, NEW_PASSWORD, params());
    set_fault(None);
    assert_eq!(result, Err(VaultError::Io("replace target")));

    // Documented intermediate state: target old, .bak new.
    assert_eq!(record_count(&dir.vault(), PASSWORD), 1);
    let bak = fs::read(dir.0.join("test.avault.bak")).expect("bak");
    assert!(open(NEW_PASSWORD, &bak).is_ok());

    // The session still uses the old key; a retry of a normal save works.
    file.save().expect("save");
    file.close();
    assert!(VaultFile::open(dir.vault(), PASSWORD).is_ok());
}

#[test]
fn wrong_current_password_writes_nothing() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    let before = fs::read(dir.vault()).expect("before");
    assert_eq!(
        file.change_password(b"not the password", NEW_PASSWORD, params()),
        Err(VaultError::AuthenticationFailed)
    );
    assert_eq!(fs::read(dir.vault()).expect("after"), before);
}

#[test]
fn storage_full_is_io_error_and_keeps_old_file() {
    // ENOSPC is simulated by the injected `StorageFull` error.
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    let old = fs::read(dir.vault()).expect("old");
    file.vault_mut().add(record(2)).expect("add");
    set_fault(Some((Stage::WriteTemp, false)));
    assert_eq!(file.save(), Err(VaultError::Io("write temp")));
    set_fault(None);
    assert_eq!(fs::read(dir.vault()).expect("target"), old);
}

#[cfg(unix)]
#[test]
fn read_only_directory_is_unavailable_and_keeps_old_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    let old = fs::read(dir.vault()).expect("old");

    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o500)).expect("chmod");
    if fs::write(dir.0.join("probe"), b"").is_ok() {
        eprintln!("running with elevated privileges; permission test skipped");
        return;
    }
    file.vault_mut().add(record(2)).expect("add");
    assert_eq!(
        file.save(),
        Err(VaultError::Unavailable("permission denied"))
    );
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).expect("chmod back");
    assert_eq!(fs::read(dir.vault()).expect("target"), old);
    assert!(dir.temp_files().is_empty());
}

#[cfg(unix)]
#[test]
fn unreadable_vault_is_unavailable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    prepared(&dir).close();
    fs::set_permissions(dir.vault(), fs::Permissions::from_mode(0o000)).expect("chmod");
    if fs::read(dir.vault()).is_ok() {
        eprintln!("running with elevated privileges; permission test skipped");
        return;
    }
    assert_eq!(
        VaultFile::open(dir.vault(), PASSWORD).map(|_| ()),
        Err(VaultError::Unavailable("permission denied"))
    );
}

#[test]
fn debug_does_not_show_path_or_secrets() {
    let dir = TempDir::new();
    let file = prepared(&dir);
    let text = format!("{file:?}");
    assert!(!text.contains("test.avault"));
    assert!(!text.contains("persist-test-secret"));
    assert!(!text.contains("example.test"));
}
