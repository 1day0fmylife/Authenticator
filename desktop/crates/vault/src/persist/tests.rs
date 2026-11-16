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

// ---- VAULT-005: export, copy, import, restore, verify -------------------

fn other_vault_file(dir: &TempDir, name: &str, password: &[u8], records: u64) -> PathBuf {
    let path = dir.0.join(name);
    let mut vault = UnlockedVault::create(password, params()).expect("create");
    for counter in 0..records {
        vault.add(record(100 + counter)).expect("add");
    }
    fs::write(&path, vault.seal().expect("seal")).expect("write");
    path
}

fn header_salt(bytes: &[u8]) -> Vec<u8> {
    bytes[28..44].to_vec()
}

#[test]
fn export_reencrypts_with_new_password_and_never_overwrites() {
    let dir = TempDir::new();
    let file = prepared(&dir);
    let dest = dir.0.join("export.avault");

    file.export_to(&dest, NEW_PASSWORD, params())
        .expect("export");
    assert_eq!(verify_file(&dest, NEW_PASSWORD), Ok(1));
    assert_eq!(
        verify_file(&dest, PASSWORD),
        Err(VaultError::AuthenticationFailed)
    );
    let source = fs::read(dir.vault()).expect("source");
    let exported = fs::read(&dest).expect("export");
    assert_ne!(header_salt(&source), header_salt(&exported), "new salt");
    assert!(!exported
        .windows(b"persist-test-secret".len())
        .any(|w| w == b"persist-test-secret"));

    // Existing destination is never replaced.
    assert_eq!(
        file.export_to(&dest, NEW_PASSWORD, params()),
        Err(VaultError::AlreadyExists)
    );
    assert_eq!(fs::read(&dest).expect("export"), exported);

    for own in [
        dir.vault(),
        dir.0.join("test.avault.bak"),
        dir.0.join("test.avault.lock"),
    ] {
        assert_eq!(
            file.export_to(&own, NEW_PASSWORD, params()),
            Err(VaultError::InvalidInput("destination is the vault itself"))
        );
    }

    let weak = dir.0.join("weak.avault");
    assert_eq!(
        file.export_to(&weak, b"short", params()),
        Err(VaultError::InvalidInput("password length"))
    );
    assert!(!weak.exists());
    assert_eq!(
        file.export_to(
            dir.0.join("no-such-dir").join("x.avault"),
            NEW_PASSWORD,
            params()
        ),
        Err(VaultError::Unavailable("directory not found"))
    );
}

#[test]
fn failed_export_leaves_no_partial_file() {
    for stage in [Stage::WriteTemp, Stage::SyncTemp, Stage::SyncDirectory] {
        let dir = TempDir::new();
        let file = prepared(&dir);
        let dest = dir.0.join("export.avault");
        set_fault(Some((stage, false)));
        let result = file.export_to(&dest, NEW_PASSWORD, params());
        set_fault(None);
        assert_eq!(result, Err(VaultError::Io(stage.name())), "{stage:?}");
        assert!(!dest.exists(), "{stage:?}: partial export left behind");
    }
}

#[test]
fn byte_copy_is_identical_and_checks_for_conflicts() {
    let dir = TempDir::new();
    let file = prepared(&dir);
    let dest = dir.0.join("copy.avault");
    file.copy_to(&dest).expect("copy");
    assert_eq!(
        fs::read(&dest).expect("copy"),
        fs::read(dir.vault()).expect("vault")
    );
    assert_eq!(verify_file(&dest, PASSWORD), Ok(1));
    assert_eq!(file.copy_to(&dest), Err(VaultError::AlreadyExists));

    fs::write(dir.vault(), b"changed elsewhere").expect("external");
    assert_eq!(
        file.copy_to(dir.0.join("copy2.avault")),
        Err(VaultError::Conflict)
    );
    assert!(!dir.0.join("copy2.avault").exists());
}

#[test]
fn import_replaces_records_after_full_verification() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    let before = fs::read(dir.vault()).expect("before");
    let source = other_vault_file(&dir, "source.avault", NEW_PASSWORD, 3);

    assert_eq!(file.import_replace(&source, NEW_PASSWORD), Ok(3));
    assert_eq!(file.vault().len(), 3);
    assert_eq!(
        fs::read(dir.0.join("test.avault.bak")).expect("bak"),
        before,
        "previous file becomes .bak"
    );
    // The target keeps the vault's own password, not the source password.
    assert_eq!(
        open(NEW_PASSWORD, &fs::read(dir.vault()).expect("target")).map(|_| ()),
        Err(VaultError::AuthenticationFailed)
    );
    file.close();
    assert_eq!(verify_file(dir.vault(), PASSWORD), Ok(3));
}

#[test]
fn rejected_import_changes_nothing() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    let before = fs::read(dir.vault()).expect("before");
    let source = other_vault_file(&dir, "source.avault", NEW_PASSWORD, 2);

    assert_eq!(
        file.import_replace(&source, PASSWORD),
        Err(VaultError::AuthenticationFailed)
    );
    fs::write(dir.0.join("garbage.avault"), vec![7_u8; 300]).expect("garbage");
    assert!(matches!(
        file.import_replace(dir.0.join("garbage.avault"), NEW_PASSWORD),
        Err(VaultError::Corrupt(_))
    ));
    assert_eq!(
        file.import_replace(dir.0.join("missing.avault"), NEW_PASSWORD),
        Err(VaultError::NotFound)
    );

    // A failure while saving restores the previous records in memory.
    set_fault(Some((Stage::ReplaceTarget, false)));
    let result = file.import_replace(&source, NEW_PASSWORD);
    set_fault(None);
    assert_eq!(result, Err(VaultError::Io("replace target")));

    assert_eq!(file.vault().len(), 1);
    assert_eq!(
        file.vault().records().next().map(|(_, r)| r),
        Some(&record(1))
    );
    assert_eq!(fs::read(dir.vault()).expect("after"), before);
    file.save().expect("session still usable");
}

#[test]
fn restore_from_backup_rekeys_and_rotates_bak() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    file.vault_mut().add(record(2)).expect("add");
    file.save().expect("save"); // .bak now holds the 1-record version
    file.close();
    let target_before = fs::read(dir.vault()).expect("target");
    let bak = dir.0.join("test.avault.bak");
    let bak_copy = dir.0.join("bak-copy.avault");
    fs::copy(&bak, &bak_copy).expect("copy bak");

    let restored = VaultFile::restore(
        dir.vault(),
        &bak_copy,
        PASSWORD,
        NEW_PASSWORD,
        params(),
        RestoreMode::RequireIntactTarget,
    )
    .expect("restore");
    assert_eq!(restored.vault().len(), 1);
    restored.close();

    assert_eq!(verify_file(dir.vault(), NEW_PASSWORD), Ok(1));
    assert_eq!(
        verify_file(dir.vault(), PASSWORD),
        Err(VaultError::AuthenticationFailed)
    );
    assert_ne!(
        header_salt(&fs::read(dir.vault()).expect("target")),
        header_salt(&fs::read(&bak_copy).expect("bak")),
        "restore uses a new salt"
    );
    assert_eq!(
        fs::read(&bak).expect("bak"),
        target_before,
        "previous target kept as .bak"
    );
}

#[test]
fn restore_from_managed_bak_itself_is_safe() {
    let dir = TempDir::new();
    let mut file = prepared(&dir);
    file.vault_mut().add(record(2)).expect("add");
    file.save().expect("save");
    file.close();
    let restored = VaultFile::restore(
        dir.vault(),
        dir.0.join("test.avault.bak"),
        PASSWORD,
        PASSWORD,
        params(),
        RestoreMode::RequireIntactTarget,
    )
    .expect("restore");
    assert_eq!(restored.vault().len(), 1);
    // The 2-record version moved into .bak; nothing was lost.
    assert_eq!(verify_file(dir.0.join("test.avault.bak"), PASSWORD), Ok(2));
}

#[test]
fn restore_into_missing_or_damaged_target_needs_confirmation() {
    let dir = TempDir::new();
    let backup = other_vault_file(&dir, "backup.avault", PASSWORD, 2);
    let target = dir.0.join("restored.avault");

    let restore = |mode| {
        VaultFile::restore(&target, &backup, PASSWORD, PASSWORD, params(), mode).map(|f| f.close())
    };
    assert_eq!(
        restore(RestoreMode::RequireIntactTarget),
        Err(VaultError::NotFound)
    );
    assert!(!target.exists(), "no implicit vault creation");
    assert_eq!(restore(RestoreMode::ReplaceDamagedTarget), Ok(()));
    assert_eq!(verify_file(&target, PASSWORD), Ok(2));
    assert!(!dir.0.join("restored.avault.bak").exists());

    fs::write(&target, vec![0x41; 200]).expect("damage");
    assert!(matches!(
        restore(RestoreMode::RequireIntactTarget),
        Err(VaultError::Corrupt(_))
    ));
    assert_eq!(fs::read(&target).expect("damaged"), vec![0x41; 200]);
    assert_eq!(restore(RestoreMode::ReplaceDamagedTarget), Ok(()));
    assert_eq!(verify_file(&target, PASSWORD), Ok(2));
    // Damaged bytes are not promoted into .bak.
    assert!(!dir.0.join("restored.avault.bak").exists());
}

#[test]
fn restore_never_replaces_unusable_targets_or_on_bad_backup() {
    let dir = TempDir::new();
    let backup = other_vault_file(&dir, "backup.avault", PASSWORD, 1);
    let target = dir.0.join("target.avault");
    fs::create_dir(&target).expect("mkdir");
    assert_eq!(
        VaultFile::restore(
            &target,
            &backup,
            PASSWORD,
            PASSWORD,
            params(),
            RestoreMode::ReplaceDamagedTarget
        )
        .map(|_| ()),
        Err(VaultError::Unavailable("not a regular file"))
    );
    fs::remove_dir(&target).expect("rmdir");

    for mode in [
        RestoreMode::RequireIntactTarget,
        RestoreMode::ReplaceDamagedTarget,
    ] {
        assert_eq!(
            VaultFile::restore(
                &target,
                &backup,
                b"wrong password",
                PASSWORD,
                params(),
                mode
            )
            .map(|_| ()),
            Err(VaultError::AuthenticationFailed)
        );
        assert!(!target.exists());
    }

    // Busy while another session holds the target.
    let open_session = prepared(&dir);
    assert_eq!(
        VaultFile::restore(
            dir.vault(),
            &backup,
            PASSWORD,
            PASSWORD,
            params(),
            RestoreMode::RequireIntactTarget
        )
        .map(|_| ()),
        Err(VaultError::Busy)
    );
    drop(open_session);
}

#[test]
fn interrupted_restore_always_leaves_a_complete_copy() {
    let restore_stages = [
        Stage::WriteTemp,
        Stage::SyncTemp,
        Stage::WriteBackup,
        Stage::SyncBackup,
        Stage::ReplaceTarget,
        Stage::ReplaceBackup,
        Stage::SyncDirectory,
    ];
    for crash in [false, true] {
        for stage in restore_stages {
            let dir = TempDir::new();
            prepared(&dir).close(); // target: 1 record, .bak: empty vault
            let target_before = fs::read(dir.vault()).expect("target");
            let backup = other_vault_file(&dir, "backup.avault", PASSWORD, 3);

            set_fault(Some((stage, crash)));
            let result = VaultFile::restore(
                dir.vault(),
                &backup,
                PASSWORD,
                PASSWORD,
                params(),
                RestoreMode::RequireIntactTarget,
            )
            .map(|f| f.close());
            set_fault(None);
            let label = format!("{stage:?} crash={crash}");

            let target_now = verify_file(dir.vault(), PASSWORD).expect("target whole");
            let replaced = matches!(stage, Stage::ReplaceBackup | Stage::SyncDirectory);
            if replaced {
                assert_eq!(result, Err(VaultError::DurabilityUncertain), "{label}");
                assert_eq!(target_now, 3, "{label}: target restored");
            } else {
                assert_eq!(result, Err(VaultError::Io(stage.name())), "{label}");
                assert_eq!(
                    fs::read(dir.vault()).expect("target"),
                    target_before,
                    "{label}: target untouched"
                );
            }
            // The backup source is never modified.
            assert_eq!(verify_file(&backup, PASSWORD), Ok(3), "{label}");
            // .bak is always a complete vault.
            assert!(
                verify_file(dir.0.join("test.avault.bak"), PASSWORD).is_ok(),
                "{label}"
            );

            // Reopen cleans up anything a crash left behind.
            let reopened = VaultFile::open(dir.vault(), PASSWORD).expect("reopen");
            drop(reopened);
            assert!(dir.temp_files().is_empty(), "{label}: temp left");
        }
    }
}

#[test]
fn verify_file_reports_integrity() {
    let dir = TempDir::new();
    prepared(&dir).close();
    assert_eq!(verify_file(dir.vault(), PASSWORD), Ok(1));
    assert_eq!(
        verify_file(dir.vault(), NEW_PASSWORD),
        Err(VaultError::AuthenticationFailed)
    );
    let mut bytes = fs::read(dir.vault()).expect("read");
    bytes[50] ^= 1;
    fs::write(dir.vault(), &bytes).expect("write");
    assert_eq!(
        verify_file(dir.vault(), PASSWORD),
        Err(VaultError::AuthenticationFailed)
    );
    assert_eq!(
        verify_file(dir.0.join("missing"), PASSWORD),
        Err(VaultError::NotFound)
    );
}

#[test]
fn inspect_file_reports_public_metadata_only() {
    let dir = TempDir::new();
    prepared(&dir).close();
    let bytes = fs::read(dir.vault()).expect("read");
    let info = inspect_file(dir.vault()).expect("inspect");
    assert_eq!(info.envelope_version, 1);
    assert_eq!(info.kdf, params());
    assert_eq!(info.file_len, bytes.len() as u64);
    assert_eq!(
        info.ciphertext_len,
        (bytes.len() - crate::format::HEADER_LEN) as u64
    );
    assert_eq!(info.sha256, digest(&bytes));

    // Structure only: a flipped ciphertext byte is not detected here.
    let mut tampered = bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    fs::write(dir.vault(), &tampered).expect("write");
    assert!(inspect_file(dir.vault()).is_ok());
    fs::write(dir.vault(), &tampered[..100]).expect("truncate");
    assert!(matches!(
        inspect_file(dir.vault()),
        Err(VaultError::Corrupt(_))
    ));
}
