//! VAULT-004: end-to-end error model through the public API.
//!
//! Every failure scenario of ADR-004 §10 maps to its own error class, leaves
//! the directory unchanged (apart from the empty sidecar `.lock`) and never
//! creates or rewrites a vault. Error text contains no password, secret,
//! account label or file path.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use otp_core::{Algorithm, Digits};
use vault::format::{MIN_M_COST_KIB, MIN_P_COST, MIN_T_COST};
use vault::{KdfParams, OtpRecord, VaultError, VaultFile, MAX_FILE_BYTES};

const PASSWORD: &[u8] = b"correct horse battery staple";
const SECRET: &[u8] = b"error-model-unique-secret";
const ACCOUNT: &str = "error-model-account@example.test";

fn params() -> KdfParams {
    KdfParams::new(MIN_M_COST_KIB, MIN_T_COST, MIN_P_COST).expect("params")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).expect("random");
        let name: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("vault-errmodel-{name}"));
        fs::create_dir(&path).expect("mkdir");
        Self(path)
    }

    fn vault(&self) -> PathBuf {
        self.0.join("model.avault")
    }

    /// Directory snapshot without the sidecar lock (which open may create).
    fn snapshot(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        fs::read_dir(&self.0)
            .expect("read dir")
            .map(|entry| entry.expect("entry"))
            .filter(|entry| !entry.file_name().to_string_lossy().ends_with(".lock"))
            .map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let content = entry
                    .file_type()
                    .expect("type")
                    .is_file()
                    .then(|| fs::read(entry.path()).unwrap_or_default());
                (name, content)
            })
            .collect()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(entries) = fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600));
                }
            }
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A valid vault with one record, closed again.
fn valid_vault(dir: &TempDir) -> Vec<u8> {
    let mut file = VaultFile::create(dir.vault(), PASSWORD, params()).expect("create");
    file.vault_mut()
        .add(
            OtpRecord::totp(
                Algorithm::Sha1,
                Digits::Six,
                30,
                SECRET.to_vec(),
                "Example".to_owned(),
                ACCOUNT.to_owned(),
            )
            .expect("record"),
        )
        .expect("add");
    file.save().expect("save");
    file.close();
    fs::read(dir.vault()).expect("read")
}

fn assert_clean_error(error: &VaultError, dir: &Path) {
    let dir_text = dir.to_string_lossy().into_owned();
    for rendered in [error.to_string(), format!("{error:?}")] {
        for needle in [
            std::str::from_utf8(PASSWORD).expect("utf8"),
            std::str::from_utf8(SECRET).expect("utf8"),
            ACCOUNT,
            dir_text.as_str(),
            "model.avault",
        ] {
            assert!(!rendered.contains(needle), "error text leaked {needle:?}");
        }
    }
}

/// Runs `open` and checks: expected class, no directory change, clean text.
fn expect_open_error(dir: &TempDir, path: &Path, password: &[u8], expected: VaultError) {
    let before = dir.snapshot();
    let error = VaultFile::open(path, password).expect_err("open must fail");
    assert_eq!(error, expected);
    assert_eq!(dir.snapshot(), before, "{expected:?}: directory changed");
    assert_clean_error(&error, &dir.0);
}

#[test]
fn missing_file_is_not_found_and_nothing_is_created() {
    let dir = TempDir::new();
    expect_open_error(&dir, &dir.vault(), PASSWORD, VaultError::NotFound);
    assert!(!dir.vault().exists());
}

#[test]
fn wrong_password_and_tampering_are_the_same_authentication_failure() {
    let dir = TempDir::new();
    let bytes = valid_vault(&dir);
    expect_open_error(
        &dir,
        &dir.vault(),
        b"wrong password",
        VaultError::AuthenticationFailed,
    );

    let mut tampered = bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    fs::write(dir.vault(), &tampered).expect("write");
    expect_open_error(
        &dir,
        &dir.vault(),
        PASSWORD,
        VaultError::AuthenticationFailed,
    );
}

#[test]
fn structural_corruption_is_corrupt_not_authentication() {
    let dir = TempDir::new();
    let bytes = valid_vault(&dir);

    fs::write(dir.vault(), &bytes[..bytes.len() - 3]).expect("truncate");
    expect_open_error(
        &dir,
        &dir.vault(),
        PASSWORD,
        VaultError::Corrupt("file length mismatch"),
    );

    fs::write(dir.vault(), &bytes[..40]).expect("truncate header");
    expect_open_error(
        &dir,
        &dir.vault(),
        PASSWORD,
        VaultError::Corrupt("truncated file"),
    );

    let mut bad_magic = bytes.clone();
    bad_magic[..4].copy_from_slice(b"ZIP!");
    fs::write(dir.vault(), &bad_magic).expect("write");
    expect_open_error(
        &dir,
        &dir.vault(),
        PASSWORD,
        VaultError::Corrupt("envelope magic"),
    );

    // Structural errors do not depend on the password.
    expect_open_error(
        &dir,
        &dir.vault(),
        b"wrong password",
        VaultError::Corrupt("envelope magic"),
    );

    fs::write(dir.vault(), b"").expect("empty");
    expect_open_error(
        &dir,
        &dir.vault(),
        PASSWORD,
        VaultError::Corrupt("truncated file"),
    );
}

#[test]
fn future_versions_are_unsupported() {
    let dir = TempDir::new();
    let mut bytes = valid_vault(&dir);
    bytes[4..6].copy_from_slice(&2_u16.to_be_bytes());
    fs::write(dir.vault(), &bytes).expect("write");
    expect_open_error(
        &dir,
        &dir.vault(),
        PASSWORD,
        VaultError::Unsupported("envelope version"),
    );
}

#[test]
fn oversized_file_is_a_resource_limit() {
    let dir = TempDir::new();
    let file = fs::File::create(dir.vault()).expect("create");
    file.set_len(MAX_FILE_BYTES as u64 + 1).expect("sparse");
    drop(file);
    let before = fs::metadata(dir.vault()).expect("meta").len();
    let error = VaultFile::open(dir.vault(), PASSWORD).expect_err("must fail");
    assert_eq!(error, VaultError::ResourceLimit("file length"));
    assert_eq!(fs::metadata(dir.vault()).expect("meta").len(), before);
}

#[test]
fn unusable_paths_are_unavailable() {
    let dir = TempDir::new();
    fs::create_dir(dir.vault()).expect("mkdir");
    expect_open_error(
        &dir,
        &dir.vault(),
        PASSWORD,
        VaultError::Unavailable("not a regular file"),
    );
    fs::remove_dir(dir.vault()).expect("rmdir");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        valid_vault(&dir);
        fs::set_permissions(dir.vault(), fs::Permissions::from_mode(0o000)).expect("chmod");
        if fs::read(dir.vault()).is_err() {
            let error = VaultFile::open(dir.vault(), PASSWORD).expect_err("must fail");
            assert_eq!(error, VaultError::Unavailable("permission denied"));
            assert_clean_error(&error, &dir.0);
        } else {
            eprintln!("elevated privileges; permission case skipped");
        }
    }
}

#[test]
fn concurrent_session_is_busy_and_external_change_is_conflict() {
    let dir = TempDir::new();
    valid_vault(&dir);
    let mut first = VaultFile::open(dir.vault(), PASSWORD).expect("open");
    expect_open_error(&dir, &dir.vault(), PASSWORD, VaultError::Busy);

    fs::write(dir.vault(), b"replaced by someone else").expect("write");
    let before = dir.snapshot();
    let error = first.save().expect_err("must conflict");
    assert_eq!(error, VaultError::Conflict);
    assert_eq!(dir.snapshot(), before);
    assert_clean_error(&error, &dir.0);
}

#[test]
fn create_refuses_existing_and_invalid_inputs() {
    let dir = TempDir::new();
    let bytes = valid_vault(&dir);
    assert_eq!(
        VaultFile::create(dir.vault(), PASSWORD, params()).map(|_| ()),
        Err(VaultError::AlreadyExists)
    );
    assert_eq!(fs::read(dir.vault()).expect("read"), bytes);

    let fresh = dir.0.join("fresh.avault");
    assert_eq!(
        VaultFile::create(&fresh, b"short", params()).map(|_| ()),
        Err(VaultError::InvalidInput("password length"))
    );
    assert_eq!(
        VaultFile::create(&fresh, &[b'p'; 1025], params()).map(|_| ()),
        Err(VaultError::InvalidInput("password length"))
    );
    assert!(!fresh.exists(), "failed create leaves no vault");
    assert_eq!(
        VaultFile::open(dir.vault(), &[b'p'; 1025]).map(|_| ()),
        Err(VaultError::InvalidInput("password length"))
    );
}
