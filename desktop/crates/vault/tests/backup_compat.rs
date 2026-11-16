//! VAULT-005: backward compatibility of backup/restore/import/export with
//! the checked-in v1 fixtures (`tests/vault/v1`).
//!
//! Every fixture, written once by the VAULT-001 generator, must still verify,
//! restore into a new target, import into an existing vault and survive an
//! export round trip with identical records. The fixtures are synthetic
//! (see `manifest.json`). This runs on the build host only; it is not a
//! cross-OS test by itself.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use vault::format::{MIN_M_COST_KIB, MIN_P_COST, MIN_T_COST};
use vault::{verify_file, KdfParams, RestoreMode, VaultFile};

const NEW_PASSWORD: &[u8] = b"restored test passphrase";

fn params() -> KdfParams {
    KdfParams::new(MIN_M_COST_KIB, MIN_T_COST, MIN_P_COST).expect("params")
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/vault/v1")
}

fn manifest() -> Value {
    let text = fs::read_to_string(fixture_dir().join("manifest.json")).expect("manifest");
    serde_json::from_str(&text).expect("parse manifest")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).expect("random");
        let name: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("vault-compat-{name}"));
        fs::create_dir(&path).expect("mkdir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// (otp_type, algorithm, digits, period, counter, secret hex, issuer, account)
type RecordView = (String, String, u32, u32, u64, String, String, String);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn records_of(file: &VaultFile) -> Vec<RecordView> {
    file.vault()
        .records()
        .map(|(_, r)| {
            (
                match r.otp_type() {
                    vault::OtpType::Totp => "totp".to_owned(),
                    vault::OtpType::Hotp => "hotp".to_owned(),
                },
                r.algorithm().as_str().to_owned(),
                r.digits().as_u32(),
                r.period(),
                r.counter(),
                hex(r.secret()),
                r.issuer().to_owned(),
                r.account().to_owned(),
            )
        })
        .collect()
}

fn records_of_manifest(fixture: &Value) -> Vec<RecordView> {
    fixture["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|r| {
            (
                r["otp_type"].as_str().expect("type").to_owned(),
                r["algorithm"].as_str().expect("alg").to_owned(),
                r["digits"].as_u64().expect("digits") as u32,
                r["period"].as_u64().expect("period") as u32,
                r["counter"].as_u64().expect("counter"),
                r["secret_hex"].as_str().expect("secret").to_owned(),
                r["issuer"].as_str().expect("issuer").to_owned(),
                r["account"].as_str().expect("account").to_owned(),
            )
        })
        .collect()
}

#[test]
fn every_fixture_verifies_restores_imports_and_exports() {
    let manifest = manifest();
    let password = manifest["password"].as_str().expect("password").as_bytes();

    for fixture in manifest["fixtures"].as_array().expect("fixtures") {
        let name = fixture["name"].as_str().expect("name");
        let source = fixture_dir().join(fixture["file"].as_str().expect("file"));
        let source_bytes = fs::read(&source).expect("fixture");
        let expected = records_of_manifest(fixture);
        let dir = TempDir::new();

        // 1. Integrity check of the backup itself.
        assert_eq!(verify_file(&source, password), Ok(expected.len()), "{name}");

        // 2. Restore into a fresh target (explicitly confirmed: none exists).
        let target = dir.0.join("restored.avault");
        let restored = VaultFile::restore(
            &target,
            &source,
            password,
            NEW_PASSWORD,
            params(),
            RestoreMode::ReplaceDamagedTarget,
        )
        .unwrap_or_else(|error| panic!("{name}: restore: {error}"));
        assert_eq!(records_of(&restored), expected, "{name}: restored records");

        // 3. Export the restored vault and read it back.
        let export = dir.0.join("export.avault");
        restored
            .export_to(&export, password, params())
            .unwrap_or_else(|error| panic!("{name}: export: {error}"));
        restored.close();
        let exported = VaultFile::open(&export, password).expect("open export");
        assert_eq!(records_of(&exported), expected, "{name}: exported records");
        exported.close();

        // 4. Import (replace) into an unrelated existing vault.
        let other = dir.0.join("other.avault");
        let mut other_file =
            VaultFile::create(&other, NEW_PASSWORD, params()).expect("create other");
        assert_eq!(
            other_file.import_replace(&source, password),
            Ok(expected.len()),
            "{name}"
        );
        other_file.close();
        let reopened = VaultFile::open(&other, NEW_PASSWORD).expect("reopen other");
        assert_eq!(records_of(&reopened), expected, "{name}: imported records");

        // The fixture itself is never modified by any of these operations.
        assert_eq!(fs::read(&source).expect("fixture"), source_bytes, "{name}");
    }
}

#[test]
fn byte_copies_of_fixtures_are_valid_backups() {
    let manifest = manifest();
    let password = manifest["password"].as_str().expect("password").as_bytes();
    let dir = TempDir::new();
    for fixture in manifest["fixtures"].as_array().expect("fixtures") {
        let file = fixture["file"].as_str().expect("file");
        let copy = dir.0.join(file);
        fs::copy(fixture_dir().join(file), &copy).expect("copy");
        let count = fixture["records"].as_array().expect("records").len();
        assert_eq!(verify_file(&copy, password), Ok(count), "{file}");
    }
}
