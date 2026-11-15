//! Conformance and negative tests for the checked-in vault v1 fixtures.
//!
//! The fixtures are synthetic (see `tests/vault/v1/manifest.json`). These tests
//! prove that the checked-in bytes decrypt to the published metadata and that
//! corruption of the header, ciphertext or file length fails closed.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};
use vault::{open, VaultError};

const HEADER_LEN: usize = 80;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/vault/v1")
}

fn load_manifest() -> Value {
    let text = fs::read_to_string(fixture_dir().join("manifest.json")).expect("read manifest");
    serde_json::from_str(&text).expect("parse manifest")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn hex_decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "odd hex length");
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("hex digit");
            let lo = (pair[1] as char).to_digit(16).expect("hex digit");
            ((hi << 4) | lo) as u8
        })
        .collect()
}

fn fixtures(manifest: &Value) -> &[Value] {
    manifest["fixtures"].as_array().expect("fixtures array")
}

fn fixture_password(manifest: &Value) -> &[u8] {
    manifest["password"]
        .as_str()
        .expect("manifest password")
        .as_bytes()
}

fn read_fixture(fixture: &Value) -> Vec<u8> {
    let file_name = fixture["file"].as_str().expect("fixture file name");
    fs::read(fixture_dir().join(file_name))
        .unwrap_or_else(|error| panic!("read {file_name}: {error}"))
}

#[test]
fn manifest_is_synthetic_and_named() {
    let manifest = load_manifest();
    assert_eq!(manifest["format"], "vault-v1");
    assert_eq!(manifest["synthetic"], true);
    assert!(manifest["note"]
        .as_str()
        .is_some_and(|note| !note.is_empty()));

    let mut seen = std::collections::BTreeSet::new();
    for fixture in fixtures(&manifest) {
        let name = fixture["name"].as_str().expect("fixture name");
        assert!(seen.insert(name.to_owned()), "duplicate fixture {name}");
        assert!(fixture["file"]
            .as_str()
            .is_some_and(|f| f.ends_with(".avault")));
        assert!(fixture["kdf"]["id"].as_str() == Some("argon2id-v19"));
    }
}

#[test]
fn fixtures_open_and_match_manifest() {
    let manifest = load_manifest();
    let password = fixture_password(&manifest);

    for fixture in fixtures(&manifest) {
        let name = fixture["name"].as_str().expect("fixture name");
        let file = read_fixture(fixture);

        assert_eq!(
            file.len(),
            fixture["file_size"].as_u64().expect("file_size") as usize,
            "{name}: file size"
        );
        assert_eq!(&file[..4], b"AVLT", "{name}: envelope magic");
        assert_eq!(
            hex_encode(&file[..HEADER_LEN]),
            fixture["header_hex"].as_str().expect("header_hex"),
            "{name}: header bytes"
        );
        assert_eq!(
            hex_encode(&Sha256::digest(&file)),
            fixture["file_sha256"].as_str().expect("file_sha256"),
            "{name}: file digest"
        );
        assert_eq!(
            fixture["ciphertext_len"].as_u64().expect("ciphertext_len") as usize,
            file.len() - HEADER_LEN,
            "{name}: ciphertext length"
        );

        let header = &file[..HEADER_LEN];
        assert_eq!(
            hex_encode(&header[28..44]),
            fixture["salt_hex"].as_str().expect("salt_hex"),
            "{name}: salt"
        );
        assert_eq!(
            hex_encode(&header[44..68]),
            fixture["nonce_hex"].as_str().expect("nonce_hex"),
            "{name}: nonce"
        );

        let payload = open(password, &file).unwrap_or_else(|error| panic!("{name}: open: {error}"));
        let documents = fixture["records"].as_array().expect("records");
        assert_eq!(payload.len(), documents.len(), "{name}: record count");

        for (record, expected) in payload.records().iter().zip(documents) {
            let expected_type = expected["otp_type"].as_str().expect("otp_type");
            let actual_type = match record.otp_type() {
                vault::OtpType::Totp => "totp",
                vault::OtpType::Hotp => "hotp",
            };
            assert_eq!(actual_type, expected_type, "{name}: otp_type");
            assert_eq!(
                record.algorithm().as_str(),
                expected["algorithm"].as_str().expect("algorithm"),
                "{name}: algorithm"
            );
            assert_eq!(
                record.digits().as_u32(),
                expected["digits"].as_u64().expect("digits") as u32,
                "{name}: digits"
            );
            assert_eq!(
                u64::from(record.period()),
                expected["period"].as_u64().expect("period"),
                "{name}: period"
            );
            assert_eq!(
                record.counter(),
                expected["counter"].as_u64().expect("counter"),
                "{name}: counter"
            );
            assert_eq!(
                hex_encode(record.secret()),
                expected["secret_hex"].as_str().expect("secret_hex"),
                "{name}: secret"
            );
            assert_eq!(
                record.issuer(),
                expected["issuer"].as_str().expect("issuer"),
                "{name}: issuer"
            );
            assert_eq!(
                record.account(),
                expected["account"].as_str().expect("account"),
                "{name}: account"
            );
        }
    }
}

#[test]
fn wrong_password_fails_for_every_fixture() {
    let manifest = load_manifest();

    for fixture in fixtures(&manifest) {
        let name = fixture["name"].as_str().expect("fixture name");
        let file = read_fixture(fixture);
        assert_eq!(
            open(b"this is not the fixture password", &file),
            Err(VaultError::AuthenticationFailed),
            "{name}: wrong password"
        );
    }
}

#[test]
fn ciphertext_and_nonce_tampering_fails_authentication() {
    let manifest = load_manifest();
    let password = fixture_password(&manifest);

    for fixture in fixtures(&manifest) {
        let name = fixture["name"].as_str().expect("fixture name");
        let file = read_fixture(fixture);

        let mut tampered = file.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            open(password, &tampered),
            Err(VaultError::AuthenticationFailed),
            "{name}: ciphertext flip"
        );

        let mut tampered = file;
        tampered[44] ^= 0x01; // nonce is part of AAD and of the AEAD nonce
        assert_eq!(
            open(password, &tampered),
            Err(VaultError::AuthenticationFailed),
            "{name}: nonce flip"
        );
    }
}

#[test]
fn structural_corruption_is_rejected() {
    let manifest = load_manifest();
    let password = fixture_password(&manifest);
    let fixture = fixtures(&manifest)
        .iter()
        .find(|fixture| fixture["name"] == "totp-sha1")
        .expect("totp-sha1 fixture");
    let file = read_fixture(fixture);

    let mut tampered = file.clone();
    tampered[76] = 0x01; // reserved header byte
    assert_eq!(
        open(password, &tampered),
        Err(VaultError::Corrupt("reserved header bytes"))
    );

    let mut tampered = file.clone();
    tampered[0] = b'X';
    assert_eq!(
        open(password, &tampered),
        Err(VaultError::Corrupt("envelope magic"))
    );

    assert_eq!(
        open(password, &file[..file.len() - 1]),
        Err(VaultError::Corrupt("file length mismatch"))
    );

    let mut trailing = file;
    trailing.push(0x00);
    assert_eq!(
        open(password, &trailing),
        Err(VaultError::Corrupt("file length mismatch"))
    );
}

#[test]
fn manifest_hex_fields_decode() {
    let manifest = load_manifest();

    for fixture in fixtures(&manifest) {
        for field in [
            "salt_hex",
            "nonce_hex",
            "header_hex",
            "file_sha256",
            "payload_hex",
        ] {
            let decoded = hex_decode(fixture[field].as_str().expect(field));
            assert!(!decoded.is_empty(), "empty {field}");
        }
        assert_eq!(
            hex_decode(fixture["salt_hex"].as_str().expect("salt")).len(),
            16
        );
        assert_eq!(
            hex_decode(fixture["nonce_hex"].as_str().expect("nonce")).len(),
            24
        );
        assert_eq!(
            hex_decode(fixture["file_sha256"].as_str().expect("sha")).len(),
            32
        );
    }
}
