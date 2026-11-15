//! Deterministic vault fixtures for VAULT-001 conformance tests.
//!
//! The checked-in files under `tests/vault/v1/` are **synthetic**: every
//! password, secret, issuer and account value below is a public test value,
//! never a real credential. The original plaintext is also published in
//! `manifest.json`, which is why only synthetic data may be used here.
//!
//! Regeneration is explicit and reviewed:
//!
//! ```text
//! cd desktop && cargo test -p vault generate_fixtures -- --ignored
//! ```
//!
//! Production code never accepts caller-supplied salt or nonce; `seal_with`
//! exists only for these fixtures and crate tests.

use std::fs;
use std::path::PathBuf;

use otp_core::{Algorithm, Digits};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::crypto::seal_with;
use crate::error::VaultResult;
use crate::format::{
    KdfParams, OtpRecord, OtpType, Payload, DEFAULT_M_COST_KIB, DEFAULT_P_COST, DEFAULT_T_COST,
    MIN_M_COST_KIB, MIN_P_COST, MIN_T_COST, NONCE_LEN, SALT_LEN,
};

/// Public, test-only fixture password (ADR-004 test plan).
pub(crate) const FIXTURE_PASSWORD: &[u8] = b"correct horse battery staple";

const FIXTURE_DIR: &str = "../../../tests/vault/v1";

struct FixtureSpec {
    name: &'static str,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    payload: Payload,
}

fn salt(seed: u8) -> [u8; SALT_LEN] {
    std::array::from_fn(|i| seed.wrapping_add(i as u8))
}

fn nonce(seed: u8) -> [u8; NONCE_LEN] {
    std::array::from_fn(|i| seed.wrapping_add(i as u8))
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

fn specs() -> VaultResult<Vec<FixtureSpec>> {
    let min_params = KdfParams::new(MIN_M_COST_KIB, MIN_T_COST, MIN_P_COST)?;
    let default_params = KdfParams::new(DEFAULT_M_COST_KIB, DEFAULT_T_COST, DEFAULT_P_COST)?;

    Ok(vec![
        FixtureSpec {
            name: "empty",
            params: min_params,
            salt: salt(0x10),
            nonce: nonce(0x10),
            payload: Payload::new(),
        },
        FixtureSpec {
            name: "totp-sha1",
            params: min_params,
            salt: salt(0x20),
            nonce: nonce(0x20),
            payload: Payload::from_records(vec![OtpRecord::totp(
                Algorithm::Sha1,
                Digits::Six,
                30,
                b"12345678901234567890".to_vec(),
                "Example".to_owned(),
                "alice@example.test".to_owned(),
            )?])?,
        },
        FixtureSpec {
            name: "totp-sha256",
            params: min_params,
            salt: salt(0x30),
            nonce: nonce(0x30),
            payload: Payload::from_records(vec![OtpRecord::totp(
                Algorithm::Sha256,
                Digits::Eight,
                60,
                vec![0x01; 32],
                "Example".to_owned(),
                "sha256@example.test".to_owned(),
            )?])?,
        },
        FixtureSpec {
            name: "totp-sha512",
            params: min_params,
            salt: salt(0x40),
            nonce: nonce(0x40),
            payload: Payload::from_records(vec![OtpRecord::totp(
                Algorithm::Sha512,
                Digits::Six,
                86_400,
                b"fixture-sha512-secret".to_vec(),
                "Example".to_owned(),
                "sha512@example.test".to_owned(),
            )?])?,
        },
        FixtureSpec {
            name: "hotp",
            params: min_params,
            salt: salt(0x50),
            nonce: nonce(0x50),
            payload: Payload::from_records(vec![OtpRecord::hotp(
                Algorithm::Sha1,
                Digits::Six,
                42,
                b"fixture-hotp-secret".to_vec(),
                "Example".to_owned(),
                "hotp@example.test".to_owned(),
            )?])?,
        },
        FixtureSpec {
            name: "mixed-boundaries",
            params: default_params,
            salt: salt(0x60),
            nonce: nonce(0x60),
            payload: Payload::from_records(vec![
                OtpRecord::totp(
                    Algorithm::Sha1,
                    Digits::Six,
                    1,
                    vec![0xab],
                    String::new(),
                    "x".to_owned(),
                )?,
                OtpRecord::hotp(
                    Algorithm::Sha256,
                    Digits::Eight,
                    u64::MAX,
                    vec![0xa5; 1024],
                    "i".repeat(256),
                    "a".repeat(256),
                )?,
                OtpRecord::totp(
                    Algorithm::Sha512,
                    Digits::Eight,
                    30,
                    b"fixture-utf8-secret".to_vec(),
                    "Пример".to_owned(),
                    "用户@example.test".to_owned(),
                )?,
            ])?,
        },
    ])
}

fn record_metadata(record: &OtpRecord) -> Value {
    json!({
        "otp_type": match record.otp_type() {
            OtpType::Totp => "totp",
            OtpType::Hotp => "hotp",
        },
        "algorithm": record.algorithm().as_str(),
        "digits": record.digits().as_u32(),
        "period": record.period(),
        "counter": record.counter(),
        "secret_hex": hex(record.secret()),
        "issuer": record.issuer(),
        "account": record.account(),
    })
}

fn manifest_entry(spec: &FixtureSpec, file: &[u8]) -> VaultResult<Value> {
    let payload_bytes = spec.payload.encode()?;
    let digest = Sha256::digest(file);

    Ok(json!({
        "name": spec.name,
        "file": format!("{}.avault", spec.name),
        "kdf": {
            "id": "argon2id-v19",
            "m_cost_kib": spec.params.m_cost_kib(),
            "t_cost": spec.params.t_cost(),
            "p_cost": spec.params.p_cost(),
        },
        "salt_hex": hex(&spec.salt),
        "nonce_hex": hex(&spec.nonce),
        "header_hex": hex(&file[..crate::format::HEADER_LEN]),
        "ciphertext_len": payload_bytes.len() + crate::format::TAG_LEN,
        "file_size": file.len(),
        "file_sha256": hex(&digest),
        "payload_hex": hex(&payload_bytes),
        "records": spec
            .payload
            .records()
            .iter()
            .map(record_metadata)
            .collect::<Vec<_>>(),
    }))
}

type FixtureFile = (PathBuf, Vec<u8>);
type GeneratedFixtures = (Vec<FixtureFile>, Value);

fn generate() -> VaultResult<GeneratedFixtures> {
    let mut files = Vec::new();
    let mut entries = Vec::new();

    for spec in specs()? {
        let file = seal_with(
            FIXTURE_PASSWORD,
            &spec.payload,
            spec.params,
            spec.salt,
            spec.nonce,
        )?;
        entries.push(manifest_entry(&spec, &file)?);
        files.push((PathBuf::from(format!("{}.avault", spec.name)), file));
    }

    let manifest = json!({
        "format": "vault-v1",
        "generated_by": "desktop/crates/vault/src/fixtures.rs (ignored test)",
        "synthetic": true,
        "note": "All passwords, secrets and labels are public test values. Never store real credentials in fixtures.",
        "password": "correct horse battery staple",
        "fixtures": entries,
    });

    Ok((files, manifest))
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_DIR)
}

#[test]
#[ignore = "regenerates the checked-in vault fixtures; run explicitly after a reviewed format change"]
fn generate_fixtures() {
    let (files, manifest) = generate().expect("generate fixtures");
    let dir = fixture_dir();
    fs::create_dir_all(&dir).expect("create fixture directory");

    for (name, bytes) in &files {
        fs::write(dir.join(name), bytes).expect("write fixture");
    }

    let mut text = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
    text.push('\n');
    fs::write(dir.join("manifest.json"), text).expect("write manifest");
}

#[test]
fn checked_in_fixtures_match_generator() {
    let (files, manifest) = generate().expect("generate fixtures");
    let dir = fixture_dir();

    for (name, bytes) in &files {
        let on_disk =
            fs::read(dir.join(name)).unwrap_or_else(|error| panic!("read {name:?}: {error}"));
        assert_eq!(&on_disk, bytes, "fixture {name:?} is stale");
    }

    let mut text = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
    text.push('\n');
    let on_disk = fs::read_to_string(dir.join("manifest.json")).expect("read manifest");
    assert_eq!(on_disk, text, "manifest.json is stale");
}
