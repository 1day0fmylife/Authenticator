//! Conformance tests for the shared `otpauth://` vectors.
//!
//! The same JSON file is consumed by the Go test in `server/internal/otp`, so a
//! divergence between the two implementations is a test failure, not a
//! judgement call.

use std::fs;

use otp_core::{Algorithm, Digits, OtpType, OtpUri};
use serde_json::Value;

fn load() -> Value {
    let path = format!(
        "{}/../../../tests/vectors/otpauth.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    let doc: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"));
    assert_eq!(
        doc["schema"].as_u64(),
        Some(1),
        "{path}: unsupported schema"
    );
    assert_eq!(doc["kind"].as_str(), Some("otpauth"), "{path}: wrong kind");
    doc
}

fn hex_decode(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "odd hex length");
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex digit");
            let low = (pair[1] as char).to_digit(16).expect("hex digit");
            ((high << 4) | low) as u8
        })
        .collect()
}

fn algorithm(value: &Value) -> Algorithm {
    Algorithm::try_from(value.as_str().expect("algorithm string")).expect("supported algorithm")
}

fn digits(value: &Value) -> Digits {
    let value = value.as_u64().expect("digits integer");
    Digits::try_from(u8::try_from(value).expect("digits fit u8")).expect("6 or 8 digits")
}

#[test]
fn valid_vectors_parse_and_render_canonically() {
    let doc = load();
    let vectors = doc["valid"].as_array().expect("valid array");
    assert!(vectors.len() >= 20);

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let input = vector["uri"].as_str().expect("uri");
        let canonical = vector["canonical"].as_str().expect("canonical");

        let parsed = OtpUri::parse(input).unwrap_or_else(|error| panic!("{name}: {error}"));

        let expected_type = match vector["type"].as_str().expect("type") {
            "totp" => OtpType::Totp,
            "hotp" => OtpType::Hotp,
            other => panic!("{name}: unknown type {other}"),
        };
        assert_eq!(parsed.otp_type(), expected_type, "{name}: type");
        assert_eq!(
            parsed.algorithm(),
            algorithm(&vector["algorithm"]),
            "{name}: algorithm"
        );
        assert_eq!(parsed.digits(), digits(&vector["digits"]), "{name}: digits");
        assert_eq!(
            parsed.secret(),
            hex_decode(vector["secret_hex"].as_str().expect("secret_hex")),
            "{name}: secret"
        );
        assert_eq!(
            parsed.issuer(),
            vector["issuer"].as_str().expect("issuer"),
            "{name}: issuer"
        );
        assert_eq!(
            parsed.account(),
            vector["account"].as_str().expect("account"),
            "{name}: account"
        );

        match parsed.otp_type() {
            OtpType::Totp => {
                let period = vector["period"].as_u64().expect("totp period") as u32;
                assert_eq!(parsed.period(), period, "{name}: period");
                assert_eq!(parsed.counter(), 0, "{name}: counter");
                assert!(vector["counter"].is_null(), "{name}: counter must be null");
            }
            OtpType::Hotp => {
                assert!(vector["period"].is_null(), "{name}: period must be null");
                assert_eq!(
                    parsed.counter(),
                    vector["counter"].as_u64().expect("hotp counter"),
                    "{name}: counter"
                );
                assert_eq!(parsed.period(), 0, "{name}: period");
            }
        }

        assert_eq!(
            parsed
                .to_uri()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            canonical,
            "{name}: canonical output"
        );

        let reparsed = OtpUri::parse(canonical)
            .unwrap_or_else(|error| panic!("{name}: canonical is not accepted: {error}"));
        assert_eq!(reparsed, parsed, "{name}: canonical round trip");
    }
}

#[test]
fn invalid_vectors_are_rejected() {
    let doc = load();
    let vectors = doc["invalid"].as_array().expect("invalid array");
    assert!(vectors.len() >= 40);

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let input = vector["uri"].as_str().expect("uri");
        let error = OtpUri::parse(input).expect_err(name);
        assert!(
            !format!("{error:?}").contains("JBSWY3DPEHPK3PXP"),
            "{name}: error contains secret"
        );
        assert!(
            !error.to_string().contains("JBSWY3DPEHPK3PXP"),
            "{name}: message contains secret"
        );
    }
}

#[test]
fn vector_names_are_unique_and_synthetic() {
    let doc = load();
    let mut seen = std::collections::BTreeSet::new();

    for section in ["valid", "invalid"] {
        for vector in doc[section].as_array().expect("vector array") {
            let name = vector["name"].as_str().expect("vector name");
            assert!(seen.insert(name.to_owned()), "duplicate vector {name}");
            assert!(vector["uri"].as_str().is_some());
            if section == "valid" {
                assert!(vector["secret_hex"]
                    .as_str()
                    .is_some_and(|secret| !secret.is_empty()));
            }
        }
    }
}

#[test]
fn generator_rejects_unrepresentable_values() {
    let secret = b"Hello!\xde\xad\xbe\xef".to_vec();

    assert!(OtpUri::totp(
        secret.clone(),
        "i".repeat(256),
        "a".repeat(256),
        Algorithm::Sha512,
        Digits::Eight,
        86_400,
    )
    .is_ok());

    assert!(OtpUri::totp(
        secret.clone(),
        String::new(),
        "a".to_owned(),
        Algorithm::Sha1,
        Digits::Six,
        0,
    )
    .is_err());

    assert!(OtpUri::hotp(
        secret,
        String::new(),
        "a".to_owned(),
        Algorithm::Sha1,
        Digits::Six,
        u64::MAX,
    )
    .is_ok());
}
