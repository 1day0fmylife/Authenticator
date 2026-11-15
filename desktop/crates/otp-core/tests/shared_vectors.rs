use std::fs;

use otp_core::{generate_hotp, generate_totp, Algorithm, Digits};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../../tests/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn secret(doc: &Value, id: &str) -> Vec<u8> {
    doc["secrets"][id]["ascii"]
        .as_str()
        .unwrap_or_else(|| panic!("missing ascii secret {id}"))
        .as_bytes()
        .to_vec()
}

fn digits(value: &Value) -> Digits {
    let value = value.as_u64().expect("digits must be an integer");
    let value = u8::try_from(value).expect("digits must fit u8");
    Digits::try_from(value).expect("digits must be 6 or 8")
}

fn algorithm(value: &Value) -> Algorithm {
    Algorithm::try_from(value.as_str().expect("algorithm must be a string"))
        .expect("algorithm must be supported")
}

#[test]
fn hotp_shared_vectors() {
    let doc = load("rfc4226-hotp.json");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 20);

    for vector in vectors {
        let id = vector["id"].as_str().expect("vector id");
        let secret = secret(&doc, vector["secret"].as_str().expect("secret id"));
        let counter = vector["counter"].as_u64().expect("counter");
        let expected = vector["code"].as_str().expect("code");

        let got = generate_hotp(
            &secret,
            counter,
            digits(&vector["digits"]),
            algorithm(&vector["algorithm"]),
        )
        .unwrap_or_else(|error| panic!("{id}: {error}"));

        assert_eq!(got, expected, "vector {id}");
    }
}

#[test]
fn totp_shared_vectors() {
    let doc = load("rfc6238-totp.json");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 51);

    for vector in vectors {
        let id = vector["id"].as_str().expect("vector id");
        let secret = secret(&doc, vector["secret"].as_str().expect("secret id"));
        let unix_time = vector["unix_time"].as_i64().expect("unix_time");
        let period = vector["period"].as_u64().expect("period") as u32;
        let expected = vector["code"].as_str().expect("code");

        let got = generate_totp(
            &secret,
            unix_time,
            period,
            digits(&vector["digits"]),
            algorithm(&vector["algorithm"]),
        )
        .unwrap_or_else(|error| panic!("{id}: {error}"));

        assert_eq!(got, expected, "vector {id}");
    }
}

#[test]
fn shared_secrets_are_public_test_values() {
    let hotp = load("rfc4226-hotp.json");
    let totp = load("rfc6238-totp.json");
    assert_eq!(
        hotp["secrets"]["rfc4226-ascii"]["ascii"].as_str(),
        Some("12345678901234567890")
    );
    assert_eq!(
        totp["secrets"]["rfc6238-sha1"]["ascii"].as_str(),
        Some("12345678901234567890")
    );
    assert!(totp["secrets"]["rfc6238-sha512"]["ascii"]
        .as_str()
        .is_some_and(|value| value.len() == 64));
}
