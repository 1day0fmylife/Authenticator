//! Deterministic mutation fuzzing for the strict `otpauth://` parser.
//!
//! The project does not depend on `cargo-fuzz`/libFuzzer (nightly toolchain and
//! extra supply-chain surface), so this harness mutates the shared public
//! vectors with a fixed-seed xorshift generator. Runs are reproducible offline:
//! a failure prints the seed and iteration, and the same input can be replayed.
//!
//! Invariants checked for every input:
//!
//! * parsing never panics, whatever the bytes are;
//! * accepted input renders to canonical printable ASCII within `MAX_URI_BYTES`;
//! * canonical output reparses to an equal value and is stable byte-for-byte;
//! * accepted secrets stay within the documented limit;
//! * `Debug` output contains no secret, issuer or account material.
//!
//! The Rust parser takes `&str`, so non-UTF-8 byte sequences are not reachable
//! through this boundary; the Go test fuzzes raw bytes, which covers that side.

use std::fs;

use otp_core::{OtpUri, UriError, MAX_SECRET_BYTES, MAX_URI_BYTES};
use serde_json::Value;

const ITERATIONS_PER_SEED: u64 = 96;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next() % bound
        }
    }
}

fn load_seeds() -> Vec<String> {
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

    let mut seeds = Vec::new();
    for vector in doc["valid"].as_array().expect("valid array") {
        for field in ["uri", "canonical"] {
            seeds.push(
                vector[field]
                    .as_str()
                    .unwrap_or_else(|| panic!("{path}: valid.{field} is not a string"))
                    .to_owned(),
            );
        }
    }
    for vector in doc["invalid"].as_array().expect("invalid array") {
        seeds.push(
            vector["uri"]
                .as_str()
                .unwrap_or_else(|| panic!("{path}: invalid.uri is not a string"))
                .to_owned(),
        );
    }

    seeds.extend([
        String::new(),
        "?".to_owned(),
        "otpauth://".to_owned(),
        "otpauth://totp/".to_owned(),
        "otpauth://totp/x?secret=".to_owned(),
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_owned(),
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0".to_owned(),
        "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551615".to_owned(),
        "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551616".to_owned(),
        "otpauth://totp/a:b?secret=JBSWY3DPEHPK3PXP&issuer=a".to_owned(),
        "otpauth://totp/a%00b?secret=JBSWY3DPEHPK3PXP".to_owned(),
        "otpauth://totp/%ff?secret=JBSWY3DPEHPK3PXP".to_owned(),
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP#fragment".to_owned(),
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP%".to_owned(),
        "OTPAUTH://TOTP/X?SECRET=JBSWY3DPEHPK3PXP".to_owned(),
        "otpauth://totp/Пример:почта@example.com?secret=JBSWY3DPEHPK3PXP".to_owned(),
        "A".repeat(MAX_URI_BYTES),
        "A".repeat(MAX_URI_BYTES + 1),
    ]);
    assert!(seeds.len() > 90, "seed corpus is unexpectedly small");
    seeds
}

const PRINTABLE: &[u8] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

fn mutate(rng: &mut Rng, seed: &str) -> String {
    let mut bytes = seed.as_bytes().to_vec();
    let rounds = 1 + rng.below(4) as usize;
    for _ in 0..rounds {
        match rng.below(7) {
            0 => {
                if !bytes.is_empty() {
                    let index = rng.below(bytes.len() as u64) as usize;
                    bytes.remove(index);
                }
            }
            1 => {
                if bytes.len() < MAX_URI_BYTES * 2 {
                    let index = rng.below(bytes.len() as u64 + 1) as usize;
                    let byte = PRINTABLE[rng.below(PRINTABLE.len() as u64) as usize];
                    bytes.insert(index, byte);
                }
            }
            2 => {
                if !bytes.is_empty() {
                    let index = rng.below(bytes.len() as u64) as usize;
                    bytes[index] = PRINTABLE[rng.below(PRINTABLE.len() as u64) as usize];
                }
            }
            3 => {
                if !bytes.is_empty() {
                    bytes.truncate(rng.below(bytes.len() as u64 + 1) as usize);
                }
            }
            4 => {
                if bytes.len() < MAX_URI_BYTES * 2 {
                    let byte = PRINTABLE[rng.below(PRINTABLE.len() as u64) as usize];
                    bytes.push(byte);
                }
            }
            5 => {
                // Insert a non-ASCII scalar to exercise the ASCII-only gate.
                if bytes.len() < MAX_URI_BYTES * 2 {
                    let scalar = ['Я', 'é', '中', '🦀'][rng.below(4) as usize];
                    let index = rng.below(bytes.len() as u64 + 1) as usize;
                    let mut encoded = [0_u8; 4];
                    let text = scalar.encode_utf8(&mut encoded);
                    bytes.splice(index..index, text.bytes());
                }
            }
            _ => {
                // Duplicate a slice of the seed.
                if !bytes.is_empty() && bytes.len() < MAX_URI_BYTES * 2 {
                    let start = rng.below(bytes.len() as u64) as usize;
                    let end = start + rng.below((bytes.len() - start) as u64 + 1) as usize;
                    let slice = bytes[start..end].to_vec();
                    bytes.splice(end..end, slice);
                }
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn assert_canonical(canonical: &str) {
    assert!(
        canonical.len() <= MAX_URI_BYTES,
        "canonical URI is {} bytes, limit is {MAX_URI_BYTES}",
        canonical.len()
    );
    assert!(
        canonical.starts_with("otpauth://"),
        "canonical URI lost the scheme"
    );
    assert!(
        canonical.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
        "canonical URI contains a non-printable byte"
    );
}

#[test]
fn mutation_fuzz_parser_invariants() {
    let seeds = load_seeds();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);

    for seed in &seeds {
        // The corpus itself must be accepted or rejected cleanly.
        let _ = OtpUri::parse(seed);

        for iteration in 0..ITERATIONS_PER_SEED {
            let input = mutate(&mut rng, seed);
            let state = rng.0;
            match OtpUri::parse(&input) {
                Ok(uri) => {
                    assert!(
                        !uri.secret().is_empty() && uri.secret().len() <= MAX_SECRET_BYTES,
                        "seed state {state:#x}, iteration {iteration}: secret length {}",
                        uri.secret().len()
                    );
                    let canonical = uri.to_uri().unwrap_or_else(|error| {
                        panic!(
                            "seed state {state:#x}, iteration {iteration}: accepted URI failed to format: {error}"
                        )
                    });
                    assert_canonical(&canonical);

                    let reparsed = OtpUri::parse(&canonical).unwrap_or_else(|error| {
                        panic!(
                            "seed state {state:#x}, iteration {iteration}: canonical URI did not reparse: {error}"
                        )
                    });
                    assert_eq!(
                        reparsed, uri,
                        "seed state {state:#x}, iteration {iteration}: canonical round-trip changed the value"
                    );
                    let second = reparsed.to_uri().expect("canonical URI must reformat");
                    assert_eq!(
                        second, canonical,
                        "seed state {state:#x}, iteration {iteration}: canonical form is not stable"
                    );

                    // Pin the exact redacted shape: only enum/limit fields and
                    // label lengths may appear. Comparing exact text avoids the
                    // false negative where a one-character issuer occurs in
                    // unrelated field names such as "otp_type".
                    let debug = format!("{uri:?}");
                    let expected = format!(
                        "OtpUri {{ otp_type: {:?}, algorithm: {:?}, digits: {:?}, period: {}, counter: {}, secret: \"[redacted]\", issuer_len: {}, account_len: {} }}",
                        uri.otp_type(),
                        uri.algorithm(),
                        uri.digits(),
                        uri.period(),
                        uri.counter(),
                        uri.issuer().len(),
                        uri.account().len()
                    );
                    assert_eq!(
                        debug, expected,
                        "seed state {state:#x}, iteration {iteration}: Debug shape changed and may expose material"
                    );
                }
                Err(error) => {
                    if input.len() > MAX_URI_BYTES {
                        assert_eq!(
                            error,
                            UriError::TooLong,
                            "seed state {state:#x}, iteration {iteration}: oversized input was not rejected as TooLong"
                        );
                    }
                    if input.is_empty() {
                        assert_eq!(
                            error,
                            UriError::Empty,
                            "seed state {state:#x}, iteration {iteration}: empty input was not rejected as Empty"
                        );
                    }
                    assert!(
                        !error.to_string().is_empty(),
                        "seed state {state:#x}, iteration {iteration}: empty error text"
                    );
                }
            }
        }
    }
}
