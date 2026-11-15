//! Encrypted vault format v1 for the desktop Authenticator.
//!
//! This crate implements the **format and cryptography layer** specified by
//! [ADR-004](../../../../security/adr/0004-vault.md): an 80-byte envelope header,
//! Argon2id key derivation and one XChaCha20-Poly1305 ciphertext per file.
//!
//! Scope of VAULT-001:
//!
//! - strict, fail-closed parsing of the envelope and payload;
//! - OTP record encoding with ADR-004 limits;
//! - `seal_new`/`open` with OS CSPRNG salt and nonce;
//! - checked-in deterministic fixtures and negative tests.
//!
//! Persistence (atomic write, `.bak`, locking, CRUD, password change) is
//! **not** part of this crate yet; it is VAULT-002 onwards. This crate has no
//! GUI, network, logging or telemetry code and forbids `unsafe`.

#![forbid(unsafe_code)]

mod crypto;
pub mod error;
#[cfg(test)]
mod fixtures;
pub mod format;

pub use crypto::{open, seal_new};
pub use error::{VaultError, VaultResult};
pub use format::{
    KdfParams, OtpRecord, OtpType, Payload, DEFAULT_M_COST_KIB, DEFAULT_P_COST, DEFAULT_T_COST,
    ENVELOPE_VERSION, HEADER_LEN, KDF_ID_ARGON2ID_V19, KEY_LEN, MAX_CIPHERTEXT_BYTES,
    MAX_FILE_BYTES, MAX_PASSWORD_BYTES, MAX_PAYLOAD_BYTES, MAX_PERIOD_SECONDS, MAX_RECORDS,
    MAX_SECRET_BYTES, MAX_STRING_BYTES, MIN_FILE_BYTES, MIN_NEW_PASSWORD_BYTES, MIN_PERIOD_SECONDS,
    NONCE_LEN, PAYLOAD_VERSION, SALT_LEN, TAG_LEN,
};
