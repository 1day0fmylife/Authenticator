//! Encrypted vault format v1 for the desktop Authenticator.
//!
//! This crate implements the **format, cryptography, session and persistence
//! layer** specified by [ADR-004](../../../../security/adr/0004-vault.md): an
//! 80-byte envelope header, Argon2id key derivation and one
//! XChaCha20-Poly1305 ciphertext per file.
//!
//! - VAULT-001: strict, fail-closed parsing of the envelope and payload; OTP
//!   record encoding with ADR-004 limits; `seal_new`/`open` with OS CSPRNG
//!   salt and nonce; checked-in deterministic fixtures and negative tests.
//! - VAULT-002: [`UnlockedVault`] — create, unlock, lock, record CRUD,
//!   re-seal with a fresh nonce and password change / KDF upgrade.
//! - VAULT-003: [`VaultFile`] — sidecar lock, `baseline_digest` conflict
//!   check, temp + fsync + atomic replace, managed `.bak`, stale temp cleanup
//!   (Unix implemented and tested; Windows durability not claimed yet).
//!
//! Export/import/restore (VAULT-005) are not part of this crate yet. This
//! crate has no GUI, network, logging or telemetry code and forbids `unsafe`.

#![forbid(unsafe_code)]

mod crypto;
pub mod error;
#[cfg(test)]
mod fixtures;
pub mod format;
mod persist;
mod session;

pub use crypto::{open, seal_new};
pub use error::{VaultError, VaultResult};
pub use format::{
    KdfParams, OtpRecord, OtpType, Payload, DEFAULT_M_COST_KIB, DEFAULT_P_COST, DEFAULT_T_COST,
    ENVELOPE_VERSION, HEADER_LEN, KDF_ID_ARGON2ID_V19, KEY_LEN, MAX_CIPHERTEXT_BYTES,
    MAX_FILE_BYTES, MAX_PASSWORD_BYTES, MAX_PAYLOAD_BYTES, MAX_PERIOD_SECONDS, MAX_RECORDS,
    MAX_SECRET_BYTES, MAX_STRING_BYTES, MIN_FILE_BYTES, MIN_NEW_PASSWORD_BYTES, MIN_PERIOD_SECONDS,
    NONCE_LEN, PAYLOAD_VERSION, SALT_LEN, TAG_LEN,
};
pub use persist::{verify_file, CleanupReport, RestoreMode, VaultFile};
pub use session::{RecordId, UnlockedVault};
