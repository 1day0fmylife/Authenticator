//! Error classes for the vault format layer.
//!
//! File-level errors (`NotFound`, `Busy`, `Conflict`, `Io`,
//! `DurabilityUncertain`) belong to the persistence layer added in VAULT-002.
//! This module covers parsing, limits and cryptographic authentication.
//!
//! Error values never contain a password, key, secret, issuer/account value or
//! decrypted payload. Messages are static or contain public structural details.

use std::fmt;

/// Result alias for vault format operations.
pub type VaultResult<T> = Result<T, VaultError>;

/// Fail-closed error classes from ADR-004.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// Structurally invalid file or payload.
    Corrupt(&'static str),
    /// Well-formed but unknown version/algorithm/key id.
    Unsupported(&'static str),
    /// AEAD tag mismatch: wrong password or modified ciphertext.
    AuthenticationFailed,
    /// A file, payload, record or KDF value exceeds a v1 limit.
    ResourceLimit(&'static str),
    /// Caller supplied an invalid value while sealing (length/invariant).
    InvalidInput(&'static str),
    /// Internal cryptographic operation failed.
    Crypto,
    /// OS CSPRNG failed; no fallback is allowed.
    Random,
    /// A session record id does not refer to a record in this unlocked vault.
    UnknownRecord,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt(reason) => write!(f, "vault is corrupt: {reason}"),
            Self::Unsupported(reason) => write!(f, "unsupported vault format: {reason}"),
            Self::AuthenticationFailed => f.write_str("vault authentication failed"),
            Self::ResourceLimit(reason) => write!(f, "vault limit exceeded: {reason}"),
            Self::InvalidInput(reason) => write!(f, "invalid vault input: {reason}"),
            Self::Crypto => f.write_str("cryptographic operation failed"),
            Self::Random => f.write_str("secure random generator failed"),
            Self::UnknownRecord => f.write_str("unknown vault record"),
        }
    }
}

impl std::error::Error for VaultError {}
