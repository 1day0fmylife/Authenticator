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
    /// The vault file does not exist; it is never created implicitly.
    NotFound,
    /// `create` refused to overwrite an existing path.
    AlreadyExists,
    /// The file cannot be accessed: permission, read-only, symlink, not a
    /// regular file, missing directory or read I/O error.
    Unavailable(&'static str),
    /// Another session holds the sidecar lock.
    Busy,
    /// The file changed or disappeared since it was opened; nothing written.
    Conflict,
    /// A write/fsync/rename step failed before the target was replaced; the
    /// previous file is intact.
    Io(&'static str),
    /// The target was replaced but durability could not be confirmed; the
    /// session must be reopened before further writes.
    DurabilityUncertain,
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
            Self::NotFound => f.write_str("vault file not found"),
            Self::AlreadyExists => f.write_str("vault file already exists"),
            Self::Unavailable(reason) => write!(f, "vault file unavailable: {reason}"),
            Self::Busy => f.write_str("vault is open in another session"),
            Self::Conflict => f.write_str("vault file changed since it was opened"),
            Self::Io(stage) => write!(f, "vault write failed at {stage}; previous file kept"),
            Self::DurabilityUncertain => {
                f.write_str("vault written but durability not confirmed; reopen required")
            }
        }
    }
}

impl std::error::Error for VaultError {}
