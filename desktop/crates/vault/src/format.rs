//! Versioned binary payload and envelope-header encoding for vault v1.
//!
//! The exact layout is specified by ADR-004. This module is deliberately
//! strict: every length is checked before allocation, every enum is validated,
//! and unknown versions/flags/record types fail closed.

use std::fmt;

use otp_core::{Algorithm, Digits};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{VaultError, VaultResult};

/// Envelope/AAD version implemented by this crate.
pub const ENVELOPE_VERSION: u16 = 1;
/// Fixed envelope header length for v1.
pub const HEADER_LEN: usize = 80;
/// Payload schema version implemented by this crate.
pub const PAYLOAD_VERSION: u16 = 1;
/// Fixed payload header length.
pub const PAYLOAD_HEADER_LEN: usize = 16;
/// Upper bound for a future envelope header; v1 uses [`HEADER_LEN`].
pub const MAX_HEADER_BYTES: usize = 4096;
/// Minimum valid file: header + empty payload header + AEAD tag.
pub const MIN_FILE_BYTES: usize = HEADER_LEN + PAYLOAD_HEADER_LEN + 16;
/// Maximum plaintext payload before encryption (16 MiB).
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum ciphertext length including the 16-byte tag.
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_PAYLOAD_BYTES + 16;
/// Maximum file length: envelope header + ciphertext.
pub const MAX_FILE_BYTES: usize = HEADER_LEN + MAX_CIPHERTEXT_BYTES;
/// Maximum number of records in one payload.
pub const MAX_RECORDS: usize = 10_000;
/// Maximum secret length in bytes.
pub const MAX_SECRET_BYTES: usize = 1024;
/// Maximum issuer or account length in bytes.
pub const MAX_STRING_BYTES: usize = 256;
/// Minimum TOTP period in seconds.
pub const MIN_PERIOD_SECONDS: u32 = 1;
/// Maximum TOTP period in seconds.
pub const MAX_PERIOD_SECONDS: u32 = 86_400;
/// Maximum password length in bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Minimum password length for creation/password change.
pub const MIN_NEW_PASSWORD_BYTES: usize = 12;
/// Minimum ciphertext length: payload header plus tag.
pub const MIN_CIPHERTEXT_BYTES: usize = PAYLOAD_HEADER_LEN + 16;

/// Argon2id v19 KDF identifier in the envelope header.
pub const KDF_ID_ARGON2ID_V19: u16 = 1;
/// Default Argon2id memory cost (64 MiB).
pub const DEFAULT_M_COST_KIB: u32 = 65_536;
/// Default Argon2id iterations.
pub const DEFAULT_T_COST: u32 = 3;
/// Default Argon2id parallelism.
pub const DEFAULT_P_COST: u32 = 1;
/// Minimum accepted Argon2id memory cost (19 MiB).
pub const MIN_M_COST_KIB: u32 = 19_456;
/// Maximum accepted Argon2id memory cost (256 MiB).
pub const MAX_M_COST_KIB: u32 = 262_144;
/// Minimum accepted Argon2id iterations.
pub const MIN_T_COST: u32 = 2;
/// Maximum accepted Argon2id iterations.
pub const MAX_T_COST: u32 = 6;
/// Minimum accepted Argon2id parallelism.
pub const MIN_P_COST: u32 = 1;
/// Maximum accepted Argon2id parallelism.
pub const MAX_P_COST: u32 = 4;
/// Derived key length in bytes.
pub const KEY_LEN: usize = 32;
/// Argon2id salt length in bytes.
pub const SALT_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// XChaCha20-Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

const ENVELOPE_MAGIC: &[u8; 4] = b"AVLT";
const PAYLOAD_MAGIC: &[u8; 4] = b"AVP1";
const RECORD_TYPE_OTP: u8 = 1;
/// Record bytes excluding variable fields: type, otp_type, algorithm, digits,
/// period (4), counter (8) and three u16 length prefixes.
const RECORD_FIXED_LEN: usize = 4 + 4 + 8 + 2 + 2 + 2;

/// Argon2id parameters stored in the envelope header.
///
/// Values are constrained to the ADR-004 bounds before they are used to
/// allocate memory. A hostile file cannot request an unbounded KDF cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    /// Creates validated KDF parameters.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> VaultResult<Self> {
        let params = Self {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        params.validate()?;
        Ok(params)
    }

    /// Memory cost in KiB.
    pub const fn m_cost_kib(self) -> u32 {
        self.m_cost_kib
    }

    /// Iteration count.
    pub const fn t_cost(self) -> u32 {
        self.t_cost
    }

    /// Parallelism.
    pub const fn p_cost(self) -> u32 {
        self.p_cost
    }

    /// Validates the ADR-003/ADR-004 bounds.
    pub fn validate(self) -> VaultResult<()> {
        if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&self.m_cost_kib) {
            return Err(VaultError::ResourceLimit("kdf memory cost"));
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost) {
            return Err(VaultError::ResourceLimit("kdf iteration count"));
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&self.p_cost) {
            return Err(VaultError::ResourceLimit("kdf parallelism"));
        }
        // Argon2 requires m_cost >= 8 * p_cost. The v1 bounds already imply
        // this, but keep the invariant explicit for future bound changes.
        if self.m_cost_kib < 8 * self.p_cost {
            return Err(VaultError::ResourceLimit("kdf memory/parallelism"));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

/// OTP family stored in a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpType {
    /// Time-based OTP (RFC 6238).
    Totp,
    /// Counter-based OTP (RFC 4226).
    Hotp,
}

impl OtpType {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Totp => 1,
            Self::Hotp => 2,
        }
    }

    fn from_u8(value: u8) -> VaultResult<Self> {
        match value {
            1 => Ok(Self::Totp),
            2 => Ok(Self::Hotp),
            _ => Err(VaultError::Corrupt("unknown otp type")),
        }
    }
}

fn algorithm_to_u8(algorithm: Algorithm) -> u8 {
    match algorithm {
        Algorithm::Sha1 => 1,
        Algorithm::Sha256 => 2,
        Algorithm::Sha512 => 3,
    }
}

fn algorithm_from_u8(value: u8) -> VaultResult<Algorithm> {
    match value {
        1 => Ok(Algorithm::Sha1),
        2 => Ok(Algorithm::Sha256),
        3 => Ok(Algorithm::Sha512),
        _ => Err(VaultError::Corrupt("unknown algorithm")),
    }
}

fn digits_to_u8(digits: Digits) -> u8 {
    // Digits is a two-variant enum; the cast is exact for 6/8.
    digits.as_u32() as u8
}

fn digits_from_u8(value: u8) -> VaultResult<Digits> {
    Digits::try_from(value).map_err(|_| VaultError::Corrupt("invalid digits"))
}

/// Reclassifies caller-input validation failures as file corruption when
/// parsing authenticated payload bytes.
fn as_corrupt<T>(result: VaultResult<T>) -> VaultResult<T> {
    result.map_err(|error| match error {
        VaultError::InvalidInput(reason) => VaultError::Corrupt(reason),
        other => other,
    })
}

/// One OTP entry inside the encrypted payload.
///
/// `secret` is zeroized on drop and is never shown by `Debug`.
pub struct OtpRecord {
    otp_type: OtpType,
    algorithm: Algorithm,
    digits: Digits,
    period: u32,
    counter: u64,
    secret: Zeroizing<Vec<u8>>,
    issuer: String,
    account: String,
}

impl OtpRecord {
    /// Creates a validated TOTP record (`counter` is always zero).
    pub fn totp(
        algorithm: Algorithm,
        digits: Digits,
        period: u32,
        secret: Vec<u8>,
        issuer: String,
        account: String,
    ) -> VaultResult<Self> {
        Self::build(Self {
            otp_type: OtpType::Totp,
            algorithm,
            digits,
            period,
            counter: 0,
            secret: Zeroizing::new(secret),
            issuer,
            account,
        })
    }

    /// Creates a validated HOTP record (`period` is always zero).
    pub fn hotp(
        algorithm: Algorithm,
        digits: Digits,
        counter: u64,
        secret: Vec<u8>,
        issuer: String,
        account: String,
    ) -> VaultResult<Self> {
        Self::build(Self {
            otp_type: OtpType::Hotp,
            algorithm,
            digits,
            period: 0,
            counter,
            secret: Zeroizing::new(secret),
            issuer,
            account,
        })
    }

    fn build(record: Self) -> VaultResult<Self> {
        record.validate()?;
        Ok(record)
    }

    /// OTP family.
    pub const fn otp_type(&self) -> OtpType {
        self.otp_type
    }

    /// HMAC algorithm.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Code length.
    pub const fn digits(&self) -> Digits {
        self.digits
    }

    /// TOTP period in seconds, or zero for HOTP.
    pub const fn period(&self) -> u32 {
        self.period
    }

    /// HOTP counter, or zero for TOTP.
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Raw secret bytes.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Issuer label (may be empty).
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Account label (non-empty).
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Validates record invariants and ADR-004 limits.
    pub fn validate(&self) -> VaultResult<()> {
        if self.secret.is_empty() || self.secret.len() > MAX_SECRET_BYTES {
            return Err(VaultError::InvalidInput("secret length"));
        }
        if self.issuer.len() > MAX_STRING_BYTES {
            return Err(VaultError::InvalidInput("issuer length"));
        }
        if self.account.is_empty() || self.account.len() > MAX_STRING_BYTES {
            return Err(VaultError::InvalidInput("account length"));
        }
        match self.otp_type {
            OtpType::Totp => {
                if !(MIN_PERIOD_SECONDS..=MAX_PERIOD_SECONDS).contains(&self.period) {
                    return Err(VaultError::InvalidInput("totp period"));
                }
                if self.counter != 0 {
                    return Err(VaultError::InvalidInput("totp counter"));
                }
            }
            OtpType::Hotp => {
                if self.period != 0 {
                    return Err(VaultError::InvalidInput("hotp period"));
                }
            }
        }
        Ok(())
    }

    /// Exact encoded length: 22 fixed bytes plus secret, issuer and account.
    fn encoded_len(&self) -> usize {
        RECORD_FIXED_LEN + self.secret.len() + self.issuer.len() + self.account.len()
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> VaultResult<()> {
        self.validate()?;

        let secret_len = u16::try_from(self.secret.len())
            .map_err(|_| VaultError::ResourceLimit("secret length"))?;
        let issuer_len = u16::try_from(self.issuer.len())
            .map_err(|_| VaultError::ResourceLimit("issuer length"))?;
        let account_len = u16::try_from(self.account.len())
            .map_err(|_| VaultError::ResourceLimit("account length"))?;

        out.push(RECORD_TYPE_OTP);
        out.push(self.otp_type.as_u8());
        out.push(algorithm_to_u8(self.algorithm));
        out.push(digits_to_u8(self.digits));
        out.extend_from_slice(&self.period.to_be_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&secret_len.to_be_bytes());
        out.extend_from_slice(&self.secret[..]);
        out.extend_from_slice(&issuer_len.to_be_bytes());
        out.extend_from_slice(self.issuer.as_bytes());
        out.extend_from_slice(&account_len.to_be_bytes());
        out.extend_from_slice(self.account.as_bytes());
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> VaultResult<Self> {
        let record_type = reader.u8()?;
        if record_type != RECORD_TYPE_OTP {
            return Err(VaultError::Corrupt("unknown record type"));
        }

        let otp_type = OtpType::from_u8(reader.u8()?)?;
        let algorithm = algorithm_from_u8(reader.u8()?)?;
        let digits = digits_from_u8(reader.u8()?)?;
        let period = reader.u32()?;
        let counter = reader.u64()?;

        let secret_len = usize::from(reader.u16()?);
        if !(1..=MAX_SECRET_BYTES).contains(&secret_len) {
            return Err(VaultError::Corrupt("secret length"));
        }
        let secret = Zeroizing::new(reader.take(secret_len)?.to_vec());

        let issuer_len = usize::from(reader.u16()?);
        if issuer_len > MAX_STRING_BYTES {
            return Err(VaultError::Corrupt("issuer length"));
        }
        let issuer = std::str::from_utf8(reader.take(issuer_len)?)
            .map_err(|_| VaultError::Corrupt("issuer utf8"))?
            .to_owned();

        let account_len = usize::from(reader.u16()?);
        if !(1..=MAX_STRING_BYTES).contains(&account_len) {
            return Err(VaultError::Corrupt("account length"));
        }
        let account = std::str::from_utf8(reader.take(account_len)?)
            .map_err(|_| VaultError::Corrupt("account utf8"))?
            .to_owned();

        // Enforce the cross-field invariants explicitly before constructing the
        // typed record; otherwise a decoded TOTP counter or HOTP period would be
        // silently dropped instead of rejected.
        match otp_type {
            OtpType::Totp if counter != 0 => Err(VaultError::Corrupt("totp counter")),
            OtpType::Hotp if period != 0 => Err(VaultError::Corrupt("hotp period")),
            OtpType::Totp => as_corrupt(Self::totp(
                algorithm,
                digits,
                period,
                secret.to_vec(),
                issuer,
                account,
            )),
            OtpType::Hotp => as_corrupt(Self::hotp(
                algorithm,
                digits,
                counter,
                secret.to_vec(),
                issuer,
                account,
            )),
        }
    }
}

impl fmt::Debug for OtpRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret or account label; only public metadata.
        f.debug_struct("OtpRecord")
            .field("otp_type", &self.otp_type)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("counter", &self.counter)
            .field("secret", &"[redacted]")
            .field("issuer_len", &self.issuer.len())
            .field("account_len", &self.account.len())
            .finish()
    }
}

impl PartialEq for OtpRecord {
    fn eq(&self, other: &Self) -> bool {
        self.otp_type == other.otp_type
            && self.algorithm == other.algorithm
            && self.digits == other.digits
            && self.period == other.period
            && self.counter == other.counter
            && self.issuer == other.issuer
            && self.account == other.account
            && self.secret.len() == other.secret.len()
            && bool::from(self.secret[..].ct_eq(&other.secret[..]))
    }
}

impl Eq for OtpRecord {}

/// Decrypted payload: an ordered list of OTP records.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct Payload {
    records: Vec<OtpRecord>,
}

impl Payload {
    /// Creates an empty payload.
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Creates a payload from validated records.
    pub fn from_records(records: Vec<OtpRecord>) -> VaultResult<Self> {
        if records.len() > MAX_RECORDS {
            return Err(VaultError::ResourceLimit("record count"));
        }
        for record in &records {
            record.validate()?;
        }
        Ok(Self { records })
    }

    /// Records in user order.
    pub fn records(&self) -> &[OtpRecord] {
        &self.records
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the payload has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Appends a validated record.
    pub fn push(&mut self, record: OtpRecord) -> VaultResult<()> {
        if self.records.len() >= MAX_RECORDS {
            return Err(VaultError::ResourceLimit("record count"));
        }
        record.validate()?;
        self.records.push(record);
        Ok(())
    }

    /// Replaces the record at `index` after validating the new value.
    pub(crate) fn replace(&mut self, index: usize, record: OtpRecord) -> VaultResult<()> {
        record.validate()?;
        let slot = self
            .records
            .get_mut(index)
            .ok_or(VaultError::UnknownRecord)?;
        *slot = record;
        Ok(())
    }

    /// Removes the record at `index`; its secret is zeroized on drop.
    pub(crate) fn remove(&mut self, index: usize) -> VaultResult<()> {
        if index >= self.records.len() {
            return Err(VaultError::UnknownRecord);
        }
        drop(self.records.remove(index));
        Ok(())
    }

    pub(crate) fn encode(&self) -> VaultResult<Zeroizing<Vec<u8>>> {
        if self.records.len() > MAX_RECORDS {
            return Err(VaultError::ResourceLimit("record count"));
        }

        // Compute the exact size first and allocate once: growing a buffer that
        // holds secrets would leave un-zeroized copies behind on reallocation.
        let mut body_len = 0_usize;
        for record in &self.records {
            body_len = body_len
                .checked_add(record.encoded_len())
                .ok_or(VaultError::ResourceLimit("payload length"))?;
        }
        let total = PAYLOAD_HEADER_LEN
            .checked_add(body_len)
            .ok_or(VaultError::ResourceLimit("payload length"))?;
        if total > MAX_PAYLOAD_BYTES {
            return Err(VaultError::ResourceLimit("payload length"));
        }
        let body_len_u32 =
            u32::try_from(body_len).map_err(|_| VaultError::ResourceLimit("payload length"))?;
        let record_count = u32::try_from(self.records.len())
            .map_err(|_| VaultError::ResourceLimit("record count"))?;

        let mut out = Zeroizing::new(Vec::with_capacity(total));
        out.extend_from_slice(PAYLOAD_MAGIC);
        out.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&body_len_u32.to_be_bytes());
        out.extend_from_slice(&record_count.to_be_bytes());
        for record in &self.records {
            record.encode_into(&mut out)?;
        }
        if out.len() != total || out.capacity() != total {
            return Err(VaultError::InvalidInput("payload length"));
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> VaultResult<Self> {
        let mut reader = Reader::new(bytes);

        if reader.take(4)? != &PAYLOAD_MAGIC[..] {
            return Err(VaultError::Corrupt("payload magic"));
        }
        let version = reader.u16()?;
        if version != PAYLOAD_VERSION {
            return Err(VaultError::Unsupported("payload version"));
        }
        let flags = reader.u16()?;
        if flags != 0 {
            return Err(VaultError::Corrupt("payload flags"));
        }

        let body_len = usize::try_from(reader.u32()?)
            .map_err(|_| VaultError::ResourceLimit("payload length"))?;
        if body_len > MAX_PAYLOAD_BYTES - PAYLOAD_HEADER_LEN {
            return Err(VaultError::ResourceLimit("payload length"));
        }
        let record_count = usize::try_from(reader.u32()?)
            .map_err(|_| VaultError::ResourceLimit("record count"))?;
        if record_count > MAX_RECORDS {
            return Err(VaultError::ResourceLimit("record count"));
        }
        if bytes.len() != PAYLOAD_HEADER_LEN + body_len {
            return Err(VaultError::Corrupt("payload length mismatch"));
        }

        let mut records = Vec::new();
        for _ in 0..record_count {
            records.push(OtpRecord::decode(&mut reader)?);
        }
        if reader.remaining() != 0 {
            return Err(VaultError::Corrupt("trailing payload bytes"));
        }
        as_corrupt(Self::from_records(records))
    }
}

/// Envelope header (80 bytes, authenticated as AAD).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) params: KdfParams,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) nonce: [u8; NONCE_LEN],
    pub(crate) ciphertext_len: u64,
}

impl Header {
    pub(crate) fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(ENVELOPE_MAGIC);
        bytes[4..6].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        bytes[6..8].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        bytes[8..10].copy_from_slice(&KDF_ID_ARGON2ID_V19.to_be_bytes());
        bytes[10..12].copy_from_slice(&0_u16.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.params.m_cost_kib().to_be_bytes());
        bytes[16..20].copy_from_slice(&self.params.t_cost().to_be_bytes());
        bytes[20..24].copy_from_slice(&self.params.p_cost().to_be_bytes());
        bytes[24..28].copy_from_slice(&0_u32.to_be_bytes());
        bytes[28..44].copy_from_slice(&self.salt);
        bytes[44..68].copy_from_slice(&self.nonce);
        bytes[68..76].copy_from_slice(&self.ciphertext_len.to_be_bytes());
        // bytes[76..80] stay zero (reserved).
        bytes
    }

    pub(crate) fn parse(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(VaultError::Corrupt("header length"));
        }
        let mut reader = Reader::new(bytes);

        if reader.take(4)? != &ENVELOPE_MAGIC[..] {
            return Err(VaultError::Corrupt("envelope magic"));
        }
        let version = reader.u16()?;
        if version != ENVELOPE_VERSION {
            return Err(VaultError::Unsupported("envelope version"));
        }
        let header_len = reader.u16()?;
        if header_len != HEADER_LEN as u16 {
            return Err(VaultError::Corrupt("header length"));
        }
        let kdf_id = reader.u16()?;
        if kdf_id != KDF_ID_ARGON2ID_V19 {
            return Err(VaultError::Unsupported("kdf id"));
        }
        let flags = reader.u16()?;
        if flags != 0 {
            return Err(VaultError::Corrupt("header flags"));
        }

        let m_cost_kib = reader.u32()?;
        let t_cost = reader.u32()?;
        let p_cost = reader.u32()?;
        let params = KdfParams::new(m_cost_kib, t_cost, p_cost)?;

        let key_id = reader.u32()?;
        if key_id != 0 {
            return Err(VaultError::Unsupported("key id"));
        }

        let salt: [u8; SALT_LEN] = reader
            .take(SALT_LEN)?
            .try_into()
            .map_err(|_| VaultError::Corrupt("salt length"))?;
        let nonce: [u8; NONCE_LEN] = reader
            .take(NONCE_LEN)?
            .try_into()
            .map_err(|_| VaultError::Corrupt("nonce length"))?;
        let ciphertext_len = reader.u64()?;
        if ciphertext_len < MIN_CIPHERTEXT_BYTES as u64 {
            return Err(VaultError::Corrupt("ciphertext length"));
        }
        if ciphertext_len > MAX_CIPHERTEXT_BYTES as u64 {
            return Err(VaultError::ResourceLimit("ciphertext length"));
        }

        let reserved = reader.u32()?;
        if reserved != 0 {
            return Err(VaultError::Corrupt("reserved header bytes"));
        }
        if reader.remaining() != 0 {
            return Err(VaultError::Corrupt("trailing header bytes"));
        }

        Ok(Self {
            params,
            salt,
            nonce,
            ciphertext_len,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, len: usize) -> VaultResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(VaultError::Corrupt("length overflow"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(VaultError::Corrupt("truncated input"))?;
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> VaultResult<u8> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    fn u16(&mut self) -> VaultResult<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> VaultResult<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> VaultResult<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> OtpRecord {
        OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            30,
            b"12345678901234567890".to_vec(),
            "Example".to_owned(),
            "alice@example.com".to_owned(),
        )
        .expect("valid record")
    }

    fn payload() -> Payload {
        Payload::from_records(vec![record()]).expect("valid payload")
    }

    fn header() -> Header {
        Header {
            params: KdfParams::default(),
            salt: [0x11; SALT_LEN],
            nonce: [0x22; NONCE_LEN],
            ciphertext_len: 128,
        }
    }

    #[test]
    fn header_round_trip() {
        let encoded = header().encode();
        assert_eq!(encoded.len(), HEADER_LEN);
        let parsed = Header::parse(&encoded).expect("parse header");
        assert_eq!(parsed.params, KdfParams::default());
        assert_eq!(parsed.salt, [0x11; SALT_LEN]);
        assert_eq!(parsed.nonce, [0x22; NONCE_LEN]);
        assert_eq!(parsed.ciphertext_len, 128);
    }

    #[test]
    fn header_rejects_structural_corruption() {
        let cases: &[(usize, u8, VaultError)] = &[
            (0, b'X', VaultError::Corrupt("envelope magic")),
            (4, 2, VaultError::Unsupported("envelope version")),
            (6, 79, VaultError::Corrupt("header length")),
            (8, 2, VaultError::Unsupported("kdf id")),
            (10, 1, VaultError::Corrupt("header flags")),
            (76, 1, VaultError::Corrupt("reserved header bytes")),
        ];
        for &(offset, value, expected) in cases {
            let mut bytes = header().encode();
            bytes[offset] = value;
            assert_eq!(Header::parse(&bytes), Err(expected), "offset {offset}");
        }
    }

    #[test]
    fn header_rejects_unknown_key_id() {
        let mut bytes = header().encode();
        bytes[27] = 1; // low byte of key_id
        assert_eq!(
            Header::parse(&bytes),
            Err(VaultError::Unsupported("key id"))
        );
    }

    #[test]
    fn header_rejects_hostile_kdf_parameters() {
        let mut bytes = header().encode();
        // m_cost_kib = 1 KiB
        bytes[12..16].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            Header::parse(&bytes),
            Err(VaultError::ResourceLimit("kdf memory cost"))
        );

        let mut bytes = header().encode();
        // t_cost = 1
        bytes[16..20].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            Header::parse(&bytes),
            Err(VaultError::ResourceLimit("kdf iteration count"))
        );

        let mut bytes = header().encode();
        // p_cost = 0
        bytes[20..24].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            Header::parse(&bytes),
            Err(VaultError::ResourceLimit("kdf parallelism"))
        );
    }

    #[test]
    fn header_rejects_bad_ciphertext_length() {
        let mut bytes = header().encode();
        bytes[68..76].copy_from_slice(&0_u64.to_be_bytes());
        assert_eq!(
            Header::parse(&bytes),
            Err(VaultError::Corrupt("ciphertext length"))
        );

        let mut bytes = header().encode();
        bytes[68..76].copy_from_slice(&(MAX_CIPHERTEXT_BYTES as u64 + 1).to_be_bytes());
        assert_eq!(
            Header::parse(&bytes),
            Err(VaultError::ResourceLimit("ciphertext length"))
        );
    }

    #[test]
    fn payload_encode_allocates_exactly_once() {
        let mut many = Payload::new();
        for i in 0..64_u8 {
            let record = OtpRecord::hotp(
                Algorithm::Sha256,
                Digits::Eight,
                u64::from(i),
                vec![i; 1 + usize::from(i)],
                "issuer".repeat(usize::from(i % 4)),
                format!("account-{i}"),
            )
            .expect("valid record");
            many.push(record).expect("push");
        }
        for payload in [Payload::new(), payload(), many] {
            let encoded = payload.encode().expect("encode payload");
            // No reallocation means no un-zeroized plaintext copies were freed.
            assert_eq!(encoded.capacity(), encoded.len());
            let expected: usize = PAYLOAD_HEADER_LEN
                + payload
                    .records()
                    .iter()
                    .map(OtpRecord::encoded_len)
                    .sum::<usize>();
            assert_eq!(encoded.len(), expected);
            assert_eq!(Payload::decode(&encoded).expect("decode"), payload);
        }
    }

    #[test]
    fn payload_round_trip() {
        let encoded = payload().encode().expect("encode payload");
        let decoded = Payload::decode(&encoded).expect("decode payload");
        assert_eq!(decoded, payload());
        assert_eq!(decoded.records()[0].secret(), b"12345678901234567890");
    }

    #[test]
    fn payload_rejects_header_corruption() {
        let encoded = payload().encode().expect("encode payload");

        let mut bad = encoded.to_vec();
        bad[0] = b'X';
        assert_eq!(
            Payload::decode(&bad),
            Err(VaultError::Corrupt("payload magic"))
        );

        let mut bad = encoded.to_vec();
        bad[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            Payload::decode(&bad),
            Err(VaultError::Unsupported("payload version"))
        );

        let mut bad = encoded.to_vec();
        bad[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            Payload::decode(&bad),
            Err(VaultError::Corrupt("payload flags"))
        );

        let mut bad = encoded.to_vec();
        bad[8..12].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            Payload::decode(&bad),
            Err(VaultError::Corrupt("payload length mismatch"))
        );

        let mut bad = encoded.to_vec();
        bad[12..16].copy_from_slice(&2_u32.to_be_bytes());
        assert!(Payload::decode(&bad).is_err());
    }

    #[test]
    fn payload_rejects_truncation_and_trailing_bytes() {
        let encoded = payload().encode().expect("encode payload");
        assert!(Payload::decode(&encoded[..encoded.len() - 1]).is_err());

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            Payload::decode(&trailing),
            Err(VaultError::Corrupt("payload length mismatch"))
        );
    }

    #[test]
    fn record_rejects_invalid_fields() {
        let base = || {
            OtpRecord::totp(
                Algorithm::Sha1,
                Digits::Six,
                30,
                b"secret".to_vec(),
                "Issuer".to_owned(),
                "account".to_owned(),
            )
        };
        assert!(base().is_ok());

        let empty_secret = OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            30,
            Vec::new(),
            "Issuer".to_owned(),
            "account".to_owned(),
        );
        assert_eq!(empty_secret, Err(VaultError::InvalidInput("secret length")));

        let too_long = OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            30,
            vec![0; MAX_SECRET_BYTES + 1],
            "Issuer".to_owned(),
            "account".to_owned(),
        );
        assert_eq!(too_long, Err(VaultError::InvalidInput("secret length")));

        let empty_account = OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            30,
            b"secret".to_vec(),
            "Issuer".to_owned(),
            String::new(),
        );
        assert_eq!(
            empty_account,
            Err(VaultError::InvalidInput("account length"))
        );

        let long_issuer = OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            30,
            b"secret".to_vec(),
            "i".repeat(MAX_STRING_BYTES + 1),
            "account".to_owned(),
        );
        assert_eq!(long_issuer, Err(VaultError::InvalidInput("issuer length")));

        let zero_period = OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            0,
            b"secret".to_vec(),
            "Issuer".to_owned(),
            "account".to_owned(),
        );
        assert_eq!(zero_period, Err(VaultError::InvalidInput("totp period")));

        let long_period = OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            MAX_PERIOD_SECONDS + 1,
            b"secret".to_vec(),
            "Issuer".to_owned(),
            "account".to_owned(),
        );
        assert_eq!(long_period, Err(VaultError::InvalidInput("totp period")));

        assert!(OtpRecord::hotp(
            Algorithm::Sha1,
            Digits::Six,
            u64::MAX,
            b"secret".to_vec(),
            "Issuer".to_owned(),
            "account".to_owned(),
        )
        .is_ok());
    }

    #[test]
    fn record_decode_rejects_bad_enums_and_utf8() {
        let valid = {
            let mut payload = payload().encode().expect("encode");
            let start = PAYLOAD_HEADER_LEN;
            payload.drain(..start);
            payload
        };

        let mut bad = valid.clone();
        bad[1] = 9; // otp_type
        assert_eq!(
            OtpRecord::decode(&mut Reader::new(&bad)),
            Err(VaultError::Corrupt("unknown otp type"))
        );

        let mut bad = valid.clone();
        bad[2] = 9; // algorithm
        assert_eq!(
            OtpRecord::decode(&mut Reader::new(&bad)),
            Err(VaultError::Corrupt("unknown algorithm"))
        );

        let mut bad = valid.clone();
        bad[3] = 7; // digits
        assert_eq!(
            OtpRecord::decode(&mut Reader::new(&bad)),
            Err(VaultError::Corrupt("invalid digits"))
        );

        // Corrupt the first issuer byte into invalid UTF-8 while keeping the
        // declared length. The record layout is 18 header + 20 secret +
        // 2 length bytes before the issuer.
        let mut bad = valid;
        bad[18 + 20 + 2] = 0xff;
        assert_eq!(
            OtpRecord::decode(&mut Reader::new(&bad)),
            Err(VaultError::Corrupt("issuer utf8"))
        );
    }

    #[test]
    fn record_decode_rejects_cross_field_violations() {
        let valid = {
            let mut payload = payload().encode().expect("encode");
            payload.drain(..PAYLOAD_HEADER_LEN);
            payload
        };

        // TOTP record with a non-zero counter.
        let mut bad = valid;
        bad[8..16].copy_from_slice(&1_u64.to_be_bytes());
        assert_eq!(
            OtpRecord::decode(&mut Reader::new(&bad)),
            Err(VaultError::Corrupt("totp counter"))
        );

        // HOTP record with a non-zero period.
        let hotp = OtpRecord::hotp(
            Algorithm::Sha1,
            Digits::Six,
            7,
            b"secret".to_vec(),
            "Issuer".to_owned(),
            "account".to_owned(),
        )
        .expect("valid hotp");
        let mut bad = Vec::new();
        hotp.encode_into(&mut bad).expect("encode hotp");
        bad[4..8].copy_from_slice(&30_u32.to_be_bytes());
        assert_eq!(
            OtpRecord::decode(&mut Reader::new(&bad)),
            Err(VaultError::Corrupt("hotp period"))
        );
    }

    #[test]
    fn debug_does_not_leak_secret_or_account() {
        let rendered = format!("{:?}", record());
        assert!(!rendered.contains("12345678901234567890"));
        assert!(!rendered.contains("alice@example.com"));
        assert!(rendered.contains("redacted"));
    }

    // ---- VAULT-004: decode-side bounds and robustness -------------------

    /// Raw record bytes with arbitrary (possibly invalid) field values.
    #[allow(clippy::too_many_arguments)]
    fn raw_record(
        record_type: u8,
        otp_type: u8,
        algorithm: u8,
        digits: u8,
        period: u32,
        counter: u64,
        secret: &[u8],
        issuer: &[u8],
        account: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![record_type, otp_type, algorithm, digits];
        out.extend_from_slice(&period.to_be_bytes());
        out.extend_from_slice(&counter.to_be_bytes());
        for field in [secret, issuer, account] {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    fn valid_raw(secret: &[u8], issuer: &[u8], account: &[u8], period: u32) -> Vec<u8> {
        raw_record(1, 1, 1, 6, period, 0, secret, issuer, account)
    }

    fn raw_payload(body: &[u8], record_count: u32) -> Vec<u8> {
        let mut out = PAYLOAD_MAGIC.to_vec();
        out.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&record_count.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn decode_one(record: &[u8]) -> VaultResult<Payload> {
        Payload::decode(&raw_payload(record, 1))
    }

    #[test]
    fn raw_builder_matches_encoder() {
        let raw = raw_payload(
            &valid_raw(
                b"12345678901234567890",
                b"Example",
                b"alice@example.com",
                30,
            ),
            1,
        );
        assert_eq!(&raw[..], &payload().encode().expect("encode")[..]);
    }

    #[test]
    fn record_decode_enforces_every_length_and_value_bound() {
        let ok = |secret: &[u8], issuer: &[u8], account: &[u8], period| {
            decode_one(&valid_raw(secret, issuer, account, period))
        };
        let max_secret = vec![0xa5; MAX_SECRET_BYTES];
        let max_string = vec![b'x'; MAX_STRING_BYTES];

        // Inclusive boundaries are accepted.
        assert!(ok(&[1], b"", b"a", MIN_PERIOD_SECONDS).is_ok());
        assert!(ok(&max_secret, &max_string, &max_string, MAX_PERIOD_SECONDS).is_ok());

        // One past each boundary is rejected as corruption.
        let cases: [(VaultResult<Payload>, &str); 7] = [
            (ok(&[], b"i", b"a", 30), "secret length"),
            (
                ok(&vec![0; MAX_SECRET_BYTES + 1], b"i", b"a", 30),
                "secret length",
            ),
            (
                ok(&[1], &vec![b'x'; MAX_STRING_BYTES + 1], b"a", 30),
                "issuer length",
            ),
            (ok(&[1], b"i", b"", 30), "account length"),
            (
                ok(&[1], b"i", &vec![b'x'; MAX_STRING_BYTES + 1], 30),
                "account length",
            ),
            (ok(&[1], b"i", b"a", 0), "totp period"),
            (ok(&[1], b"i", b"a", MAX_PERIOD_SECONDS + 1), "totp period"),
        ];
        for (result, reason) in cases {
            assert_eq!(result, Err(VaultError::Corrupt(reason)), "{reason}");
        }

        assert_eq!(
            ok(&[1], b"i", &[0xff, 0xfe], 30),
            Err(VaultError::Corrupt("account utf8"))
        );
        assert_eq!(
            decode_one(&raw_record(2, 1, 1, 6, 30, 0, &[1], b"i", b"a")),
            Err(VaultError::Corrupt("unknown record type"))
        );
        assert_eq!(
            decode_one(&raw_record(0, 1, 1, 6, 30, 0, &[1], b"i", b"a")),
            Err(VaultError::Corrupt("unknown record type"))
        );
    }

    #[test]
    fn payload_decode_enforces_count_and_size_limits() {
        let mut bytes = raw_payload(&[], 0);
        bytes[12..16].copy_from_slice(&(MAX_RECORDS as u32 + 1).to_be_bytes());
        assert_eq!(
            Payload::decode(&bytes),
            Err(VaultError::ResourceLimit("record count"))
        );

        let mut bytes = raw_payload(&[], 0);
        let too_big = (MAX_PAYLOAD_BYTES - PAYLOAD_HEADER_LEN + 1) as u32;
        bytes[8..12].copy_from_slice(&too_big.to_be_bytes());
        assert_eq!(
            Payload::decode(&bytes),
            Err(VaultError::ResourceLimit("payload length"))
        );

        // record_count smaller than the records present: trailing bytes.
        let record = valid_raw(&[1], b"i", b"a", 30);
        let mut two = record.clone();
        two.extend_from_slice(&record);
        assert_eq!(
            Payload::decode(&raw_payload(&two, 1)),
            Err(VaultError::Corrupt("trailing payload bytes"))
        );
        assert_eq!(
            Payload::decode(&raw_payload(&two, 2)).map(|p| p.len()),
            Ok(2)
        );
    }

    #[test]
    fn encoder_refuses_more_than_max_records() {
        let mut payload = Payload::new();
        for _ in 0..MAX_RECORDS {
            payload
                .push(
                    OtpRecord::hotp(
                        Algorithm::Sha1,
                        Digits::Six,
                        0,
                        vec![1],
                        String::new(),
                        "a".to_owned(),
                    )
                    .expect("record"),
                )
                .expect("push");
        }
        let extra = OtpRecord::hotp(
            Algorithm::Sha1,
            Digits::Six,
            0,
            vec![1],
            String::new(),
            "a".to_owned(),
        )
        .expect("record");
        assert_eq!(
            payload.push(extra),
            Err(VaultError::ResourceLimit("record count"))
        );
        let encoded = payload.encode().expect("encode at the limit");
        assert_eq!(Payload::decode(&encoded).map(|p| p.len()), Ok(MAX_RECORDS));
    }

    /// Fixed-seed xorshift64*, same approach as otp-core property tests.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }
    }

    /// Decoding either fails with a classified error or yields a payload that
    /// re-encodes to exactly the same bytes. It never panics.
    fn check_payload_bytes(bytes: &[u8]) {
        match Payload::decode(bytes) {
            Ok(decoded) => {
                let encoded = decoded.encode().expect("re-encode");
                assert_eq!(&encoded[..], bytes, "decode/encode must be canonical");
            }
            Err(error) => assert!(matches!(
                error,
                VaultError::Corrupt(_) | VaultError::Unsupported(_) | VaultError::ResourceLimit(_)
            )),
        }
    }

    fn check_header_bytes(bytes: &[u8]) {
        match Header::parse(bytes) {
            Ok(parsed) => assert_eq!(&parsed.encode()[..], bytes, "canonical header"),
            Err(error) => assert!(matches!(
                error,
                VaultError::Corrupt(_) | VaultError::Unsupported(_) | VaultError::ResourceLimit(_)
            )),
        }
    }

    #[test]
    fn decoders_never_panic_on_truncation_and_bit_flips() {
        let mut mixed = payload();
        mixed
            .push(
                OtpRecord::hotp(
                    Algorithm::Sha512,
                    Digits::Eight,
                    u64::MAX,
                    vec![0xff; 40],
                    "Пример".to_owned(),
                    "用户@example.test".to_owned(),
                )
                .expect("record"),
            )
            .expect("push");
        let payload_bytes = mixed.encode().expect("encode");
        let header_bytes = header().encode();

        for len in 0..=payload_bytes.len() {
            check_payload_bytes(&payload_bytes[..len]);
        }
        for bit in 0..payload_bytes.len() * 8 {
            let mut flipped = payload_bytes.to_vec();
            flipped[bit / 8] ^= 1 << (bit % 8);
            check_payload_bytes(&flipped);
        }
        for len in 0..=HEADER_LEN {
            check_header_bytes(&header_bytes[..len]);
        }
        for bit in 0..HEADER_LEN * 8 {
            let mut flipped = header_bytes;
            flipped[bit / 8] ^= 1 << (bit % 8);
            check_header_bytes(&flipped);
        }
    }

    #[test]
    fn decoders_never_panic_on_random_input() {
        let mut rng = XorShift(0x5641_554c_5430_3034); // "VAULT004"
        let template = payload().encode().expect("encode");
        for _ in 0..20_000 {
            let len = rng.below(320);
            let mut bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            // Half of the inputs keep a valid payload prefix so that record
            // parsing, not just the magic check, is exercised.
            if rng.next() & 1 == 0 && len >= PAYLOAD_HEADER_LEN {
                bytes[..PAYLOAD_HEADER_LEN].copy_from_slice(&template[..PAYLOAD_HEADER_LEN]);
                let body = (len - PAYLOAD_HEADER_LEN) as u32;
                bytes[8..12].copy_from_slice(&body.to_be_bytes());
                bytes[12..16].copy_from_slice(&(rng.below(4) as u32).to_be_bytes());
            }
            check_payload_bytes(&bytes);

            let mut header_bytes = [0_u8; HEADER_LEN];
            header_bytes.iter_mut().for_each(|b| *b = rng.next() as u8);
            if rng.next() & 1 == 0 {
                header_bytes[..12].copy_from_slice(&header().encode()[..12]);
            }
            check_header_bytes(&header_bytes);
        }
    }
}
