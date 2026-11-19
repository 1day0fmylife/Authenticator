//! RFC 4226 HOTP, RFC 6238 TOTP and strict `otpauth://` Key URI handling.
//!
//! This crate is deliberately limited to OTP computation and Key URI parsing:
//! no GUI, storage, network or logging code. It does not implement replay
//! protection; accepting a time-step or counter exactly once is the caller's
//! responsibility.
//!
//! Secrets are never included in error values or `Debug` output.

#![forbid(unsafe_code)]

mod uri;

use std::fmt;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use uri::{OtpType, OtpUri, UriError, DEFAULT_PERIOD_SECONDS, MAX_LABEL_BYTES, MAX_URI_BYTES};

/// Minimum accepted secret length in bytes.
pub const MIN_SECRET_BYTES: usize = 1;
/// Maximum accepted secret length in bytes.
pub const MAX_SECRET_BYTES: usize = 1024;
/// Minimum TOTP period in seconds.
pub const MIN_PERIOD_SECONDS: u32 = 1;
/// Maximum TOTP period in seconds.
pub const MAX_PERIOD_SECONDS: u32 = 86_400;
/// Maximum accepted TOTP clock-drift window, in steps in each direction.
pub const MAX_SKEW_STEPS: u8 = 2;
/// Maximum accepted HOTP counter look-ahead.
pub const MAX_HOTP_LOOK_AHEAD: u8 = 10;

/// Supported HMAC hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA-1, required for compatibility with existing TOTP services.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Algorithm {
    /// Canonical uppercase name, e.g. `SHA1`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl TryFrom<&str> for Algorithm {
    type Error = OtpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(OtpError::InvalidAlgorithm),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Supported OTP code lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digits {
    /// Six decimal digits.
    Six,
    /// Eight decimal digits.
    Eight,
}

impl Digits {
    /// Number of decimal digits.
    pub const fn as_usize(self) -> usize {
        match self {
            Self::Six => 6,
            Self::Eight => 8,
        }
    }

    /// Number of decimal digits as `u32`.
    pub const fn as_u32(self) -> u32 {
        self.as_usize() as u32
    }
}

impl TryFrom<u8> for Digits {
    type Error = OtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            6 => Ok(Self::Six),
            8 => Ok(Self::Eight),
            _ => Err(OtpError::InvalidDigits),
        }
    }
}

/// Input and state errors. Error values never contain secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    /// Secret is empty or longer than [`MAX_SECRET_BYTES`].
    InvalidSecret,
    /// Code length is not 6 or 8.
    InvalidDigits,
    /// Unsupported hash algorithm.
    InvalidAlgorithm,
    /// TOTP period is outside the accepted bounds.
    InvalidPeriod,
    /// Unix timestamp is negative.
    InvalidTime,
    /// Code must contain exactly the configured number of ASCII digits.
    InvalidCode,
    /// Skew or look-ahead exceeds the accepted bounds.
    InvalidSkew,
    /// Counter plus look-ahead does not fit in `u64`.
    CounterOverflow,
}

impl fmt::Display for OtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSecret => "invalid secret length",
            Self::InvalidDigits => "digits must be 6 or 8",
            Self::InvalidAlgorithm => "unsupported algorithm",
            Self::InvalidPeriod => "invalid period",
            Self::InvalidTime => "invalid unix time",
            Self::InvalidCode => "invalid code format",
            Self::InvalidSkew => "invalid skew window",
            Self::CounterOverflow => "counter overflow",
        };
        f.write_str(message)
    }
}

impl std::error::Error for OtpError {}

fn validate_secret(secret: &[u8]) -> Result<(), OtpError> {
    if secret.len() < MIN_SECRET_BYTES || secret.len() > MAX_SECRET_BYTES {
        return Err(OtpError::InvalidSecret);
    }
    Ok(())
}

fn validate_period(period: u32) -> Result<(), OtpError> {
    if !(MIN_PERIOD_SECONDS..=MAX_PERIOD_SECONDS).contains(&period) {
        return Err(OtpError::InvalidPeriod);
    }
    Ok(())
}

fn validate_code(code: &str, digits: Digits) -> Result<(), OtpError> {
    if code.len() != digits.as_usize() || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OtpError::InvalidCode);
    }
    Ok(())
}

fn hmac_tag(
    secret: &[u8],
    msg: &[u8],
    algorithm: Algorithm,
) -> Result<(Zeroizing<[u8; 64]>, usize), OtpError> {
    let mut digest = Zeroizing::new([0_u8; 64]);
    let length = match algorithm {
        Algorithm::Sha1 => {
            let mut mac =
                Hmac::<Sha1>::new_from_slice(secret).map_err(|_| OtpError::InvalidSecret)?;
            mac.update(msg);
            let tag = mac.finalize().into_bytes();
            digest[..tag.len()].copy_from_slice(&tag);
            tag.len()
        }
        Algorithm::Sha256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).map_err(|_| OtpError::InvalidSecret)?;
            mac.update(msg);
            let tag = mac.finalize().into_bytes();
            digest[..tag.len()].copy_from_slice(&tag);
            tag.len()
        }
        Algorithm::Sha512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(secret).map_err(|_| OtpError::InvalidSecret)?;
            mac.update(msg);
            let tag = mac.finalize().into_bytes();
            digest[..tag.len()].copy_from_slice(&tag);
            tag.len()
        }
    };
    Ok((digest, length))
}

fn hotp_value(
    secret: &[u8],
    counter: u64,
    digits: Digits,
    algorithm: Algorithm,
) -> Result<u32, OtpError> {
    validate_secret(secret)?;

    let (digest, length) = hmac_tag(secret, &counter.to_be_bytes(), algorithm)?;
    if length < 4 {
        return Err(OtpError::InvalidAlgorithm);
    }

    // RFC 4226 §5.3 dynamic truncation. The offset is at most 15 and every
    // supported hash is at least 20 bytes, so the checked bound is internal.
    let offset = usize::from(digest[length - 1] & 0x0f);
    let end = offset.checked_add(4).ok_or(OtpError::InvalidAlgorithm)?;
    if end > length {
        return Err(OtpError::InvalidAlgorithm);
    }
    let bytes = &digest[offset..end];

    let value = (u32::from(bytes[0] & 0x7f) << 24)
        | (u32::from(bytes[1]) << 16)
        | (u32::from(bytes[2]) << 8)
        | u32::from(bytes[3]);

    Ok(value % 10_u32.pow(digits.as_u32()))
}

fn format_code(value: u32, digits: Digits) -> String {
    format!("{value:0width$}", width = digits.as_usize())
}

fn codes_equal(a: &str, b: &str) -> bool {
    // Length is public; only the content comparison must be constant-time.
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Generates an HOTP code for `counter` (RFC 4226).
pub fn generate_hotp(
    secret: &[u8],
    counter: u64,
    digits: Digits,
    algorithm: Algorithm,
) -> Result<String, OtpError> {
    Ok(format_code(
        hotp_value(secret, counter, digits, algorithm)?,
        digits,
    ))
}

/// Converts a Unix timestamp to a TOTP time-step.
pub fn time_step(unix_time: i64, period: u32) -> Result<u64, OtpError> {
    if unix_time < 0 {
        return Err(OtpError::InvalidTime);
    }
    validate_period(period)?;
    Ok((unix_time as u64) / u64::from(period))
}

/// Generates a TOTP code for an explicit time-step.
pub fn generate_totp_at_step(
    secret: &[u8],
    step: u64,
    digits: Digits,
    algorithm: Algorithm,
) -> Result<String, OtpError> {
    generate_hotp(secret, step, digits, algorithm)
}

/// Generates a TOTP code for a Unix timestamp and period (RFC 6238).
pub fn generate_totp(
    secret: &[u8],
    unix_time: i64,
    period: u32,
    digits: Digits,
    algorithm: Algorithm,
) -> Result<String, OtpError> {
    let step = time_step(unix_time, period)?;
    generate_totp_at_step(secret, step, digits, algorithm)
}

/// Compares two OTP codes in constant time for equal lengths.
pub fn constant_time_equal(a: &str, b: &str) -> bool {
    codes_equal(a, b)
}

/// Validates a TOTP code at `unix_time`, allowing `skew_steps` steps of clock
/// drift in each direction.
///
/// Replay protection is not performed here: the caller must atomically record
/// an accepted time-step.
pub fn validate_totp(
    secret: &[u8],
    code: &str,
    unix_time: i64,
    period: u32,
    digits: Digits,
    algorithm: Algorithm,
    skew_steps: u8,
) -> Result<bool, OtpError> {
    if skew_steps > MAX_SKEW_STEPS {
        return Err(OtpError::InvalidSkew);
    }
    validate_code(code, digits)?;
    let base = time_step(unix_time, period)?;

    let skew = i64::from(skew_steps);
    let mut matched = false;
    for delta in -skew..=skew {
        let candidate = if delta < 0 {
            let back = delta.unsigned_abs();
            match base.checked_sub(back) {
                Some(candidate) => candidate,
                None => continue,
            }
        } else {
            base.checked_add(delta as u64)
                .ok_or(OtpError::CounterOverflow)?
        };

        let expected = generate_totp_at_step(secret, candidate, digits, algorithm)?;
        // Compare every candidate instead of returning early so the number of
        // comparisons does not reveal which step matched.
        matched |= codes_equal(code, &expected);
    }
    Ok(matched)
}

/// Validates an HOTP code in `counter..=counter+look_ahead`.
///
/// Returns the matched counter. The caller must atomically persist the
/// accepted counter and reject replays.
pub fn validate_hotp(
    secret: &[u8],
    code: &str,
    counter: u64,
    digits: Digits,
    algorithm: Algorithm,
    look_ahead: u8,
) -> Result<Option<u64>, OtpError> {
    if look_ahead > MAX_HOTP_LOOK_AHEAD {
        return Err(OtpError::InvalidSkew);
    }
    validate_code(code, digits)?;
    counter
        .checked_add(u64::from(look_ahead))
        .ok_or(OtpError::CounterOverflow)?;

    let mut matched = None;
    for offset in 0..=u64::from(look_ahead) {
        let candidate = counter + offset;
        let expected = generate_hotp(secret, candidate, digits, algorithm)?;
        if matched.is_none() && codes_equal(code, &expected) {
            matched = Some(candidate);
        }
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn code_comparison() {
        assert!(constant_time_equal("123456", "123456"));
        assert!(!constant_time_equal("123456", "123457"));
        assert!(!constant_time_equal("123456", "1234567"));
    }

    #[test]
    fn algorithm_names() {
        assert_eq!(Algorithm::try_from("SHA1"), Ok(Algorithm::Sha1));
        assert_eq!(Algorithm::try_from("SHA256"), Ok(Algorithm::Sha256));
        assert_eq!(Algorithm::try_from("SHA512"), Ok(Algorithm::Sha512));
        assert_eq!(Algorithm::try_from("MD5"), Err(OtpError::InvalidAlgorithm));
        assert_eq!(Algorithm::Sha512.to_string(), "SHA512");
    }

    #[test]
    fn digits_conversion() {
        assert_eq!(Digits::try_from(6), Ok(Digits::Six));
        assert_eq!(Digits::try_from(8), Ok(Digits::Eight));
        assert_eq!(Digits::try_from(7), Err(OtpError::InvalidDigits));
        assert_eq!(Digits::Eight.as_usize(), 8);
    }

    #[test]
    fn secret_limits() {
        assert_eq!(
            generate_hotp(&[], 0, Digits::Six, Algorithm::Sha1),
            Err(OtpError::InvalidSecret)
        );
        assert!(generate_hotp(
            &vec![0_u8; MAX_SECRET_BYTES],
            0,
            Digits::Six,
            Algorithm::Sha1
        )
        .is_ok());
        assert_eq!(
            generate_hotp(
                &vec![0_u8; MAX_SECRET_BYTES + 1],
                0,
                Digits::Six,
                Algorithm::Sha1
            ),
            Err(OtpError::InvalidSecret)
        );
    }

    #[test]
    fn period_and_time_bounds() {
        assert_eq!(time_step(-1, 30), Err(OtpError::InvalidTime));
        assert_eq!(time_step(0, 0), Err(OtpError::InvalidPeriod));
        assert_eq!(
            time_step(0, MAX_PERIOD_SECONDS + 1),
            Err(OtpError::InvalidPeriod)
        );
        assert_eq!(time_step(59, 30), Ok(1));
        assert_eq!(time_step(60, 30), Ok(2));
    }

    #[test]
    fn skew_bounds() {
        assert_eq!(
            validate_totp(
                SECRET,
                "287082",
                59,
                30,
                Digits::Six,
                Algorithm::Sha1,
                MAX_SKEW_STEPS + 1
            ),
            Err(OtpError::InvalidSkew)
        );
        assert_eq!(
            validate_hotp(
                SECRET,
                "755224",
                0,
                Digits::Six,
                Algorithm::Sha1,
                MAX_HOTP_LOOK_AHEAD + 1
            ),
            Err(OtpError::InvalidSkew)
        );
    }

    #[test]
    fn counter_overflow() {
        assert!(generate_hotp(SECRET, u64::MAX, Digits::Six, Algorithm::Sha1).is_ok());
        assert_eq!(
            validate_hotp(SECRET, "000000", u64::MAX, Digits::Six, Algorithm::Sha1, 1),
            Err(OtpError::CounterOverflow)
        );
    }

    #[test]
    fn rejects_malformed_codes() {
        for code in ["28708", "28708a", "", "2870820"] {
            assert_eq!(
                validate_totp(SECRET, code, 59, 30, Digits::Six, Algorithm::Sha1, 0),
                Err(OtpError::InvalidCode),
                "code {code:?}"
            );
        }
    }

    #[test]
    fn errors_do_not_contain_secret() {
        let secret = b"super-secret-test-value";
        let error = validate_totp(secret, "bad", 0, 30, Digits::Six, Algorithm::Sha1, 0)
            .expect_err("invalid code must fail");
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("super-secret-test-value"));
    }
}
