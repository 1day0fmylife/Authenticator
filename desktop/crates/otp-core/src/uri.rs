//! Strict `otpauth://` Key URI parser and generator.
//!
//! The grammar implemented here is the Key Uri Format used by Google
//! Authenticator and compatible products, restricted to the subset supported by
//! this project: `totp` and `hotp`, SHA-1/256/512, 6/8 digits and a bounded
//! period/counter.
//!
//! Deliberate v1 restrictions (documented in `tests/vectors/README.md`):
//!
//! - raw input must be ASCII and at most [`MAX_URI_BYTES`] bytes; issuer,
//!   account and label values with non-ASCII text must be percent-encoded;
//! - percent-decoding only, never form-decoding: a literal `+` stays `+`;
//! - unknown or duplicate query parameters are rejected instead of ignored;
//! - digits must be exactly `6` or `8`, period exactly `1..=86400`, HOTP
//!   counter must fit `u64`; defaults are SHA-1, 6 digits and period 30;
//! - an `issuer` parameter and a label issuer prefix must agree exactly;
//! - for HOTP `counter` is required and `period` is forbidden; for TOTP the
//!   opposite applies.
//!
//! Errors and `Debug` never include the secret, account or issuer values.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Algorithm, Digits, MAX_PERIOD_SECONDS, MAX_SECRET_BYTES, MIN_PERIOD_SECONDS};

/// Maximum accepted raw URI length in bytes.
pub const MAX_URI_BYTES: usize = 4096;
/// Maximum issuer or account length in bytes after decoding.
pub const MAX_LABEL_BYTES: usize = 256;
/// Default TOTP period in seconds.
pub const DEFAULT_PERIOD_SECONDS: u32 = 30;

const SCHEME: &str = "otpauth://";

/// OTP family encoded in the URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpType {
    /// Time-based OTP.
    Totp,
    /// Counter-based OTP.
    Hotp,
}

impl OtpType {
    /// Canonical lowercase name used in the URI.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
        }
    }
}

/// Parser and generator errors.
///
/// Values are static: no error variant can carry a secret, account, issuer or
/// the rejected input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriError {
    /// Input is empty.
    Empty,
    /// Input exceeds [`MAX_URI_BYTES`].
    TooLong,
    /// Scheme is not `otpauth://`.
    InvalidScheme,
    /// OTP type is not `totp` or `hotp`.
    InvalidType,
    /// Label is empty, malformed or has multiple raw colons.
    InvalidLabel,
    /// Percent escape is truncated or not hexadecimal.
    InvalidEscape,
    /// Raw byte is not ASCII printable.
    InvalidCharacter,
    /// Decoded byte or character is a control character.
    ControlCharacter,
    /// Decoded issuer/account is not valid UTF-8.
    InvalidUtf8,
    /// Secret is missing, not Base32, empty or over the byte limit.
    InvalidSecret,
    /// Issuer is empty, too long or contains control characters.
    InvalidIssuer,
    /// Account is empty, too long or contains control characters.
    InvalidAccount,
    /// Required `secret` parameter is absent.
    MissingSecret,
    /// HOTP `counter` parameter is absent.
    MissingCounter,
    /// A query parameter appears more than once.
    DuplicateParameter,
    /// Query parameter is not part of the v1 subset.
    UnknownParameter,
    /// Query parameter is malformed (no `=`, empty key or empty item).
    InvalidParameter,
    /// Algorithm is not SHA1/SHA256/SHA512.
    InvalidAlgorithm,
    /// Digits are not exactly 6 or 8.
    InvalidDigits,
    /// Period is not a canonical decimal in `1..=86400`.
    InvalidPeriod,
    /// Counter is not a canonical decimal `u64`.
    InvalidCounter,
    /// Label issuer and `issuer` parameter disagree.
    ContradictoryIssuer,
    /// `period` on HOTP or `counter` on TOTP.
    UnexpectedParameter,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty OTP URI",
            Self::TooLong => "OTP URI is too long",
            Self::InvalidScheme => "OTP URI scheme must be otpauth://",
            Self::InvalidType => "OTP URI type must be totp or hotp",
            Self::InvalidLabel => "invalid OTP URI label",
            Self::InvalidEscape => "invalid percent escape",
            Self::InvalidCharacter => "invalid character in OTP URI",
            Self::ControlCharacter => "control character in OTP URI",
            Self::InvalidUtf8 => "invalid UTF-8 in OTP URI label",
            Self::InvalidSecret => "invalid OTP secret",
            Self::InvalidIssuer => "invalid OTP issuer",
            Self::InvalidAccount => "invalid OTP account",
            Self::MissingSecret => "OTP URI is missing secret",
            Self::MissingCounter => "HOTP URI is missing counter",
            Self::DuplicateParameter => "duplicate OTP URI parameter",
            Self::UnknownParameter => "unsupported OTP URI parameter",
            Self::InvalidParameter => "malformed OTP URI parameter",
            Self::InvalidAlgorithm => "unsupported OTP algorithm",
            Self::InvalidDigits => "OTP digits must be 6 or 8",
            Self::InvalidPeriod => "invalid OTP period",
            Self::InvalidCounter => "invalid HOTP counter",
            Self::ContradictoryIssuer => "OTP issuer prefix and parameter disagree",
            Self::UnexpectedParameter => "OTP URI parameter is not valid for this type",
        })
    }
}

impl std::error::Error for UriError {}

/// Parsed `otpauth://` entry.
///
/// The secret is zeroized on drop and redacted from `Debug`; comparison of two
/// URIs compares secrets in constant time.
pub struct OtpUri {
    otp_type: OtpType,
    algorithm: Algorithm,
    digits: Digits,
    period: u32,
    counter: u64,
    secret: Zeroizing<Vec<u8>>,
    issuer: String,
    account: String,
}

impl OtpUri {
    /// Creates a validated TOTP URI value.
    pub fn totp(
        secret: Vec<u8>,
        issuer: String,
        account: String,
        algorithm: Algorithm,
        digits: Digits,
        period: u32,
    ) -> Result<Self, UriError> {
        let uri = Self {
            otp_type: OtpType::Totp,
            algorithm,
            digits,
            period,
            counter: 0,
            secret: Zeroizing::new(secret),
            issuer,
            account,
        };
        uri.to_uri()?;
        Ok(uri)
    }

    /// Creates a validated HOTP URI value.
    pub fn hotp(
        secret: Vec<u8>,
        issuer: String,
        account: String,
        algorithm: Algorithm,
        digits: Digits,
        counter: u64,
    ) -> Result<Self, UriError> {
        let uri = Self {
            otp_type: OtpType::Hotp,
            algorithm,
            digits,
            period: 0,
            counter,
            secret: Zeroizing::new(secret),
            issuer,
            account,
        };
        uri.to_uri()?;
        Ok(uri)
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

    /// Issuer label; may be empty.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Account label; never empty.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Renders the canonical `otpauth://` URI.
    ///
    /// Defaults are omitted (SHA1, 6 digits, period 30), the secret is uppercase
    /// Base32 without padding, and all non-unreserved label bytes are
    /// percent-encoded.
    pub fn to_uri(&self) -> Result<String, UriError> {
        self.validate()?;

        let mut out = String::with_capacity(128);
        out.push_str(SCHEME);
        out.push_str(self.otp_type.as_str());
        out.push('/');
        if !self.issuer.is_empty() {
            percent_encode_into(&self.issuer, &mut out);
            out.push(':');
        }
        percent_encode_into(&self.account, &mut out);
        out.push_str("?secret=");
        base32_encode_into(&self.secret, &mut out);
        if !self.issuer.is_empty() {
            out.push_str("&issuer=");
            percent_encode_into(&self.issuer, &mut out);
        }
        if self.algorithm != Algorithm::Sha1 {
            out.push_str("&algorithm=");
            out.push_str(self.algorithm.as_str());
        }
        if self.digits != Digits::Six {
            out.push_str("&digits=");
            out.push_str(match self.digits {
                Digits::Six => "6",
                Digits::Eight => "8",
            });
        }
        match self.otp_type {
            OtpType::Totp => {
                if self.period != DEFAULT_PERIOD_SECONDS {
                    out.push_str("&period=");
                    out.push_str(&self.period.to_string());
                }
            }
            OtpType::Hotp => {
                out.push_str("&counter=");
                out.push_str(&self.counter.to_string());
            }
        }
        if out.len() > MAX_URI_BYTES {
            return Err(UriError::TooLong);
        }
        Ok(out)
    }

    /// Parses and validates a strict `otpauth://` URI.
    pub fn parse(uri: &str) -> Result<Self, UriError> {
        let bytes = uri.as_bytes();
        if bytes.is_empty() {
            return Err(UriError::Empty);
        }
        if bytes.len() > MAX_URI_BYTES {
            return Err(UriError::TooLong);
        }
        for &byte in bytes {
            if byte == b'#' {
                return Err(UriError::InvalidCharacter);
            }
            if byte >= 0x80 || byte == b' ' {
                return Err(UriError::InvalidCharacter);
            }
            if byte < 0x20 || byte == 0x7f {
                return Err(UriError::ControlCharacter);
            }
        }

        let rest = match uri.get(..SCHEME.len()) {
            Some(prefix) if prefix.eq_ignore_ascii_case(SCHEME) => &uri[SCHEME.len()..],
            _ => return Err(UriError::InvalidScheme),
        };
        let (type_part, after_type) = rest.split_once('/').ok_or(UriError::InvalidType)?;
        if after_type.is_empty() {
            return Err(UriError::InvalidLabel);
        }
        let otp_type = parse_type(type_part)?;

        let (label_raw, query_raw) = match after_type.split_once('?') {
            Some((label, query)) => (label, Some(query)),
            None => (after_type, None),
        };
        if label_raw.is_empty() || label_raw.contains('/') {
            return Err(UriError::InvalidLabel);
        }
        let (label_issuer, account) = parse_label(label_raw)?;

        let mut seen = [false; 6];
        let mut secret: Option<Zeroizing<Vec<u8>>> = None;
        let mut issuer_param: Option<String> = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = Digits::Six;
        let mut period: Option<u32> = None;
        let mut counter: Option<u64> = None;

        if let Some(query) = query_raw {
            if query.is_empty() {
                return Err(UriError::InvalidParameter);
            }
            for item in query.split('&') {
                if item.is_empty() {
                    return Err(UriError::InvalidParameter);
                }
                let (key_raw, value_raw) =
                    item.split_once('=').ok_or(UriError::InvalidParameter)?;
                if key_raw.is_empty() {
                    return Err(UriError::InvalidParameter);
                }
                let index = parameter_index(key_raw);
                let index = match index {
                    Some(index) => index,
                    None => return Err(UriError::UnknownParameter),
                };
                if seen[index] {
                    return Err(UriError::DuplicateParameter);
                }
                seen[index] = true;

                let value = percent_decode(value_raw.as_bytes())?;

                match index {
                    0 => {
                        let decoded = base32_decode(&value)?;
                        if decoded.is_empty() || decoded.len() > MAX_SECRET_BYTES {
                            return Err(UriError::InvalidSecret);
                        }
                        secret = Some(Zeroizing::new(decoded));
                    }
                    1 => {
                        let decoded = decode_text(&value, UriError::InvalidIssuer)?;
                        if decoded.is_empty() {
                            return Err(UriError::InvalidIssuer);
                        }
                        if decoded.len() > MAX_LABEL_BYTES {
                            return Err(UriError::InvalidIssuer);
                        }
                        issuer_param = Some(decoded);
                    }
                    2 => algorithm = parse_algorithm(&value)?,
                    3 => digits = parse_digits(&value)?,
                    4 => {
                        if otp_type == OtpType::Hotp {
                            return Err(UriError::UnexpectedParameter);
                        }
                        let parsed = parse_decimal_u32(&value, UriError::InvalidPeriod)?;
                        if !(MIN_PERIOD_SECONDS..=MAX_PERIOD_SECONDS).contains(&parsed) {
                            return Err(UriError::InvalidPeriod);
                        }
                        period = Some(parsed);
                    }
                    5 => {
                        if otp_type == OtpType::Totp {
                            return Err(UriError::UnexpectedParameter);
                        }
                        counter = Some(parse_decimal_u64(&value, UriError::InvalidCounter)?);
                    }
                    _ => return Err(UriError::UnknownParameter),
                }
            }
        }

        let secret = secret.ok_or(UriError::MissingSecret)?;
        let issuer = match (label_issuer, issuer_param) {
            (Some(label), Some(param)) if label != param => {
                return Err(UriError::ContradictoryIssuer);
            }
            (Some(label), _) => label,
            (None, Some(param)) => param,
            (None, None) => String::new(),
        };

        let (period, counter) = match otp_type {
            OtpType::Totp => (period.unwrap_or(DEFAULT_PERIOD_SECONDS), 0),
            OtpType::Hotp => (0, counter.ok_or(UriError::MissingCounter)?),
        };

        let parsed = Self {
            otp_type,
            algorithm,
            digits,
            period,
            counter,
            secret,
            issuer,
            account,
        };
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), UriError> {
        if self.secret.is_empty() || self.secret.len() > MAX_SECRET_BYTES {
            return Err(UriError::InvalidSecret);
        }
        if self.issuer.len() > MAX_LABEL_BYTES || self.issuer.chars().any(char::is_control) {
            return Err(UriError::InvalidIssuer);
        }
        if self.account.is_empty()
            || self.account.len() > MAX_LABEL_BYTES
            || self.account.chars().any(char::is_control)
        {
            return Err(UriError::InvalidAccount);
        }
        match self.otp_type {
            OtpType::Totp => {
                if !(MIN_PERIOD_SECONDS..=MAX_PERIOD_SECONDS).contains(&self.period)
                    || self.counter != 0
                {
                    return Err(UriError::InvalidPeriod);
                }
            }
            OtpType::Hotp => {
                if self.period != 0 {
                    return Err(UriError::InvalidPeriod);
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for OtpUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpUri")
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

impl PartialEq for OtpUri {
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

impl Eq for OtpUri {}

fn parse_type(value: &str) -> Result<OtpType, UriError> {
    if value.eq_ignore_ascii_case("totp") {
        Ok(OtpType::Totp)
    } else if value.eq_ignore_ascii_case("hotp") {
        Ok(OtpType::Hotp)
    } else {
        Err(UriError::InvalidType)
    }
}

fn parameter_index(key: &str) -> Option<usize> {
    if key.eq_ignore_ascii_case("secret") {
        Some(0)
    } else if key.eq_ignore_ascii_case("issuer") {
        Some(1)
    } else if key.eq_ignore_ascii_case("algorithm") {
        Some(2)
    } else if key.eq_ignore_ascii_case("digits") {
        Some(3)
    } else if key.eq_ignore_ascii_case("period") {
        Some(4)
    } else if key.eq_ignore_ascii_case("counter") {
        Some(5)
    } else {
        None
    }
}

fn parse_label(raw: &str) -> Result<(Option<String>, String), UriError> {
    let (issuer_raw, account_raw) = match raw.split_once(':') {
        Some((issuer, account)) => {
            if issuer.is_empty() || account.is_empty() || account.contains(':') {
                return Err(UriError::InvalidLabel);
            }
            (Some(issuer), account)
        }
        None => (None, raw),
    };

    let issuer = match issuer_raw {
        Some(raw) => {
            let decoded = percent_decode(raw.as_bytes())?;
            let decoded = decode_text(&decoded, UriError::InvalidUtf8)?;
            if decoded.is_empty() {
                return Err(UriError::InvalidIssuer);
            }
            if decoded.len() > MAX_LABEL_BYTES {
                return Err(UriError::InvalidIssuer);
            }
            Some(decoded)
        }
        None => None,
    };

    let decoded = percent_decode(account_raw.as_bytes())?;
    let account = decode_text(&decoded, UriError::InvalidUtf8)?;
    if account.is_empty() {
        return Err(UriError::InvalidAccount);
    }
    if account.len() > MAX_LABEL_BYTES {
        return Err(UriError::InvalidAccount);
    }

    Ok((issuer, account))
}

fn decode_text(bytes: &[u8], utf8_error: UriError) -> Result<String, UriError> {
    let text = std::str::from_utf8(bytes).map_err(|_| utf8_error)?;
    if text.chars().any(char::is_control) {
        return Err(UriError::ControlCharacter);
    }
    Ok(text.to_owned())
}

fn percent_decode(input: &[u8]) -> Result<Vec<u8>, UriError> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        let byte = input[index];
        if byte == b'%' {
            if index + 2 >= input.len() {
                return Err(UriError::InvalidEscape);
            }
            let high = hex_value(input[index + 1]).ok_or(UriError::InvalidEscape)?;
            let low = hex_value(input[index + 2]).ok_or(UriError::InvalidEscape)?;
            let decoded = (high << 4) | low;
            if decoded < 0x20 || decoded == 0x7f {
                return Err(UriError::ControlCharacter);
            }
            out.push(decoded);
            index += 3;
        } else {
            if byte < 0x20 || byte == 0x7f {
                return Err(UriError::ControlCharacter);
            }
            if byte >= 0x80 {
                return Err(UriError::InvalidCharacter);
            }
            out.push(byte);
            index += 1;
        }
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_algorithm(value: &[u8]) -> Result<Algorithm, UriError> {
    if value.eq_ignore_ascii_case(b"SHA1") {
        Ok(Algorithm::Sha1)
    } else if value.eq_ignore_ascii_case(b"SHA256") {
        Ok(Algorithm::Sha256)
    } else if value.eq_ignore_ascii_case(b"SHA512") {
        Ok(Algorithm::Sha512)
    } else {
        Err(UriError::InvalidAlgorithm)
    }
}

fn parse_digits(value: &[u8]) -> Result<Digits, UriError> {
    match value {
        b"6" => Ok(Digits::Six),
        b"8" => Ok(Digits::Eight),
        _ => Err(UriError::InvalidDigits),
    }
}

fn parse_decimal_u32(value: &[u8], error: UriError) -> Result<u32, UriError> {
    if value.is_empty() || (value.len() > 1 && value[0] == b'0') {
        return Err(error);
    }
    let mut parsed: u32 = 0;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return Err(error);
        }
        parsed = parsed
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(byte - b'0')))
            .ok_or(error)?;
    }
    Ok(parsed)
}

fn parse_decimal_u64(value: &[u8], error: UriError) -> Result<u64, UriError> {
    if value.is_empty() || (value.len() > 1 && value[0] == b'0') {
        return Err(error);
    }
    let mut parsed: u64 = 0;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return Err(error);
        }
        parsed = parsed
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(byte - b'0')))
            .ok_or(error)?;
    }
    Ok(parsed)
}

fn base32_decode(input: &[u8]) -> Result<Vec<u8>, UriError> {
    let mut data_len = input.len();
    let mut padding = 0;
    while data_len > 0 && input[data_len - 1] == b'=' {
        data_len -= 1;
        padding += 1;
    }
    if data_len == 0 {
        return Err(UriError::InvalidSecret);
    }
    let data = &input[..data_len];
    let remainder = data.len() % 8;

    if padding == 0 {
        if !matches!(remainder, 0 | 2 | 4 | 5 | 7) {
            return Err(UriError::InvalidSecret);
        }
    } else {
        if padding > 6 || !input.len().is_multiple_of(8) {
            return Err(UriError::InvalidSecret);
        }
        let expected = match remainder {
            0 => 0,
            2 => 6,
            4 => 4,
            5 => 3,
            7 => 1,
            _ => return Err(UriError::InvalidSecret),
        };
        if padding != expected {
            return Err(UriError::InvalidSecret);
        }
    }

    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(UriError::InvalidSecret),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1_u32 << bits) - 1;
        }
    }
    if bits > 0 && buffer != 0 {
        return Err(UriError::InvalidSecret);
    }
    Ok(out)
}

fn base32_encode_into(bytes: &[u8], out: &mut String) {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1_u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
}

fn percent_encode_into(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[usize::from(byte >> 4)] as char);
                out.push(HEX[usize::from(byte & 0x0f)] as char);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"Hello!\xde\xad\xbe\xef";
    const BASE32: &str = "JBSWY3DPEHPK3PXP";

    #[test]
    fn parses_minimal_totp() {
        let uri = OtpUri::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").expect("valid URI");
        assert_eq!(uri.otp_type(), OtpType::Totp);
        assert_eq!(uri.algorithm(), Algorithm::Sha1);
        assert_eq!(uri.digits(), Digits::Six);
        assert_eq!(uri.period(), 30);
        assert_eq!(uri.counter(), 0);
        assert_eq!(uri.secret(), SECRET);
        assert_eq!(uri.issuer(), "");
        assert_eq!(uri.account(), "alice");
        assert_eq!(
            uri.to_uri().expect("render"),
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn parses_and_normalizes_full_uri() {
        let uri = OtpUri::parse(
            "otpauth://TOTP/Example:alice?SECRET=jbswy3dpehpk3pxp&ISSUER=Example\
             &ALGORITHM=sha512&DIGITS=8&PERIOD=60",
        )
        .expect("valid URI");
        assert_eq!(uri.algorithm(), Algorithm::Sha512);
        assert_eq!(uri.digits(), Digits::Eight);
        assert_eq!(uri.period(), 60);
        assert_eq!(
            uri.to_uri().expect("render"),
            "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\
             &algorithm=SHA512&digits=8&period=60"
        );
    }

    #[test]
    fn parses_hotp_with_counter() {
        let uri = OtpUri::parse(
            "otpauth://hotp/Example:bob?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=42",
        )
        .expect("valid URI");
        assert_eq!(uri.otp_type(), OtpType::Hotp);
        assert_eq!(uri.period(), 0);
        assert_eq!(uri.counter(), 42);
        assert_eq!(uri.account(), "bob");
    }

    #[test]
    fn padding_and_case_are_normalized() {
        let uri = OtpUri::parse("otpauth://totp/foo?secret=mzxw6%3d%3d%3d").expect("valid URI");
        assert_eq!(uri.secret(), b"foo");
        assert_eq!(
            uri.to_uri().expect("render"),
            "otpauth://totp/foo?secret=MZXW6"
        );
    }

    #[test]
    fn rejects_malformed_input_without_echoing_it() {
        let secret = "JBSWY3DPEHPK3PXP";
        let cases = [
            ("", UriError::Empty),
            (
                "https://totp/a?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidScheme,
            ),
            (
                "otpauth:/totp/a?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidScheme,
            ),
            (
                "otpauth://motp/a?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidType,
            ),
            (
                "otpauth://totp?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidType,
            ),
            (
                "otpauth://totp/?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidLabel,
            ),
            (
                "otpauth://totp/a/b?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidLabel,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP#x",
                UriError::InvalidCharacter,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&image=x",
                UriError::UnknownParameter,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP",
                UriError::DuplicateParameter,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=7",
                UriError::InvalidDigits,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
                UriError::InvalidAlgorithm,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0",
                UriError::InvalidPeriod,
            ),
            (
                "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP",
                UriError::MissingCounter,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&counter=1",
                UriError::UnexpectedParameter,
            ),
            (
                "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=1&period=30",
                UriError::UnexpectedParameter,
            ),
            (
                "otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP&issuer=B",
                UriError::ContradictoryIssuer,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP%00",
                UriError::ControlCharacter,
            ),
            (
                "otpauth://totp/a%ff?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidUtf8,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP%",
                UriError::InvalidEscape,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=%00",
                UriError::ControlCharacter,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=",
                UriError::InvalidIssuer,
            ),
            (
                "otpauth://totp/:a?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidLabel,
            ),
            (
                "otpauth://totp/A:b:c?secret=JBSWY3DPEHPK3PXP",
                UriError::InvalidLabel,
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&",
                UriError::InvalidParameter,
            ),
            ("otpauth://totp/a?secret", UriError::InvalidParameter),
        ];
        for (input, expected) in cases {
            let error = OtpUri::parse(input).expect_err(input);
            assert_eq!(error, expected, "input {input:?}");
            assert!(!error.to_string().contains(secret));
            assert!(!format!("{error:?}").contains(secret));
        }
    }

    #[test]
    fn debug_redacts_labels_and_secret() {
        let uri = OtpUri::parse(&format!(
            "otpauth://totp/Example:alice?secret={BASE32}&issuer=Example"
        ))
        .expect("valid URI");
        let rendered = format!("{uri:?}");
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("Example"));
        assert!(!rendered.contains(BASE32));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn label_limits_and_control_characters() {
        assert!(OtpUri::totp(
            SECRET.to_vec(),
            "i".repeat(MAX_LABEL_BYTES),
            "a".repeat(MAX_LABEL_BYTES),
            Algorithm::Sha1,
            Digits::Six,
            30
        )
        .is_ok());
        assert_eq!(
            OtpUri::totp(
                SECRET.to_vec(),
                "i".repeat(MAX_LABEL_BYTES + 1),
                "a".to_owned(),
                Algorithm::Sha1,
                Digits::Six,
                30
            ),
            Err(UriError::InvalidIssuer)
        );
        assert_eq!(
            OtpUri::totp(
                SECRET.to_vec(),
                String::new(),
                "a".repeat(MAX_LABEL_BYTES + 1),
                Algorithm::Sha1,
                Digits::Six,
                30
            ),
            Err(UriError::InvalidAccount)
        );
        assert_eq!(
            OtpUri::totp(
                SECRET.to_vec(),
                String::new(),
                "a\nb".to_owned(),
                Algorithm::Sha1,
                Digits::Six,
                30
            ),
            Err(UriError::InvalidAccount)
        );
    }

    #[test]
    fn secret_and_period_bounds() {
        assert_eq!(
            OtpUri::totp(
                Vec::new(),
                String::new(),
                "a".to_owned(),
                Algorithm::Sha1,
                Digits::Six,
                30
            ),
            Err(UriError::InvalidSecret)
        );
        assert_eq!(
            OtpUri::totp(
                vec![0; MAX_SECRET_BYTES + 1],
                String::new(),
                "a".to_owned(),
                Algorithm::Sha1,
                Digits::Six,
                30
            ),
            Err(UriError::InvalidSecret)
        );
        assert_eq!(
            OtpUri::totp(
                SECRET.to_vec(),
                String::new(),
                "a".to_owned(),
                Algorithm::Sha1,
                Digits::Six,
                MAX_PERIOD_SECONDS + 1
            ),
            Err(UriError::InvalidPeriod)
        );
    }
}
