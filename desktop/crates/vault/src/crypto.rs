//! XChaCha20-Poly1305 sealing/opening and Argon2id key derivation for vault v1.
//!
//! All randomness comes from the OS CSPRNG. There is no deterministic fallback
//! and no caller-supplied nonce in the production API; fixed salt/nonce is
//! available only to crate tests via `seal_with`.

use argon2::{Algorithm as Argon2Algorithm, Argon2, Block, Params as Argon2Params, Version};
use chacha20poly1305::aead::{Aead, Payload as AeadPayload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use getrandom::fill as fill_random;
use zeroize::Zeroizing;

use crate::error::{VaultError, VaultResult};
use crate::format::{
    Header, KdfParams, Payload, HEADER_LEN, KEY_LEN, MAX_CIPHERTEXT_BYTES, MAX_FILE_BYTES,
    MAX_PASSWORD_BYTES, MIN_FILE_BYTES, MIN_NEW_PASSWORD_BYTES, NONCE_LEN, SALT_LEN, TAG_LEN,
};

pub(crate) fn validate_password(password: &[u8]) -> VaultResult<()> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(VaultError::InvalidInput("password length"));
    }
    Ok(())
}

pub(crate) fn validate_new_password(password: &[u8]) -> VaultResult<()> {
    if password.len() < MIN_NEW_PASSWORD_BYTES || password.len() > MAX_PASSWORD_BYTES {
        return Err(VaultError::InvalidInput("password length"));
    }
    Ok(())
}

pub(crate) fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> VaultResult<Zeroizing<[u8; KEY_LEN]>> {
    let argon_params = Argon2Params::new(
        params.m_cost_kib(),
        params.t_cost(),
        params.p_cost(),
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::ResourceLimit("kdf params"))?;
    let block_count = argon_params.block_count();
    let argon = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, argon_params);

    // `hash_password_into` would allocate and free the password-derived memory
    // blocks without clearing them. Own the blocks so they are zeroized on drop.
    let mut blocks: Zeroizing<Vec<Block>> = Zeroizing::new(vec![Block::default(); block_count]);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon
        .hash_password_into_with_memory(password, salt, &mut key[..], &mut blocks[..])
        .map_err(|_| VaultError::Crypto)?;
    Ok(key)
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key))
}

/// Internal deterministic sealing used by tests and checked-in fixtures.
///
/// Production callers use [`seal_new`], which obtains salt and nonce from the
/// OS CSPRNG. This function is not public outside the crate.
pub(crate) fn seal_with(
    password: &[u8],
    payload: &Payload,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> VaultResult<Vec<u8>> {
    validate_password(password)?;
    params.validate()?;
    let key = derive_key(password, &salt, params)?;
    seal_with_key(&key, payload, params, salt, nonce)
}

/// Encrypts `payload` under an already derived key.
///
/// Callers must pass a nonce never used before with this key: production
/// paths obtain it from [`random_nonce`] immediately before this call.
pub(crate) fn seal_with_key(
    key: &[u8; KEY_LEN],
    payload: &Payload,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> VaultResult<Vec<u8>> {
    params.validate()?;
    let payload_bytes = payload.encode()?;
    let ciphertext_len = payload_bytes
        .len()
        .checked_add(TAG_LEN)
        .ok_or(VaultError::ResourceLimit("ciphertext length"))?;
    if ciphertext_len > MAX_CIPHERTEXT_BYTES {
        return Err(VaultError::ResourceLimit("ciphertext length"));
    }

    let header = Header {
        params,
        salt,
        nonce,
        ciphertext_len: ciphertext_len as u64,
    };
    let header_bytes = header.encode();
    let ciphertext = cipher(key)
        .encrypt(
            XNonce::from_slice(&nonce),
            AeadPayload {
                msg: &payload_bytes[..],
                aad: &header_bytes[..],
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    if ciphertext.len() != ciphertext_len {
        return Err(VaultError::Crypto);
    }

    let mut file = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    file.extend_from_slice(&header_bytes);
    file.extend_from_slice(&ciphertext);
    if file.len() > MAX_FILE_BYTES {
        return Err(VaultError::ResourceLimit("file length"));
    }
    Ok(file)
}

/// Seals a payload into a new v1 file with a fresh salt and nonce.
///
/// The password is used as UTF-8 bytes without normalization. The caller keeps
/// ownership of the password buffer and should zeroize it when possible.
pub fn seal_new(password: &[u8], payload: &Payload, params: KdfParams) -> VaultResult<Vec<u8>> {
    validate_new_password(password)?;
    params.validate()?;
    seal_with(password, payload, params, random_salt()?, random_nonce()?)
}

/// Fresh salt from the OS CSPRNG; failure aborts the operation.
pub(crate) fn random_salt() -> VaultResult<[u8; SALT_LEN]> {
    let mut salt = [0_u8; SALT_LEN];
    fill_random(&mut salt).map_err(|_| VaultError::Random)?;
    Ok(salt)
}

/// Fresh nonce from the OS CSPRNG; failure aborts the operation.
pub(crate) fn random_nonce() -> VaultResult<[u8; NONCE_LEN]> {
    let mut nonce = [0_u8; NONCE_LEN];
    fill_random(&mut nonce).map_err(|_| VaultError::Random)?;
    Ok(nonce)
}

/// Opens and authenticates a v1 file, returning its decrypted payload.
///
/// Wrong password and modified ciphertext are intentionally reported as the
/// same [`VaultError::AuthenticationFailed`] variant.
pub fn open(password: &[u8], file: &[u8]) -> VaultResult<Payload> {
    open_with_key(password, file).map(|opened| opened.payload)
}

/// Result of a successful open: the payload plus the key material needed to
/// re-seal it with a fresh nonce (ADR-004 §7, normal save).
pub(crate) struct Opened {
    pub(crate) payload: Payload,
    pub(crate) key: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) params: KdfParams,
    pub(crate) salt: [u8; SALT_LEN],
}

pub(crate) fn open_with_key(password: &[u8], file: &[u8]) -> VaultResult<Opened> {
    validate_password(password)?;
    if file.len() < MIN_FILE_BYTES {
        return Err(VaultError::Corrupt("truncated file"));
    }
    if file.len() > MAX_FILE_BYTES {
        return Err(VaultError::ResourceLimit("file length"));
    }

    let header = Header::parse(&file[..HEADER_LEN])?;
    let ciphertext_len = usize::try_from(header.ciphertext_len)
        .map_err(|_| VaultError::ResourceLimit("ciphertext length"))?;
    let expected_len = HEADER_LEN
        .checked_add(ciphertext_len)
        .ok_or(VaultError::ResourceLimit("file length"))?;
    if file.len() != expected_len {
        return Err(VaultError::Corrupt("file length mismatch"));
    }

    let key = derive_key(password, &header.salt, header.params)?;
    let plaintext = cipher(&key)
        .decrypt(
            XNonce::from_slice(&header.nonce),
            AeadPayload {
                msg: &file[HEADER_LEN..],
                aad: &file[..HEADER_LEN],
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    let payload = Payload::decode(&plaintext[..])?;
    Ok(Opened {
        payload,
        key,
        params: header.params,
        salt: header.salt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{OtpRecord, MIN_M_COST_KIB, MIN_T_COST};
    use otp_core::{Algorithm, Digits};

    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn params() -> KdfParams {
        KdfParams::new(MIN_M_COST_KIB, MIN_T_COST, 1).expect("test params")
    }

    fn payload() -> Payload {
        let record = OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            30,
            b"12345678901234567890".to_vec(),
            "Example".to_owned(),
            "alice@example.com".to_owned(),
        )
        .expect("valid record");
        Payload::from_records(vec![record]).expect("valid payload")
    }

    fn sealed() -> Vec<u8> {
        seal_with(
            PASSWORD,
            &payload(),
            params(),
            [0x11; SALT_LEN],
            [0x22; NONCE_LEN],
        )
        .expect("seal")
    }

    #[test]
    fn round_trip() {
        let file = sealed();
        let opened = open(PASSWORD, &file).expect("open");
        assert_eq!(opened, payload());
    }

    #[test]
    fn seal_new_uses_fresh_salt_and_nonce() {
        let first = seal_new(PASSWORD, &payload(), params()).expect("first seal");
        let second = seal_new(PASSWORD, &payload(), params()).expect("second seal");
        assert_ne!(first, second);

        let first_header = Header::parse(&first[..HEADER_LEN]).expect("first header");
        let second_header = Header::parse(&second[..HEADER_LEN]).expect("second header");
        assert_ne!(first_header.salt, second_header.salt);
        assert_ne!(first_header.nonce, second_header.nonce);
    }

    #[test]
    fn wrong_password_is_authentication_failure() {
        let file = sealed();
        assert_eq!(
            open(b"wrong password", &file),
            Err(VaultError::AuthenticationFailed)
        );
    }

    #[test]
    fn tampered_ciphertext_is_authentication_failure() {
        let mut file = sealed();
        let last = file.len() - 1;
        file[last] ^= 1;
        assert_eq!(open(PASSWORD, &file), Err(VaultError::AuthenticationFailed));
    }

    #[test]
    fn tampered_header_fields_fail_closed() {
        let mut file = sealed();
        file[28] ^= 1; // salt, authenticated as AAD and used by the KDF
        assert_eq!(open(PASSWORD, &file), Err(VaultError::AuthenticationFailed));

        let mut file = sealed();
        file[44] ^= 1; // nonce, authenticated as AAD
        assert_eq!(open(PASSWORD, &file), Err(VaultError::AuthenticationFailed));

        let mut file = sealed();
        file[10] = 1; // flags: structural rejection before KDF
        assert_eq!(
            open(PASSWORD, &file),
            Err(VaultError::Corrupt("header flags"))
        );
    }

    #[test]
    fn truncated_and_trailing_files_fail() {
        let file = sealed();
        assert_eq!(
            open(PASSWORD, &file[..file.len() - 1]),
            Err(VaultError::Corrupt("file length mismatch"))
        );

        let mut trailing = file;
        trailing.push(0);
        assert_eq!(
            open(PASSWORD, &trailing),
            Err(VaultError::Corrupt("file length mismatch"))
        );
    }

    #[test]
    fn oversized_file_is_rejected_before_parsing() {
        let file = vec![0_u8; MAX_FILE_BYTES + 1];
        assert_eq!(
            open(PASSWORD, &file),
            Err(VaultError::ResourceLimit("file length"))
        );
    }

    #[test]
    fn password_limits() {
        assert_eq!(
            seal_new(&[], &payload(), params()),
            Err(VaultError::InvalidInput("password length"))
        );
        assert_eq!(
            seal_new(&[0_u8; MIN_NEW_PASSWORD_BYTES - 1], &payload(), params()),
            Err(VaultError::InvalidInput("password length"))
        );
        assert!(seal_new(&[0_u8; MIN_NEW_PASSWORD_BYTES], &payload(), params()).is_ok());

        let file = sealed();
        assert_eq!(
            open(&[], &file),
            Err(VaultError::InvalidInput("password length"))
        );
        assert_eq!(
            open(&vec![0_u8; MAX_PASSWORD_BYTES + 1], &file),
            Err(VaultError::InvalidInput("password length"))
        );
    }

    #[test]
    fn kdf_bounds_are_enforced() {
        assert_eq!(
            KdfParams::new(MIN_M_COST_KIB - 1, MIN_T_COST, 1),
            Err(VaultError::ResourceLimit("kdf memory cost"))
        );
        assert_eq!(
            KdfParams::new(MIN_M_COST_KIB, 1, 1),
            Err(VaultError::ResourceLimit("kdf iteration count"))
        );
        assert_eq!(
            KdfParams::new(MIN_M_COST_KIB, MIN_T_COST, 0),
            Err(VaultError::ResourceLimit("kdf parallelism"))
        );
    }

    #[test]
    fn deterministic_seal_matches_for_fixtures() {
        assert_eq!(sealed(), sealed());
    }

    /// Encrypts arbitrary plaintext with a correct header/AAD, bypassing the
    /// payload encoder, to model a buggy or hostile writer that knows the key.
    fn seal_raw(plaintext: &[u8]) -> Vec<u8> {
        let salt = [0x33; SALT_LEN];
        let nonce = [0x44; NONCE_LEN];
        let header = Header {
            params: params(),
            salt,
            nonce,
            ciphertext_len: (plaintext.len() + TAG_LEN) as u64,
        }
        .encode();
        let key = derive_key(PASSWORD, &salt, params()).expect("kdf");
        let ciphertext = cipher(&key)
            .encrypt(
                XNonce::from_slice(&nonce),
                AeadPayload {
                    msg: plaintext,
                    aad: &header[..],
                },
            )
            .expect("encrypt");
        [header.to_vec(), ciphertext].concat()
    }

    #[test]
    fn authenticated_but_invalid_payload_is_corrupt_not_auth_failure() {
        let good = payload().encode().expect("encode");
        assert_eq!(open(PASSWORD, &seal_raw(&good)), Ok(payload()));

        let mut bad_magic = good.to_vec();
        bad_magic[0] = b'X';
        let file = seal_raw(&bad_magic);
        assert_eq!(
            open(PASSWORD, &file),
            Err(VaultError::Corrupt("payload magic"))
        );
        // The same file with a wrong password is indistinguishable from
        // tampering, and distinct from structural corruption.
        assert_eq!(
            open(b"wrong password", &file),
            Err(VaultError::AuthenticationFailed)
        );

        let mut future = good.to_vec();
        future[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            open(PASSWORD, &seal_raw(&future)),
            Err(VaultError::Unsupported("payload version"))
        );

        let mut trailing = good.to_vec();
        trailing.push(0);
        assert_eq!(
            open(PASSWORD, &seal_raw(&trailing)),
            Err(VaultError::Corrupt("payload length mismatch"))
        );

        assert_eq!(
            open(PASSWORD, &seal_raw(&[0_u8; 16])),
            Err(VaultError::Corrupt("payload magic"))
        );
    }

    #[test]
    fn header_version_and_kdf_changes_fail_before_kdf() {
        let mut file = sealed();
        file[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            open(PASSWORD, &file),
            Err(VaultError::Unsupported("envelope version"))
        );

        // A hostile memory cost is refused without running Argon2id.
        let mut file = sealed();
        file[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            open(PASSWORD, &file),
            Err(VaultError::ResourceLimit("kdf memory cost"))
        );

        // In-range but different KDF params change the derived key: the
        // header is authenticated, so this is an authentication failure.
        let mut file = sealed();
        file[16..20].copy_from_slice(&(MIN_T_COST + 1).to_be_bytes());
        assert_eq!(open(PASSWORD, &file), Err(VaultError::AuthenticationFailed));
    }
}
