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

fn validate_password(password: &[u8]) -> VaultResult<()> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(VaultError::InvalidInput("password length"));
    }
    Ok(())
}

fn validate_new_password(password: &[u8]) -> VaultResult<()> {
    if password.len() < MIN_NEW_PASSWORD_BYTES || password.len() > MAX_PASSWORD_BYTES {
        return Err(VaultError::InvalidInput("password length"));
    }
    Ok(())
}

fn derive_key(
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
    let key = derive_key(password, &salt, params)?;
    let ciphertext = cipher(&key)
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

    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    fill_random(&mut salt).map_err(|_| VaultError::Random)?;
    fill_random(&mut nonce).map_err(|_| VaultError::Random)?;
    seal_with(password, payload, params, salt, nonce)
}

/// Opens and authenticates a v1 file, returning its decrypted payload.
///
/// Wrong password and modified ciphertext are intentionally reported as the
/// same [`VaultError::AuthenticationFailed`] variant.
pub fn open(password: &[u8], file: &[u8]) -> VaultResult<Payload> {
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
    Payload::decode(&plaintext[..])
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
}
