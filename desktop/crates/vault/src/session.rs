//! Unlocked vault session: create, unlock, CRUD, re-seal and password change
//! (VAULT-002, ADR-004 §7 and §8.4).
//!
//! This layer works on bytes only. Writing them to disk (temp file, fsync,
//! atomic replace, `.bak`, sidecar lock, `baseline_digest`) is VAULT-003.
//!
//! Key handling:
//!
//! - the password is never stored; only the derived 32-byte key is kept, in a
//!   [`Zeroizing`] buffer that is cleared when the session is locked/dropped;
//! - [`UnlockedVault::seal`] reuses salt/key/KDF params and takes a fresh
//!   nonce from the OS CSPRNG on every call (no nonce reuse on retry);
//! - [`UnlockedVault::change_password`] verifies the current password and
//!   switches to a new salt, key and (optionally upgraded) KDF params.
//!
//! The envelope header carries only public format data (magic, versions, KDF
//! params, salt, nonce, ciphertext length); all records, including issuer and
//! account labels, live inside the single AEAD ciphertext.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::{
    derive_key, open_with_key, random_nonce, random_salt, seal_with_key, validate_new_password,
    validate_password,
};
use crate::error::{VaultError, VaultResult};
use crate::format::{KdfParams, OtpRecord, Payload, KEY_LEN, SALT_LEN};

/// Session-local handle to a record.
///
/// Ids are assigned when a vault is unlocked or a record is added. They are
/// **not** stored in the file and are never reused within one session, so a
/// stale id cannot silently address a different record after a removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordId(u64);

/// A decrypted vault held in memory.
///
/// Not `Clone`: there is exactly one owner of the key material. `Debug` shows
/// only public metadata.
pub struct UnlockedVault {
    key: Zeroizing<[u8; KEY_LEN]>,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    payload: Payload,
    ids: Vec<RecordId>,
    next_id: u64,
}

impl UnlockedVault {
    /// Creates a new empty vault protected by `password` (12…1024 bytes).
    ///
    /// Salt comes from the OS CSPRNG. Use [`KdfParams::default`] in production.
    pub fn create(password: &[u8], params: KdfParams) -> VaultResult<Self> {
        validate_new_password(password)?;
        params.validate()?;
        let salt = random_salt()?;
        let key = derive_key(password, &salt, params)?;
        Ok(Self::from_parts(key, params, salt, Payload::new()))
    }

    /// Authenticates and decrypts an existing v1 file.
    ///
    /// Wrong password and modified ciphertext both yield
    /// [`VaultError::AuthenticationFailed`]. No error creates an empty vault.
    pub fn unlock(password: &[u8], file: &[u8]) -> VaultResult<Self> {
        let opened = open_with_key(password, file)?;
        Ok(Self::from_parts(
            opened.key,
            opened.params,
            opened.salt,
            opened.payload,
        ))
    }

    fn from_parts(
        key: Zeroizing<[u8; KEY_LEN]>,
        params: KdfParams,
        salt: [u8; SALT_LEN],
        payload: Payload,
    ) -> Self {
        let count = payload.len() as u64;
        Self {
            key,
            params,
            salt,
            ids: (0..count).map(RecordId).collect(),
            next_id: count,
            payload,
        }
    }

    /// Encrypts the whole payload into a complete v1 file.
    ///
    /// Every call uses a fresh random nonce; salt, key and KDF params stay the
    /// same (ADR-004 §7, normal save).
    pub fn seal(&self) -> VaultResult<Vec<u8>> {
        seal_with_key(
            &self.key,
            &self.payload,
            self.params,
            self.salt,
            random_nonce()?,
        )
    }

    /// Locks the vault: the key and all decrypted records are zeroized.
    pub fn lock(self) {
        drop(self);
    }

    /// KDF parameters that the next [`seal`](Self::seal) will write.
    pub fn kdf_params(&self) -> KdfParams {
        self.params
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Whether the vault has no records.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Records in user order with their session ids.
    pub fn records(&self) -> impl Iterator<Item = (RecordId, &OtpRecord)> + '_ {
        self.ids.iter().copied().zip(self.payload.records().iter())
    }

    /// Looks up one record.
    pub fn get(&self, id: RecordId) -> Option<&OtpRecord> {
        self.index_of(id)
            .ok()
            .map(|index| &self.payload.records()[index])
    }

    /// Appends a record and returns its new session id.
    pub fn add(&mut self, record: OtpRecord) -> VaultResult<RecordId> {
        let id = RecordId(self.next_id);
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or(VaultError::ResourceLimit("record id"))?;
        self.payload.push(record)?;
        self.ids.push(id);
        self.next_id = next_id;
        Ok(id)
    }

    /// Replaces a record (e.g. edited labels or an advanced HOTP counter).
    pub fn update(&mut self, id: RecordId, record: OtpRecord) -> VaultResult<()> {
        let index = self.index_of(id)?;
        self.payload.replace(index, record)
    }

    /// Removes a record; its secret is zeroized.
    pub fn remove(&mut self, id: RecordId) -> VaultResult<()> {
        let index = self.index_of(id)?;
        self.payload.remove(index)?;
        self.ids.remove(index);
        Ok(())
    }

    fn index_of(&self, id: RecordId) -> VaultResult<usize> {
        self.ids
            .iter()
            .position(|candidate| *candidate == id)
            .ok_or(VaultError::UnknownRecord)
    }

    /// Changes the password and/or upgrades KDF params (ADR-004 §8.4).
    ///
    /// `current` is re-derived with the session salt/params and compared with
    /// the session key in constant time; a mismatch is
    /// [`VaultError::AuthenticationFailed`] and changes nothing. On success
    /// the session switches to a new random salt and a key derived from `new`
    /// with `params`; the next [`seal`](Self::seal) re-encrypts everything.
    /// Passing the same password with stronger params is a KDF upgrade.
    pub fn change_password(
        &mut self,
        current: &[u8],
        new: &[u8],
        params: KdfParams,
    ) -> VaultResult<()> {
        let rekey = self.prepare_rekey(current, new, params)?;
        self.apply_rekey(rekey);
        Ok(())
    }

    /// Verifies `current` and derives new key material without changing the
    /// session. Persistence seals with it first and applies it only after the
    /// new file is in place (ADR-004 §8.4).
    pub(crate) fn prepare_rekey(
        &self,
        current: &[u8],
        new: &[u8],
        params: KdfParams,
    ) -> VaultResult<Rekey> {
        validate_password(current)?;
        validate_new_password(new)?;
        params.validate()?;

        let check = derive_key(current, &self.salt, self.params)?;
        if !bool::from(check[..].ct_eq(&self.key[..])) {
            return Err(VaultError::AuthenticationFailed);
        }

        let salt = random_salt()?;
        let key = derive_key(new, &salt, params)?;
        Ok(Rekey { key, salt, params })
    }

    /// Seals the current payload under prepared key material (fresh nonce).
    pub(crate) fn seal_rekeyed(&self, rekey: &Rekey) -> VaultResult<Vec<u8>> {
        seal_with_key(
            &rekey.key,
            &self.payload,
            rekey.params,
            rekey.salt,
            random_nonce()?,
        )
    }

    /// Switches the session to prepared key material; the old key is zeroized.
    pub(crate) fn apply_rekey(&mut self, rekey: Rekey) {
        self.key = rekey.key;
        self.salt = rekey.salt;
        self.params = rekey.params;
    }
}

/// New key material produced by a verified password change, not yet applied.
pub(crate) struct Rekey {
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("key", &"[redacted]")
            .field("params", &self.params)
            .field("records", &self.payload.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::open;
    use crate::format::{Header, HEADER_LEN, MIN_M_COST_KIB, MIN_P_COST, MIN_T_COST};
    use otp_core::{Algorithm, Digits};

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const NEW_PASSWORD: &[u8] = b"a different test passphrase";
    const SECRET: &[u8] = b"VAULT002-UNIQUE-SECRET-MARKER";
    const ISSUER: &str = "IssuerMarkerVault002";
    const ACCOUNT: &str = "account-marker@vault002.test";

    fn min_params() -> KdfParams {
        KdfParams::new(MIN_M_COST_KIB, MIN_T_COST, MIN_P_COST).expect("min params")
    }

    fn stronger_params() -> KdfParams {
        KdfParams::new(MIN_M_COST_KIB, MIN_T_COST + 1, MIN_P_COST).expect("params")
    }

    fn totp() -> OtpRecord {
        OtpRecord::totp(
            Algorithm::Sha1,
            Digits::Six,
            30,
            SECRET.to_vec(),
            ISSUER.to_owned(),
            ACCOUNT.to_owned(),
        )
        .expect("totp")
    }

    fn hotp(counter: u64) -> OtpRecord {
        OtpRecord::hotp(
            Algorithm::Sha256,
            Digits::Eight,
            counter,
            b"hotp-secret".to_vec(),
            "Example".to_owned(),
            "hotp@example.test".to_owned(),
        )
        .expect("hotp")
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn create_add_seal_unlock_round_trip() {
        let mut vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        assert!(vault.is_empty());
        let a = vault.add(totp()).expect("add totp");
        let b = vault.add(hotp(7)).expect("add hotp");
        assert_ne!(a, b);
        let file = vault.seal().expect("seal");
        vault.lock();

        let reopened = UnlockedVault::unlock(PASSWORD, &file).expect("unlock");
        assert_eq!(reopened.len(), 2);
        let records: Vec<_> = reopened.records().map(|(_, record)| record).collect();
        assert_eq!(records[0], &totp());
        assert_eq!(records[1], &hotp(7));
        assert_eq!(reopened.kdf_params(), min_params());
    }

    #[test]
    fn header_has_no_secrets_or_personal_fields() {
        let mut vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        vault.add(totp()).expect("add");
        let file = vault.seal().expect("seal");

        // Nothing sensitive anywhere in the file, header or ciphertext.
        for needle in [
            SECRET,
            ISSUER.as_bytes(),
            ACCOUNT.as_bytes(),
            PASSWORD,
            &vault.key[..],
        ] {
            assert!(!contains(&file, needle), "plaintext leaked into file");
        }

        // The header decodes to public fields only; the whole payload is the
        // AEAD ciphertext that follows it.
        let header = Header::parse(&file[..HEADER_LEN]).expect("header");
        assert_eq!(header.params, min_params());
        assert_eq!(header.salt, vault.salt);
        assert_eq!(header.ciphertext_len as usize, file.len() - HEADER_LEN);
    }

    #[test]
    fn reseal_keeps_salt_and_uses_fresh_nonce() {
        let mut vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        vault.add(totp()).expect("add");
        let first = vault.seal().expect("first");
        let second = vault.seal().expect("second");
        assert_ne!(first, second);

        let h1 = Header::parse(&first[..HEADER_LEN]).expect("h1");
        let h2 = Header::parse(&second[..HEADER_LEN]).expect("h2");
        assert_eq!(h1.salt, h2.salt);
        assert_eq!(h1.params, h2.params);
        assert_ne!(h1.nonce, h2.nonce);
        assert_eq!(open(PASSWORD, &first), open(PASSWORD, &second));
    }

    #[test]
    fn update_and_remove_by_id() {
        let mut vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        let a = vault.add(totp()).expect("a");
        let b = vault.add(hotp(1)).expect("b");
        let c = vault.add(hotp(2)).expect("c");

        vault.update(b, hotp(100)).expect("update");
        assert_eq!(vault.get(b), Some(&hotp(100)));

        vault.remove(a).expect("remove");
        assert_eq!(vault.get(a), None);
        assert_eq!(vault.remove(a), Err(VaultError::UnknownRecord));
        assert_eq!(vault.update(a, totp()), Err(VaultError::UnknownRecord));
        // Ids of remaining records stay valid after removal.
        assert_eq!(vault.get(c), Some(&hotp(2)));

        // A new record never reuses a removed id.
        let d = vault.add(totp()).expect("d");
        assert!(d != a && d != b && d != c);

        let order: Vec<_> = vault.records().map(|(id, _)| id).collect();
        assert_eq!(order, vec![b, c, d]);

        let reopened =
            UnlockedVault::unlock(PASSWORD, &vault.seal().expect("seal")).expect("unlock");
        let records: Vec<_> = reopened.records().map(|(_, record)| record).collect();
        assert_eq!(records, vec![&hotp(100), &hotp(2), &totp()]);
    }

    #[test]
    fn change_password_reencrypts_with_new_salt() {
        let mut vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        vault.add(totp()).expect("add");
        let before = vault.seal().expect("before");
        let old_salt = vault.salt;

        vault
            .change_password(PASSWORD, NEW_PASSWORD, min_params())
            .expect("change");
        assert_ne!(vault.salt, old_salt);
        let after = vault.seal().expect("after");

        assert_eq!(
            open(PASSWORD, &after),
            Err(VaultError::AuthenticationFailed)
        );
        let reopened = UnlockedVault::unlock(NEW_PASSWORD, &after).expect("unlock new");
        assert_eq!(reopened.get(RecordId(0)), Some(&totp()));
        // An earlier copy stays readable with the old password (documented).
        assert!(open(PASSWORD, &before).is_ok());
    }

    #[test]
    fn change_password_rejects_wrong_current_and_changes_nothing() {
        let mut vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        let salt = vault.salt;
        let key = *vault.key;

        assert_eq!(
            vault.change_password(b"not the password", NEW_PASSWORD, min_params()),
            Err(VaultError::AuthenticationFailed)
        );
        assert_eq!(
            vault.change_password(PASSWORD, b"too short", min_params()),
            Err(VaultError::InvalidInput("password length"))
        );
        assert_eq!(
            vault.change_password(&[], NEW_PASSWORD, min_params()),
            Err(VaultError::InvalidInput("password length"))
        );
        assert_eq!(vault.salt, salt);
        assert_eq!(*vault.key, key);

        let file = vault.seal().expect("seal");
        assert!(UnlockedVault::unlock(PASSWORD, &file).is_ok());
    }

    #[test]
    fn kdf_upgrade_with_same_password() {
        let mut vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        vault
            .change_password(PASSWORD, PASSWORD, stronger_params())
            .expect("upgrade");
        let file = vault.seal().expect("seal");
        let header = Header::parse(&file[..HEADER_LEN]).expect("header");
        assert_eq!(header.params, stronger_params());
        let reopened = UnlockedVault::unlock(PASSWORD, &file).expect("unlock");
        assert_eq!(reopened.kdf_params(), stronger_params());
    }

    #[test]
    fn create_and_unlock_validate_inputs() {
        assert_eq!(
            UnlockedVault::create(b"short", min_params()).map(|_| ()),
            Err(VaultError::InvalidInput("password length"))
        );
        let vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        let file = vault.seal().expect("seal");
        assert_eq!(
            UnlockedVault::unlock(b"wrong password", &file).map(|_| ()),
            Err(VaultError::AuthenticationFailed)
        );
        assert_eq!(
            UnlockedVault::unlock(PASSWORD, &file[..10]).map(|_| ()),
            Err(VaultError::Corrupt("truncated file"))
        );
    }

    #[test]
    fn debug_is_redacted() {
        let mut vault = UnlockedVault::create(PASSWORD, min_params()).expect("create");
        vault.add(totp()).expect("add");
        let text = format!("{vault:?}");
        assert!(text.contains("[redacted]"));
        for needle in [ISSUER, ACCOUNT, "VAULT002"] {
            assert!(!text.contains(needle), "debug leaked {needle:?}");
        }
    }
}
