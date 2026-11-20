# Recovery & Device Lifecycle

Status: proposed design (2026-11-19). Scope: offline-first Rust desktop and independent Go MFA verifier. This proposal does not imply implementation.

Related: [recovery threat model](../../security/recovery-threat-model.md), [device lifecycle](device-lifecycle.md), [ADR-003](../../security/adr/0003-crypto.md), [ADR-004](../../security/adr/0004-vault.md), [ADR-005](../../security/adr/0005-verifier.md) (proposed), [TODO](../../TODO.md) (`REC-001`…`REC-003`, `SRV-007`), [ADR-006](../../security/adr/0006-recovery.md) (proposed).

## Recovery boundaries

1. Desktop personal recovery: portable password-encrypted vault backup; no server, cloud, hardware-bound unlock key, or mandatory keyring. Existing vault v1 and ADR-004 remain authoritative; reuse its format/crypto and atomic persistence, do not invent a second incompatible vault format.
2. Service account recovery: verifier-generated one-time recovery codes, securely stored by user, validated by the service; these **do not** reconstruct third-party TOTP seeds.
3. Enterprise factor reset: authenticated application administrators may revoke an enrollment and authorize a fresh one, but never read/export an old TOTP seed. Require independent identity verification, step-up or dual approval according to policy, audit and notifications.
4. Lost-device response: revoke managed sessions and device credentials where applicable, re-enroll managed MFA; for third-party services, user must rotate each seed using that service's recovery process. Revoking a desktop device cannot remotely invalidate a copied offline TOTP secret.

## Recovery scenarios

- Backup available: install client, verify backup authenticity and integrity, unlock using recovery passphrase, import atomically, verify restored entries, rotate potentially exposed seeds.
- No backup, service recovery codes available: redeem single-use codes with throttling and replay prevention, remove compromised enrollment, register a fresh seed.
- Neither: service-owned identity proofing and administrative reset where permitted; no bypass of MFA by simply claiming device loss.
- Offline personal vault with no recovery material: cryptographic recovery is impossible.

## Design constraints

- Password-based backup key derived via Argon2id, AEAD via XChaCha20-Poly1305, CSPRNG nonces and salts; follow existing ADR-003/004 and enforce bounded parameters, authenticated metadata, version and format limits.
- Keep backups independent from source TPM/OS keyring; never log plaintext seed, password, recovery code, or unencrypted export.
- Explicitly distinguish vault backup from verifier database backups and from recovery codes.
- Default no background sync, no cloud escrow, no central plaintext backup.
- Recovery UI must warn that stolen devices may retain valid offline seeds; require service-side re-enrollment for actual revocation.
- Optional multi-device or Shamir recovery only after separate ADR and security review.

## Milestones

P0: recovery threat model; cross-platform backup/restore verification; recovery code lifecycle and verifier API; safe factor replacement and audit.
P1: trusted-device inventory for managed credentials, administrator recovery approval workflow, user notification and policy controls.
P2: independently reviewed threshold recovery and E2EE synchronization.

Acceptance: tests cover Linux↔Windows portability, wrong password, tampering, truncation, rollback policy, crash consistency, single-use code concurrency, race-free enrollment replacement, tenant isolation, rate limiting and audit redaction.
