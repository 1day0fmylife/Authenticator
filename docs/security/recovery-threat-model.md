# Recovery threat model

Status: proposal. Related: security/threat-model.md, security/adr/0003-crypto.md, security/adr/0004-vault.md.

Assets: desktop OTP seeds, backup passphrase, encrypted backup, verifier-side MFA seeds, recovery code verifiers, service identities, admin approvals, audit trail.

Trust boundaries: desktop OS and storage; removable backup media; service backend→Go verifier; tenant isolation; administrator→recovery authorization.

Threats and mitigations:

- Theft of unlocked device: seeds may already be copied. Device revocation is not enough; rotate TOTP seeds at relying services.
- Theft of encrypted backup: offline password guessing. Use Argon2id with documented minimum cost and passphrase guidance; AEAD integrity and bounded resource use.
- Malicious backup import: untrusted file parsing, oversized KDF parameters, decompression or allocation abuse, path traversal. Bound all sizes and use negative/fuzz tests.
- Backup rollback: old valid backups can restore revoked seeds. Document limitations and optionally track versions in managed deployments; do not claim offline rollback prevention.
- Recovery code theft/replay: generate with CSPRNG, show once, store only keyed verifiers/hashes as appropriate, use single-use transactional consumption, throttling, audit, invalidate after factor reset.
- Social-engineering administrator: require independent identity verification, separation of duties for high-assurance tenants, notifications, immutable audit records.
- Cross-tenant reset: derive tenant from authenticated service identity, enforce tenant-scoped authorization on every operation.
- Concurrent recovery: atomic invalidation and new enrollment activation; stale challenges must fail.

Residual risks: compromised endpoint, compromised administrator, stolen backup+passphrase, service-side seed exposure, third-party services beyond verifier control.
