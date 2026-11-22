# Security review: ADR-005 verifier contract

**Review date:** 22.11.2026
**Subject:** [`security/adr/0005-verifier.md`](../adr/0005-verifier.md) v0.2
**Status:** author-side adversarial review completed. **Not** an independent review; `QA-002` remains required before production.
**Scope:** Go MFA verifier contract: mTLS service identity, tenant resolution, enrollment, challenge/verify, replay, idempotency, rate limits, encryption at rest, key lifecycle, schema/migrations, audit, provisioning.

## 1. Inputs

- [ADR-005](../adr/0005-verifier.md), [ADR-001](../adr/0001-independence.md), [ADR-003](../adr/0003-crypto.md), [ADR-004](../adr/0004-vault.md), [ADR-006](../adr/0006-recovery.md) (proposed).
- [Threat model](../threat-model.md) `T-S1`…`T-S17`, [supply-chain policy](../supply-chain.md).
- [Recovery threat model](../recovery-threat-model.md), [recovery design](../../docs/architecture/recovery.md), [device lifecycle](../../docs/architecture/device-lifecycle.md).

## 2. Method

Adversarial review of trust boundaries and state transitions:

1. tenant and service identity spoofing;
2. OTP/enrollment replay, race conditions and idempotency;
3. challenge/binding lifecycle and enumeration;
4. secret storage, AEAD envelope, key rotation and backup restore;
5. failure modes: DB/key/audit/rate-limit outage, partial transactions;
6. logging, audit, metrics and error leakage;
7. schema constraints, migrations and provisioning;
8. operational assumptions: TLS, clocks, PostgreSQL roles, HA.

## 3. Findings

| ID | Severity | Finding | Resolution in v0.2 | Residual |
| --- | --- | --- | --- | --- |
| F-1 | Critical | Tenant could be taken from request body/query and cause cross-tenant IDOR | Tenant only from authenticated mTLS certificate; `tenant*` fields rejected; composite tenant-bound FKs; cross-tenant tests | RP/service credential compromise still gives its own tenant |
| F-2 | Critical | Same OTP/time-step could be accepted twice, including concurrently | `last_accepted_step` monotonic barrier with row lock and conditional `UPDATE … RETURNING`; challenge state transition in the same transaction | Accepted late-but-valid step is rejected by design |
| F-3 | High | `session_binding` hash in DB could be guessed offline | HMAC-SHA-256 with a separate binding key and tenant binding; separate key ID; no plaintext binding in logs | Compromise of binding key + DB allows guessing weak RP bindings |
| F-4 | High | Key rotation could make backups unreadable or leave old keys uncontrolled | Old AES keys retired/read-only until re-encryption; key retention ≥ backup retention; binding-key overlap ≥ max TTL; startup fail-closed | Operator error remains possible; rotation tests required |
| F-5 | Critical | DB dump plus key material reveals seeds | Seeds only in AES-256-GCM envelope; keys outside DB/image in 0600 file; AAD binds version/key/tenant/subject/record | Host or key-file compromise still exposes plaintext in memory |
| F-6 | Medium | Audit can be modified by a DB-privileged actor | Append-only audit role; no UPDATE/DELETE; external log shipping is a deployment requirement; v1 does not claim hash-chain tamper-proofing | DB superuser/administrator can alter data and external collector if compromised |
| F-7 | Medium | Error codes/timing reveal subject or factor existence | Uniform `403 mfa_denied` body; same status for unknown/foreign enrollment/challenge; dummy work on unknown challenge is best-effort | Timing equalization is not formally proven |
| F-8 | High | Idempotent replay could authorize a different challenge | Key scoped to tenant/service/route; `request_hash` is canonical and includes `challenge_id`; different request → `409` | Stored `allow` is visible to DB readers but cannot be replayed for a new challenge |
| F-9 | High | Enrollment seed/URI can leak through logs, proxies or caches | URI returned once; no body logging; `Cache-Control: no-store` + `Pragma: no-cache`; RP obligations documented | RP or client may still leak it outside verifier |
| F-10 | High | DB connection without server verification enables MITM | `sslmode=verify-full` with CA required in production; least-privilege app/migration/audit roles; schema-qualified SQL | Misconfigured DSN or CA remains an operational risk |
| F-11 | High | Provisioning API could become a second authentication path | No HTTP admin/provisioning API in v1; operator SQL/offline admin only; no default tenant/client/key | Operator with DB access is highly privileged |
| F-12 | Medium | Challenge/rate-limit/DB operations can be used for DoS | Max 5 pending challenges, per-subject/per-client limits, 64 KiB body, timeouts, DB fail-closed | Legitimate load or DB outage still stops MFA by design |
| F-13 | Medium | Clock drift breaks TOTP or widens acceptance | NTP required; ±1 step; drift > period is an incident; server clock authoritative | VM/clock misconfiguration remains operational |
| F-14 | Low | AAD did not cover envelope version/key ID | v0.2 includes `version` and `key_id` in AAD; header tampering fails tag verification | None beyond GCM assumptions |
| F-15 | Medium | Multiple tenants per service client complicates isolation | Exactly one tenant per client/certificate; separate credentials per tenant | More certificates to operate |
| F-16 | Medium | HOTP replay/counter state expands attack surface | HOTP absent from verifier v1; separate ADR required | Desktop HOTP unaffected |
| F-17 | Medium | Audit retention may conflict with privacy/storage | `audit_retention_days` default 365, min 90, max 2555; no automatic deletion before `SRV-009`; no PII in audit | Long retention increases impact of audit-store compromise |
| F-18 | Medium | Token fallback could weaken mTLS | No bearer/token mode in v1; separate ADR only | Environments without client certs cannot integrate yet |
| F-19 | High | TLS session resumption could skip client-certificate/revocation checks | `SessionTicketsDisabled=true`; fingerprint/status checked in DB on every request | Existing HTTP connection still carries traffic until request check; revocation applies on next request |
| F-20 | Medium | Mixing `subject` (lookup ID) with `account` (display label) could store PII or make exact lookup ambiguous | `subject_id` is the opaque RP subject used for lookup/FK/audit; RP must send a stable non-email ID; `account` is only used in `otpauth://` and not stored | RP may still send email as `subject`; DB access and backups remain sensitive |

## 4. Closed decisions

All ten open questions from ADR-005 v0.1 are closed in [§8](../adr/0005-verifier.md#8-решения-по-открытым-вопросам):

1. TTL/limits/lockout;
2. `Idempotency-Key` scope and lifetime;
3. no token mode in v1;
4. local key file v1 and rotation;
5. PostgreSQL driver delegated to `SRV-002` dependency review;
6. no HOTP in verifier v1;
7. audit retention and no hash-chain claim;
8. exactly one tenant per service client;
9. `period` 30/60 and ±1 window;
10. minimal `verify` response without binding hash.

## 5. Verification required before production

- `SRV-002`: schema/migration tests, tenant-bound FK/unique/index checks.
- `SRV-003`: mTLS/certificate/scopes, TLS resumption disabled, revocation on existing connection, cross-tenant negative tests.
- `SRV-004`: enrollment TTL, binding, confirm race, seed redaction.
- `SRV-005`: 100+ concurrent verify, replay/late-step, lockout, idempotency.
- `SRV-006`: AEAD/AAD tamper, key rotation, backup retention, startup fail-closed.
- `SRV-008`: OpenAPI contract tests for §4.8/§4.9.
- `SRV-009`: audit retention and secret-leak grep tests.
- `QA-001`: full negative/race/IDOR/outage matrix.
- `QA-002`: independent security review before any production claim.

## 6. Sign-off

Author-side review complete; findings have resolutions or documented residual risk. This document does **not** constitute an independent security audit, penetration test, or production approval. ADR-005 `Accepted v0.2` means the architecture decision is accepted, not that the implementation is secure or complete.
