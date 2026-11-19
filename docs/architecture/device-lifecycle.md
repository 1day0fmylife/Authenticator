# Managed device and factor lifecycle

Status: proposal v0.1 (2026-11-19). Related: [recovery.md](recovery.md), [recovery threat model](../../security/recovery-threat-model.md), [TODO](../../TODO.md) (`REC-002`/`REC-003`, `SRV-007`).

Distinguish device inventory from TOTP seed enrollment: standard offline TOTP has no cryptographic device identity.

States (managed credentials only): pending → active → revoked; replacement creates a new credential/enrollment rather than reactivating a revoked one.

Operations: enroll with authenticated service-bound challenge; list managed device credentials (never infer unique physical device from TOTP alone); revoke sessions/device credentials; replace factor with fresh seed; notify user; record actor, tenant, reason, time, approval references without secrets.

Enterprise reset: service initiates request → identity verification → optional second approver → short-lived single-use authorization → new factor enrollment → revoke old factor and sessions → notification and audit. Prevent self-approval where dual control is required.

Offline-only personal mode: no remote device registry or remote wipe guarantee. Backup and service-side seed rotation are the recovery path.
