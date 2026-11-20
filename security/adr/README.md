# Architecture Decision Records

Каталог ADR проекта. Нумерация соответствует [TODO.md](../../TODO.md); при расхождении с inline-заголовками в [PLAN.md](../../PLAN.md) приоритет имеет этот индекс.

| ADR | Тема | Статус | Файл |
| --- | --- | --- | --- |
| ADR-001 | Независимость desktop/verifier, Rust-first, RFC 4226/6238, модель ответственности | Accepted v0.1 | [0001-independence.md](0001-independence.md) |
| ADR-002 | GUI framework (egui/eframe vs Slint) после dependency/license/offline audit | Open | `0002-gui.md` (планируется) |
| ADR-003 | RustCrypto crates, AEAD, Argon2id, key envelope | Accepted v1.0 | [0003-crypto.md](0003-crypto.md) |
| ADR-004 | Формат vault v1, limits, recovery | Accepted v1.0 | [0004-vault.md](0004-vault.md) |
| ADR-005 | Контракт Go verifier: mTLS/service identity, tenant resolution, session binding, replay, идемпотентность, схема и миграции | Proposed v0.1 | [0005-verifier.md](0005-verifier.md) |
| ADR-006 | Recovery codes и managed factor reset: формат, хранение, погашение, reset-authorization, dual control | Proposed v0.1 | [0006-recovery.md](0006-recovery.md) |

## Правила

- Один ADR — одно архитектурное решение; изменения оформляются новым ADR или новой версией с changelog.
- Security-sensitive ADR требуют явного раздела trust boundaries и негативных сценариев.
- ADR не заменяет TODO: «Accepted» означает решение, а не реализацию и не production readiness.
- Ссылки на внешние документы и тесты обязательны; непроверенные утверждения помечаются.
