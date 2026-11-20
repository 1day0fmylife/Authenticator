# Authenticator

**Статус:** architecture bootstrap / draft v0.6. Документация и security policy опубликованы. Реализованы **Go и Rust OTP core** (RFC 4226/6238) с общими векторами; vault v1 зафиксирован ([ADR-004](security/adr/0004-vault.md)) и реализован на уровне **format/crypto, in-memory сессии и atomic persistence для Linux** (VAULT-001…005; persistence и backup/restore пока проверены только на Linux); Windows-durability и восстановление на другой ОС ещё не проверены. GUI и HTTP API verifier ещё не реализованы.

Authenticator — независимая open-source платформа второго фактора:

- **Desktop Authenticator (P0)** — приложение для **Windows и Ubuntu**: локальная генерация TOTP/HOTP, зашифрованное переносимое хранилище, offline-first. **Rust-first**, GUI выбирается после security/dependency review.
- **MFA Verifier (P0)** — независимый **Go** сервис проверки второго фактора для FastAPI/Go и любых других backend, через HTTPS/OpenAPI + PostgreSQL.
- **Мобильные клиенты (P3)** — **очень низкий приоритет**; только после стабильных релизов desktop и verifier.

Проект не является форком Ente; **не зависит от конкретного IAM, Authenticator, облачного сервиса или GUI-фреймворка.**

## Цели безопасности

1. **Минимальная TCB и supply chain:** меньше зависимостей, build scripts, привилегий, runtime-компонентов и непрозрачных сторонних поставщиков.
2. **Нативный Rust desktop без браузерного runtime**, с независимыми crates для OTP, зашифрованного vault, бизнес-логики и интерфейса.
3. **Обязательный офлайн-режим:** desktop не требует сервера, интернета, аккаунта, облачной синхронизации или push.
4. **Открытая совместимость:** RFC 4226 (HOTP), RFC 6238 (TOTP), `otpauth://`; генератор работает со сторонними сервисами; verifier принимает коды из сторонних приложений.
5. **Независимое восстановление:** открытый версионированный формат vault, password-backed зашифрованный backup, отсутствие обязательного Keyring.
6. **Безопасное серверное MFA:** service authentication, многоарендность, replay protection, challenge/session binding, ограничение попыток, аудит без раскрытия секретов.
7. **Проверяемые релизы:** pinned toolchains и lockfiles, SBOM, vendor/offline build, code review, независимые signatures и security tests.

## Стек

| Направление | Основной стек | Приоритет |
| --- | --- | --- |
| Desktop OTP, vault и application logic | **Rust stable**; отдельные crates в одном workspace | **P0** |
| Desktop GUI | Rust-native: **egui/eframe** или **Slint**; выбор после измерения dependency graph/лицензий/сборки | **P0**, ADR открыт |
| Desktop storage | Один версионированный AEAD-encrypted vault-файл, без обязательной SQLite — [ADR-004](security/adr/0004-vault.md) | **P0**, реализация не начата |
| Desktop crypto | RustCrypto crates, Argon2id, XChaCha20-Poly1305 — [ADR-003](security/adr/0003-crypto.md) | **P0**, формат vault — ADR-004 |
| Сервер verifier | **Go**, стандартный `net/http` + `crypto/*` | **P0** |
| БД сервера | PostgreSQL с одним закреплённым драйвером, SQL migrations | **P0** |
| Интеграции | HTTPS/JSON, OpenAPI; примеры FastAPI и Go | P1 |
| QR, OS unlock, WebAuthn, E2EE sync | Дополнительные функции только по ADR | P2 |
| Android / iOS | Не разрабатывать до стабилизации core/backend | **P3** |

**Почему не C++/Qt по умолчанию?** Rust позволяет держать криптографию и бизнес-логику в едином safe-Rust ядре без обязательной C++ ABI. Однако Rust не гарантирует малую supply chain: GUI-кандидаты и криптографические crates будут отдельно измерены. До окончания GUI Dependency Gate **никакой UI toolkit не является обязательной зависимостью ядра**.

## Принципиальная схема

```text
 Windows / Ubuntu (local, offline)
 +----------------------------------+
 | Rust Desktop Authenticator       |
 | OTP Core (HOTP/TOTP)             |
 | Encrypted Vault + backup         |
 | App use cases / Rust-native GUI  |
 +------------------+---------------+
                    |
          стандартный TOTP-код
                    |
                    v
             [Пользователь]
                    |
                    v
 +----------------------------------+
 | Backend приложения (FastAPI/Go)  |
 | primary login + session control  |
 +------------------+---------------+
                    |
          trusted server-to-server
                    v
 +----------------------------------+
 | Go MFA Verifier                   |
 | enrollment, challenge, verify     |
 | tenant isolation, replay guard   |
 +------------------+---------------+
                    |
                    v
          PostgreSQL + encrypted
          server-side MFA seeds
```

**Важное разделение:** десктопный vault **не синхронизируется через MFA verifier**; verifier хранит только секреты, необходимые для проверки кодов пользователей, зарегистрировавших MFA в интегрированных сервисах. Корректный TOTP-клиент и корректный MFA-verifier полностью взаимозаменяемы со стандартными альтернативами.

## Граница безопасности

- Desktop vault защищается AEAD, парольной Argon2id KDF и безопасным процессом записи/восстановления. Парольный/PIN UX не должен обходить криптографическую защиту. Системные DPAPI/Secret Service — только необязательная оптимизация позднее.
- MFA verifier принимает запросы только от доверенных backend-приложений. Проект/tenant определяется из **service identity**, а не из браузерного запроса. Успешная MFA-проверка возвращает backend решение, но не создаёт primary session сама.
- На backend seed зашифрован отдельным ключом вне БД/контейнерного образа. Принятый TOTP time-step нельзя использовать повторно даже при параллельных запросах.
- Не реализуем собственные криптографические алгоритмы. Не заявляем об абсолютной защите от компрометации ОС или о фишинг-устойчивости TOTP.
- Сетевой сервис, мобильная часть и синхронизация не должны увеличивать TCB локального desktop генератора.

## Структура репозитория

```text
desktop/crates/otp-core/    # Rust core RFC4226/6238 (создан)
desktop/crates/vault/       # создан: v1 format/crypto, сессия, persistence (Linux), fixtures
desktop/crates/app-core/    # domain/use cases (не создан)
desktop/crates/app-cli/     # создан: headless CLI `authenticator-cli` (диагностика/тесты, без вывода секретов)
desktop/crates/app-gui/     # GUI isolated behind interfaces; framework TBD (не создан)
server/                    # Go MFA-verifier: internal/otp, internal/api (skeleton + health), cmd/authenticator-mfa, cmd/verify-vectors
api/                       # OpenAPI (не создан)
tests/vectors/             # shared RFC test fixtures (созданы)
tests/vault/v1/            # synthetic vault v1 fixtures + manifest (созданы)
.github/workflows/         # CI: Rust (ubuntu/windows), Go, native Go fuzzing (создан)
security/                  # threat model, ADR, supply-chain policy, recovery threat model
docs/architecture/         # recovery и managed device lifecycle (proposals)
packaging/                 # Windows/Ubuntu offline releases
README.md  PLAN.md  TODO.md  AGENTS.md  CLAUDE.md  SECURITY.md
```

`desktop/crates/otp-core`, `desktop/crates/vault`, `desktop/crates/app-cli`, `server/internal/otp`, `server/cmd/verify-vectors`, `tests/vectors`, `tests/vault/v1` и `.github/workflows/ci.yml` уже существуют; остальные каталоги с исходным кодом — **план**.

CI ([`ci.yml`](.github/workflows/ci.yml)) фиксирует Rust 1.91.0 из `rust-toolchain.toml` и Go из `go.mod`, пинует actions по commit SHA, работает с `permissions: contents: read` и без секретов. Jobs: Rust fmt/clippy/test/release `--frozen` на Ubuntu, `otp-core` tests + workspace check на Windows, Go fmt/vet/test/race/shared vectors и 30-секундный native Go fuzzing. Rust mutation-fuzz детерминированный (фиксированный seed, без nightly/libFuzzer), поэтому он не заменяет coverage-guided fuzzing; реальные Windows runtime tests для vault остаются в VAULT-003.

## Порядок реализации

1. **M1:** RFC-векторы, Rust/Go OTP core, тестирование URI и API контрактов.
2. **M2:** спецификация vault, format/crypto crate и fixtures (VAULT-001) → persistence, recovery и backup (VAULT-002…005).
3. **M3/M4:** GUI Dependency Gate, Windows/Ubuntu UI; параллельно Go verifier с PostgreSQL.
4. **M5:** интеграция с FastAPI/Go, эксплуатация в офлайн-сети, SBOM, подписи релизов и security review.
5. **M6/M7:** дополнительные механизмы, мобильные приложения только после stable v1.

## Документы и правила

- [PLAN.md](PLAN.md) — архитектура, проектные ADR, threat model, этапы и security gates.
- [TODO.md](TODO.md) — конкретные задачи с критериями приёмки, в порядке зависимостей.
- [AGENTS.md](AGENTS.md) — обязательные правила всех coding agents.
- [CLAUDE.md](CLAUDE.md) — дополнительные инструкции для Claude Code.
- [security/threat-model.md](security/threat-model.md) — активы, акторы, trust boundaries, угрозы и остаточные риски.
- [security/recovery-threat-model.md](security/recovery-threat-model.md) — детализация угроз recovery, backup и managed factor reset.
- [docs/architecture/recovery.md](docs/architecture/recovery.md) — границы восстановления desktop/verifier (proposal).
- [docs/architecture/device-lifecycle.md](docs/architecture/device-lifecycle.md) — managed device/factor lifecycle (proposal).
- [security/supply-chain.md](security/supply-chain.md) — политика зависимостей, toolchain, SBOM и offline build.
- [security/adr/0003-crypto.md](security/adr/0003-crypto.md) — принятые crypto crates, AEAD, Argon2id и ключевой envelope.
- [security/adr/0004-vault.md](security/adr/0004-vault.md) — бинарный формат vault v1, лимиты, atomic write и восстановление.
- [security/adr/0005-verifier.md](security/adr/0005-verifier.md) — контракт Go verifier: mTLS, tenant isolation, enrollment/challenge/verify, replay, ключи и миграции (proposed).
- [security/adr/0006-recovery.md](security/adr/0006-recovery.md) — recovery codes и managed factor reset (proposed).
- [SECURITY.md](SECURITY.md) — как сообщить об уязвимости и политика раскрытия.

**Не начинайте код с установки крупного UI framework или добавления Cloud Sync.** Первый реализуемый срез — независимо проверяемое ядро OTP; формат vault v1 и его fixtures уже реализованы ([ADR-004](security/adr/0004-vault.md), [fixtures](tests/vault/v1/README.md)), in-memory сессия (VAULT-002) и Linux persistence (VAULT-003, частично) готовы; модель ошибок (VAULT-004), backup/export/import/restore для Linux (VAULT-005, частично) и headless `app-cli` (VAULT-006) готовы; дальше — Windows-части VAULT-003/005, затем GUI Dependency Gate и серверный verifier.

## Лицензия

Проект распространяется на условиях **MIT OR Apache-2.0** по выбору получателя: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE). SPDX-выражение задано в `desktop/Cargo.toml` (`workspace.package.license`).

Если явно не указано иное, любой вклад, намеренно отправленный в проект, лицензируется на тех же условиях (MIT OR Apache-2.0) без дополнительных условий.
