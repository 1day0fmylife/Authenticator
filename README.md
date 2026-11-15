# Authenticator

**Статус:** architecture bootstrap / draft v0.4. Документация и security policy опубликованы. Реализованы **Go и Rust OTP core** (RFC 4226/6238) с общими векторами; desktop vault, GUI и HTTP API verifier ещё не реализованы.

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
| Desktop storage | Один версионированный AEAD-encrypted vault-файл, без обязательной SQLite | **P0** |
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
desktop/crates/vault/       # encrypted vault + backups (не создан)
desktop/crates/app-core/    # domain/use cases (не создан)
desktop/crates/app-cli/     # headless test/maintenance tool (не создан)
desktop/crates/app-gui/     # GUI isolated behind interfaces; framework TBD (не создан)
server/                    # Go MFA-verifier; сейчас только internal/otp и cmd/verify-vectors
api/                       # OpenAPI (не создан)
tests/vectors/             # shared RFC test fixtures (созданы)
security/                  # threat model, ADR, supply-chain policy
packaging/                 # Windows/Ubuntu offline releases
README.md  PLAN.md  TODO.md  AGENTS.md  CLAUDE.md  SECURITY.md
```

`desktop/crates/otp-core`, `server/internal/otp`, `server/cmd/verify-vectors` и `tests/vectors` уже существуют; остальные каталоги с исходным кодом — **план**.

## Порядок реализации

1. **M1:** RFC-векторы, Rust/Go OTP core, тестирование URI и API контрактов.
2. **M2:** спецификация vault и Rust crypto/storage, восстановление после ошибок.
3. **M3/M4:** GUI Dependency Gate, Windows/Ubuntu UI; параллельно Go verifier с PostgreSQL.
4. **M5:** интеграция с FastAPI/Go, эксплуатация в офлайн-сети, SBOM, подписи релизов и security review.
5. **M6/M7:** дополнительные механизмы, мобильные приложения только после stable v1.

## Документы и правила

- [PLAN.md](PLAN.md) — архитектура, проектные ADR, threat model, этапы и security gates.
- [TODO.md](TODO.md) — конкретные задачи с критериями приёмки, в порядке зависимостей.
- [AGENTS.md](AGENTS.md) — обязательные правила всех coding agents.
- [CLAUDE.md](CLAUDE.md) — дополнительные инструкции для Claude Code.
- [security/threat-model.md](security/threat-model.md) — активы, акторы, trust boundaries, угрозы и остаточные риски.
- [security/supply-chain.md](security/supply-chain.md) — политика зависимостей, toolchain, SBOM и offline build.
- [security/adr/0003-crypto.md](security/adr/0003-crypto.md) — принятые crypto crates, AEAD, Argon2id и ключевой envelope.
- [SECURITY.md](SECURITY.md) — как сообщить об уязвимости и политика раскрытия.

**Не начинайте код с установки крупного UI framework или добавления Cloud Sync.** Первый реализуемый срез — независимо проверяемое ядро OTP, затем спецификация и реализация vault и серверного verifier.
