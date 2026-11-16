# TODO.md — бэклог разработки Authenticator

> Все задачи изначально **не выполнены**, кроме опубликования документационной основы. Приоритеты: P0 — блокирует MVP; P1 — стабильность; P2 — расширения; P3 — mobile. Задачи выполняются только после зависимостей и критериев приёмки.

## P0 — документация и границы доверия

- [x] **DOC-001** Создать стартовые README/PLAN/TODO/AGENTS/CLAUDE с Rust-first desktop + Go MFA verifier. **Готово:** ссылки между документами работают, мобильный приоритет явно P3.
- [x] **SEC-001** Опубликовать `security/threat-model.md` (desktop vault, OS, import, server, CI/CD, update). **Готово:** активы, атакующие, границы, допущения, угрозы, меры и остаточные риски описаны. → [`security/threat-model.md`](security/threat-model.md) (v0.1, меры `planned` до появления тестов).
- [x] **SEC-002** Опубликовать `security/supply-chain.md`. **Готово:** budget/allowlist прямых и транзитивных зависимостей, требования к build scripts/proc-macros/unsafe, pinned tools, SBOM, offline ingestion/build, security disclosure. → [`security/supply-chain.md`](security/supply-chain.md), [`SECURITY.md`](SECURITY.md) (бюджет стартовый, зависимости ещё не выбраны).
- [x] **ADR-001** Утвердить независимость desktop и MFA verifier, стандарты RFC4226/6238 и модель ответственности. **Готово:** документирован ADR; отсутствует зависимость desktop от сервера и desktop-specific формата в API. → [`security/adr/0001-independence.md`](security/adr/0001-independence.md).
- [ ] **ADR-002** Выполнить сравнение egui/eframe vs Slint и зафиксировать выбор GUI. **Готово:** измерены обычные/build/dev/native зависимости, размеры бинарников, build scripts, лицензии, Wayland/X11, Windows GUI, backend graphics, accessibility и offline build. GUI не выбран только из эстетических соображений.
- [x] **ADR-003** Выбрать разрешённые RustCrypto crates, AEAD, параметры Argon2id и ключевой envelope. **Готово:** threat model, спецификация, license/dependency assessment и проверенные test vectors. → [`security/adr/0003-crypto.md`](security/adr/0003-crypto.md): XChaCha20-Poly1305, Argon2id 64 MiB/t=3/p=1, границы KDF, envelope, RFC 9106/draft-XChaCha/RFC 4231 векторы; граф 13 пакетов для `otp-core`.
- [x] **ADR-004** Утвердить формат vault v1 и ключевые сценарии восстановления. **Готово:** открытая спецификация с версиями, limits, nonce/AAD, KDF migration, atomic writes, error handling. → [`security/adr/0004-vault.md`](security/adr/0004-vault.md): envelope 80 байт, payload/record v1, лимиты 16 MiB/10 000 записей, AAD, `.bak`/lock/conflict, backup/export/import/restore, error model. Код и fixtures — VAULT-001…005.
- [ ] **ADR-005** Утвердить контракт Go verifier, доверенные сервисные identity, session binding, replay policy и migration scheme. **Готово:** OpenAPI + sequence diagrams + негативные тесты.

## P0 — общий OTP protocol core

- [x] **OTP-001** Подготовить общие публичные RFC 4226 / RFC 6238 векторы в `tests/vectors/`. **Готово:** SHA-1/256/512, временные границы, HOTP counters, 6/8 digits, собственные и независимые проверочные реализации. → 71 вектор в [`tests/vectors/`](tests/vectors/README.md); независимая проверка `cd server && go run ./cmd/verify-vectors` (stdlib Go, Python не используется).
- [x] **OTP-002** Реализовать `desktop/crates/otp-core` на Rust без GUI и сетевых API. **Готово:** проходят RFC vectors и property tests; нет unsafe, кроме отдельно одобренных участков. → [`desktop/crates/otp-core`](desktop/crates/otp-core/src/lib.rs): `#![forbid(unsafe_code)]`, 71 shared vector + property/negative tests; `cargo fmt`, `clippy -D warnings`, `cargo test --locked`, release `--frozen` пройдены.
- [x] **OTP-003** Реализовать независимый Go OTP package на стандартной библиотеке. **Готово:** те же RFC vectors, отсутствие переполнений/ошибок mod/div, тесты window policy и constant-time compare. → [`server/internal/otp`](server/internal/otp/otp.go): 71 shared vector test, границы времени, overflow counter, skew 0…2, constant-time compare; `go test -race ./...` пройден.
- [ ] **OTP-004** Разработать строгий `otpauth://` parser/generator. **Готово:** поддержка issuer/account, URI encoding, digit/period/algorithm/counter, контроль длины, отказ на противоречиях и некорректных полях.
- [ ] **OTP-005** Подключить fuzzing OTP/URI и CI matrix. **Готово:** invalid input не приводит к panic/crash/OOM; проверки запускаются offline.

## P0 — локальный Rust vault

- [x] **VAULT-001** Документировать file format v1 и KDF/AEAD/backup policy до реализации. **Готово:** бинарная спецификация и тестовые зашифрованные образцы формата. → [ADR-004](security/adr/0004-vault.md) + [`desktop/crates/vault`](desktop/crates/vault/src/lib.rs): strict envelope/payload/record v1, Argon2id + XChaCha20-Poly1305, `#![forbid(unsafe_code)]`; 6 синтетических fixtures в [`tests/vault/v1`](tests/vault/v1/README.md) (пустой, TOTP SHA-1/256/512, HOTP, границы лимитов) и conformance/negative тесты. Выполнены `cargo fmt`, `clippy -D warnings`, `cargo test --locked` (24 unit + 6 integration), повторная генерация fixtures побайтово идентична, release `--frozen`. Persistence/CRUD/backup — VAULT-002…005.
- [x] **VAULT-002** Реализовать создание, lock/unlock, CRUD и изменение пароля. **Готово:** корректное шифрование всего payload, нет секретов/персональных полей в заголовке. → [`UnlockedVault`](desktop/crates/vault/src/session.rs): `create`/`unlock`/`lock`, CRUD по session-local `RecordId` (не переиспользуется), `seal` с прежними salt/key и новым nonce, `change_password` (проверка текущего пароля constant-time, новые salt/key, KDF upgrade). Тесты: весь payload в одном AEAD-шифротексте, в файле нет secret/issuer/account/пароля/ключа, заголовок разбирается только в публичные поля; неверный текущий пароль ничего не меняет; redacted `Debug`. `cargo test --locked`: 33 unit + 6 integration. Работа на уровне байтов: запись на диск, `.bak`, lock и `Conflict` — VAULT-003.
- [ ] **VAULT-003** Реализовать write/fsync/atomic replace + crash consistency на Windows и Ubuntu. **Готово:** тесты отключения питания/прерванной записи/permission error/диска без места; предыдущая копия сохраняется.
  - **Частично (Linux):** [`VaultFile`](desktop/crates/vault/src/persist.rs): sidecar lock (`Busy`), `baseline_digest` (`Conflict`), temp + fsync + atomic rename + fsync директории, `.bak` (предыдущая версия; при смене пароля — новый шифротекст), `O_NOFOLLOW`/0600, очистка stale temp, `DurabilityUncertain` → reopen. Тесты на Linux/tmpfs: fault injection на каждом из 7 шагов (ошибка и симулированный crash), permission/read-only, симулированный ENOSPC, symlink/FIFO/каталог, oversize, конфликт, две сессии; 52 unit + 6 integration. **Не сделано:** Windows (write-through, reparse points, ACL) не компилировался и не тестировался; реальные отключения питания и полный диск не проверялись.
- [x] **VAULT-004** Реализовать ограниченную сериализацию/десериализацию, максимальную длину входов, и error model. **Готово:** corrupted/wrong-password/unavailable различаются; ошибка никогда не создаёт пустой vault. → лимиты проверяются и при encode, и при decode (каждая граница ±1: secret, issuer, account, period, `record_count`, `body_len`, файл, пароль, KDF); декодеры не паникуют на всех усечениях, всех однобитных порчах и 20 000 детерминированных случайных входах, а успешный decode канонически перекодируется в те же байты; payload, битый внутри валидного AEAD, даёт `Corrupt`/`Unsupported`, а не `AuthenticationFailed`. [`tests/error_model.rs`](desktop/crates/vault/tests/error_model.rs): `NotFound`/`Corrupt`/`Unsupported`/`AuthenticationFailed`/`ResourceLimit`/`Unavailable`/`Busy`/`Conflict`/`AlreadyExists`/`InvalidInput` различаются, каталог не меняется (кроме пустого `.lock`), тексты ошибок без пароля/secret/account/пути. `cargo test --locked`: 60 unit + 8 + 6 integration. Файловые сценарии проверены только на Linux.
- [ ] **VAULT-005** Реализовать portable encrypted backup/export/import/restore с проверкой целостности. **Готово:** восстановление на другой ОС и обратная совместимость fixture test.
  - **Частично (Linux):** [`VaultFile`](desktop/crates/vault/src/persist.rs) `export_to` (новые salt/key/nonce, без перезаписи, read-back + расшифровка), `copy_to` (побайтовая копия с проверкой SHA-256 и `Conflict`), `import_replace` (полная проверка источника, только replace, откат в памяти), `restore` (новый ключ; target → `.bak`; пропавший/повреждённый target только с `RestoreMode::ReplaceDamagedTarget`; сначала target, потом `.bak`), `verify_file`. Тесты: fault injection restore на 7 шагах (ошибка и crash), отказы без изменений, обратная совместимость всех 6 fixtures v1 ([`backup_compat.rs`](desktop/crates/vault/tests/backup_compat.rs)); 71 unit + 16 integration. **Не сделано:** восстановление на другой ОС (Windows) не проверялось.
- [ ] **VAULT-006** Добавить `app-cli` для headless интеграционных тестов и диагностики, без вывода secrets по умолчанию. **Готово:** проверка vault без запуска GUI.

## P0 — Windows/Ubuntu desktop

- [ ] **GUI-001** Создать 2 throwaway spikes (egui/eframe, Slint) и собрать BOM/dependency comparison. **Готово:** есть ADR-002, источник и версия выбранного GUI зафиксированы.
- [ ] **GUI-002** Реализовать Rust GUI с моделью отображения отдельно от криптографических use cases. **Готово:** создать/открыть/закрыть vault, список, поиск, добавление/удаление, отображение TOTP и явный HOTP advance.
- [ ] **GUI-003** Реализовать auto-lock, clipboard best-effort, protected error UX. **Готово:** заблокированный интерфейс не показывает seed; secret logging отсутствует.
- [ ] **GUI-004** Протестировать Windows 10/11 и актуальные Ubuntu LTS, X11/Wayland, HiDPI, DPI scaling. **Готово:** есть реальная test matrix, а не только CI unit tests.
- [ ] **GUI-005** Определить packaging/update strategy без обязательного remote updater. **Готово:** portable/install package, подписи и офлайн-проверка обновления.

## P0 — серверная часть Go

- [ ] **SRV-001** Создать Go-модуль и `net/http` skeleton с structured errors и health endpoints. **Готово:** dependency graph ограничен stdlib и утвержденным PostgreSQL-драйвером.
- [ ] **SRV-002** Спроектировать PostgreSQL схему, ограничения tenant isolation и миграции. **Готово:** фикстуры и rollback/upgrade тесты проверяют FK, UNIQUE, индексы.
- [ ] **SRV-003** Добавить служебную аутентификацию (mTLS или эквивалент), scopes и tenant resolution. **Готово:** клиент из tenant A не может обратиться к данным tenant B или указать произвольный tenant.
- [ ] **SRV-004** Реализовать TOTP enrollment start/confirm с short TTL и secure seed handling. **Готово:** enrolment невозможно без доверенной сессии backend и подтверждения действительным OTP.
- [ ] **SRV-005** Реализовать challenge/verify с session-binding, atomic used-step/replay barrier, tenant isolation и rate limit в PostgreSQL. **Готово:** конкурентные проверки одного OTP/time-step принимаются не больше одного раза.
- [ ] **SRV-006** Реализовать AEAD encryption-at-rest и key rotation с key IDs. **Готово:** секреты отсутствуют в plaintext DB/log/image; key material поступает извне; migration/rotation tests проходят.
- [ ] **SRV-007** Реализовать безопасные одноразовые recovery codes, disable и re-enrollment. **Готово:** step-up/controlled recovery, атомарное погашение кода, без обхода MFA при ошибке БД.
- [ ] **SRV-008** Сформировать `api/openapi.yaml` и контрактные тесты. **Готово:** доверенная интеграция с FastAPI/Go без привязки к фреймворку.
- [ ] **SRV-009** Добавить privacy-preserving audit, readiness/liveness, basic metrics. **Готово:** нет OTP/seed/паролей/recovery plaintext, high-cardinality private labels исключены.

## P1 — инфраструктура и стабилизация

- [ ] **SUP-001** Pin rustup/Cargo/Go/toolchains и OS build images по digest, закрепить источники. **Готово:** политика toolchain update и CI подписана/зафиксирована.
- [ ] **SUP-002** Vendor Rust/Go dependencies и провести релизную сборку **без сети**. **Готово:** чистая машина собирает из проверенного offline mirror с `cargo --frozen` и Go vendor.
- [ ] **SUP-003** Генерировать SBOM, лицензии, SCA report, provenance, hashes и подписанные артефакты. **Готово:** документы проверяются независимо; ограничения reproducibility указаны честно.
- [ ] **SUP-004** Ввести mandatory dependency/unsafe/build-script review и security updates SLAs. **Готово:** CI обнаруживает неразрешённое изменение графа зависимостей.
- [ ] **INT-001** Пример FastAPI адаптера для двухфазного login + session upgrade. **Готово:** защищён от повторного использования verification result, session fixation и bypass при outage.
- [ ] **INT-002** Пример Go relying party + интеграционные тесты с независимым TOTP-клиентом. **Готово:** пользователю не нужен собственный desktop Authenticator.
- [ ] **QA-001** Полная матрица негативных security tests: replay, brute force, IDOR, race, clock drift, corrupted vault, backup theft, build tampering. **Готово:** релиз блокируется при провале любого критического теста.
- [ ] **QA-002** Независимый security review перед public stable. **Готово:** результаты и исправления оформлены в репозитории (без публикации рабочих секретов/эксплойтов).

## P2 — после релиза

- [ ] **EXT-001** QR import/export после оценки QR-библиотек и экрана/камеры.
- [ ] **EXT-002** Windows DPAPI / Linux Secret Service unlock с отдельным password recovery, не зависящим от keyring.
- [ ] **EXT-003** Optional E2EE vault sync как **отдельный** продукт/контракт, не связанный с MFA verifier.
- [ ] **EXT-004** WebAuthn/FIDO2/passkeys и phishing-resistant auth; отдельный threat model.
- [ ] **EXT-005** Модуль корпоративных политик и дополнительная интеграция с IAM без обязательного Keycloak.

## P3 — мобильные устройства (не начинать до stable desktop/server)

- [ ] **MOB-001** Измерить потребности в Android/iOS, нативные SDK и threat model.
- [ ] **MOB-002** Определить мобильный код, независимый от GUI и cloud, по результатам mobile ADR.
- [ ] **MOB-003** Отдельный выпуск после security review и hardening.

## Правила работы с задачами

- Не отмечать задачу выполненной без тестов/артефактов, подтверждающих её критерий приемки.
- Не объединять архитектурный дизайн и «готово к production» в одну задачу.
- Обязательны независимые security review для vault format, криптопротоколов, recovery и server verification.
- Для каждой крупной задачи формировать отдельный PR с ссылкой на идентификатор TODO.
