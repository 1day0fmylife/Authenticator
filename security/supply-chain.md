# Supply-chain policy — Authenticator

**Статус:** Draft v0.5, 16.11.2026.
**Область:** Rust desktop workspace, Go MFA verifier, CI/CD, toolchains, релизные артефакты и обновления.
**Связанные документы:** [threat-model](threat-model.md), [PLAN](../PLAN.md), [TODO](../TODO.md), [AGENTS](../AGENTS.md), ADR в `security/adr/`.

Документ описывает **политику и бюджет**, а не подтверждённый аудит: ADR-003 (crypto) принят, ADR-002 (GUI) остаётся открытым. Числовые лимиты ниже — стартовые; они уточняются в ADR по результатам измерений и не могут быть превышены без отдельного решения.

## 1. Принципы

1. **Уменьшать доверенную поверхность, а не число зависимостей ради числа.** Каждая зависимость должна закрывать реальную потребность; альтернатива на стандартной библиотеке рассматривается первой.
2. **Никакой самодельной криптографии.** Используются только проверенные примитивы (RustCrypto, Go `crypto/*`) по утверждённому crypto ADR.
3. **Воспроизводимость и offline build.** Сборка релиза не скачивает код из сети и не выполняет необозреваемые скрипты.
4. **Прозрачность.** Полный транзитивный граф, лицензии, SBOM и ограничения публикуются; отсутствие проверки указывается явно, а не замалчивается.
5. **Fail-closed.** Непроверенная зависимость, подпись, toolchain или ключ блокируют релиз.
6. **Секреты не пересекают границу сборки.** Ключи подписи и токены не находятся в репозитории, образе или логах CI.

## 2. Запрещено без отдельного ADR

- GUI/web-runtime: Qt/C++ как обязательная часть, Tauri, Electron, Node.js, WebEngine, встроенный браузер.
- Облачные сервисы, аккаунты, аналитика, crash-reporting SDK, обязательный remote updater, push.
- Rust: git-зависимости, path-зависимости вне workspace, wildcard (`*`), unbounded версии, `build.rs` со скачиванием, `*-sys` крейты с vendored C/C++ без review, `unsafe` без инварианта и теста.
- Go: ORM, Gin/Fiber/Echo, Redis/Sentinel, IAM/Keycloak SDK, сторонний JWT/OAuth framework, cgo-драйвер БД, если есть разумная альтернатива на stdlib/чистом Go.
- CI: unpinned actions (`@v3` вместо SHA), `curl | sh`, сборка из mutable tag, секреты в логах, self-hosted runner без изоляции для релизных сборок.
- Форматы/протоколы: proprietary OTP, нестандартные схемы шифрования, обязательная совместимость с закрытым облаком.
- Лицензии: GPL/AGPL/LGPL-код в обязательных зависимостях, SSPL, BUSL, «unknown/custom» без юридического review; MPL-2.0 и подобные — только после checking file-level obligations.

## 3. Бюджет зависимостей (стартовый)

Бюджет считается по **полному** графу (`cargo tree --edges normal,build`, `go list -deps`), включая proc-macros и native/build-зависимости.

| Компонент | Прямые зависимости (цель) | Полный граф (цель) | Жёсткий предел без ADR |
| --- | --- | --- | --- |
| `otp-core` | ≤ 5 | ≤ 13 | 20 |
| `vault` | ≤ 8 | ≤ 40 | 60 |
| `app-core` | ≤ 6 | ≤ 40 | 60 |
| `app-cli` | ≤ 3 | ≤ 12 **новых** сверх графа `vault` | 20 новых сверх `vault` |
| `app-gui` | ≤ 8 | ≤ 120 | 160 |
| Go verifier | stdlib + 1 БД-драйвер | — | 2 прямых пакета вне stdlib |

Дополнительные ограничения:

- Бюджет `app-cli` считается **инкрементально**: CLI обязан зависеть от `vault`, поэтому учитываются только прямые зависимости CLI и крейты, которых нет в графе `vault` (решение 16.11.2026; полный граф всё равно публикуется).
- **Один** PostgreSQL-драйвер; **один** AEAD crate (или явно разделённые key-wrap и payload AEAD по ADR); **один** HMAC/SHA набор.
- Дублирование версий одного crate в графе — обосновать; больше двух версий — блокер.
- Native C/C++ код допустим только для оконной/графической подсистемы GUI и явно перечисляется в ADR-002; ядро (`otp-core`, `vault`, `app-core`) — без C/C++.
- Бинарник desktop: цель ≤ 25 МБ (release, stripped) для выбранного GUI; превышение фиксируется в ADR с причиной. Значение уточняется после spike.
- Крейты с `build.rs`/proc-macro: не более 25% полного графа; каждый — в allowlist с описанием функции.
- `unsafe`: в ядре — 0 (кроме отдельно одобренных участков с инвариантом, review и тестом); в GUI — учитывается по зависимостям, не скрывается.

Бюджет проверяется скриптом/CI (SUP-004); ручное «примерно посчитали» не считается выполнением.

## 4. Категории allowlist

Конкретные версии фиксируются в lockfile и ADR. Категория разрешена, только если выполнены §5 и §6.

### 4.1 Rust desktop

| Категория | Кандидаты | Назначение | Решение |
| --- | --- | --- | --- |
| HMAC/SHA | `hmac`, `sha1`, `sha2` (RustCrypto) | RFC 4226/6238 | ADR-003 |
| KDF | `argon2` (RustCrypto) | Argon2id | ADR-003 |
| AEAD | `chacha20poly1305` или `aes-gcm` | Payload vault (один выбор) | ADR-003 |
| CSPRNG | `getrandom` / `rand_core` (OS entropy) | Salt/nonce | ADR-003 |
| Constant-time | `subtle` | Сравнение OTP/тегов | ADR-003 |
| Zeroization | `zeroize` | Lifetime секретов | ADR-003 |
| Кодирование | `data-encoding`/`base32` или собственный строгий parser | Base32/URI | OTP-004 |
| Сериализация | без serde по умолчанию; при необходимости — ADR | Vault payload | ADR-004 |
| Ошибки | stdlib/ручные типы; `thiserror` только по ADR | Error model | ADR-004 |
| GUI | `egui`/`eframe` **или** `slint` | Только `app-gui` | ADR-002 |
| CLI | stdlib | `app-cli` | — |

Запрещено для desktop runtime: `reqwest`, `hyper`, `tokio`-сеть, telemetry SDK, updater SDK, SQLite/ORM без ADR, `openssl`-sys без review.

### 4.2 Go verifier

| Категория | Кандидаты | Назначение | Решение |
| --- | --- | --- | --- |
| HTTP | `net/http` | API | SRV-001 |
| Crypto | `crypto/hmac`, `crypto/sha1`, `crypto/sha256`, `crypto/sha512`, `crypto/subtle`, `crypto/rand` | OTP, digest, recovery | OTP-003 |
| БД | `github.com/jackc/pgx/v5` **или** `github.com/lib/pq` (один) | PostgreSQL | SRV-002 |
| Логи | `log/slog` | Structured logs без секретов | SRV-009 |
| Метрики | stdlib/простой endpoint | Без тяжёлого Prometheus-клиента в MVP | SRV-009 |

Запрещено: `gorm`, `gin`, `fiber`, `redis`, JWT-библиотеки без ADR, cloud SDK, APM-агенты с автоматическим сбором данных.

## 5. Обязательный review новой зависимости

Перед добавлением прямого dependency оформляется запись (в PR/ADR или `security/dependencies/` — по одному файлу на прямую зависимость, без массовых заглушек):

1. **Необходимость:** какую задачу решает, почему stdlib/существующая зависимость не подходит.
2. **Идентичность:** точное имя, версия, registry, checksum, ссылка на исходники, владельцы/организация.
3. **Полный граф:** `cargo tree -i <crate>` / `go mod graph`, включая build/proc-macro/native.
4. **Лицензия:** SPDX, совместимость с лицензией проекта (PLAN §7), обязательства attribution.
5. **build.rs / cgo / proc-macros:** что выполняется, есть ли сеть, генерация кода, `Command`, `include!`, скачивание, недетерминизм.
6. **unsafe/FFI:** количество, назначение, инварианты, who maintains safety.
7. **Функции:** `default-features = false`, минимальный набор features, отсутствие необязательных сетевых возможностей.
8. **Жизнеспособность:** последний релиз, активность, bus factor, история инцидентов, наличие альтернативы.
9. **Уязвимости:** RUSTSEC/OSV/GitHub Advisory на дату review; triage, а не только «скан чист».
10. **Платформы:** Windows/Ubuntu (x86_64, при наличии — arm64), MSRV, размер, offline-сборка.
11. **Тесты:** dependency не влияет на deterministic vectors; есть ли способ проверить поведение.

Одобрение фиксируется в ADR для crypto/GUI/DB и в PR для остальных. «Много звёзд на GitHub» не является доказательством безопасности.

## 6. Toolchain и lockfiles

- Rust: `rust-toolchain.toml` с точной версией, `profile = "minimal"`, обязательные components; обновление — отдельным PR с changelog и прогоном всех gates. `Cargo.lock` коммитится, `--locked` обязателен.
- Go: `go.mod` с точной директивой `go` и `toolchain`, `go.sum` коммитится; `GOFLAGS=-mod=vendor` для релиза.
- CI-образы: pin по digest (`image@sha256:...`), не `latest`; rustup/Go берутся из проверенного источника с проверкой checksum.
- `cargo`/`go` версии, OS image, actions и контейнеры фиксируются в одном манифесте (SUP-001).
- Downgrade toolchain или смена registry — отдельное решение, не «побочный эффект».

## 7. Offline ingestion и сборка

```text
[upstream registry] ──(controlled ingestion, review, checksums)──> [approved mirror]
                                                                       │
                                          vendor/ + lockfiles <────────┘
                                                  │
                                     offline build (no network)
                                                  │
                                     SBOM + hashes + signatures
```

- Rust: `cargo vendor` (или внутренний mirror) + `.cargo/config.toml` source replacement; релиз: `cargo build --workspace --release --locked --frozen --offline`.
- Go: `go mod vendor`; релиз: `GOPROXY=off GOFLAGS=-mod=vendor go build`.
- Clean-room проверка: сборка в окружении **без сетевого доступа** из зафиксированного mirror/vendor.
- Ingestion не выполняет `build.rs`/install-скрипты до review; исходники сверяются по checksum с registry.
- Любая сетевая операция во время финального build — дефект, а не удобство.

## 8. SBOM, provenance и подписи

- SBOM: CycloneDX **или** SPDX из lockfile/vendor; хранится с релизом, содержит компоненты, версии, лицензии, checksums.
- SCA/лицензионный отчёт генерируется тем же пайплайном; ограничения инструментов указываются.
- Артефакты подписываются ключом вне репозитория/образа (cosign/minisign/платформенная подпись — ADR); публикуются checksums.
- Проверка обновления/пакета — offline, без обязательного remote updater; подпись проверяется до установки.
- Reproducibility: заявляется только при фактической проверке; известные ограничения (timestamps, host toolchain, native deps) перечисляются. `SUP-003` не считается выполненным по наличию одного SBOM.
- Ключи подписи: rotation, разделение ролей, отзыв, документация; компрометация = остановка релизов.

## 9. Уязвимости и обновления

| Severity | Реакция | Исправление/решение |
| --- | --- | --- |
| Critical | Немедленный triage, блокировка релиза | ≤ 7 дней или документированный compensating control |
| High | Triage в течение 3 рабочих дней | ≤ 30 дней |
| Medium | Triage в течение 10 рабочих дней | ≤ 90 дней |
| Low | Плановое обновление | Следующий релиз |

- Источники: RUSTSEC, OSV, GitHub Advisory, CVE/NVD, Go vuln DB.
- Оценивается достижимость в нашем коде и на целевых платформах; «не exploitable» требует обоснования.
- Отключение проверки или исключение advisory фиксируется с owner, сроком и условиями пересмотра.
- Emergency update не отменяет подпись, checksums, SBOM и offline-проверку.

## 10. Enforcement (CI)

До появления CI политика действует как review-требование. Планируемые проверки (SUP-004):

- diff `Cargo.lock`/`go.sum` и полного графа; изменение без dependency review — fail;
- запрет git/path/wildcard и сетевых операций в build scripts (эвристика + review);
- license allowlist; отсутствие GPL/AGPL/SSPL/BUSL;
- `cargo fmt --check`, `clippy -D warnings`, `cargo test --locked`, `go vet`, `go test -race`;
- offline build job с отключённой сетью;
- secret scan логов/артефактов/fixtures;
- проверка, что SBOM/checksums соответствуют артефактам.

Ложные срабатывания не отключаются «навсегда»: исключение имеет owner и срок.

## 11. Текущее состояние (честно)

| Пункт | Статус |
| --- | --- |
| Rust workspace и `Cargo.lock` | не созданы |
| Go module и `go.sum` | не созданы |
| Конкретные crypto crates | не выбраны (ADR-003 открыт) |
| GUI framework | не выбран (ADR-002 открыт) |
| PostgreSQL драйвер | не выбран (ADR-005/SRV-002) |
| Vendor/mirror | отсутствует |
| SBOM/подписи/CI | отсутствуют |
| Лицензия проекта | `MIT OR Apache-2.0` (LICENSE-MIT, LICENSE-APACHE); зависимости должны быть с ней совместимы |
| Security disclosure | см. [SECURITY.md](../SECURITY.md) |

Ни одна строка выше не должна трактоваться как «проверено». До выполнения SUP-001…SUP-004 production-релиз невозможен.

## 12. Исключения

Исключение из бюджета/allowlist оформляется как ADR (или явный раздел PR) с: причиной, альтернативами, риском, owner, сроком пересмотра, compensating controls и тестами. Исключение без срока или «временно» без даты не принимается. Security-sensitive исключения требуют отдельного review (AGENTS).

## 13. Ссылки и проверки

```bash
# Rust (после создания workspace)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo tree --locked
cargo build --workspace --release --locked --frozen --offline

# Go (после создания server/)
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go list -deps ./...
```

Отчёт о фактически выполненных командах обязателен; непроверенные пункты помечаются как невыполненные.

## 14. Changelog

| Дата | Версия | Изменение |
| --- | --- | --- |
| 15.11.2026 | 0.1 | Первичная политика: бюджет, allowlist, review, toolchain, offline build, SBOM, SLA, enforcement |
| 15.11.2026 | 0.2 | ADR-003: бюджет `otp-core` уточнён до ≤5 прямых / ≤13 транзитивных по фактическому измерению `cargo tree` |
| 15.11.2026 | 0.3 | VAULT-001: измерен граф `vault` (Linux x86_64) — 6 прямых / 28 внешних normal+build (33 с dev); в рамках бюджета ≤8 / ≤40. Свой `build.rs` у crate нет; в графе `build.rs` есть у `generic-array`, `getrandom`, `libc` (3 из 28, ≈11% < 25%), их review по п. 5 ещё не оформлен. У `argon2` включён feature `zeroize` (новых пакетов не добавляет) |
| 15.11.2026 | 0.4 | VAULT-003: `vault` — 8 прямых (предел бюджета ≤8): `sha2` из dev в normal, `libc` прямой только для `cfg(unix)` (нужны `O_NOFOLLOW`/`O_NONBLOCK`/`ELOOP`, значения зависят от архитектуры; пакет уже был в графе через `getrandom`). Внешний граф не изменился: 28 normal+build. Следующая прямая зависимость требует пересмотра бюджета |
| 16.11.2026 | 0.5 | VAULT-006: бюджет `app-cli` переведён на инкрементальный (стартовый ≤12 полного графа был невыполним при 28 крейтах `vault`). Измерено: `app-cli` — 2 прямых (`vault`, `zeroize`), 0 новых крейтов, полный внешний граф 28 (тот же, что у `vault`); разбор аргументов — stdlib |
