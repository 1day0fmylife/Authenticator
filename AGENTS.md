# AGENTS.md — обязательные инструкции coding agents

Этот файл обязателен для **любых** AI coding agents, в том числе Codex, OpenCode и Claude Code. При расхождениях с CLAUDE.md преимущество имеют AGENTS.md, PLAN.md и принятые ADR. Пользовательские инструкции в текущей задаче имеют приоритет, но не отменяют security review.

## Проект и scope

- Authenticator — два **независимых** компонента: Rust desktop (Windows/Ubuntu) и Go MFA verifier (API для существующих проектов).
- Desktop генерирует RFC4226/RFC6238 коды **локально и офлайн**, не требует пользователя на сервере или подключения к собственной инфраструктуре.
- Go verifier интегрируется с любым backend через server-to-server API и проверяет коды **любого** совместимого Authenticator.
- Mobile — P3, **не начинать** без отдельного решения и стабильной desktop/server версии.
- Руководствоваться README.md, PLAN.md, TODO.md; задачи брать в порядке зависимостей и согласованных ADR.

## Неприкосновенные архитектурные ограничения

1. **Rust-first desktop**: core, vault, app use cases на Rust; GUI в отдельном crate с абстракциями, выбор между egui/eframe и Slint **только после** dependency/license/offline audit (ADR-002).
2. **Go backend**: стандартная библиотека HTTP/crypto, PostgreSQL с минимальным драйвером. Не добавлять ORM, Redis, Node, веб-фреймворк или внешние IAM как обязательные зависимости без ADR.
3. **Независимость**: не делать Ente/Keycloak/Authy/облачный сервис обязательной частью runtime; не строить proprietary OTP.
4. **Стандартность**: RFC 4226/6238 и otpauth://; общие публичные тест-векторы для Rust и Go.
5. **Секреты**: не логировать TOTP seed, OTP, QR payload, recovery codes, ключи/пароли, decrypted vault, session tokens. Не помещать их в commit, тестовые fixture с реальными данными, PR, crash dumps или telemetry.
6. **Desktop vault**: формат с версиями, AEAD+парольная KDF по утвержденному ADR; никогда не создавать пустое хранилище вместо поврежденного или недоступного; write+fsync+atomic replace, encrypted backups.
7. **Verifier**: service authentication, tenant isolation, session-bound challenge, replay protection, transaction-safe single-use OTP, rate limits, no fail-open on outage, rotation ключей и контролируемое восстановление.
8. **Не реализовывать собственные криптографические примитивы** или неаудированные схемы: выбор RustCrypto libraries + KDF/AEAD оформляется ADR.
9. **Никаких скрытых сетевых функций:** desktop runtime должен работать с запрещенной сетью; без аналитики, сторонних updater SDK или внешних crash-reporting сервисов.
10. **Supply-chain**: каждое новое расширение dependency graph требует объяснения, лицензии, полного транзитивного графа, обзора build.rs/proc-macros/unsafe и проверки offline build.

## Порядок работы над задачами

1. Прочесть README.md, PLAN.md, TODO.md, соответствующие ADR и существующие тесты.
2. Выбрать **один** TODO ID; записать scope, инварианты безопасности, API/форматы, тесты и новые зависимости.
3. Для архитектурно спорного решения сначала добавить ADR и сравнение альтернатив. Не выбирать GUI или криптографический crate «по умолчанию».
4. Писать минимальный изолированный код; протоколы и данные не должны зависеть от GUI.
5. Добавлять отрицательные тесты: ошибки входных данных, неверный пароль, отказы хранилища, replay/race/tenant IDOR.
6. Проверить, что нет секретов в логах и нет нового необоснованного runtime/network dependency.
7. Проверить форматирование, линтеры, модульные и интеграционные тесты; не утверждать, что запускались тесты, если окружение отсутствует.
8. Обновить TODO и связанную документацию **только по подтвержденному результату**; составить список принятых рисков и ограничений.

## Quality gates: desktop Rust

После создания workspace использовать (если команды поддерживаются в выбранной конфигурации):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo tree --locked
cargo build --workspace --release --frozen
```

- Отдавать предпочтение safe Rust. Любой unsafe — отдельный комментарий с инвариантом, review и тест.
- Не злоупотреблять `unwrap()`/`expect()` на внешнем вводе, crypto/IO/API boundary. Нет panic на испорченном файле/URI.
- Пределы на память, длины, число записей, KDF стоимость и обработку URI; fuzzing parser, vault reader.
- Использовать `zeroize` или эквивалент после оценки зависимостей там, где можно контролировать время жизни секретов; не обещать гарантированное стирание копий ОС.
- Не разрабатывать двоичный формат «по ходу дела»; first spec, then code, then independent fixtures.

## Quality gates: MFA server Go

После создания модуля (в `server/`):

```bash
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
```

- Использовать parameterized SQL, context timeouts и транзакции; не допускать verification race/replay.
- Не полагаться на volatile in-memory rate-limit для распределенного deployment.
- MFA verifier не объявляет сессию пользователя аутентифицированной; **это обязанность relying party backend**.
- Не принимать tenant как источник авторизации от браузера; он определяется по подтвержденному service credential.
- Ключи шифрования БД — вне самой БД и контейнерного образа; startup fail-closed при некорректном ключе.
- Перед реализацией handler сначала обновлять OpenAPI и contract tests.

## Управление зависимостями и релизами

- Не добавлять crate/package/SDK без явной необходимости и обзора альтернатив на стандартной библиотеке.
- Не использовать wildcard/unbounded версии, unpinned GitHub Actions, `curl | sh`, непроверенные бинарники и download-on-build.
- `Cargo.lock`, `go.sum`, pinned toolchains, SBOM, licensing, checksums и offline mirror обязательны для релизов.
- Если отсутствует возможность проверить новый dependency/security claim, **пометить ограничение и не выпускать production release**.
- Секреты/ключи подписи не лежат в репозитории; example configs содержат только недействительные значения.
- Для любых изменений crypto/vault/enrollment/challenge/recovery требуется отдельный security review.

## Ограничения для агентов

- Не выполнять массовые рефакторинги или перестройку технологического стека без отдельного ADR.
- Не создавать сотни файлов/пустых заглушек ради видимости прогресса.
- Не менять приоритет мобильных клиентов.
- Не отмечать P0 задачи завершенными по одному компилируемому прототипу.
- Не вводить совместимость с закрытыми нестандартными форматами ценой безопасности/независимости.
- Не выдавать результаты сканеров или тестов, которых фактически не было.

## Формат отчёта агента

Для каждого изменения указывать: TODO ID → проблема → решение → затронутые файлы → зависимости → проверки (выполнены/невыполнены) → ограничения безопасности → оставшиеся задачи. Для security-sensitive PR отдельно кратко описывать trust boundaries и негативные сценарии.
