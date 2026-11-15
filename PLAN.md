# PLAN.md — архитектура и дорожная карта Authenticator

> Статус: **Architecture Draft v0.4**, 15.11.2026. Это план, а не утверждение о готовности программного обеспечения.
> Основные приоритеты: **Windows и Ubuntu desktop + независимый MFA-сервер**. Мобильные приложения — **P3**, после стабилизации.

## 1. Цель

Создать open-source платформу аутентификации, не привязанную к Ente, Keycloak, конкретному IAM или облачному оператору:

- **Desktop Authenticator**: генерирует TOTP/HOTP полностью локально; совместим с любыми стандартными сервисами, даже если собственный сервер недоступен.
- **MFA Verifier**: самостоятельный Go-сервис для добавления второго фактора в свои проекты (FastAPI, Go и другие) через документированный межсервисный HTTP API.
- **Мобильные приложения**: отдельное будущее направление, не влияющее на desktop/backend v1.
- **Независимость**: открытые форматы и стандартные протоколы, воспроизводимый/проверяемый процесс сборки, минимум поставщиков и транзитивных зависимостей.

Генератор и сервер проверки **не связаны проприетарным протоколом**. Пользователь может использовать другой TOTP-клиент с нашим сервером, а наш клиент — с чужим сервером.

## 2. Стек и архитектурные решения

| Область | Решение | Статус |
| --- | --- | --- |
| Desktop domain, vault, OTP | **Rust** stable; workspace с отдельными core/vault/GUI crates | Принято |
| Desktop GUI | **Rust-native**, кандидаты **egui/eframe** и **Slint**; финальный выбор после GUI Dependency Gate | Открытый ADR |
| Desktop storage | **Версионированный зашифрованный файл**; сначала без SQLite | Принято как цель MVP |
| Desktop crypto | Проверенные RustCrypto crates (HMAC/SHA, Argon2id, XChaCha20-Poly1305, CSPRNG), ограниченный перечень | Принято: ADR-003 |
| Go MFA backend | Go standard library + PostgreSQL, один проверенный драйвер | Принято |
| External API | JSON over HTTPS, OpenAPI, независимый от framework контракт | Принято |
| Packaging | Windows и Ubuntu LTS; подписанные артефакты, SBOM, офлайн-сборка | Обязательная цель релиза |
| Mobile | Android/iOS после desktop/server stable | P3 |

### ADR-001 — Rust-first desktop и независимость

Решение зафиксировано в [security/adr/0001-independence.md](security/adr/0001-independence.md). Выбор Rust обоснован безопасностью памяти и возможностью реализовать domain/vault без FFI и без C++ ABI. Это **не** устраняет supply-chain риски: Cargo dependency graph, build.rs, proc-macros, Rust toolchain и графическая библиотека остаются доверенной кодовой базой.

Запрещено включать Qt/C++/WebEngine/Node.js/Electron как обязательные компоненты без отдельного сравнительного ADR и одобрения. Не использовать unsafe без документированных инвариантов, ревью и тестов.

### ADR-002 — GUI изолирован от безопасности и данных

Структура Rust workspace (план):

```text
desktop/
  crates/
    otp-core/       # создан: RFC 4226/6238 (без GUI/storage/network)
    vault/          # формат файла, AEAD, KDF, persistence, recovery
    app-core/       # use cases, traits, state machine, ошибки
    app-gui/        # только представление и OS integration; framework TBD
    app-cli/        # тестирование, обслуживаемые offline команды
  tests/
server/
  cmd/authenticator-mfa/   # план
  cmd/verify-vectors/      # создан: независимая проверка shared vectors
  internal/otp/            # создан: RFC 4226/6238 (stdlib)
  internal/{api,application,domain,storage,security}/  # план
  migrations/              # план
api/
  openapi.yaml             # план
tests/
  vectors/                 # создан: rfc4226/rfc6238 + README
security/
  threat-model.md
  supply-chain.md
  adr/0001-independence.md
  adr/0003-crypto.md       # создан: crates, AEAD, Argon2id, envelope
packaging/
  windows/
  ubuntu/
README.md  PLAN.md  TODO.md  AGENTS.md  CLAUDE.md  SECURITY.md
```

Созданы `desktop/crates/otp-core`, `server/internal/otp`, `server/cmd/verify-vectors`, `tests/vectors`, `security/adr/0001-independence.md` и `security/adr/0003-crypto.md`; остальные папки с исходным кодом — **план**. Без локального HTTP/IPC daemon и без сетевых разрешений в GUI v1.

**GUI Dependency Gate до выбора:**
1. Сделать по одному маленькому Rust-прототипу egui/eframe и Slint для Windows + Ubuntu.
2. Сравнить **полные** dependency graph (normal/build/proc-macro/native), лицензии, объем unsafe/native code, build scripts, графические backend, размер бинарника, доступность/offline build и обновляемость.
3. Проверить accessibility, clipboard, system tray, screen locking, Wayland/X11, HiDPI, отсутствие необязательного network/web runtime, FPS/CPU без нагрузки.
4. Для Slint особо проверить требования выбранной лицензии и варианты backend; для eframe — графические и оконные зависимости; не путать небольшой egui core с полной стоимостью eframe.
5. Зафиксировать результат и бюджет зависимостей в `security/adr/0002-gui.md`; GUI не должен влиять на тесты и API core.

### Supply-chain policy — минимум сторонних зависимостей

Полная политика, бюджет зависимостей и review-процесс: [security/supply-chain.md](security/supply-chain.md) (SEC-002). Ниже — краткие принципы.

**Rust:** `Cargo.lock` обязателен, default-features отключать где оправдано, `cargo vendor` для релизной сборки, `cargo --frozen` и отключенный network в CI; каждый новый crate проверять по лицензии, источнику, владельцам, жизнеспособности, `build.rs`, unsafe и транзитивным зависимостям.

**Go:** standard library везде, где можно, только обоснованный PostgreSQL-драйвер; закрепленные версии в `go.mod/go.sum`, `go mod vendor` и `-mod=vendor` для offline release. Не вводить Gin/Fiber/GORM/Redis/Keycloak SDK в MVP без ADR.

**Infrastructure:** pinned toolchains, независимые checksums, signed provenance, SBOM SPDX/CycloneDX, уязвимости + лицензии, controlled ingestion → offline build; никаких сетевых скачиваний во время финального build и `curl | sh`.

Цель — **уменьшить доверенную поверхность**, а не механически довести число зависимостей до нуля. Не писать собственные криптографические примитивы. Не считать «прошёл CVE scan» доказательством безопасности.

### Совместимость и стандарты (ADR-001)

HOTP RFC 4226, TOTP RFC 6238, `otpauth://`; алгоритмы SHA-1 (для совместимости), SHA-256, SHA-512, digits 6/8, period 30 с поддержкой валидируемых параметров; корректный HOTP counter. Строгий URI parser с ограничениями входа и отказом от неподдерживаемых параметров. Стандартные RFC test vectors обязательны. Пароль/секрет не записываются в логи.

### Криптография и формат vault (ADR-003, ADR-004)

[ADR-003](security/adr/0003-crypto.md) принят: **XChaCha20-Poly1305**, **Argon2id** (v19, `m=64 MiB`, `t=3`, `p=1`, salt 16, key 32), прямой ключевой envelope без HKDF в v1, точные pinned-версии и проверенные RFC-векторы. Бинарная раскладка файла и recovery-сценарии — ADR-004; до него код vault не пишется.

Модель **offline, portable, fail-closed**:
- В v1 один защищенный файл: versioned binary envelope + аутентифицированный зашифрованный payload с записями. Не считать само файловое шифрование эквивалентом защиты памяти/процесса.
- Использовать CSPRNG ОС, **Argon2id** для ключа из парольной фразы и **XChaCha20-Poly1305**; схема и параметры зафиксированы ADR-003. Не комбинировать/придумывать свои криптосхемы.
- KDF salt/params, формат, версия, nonce и AAD задаются спецификацией до кода. Установить жёсткие лимиты на размер, число записей, KDF cost и длину строк.
- Сохранение: write → fsync → atomic rename с учетом Windows/Ubuntu semantics, резервная копия, отказоустойчивость/rollback-тесты. Ошибки разблокировки и поврежденный файл не должны создавать «пустой vault».
- Первый ключ **не обязан** храниться в Windows DPAPI / Linux Secret Service; удобное OS-unlock — отдельная P1-функция с независимым recovery path. Потеря Keyring **не удаляет** данные.
- Парольный backup должен оставаться переносимым и доступным без сервера. Недопустимо использование 4/6-значного PIN в качестве единственной криптографической защиты vault.
- Минимизация lifetime секретов в памяти, best-effort clipboard clearing, без телеметрии, HTTP, embedded browser.

## 3. Desktop use cases (MVP)

Создать/открыть/закрыть vault; добавить/изменить/удалить запись; показать TOTP с периодом; вручную увеличить HOTP counter и атомарно сохранить; импорт `otpauth://` по тексту; поиск после разблокировки; encrypted export/import и проверенное восстановление; автоматическая блокировка после простоя. QR сканер и интеграция с tray — после анализа дополнительных dependencies (P1), а не через необоснованный крупный framework.

**Необязательная синхронизация vault** отложена: собственный MFA-verifier не должен получать или синхронизировать vault клиентских токенов.

## 4. Go MFA Verifier: trust boundaries

```text
[Пользователь] ── primary auth ──> [Backend приложения / свой IdP]
                                        │  server-to-server HTTPS + identity
                                        ▼
                               [Go MFA Verifier]
                                │ enrollment/verify
                                ▼
                     [PostgreSQL: шифрованные seeds]
                                        │
Backend приложения <-- MFA decision ----┘
         │
         └── только backend приложения повышает свою authenticated session
```

- MFA-verifier не заменяет primary authentication и RBAC/ABAC существующих проектов.
- Tenant/project определяется **аутентифицированной service identity** (mTLS либо scoped machine credentials); не принимается как пользовательский, непроверенный JSON-параметр.
- Subject ID валидируется в пространстве tenant; challenge связан с `tenant_id + subject_id + purpose + session_binding` и имеет TTL, попытки, одноразовый статус.
- Enrollment seed создается сервером; предъявляется доверенным backend только после аутентификации и подтверждается TOTP. Вторая сторона может использовать **любой** TOTP-клиент.
- Endpoint disable/re-enroll/recovery требует step-up или контролируемого процесса восстановления; запрещен fail-open при недоступном verifier.
- Seed в БД: AEAD encryption, `key_id`, ключи шифрования из управляемого файла/secret provider **вне PostgreSQL и образа контейнера**. Документировать key rotation.
- Verify: ограниченное окно времени, проверка по HMAC, constant-time сравнение, атомарное однократное принятие временного шага, защита от повторов при конкурентных запросах; транзакции и constraints в БД.
- Защита от перебора: лимиты попыток на challenge/subject/tenant/service, fail closed, при нескольких репликах состояние в PostgreSQL (без обязательного Redis).
- Recovery codes: CSPRNG, достаточно длинные, одноразовые, хеширование с server-held pepper, атомарное использование.
- Логи и аудит: без OTP/seed/QR/backup/recovery plaintext. Correlation ID, purpose, решение, причину отказа — только в безопасной форме, без subject enumeration.
- OTP — **не phishing-resistant**; WebAuthn/FIDO2 проектируется в будущем как отдельный фактор, не должен быть неверно обозначен как уже реализованный.

### 4.1. API (предложение; **ещё не реализовано**)

```http
POST /v1/mfa/enrollments/start
POST /v1/mfa/enrollments/{id}/confirm
POST /v1/mfa/challenges
POST /v1/mfa/challenges/{id}/verify
POST /v1/mfa/factors/{id}/disable
POST /v1/mfa/recovery-codes/rotate
GET  /health/live
GET  /health/ready
```

Схемы запросов/ответов, способы привязки к relying session, TTL, idempotency и ошибки согласовать в `api/openapi.yaml` перед реализацией.

### 4.2. Концептуальная схема данных

- `mfa_service_clients(id,tenant_id,credential_ref,status)`
- `mfa_subjects(tenant_id,subject_id,status)`
- `mfa_factors(id,tenant_id,subject_id,type,algorithm,digits,period,secret_ciphertext,key_id,last_accepted_step,status)`
- `mfa_enrollments(id,tenant_id,subject_id,secret_ciphertext,expires_at,state)`
- `mfa_challenges(id,tenant_id,subject_id,session_binding_hash,purpose,expires_at,attempts,state)`
- `mfa_recovery_codes(id,tenant_id,subject_id,digest,used_at)`
- `mfa_audit(id,tenant_id,subject_id,event,decision,created_at,correlation_id)`

В SQL обязательно включить tenant-bound foreign keys, uniqueness, migrations и индексы. Схема пока проектная, не существует в БД. Idempotent confirmation и exact replay guard требуют отдельных транзакционных тестов.

## 5. Threat model и release gates

Актуальный реестр активов, trust boundaries, угроз и остаточных рисков: [security/threat-model.md](security/threat-model.md) (SEC-001). Ниже — сводка.

Угрозы: повреждение локального vault, кража зашифрованного backup и offline password guessing, компрометация desktop-процесса/ОС, фишинг TOTP, compromised MFA database или service identity, серверный replay, brute force, гонки, tenant IDOR, malware/typosquatting crates, malicious build scripts, подмена toolchain и обновлений, rollback/migration failure.

**Security Definition of Done**:
1. Сформулированы trust boundaries и тесты отрицательных сценариев; нет заявления, что полностью компрометированную ОС можно защитить.
2. Есть RFC vector tests для Rust и Go, fuzzing `otpauth://` и vault parser, race/concurrency tests для backend.
3. Реализовано отсутствие секретов в логах, exception, CI/artifacts и необязательных сетевых компонентах.
4. Новые зависимости проверены, закреплены, лицензии учтены, SBOM сформирован, reproducibility проверена или ограничение указано явно.
5. Проверены отказ/восстановление vault, backup restore, login step-up, replay, key rotation и database migration.
6. Нужен независимый security review до заявления о production readiness.

## 6. Этапы

| Этап | Содержание | Критерий перехода |
| --- | --- | --- |
| M0 — bootstrap | README, PLAN, TODO, AGENTS, CLAUDE | Документы в GitHub, стек определён, неизвестные факторы помечены |
| M1 — RFC core | Rust/Go HOTP/TOTP, строгий URI parser, независимые тест-векторы | Совпадение RFC, негативные и граничные тесты |
| M2 — crypto/vault | Спецификация формата, KDF+AEAD, атомарные записи, recovery | Смена/порча файла и прерванные записи не уничтожают доступ |
| M3 — desktop GUI | GUI Dependency Gate, Rust GUI, UX, Windows/Ubuntu packages | Без облака, тестируемые UX flows в обеих ОС |
| M4 — MFA server | PostgreSQL migrations, enrollment/challenge/verify/recovery, OpenAPI | Cross-tenant, replay, brute-force, race тесты |
| M5 — release hardening | SBOM, offline build, signatures, FastAPI/Go examples, integration tests | Повторяемая сборка, secure deployment, external review |
| M6 — optional | OS-unlock, QR scanner, WebAuthn, E2EE sync только по ADR | Не меняет обязательный контракт v1 |
| M7 — mobile | Android/iOS, только после стабильных релизов | Отдельный threat model, runtime и supply-chain review |

Приоритет реализации: **M1 → M2/M4 параллельно → M3 → M5**. Сервер не должен блокироваться ожиданием GUI.

## 7. Решения, которые предстоит закрыть ADR

- GUI framework после измерения графа зависимостей и лицензий.
- Конкретные криптографические Rust crates, AEAD, параметры Argon2id, backup/vault format.
- Windows/Ubuntu installers, подпись пакетов и совместимость версий ОС.
- Trust scheme (mTLS/service token), ограничения challenge, key rotation и HA для Go backend.
- Лицензия **собственного** репозитория (не копировать AGPL/GPL автоматически), policy security disclosure.
