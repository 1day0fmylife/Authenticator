# ADR-005: Контракт Go MFA verifier

**Статус:** Accepted v0.2, 22.11.2026. Архитектурное решение принято; это **не** production readiness. Независимый security review (`QA-002`) остаётся обязательным до stable. Реализация `SRV-002+` разрешена после dependency review PostgreSQL-драйвера; авторский adversarial review — §10 и [`security/reviews/0005-verifier-review.md`](../reviews/0005-verifier-review.md).
**Связанные документы:** [TODO](../../TODO.md) (`ADR-005`, `SRV-001`…`SRV-009`), [ADR-001](0001-independence.md), [ADR-003](0003-crypto.md), [ADR-004](0004-vault.md), [ADR-006](0006-recovery.md) (proposed), [PLAN §4](../../PLAN.md), [threat model](../threat-model.md) (`T-S1`…`T-S17`), [supply-chain](../supply-chain.md), [recovery.md](../../docs/architecture/recovery.md), [device-lifecycle.md](../../docs/architecture/device-lifecycle.md).

## 1. Контекст

`SRV-002`…`SRV-009` описывают PostgreSQL-схему, service authentication, enrollment, challenge/verify, encryption-at-rest, recovery, OpenAPI и аудит. До сих пор ни один из этих пунктов нельзя было начинать: не были зафиксированы service identity, вывод tenant, привязка к relying session, транзакционная семантика replay barrier, формат хранения seed, коды ошибок и схема миграций. Без этого возможны несовместимые реализации и опасные компромиссы вроде tenant из тела запроса или in-memory rate limit.

ADR-001 уже установил модель ответственности: verifier проверяет второй фактор и возвращает **решение**, но не объявляет сессию пользователя аутентифицированной. ADR-006 описывает recovery codes и managed reset и зависит от инфраструктуры, которую фиксирует этот ADR. ADR-003/004 относятся к desktop vault и не задают серверный формат.

## 2. Scope и non-goals

**В scope:**

- server-to-server контракт: service authentication, tenant resolution, scopes;
- TOTP enrollment, challenge и verify;
- session binding, replay barrier, идемпотентность, rate limits;
- формат зашифрованных секретов, `key_id`, rotation и fail-closed;
- схема данных, ограничения tenant isolation и стратегия миграций;
- коды ошибок, аудит, логи, метрики, readiness;
- обязательные негативные и конкурентные тесты.

**Вне scope:**

- primary authentication, RBAC/ABAC, создание или повышение сессии relying party;
- identity proofing, уведомления, отзыв RP-сессий;
- recovery codes, managed reset и dual control — [ADR-006](0006-recovery.md);
- HOTP в verifier — отложен (см. §8, п. 6);
- WebAuthn/FIDO2, passkeys, push, email OTP;
- UI, QR-рендеринг, мобильные клиенты;
- выбор GUI, формата vault и desktop-криптографии.

Verifier — **не** IdP, не session store и не backup-сервис. Любой не-`allow` ответ означает, что relying party обязана считать MFA-шаг невыполненным.

## 3. Trust boundaries

| ID | Граница | Доверие и правило |
| --- | --- | --- |
| TB-V1 | RP backend → verifier | mTLS; tenant выводится только из аутентифицированного service identity |
| TB-V2 | Пользователь → RP UI → RP backend | Пользовательский ввод недоверенный; нормализация и лимиты на стороне RP/verifier |
| TB-V3 | Verifier → PostgreSQL | БД недоверенная на чтение: seeds только в AEAD-конверте, без plaintext |
| TB-V4 | Key store → verifier | Ключи вне БД и образа контейнера; неизвестный `key_id` → отказ |
| TB-V5 | Verifier → audit/log/metrics | Только безопасные поля; OTP, seeds, binding и токены запрещены |
| TB-V6 | Verifier → RP decision | Ответ — решение по конкретному challenge, не сессия и не подписанный assertion |
| TB-V7 | Operator → миграции/конфигурация | Отдельные роли и артефакты; приложение не мигрирует схему автоматически |

## 4. Решение

### 4.1. Инварианты

1. **Tenant только из credential.** Поля `tenant`, `tenant_id`, `project` в body/query/header отвергаются, а не игнорируются молча; авторизация всегда использует tenant из `mfa_service_clients`.
2. **Только явный `allow` — успех.** Любая ошибка, таймаут, недоступность БД/ключа, неизвестная схема или неизвестный `key_id` дают не-2xx и не создают частичного успеха. Никакого fail-open.
3. **Один OTP-шаг принимается не более одного раза** на фактор, включая конкурентные запросы и повторный challenge.
4. **Challenge одноразовый и привязан** к `tenant_id + subject_id + factor_id + purpose + session_binding`.
5. **Seed не покидает verifier после подтверждения enrollment.** Enrollment start отдаёт `otpauth://` один раз; повторный idempotent-ответ с секретом невозможен.
6. **Verifier не возвращает RP-сессию, cookie, JWT доступа или признак «пользователь аутентифицирован».** Только решение по challenge.
7. **Никаких секретов в логах, audit, метриках, ошибках и трассировках.** Код ошибки и reason — статические enum-значения.
8. **Состояние для replay/rate limits/идемпотентности — в PostgreSQL.** In-memory кэш не является источником истины; рестарт и несколько реплик не ослабляют защиту.
9. **Сначала OpenAPI, потом handlers.** `api/openapi.yaml` (SRV-008) и contract tests фиксируют пути, поля и коды ошибок до реализации.
10. **TOTP не phishing-resistant.** Контракт и документация не должны создавать обратного впечатления.

### 4.2. Service identity и tenant resolution

**Решение: mTLS с клиентскими сертификатами, проверяемыми внутри процесса verifier.**

- TLS 1.2 минимум (предпочтительно 1.3), `RequireAndVerifyClientCert`, отдельный client CA bundle. TLS session tickets/resumption отключены: иначе resumed session может не нести клиентский сертификат, и проверка отпечатка/отзыва станет неполной.
- Проверяется цепочка, срок действия и EKU `clientAuth`; CN/SAN **не** используются для tenant или прав. Отсутствующий, просроченный или невалидный сертификат обрывает TLS handshake и не доходит до HTTP-слоя.
- Идентификатор клиента — SHA-256 отпечаток DER-сертификата, сопоставленный в БД с `mfa_service_clients` и `mfa_tenants`. Валидный по цепочке сертификат без активной записи → `401`, после handshake. Проверка отпечатка и статуса выполняется на каждом запросе, поэтому отзыв действует со следующего запроса даже на уже установленном соединении.
- Один service client принадлежит **ровно одному tenant**. RP, обслуживающий несколько tenant, получает отдельный сертификат/клиент на каждый tenant.
- Scopes хранятся в БД и проверяются на каждый запрос: `mfa.enroll`, `mfa.verify`, `mfa.admin`, `mfa.recovery`. Отсутствие scope → `403`.
- Ротация: несколько активных отпечатков на клиента с перекрытием; старый отзывается после переключения. Отзыв действует немедленно, без кэша отпечатков.
- Неизвестный/отозванный сертификат → `401`; ошибка БД при аутентификации → `503` (fail-closed), не `401`.
- Bearer-токены, API keys и «доверенный reverse proxy» в v1 **не поддерживаются**. mTLS-терминация на прокси требует отдельного ADR: verifier должен видеть проверенный сертификат, а не доверять заголовку.
- Тесты используют in-process fake authenticator; отдельного «insecure auth mode» в production-сборке нет.

Порядок обработки: TLS handshake → проверка отпечатка и scope → лимит тела → строгий разбор JSON → handler. Body не читается до успешной аутентификации.

### 4.3. Enrollment (TOTP)

`POST /v1/mfa/enrollments`

- Body: `subject`, `account`, `session_binding`, опционально `algorithm`, `digits`, `period`.
- `subject` — opaque UTF-8, 1…255 байт, без control-символов; сравнивается точно, в пространстве tenant. RP обязан использовать стабильный непрозрачный идентификатор (например, UUID), а не email/username; `account` — только отображаемая метка для `otpauth://` и в БД не сохраняется.
- `account` — отображаемая метка (email/username), 1…256 байт, без control-символов; попадает в `otpauth://`.
- `session_binding` — 16…512 печатных ASCII без пробелов и control-символов; verifier хранит только `HMAC-SHA-256(binding)` с отдельным binding key и tenant_id в сообщении и никогда не пишет исходное значение в логи. RP обязан генерировать binding из своей сессии (случайный nonce), не переиспользовать его между пользователями и считать его одноразовым для конкретного flow.
- `issuer` берётся только из конфигурации tenant (≤ 64 байт printable ASCII), не из запроса.
- `algorithm` ∈ {SHA1, SHA256, SHA512}; `digits` ∈ {6, 8}; `period` ∈ {30, 60}. Default — SHA1/6/30 для совместимости. Расширение набора — новый ADR.
- Verifier генерирует **20 байт (160 бит)** из `crypto/rand`, шифрует и создаёт `mfa_enrollments` в состоянии `pending` с TTL **10 минут**. Enrollment start также создаёт/активирует `mfa_subjects` в пространстве tenant; challenge, напротив, никогда не создаёт субъекта.
- `otpauth_uri` формируется существующим строгим генератором OTP-003/OTP-004 (canonical Base32 без padding, проверка issuer/label), а не ручной конкатенацией.
- Ответ `201`: `enrollment_id`, `otpauth_uri`, `expires_at`, `algorithm`, `digits`, `period`; `Cache-Control: no-store`.
- `otpauth_uri` — единственный момент, когда seed покидает verifier. RP обязан не логировать и не сохранять его дольше provisioning-потока; verifier не пишет body в логи.
- Один активный фактор на `(tenant, subject, type)`. При наличии активного фактора start возвращает `409 enrollment_conflict`; повторный enrollment возможен только после revoke/reset (ADR-006).
- Допускается не более 3 одновременных `pending` enrollment на subject; при превышении новый запрос отклоняется `409 enrollment_conflict`, существующие pending не продлеваются.
- Enrollment start **не** идемпотентен: повтор после потерянного ответа создаёт новый enrollment, старый истекает. Секрет не хранится в idempotency-таблице и не переотправляется.

`POST /v1/mfa/enrollments/{enrollment_id}/confirm`

- Body: `code`, `session_binding`; обязательный `Idempotency-Key`.
- Проверяются: состояние `pending`, TTL, совпадение HMAC `session_binding`, формат кода, TOTP в окне ±1 шаг.
- В одной транзакции: проверка кода, `UPDATE … WHERE state='pending'`, расшифровка секрета, повторное шифрование под AAD фактора (`record_kind=factor`, `factor_id`), запись `mfa_factors` с `last_accepted_step`, очистка ciphertext в enrollment, audit. Простой перенос ciphertext запрещён: AAD привязан к записи.
- Ответ `200`: `factor_id`, `confirmed_at`, `status:"active"`. Секрет не возвращается.
- Ошибка/истёкший TTL/неверный код → `403 mfa_denied`; попытка инкрементирует счётчик. После 5 неудач enrollment переходит в `locked`, последующие попытки получают `429 rate_limited`; подтвердить его нельзя.
- Повторный confirm с тем же `Idempotency-Key` возвращает сохранённый успешный результат без повторной проверки OTP; другой ключ при уже подтверждённом enrollment → `403`.

### 4.4. Challenge и verify

`POST /v1/mfa/challenges`

- Body: `subject`, `purpose` (`login` | `step_up`), `session_binding`.
- Требуется активный фактор; иначе — единый `403 mfa_denied` (не раскрывать «нет субъекта» / «нет фактора»).
- Verifier создаёт 128-битный opaque `challenge_id` (32 hex-символа), сохраняет tenant/subject/factor/purpose/HMAC(binding)/TTL.
- TTL **120 секунд** (конфигурируемо в пределах 30…300); максимум 5 попыток.
- Ответ `201`: `challenge_id`, `expires_at`, `digits`; без seed и без подсказок о субъекте.

`POST /v1/mfa/challenges/{challenge_id}/verify`

- Body: `code`, `session_binding`; обязательный `Idempotency-Key`.
- Транзакция (READ COMMITTED + row locks, фиксированный порядок challenge → factor):
  1. Проверить service identity/scope и tenant.
  2. `SELECT … FOR UPDATE` challenge и factor.
  3. Проверить состояние, TTL, `session_binding`, `purpose`, число попыток.
  4. Расшифровать seed; вычислить TOTP для шагов `current-1 … current+1`; сравнить constant-time; выбрать максимальный совпавший шаг.
  5. Replay barrier: `UPDATE mfa_factors SET last_accepted_step=$step WHERE … AND (last_accepted_step IS NULL OR last_accepted_step < $step) RETURNING id`. Ноль строк → шаг уже использован → deny.
  6. `UPDATE mfa_challenges SET state='used', used_at=now() WHERE id=$id AND state='pending'`.
  7. Записать audit `verify_allowed` и idempotent-результат; `COMMIT`.
- Ответ `200`: `decision:"allow"`, `challenge_id`, `factor_id`, `purpose`, `verified_at`. Других 2xx для verify нет.
- Любой отказ (неверный код, истёкший/использованный challenge, несовпадение binding, replay) → `403 mfa_denied` с одинаковым телом. Причина пишется только в audit; превышение попыток/lockout → `429 rate_limited`.
- Concurrency: row lock на challenge сериализует попытки; условие `last_accepted_step < $step` — второй барьер. 100+ параллельных verify одного кода дают **не более одного** `allow`.
- Идемпотентный повтор с тем же ключом после успеха возвращает сохранённый результат, не принимая OTP повторно; идемпотентная запись живёт 15 минут. Запрос привязан к `challenge_id` через `request_hash`, поэтому повтор не может авторизовать другой challenge. RP обязан принимать `allow` только для той же своей сессии/`session_binding` и в ограниченном окне после `verified_at`; сохранённый ответ не продлевает это окно. Verifier RP-сессию не проверяет.
- Если клиент опоздал к шагу и `last_accepted_step` уже больше, код отклоняется: verifier не принимает «более старый» шаг, даже если он в окне. Это осознанный компромисс в пользу replay-защиты.
- Шаг, использованный при confirm, уже израсходован: первый login после enrollment требует следующего временного шага (до 30/60 секунд ожидания). Это ожидаемое поведение, а не ошибка.

Verifier не принимает `subject` в verify и не позволяет выбрать factor в v1: и то и другое берётся из challenge.

### 4.5. Идемпотентность

- `Idempotency-Key` обязателен для `confirm`, `verify`, `recovery-codes/redeem`, `factors/reset`; `revoke` естественно идемпотентен и ключ не требует.
- `Idempotency-Key` передаётся только заголовком; значение 16…128 символов `[A-Za-z0-9._~-]`, хэшируется SHA-256 и не логируется. Ключ из query/body игнорируется.
- Ключ scoped к `(tenant, service_client, route)`; хранение — 15 минут (не меньше TTL challenge + окно ретраев).
- Повтор с тем же ключом и тем же **семантическим** запросом (каноническая сериализация полей, не сырые байты) возвращает сохранённый статус/результат; повтор с тем же ключом и другим запросом → `409 idempotency_conflict`.
- Enrollment start исключён: сохранение seed ради повтора запрещено. Потеря ответа = новый enrollment.
- Идемпотентность не заменяет replay barrier: она защищает RP от сетевых повторов, а `last_accepted_step` — от повторного использования OTP.
- `revoke`/`reset` в той же транзакции инвалидируют все `pending` challenges фактора и его незавершённые enrollment; сохранённые результаты verify не продлеваются и не могут быть применены к новому challenge.

### 4.6. Rate limits

- Все счётчики — в PostgreSQL, инкремент в той же транзакции, что и попытка; upsert по bucket. Bucket key включает `tenant_id`; межтенантного смешивания нет.
- Значения по умолчанию (v0.2):
  - challenge: 5 неудачных `verify`; после — `locked` и `429`.
  - subject `(tenant, subject)`: 10 неудач/15 мин, 30/24 ч; lockout 15 мин → 1 ч → 24 ч; успешный `verify` сбрасывает счётчики субъекта, но не `last_accepted_step`.
  - enrollment: 5 `confirm`-попыток, не более 3 `pending`, 5 стартов/час на subject и 100 стартов/час на service client.
  - challenge creation: 30/мин на subject; не более 5 `pending` challenge на subject; сверх лимита — `429`, старые не продлеваются.
  - service client: 600 запросов/мин по умолчанию (диапазон 60…6000), burst 60; защита от перебора и DoS.
- После превышения — `429 rate_limited` с `Retry-After`; состояние lockout хранится в БД (15 мин → 1 ч → 24 ч).
- Недоступность хранилища счётчиков → `503`, не «пропустить проверку».
- Лимиты по IP не являются заменой: API только server-to-server, источник — service identity.
- Tenant может ужесточить значения в заданных пределах; ослабление ниже минимума запрещено.
- Старые окна и idempotency-записи удаляются фоновой задачей после истечения (не менее 48 часов для rate-limit истории); удаление не затрагивает audit.

### 4.7. Формат секретов и encryption at rest

**Алгоритм: AES-256-GCM из стандартной библиотеки Go** (ADR-003 относится к Rust vault; здесь другой домен).

Конверт:

```text
version(1) || key_id_len(1) || key_id || nonce(12) || ciphertext+tag(16)
```

- Nonce — 12 случайных байт из `crypto/rand` на каждое шифрование; ключ — 32 байта.
- AAD: `"mfa-secret-v1" || 0x00 || version || 0x00 || key_id || 0x00 || tenant_id || 0x00 || subject_id || 0x00 || record_kind || 0x00 || record_id || 0x00 || type || 0x00 || algorithm || 0x00 || digits || 0x00 || period`. `version` и `key_id` входят в AAD, поэтому подмена заголовка конверта не проходит проверку тега. `record_kind` — `enrollment` или `factor`; при активации секрет перешифровывается под AAD фактора. Поля разделены `0x00`; ни одно поле не содержит `0x00` (subject валидируется, ID — внутренние/hex), `digits`/`period` кодируются десятичным ASCII. Привязка не даёт переставить ciphertext между tenant/subject/записями.
- Лимит: не более 2³² шифрований на ключ (недостижимо при ожидаемом объёме); при приближении — ротация. Nonce не повторяется; повтор nonce — ошибка реализации, а не runtime-проверка.
- `key_id`: `[a-z0-9_-]{1,32}`; хранится рядом с ciphertext. Неизвестный `key_id` при чтении → отказ операции и `503`.
- Ключи — во внешнем файле (JSON/base64, mode 0600, без symlink), путь передаётся флагом; ключи не в БД, образе, env, логах и crash dump. Формат файла и загрузка — SRV-006. Файл версионирован: `version`, `active_secret_key_id`, `active_binding_key_id`, `keys[]` с полями `id`, `purpose` (`secret_aead` | `binding_hmac`), `status` (`active` | `retired`), `key_base64`, `created_at`, `retire_after`. `retired` — read-only: ключ ещё расшифровывает/проверяет старые записи, но не используется для новых. Ключи 32 байта; ровно один `active` на purpose; дубликаты `id` запрещены; файл ≤ 1 MiB, ключей ≤ 32, неизвестные поля отвергаются. Файл открывается с `O_NOFOLLOW`, проверяются regular file, владелец и mode 0600.
- Binding-HMAC использует отдельный ключ (не тот же, что AES-GCM) со своим `binding_key_id`; его ротация допускает overlap не меньше максимального TTL enrollment/challenge, после чего старый ключ удаляется вместе с истёкшими записями.
- Активный AES-ключ используется для новых записей; старые ключи остаются `retired`/read-only до перешифрования. Процедура rotation: добавить новый ключ → перешифровать строки → проверить отсутствие ссылок на старый → удалить старый. Startup fail-closed, если активный ключ отсутствует/невалиден/дублируется. Ключ, нужный для восстановления ещё не истёкшего бэкапа БД, не удаляется: retention ключей не короче retention бэкапов.
- Внешний secret manager (Vault/KMS и т.п.) в v1 не требуется и не выбирается этим ADR; его подключение — отдельный ADR с оценкой зависимости и offline-режима.
- Go не даёт гарантированного стирания копий в памяти; используется best-effort обнуление буферов, без заявлений о guaranteed zeroization.
- Plaintext seed существует только в памяти на время enrollment/verify; в БД, audit, логах, метриках, ответах (кроме одного enrollment start) и трейсах его нет.

**PostgreSQL-драйвер** в этом ADR не выбирается: SRV-002 обязан выбрать pinned, проверенный по supply-chain драйвер с `database/sql`, без ORM/codegen и без обязательного Redis. До dependency review реализация БД не начинается.

### 4.8. API surface

Базовый префикс — `/v1/mfa/`. Это канонический контракт; `PLAN §4.1` и `ADR-006 §4.9` приведены к нему.

| Метод | Путь | Scope | Назначение |
| --- | --- | --- | --- |
| POST | `/v1/mfa/enrollments` | `mfa.enroll` | начать enrollment, один раз вернуть URI |
| POST | `/v1/mfa/enrollments/{enrollment_id}/confirm` | `mfa.enroll` | подтвердить кодом, активировать фактор |
| POST | `/v1/mfa/challenges` | `mfa.verify` | создать challenge |
| POST | `/v1/mfa/challenges/{challenge_id}/verify` | `mfa.verify` | проверить код, вернуть решение |
| GET | `/v1/mfa/factors?subject=…` | `mfa.verify` | метаданные факторов, без seed |
| POST | `/v1/mfa/factors/{factor_id}/revoke` | `mfa.admin` | отозвать фактор |
| POST | `/v1/mfa/factors/reset` | `mfa.recovery` | reset по ADR-006 |
| POST | `/v1/mfa/recovery-codes` | `mfa.recovery` | выпустить коды (ADR-006) |
| POST | `/v1/mfa/recovery-codes/redeem` | `mfa.recovery` | погасить код (ADR-006) |
| GET | `/health/live` | — | liveness |
| GET | `/health/ready` | — | readiness |

- Только HTTPS и `Content-Type: application/json` для запросов с телом; иное → `415`.
- Тело ≤ 64 KiB; неизвестные поля и дубликаты ключей JSON отвергаются (нужен strict decoder, не только `DisallowUnknownFields`).
- OTP-код — JSON-строка ровно из 6 или 8 ASCII-цифр; числа, пробелы и Unicode-цифры отвергаются. OTP, `subject` (кроме списка факторов) и `session_binding` никогда не принимаются в query string или URL path.
- `enrollment_id`, `challenge_id`, `factor_id` — 32 lowercase hex; несовпадение формата → `400`, без отражения значения.
- `GET /v1/mfa/factors` принимает только `subject` в query; `subject` сравнивается как opaque bytes после percent-decoding; `+` не превращается в пробел. `tenant*` в query/body запрещён и отвергается, а не игнорируется молча. Ответ содержит только `factor_id`, `type`, `algorithm`, `digits`, `period`, `status`, `created_at`; seed, HMAC binding и внутренние ключи не возвращаются. Неизвестный subject → `200` с пустым `items`, а не `404`: иначе endpoint становится enumeration oracle.
- `Cache-Control: no-store` и `Pragma: no-cache` на всех ответах; CORS не поддерживается.
- Health endpoints не раскрывают детали; в production они ограничиваются сетью/инфраструктурой, liveness не зависит от БД, readiness проверяет БД, версию схемы, активный AES-ключ и binding-HMAC ключ.

### 4.9. Ошибки

Используется существующий RFC 9457 `application/problem+json` с `code` и `request_id`; `detail` — только статический текст.

| HTTP | `code` | Когда |
| --- | --- | --- |
| 400 | `invalid_request` | синтаксис, поля, формат ID/кода, дубликаты ключей |
| 401 | `service_unauthenticated` | валидный по цепочке сертификат не найден/отозван в БД; отсутствие или невалидность сертификата — TLS handshake failure |
| 403 | `scope_forbidden` | у service client нет scope |
| 403 | `mfa_denied` | неверный/просроченный/использованный код, replay, binding mismatch, нет активного фактора при создании challenge, неизвестный/чужой enrollment или challenge |
| 404 | `not_found` | неизвестный маршрут или factor id для revoke |
| 405 | `method_not_allowed` | метод не поддерживается маршрутом; заголовок `Allow` |
| 409 | `enrollment_conflict` | уже есть активный фактор |
| 409 | `idempotency_conflict` | тот же ключ, другой запрос |
| 413 | `body_too_large` | тело больше 64 KiB |
| 415 | `unsupported_media_type` | не JSON |
| 429 | `rate_limited` | превышен лимит или активен lockout; `Retry-After` |
| 503 | `unavailable` | БД, ключ, схема, audit или счётчик недоступны |
| 500 | `internal_error` | непредвиденная ошибка после redaction |

- `mfa_denied` не различает «нет субъекта», «нет фактора», «неверный код», «истёк» и «использован»; неизвестный и чужой enrollment/challenge дают тот же ответ. Причина — только в audit; превышение попыток и lockout — `429`, не `403`.
- `revoke` идемпотентен: повторный вызов для уже отозванного фактора возвращает `200` с текущим статусом; неизвестный `factor_id` — `404`.
- Никакой ответ не содержит seed, OTP, `session_binding`, отпечаток сертификата, SQL, stack trace или внутренние ID БД.
- Для `verify` клиент обязан считать успехом только `200` с `decision:"allow"`; любой другой ответ — отказ. Для остальных endpoints успех определяется статусом и схемой OpenAPI.

### 4.10. Схема данных и миграции

Концептуальные таблицы (точные типы, индексы и имена — SRV-002; здесь обязательные инварианты):

- `mfa_tenants(id, slug, status, issuer, config, audit_retention_days, created_at, updated_at)`.
- `mfa_service_clients(id, tenant_id, name, status, created_at, disabled_at)` + `mfa_service_scopes(service_client_id, scope)`.
- `mfa_client_certificates(id, service_client_id, fingerprint_sha256, not_before, not_after, status)`; `UNIQUE(fingerprint_sha256)`.
- `mfa_subjects(tenant_id, subject_id, status, created_at)`; `PRIMARY KEY (tenant_id, subject_id)`; `subject_id` — opaque `subject` из запроса (не email/account); создаётся enrollment start, не challenge.
- `mfa_factors(id, tenant_id, subject_id, type, algorithm, digits, period, secret_ciphertext, key_id, last_accepted_step, status, created_at, updated_at, revoked_at)`; composite FK на subject; partial unique index на один активный TOTP-фактор.
- `mfa_enrollments(id, tenant_id, subject_id, algorithm, digits, period, secret_ciphertext, key_id, session_binding_hash, binding_key_id, state, attempts, expires_at, created_at, confirmed_at, factor_id)`.
- `mfa_challenges(id, tenant_id, subject_id, factor_id, purpose, session_binding_hash, binding_key_id, state, attempts, expires_at, created_at, used_at)`.
- `mfa_idempotency(tenant_id, service_client_id, key_hash, route, request_hash, status, result, created_at, expires_at)`; `PRIMARY KEY (tenant_id, service_client_id, key_hash, route)`; `result` не содержит секретов; `request_hash` считается по канонической семантической сериализации полей, а не по сырому телу.
- `mfa_rate_limits(bucket_kind, bucket_key_hash, window_start, count, locked_until)`; `PRIMARY KEY (bucket_kind, bucket_key_hash, window_start)`.
- `mfa_audit(...)` — append-only, см. §4.11.
- Recovery-таблицы и reset-token — в ADR-006; они используют те же `tenant_id`/`subject_id` и key infrastructure.

Обязательные ограничения:

- Все дочерние таблицы содержат `tenant_id` и composite FK `(tenant_id, subject_id)` / `(tenant_id, factor_id)`; запрос без `tenant_id` запрещён code review и тестами.
- `ON DELETE RESTRICT` для субъектов/факторов/аудита; каскадное удаление исторических данных запрещено.
- CHECK на длины, enum-значения, `digits ∈ {6,8}`, `period ∈ {30,60}`, `state`, `type='totp'`, `last_accepted_step >= 0`, `audit_retention_days ∈ [90,2555]`.
- Уникальность активного фактора и активного набора recovery codes — partial unique index.
- Все timestamps — `timestamptz` в UTC; приложение сравнивает время с БД/`time.Now().UTC()`, тесты используют инъекцию часов.
- `mfa_idempotency` и `mfa_rate_limits` не содержат секретов и не продлеваются при повторных запросах сверх указанных TTL.

**Миграции:**

- Forward-only, версионированные, с checksum; `schema_migrations(version, checksum, applied_at)`.
- Отдельный `cmd/authenticator-migrate` с `pg_advisory_lock`; приложение при старте только проверяет ожидаемую версию и падает при несовпадении. Автоматических миграций на старте нет.
- Down-миграции допустимы только для локальной разработки; production rollback = roll forward. Миграция, удаляющая/обнуляющая `last_accepted_step`, `used_at`, `revoked_at` или audit, запрещена.
- Expand/contract для несовместимых изменений; zero-downtime не обещается, maintenance window допустим.
- SQL только parameterized; динамические идентификаторы не принимаются из запроса.
- Тесты: upgrade с пустой схемы, повторный запуск (idempotent), падение на середине, несовпадение checksum, неизвестная версия, сохранность replay/audit данных.

### 4.11. Аудит, логи, метрики

События: `service_auth_denied`, `enrollment_started`, `enrollment_confirmed`, `enrollment_failed`, `challenge_created`, `verify_allowed`, `verify_denied`, `rate_limited`, `factor_revoked`, `factor_reset`, `key_unavailable`, `schema_mismatch`.

Поля: `tenant_id`, `subject_id` (opaque ID, не email/account), `service_client_id`, `factor_id`, `challenge_id`, `purpose`, `decision`, `reason` (enum), `request_id`, `created_at`. Для recovery — поля ADR-006.

Запрещено: OTP, seed, `otpauth_uri`, `session_binding`, `Idempotency-Key`, reset/pepper keys, client certificate, произвольный пользовательский текст, PII в метриках.

- `mfa_audit` append-only; отдельная роль БД только на INSERT/SELECT; UPDATE/DELETE запрещены.
- Запись аудита успешного решения — в той же транзакции; сбой audit → откат и `503`.
- Access log: только шаблон маршрута, статус, длительность и `request_id`; без query, body, заголовков, subject/tenant.
- Метрики: счётчики по route/status/decision/reason, latency, DB pool; без tenant/subject/challenge/factor labels.
- Retention: `audit_retention_days` per tenant, default **365**, min **90**, max **2555**; удаление — только отдельной maintenance-ролью после истечения retention; до `SRV-009` автоматического удаления нет.
- Hash-chaining в v1 не реализуется: append-only роль и внешний log shipping (обязанность deployment) дают лучшую tamper-evidence, чем цепочка без внешнего anchor. Опция hash-chain + external anchoring — отдельное решение в `SRV-009`.
- Экспорт audit во внешнее immutable-хранилище — обязанность deployment; verifier не содержит встроенного remote sink и не отправляет audit по сети.

### 4.12. Конфигурация и fail-closed

Обязательные параметры: `-listen`, `-tls-cert`, `-tls-key`, `-client-ca`, `-db-dsn-file`, `-key-file`, таймауты, TTL, лимиты, `issuer` per tenant в БД.

- Секреты (DSN с паролем, keys) — только из файлов mode 0600; не из argv/env, чтобы не попадать в `ps`/дампы.
- `-db-dsn-file` обязан содержать `sslmode=verify-full` и CA для проверки сервера; production отвергает `disable`/`allow`/`prefer`/`require` без проверки сертификата. Соединение к PostgreSQL — только TLS.
- Роли БД: приложение — DML на нужных таблицах, без DDL и без superuser; миграции — отдельная роль; audit — INSERT/SELECT без UPDATE/DELETE. SQL schema-qualified; `search_path` не используется как граница безопасности.
- Production-режим — по умолчанию; `-dev` разрешает только loopback и явные dev-флаги. Не-loopback plaintext-listener и `-insecure-listen-any` в production невозможны.
- Startup отказывает, если: нет TLS material, пуст client CA, недоступна БД, неизвестная версия схемы, нет активного AES-ключа или binding-HMAC ключа, ключ не 32 байта, дубликат `key_id`/`binding_key_id`, небезопасные права на файлы. TLS key, DSN-файл и key file должны быть mode 0600, принадлежать service user и не быть symlink.
- Readiness: `SELECT 1`, версия схемы, активный AES-ключ и binding-HMAC ключ; liveness — только процесс. При shutdown readiness переходит в not-ready до прекращения приёма запросов (существующий `SetDraining`).
- Таймауты: HTTP как в SRV-001; контекст БД ≤ 2 с, транзакция verify ≤ 3 с, body ≤ 64 KiB, пул соединений ограничен.
- Ошибки конфигурации логируются без значений секретов и без DSN.

### 4.13. HA и эксплуатация

- Приложение stateless; всё состояние в PostgreSQL; несколько реплик работают без sticky sessions.
- Row locks и атомарный `UPDATE … WHERE` — единственный источник истины для replay; уникальные индексы защищают от дублей, advisory locks — только миграции.
- Часы синхронизируются NTP; дрейф > периода шага — эксплуатационный инцидент (TOTP зависит от времени).
- Бэкапы БД содержат только ciphertext; ключи хранятся отдельно; restore-тесты обязательны до production. Ключи, необходимые для чтения бэкапов в пределах retention, сохраняются даже после ротации.
- PostgreSQL — граница доступности: при отказе MFA не выполняется (fail-closed). Это принятое ограничение, а не баг.
- Никакого Redis, ORM, JWT-библиотек, внешних IAM/SDK как обязательных зависимостей.

### 4.14. Sequence diagrams

Enrollment:

```text
RP backend                     Verifier                     PostgreSQL
    │  POST /enrollments           │                             │
    │  (mTLS, subject, account)    │── generate 20-byte seed ───▶│ pending row (AEAD)
    │◀── 201 {enrollment_id, uri} ─│                             │
    │  (передаёт uri пользователю; не логирует)                    │
    │  POST /confirm {code}        │                             │
    │─────────────────────────────▶│── verify TOTP, re-encrypt ─▶│ active factor
    │◀── 200 {factor_id} ──────────│    seed under factor AAD     │
```

Verify:

```text
RP backend                     Verifier                     PostgreSQL
    │  POST /challenges            │                             │
    │  (subject, purpose, binding) │── create challenge ────────▶│ pending
    │◀── 201 {challenge_id} ───────│                             │
    │  пользователь вводит код     │                             │
    │  POST /verify {code, binding}│                             │
    │─────────────────────────────▶│── lock challenge+factor ───▶│
    │                              │── TOTP ±1, constant-time    │
    │                              │── last_accepted_step < step │
    │                              │── mark used, audit ────────▶│
    │◀── 200 {decision:"allow"} ───│                             │
    │  RP сам повышает свою сессию │                             │
```

Отказ/недоступность:

```text
RP backend                     Verifier
    │  POST /verify                │
    │─────────────────────────────▶│── DB/key error → 503, без allow
    │◀── 403/429/503 ──────────────│    и без частичных изменений
    │  RP не повышает сессию       │
```

### 4.15. Provisioning и bootstrap

- В v1 **нет** HTTP admin/provisioning API: tenant, service client, scopes и certificate fingerprints создаются только operator-run SQL-миграцией или offline admin-командой с доступом к БД.
- Key file создаётся и ротируется отдельно, offline, оператором с доступом к файловой системе; SQL/DB-роль не может его прочитать или изменить. Порядок: сначала key file, затем запись в БД, которая на него ссылается.
- Provisioning идемпотентен, выполняется отдельной ролью, логируется без секретов и не включает default tenant/client/certificate/key. Пустая БД не становится ready автоматически.
- Изменения scopes и отзыв сертификатов/факторов аудируются; отзыв действует немедленно. Offline admin не слушает сеть и не принимает секреты из argv/env.
- Самоподписка tenant, self-service выдача сертификатов и «первый клиент по умолчанию» запрещены: это создало бы второй путь аутентификации в обход mTLS.

## 5. Обязательные негативные и конкурентные тесты

1. Cross-tenant: service A с subject/factor из B → нет данных, единый отказ; `tenant_id` из body/query отвергается.
2. Сертификат отсутствует/просрочен/без EKU → TLS handshake failure; валидный, но неизвестный/отозванный в БД → `401` до разбора body. TLS resumption не обходит проверку сертификата; отзыв проверяется на каждом запросе.
3. Нет scope → `403`; scope другого tenant не помогает.
4. 100+ параллельных verify одного кода → не более одного `allow`.
5. Повтор того же шага в новом challenge → отказ; более старый шаг после нового → отказ.
6. Истёкший/использованный challenge, чужой `session_binding`, неверный `purpose` → `403 mfa_denied`.
7. Повтор confirm того же enrollment → нет второго фактора; истёкший TTL и 5 неудач → `locked`.
8. Идемпотентный повтор verify/confirm с тем же ключом → тот же результат без повторного принятия OTP; другой запрос с тем же ключом → `409`.
9. Enrollment start дважды → два pending, ровно один confirm активирует фактор; активный фактор блокирует повторный start.
10. БД/ключ/audit/счётчик недоступны → `503`, `allow` невозможен, частичных изменений нет.
11. Rate limit: N неудач → `429`; состояние сохраняется после рестарта; параллельные попытки не обходят лимит.
12. Enumeration: неизвестный subject при создании challenge/verify, неверный код и disabled factor дают одинаковый статус/`code`/тело; `GET /factors` для неизвестного subject — `200` с пустым `items`; сравнение TOTP — constant-time, выравнивание времени — best-effort.
13. Логи/audit/метрики/ошибки не содержат OTP, seed, URI, binding, idempotency key, сертификат.
14. Подмена ciphertext/AAD/`key_id` или binding-HMAC → ошибка/отказ; неизвестный `key_id` → `503`.
15. Rotation: старый ключ `retired`/read-only, новые записи под новым; после перешифрования старый удаляется; отсутствие активного ключа → startup fail.
16. Миграции: upgrade с нуля, повторный запуск, падение посередине, checksum mismatch, неизвестная версия → fail-closed.
17. JSON: неизвестные поля, дубликаты ключей, неверный content-type, тело > 64 KiB, OTP числом/с пробелами → `400/413/415`, без секретов в ответе.
18. Clock boundaries: шаг 0, отрицательное время, максимальный `u64`/`int64`, period 30/60, digits 6/8.
19. Health: liveness не зависит от БД; readiness отражает БД/ключ/схему и drain; детали не раскрываются.
20. TLS: без client cert/со слабой версией → handshake failure; plaintext listener в production-конфигурации невозможен.

## 6. Рассмотренные альтернативы

| Альтернатива | Почему отклонена |
| --- | --- |
| Bearer-токены/API keys вместо mTLS | Второй auth path, риск утечки и сложная ротация; mTLS уже требует инфраструктура RP |
| Tenant из тела/query | Прямой путь к cross-tenant IDOR (T-S1) |
| Stateless verify/JWT-решение | Нельзя обеспечить однократность шага, rate limit и отзыв без БД |
| In-memory rate limit/cache | Не работает между репликами и обходится рестартом |
| Redis как обязательная зависимость | Дополнительная инфраструктура и TCB; PostgreSQL достаточен |
| Signed assertion/JWT для RP | Лишняя ключевая инфраструктура и соблазн считать его сессией; ответа по mTLS достаточно |
| Plaintext seeds или шифрование ключом из БД | Дамп БД = готовые seeds (T-S5) |
| Клиентский seed при enrollment | Слабый RNG и доверие клиенту; серверный CSPRNG обязателен |
| HOTP в verifier v1 | Не нужен для MFA login, усложняет replay/счётчики; отложен |
| ORM/миграции на старте | Скрытые изменения схемы, гонки, лишние зависимости |
| Reverse proxy с mTLS-терминацией «по заголовку» | Заголовок подделывается; нужен отдельный ADR с доверенным прокси |
| Argon2id для OTP/секретов БД | Не защищает от дампа без ключа; дорогой per-request KDF — DoS |

## 7. Последствия

**Положительные:** однозначный контракт для SRV-002…009; tenant isolation и replay защищены схемой и транзакциями; RP не может случайно «повысить» сессию по не-`allow`; seed не хранится в plaintext; несколько реплик безопасны.

**Отрицательные:** нужна PKI/mTLS-инфраструктура и ротация сертификатов; PostgreSQL — единая точка отказа (fail-closed); enrollment требует передачи seed через RP; добавляется зависимость от PostgreSQL-драйвера (выбор — SRV-002); TOTP остаётся уязвим к фишингу.

**Остаточные риски:** компрометация RP/service identity даёт доступ к данным своего tenant; компрометация БД вместе с key file раскрывает seeds; компрометация хоста — plaintext в памяти; DoS на БД блокирует MFA; ошибки эксплуатации PKI/ключей; отсутствие независимого security review (`QA-002`) и production-аудита.

## 8. Решения по открытым вопросам

Вопросы v0.1 закрыты 22.11.2026. Значения ниже — часть контракта; их изменение требует новой версии ADR.

1. **TTL, лимиты, lockout.** Enrollment TTL 600 с, 5 `confirm`-попыток, 3 `pending`, 5 стартов/час на subject и 100/час на service client. Challenge TTL 120 с (диапазон 30…300), 5 попыток, 5 `pending` на subject, 30 созданий/мин на subject. Subject: 10 неудач/15 мин и 30/24 ч, lockout 15 мин → 1 ч → 24 ч. Service client: 600 запросов/мин (60…6000), burst 60. Все счётчики — в PostgreSQL; успешный `verify` сбрасывает счётчики субъекта, но не replay barrier.
2. **Idempotency-Key.** Обязателен для `confirm`, `verify`, `recovery-codes/redeem`, `factors/reset`; для `revoke` опционален; для enrollment start и challenge creation не применяется. Хранение 15 минут, ключ scoped к `(tenant, service_client, route)`, `request_hash` — каноническая семантическая сериализация; для `verify` включает `challenge_id`. Рекомендуется 128-битный случайный ключ.
3. **Token-режим без клиентских сертификатов.** В v1 не поддерживается. mTLS-only; среды без сертификатов требуют отдельного ADR, а не ослабления текущего контракта.
4. **Key provider.** В v1 — локальный versioned JSON key file с AES-256-GCM и отдельным binding-HMAC ключом, mode 0600, owner-check, `O_NOFOLLOW`, без env/argv. Внешний secret manager — отдельный ADR. AES-ротация: active → retired/read-only → re-encrypt → проверка ссылок → удаление после retention бэкапов. Binding-ротация: overlap не меньше максимального TTL enrollment/challenge, затем удаление старого ключа.
5. **PostgreSQL-драйвер.** В ADR-005 не выбирается. `SRV-002` обязан выбрать pinned драйвер для `database/sql` после dependency review: лицензия, полный транзитивный граф, отсутствие ORM/codegen/cgo, offline build, checksums. Migration runner — собственный `cmd/authenticator-migrate`, без ORM и без автоматических миграций на старте.
6. **HOTP в verifier.** В v1 отсутствует; поддерживается только TOTP. HOTP остаётся desktop-функцией. Добавление в verifier требует отдельного ADR с моделью counter/replay.
7. **Retention аудита.** `audit_retention_days` per tenant: default 365, min 90, max 2555. Append-only роль; удаление только maintenance-ролью после retention. Hash-chaining в v1 не реализуется; tamper-evidence — append-only + внешний log shipping. Детали — `SRV-009`.
8. **Несколько tenant на service client.** Ровно один tenant на клиент/сертификат. RP с несколькими tenant получает отдельные клиенты и сертификаты.
9. **`period` и окно.** Только `period` 30 или 60, окно ±1 шаг, без настройки окна в v1. Серверное время — авторитет; NTP обязателен, дрейф больше шага — инцидент.
10. **Ответ `verify`.** Возвращаются `decision`, `challenge_id`, `factor_id`, `purpose`, `verified_at`. HMAC(binding) и seed не возвращаются: RP уже знает binding, а хэш не даёт дополнительной проверки и увеличивает корреляцию.

## 9. Критерии приёмки

- [x] ADR reviewed (author-side, §10), открытые вопросы §8 закрыты, статус переведён в `Accepted v0.2`.
- [ ] `api/openapi.yaml` и contract tests обновлены **до** handlers (SRV-008) и соответствуют §4.8/§4.9.
- [ ] SRV-002…SRV-006 реализуют схему, mTLS/scopes, enrollment, verify/replay и AEAD/rotation; тесты §5 проходят, включая конкурентные и fail-closed.
- [ ] В БД и логах нет plaintext seeds/OTP; проверка дампа и grep-тесты приложены.
- [ ] `T-S1`…`T-S17` в [threat model](../threat-model.md) связаны с конкретными тестами; `T-S17` подтверждает, что TOTP не назван phishing-resistant.
- [ ] Отдельно подтверждено: verifier не создаёт RP-сессию, не выполняет identity proofing, не отдаёт seed после enrollment и не работает fail-open.
- [ ] Независимый security review (`QA-002`) пройден до заявления о production readiness.

`Accepted v0.2` означает принятое архитектурное решение, а не реализацию или production readiness.

## 10. Security review

Авторский adversarial review выполнен 22.11.2026; полный отчёт и остаточные риски — [`security/reviews/0005-verifier-review.md`](../reviews/0005-verifier-review.md). Это **не** независимый review `QA-002`.

### 10.1. Находки и решения

| ID | Находка | Решение в v0.2 |
| --- | --- | --- |
| F-1 | Tenant из body/query → cross-tenant IDOR | Tenant только из mTLS-сертификата; `tenant*` отвергается; composite FK и cross-tenant тесты (§5.1) |
| F-2 | Повторное использование OTP/шага | Row locks + `UPDATE … WHERE last_accepted_step < $step`; replay barrier раньше выдачи `allow` (§4.4, §5.4/5.5) |
| F-3 | Offline-подбор `session_binding` по дампу БД | HMAC-SHA-256 с отдельным binding-ключом и tenant в сообщении; ключ не пересекается с AES (§4.3/4.7) |
| F-4 | Ротация ключей ломает restore/бэкапы | Retention ключей не короче retention бэкапов; AES re-encrypt, binding overlap по TTL (§4.7) |
| F-5 | Дамп БД + key file раскрывает seeds | Ключи вне БД/образа; файл 0600; остаточный риск компрометации хоста/файла зафиксирован (§7/§10.3) |
| F-6 | Audit можно изменить при доступе к БД | Append-only роль, внешний log shipping; hash-chain без anchor не обещается (§4.11) |
| F-7 | Enumeration по ошибкам/таймингам | Единый `403 mfa_denied`, одинаковое тело; dummy-работа на неизвестном challenge — best-effort (§4.9, §5.12) |
| F-8 | Idempotent replay для другого challenge | `request_hash` включает `challenge_id`; другой запрос — `409` (§4.5, §5.8) |
| F-9 | Seed/URI утекает через логи или кэш | URI один раз, `no-store`/`Pragma`, body не логируется; RP обязан не логировать (§4.3/4.8) |
| F-10 | DB-трафик без проверки сервера | `sslmode=verify-full` + CA; least-privilege роли; отдельная migration/audit роль (§4.12) |
| F-11 | Provisioning становится вторым auth path | Нет HTTP admin API; operator SQL/offline admin; нет default tenant/client/key (§4.15) |
| F-12 | DoS через challenge/rate-limit/БД | Лимиты в PostgreSQL, 5 pending challenge, body 64 KiB, timeouts, fail-closed (§4.6/4.12) |
| F-19 | TLS resumption пропускает проверку client cert | Session tickets/resumption отключены; fingerprint/status проверяются на каждом запросе (§4.2) |
| F-20 | Смешение `subject` и `account` / PII в аудите | `subject_id` — opaque subject из запроса, `account` не сохраняется; audit без email (§4.3/4.10) |

### 10.2. Связь угроз и тестов

| Угроза | Решение | Тест |
| --- | --- | --- |
| `T-S1` tenant IDOR | §4.2, §4.10 | §5.1 |
| `T-S2` replay шага | §4.4 step 5, §4.10 | §5.4, §5.5 |
| `T-S3` перебор | §4.6 | §5.11 |
| `T-S4` чужой challenge/binding | §4.3, §4.4 | §5.6 |
| `T-S5` plaintext seeds в дампе | §4.7 | §5.14, §5.15 |
| `T-S6` скомпрометированная service identity | §4.2 | §5.2, §5.3 |
| `T-S7` fail-open | §4.1, §4.6, §4.12 | §5.10 |
| `T-S8` enrollment без доверенной сессии | §4.3 | §5.7, §5.9 |
| `T-S9` recovery codes | ADR-006 (вне scope) | ADR-006 §5 |
| `T-S10` enumeration | §4.9 | §5.12 |
| `T-S11` секреты в логах | §4.11 | §5.13 |
| `T-S12` key rotation | §4.7 | §5.14, §5.15 |
| `T-S13` MITM | §4.2 | §5.20 |
| `T-S14` миграции/rollback | §4.10 | §5.16 |
| `T-S15` DoS | §4.6, §4.12 | §5.11, §5.19 |
| `T-S16` high-cardinality метрики | §4.11 | §5.13 |
| `T-S17` ложное «phishing-resistant» | §2, §4.1 | review документации |

### 10.3. Остаточные риски

- Компрометация RP/service identity даёт доступ к данным своего tenant.
- Компрометация БД вместе с key file раскрывает seeds; host compromise — plaintext в памяти.
- PostgreSQL — единая точка отказа: при недоступности MFA не выполняется (fail-closed).
- Audit без внешнего anchor не является криптографически tamper-proof; нужен внешний collector.
- TOTP остаётся уязвим к фишингу и real-time relay; WebAuthn — отдельный фактор.
- Нет независимого security review и production-аудита; `QA-002` обязателен.

## 11. Changelog

| Дата | Версия | Изменение |
| --- | --- | --- |
| 20.11.2026 | 0.1 | Proposed: mTLS, tenant, enrollment/challenge/verify, replay, keys, schema, API, tests |
| 22.11.2026 | 0.2 | Accepted (architecture): закрыты §8, добавлены rate-limit defaults, key file/rotation, DB TLS/roles, provisioning, audit retention, author-side security review (§10; не независимый) |
