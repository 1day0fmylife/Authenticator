# ADR-006: Recovery codes и managed factor reset

**Статус:** Proposed v0.1, 19.11.2026. Не принят и не является разрешением на реализацию: до `Accepted` нужен security review и фиксация параметров из раздела «Открытые вопросы».
**Связанные документы:** [TODO](../../TODO.md) (`REC-002`, `REC-003`, `SRV-007`), [ADR-001](0001-independence.md), [ADR-003](0003-crypto.md), [ADR-004](0004-vault.md), [ADR-005](0005-verifier.md) (proposed), [recovery.md](../../docs/architecture/recovery.md), [device-lifecycle.md](../../docs/architecture/device-lifecycle.md), [recovery threat model](../recovery-threat-model.md), [threat-model.md](../threat-model.md) (`T-S9`).

## 1. Контекст

`SRV-007` требует безопасного восстановления доступа к managed MFA, когда пользователь потерял устройство или все факторы, и при этом запрещает обход MFA и экспорт чужих TOTP-seed. Документы [recovery.md](../../docs/architecture/recovery.md) и [device-lifecycle.md](../../docs/architecture/device-lifecycle.md) фиксируют модель, но не параметры. Без них нельзя писать ни схему БД, ни OpenAPI, ни handlers.

Восстановление десктопного vault (парольная фраза, portable backup) — отдельный домен, он определён в [ADR-004](0004-vault.md) и здесь не меняется.

## 2. Scope и non-goals

**В scope:** жизненный цикл набора recovery codes, атомарное погашение, выдаваемый reset-authorization, отзыв managed-фактора и повторный enrollment, dual control, поля аудита, rate limit, fail-closed.

**Вне scope (обязанности relying party, не verifier):**

- identity proofing и проверка документов;
- уведомления пользователю и администратору (у verifier нет контактных данных и не должно появляться);
- отзыв сессий и cookies на стороне RP;
- любой экспорт, расшифровка или восстановление существующего TOTP-seed;
- UI администратора.

Verifier не объявляет сессию пользователя аутентифицированной (ADR-001): он выдаёт ограниченную авторизацию на повторный enrollment, решение о сессии принимает RP.

## 3. Trust boundaries

| ID | Граница | Доверие |
| --- | --- | --- |
| TB-R1 | RP backend → verifier | mTLS/service identity; tenant выводится только из credential, никогда из body/query |
| TB-R2 | Пользователь → RP (ввод кода) | Не доверяем: нормализация, лимиты, одинаковые ошибки |
| TB-R3 | Verifier → PostgreSQL | БД недоверенная на чтение: в ней нет plaintext-кодов и seed |
| TB-R4 | Key store → verifier | Pepper-ключи вне БД и образа; неизвестный `key_id` → fail-closed |
| TB-R5 | RP → подтверждение identity proofing | Verifier доверяет assertion RP так же, как его service credential, и не проверяет личность сам |

## 4. Решение

### 4.1. Формат кодов

- 100 бит энтропии из CSPRNG (20 символов Base32), 10 кодов на набор.
- Алфавит Crockford Base32 (без `I`, `L`, `O`, `U`) — снижает ошибки ручного ввода; ввод нормализуется: uppercase, пробелы и дефисы удаляются, `I`/`L` → `1`, `O` → `0`, остальные символы → отказ.
- Канонический вывод: 5 групп по 4 символа через дефис, показывается один раз, ответ с `Cache-Control: no-store`.
- Один активный набор на subject. Генерация нового набора в одной транзакции отзывает предыдущий; неиспользованные коды старого набора становятся недействительными.
- Генерация требует свежей аутентификации пользователя в RP: RP передаёт step-up assertion (opaque ref + timestamp), verifier проверяет её наличие и свежесть по политике tenant, но не проверяет личность сам.
- Срок действия по умолчанию не ограничен (коды должны работать офлайн); отзыв — только перегенерация или reset.

### 4.2. Хранение verifier'ов

- `verifier = HMAC-SHA-256(pepper_key[key_id], tenant_id || 0x00 || subject_id || 0x00 || code_bytes)`.
- Контекст tenant+subject исключает перенос digest между арендаторами и субъектами.
- HMAC, а не Argon2id: код имеет 100 бит энтропии, а per-attempt Argon2id был бы вектором DoS на `/redeem`; Argon2id остаётся для низкоэнтропийных паролей (ADR-003).
- Pepper-ключ хранится вне БД/образа, с `key_id`; отсутствие или неизвестный `key_id` → отказ старта и отказ операции.
- В БД нет plaintext-кодов; plaintext не пишется в логи, audit, метрики, трассировки и ответы об ошибках.

### 4.3. Проверка кода

- Выборка активного набора по `(tenant_id, subject_id)`.
- Проверяются **все** неиспользованные кандидаты в фиксированном цикле constant-time сравнением без раннего выхода, чтобы время не зависело от позиции совпадения.
- Ошибки «нет такого кода», «код использован», «набор отозван» снаружи неразличимы (одинаковый `problem+json` и близкая latency).

### 4.4. Атомарное однократное погашение

```text
BEGIN
  SELECT ... FROM recovery_set
   WHERE tenant_id=$1 AND subject_id=$2 AND revoked_at IS NULL
   FOR UPDATE;                                  -- сериализует погашения субъекта
  -- constant-time проверка всех неиспользованных кодов
  UPDATE recovery_code
     SET consumed_at = now(), consumed_by_request = $req
   WHERE id = $code_id AND consumed_at IS NULL
  RETURNING id;                                 -- 0 строк => гонку выиграл другой запрос
  INSERT INTO reset_token (...);
  COMMIT;
```

- Изоляция `READ COMMITTED` + row lock на наборе; вторым барьером служит `UPDATE ... WHERE consumed_at IS NULL`.
- 100+ параллельных попыток одним кодом: успех ≤ 1, остальные получают тот же generic-отказ.
- Любая ошибка БД → `503 problem+json`, без токена и без частичных изменений (единая транзакция).
- Неудачная попытка пишется в rate-limit счётчик и audit, но не раскрывает причину.

### 4.5. Reset-authorization

- Opaque токен 256 бит из CSPRNG, выдаётся один раз, хранится как `HMAC-SHA-256(token_key[key_id], "reset-token" || 0x00 || token_bytes)` — отдельный домен от recovery-code verifier'ов при том же механизме `key_id`.
- TTL 10 минут, single-use, scope `factor_reset`; привязан к `tenant_id`, `subject_id`, `recovery_set_id` и, если RP его передал, к `session_binding`.
- Авторизует только: отзыв указанных managed-факторов и старт нового enrollment (SRV-004). Не является сессией, не даёт доступа к seed и не продлевается.
- Повторное использование, истечение и чужой binding → одинаковый отказ.

### 4.6. Managed reset и dual control

- Поток: запрос от service identity → (опционально) identity proofing в RP → approval evidence → verifier проверяет политику tenant → reset-authorization → новый enrollment → отзыв старого фактора → audit.
- Политика tenant (нужен ли dual control) хранится в конфигурации tenant в БД, не в теле запроса.
- При dual control `approver_service_id != requester_service_id`; self-approval отклоняется verifier'ом, а не только UI.
- Замена фактора создаёт **новый** credential id; отозванный фактор никогда не реактивируется.
- Revocation сессий RP — на стороне RP; verifier лишь фиксирует отзыв фактора и обязан явно возвращать, что сессии не отозваны.

### 4.7. Rate limit (PostgreSQL, fail-closed)

- Счётчики в БД (никаких in-memory), инкремент в той же транзакции, что и попытка.
- Лимиты: ≤ 5 попыток на `(tenant, subject)` за 15 минут; ≤ 10 за сутки; после 5 неудач — lockout 15 минут → 1 час → 24 часа.
- Отдельный бюджет на service identity против enumeration-перебора.
- Недоступность хранилища счётчиков → отказ (`503`), не «пропустить и продолжить».

### 4.8. Аудит

- Append-only события: `set_generated`, `set_revoked`, `code_redeemed`, `redeem_failed`, `token_issued`, `token_used`, `factor_revoked`, `enrollment_started`, `enrollment_confirmed`, `approval_recorded`.
- Поля: tenant, внутренний subject ref, actor service id, approver service id, approval ref, reason code (enum), request id, outcome, timestamp.
- Запрещено: коды, токены, seed, пароли, произвольный пользовательский текст, PII, high-cardinality labels в метриках.
- Append-only и ограниченные роли записи; hash-chaining/retention — SRV-009.

### 4.9. API surface (кандидат; фиксируется в OpenAPI до handlers)

| Метод | Путь | Назначение |
| --- | --- | --- |
| POST | `/v1/mfa/recovery-codes` | выпустить набор, вернуть коды один раз |
| POST | `/v1/mfa/recovery-codes/redeem` | погасить код, получить reset-authorization |
| GET | `/v1/mfa/factors?subject=…` | список managed-факторов (только метаданные); общий контракт с ADR-005 |
| POST | `/v1/mfa/factors/{factor_id}/revoke` | отозвать фактор; общий контракт с ADR-005 |
| POST | `/v1/mfa/factors/reset` | подтвердить reset-authorization и начать enrollment |

Правила: tenant только из service identity; ни один endpoint не возвращает существующий seed; все ответы — `problem+json` с устойчивыми `code`; имена/схемы фиксируются в `api/openapi.yaml` (SRV-008) до реализации. mTLS/scopes, tenant resolution, коды ошибок, аудит и key infrastructure наследуются из [ADR-005](0005-verifier.md); recovery-таблицы используют те же `tenant_id`/`subject_id` и не вводят второй способ аутентификации сервиса.

### 4.10. Схема и миграции

- Версионированные forward-only миграции; down-migration **никогда** не обнуляет `consumed_at` и не снимает `revoked_at`.
- Ограничения: FK на tenant/subject, `UNIQUE (set_id, code_index)`, partial unique index на один активный набор, CHECK на длину verifier.
- Fixture-тесты upgrade/rollback входят в SRV-002.

### 4.11. Fail-closed

- Нет pepper-ключа, неизвестный `key_id`, недоступна БД, сбой счётчика, ошибка проверки → отказ без токена и без изменения состояния.
- Startup проверяет наличие ключей и соответствие `key_id`; иначе не стартует (SRV-006).
- RP обязан трактовать любой не-`success` как «восстановление не выполнено»; API-семантика не оставляет двусмысленности.

## 5. Негативные сценарии (обязательные тесты)

1. Использованный код → отказ; повторное использование невозможно.
2. 100+ параллельных `redeem` одним кодом → ровно один успех.
3. Код из чужого tenant/subject → отказ без раскрытия существования.
4. Отозванный набор → все коды недействительны.
5. Просроченный/повторно использованный reset-authorization → отказ.
6. Reset-authorization с чужим `session_binding` → отказ.
7. Self-approval при dual control → отказ; отдельный approver → успех.
8. Недоступность БД/key store → `503`, состояния не изменены.
9. Превышение лимита попыток → lockout, затем восстановление по времени.
10. Код в нижнем регистре/с пробелами/дефисами → принимается; `I`/`O`/`L` нормализуются; прочие символы → отказ.
11. Grep логов/audit/ответов → нет кодов, токенов, seed.
12. Enumeration: неизвестный subject и неверный код дают одинаковый ответ и сопоставимое время.
13. Rollback миграции не оживляет погашенные коды.
14. Отзыв фактора не реактивирует старый credential и не даёт seed.
15. Просроченная/отсутствующая step-up assertion при генерации → отказ.
16. Брутфорс по индексам кодов (позициям) не даёт ускорения: проверяются все кандидаты одинаковое число раз.

## 6. Рассмотренные альтернативы

| Альтернатива | Почему отклонена |
| --- | --- |
| Argon2id на каждый recovery code | 100-битная энтропия делает перебор непрактичным; per-attempt KDF — DoS на `/redeem` |
| Plaintext-коды или обратимое шифрование | Утечка дампа = готовые коды; не нужно для проверки |
| Stateless подписанные коды | Нет гарантии однократности и отзыва |
| Recovery codes, восстанавливающие TOTP-seed | Невозможно для сторонних сервисов и нарушает независимость (ADR-001) |
| Identity proofing и admin UI внутри verifier | Scope creep в IAM; verifier не может проверить личность |
| In-memory rate limit | Не работает при нескольких инстансах, обходится рестартом |
| Один общий набор кодов на несколько tenant | Нарушает tenant isolation и контекст digest |

## 7. Последствия

**Положительные:** восстановление работает без облака и без экспорта seed; однократность обеспечена транзакционно; параметры совместимы с ADR-003/004.

**Отрицательные:** недоступность БД блокирует восстановление (принято, fail-closed); нужны процессы хранения pepper-ключей и ротации `key_id`; пользователь обязан сохранить коды; дополнительная нагрузка на аудит и тесты гонок.

**Остаточные риски:** кража набора кодов вместе с доступом к RP-аккаунту; компрометация approver'а; компрометация БД вместе с pepper-ключом (перебор 2¹⁰⁰ всё ещё непрактичен, но заявление об этом требует review); отзыв сессий остаётся на RP.

## 8. Открытые вопросы (закрыть до `Accepted`)

1. Финальные значения: 10 кодов × 100 бит и отсутствие expiry — достаточно ли для целевых tenant?
2. Обязателен ли `session_binding` при redeem всегда или зависит от политики tenant?
3. Формат approval evidence (opaque ref + подпись? отдельный approval endpoint?) и хранение политик tenant.
4. Нужен ли отдельный шаг step-up в RP перед redeem (например, пароль/почта) — если да, как это отражается в контракте.
5. Retention и hash-chaining аудита (пересечение с SRV-009).
6. Нужен ли `key_id` rotation-план для pepper и как проверять старые digest при ротации.

## 9. Критерии приёмки

- ADR reviewed и переведён в `Accepted`; замечания security review закрыты.
- `api/openapi.yaml` обновлён до handlers (SRV-008), схемы соответствуют §4.9.
- `T-S9` в [threat-model.md](../threat-model.md) связан с конкретными тестами SRV-007.
- Тесты §5 проходят, включая конкурентное погашение, cross-tenant, fail-closed и отсутствие секретов в логах/audit.
- Отдельно подтверждено: verifier не выполняет identity proofing, не отзывает RP-сессии и не экспортирует seed.
