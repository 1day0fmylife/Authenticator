# ADR-004 — Формат vault v1, ограничения и восстановление

- **Статус:** Accepted (v1.0)
- **Дата:** 15.11.2026
- **Задача:** TODO `ADR-004`
- **Связанные:** [ADR-003](0003-crypto.md), [SEC-001 threat model](../threat-model.md), [SEC-002 supply-chain](../supply-chain.md), [ADR-001](0001-independence.md); реализация — `VAULT-001…005`.
- **Область:** desktop Rust crate `vault`. Это **спецификация**, а не реализация: кода vault, fixtures и независимого review ещё нет.

## 1. Решение

1. **Один основной файл** `.avault`: открытый 80-байтный envelope-заголовок + один AEAD-шифротекст. Отдельной БД, journal-файла или per-record encryption в v1 нет; `.bak`/`.lock` — служебные sidecar-файлы, не второй формат.
2. **Криптография** — по ADR-003: XChaCha20-Poly1305 (nonce 24, tag 16), Argon2id v19, ключ 32 байта, salt 16 байт.
3. **AAD** — ровно 80 байт заголовка, без «нормализации» и без пересборки полей. Любое изменение заголовка приводит к ошибке аутентификации.
4. **Payload** — версионированный бинарный контейнер с записями; шифруется целиком. Внутренняя версия payload не зависит от версии envelope.
5. **Строгий fail-closed parser** с жёсткими лимитами на файл, KDF, число записей, длины строк и секретов. Неизвестная версия/тип/флаг — отказ, а не пропуск данных.
6. **Сохранение** — temp + fsync + atomic replace, одна предыдущая копия `.bak`, sidecar lock и optimistic conflict check по SHA-256. Повреждённый или недоступный файл **никогда** не заменяется пустым vault.
7. **Восстановление** — побайтовая копия является backup; export с новым паролем перешифровывает в тот же формат; import в v1 — только замена, не merge. Смена пароля/явный KDF upgrade создаёт новый salt, ключ и nonce.
8. **Ошибки** различают структурную порчу, неподдерживаемый формат, неверный пароль/повреждённый шифротекст, недоступность и конфликт. Секреты не попадают в ошибки, `Debug`, логи и имена файлов.

## 2. Trust boundaries

| Сторона | Что доверяем | Что не доверяем |
| --- | --- | --- |
| Код `vault` | Проверка границ, порядок записи, zeroize | Ошибки реализации; обязательны negative/fault-injection тесты |
| ОС CSPRNG | salt, nonce, temp-суффиксы | При ошибке RNG — отказ, без fallback |
| Файл на диске | Только после проверки заголовка и AEAD-тега | Заголовок, длины, версии, ciphertext, `.bak`, temp-файлы |
| Пароль | Байты UTF-8, введённые пользователем | Нормализация, обрезание пробелов, логирование |
| Файловая система | Атомарность rename в пределах одной директории | Сетевые/FUSE/синхронизируемые папки; fsync может быть no-op |
| Локальный пользователь | Владение профилем/правами | Другой процесс того же пользователя, malware, debugger, swap |

Vault не защищает от компрометации ОС, чтения памяти, keylogger, swap и вредоносного процесса с правами пользователя. Это остаточные риски R-1/R-7 threat model.

## 3. Envelope v1

Все целые — big-endian. Заголовок фиксирован для `envelope_version=1`.

| Offset | Size | Поле | Значение и проверка |
| --- | --- | --- | --- |
| 0 | 4 | `magic` | ASCII `AVLT` (`41 56 4C 54`) |
| 4 | 2 | `envelope_version` | `1`; иначе `Unsupported` |
| 6 | 2 | `header_len` | `80` для v1; иначе отказ |
| 8 | 2 | `kdf_id` | `1` = Argon2id v19; иначе `Unsupported` |
| 10 | 2 | `flags` | `0`; неизвестные биты → отказ |
| 12 | 4 | `m_cost_kib` | 19 456…262 144 KiB (19…256 MiB) |
| 16 | 4 | `t_cost` | 2…6 |
| 20 | 4 | `p_cost` | 1…4 |
| 24 | 4 | `key_id` | `0` в v1; иначе `Unsupported` |
| 28 | 16 | `salt` | CSPRNG; ровно 16 байт |
| 44 | 24 | `nonce` | CSPRNG; ровно 24 байта; новый на каждую запись |
| 68 | 8 | `ciphertext_len` | u64; включает 16-байтный tag; `32…16 777 232` |
| 76 | 4 | `reserved` | `0`; ненулевое → отказ |
| **80** | | | **конец заголовка / AAD** |

Инварианты:

- `file_size == header_len + ciphertext_len`; иначе `Corrupt` (truncated/trailing bytes).
- `ciphertext_len >= 32` (16 tag + 16 payload header) и `file_size <= 16 777 312`.
- Проверка заголовка выполняется **до** Argon2id; дорогой KDF не запускается на явно некорректном файле.
- `flags`, `reserved`, `key_id`, `kdf_id`, `envelope_version` и `header_len` аутентифицируются как часть AAD; после расшифровки они не могут быть изменены незаметно.
- `header_len` читается из первых 8 байт. Для будущих версий допускается `header_len <= 4096`, но v1 требует ровно 80. Неизвестная версия не парсится «наугад».

## 4. Payload v1

После AEAD-расшифровки:

| Offset | Size | Поле | Значение |
| --- | --- | --- | --- |
| 0 | 4 | `payload_magic` | ASCII `AVP1` |
| 4 | 2 | `payload_version` | `1` |
| 6 | 2 | `flags` | `0` |
| 8 | 4 | `body_len` | длина всех записей, u32 |
| 12 | 4 | `record_count` | число записей, u32 |
| **16** | | **начало body** | `record_count` записей подряд |

Инварианты:

- `decrypted_len == 16 + body_len`; padding в v1 **нет**.
- `body_len <= 16 777 200`; `record_count <= 10 000`.
- `record_count` должен совпасть с фактически разобранным числом записей; `body_len` — с суммой длин записей.
- Пустой vault допустим: `body_len=0`, `record_count=0`. Это единственный способ создать пустой файл; ошибка открытия/записи не создаёт его автоматически.
- `payload_magic`/`payload_version`/`flags` проверяются; неизвестная версия → `Unsupported`, неизвестные флаги → `Corrupt`.

## 5. Record v1

Запись одного OTP-секрета. Отдельного `label` нет: отображаемое имя выводится из `issuer`/`account`. Пользовательские метки — будущая версия payload.

| Offset | Size | Поле | Значение |
| --- | --- | --- | --- |
| 0 | 1 | `record_type` | `1` = OTP entry |
| 1 | 1 | `otp_type` | `1` = TOTP, `2` = HOTP |
| 2 | 1 | `algorithm` | `1` = SHA-1, `2` = SHA-256, `3` = SHA-512 |
| 3 | 1 | `digits` | `6` или `8` |
| 4 | 4 | `period_seconds` | TOTP: 1…86 400; HOTP: `0` |
| 8 | 8 | `counter` | HOTP: любое u64; TOTP: `0` |
| 16 | 2 | `secret_len` | 1…1024 |
| 18 | N | `secret` | сырые байты, не Base32 |
| 18+N | 2 | `issuer_len` | 0…256 |
| … | M | `issuer` | UTF-8 |
| … | 2 | `account_len` | 1…256 |
| … | A | `account` | UTF-8 |

Правила:

- Минимальная запись — 24 байта (secret 1 байт, issuer пустой, account 1 байт); максимальная — 1 558 байт (secret 1024, issuer 256, account 256).
- `otp_type`, `algorithm`, `digits` — только перечисленные значения; иначе `Corrupt`.
- TOTP: `period` в границах, `counter=0`. HOTP: `period=0`, `counter` любой; приложение отдельно не даёт увеличить `u64::MAX`.
- `issuer`/`account` — валидный UTF-8; невалидный UTF-8 → `Corrupt`. Строки не нормализуются.
- `secret` непустой; верхняя граница совпадает с `otp-core` (1024 байта). Секрет не логируется и не попадает в `Debug`.
- Записи идут в пользовательском порядке; формат не требует сортировки и не вводит ID. Дубликаты `issuer`/`account` допустимы.
- Лишние байты после последней записи, несовпадение `body_len`/`record_count`, неизвестный `record_type` → `Corrupt`; молчаливое отбрасывание неизвестных записей запрещено.

## 6. Лимиты

| Константа | Значение | Назначение |
| --- | --- | --- |
| `ENVELOPE_VERSION` | 1 | версия заголовка/AAD |
| `HEADER_LEN` | 80 | фиксированный заголовок v1 |
| `PAYLOAD_VERSION` | 1 | версия схемы записей |
| `MAX_HEADER_BYTES` | 4096 | предел для будущих версий |
| `MIN_FILE_BYTES` | 112 | 80 + 16 payload header + 16 tag |
| `MAX_PAYLOAD_BYTES` | 16 MiB (16 777 216) | до шифрования |
| `MAX_CIPHERTEXT_BYTES` | 16 MiB + 16 (16 777 232) | payload + tag |
| `MAX_FILE_BYTES` | 16 MiB + 96 (16 777 312) | header + ciphertext |
| `MAX_RECORDS` | 10 000 | число записей |
| `MAX_SECRET_BYTES` | 1 024 | один секрет |
| `MAX_STRING_BYTES` | 256 | issuer/account по отдельности |
| `MIN_PERIOD_SECONDS` | 1 | TOTP |
| `MAX_PERIOD_SECONDS` | 86 400 | TOTP |
| `MAX_PASSWORD_BYTES` | 1 024 | Argon2id input |
| `MIN_NEW_PASSWORD_BYTES` | 12 | только создание/смена пароля |

Пароль при **создании/смене** — 12…1024 байта UTF-8, без нормализации и без trim. При **открытии** принимается 1…1024 байта: политика минимальной длины не должна навсегда блокировать старый файл. Пустой пароль не принимается. Ограничение — UX-политика, а не замена энтропии.

KDF-параметры читаются из заголовка и проверяются по границам ADR-003: `m` 19 456…262 144 KiB, `t` 2…6, `p` 1…4. Значения вне границ → `ResourceLimit`/`Corrupt` до выделения памяти. Запись по умолчанию использует `m=65 536 KiB`, `t=3`, `p=1`; чтение старых параметров в границах разрешено. Автоматическая «калибровка» при открытии формат не меняет.

## 7. Ключевой envelope и AAD

Запись:

```text
salt, nonce <- CSPRNG
key <- Argon2id(password_utf8, salt, m, t, p, 32, version=0x13)
ciphertext_len <- len(payload) + 16
header <- serialize(envelope_v1, salt, nonce, ciphertext_len, ...)
ciphertext <- XChaCha20Poly1305(key, nonce, aad=header, plaintext=payload)
file <- header || ciphertext
```

Чтение:

```text
read header (<= MAX_HEADER_BYTES)
validate magic/version/header_len/kdf_id/flags/key_id/params/limits
validate file_size == header_len + ciphertext_len
key <- Argon2id(password_utf8, salt, ...)
payload <- XChaCha20Poly1305.open(key, nonce, aad=header, ciphertext)
parse payload and records with limits
zeroize payload, key, password buffers
```

- AAD — **точные байты заголовка**, включая `ciphertext_len`, `salt` и `nonce`. Нельзя пересобирать AAD из распарсенных полей с другим порядком/кодировкой.
- `nonce` одновременно входит в AAD и передаётся как nonce AEAD; это связывает заголовок с конкретным шифротекстом.
- Обычное сохранение переиспользует `salt`/`key` и генерирует новый `nonce`. Смена пароля, KDF upgrade и явный re-encrypt export генерируют новый `salt`, новый `key`, новый `nonce`.
- `key_id=0` только для v1. Будущая ротация ключей должна использовать новый `key_id`/версию; неизвестный `key_id` → отказ.
- Argon2id secret/associated data не используются в v1. Если понадобятся — новый `kdf_id`, а не изменение смысла существующего.
- Ошибка CSPRNG, KDF, AEAD, парсинга или записи отменяет операцию. Никаких нулевых/временных salt/nonce, никакого «попробовать без тега».
- Nonce не переиспользуется даже при retry после ошибки: каждый вызов seal получает свежий nonce; nonce неудавшейся попытки отбрасывается.

## 8. Сохранение, crash consistency, конкурентность

### 8.1. Блокировка и конфликт

- На время сессии берётся эксклюзивная advisory-блокировка sidecar-файла `<vault_path>.lock` (например, `vault.avault.lock`; создаётся с правами 0600, пустой, без секретов). Если блокировка занята — `Busy`; второй экземпляр не пишет.
- При открытии вычисляется `baseline_digest = SHA-256(весь файл)` и запоминается.
- Перед каждым сохранением файл перечитывается и хешируется. Если файл исчез или digest отличается — `Conflict`, запись не выполняется. Это защита от потерянного обновления, даже если другой процесс игнорирует lock.
- Sidecar lock не удаляется при выходе (удаление гоняется с другими процессами); ОС снимает advisory-lock при завершении процесса. Файл не содержит данных.

### 8.2. Обычное сохранение

1. Проверить lock, `baseline_digest`, лимиты и сериализовать payload в zeroize-буфер.
2. Сгенерировать новый `nonce`; `salt`/`key`/KDF-параметры не менять.
3. Построить заголовок (с уже известным `ciphertext_len`), зашифровать.
4. Создать temp-файл в **той же директории** через `create_new` с правами 0600 и случайным суффиксом; записать все байты, `flush`, `sync_all`, закрыть.
5. Если target существует: записать текущий (старый) файл в temp для `.bak`, `fsync`, атомарно заменить `.bak`.
6. Атомарно заменить target temp-файлом.
7. Выполнить fsync директории (Unix) или write-through replace (Windows). Обновить `baseline_digest`.
8. При любой ошибке до шага 6 target остаётся старым; temp удаляется. Ошибка после успешной замены, но до подтверждённой durability → `DurabilityUncertain`; сессия требует reopen/проверки, повторная запись не маскирует проблему.

### 8.3. Платформенные требования

- **Unix:** `rename(2)` в пределах одной директории; `fsync` файла до rename; `fsync` родительской директории после rename. Открытие vault/temp/lock — с `O_NOFOLLOW` для regular file; symlink отклоняется.
- **Windows:** `FlushFileBuffers` на temp до закрытия; замена через `ReplaceFileW` или `MoveFileExW` с `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`. Reparse point/symlink отклоняется. Если для этого нужен небольшой `windows-sys`-shim, он проходит отдельный dependency review; `std::fs::rename` без write-through не считается достаточным для заявленной durability.
- **Права:** Unix 0600 для vault/`.bak`/temp/lock; создаваемая приложением директория — 0700. Windows — ACL профиля пользователя; ужесточение DACL проверяется в VAULT-003, до этого не заявляется.
- **Не поддерживается для durability:** сетевые/FUSE/облачные sync-папки (OneDrive, Dropbox, NFS, SMB). Приложение предупреждает; корректность fsync/rename там не гарантируется.
- **Temp cleanup:** после получения lock удаляются только файлы с точным префиксом `.<name>.tmp-` / `.<name>.bak.tmp-`, созданные этим приложением. Ошибка cleanup не раскрывает секреты (там только шифротекст), но фиксируется.

### 8.4. Смена пароля и KDF upgrade

- Требует разблокированного vault и знания текущего пароля.
- Новый salt, новый ключ из нового пароля, новый nonce; payload перешифровывается целиком.
- `.bak` для этой операции записывается из **нового** шифротекста до замены target, чтобы после успешной смены пароля управляемая backup-копия не открывалась старым паролем. Если операция прервана до замены target, target остаётся старым; возможна ситуация «target старый, `.bak` новый» — это фиксируется как незавершённая смена и не скрывается.
- KDF upgrade без смены пароля — явная операция с повторным вводом пароля: старый ключ расшифровывает, новый salt/params/ключ шифрует. Автоматически при открытии не выполняется.
- Внешние копии, сделанные пользователем до смены пароля, остаются доступны старым паролем. Приложение не обещает их удаление или перешифрование.

## 9. Backup, export, import, restore

| Операция | Формат | Ключ/salt/nonce | Семантика |
| --- | --- | --- | --- |
| Managed `.bak` | тот же v1 | обычное сохранение: старые salt/key, старый nonce; смена пароля: новые | одна предыдущая версия для crash recovery |
| Побайтовая копия | тот же v1 | без изменений | допустимый backup; не «перешифрование» |
| Export | тот же v1 | **новые** salt/key/nonce | расшифровать и зашифровать заново с экспортным паролем; plaintext на диск не пишется |
| Import | v1 | текущий ключ vault + новый nonce | v1: **только replace** после полной проверки источника; merge — отдельная будущая версия |
| Restore `.bak` | v1 | новые salt/key/nonce (при сохранении в target) | открыть backup, проверить, сохранить как target; текущий target сначала проходит обычную backup-политику, если читаем |

Правила:

- Import/export/restore сначала полностью проверяют источник (заголовок, AEAD, payload, лимиты), и только потом меняют target. Частично импортированные данные не допускаются.
- Export не предлагает plaintext-формат в v1. Перенос в другой менеджер — отдельный явный сценарий с предупреждением, не «backup».
- Restore/import в повреждённый или недоступный target требует явного подтверждения пользователя; автоматическое создание пустого vault запрещено.
- `.bak` не является единственным backup; пользовательские копии вне директории приложения рекомендуются. Приложение не удаляет внешние копии.
- Восстановление пароля в v1 **не существует**: нет recovery key, recovery code или server escrow. Потеря пароля = потеря данных. Это осознанное ограничение, а не недоделка; recovery-key envelope — отдельный ADR/версия.

## 10. Ошибки

Публичная модель (имена могут уточниться в коде, классы — нет):

| Класс | Когда | Что нельзя раскрывать |
| --- | --- | --- |
| `NotFound` | target отсутствует; создание только явное | — |
| `Unavailable` | permission denied, read-only, нет директории, I/O чтения | секреты/пароль |
| `Busy` | sidecar lock занят | — |
| `Corrupt` | magic/header_len/truncated/trailing/payload/record invariants, неизвестный `record_type` в v1 | plaintext/секрет |
| `Unsupported` | неизвестная envelope/payload version, kdf_id, key_id | — |
| `AuthenticationFailed` | AEAD tag mismatch: неверный пароль **или** изменённый шифротекст | нельзя различать эти причины |
| `ResourceLimit` | файл/payload/records/строки/KDF-параметры вне лимитов | — |
| `Conflict` | файл изменился с момента открытия | — |
| `Io` | ошибка записи/fsync/rename | — |
| `DurabilityUncertain` | замена прошла, durability не подтверждена | — |

- `AuthenticationFailed` намеренно не говорит «неверный пароль»: иначе появляется oracle для различения пароля и модификации шифротекста. UI пишет «неверный пароль или повреждённый файл».
- Структурная порча заголовка может отличаться от AEAD-ошибки: заголовок публичен, это не даёт oracle о пароле.
- Ошибки содержат только публичные метаданные (offset, ожидаемая/фактическая длина, версия). Никогда — пароль, ключ, secret, plaintext, decrypted payload.
- `Debug`/`Display`/panic-сообщения не включают секреты. Ошибка не приводит к автоматическому созданию/перезаписи vault.
- Format-слой (`desktop/crates/vault`) добавляет внутренние классы сверх таблицы: `InvalidInput` (невалидный аргумент вызывающего кода при seal), `Crypto` (недостижимый отказ примитива), `Random` (отказ OS CSPRNG) и `UnknownRecord` (session-local `RecordId` не найден, VAULT-002). Они не раскрывают секретов; persistence-классы (`NotFound`, `Busy`, `Conflict`, `Io`, `DurabilityUncertain`) появятся в VAULT-003 вместе с записью на диск.

## 11. Версионирование и миграция

- `envelope_version` описывает заголовок/AAD/AEAD-layout; `payload_version` — схему записей. Они версионируются независимо.
- Reader поддерживает только известные версии. Неизвестная версия → `Unsupported`; нельзя «пропустить незнакомые поля» и продолжить.
- Writer всегда пишет текущую версию. Downgrade и «совместимое» дописывание полей без версии запрещены.
- Новый `kdf_id` — только для нового алгоритма/смысла параметров. Изменение `m/t/p` в допустимых границах не требует нового `kdf_id`.
- Старый файл с параметрами ниже текущих defaults открывается; UI может предложить upgrade, но не переписывает файл без действия пользователя.
- Новый `record_type`/поле требует нового `payload_version`; старый reader обязан отказаться, а не терять записи.
- Парольная политика может меняться для новых паролей; bytes-формат и отсутствие нормализации фиксированы. Смена нормализации — только новая версия с явной миграцией.

## 12. Test vectors и обязательные проверки

Fixtures (появятся в VAULT-001, не в этом ADR):

- `tests/vault/v1/` — синтетические файлы: пустой vault, TOTP SHA-1/256/512, HOTP, 6/8 digits, границы строк/секрета, минимальные и default KDF-параметры.
- `manifest.json` — test-only пароль, salt/nonce hex, параметры, expected header hex, SHA-256 файла и plaintext hex/JSON. Никаких реальных секретов.
- Генератор fixtures использует test-only инъекцию salt/nonce; production API не принимает caller-supplied nonce/salt. Иначе появляется риск повторного nonce.

Обязательные тесты до объявления VAULT-001/002 готовыми:

1. Known-answer: точные байты заголовка, ciphertext и tag для фиксированных salt/nonce/password/plaintext; decrypt round-trip.
2. Negative: неверный magic/version/header_len/kdf_id/key_id/flags/reserved; truncated/trailing; ciphertext_len mismatch; tag/nonce/salt flip; payload magic/version; body_len/record_count mismatch; unknown record_type; invalid UTF-8; oversized secret/string; TOTP/HOTP invariants.
3. Ошибки: wrong password vs structural corruption vs unavailable vs conflict vs busy; отсутствие паники и секретов в `Debug`.
4. Crash/fault injection: обрыв на шагах 3–7 §8.2; target всегда старый или новый целиком, не частичный; `.bak` и temp cleanup.
5. Concurrency: два процесса, lock/Conflict, отсутствие потерянного обновления.
6. Cross-OS: один и тот же fixture открывается на Windows и Ubuntu; переносимый export/import.
7. Permission/disk-full/read-only/symlink/reparse-point сценарии.

Primitive-level независимость обеспечивают RFC 4231/9106/draft-XChaCha векторы ADR-003. Отдельного независимого cross-language verifier **пока нет**; он не заявляется. Если понадобится, это dev-only инструмент с отдельным supply-chain review (Argon2id отсутствует в Go stdlib).

## 13. Альтернативы

| Альтернатива | Причина отказа |
| --- | --- |
| JSON/CBOR/MessagePack + AEAD | Канонизация, размеры и сторонние parser-зависимости; бинарный fixed-layout проще ограничивать |
| SQLite + SQLCipher | Тяжёлый native dependency, собственный key management и WAL/journal; противоречит минимальному storage v1 |
| Per-record AEAD | Раскрывает число записей и усложняет атомарное обновление; whole-payload проще и скрывает структуру |
| Append-only journal | Сложность recovery/compaction; atomic replace достаточен для ≤16 MiB |
| Key-wrap/HKDF в v1 | ADR-003: один ключ и один payload; выгоды без ротации нет |
| Random padding в v1 | Уменьшает утечку длины, но добавляет ветку формата; отложено до payload v2. В v1 длина шифротекста примерно раскрывает число/размер записей |
| Plaintext header без AAD | Позволяет менять KDF-параметры/nonce/длины; отвергнуто |
| Auto-restore `.bak` при ошибке | Может затереть более новую/частично записанную версию; restore только явный |
| Recovery key/escrow в v1 | Меняет модель угроз и формат; отдельный ADR/версия |
| OS keyring как основной ключ | Привязывает переносимость к ОС и создаёт ложное ощущение recovery; пароль остаётся основным |

## 14. Остаточные риски

- Длина файла/шифротекста раскрывает приблизительное число и размер записей; padding не входит в v1.
- Откат на старую аутентичную копию не детектируется без внешнего доверенного счётчика.
- `.bak` и внешние копии: внешние копии после смены пароля остаются доступны старым паролем; управляемый `.bak` может остаться старым только при прерванной смене пароля.
- Локальный malware/debugger/keylogger/swap может получить пароль, ключ или plaintext; vault этого не предотвращает.
- fsync/rename могут не соблюдаться на сетевых/FUSE/sync-ФС; такие папки не поддерживаются для durability.
- Windows ACL в v1 наследуются от профиля; приложение не гарантирует ужесточение DACL до проверки VAULT-003.
- Слабый пароль — главный риск; Argon2id только повышает стоимость подбора.
- Нет независимого security review (QA-002) и нет независимого cross-language verifier формата.
- Нет recovery key: потеря пароля необратима.

## 15. Статус реализации

- `VAULT-001` создал `desktop/crates/vault` (format/crypto) и синтетические fixtures в `tests/vault/v1/` с conformance/negative тестами. Persistence, crash consistency и backup/restore — `VAULT-003…005`; их в коде пока нет.
- `VAULT-002` добавил `UnlockedVault` (`session.rs`): create/unlock/lock, CRUD, `seal` с прежними salt/key и новым nonce (§7), `change_password`/KDF upgrade с проверкой текущего пароля и новыми salt/key (§8.4). Он работает с байтами; managed `.bak` из нового шифротекста при смене пароля, lock и `Conflict` (§8) — VAULT-003.
- Fixtures проверяют точные байты заголовка, SHA-256 файла, расшифровку, неверный пароль, повреждение ciphertext/nonce/header и границы формата. Это **не** доказывает crash consistency, поведение на Windows или отсутствие уязвимостей.
- До появления persistence-кода нельзя заявлять, что формат переживает power loss или прошёл security review.
- Изменения формата после появления fixtures — новая версия ADR/payload/envelope с changelog, а не «тихая» правка.

## 16. Changelog

| Дата | Версия | Изменение |
| --- | --- | --- |
| 15.11.2026 | 1.0 | Зафиксированы envelope/payload/record layout, лимиты, AAD, atomic write, `.bak`, lock/conflict, backup/export/import/restore, ошибки, версии и test plan |
| 15.11.2026 | 1.1 | VAULT-001: fixtures и format/crypto crate добавлены без изменения формата; уточнены три внутренних класса ошибок format-слоя; payload сериализуется в один zeroize-буфер точного размера, блоки памяти Argon2id зануляются при освобождении |
| 15.11.2026 | 1.2 | VAULT-002: in-memory сессия vault; класс `UnknownRecord`; persistence-классы перенесены в VAULT-003. Формат не изменён |
