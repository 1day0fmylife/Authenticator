# Threat Model — Authenticator

**Статус:** Draft v0.2, 19.11.2026.
**Область:** desktop Authenticator (Rust, Windows/Ubuntu), Go MFA verifier, общие `otpauth://`/RFC-компоненты, упаковка, CI/CD и обновления.
**Связанные документы:** [README](../README.md), [PLAN](../PLAN.md), [TODO](../TODO.md), [AGENTS](../AGENTS.md), [supply-chain](supply-chain.md), [recovery threat model](recovery-threat-model.md), ADR в `security/adr/`.

Это рабочий документ, а не заявление о готовности или о пройденном аудите. Он описывает **модель**, а не подтверждает реализацию: большинство мер ниже пока имеют статус *planned* и закрываются соответствующими TODO ID. Формулировки «защищено» допустимы только после появления тестов/артефактов, указанных в колонке «Проверка».

## 1. Цель и что документ НЕ покрывает

Цель — зафиксировать активы, акторов, границы доверия, допущения и угрозы, чтобы:

1. каждая P0-задача имела явный набор негативных сценариев;
2. архитектурные ADR (GUI, crypto, vault format, verifier contract) опирались на один и тот же список угроз;
3. остаточные риски были сформулированы честно и не маскировались маркетингом.

**Вне области v0.1:**

- Mobile (P3) — отдельный threat model перед началом.
- WebAuthn/FIDO2/passkeys — отдельный threat model (P2).
- E2EE sync vault — отдельный продукт и контракт (P2).
- Enterprise IAM/SSO-интеграции (P2).
- Компрометация аппаратного обеспечения, firmware, hypervisor, физический доступ к включённой машине с активной сессией.
- Криптоанализ примитивов: используется допущение, что выбранные аудированные библиотеки (RustCrypto/Go stdlib) стойки при корректном использовании.

## 2. Методология

- **Активы** (A) — что защищаем.
- **Акторы** (AD) — кто/что угрожает и с какими возможностями.
- **Границы доверия** (TB) — где меняется доверие к вводу/среде.
- **Угрозы** (T) — сценарий + impact + вероятный вектор.
- **Меры** (M) — конкретный контроль, привязанный к TODO/ADR.
- **Остаточный риск** (R) — что остаётся после мер и почему это принято.

Приоритеты impact: **Critical** — раскрытие всех seed или обход MFA в масштабе; **High** — компрометация отдельного пользователя/tenant, необратимая потеря vault; **Medium** — ограниченное раскрытие метаданных, DoS, деградация; **Low** — неудобство без потери секретов.

Статусы мер: `planned` (описано, не реализовано), `partial` (есть прототип/часть тестов), `done` (есть воспроизводимая проверка), `n/a` (вне области).

Документ пересматривается при: изменении формата vault, схемы БД, API-контракта, GUI framework, модели обновлений, состава зависимостей, а также после каждого независимого security review.

## 3. Активы

| ID | Актив | Где существует | Почему важен |
| --- | --- | --- | --- |
| A-1 | TOTP/HOTP seeds (shared secrets) | Desktop vault (зашифровано), память процесса; серверная БД (зашифровано) | Компрометация = генерация валидных кодов = обход второго фактора |
| A-2 | Парольная фраза vault | Память процесса, ввод пользователя | Даёт доступ к A-1 offline |
| A-3 | Derived keys / KDF output / AEAD keys | Память процесса | Эквивалентны A-1 пока живы |
| A-4 | Расшифрованный vault payload и метаданные (issuer/account) | Память, clipboard, GUI | Раскрытие списка аккаунтов и связей |
| A-5 | Резервные копии/экспорт vault | Файловая система, внешние носители | Offline-атака на пароль, кража |
| A-6 | Recovery codes | Серверная БД (digest), выдача пользователю | Обход второго фактора при компрометации |
| A-7 | Session bindings, challenges, OTP-коды в полёте | Память, сеть, БД | Replay/перехват = обход MFA |
| A-8 | Service credentials / mTLS keys verifier | Конфигурация backend-клиента, секрет-хранилище | Доступ к данным нескольких tenant |
| A-9 | Ключи шифрования БД (`key_id`, key material) | Вне БД и образа, secret provider/файл | Раскрытие всех серверных seeds |
| A-10 | Аудит-логи и метрики verifier | БД, log sink, метрики | Раскрытие паттернов, enumeration, PII |
| A-11 | Целостность артефактов и цепочки сборки | Исходники, CI, mirror, packages | Подмена бинарника = компрометация всех пользователей |
| A-12 | Доступность desktop vault и verifier | Локальный файл, сервис, PostgreSQL | Потеря доступа, lock-out, DoS |
| A-13 | Идентичность субъекта/tenant в verifier | Service identity + БД | Cross-tenant IDOR = чужие факторы |
| A-14 | Пользовательские ожидания/UI-состояние (locked/unlocked) | GUI | Ложное чувство защиты, утечка при auto-lock failure |

**Не активы (явно):** никнеймы записей и issuer'ы не считаются секретами сами по себе, но в зашифрованном payload их скрываем, чтобы не раскрывать связи «сервис ↔ пользователь».

## 4. Акторы и возможности

| ID | Актор | Возможности | Типичная цель |
| --- | --- | --- | --- |
| AD-1 | Локальный непривилегированный пользователь той же ОС | Чтение файлов пользователя, процессы, clipboard | A-1, A-5, A-4 |
| AD-2 | Вредоносное ПО / руткит с правами пользователя или выше | Перехват ввода, памяти, инъекции, чтение файлов | A-1…A-5 |
| AD-3 | Атакующий с кражей зашифрованного файла/бэкапа | Offline password guessing, модификация файла | A-1, A-5 |
| AD-4 | Сетевой атакующий между backend и verifier | MITM, replay, подмена запросов | A-7, A-13 |
| AD-5 | Скомпрометированный или вредоносный backend-клиент (валидная service identity) | Легитимные вызовы API в своём tenant | A-13 (эскалация в чужой tenant), enumeration |
| AD-6 | Внешний неаутентифицированный сканер | Публичные endpoint'ы, health | DoS, enumeration, fingerprinting |
| AD-7 | Злоумышленник в supply chain | Typosquatting crate/module, malicious build script/proc-macro, подмена зависимости | A-11 → A-1 |
| AD-8 | Атакующий CI/CD | Изменение пайплайна, секретов подписи, артефактов | A-11 |
| AD-9 | Фишинговый сайт/агент | Сбор OTP-кодов в реальном времени | A-7 (TOTP не phishing-resistant) |
| AD-10 | Инсайдер с доступом к БД/бэкапам сервера | Дамп PostgreSQL, копии логов | A-1, A-9, A-10 |
| AD-11 | Атакующий с физическим доступом к выключенной машине | Копирование диска, offline-атака | A-1, A-5 |
| AD-12 | Недобросовестный/ошибочный оператор развёртывания | Misconfiguration, ключи в образе, fail-open | A-9, A-13, A-12 |

Границы возможностей по умолчанию: **AD-2 с полным контролем ОС не может быть полностью побеждён** приложением user-space. Это допущение, а не дефект дизайна.

## 5. Границы доверия и потоки данных

```text
[Пользователь]
   │ пароль, OTP, действия UI
   ▼
┌──────────────────────────── Desktop (Windows/Ubuntu) ────────────────────────────┐
│ TB-1: GUI ↔ app-core (недоверенный UI-ввод, доверенная use-case логика)          │
│ TB-2: app-core ↔ otp-core (чистые функции, без сети, без secrets в логах)        │
│ TB-3: app-core ↔ vault (пароль/ключи, зашифрованный файл)                         │
│ TB-4: vault ↔ filesystem (атомарная запись, fsync, permissions)                   │
│ TB-5: clipboard/OS (утечка через буфер, скриншоты, accessibility API)             │
│ TB-6: импорт `otpauth://`/файла (недоверенный внешний ввод)                       │
└───────────────────────────────────┬──────────────────────────────────────────────┘
                                    │ только пользователь вводит код
                                    ▼
                        [Backend приложения: primary auth + session]
                                    │ TB-7: HTTPS + service identity (mTLS/token)
                                    ▼
┌──────────────────────────── Go MFA verifier ─────────────────────────────────────┐
│ TB-8: HTTP handler ↔ application (валидация, authN/authZ, tenant resolution)     │
│ TB-9: application ↔ PostgreSQL (транзакции, tenant-bound constraints)            │
│ TB-10: application ↔ key provider (AEAD ключи вне БД/образа)                     │
│ TB-11: verifier ↔ logs/metrics (только безопасные поля)                          │
└──────────────────────────────────────────────────────────────────────────────────┘
                                    ▲
TB-12: CI/CD, dependency ingestion, mirror → build → signing → distribution
```

Ключевые инварианты границ:

- Desktop **не имеет** сетевого канала в runtime; отсутствие сети — часть модели, а не настройка.
- Tenant и subject в verifier **не берутся** из пользовательского JSON как источник авторизации; tenant определяется service identity.
- Verifier не объявляет сессию пользователя аутентифицированной и не заменяет primary auth.
- Все секреты пересекают TB-3/TB-6/TB-9/TB-10 только в контролируемой форме; логирование на TB-11 запрещает секреты полностью.

## 6. Допущения

| ID | Допущение | Что делать, если оно неверно |
| --- | --- | --- |
| AS-1 | ОС и её CSPRNG не скомпрометированы; TLS-стек корректен | Компрометация ОС/стека вне возможностей приложения; фиксируется как остаточный риск |
| AS-2 | Пользователь выбирает достаточно энтропийный пароль vault (нижняя граница длины/сложности задаётся UX и ADR) | Argon2id повышает стоимость offline-подбора, но не спасает слабый пароль |
| AS-3 | Часы устройства/сервера reasonably синхронизированы; дрейф ограничен политикой окна | Расширение окна повышает риск replay; при большом дрейфе — отказ, не fail-open |
| AS-4 | Backend-приложение корректно реализует primary auth и не доверяет клиенту флаг «MFA verified» | Ошибка интеграции — ответственность relying party; контракт и примеры должны это явно показывать |
| AS-5 | Оператор развёртывания подаёт ключи шифрования извне и не кладёт их в образ/репозиторий | Startup fail-closed при отсутствии/некорректности ключа |
| AS-6 | Зависимости и toolchain получены из проверенного источника и закреплены | Нарушение = инцидент supply chain, релиз блокируется |
| AS-7 | TOTP по своей природе не phishing-resistant | Не позиционировать иначе; WebAuthn — отдельный будущий фактор |
| AS-8 | Пользователь не устанавливает приложение из непроверенного источника | Подпись и checksums снижают, но не устраняют риск |

## 7. Угрозы и меры

### 7.1 Desktop vault и локальное хранилище

| ID | Угроза | Impact | Меры (TODO/ADR) | Проверка | Статус |
| --- | --- | --- | --- | --- | --- |
| T-V1 | Кража зашифрованного файла → offline password guessing | High | Argon2id с согласованными параметрами и salt; AEAD; запрет слабого PIN как единственной защиты (ADR-003, VAULT-001/002) | Бенчмарк KDF, тест параметров в фикстурах, negative tests | planned |
| T-V2 | Подмена/повреждение файла → принятие модифицированного payload | High | AEAD authentication, версия формата, AAD, строгая проверка заголовка; отказ без создания пустого vault (VAULT-004) | Corrupted/tampered fixtures, fuzz парсера | planned |
| T-V3 | Прерванная запись/отключение питания → потеря vault | High | write → fsync → atomic replace, резервная копия, crash-тесты Windows/Ubuntu (VAULT-003) | Инъекция сбоев, permission/ENOSPC тесты | planned |
| T-V4 | Неверный пароль трактуется как «новый vault» | Critical | Различать wrong-password/corrupted/unavailable; никогда не перезаписывать при ошибке (VAULT-002/004) | Негативные тесты на пустой файл/ошибку IO | planned |
| T-V5 | Nonce reuse / повторное использование ключа | Critical | Спецификация nonce/AAD до кода, CSPRNG, отдельные ключи по назначению (ADR-003/004) | Векторы, review crypto-кода, тест уникальности | planned |
| T-V6 | Секреты остаются в памяти/дампах/swap | High | `zeroize` там, где контролируемо; минимизация lifetime; без crash dumps с секретами; отказ от телеметрии | Code review, тест на отсутствие секретов в выводе/логах | partial (policy) |
| T-V7 | Широкие права на файл vault/бэкапа | Medium | Ограниченные permissions (0600 на Unix, ACL на Windows), предупреждение при небезопасных правах | Платформенные тесты | planned |
| T-V8 | Потеря пароля → необратимая потеря A-1 | High | Явный UX, переносимый encrypted backup, документированная процедура восстановления; **без** backdoor | Backup/restore fixture тест (VAULT-005) | planned |
| T-V9 | Слабая парольная политика обходится UI | High | Не позволять «пустой»/тривиальный пароль без явного риска; нижняя граница энтропии в ADR/UX | UI-тесты, review | planned |

### 7.2 Desktop-процесс, ОС и интерфейс

| ID | Угроза | Impact | Меры | Проверка | Статус |
| --- | --- | --- | --- | --- | --- |
| T-D1 | Вредоносный процесс читает память/ввод (AD-2) | Critical | Не заявлять защиту от compromised OS; минимизировать открытые окна секретов, auto-lock, zeroize, без лишних привилегий | Документированный residual risk; review | accepted risk |
| T-D2 | GUI показывает seed/ключи в ошибке, логе, tooltip, crash | Critical | Отдельная модель отображения; запрет seed в UI кроме явного действия; protected error UX (GUI-002/003) | Тест «в логах/ошибках нет секретов», grep по артефактам | planned |
| T-D3 | Clipboard остаётся с OTP/секретом | Medium | Best-effort очистка, TTL, явное действие пользователя, предупреждение (GUI-003) | Ручной/интеграционный тест | planned |
| T-D4 | Auto-lock не срабатывает (idle, suspend, lock screen) | High | Таймаут, реакция на OS lock/suspend, немедленная блокировка UI и очистка отображения (GUI-003) | Платформенные сценарии | planned |
| T-D5 | Скриншоты/запись экрана/accessibility API раскрывают коды | Medium | Предупреждение, минимизация времени показа, по возможности platform hints | Ручная проверка матрицы | planned |
| T-D6 | Заблокированный UI продолжает отдавать данные через IPC/файлы/кэш | High | Единая state machine; блокировка = недоступность данных, а не только overlay (app-core) | Тест состояния locked | planned |
| T-D7 | Подмена времени/часов устройства → неверные/повторно валидные коды | Medium | Отображать расхождение, не расширять окно произвольно; документация | Unit-тесты границ времени | planned |

### 7.3 Импорт, `otpauth://` и внешние входы

| ID | Угроза | Impact | Меры | Проверка | Статус |
| --- | --- | --- | --- | --- | --- |
| T-I1 | Паника/OOM на вредоносном URI/файле | Medium | Строгий parser, лимиты длины/полей/записей, отказ на противоречиях (OTP-004/005) | Fuzz, corpus, лимиты | planned |
| T-I2 | URI с неоднозначными параметрами (issuer mismatch, повторяющиеся поля) | Medium | Явная нормализация, отказ при конфликте, предсказуемая модель ошибок | Негативные тесты | planned |
| T-I3 | Импорт секрета из недоверенного источника без предупреждения | Medium | Подтверждение пользователя, показ issuer/account, запрет авто-импорта | UX/тесты | planned |
| T-I4 | Секреты из импорта попадают в логи/тесты/fixtures | Critical | Только синтетические fixtures; запрет реальных seed; проверка логов | CI secret scan, review | planned |
| T-I5 | Malformed Base32/неверная длина/алгоритм → небезопасное поведение | High | Строгая валидация, отказ вместо «угадывания» | Unit/negative tests | planned |

### 7.4 Go MFA verifier

| ID | Угроза | Impact | Меры | Проверка | Статус |
| --- | --- | --- | --- | --- | --- |
| T-S1 | Browser/client подставляет произвольный tenant → IDOR | Critical | Tenant из service identity; subject валидируется в tenant; tenant-bound FK/UNIQUE (SRV-003/002) | Cross-tenant negative tests | planned |
| T-S2 | Повторное использование одного OTP/time-step, в т.ч. конкурентно | Critical | Атомарное однократное принятие шага в транзакции, replay barrier, row locks/constraints (SRV-005) | Race/concurrency тесты | planned |
| T-S3 | Перебор кодов | High | Rate limit в PostgreSQL (не только память), лимиты попыток challenge/subject/tenant, fail closed (SRV-005) | Нагрузочные/негативные тесты | planned |
| T-S4 | Replay чужого challenge / отсутствие session binding | High | Challenge связан с tenant+subject+purpose+session_binding, TTL, одноразовость (SRV-005, ADR-005) | Negative tests на binding | planned |
| T-S5 | Кража дампа БД → plaintext seeds | Critical | AEAD at rest, ключи вне БД/образа, key rotation c `key_id` (SRV-006, ADR-005) | Проверка дампа на plaintext, rotation tests | planned |
| T-S6 | Скомпрометированная service identity обращается к чужим данным | High | mTLS/scoped credentials, минимальные scopes, rotation, audit (SRV-003) | Cross-service/IDOR тесты | planned |
| T-S7 | Fail-open при недоступности БД/verifier или ошибке проверки | Critical | Любая ошибка = отказ; backend не должен повышать сессию без явного success (SRV-005, INT-001) | Chaos/outage тесты | planned |
| T-S8 | Enrollment без доверенной сессии/подтверждения | Critical | Enrollment start/confirm только через service identity, short TTL, подтверждение валидным OTP (SRV-004) | Negative tests | planned |
| T-S9 | Recovery codes: повторное использование, слабая энтропия, plaintext в БД | Critical | CSPRNG, digest+pepper, атомарное погашение, step-up (SRV-007) | Race/negative тесты | planned |
| T-S10 | Enumeration субъектов/факторов по кодам ошибок и таймингам | Medium | Унифицированные безопасные ошибки, correlation ID без PII, без различий «нет пользователя/неверный код» наружу | Contract-тесты | planned |
| T-S11 | Утечка OTP/seed/recovery в логи, метрики, трейсы, ошибки | Critical | Allowlist полей, redaction, review (SRV-009) | Тест на отсутствие секретов в логах | planned |
| T-S12 | Key rotation ломает данные / оставляет старый ключ безконтрольно | High | `key_id`, двухфазная rotation, тесты upgrade/rollback, fail-closed при неизвестном key_id (SRV-006) | Migration/rotation тесты | planned |
| T-S13 | MITM между backend и verifier | High | TLS с проверкой, mTLS, отсутствие «insecure» режимов в production | Конфигурационные тесты | planned |
| T-S14 | Ошибка миграции/rollback схемы | High | Версионированные миграции, FK/UNIQUE/индексы, тесты upgrade/rollback (SRV-002) | Migration fixture tests | planned |
| T-S15 | DoS публичных endpoint'ов | Medium | Health отдельно, лимиты, timeouts, context deadlines, отсутствие дорогих операций без auth | Нагрузочные тесты | planned |
| T-S16 | Утечка через audit/метрики high-cardinality private labels | Medium | Только безопасные поля, никаких subject/tenant в публичных метриках (SRV-009) | Review метрик | planned |
| T-S17 | Verifier ошибочно считается «phishing-resistant» | High | Документация и API-семантика явно ограничивают TOTP; WebAuthn — отдельный фактор | Review документации | planned |

Recovery-потоки (recovery codes, enterprise reset, lost device, backup rollback) детализированы отдельно: [recovery-threat-model.md](recovery-threat-model.md). Записи `T-S9` здесь и там описывают одну и ту же угрозу; при расхождении приоритет имеет этот документ, а детали параметров — ADR-006 (`REC-002`).

### 7.5 CI/CD и supply chain

| ID | Угроза | Impact | Меры | Проверка | Статус |
| --- | --- | --- | --- | --- | --- |
| T-C1 | Typosquatting/вредоносная зависимость с build script | Critical | Allowlist/budget, review build.rs/proc-macros/unsafe, pinned versions (SUP-004, SEC-002) | CI diff dependency graph | planned |
| T-C2 | Подмена toolchain/OS image | High | Pin rustup/Go/images by digest, checksums (SUP-001) | Verification script | planned |
| T-C3 | Сеть во время сборки подтягивает подменённый код | High | vendor + `--frozen`/`-mod=vendor`, offline build (SUP-002) | Offline clean-room build | planned |
| T-C4 | Непроверенные артефакты/подписи | Critical | SBOM, provenance, signatures, hashes (SUP-003) | Independent verification | planned |
| T-C5 | Секреты подписи/ключи в репозитории или CI-логах | Critical | Внешний secret store, маскирование, ротация; запрет в примерах | Secret scan, review | planned |
| T-C6 | Компрометация CI-пайплайна меняет артефакт | Critical | Минимальные права, protected branches, review, воспроизводимость | Audit CI config | planned |
| T-C7 | Unpinned GitHub Actions / `curl \| sh` | High | Запрет политикой (AGENTS), pin по SHA | Lint пайплайна | planned |
| T-C8 | Уязвимость в транзитивной зависимости | High | SCA, SLA обновлений, мониторинг CVE; честно указывать ограничения | SCA report | planned |

### 7.6 Обновления и упаковка

| ID | Угроза | Impact | Меры | Проверка | Статус |
| --- | --- | --- | --- | --- | --- |
| T-U1 | Подменённый установщик/бинарник | Critical | Подписанные артефакты, checksums, offline-проверка (GUI-005, SUP-003) | Проверка подписи в чистой среде | planned |
| T-U2 | Обязательный remote updater как скрытый сетевой канал | High | Без обязательного updater; offline-проверка обновления; без аналитики (GUI-005) | Network-off тест | planned |
| T-U3 | Rollback на уязвимую/несовместимую версию | High | Version pinning, отказ от понижения без явного решения, migration policy | Release tests | planned |
| T-U4 | Обновление ломает формат vault | High | Версионирование формата, обратная совместимость, fixture tests (VAULT-001/005) | Cross-version fixtures | planned |
| T-U5 | Пакет с небезопасными правами/лишними файлами | Medium | Минимальный состав пакета, review манифестов | Package diff | planned |

### 7.7 Приватность, логи, эксплуатация

| ID | Угроза | Impact | Меры | Проверка | Статус |
| --- | --- | --- | --- | --- | --- |
| T-P1 | Секреты в логах/трейсах/ошибках (оба компонента) | Critical | Allowlist/redaction, code review, тест «grep секретов» в артефактах (SRV-009, GUI-003) | CI secret scan, review | planned |
| T-P2 | Скрытая телеметрия/аналитика | High | Полный запрет в desktop; явная политика; отсутствие сетевых зависимостей | Network-off тест, dependency audit | planned |
| T-P3 | PII/связи аккаунтов в метриках verifier | Medium | Отсутствие subject/tenant labels, агрегация | Review | planned |
| T-P4 | Debug/verbose режим включает секреты | High | Отдельные безопасные debug-уровни, запрет дампа payload | Тест конфигураций | planned |

## 8. Негативные сценарии, которые обязательны к тестированию

Минимальный набор (расширяется в QA-001):

1. Неверный пароль vault → отказ, файл не изменён, пустой vault не создан.
2. Повреждённый/усечённый/подменённый vault → явная ошибка целостности, без восстановления «наугад».
3. Прерывание записи (между write и rename, ENOSPC, permission denied) → предыдущая копия доступна.
4. Fuzz `otpauth://` и парсера vault → нет panic/OOM, лимиты соблюдаются.
5. Повторное использование OTP/time-step, в том числе 100+ параллельных запросов → успех ≤ 1.
6. Replay challenge с другим subject/tenant/session_binding → отказ.
7. Cross-tenant запрос с валидной service identity → отказ без раскрытия существования данных.
8. Недоступность БД/verifier → отказ, relying party не повышает сессию.
9. Истёкший/использованный recovery code → отказ; повторное использование невозможно.
10. Неизвестный `key_id`/отсутствующий ключ → startup fail-closed.
11. Медленный/подменённый ответ backend → verifier не принимает неподписанные/непроверенные данные.
12. Сборка с отключённой сетью → успешна из проверенного mirror/vendor.
13. Проверка артефактов: подпись/checksum/SBOM соответствуют сборке.
14. Grep по логам/фикстурам/примерам → нет реальных seed/OTP/recovery/ключей.

## 9. Остаточные риски (принятые и явные)

| ID | Риск | Почему остаётся | Что снижает | Решение |
| --- | --- | --- | --- | --- |
| R-1 | Компрометированная ОС читает память/ввод/файлы | User-space приложение не может защититься от kernel/malware | Минимизация lifetime секретов, auto-lock, zeroize, отсутствие лишних привилегий | Принято; документировать в README/UI |
| R-2 | Слабый пароль vault → offline подбор | Пользовательский выбор | Argon2id, UX-предупреждения, backup-политика | Принято с границами |
| R-3 | Кража разблокированного устройства/сессии | Физический доступ | Auto-lock, OS lock integration | Принято |
| R-4 | TOTP фишинг/real-time relay | Природа TOTP | Явное позиционирование, будущий WebAuthn | Принято; не заявлять phishing resistance |
| R-5 | Компрометация relying party после успешной проверки | Вне периметра verifier | Контракт, примеры, предупреждения | Ответственность интегратора |
| R-6 | Атаки на цепочку поставок до ingestion | Доверие к upstream | Allowlist, review, vendor, SBOM, offline build | Принято с review-процессом |
| R-7 | Остаточные копии секретов в swap/дампах/ОС | Не контролируется полностью | zeroize best-effort, без crash reporting | Принято |
| R-8 | Непроверенное «железо»/TLS-стек | Вне периметра | Стандартные ОС/библиотеки | Принято |
| R-9 | DoS против локального desktop (диск, права, антивирус) | Локальная среда | Резервные копии, понятные ошибки | Принято |
| R-10 | Ошибки интеграции backend (неверная проверка результата) | Вне периметра | OpenAPI, примеры, contract tests, явные статусы | Принято; документировать |

## 10. Открытые вопросы → ADR

| Вопрос | ADR/TODO | Что должно быть решено |
| --- | --- | --- |
| Конкретные RustCrypto crates, AEAD, Argon2id параметры, key envelope | ADR-003 | Минимальный граф, лицензии, nonce/AAD, test vectors |
| Бинарный формат vault v1, limits, backup | ADR-004, VAULT-001 | Версии, поля, KDF migration, atomic write, error model |
| GUI framework и его поверхность атаки | ADR-002, GUI-001 | Dependency graph, native/unsafe, Wayland/X11, clipboard |
| Service authentication (mTLS vs scoped tokens) | ADR-005, SRV-003 | Trust scheme, scopes, rotation, tenant resolution |
| Challenge/TTL/rate-limit/replay policy | ADR-005, SRV-005 | Точные параметры, транзакционная семантика |
| Recovery codes, managed factor reset, dual control | ADR-006, REC-002, SRV-007 | Формат/энтропия кодов, хранение verifier'ов, атомарное погашение, reset-token, rate limit в БД, fail-closed, границы relying party |
| Модель обновлений и подписи | GUI-005, SUP-003 | Offline verification, ключи, rollback policy |
| Политика security disclosure и лицензия | PLAN §7 | Канал, SLA, публикация |

## 11. Матрица «актив → основная угроза → ключевая мера»

| Актив | Главные угрозы | Ключевые меры |
| --- | --- | --- |
| A-1 seeds desktop | T-V1, T-V2, T-D1, T-D2 | AEAD+KDF, atomic write, protected UX |
| A-1 seeds сервер | T-S5, T-S11, T-S12 | AEAD at rest, внешние ключи, rotation, redaction |
| A-2/A-3 пароль и ключи | T-V1, T-V6, T-D1 | Argon2id, zeroize, минимизация lifetime |
| A-5 backup | T-V1, T-V2, T-V8 | Тот же формат+AAD, проверка целостности, restore tests |
| A-6 recovery | T-S9, T-S11 | CSPRNG, digest+pepper, атомарное погашение |
| A-7 challenges/OTP | T-S2, T-S3, T-S4, T-S13 | Session binding, atomic step, rate limit, TLS |
| A-8/A-9 ключи и identity | T-S5, T-S6, T-S12 | Внешний secret store, scopes, rotation |
| A-10/A-11 логи и артефакты | T-P1, T-P3, T-C4, T-C5 | Redaction, SBOM, signatures |
| A-12 доступность | T-V3, T-S7, T-S14 | Atomic write, fail-closed, migrations |
| A-13 tenant identity | T-S1, T-S6 | Service identity, tenant-bound constraints |

## 12. Definition of Done для этого документа

- [x] Перечислены активы, акторы, границы доверия и допущения.
- [x] Для каждого домена (vault, OS/GUI, импорт, сервер, CI/CD, обновления) есть таблица угроз с impact и мерами.
- [x] Остаточные риски сформулированы без обещаний абсолютной защиты.
- [ ] Меры переведены из `planned` в `done` по мере появления тестов и артефактов (отслеживается в TODO).
- [ ] Проведён независимый security review (QA-002) и документ обновлён по результатам.

## 13. Changelog

| Дата | Версия | Изменение |
| --- | --- | --- |
| 15.11.2026 | 0.1 | Первичная публикация: активы, акторы, TB, угрозы по 7 доменам, остаточные риски, открытые ADR |
| 19.11.2026 | 0.2 | Ссылка на [recovery threat model](recovery-threat-model.md); открытый вопрос recovery → ADR-006 (`REC-002`) |
