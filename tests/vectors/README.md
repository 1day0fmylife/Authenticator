# OTP test vectors

Общие публичные векторы для Rust (`desktop/crates/otp-core`) и Go (`server/internal/otp`). Один и тот же файл используется обеими реализациями; расхождение — блокер.

## Файлы

| Файл | Содержимое |
| --- | --- |
| `rfc4226-hotp.json` | HOTP RFC 4226: counters 0…9, 6 digits (published) и 8 digits (derived) |
| `rfc6238-totp.json` | TOTP RFC 6238: SHA-1/256/512, published 8-digit values; derived 6-digit; границы времени и period=60 |

## Правила

- **Это не реальные секреты.** Все `secret` — публичные тестовые значения из RFC. Не заменять их пользовательскими seed, не добавлять реальные OTP/QR/URI с секретом.
- `provenance` обязателен для каждого вектора:
  - `RFC 4226 Appendix D (published test value)` / `RFC 6238 Appendix B (published test value)` — значения напечатаны в RFC;
  - `derived: ...` — вычислены той же стандартной схемой (dynamic truncation, mod 10^digits, time-step), но не опубликованы в RFC.
- `digits` — только 6 или 8. `period` — положительное целое; в v1 поддержка нестандартных period допускается только при явной валидации.
- Векторы не описывают replay/rate-limit — это уровень verifier (SRV-005), не OTP core.

## Проверка

Независимая проверка на Go (stdlib; намеренно **не** импортирует `internal/otp`):

```bash
cd server
go run ./cmd/verify-vectors
# или с явным каталогом:
go run ./cmd/verify-vectors -dir ../tests/vectors
```

Инструмент пересчитывает все значения, отдельно сверяет published RFC-векторы и валидирует структуру JSON. Go-тесты пакета `server/internal/otp` читают эти же файлы.

Python и другие внешние генераторы в проекте не используются: векторы статичны, проверяются Go-инструментом и тестами.

## Изменение векторов

1. Добавить/изменить `provenance` и объяснить, откуда взято значение.
2. Запустить `go run ./cmd/verify-vectors` и тесты обеих реализаций; обновить обе реализации при необходимости.
3. Не «подгонять» реализацию под ошибочный вектор: published RFC-значения имеют приоритет.
