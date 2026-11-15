# Vault v1 test fixtures

Синтетические зашифрованные образцы формата vault v1 из [ADR-004](../../../security/adr/0004-vault.md). Используются conformance-тестами `desktop/crates/vault`; сам формат здесь не «объявляется проверенным» — фиксируются только байты и negative-сценарии.

## Это не реальные секреты

Все пароли, secret, issuer и account в fixtures — **публичные тестовые значения**. `manifest.json` намеренно содержит plaintext payload и secret в hex, поэтому реальные credentials сюда добавлять нельзя. Никогда не переносить в fixtures пользовательские seed, OTP, QR payload или recovery codes.

Единственный пароль fixtures: `correct horse battery staple` (test-only, 28 байт). Он одинаков для всех файлов, чтобы проверять формат, а не политику паролей.

## Файлы

| Файл | Содержимое | KDF |
| --- | --- | --- |
| `empty.avault` | пустой payload (`record_count=0`), минимальный размер файла 112 байт | min: 19 456 KiB, t=2, p=1 |
| `totp-sha1.avault` | TOTP SHA-1, 6 digits, period 30 | min |
| `totp-sha256.avault` | TOTP SHA-256, 8 digits, period 60 | min |
| `totp-sha512.avault` | TOTP SHA-512, 6 digits, period 86 400 (верхняя граница) | min |
| `hotp.avault` | HOTP SHA-1, 6 digits, counter 42 | min |
| `mixed-boundaries.avault` | несколько записей: минимальные длины, secret 1024 байта, строки 256 байт, UTF-8 issuer/account, `u64::MAX` counter | default: 65 536 KiB, t=3, p=1 |
| `manifest.json` | пароль, salt/nonce hex, заголовок, SHA-256 файла, plaintext hex и метаданные записей | — |

`min`-параметры выбраны только для скорости тестов; production default — 64 MiB, t=3, p=1. Значения salt/nonce детерминированы и уникальны для каждого файла, потому что production API не принимает их от вызывающего кода.

## Проверка

```bash
cd desktop
cargo test -p vault --locked
```

Что проверяется:

- файл побайтово совпадает с повторной генерацией (заголовок, ciphertext, manifest);
- `open` с правильным паролем возвращает записи, совпадающие с manifest;
- неверный пароль, изменённый ciphertext или nonce → `AuthenticationFailed`;
- изменённый reserved/magic, усечённый файл или trailing bytes → `Corrupt`;
- лимиты формата и отсутствие секретов в `Debug` — unit-тестами crate.

## Перегенерация

Только после **reviewed** изменения формата или fixtures, а не для «починки» упавшего теста:

```bash
cd desktop
cargo test -p vault generate_fixtures -- --ignored
```

Команда перезаписывает `*.avault` и `manifest.json` в этой директории. После неё нужно проверить diff, прогнать полный `cargo test`/`clippy` и обновить ADR-004 (новая версия при изменении формата).

## Ограничения

- Нет независимого cross-language verifier формата; Argon2id отсутствует в Go stdlib. Проверка примитивов опирается на RFC-векторы ADR-003.
- Fixtures не проверяют crash consistency, Windows ACL, сетевые ФС и поведение при нехватке места — это VAULT-003.
- Совместимость формата с будущими версиями не гарантируется: reader обязан отклонять неизвестные версии.
