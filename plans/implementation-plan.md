# План реализации MIA Secret

## Статус на 2026-03-23

### Sprint 1: Foundation + Config + Storage bootstrap
- [x] Инициализация проекта на Rust stable, единый бинарник.
- [x] Базовая модульная структура (`domain`, `service`, `storage`, `api`, `cli`, `config`, `crypto`).
- [x] Конфигурация TOML + ENV + CLI overrides с валидацией.
- [x] Команды `config init/show/validate`.
- [x] Команда `init`: создание `data-dir`, `secrets.db`, `master.key`.
- [x] Миграции вынесены в отдельную папку `migrations/` и применяются через `schema_migrations`.

### Sprint 2: Crypto + Application use cases
- [x] `CryptoService`: Argon2id + HKDF-SHA256 + AES-256-GCM.
- [x] CRUD use-cases секретов с шифрованием чувствительных полей.
- [x] Токены: create/list/revoke, в БД хранится hash токена.
- [~] Zeroization используется частично, можно усилить (временные буферы/ключи).

### Sprint 3: HTTP API + CLI
- [x] Axum API `/api/v1` для `health`, `secrets`, `tokens`.
- [x] Единый формат ошибок API.
- [x] CLI как клиент локального API (`add/get/list/update/delete`, `token ...`, `config ...`).
- [x] Авторизация/проверка scopes вынесена в middleware.
- [x] `traceId` и `x-trace-id` реализованы централизованно через middleware.

### Sprint 4: Hardening + Docs
- [x] README + документация API/CLI.
- [x] Интеграционные тесты на storage/service/token/secrets.
- [~] Security/operational hardening реализован частично.

## Что осталось до полного закрытия ТЗ

### 1. Безопасность и эксплуатация (высокий приоритет)
1. [x] Добавить явный middleware-пайплайн: auth bearer, scope-check, trace-id, request timeout.
2. [x] Добавить строгую политику логирования с редактированием чувствительных данных.
3. [x] Усилить работу с секретами в памяти (zeroize для критичных временных буферов в crypto/bootstrap/service).
4. [~] Ограничить права на `master.key` на уровне ОС (Unix: `0600` готово, Windows: best-effort ACL через `icacls`).

### 2. Хранилище и транзакционность (высокий приоритет)
1. [x] Ввести явные транзакции для операций записи (create/update/delete, revoke, last_used_at update).
2. [x] Вынести SQL-схему в отдельные миграции (`migrations/`) как артефакт поставки.
3. [x] Реализовать политику backup из конфига (`create_backup_before_write`, `max_backups`).

### 3. API/CLI соответствие ТЗ (средний приоритет)
1. [x] Опциональный `GET /api/v1/config` (только безопасные поля).
2. [x] Поддержка scopes/проверок в одном месте (централизованный route policy в API middleware).
3. [x] Улучшить коды ошибок CLI при API-ошибках (маппинг в категории из ТЗ).

### 4. Тесты и качество (средний приоритет)
1. [x] Добавить e2e-тесты API поверх HTTP (не только service/storage).
2. [~] Добавить негативные security-тесты: истекший/отозванный токен, missing scope, loopback-only bind (частично закрыто: revoked/missing scope).
3. [x] Включить в CI `clippy -D warnings`, `fmt --check`, `test`.

### 5. Поставка (средний приоритет)
1. Добавить инструкции по сборке для Windows/Linux в README.
2. Добавить checklist приемки (пункты 1-10 из ТЗ) в отдельный документ.
3. Оформить release-артефакты и версионирование.

## Критерии готовности (обновлено)
- [x] Только loopback bind (`127.0.0.1`/`::1`).
- [x] Конфиг обязателен и валидируется.
- [x] Базовый API и CLI работают.
- [x] Чувствительные поля секретов хранятся в шифрованном виде.
- [~] Полный security hardening и эксплуатационные требования (backup/ACL/log-redaction/zeroize) требуют доработки.
- [~] Полный security hardening и эксплуатационные требования (в основном остается надежный Windows ACL-hardening без best-effort) требуют доработки.
