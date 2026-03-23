# План реализации MIA Secret

## Sprint 1: Foundation + Config + Storage bootstrap
1. Инициализация проекта на Rust stable, единый бинарник, базовые quality gates (`rustfmt`, `clippy`, тесты).
2. Архитектурные слои: `domain`, `application`, `infrastructure`, `api`, `cli`, `config`.
3. Реализация конфигурации (TOML + ENV + CLI) с приоритетом: CLI > ENV > TOML > defaults.
4. Команды `config init/show/validate`.
5. Команда `init`: создание data-dir, БД, миграций, key-файла.

## Sprint 2: Crypto + Application use cases
1. `CryptoService`: Argon2id + HKDF-SHA256 + AES-256-GCM.
2. CRUD use-cases для секретов с валидацией и шифрованием.
3. Управление токенами (create/list/revoke), хранение только hash.

## Sprint 3: HTTP API + CLI
1. Axum API `/api/v1` (secrets/tokens/health).
2. Middleware: Bearer auth, scopes, trace-id, unified errors.
3. CLI как основной клиент к локальному API.

## Sprint 4: Hardening + Docs
1. Безопасные логи без утечек чувствительных данных.
2. Интеграционные и security-тесты.
3. README, примеры конфигурации, документация API и CLI.

## Критерии готовности
- Только loopback bind (`127.0.0.1`/`::1`).
- Секреты в БД только в зашифрованном виде.
- Конфиг обязателен и валидируется.
- Единая бизнес-логика для API и CLI.
