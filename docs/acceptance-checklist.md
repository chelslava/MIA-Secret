# Acceptance Checklist

Чеклист основан на критериях приемки из `tz.md`.

1. Проект полностью реализован на Rust.
- [x] Исходный код на Rust, сборка через `cargo`.

2. Приложение использует TOML-конфиг.
- [x] Основной формат конфигурации `mia-secret.toml`.

3. Конфиг создается и валидируется.
- [x] `config init`, `config validate`, валидация на старте.

4. Сервис работает только локально.
- [x] Разрешен loopback-only bind; `0.0.0.0` отклоняется.

5. API доступен.
- [x] Реализованы endpoint-ы `/api/v1/health`, `/secrets`, `/tokens`, `/config`.

6. CLI полностью работает.
- [x] Реализованы базовые команды `serve/init/health/config/...` и `secrets/tokens`.
- [~] UX-маппинг ошибок улучшен, возможна дальнейшая полировка текстов.

7. Секреты шифруются.
- [x] Чувствительные поля шифруются через AES-256-GCM.

8. Токены работают корректно.
- [x] Хранится hash, есть create/list/revoke, проверка scopes/expiry/revoked.

9. Чувствительные данные не пишутся в логи.
- [x] Централизованные middleware-логи без body/token.
- [x] Redaction для неструктурированных API-ошибок в CLI.

10. Конфигурация управляет параметрами сервиса и безопасности.
- [x] Параметры server/security/crypto/storage применяются runtime.

## Дополнительная верификация

- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --all-targets -- -D warnings`
- [x] `cargo test --tests`
