# План дальнейшего развития MIA Secret

Дата обновления: 2026-03-23
Горизонт: 3 спринта (по 2 недели)

## Сводка статуса
- Sprint A (Надежность и наблюдаемость): **закрыт**
- Sprint B (Качество и тестирование): **высокий приоритет закрыт, идет расширение контрактов**
- Sprint C (DX и релизы): **закрыт**

## Что уже закрыто
1. Надежность и guardrails
- [x] `GET /api/v1/ready` с реальными проверками SQLite + `schema_migrations`.
- [x] Request timeout middleware + e2e проверка поведения.
- [x] Graceful shutdown e2e: после stop сервер не принимает новые соединения.
- [x] Ограничение размера body через `server.max_request_body_kb` + e2e на `413`.
- [x] Rate-limit защищенных endpoint-ов через `server.protected_rate_limit_rps` + e2e на `429`.
- [x] Явный SQLite busy-timeout через `storage.sqlite_busy_timeout_ms`.

2. Наблюдаемость
- [x] `GET /api/v1/metrics` в Prometheus-формате.
- [x] HTTP-метрики: requests/errors/timeouts/route counters/latency sum.
- [x] Security/ops-метрики: `auth_failures`, `rate_limited`, `token_created`, `token_revoked`.
- [x] Runbook по наблюдаемости: `docs/observability.md`.

3. Качество и контракты
- [x] Существенно расширено покрытие unit/e2e в `api/config/main/error`.
- [x] Цели покрытия достигнуты: line > 75%, function > 70%.
- [x] Базовые и строгие API contract tests (`tests/api_contract.rs`).
- [x] Выделенный CI job для API контрактов (`api-contract`).
- [x] CLI smoke tests + выделенный CI job (`cli-smoke`).
- [x] Стабильные CLI exit-коды задокументированы и покрыты тестами.

4. Импорт/миграция из других менеджеров паролей
- [x] CLI `import csv`.
- [x] Поддержка источников `generic` и `bitwarden`.
- [x] Политики дубликатов `skip` / `update`.
- [x] Smoke-проверка импорта CSV в тестах.

5. Релизный контур (частично Sprint C)
- [x] Скрипты сборки артефактов одной командой:
  - `scripts/release-build.sh`
  - `scripts/release-build.ps1`
- [x] Packaging + `sha256` checksum.
- [x] CI workflow для релизных артефактов (`release-artifacts.yml`, trigger по tag `v*`/manual).
- [x] Обновлена документация релиза (`docs/release.md`).

## Что осталось (по приоритету)

### P0 — Дозакрыть Sprint A
1. Негативная деградация хранилища
- [x] Добавить e2e/contract сценарий `ready = not_ready` при деградации БД (например, отсутствует/повреждена таблица миграций).
- [x] Проверить ожидаемое поведение CLI `health` при такой деградации.

### P1 — Укрепить Sprint B
1. Контрактные тесты API (расширение)
- [ ] Добавить контрактные проверки для дополнительных error-case веток `tokens`/`secrets` (особенно конфликты и edge-cases update/delete).
- [ ] При необходимости вынести ожидания схем в snapshot-файлы для более прозрачного diff.

2. CLI контракт ошибок
- [x] Расширить smoke-пакет для `add/get/update/delete/token` на стабильность exit-code + ключевых сообщений.

### P2 — Продолжить Sprint C
1. Release automation v2
- [x] Добавить автогенерацию release notes/changelog (Conventional Commits или аналог).
- [x] Добавить smoke-check запуска собранного артефакта в release workflow.

2. Эксплуатационная документация
- [x] Runbook backup/restore и ротации ключей (отдельный документ).
- [x] Quickstart для бинарной поставки без `cargo run` (с примерами для Linux/Windows).

## Ближайшие коммиты (актуальный порядок)
1. Расширение API contract tests по конфликтам и update/delete edge-cases.
2. Snapshot-ожидания для API контрактов (если упростят review diff).

## KPI (актуально)
- Line coverage >= 75%: [x]
- Function coverage >= 70%: [x]
- API contract checks в CI: [x]
- CLI smoke checks в CI: [x]
- Наблюдаемость (health/readiness/metrics + runbook) готова для локальной эксплуатации: [x]
- Полный production-runbook (backup/restore/key-rotation/release notes automation): [x]
