# Observability Runbook

## Быстрый старт

1. Убедиться, что сервис запущен локально.
2. Проверить liveness:
   - `curl http://127.0.0.1:3765/api/v1/health`
3. Проверить readiness:
   - `curl http://127.0.0.1:3765/api/v1/ready`
4. Снять метрики:
   - `curl http://127.0.0.1:3765/api/v1/metrics`

## Ключевые метрики

- `mia_http_requests_total`: общий входящий трафик.
- `mia_http_errors_total`: общее количество ответов с `status >= 400`.
- `mia_http_timeouts_total`: число ответов `408`.
- `mia_auth_failures_total`: ошибки авторизации (missing/invalid token, missing scope, revoked/expired token).
- `mia_rate_limited_total`: количество отклонений по rate-limit.
- `mia_token_created_total`: успешно созданные токены.
- `mia_token_revoked_total`: успешно отозванные токены.
- `mia_http_requests_by_route_total{method,path,status}`: детализация трафика по маршрутам.
- `mia_http_latency_ms_sum{method,path,status}`: суммарная задержка по маршрутам.

## Диагностика

1. Если `ready.status = not_ready`:
   - проверить путь к БД в конфиге;
   - проверить наличие `schema_migrations`;
   - перепроверить права доступа к каталогу данных.

2. Если растет `mia_auth_failures_total`:
   - проверить валидность `MIA_SECRET_TOKEN`;
   - проверить expiry/revoked у токенов;
   - проверить требуемые `scopes` для конкретного endpoint.

3. Если растет `mia_rate_limited_total`:
   - временно увеличить `server.protected_rate_limit_rps`;
   - проверить burst-нагрузку клиента и добавить backoff/retry политику.

4. Если растет `mia_http_timeouts_total`:
   - проверить `server.request_timeout_secs`;
   - проверить нагрузку на SQLite и длительные операции.
