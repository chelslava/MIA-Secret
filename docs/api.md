# API

HTTP API доступен по префиксу `/api/v1`.

Все защищенные запросы принимают заголовок:

```http
Authorization: Bearer <token>
```

Если заголовок не задан или токен невалиден, сервер возвращает `401 Unauthorized`.

## Формат Ошибки

Ошибка возвращается в обертке:

```json
{
  "error": {
    "code": "unauthorized",
    "message": "missing bearer token",
    "traceId": "c6d5b0e3-7d15-4e43-8a1f-6a5be8ccf3a4"
  }
}
```

Возможные коды включают:

* `validation_error`
* `not_found`
* `conflict`
* `unauthorized`
* `forbidden`
* `rate_limited`
* `crypto_error`
* `config_error`
* `storage_error`
* `internal_error`

`traceId` удобно передавать при разборе инцидентов и логов.
Также сервер возвращает тот же идентификатор в HTTP-заголовке `x-trace-id`.

## Health

`GET /api/v1/health`

Пример ответа:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "database_ready": true,
  "config_loaded": true
}
```

## Readiness

`GET /api/v1/ready`

Проверяет реальную готовность сервиса к обработке запросов:
- доступность SQLite в read-only режиме;
- наличие таблицы миграций `schema_migrations`;
- факт загрузки конфигурации.

Возвращает:
- `200 OK`, если сервис готов (`status = "ready"`);
- `503 Service Unavailable`, если хотя бы одна проверка провалена (`status = "not_ready"`).

Пример ответа:

```json
{
  "status": "ready",
  "version": "0.1.0",
  "checks": {
    "config_loaded": true,
    "database_connection": true,
    "schema_migrations_present": true
  }
}
```

## Metrics

`GET /api/v1/metrics`

Возвращает метрики в текстовом формате Prometheus (`text/plain`).
Endpoint доступен без токена и предназначен для локального мониторинга.

Основные метрики:
- `mia_http_requests_total`
- `mia_http_errors_total`
- `mia_http_timeouts_total`
- `mia_auth_failures_total`
- `mia_rate_limited_total`
- `mia_token_created_total`
- `mia_token_revoked_total`
- `mia_http_requests_by_route_total{method,path,status}`
- `mia_http_latency_ms_sum{method,path,status}`

## Секреты

### Создать секрет

`POST /api/v1/secrets`

Пример запроса:

```json
{
  "path": "apps/prod/db",
  "resource": "PostgreSQL",
  "login": "admin",
  "password": "S3cret!",
  "url": "https://db.example.local",
  "notes": "Основной продовый доступ",
  "tags": ["prod", "db"],
  "custom_fields": {
    "owner": "platform",
    "rotation_days": 30
  }
}
```

Пример ответа:

```json
{
  "id": "2f4c6f3f-1b43-4f89-8d66-3a1f6d7e8f10",
  "path": "apps/prod/db",
  "resource": "PostgreSQL",
  "login": "admin",
  "password": "S3cret!",
  "url": "https://db.example.local",
  "notes": "Основной продовый доступ",
  "tags": ["prod", "db"],
  "custom_fields": {
    "owner": "platform",
    "rotation_days": 30
  },
  "created_at": 1711180800,
  "updated_at": 1711180800
}
```

### Список секретов

`GET /api/v1/secrets`

Пример ответа:

```json
[
  {
    "id": "2f4c6f3f-1b43-4f89-8d66-3a1f6d7e8f10",
    "path": "apps/prod/db",
    "resource": "PostgreSQL",
    "login": "admin",
    "password": "S3cret!",
    "url": "https://db.example.local",
    "notes": "Основной продовый доступ",
    "tags": ["prod", "db"],
    "custom_fields": null,
    "created_at": 1711180800,
    "updated_at": 1711180800
  }
]
```

### Получить секрет по UUID

`GET /api/v1/secrets/{id}`

### Получить секрет по пути

`GET /api/v1/secrets/by-path/{path}`

Пример:

```bash
curl -H "Authorization: Bearer $MIA_SECRET_TOKEN" \
  http://127.0.0.1:3765/api/v1/secrets/by-path/apps%2Fprod%2Fdb
```

### Обновить секрет

`PATCH /api/v1/secrets/{id}`

В запросе можно передавать только поля, которые нужно заменить.

Пример:

```json
{
  "login": "readonly",
  "tags": ["prod", "db", "readonly"]
}
```

### Удалить секрет

`DELETE /api/v1/secrets/{id}`

Успешный ответ возвращает `204 No Content`.

## Токены

### Создать токен

`POST /api/v1/tokens`

Пример запроса:

```json
{
  "name": "ops-token",
  "scopes": ["secrets.read", "secrets.list"],
  "expires_at": 1713772800
}
```

Пример ответа:

```json
{
  "token": "eyJ1c2VyLWdlbmVyYXRlZC10b2tlbi1zdHJpbmci",
  "record": {
    "id": "8ce4eb74-ff4d-4a02-9b2f-5b53a2f2cb87",
    "name": "ops-token",
    "scopes": ["secrets.read", "secrets.list"],
    "created_at": 1711180800,
    "expires_at": 1713772800,
    "revoked_at": null,
    "last_used_at": null
  }
}
```

### Список токенов

`GET /api/v1/tokens`

Пример ответа:

```json
[
  {
    "id": "8ce4eb74-ff4d-4a02-9b2f-5b53a2f2cb87",
    "name": "ops-token",
    "scopes": ["secrets.read", "secrets.list"],
    "created_at": 1711180800,
    "expires_at": 1713772800,
    "revoked_at": null,
    "last_used_at": 1711180900
  }
]
```

### Отозвать токен

`POST /api/v1/tokens/{id}/revoke`

Пример ответа:

```json
{
  "id": "8ce4eb74-ff4d-4a02-9b2f-5b53a2f2cb87",
  "name": "ops-token",
  "scopes": ["secrets.read", "secrets.list"],
  "created_at": 1711180800,
  "expires_at": 1713772800,
  "revoked_at": 1711182000,
  "last_used_at": 1711180900
}
```

## Конфигурация

### Безопасное чтение конфигурации

`GET /api/v1/config`

Возвращает только безопасные поля конфигурации (без ключевого материала и без секретов).
Требует scope `config.read`.

Пример ответа:

```json
{
  "general": {
    "data_dir": "./data",
    "database_path": "./data/secrets.db",
    "log_level": "info",
    "enable_file_logging": true
  },
  "server": {
    "host": "127.0.0.1",
    "port": 3765,
    "request_timeout_secs": 30,
    "max_request_body_kb": 64,
    "protected_rate_limit_rps": 30
  }
}
```

## Скоупы

Поддерживаемые значения `scopes`:

* `secrets.read`
* `secrets.write`
* `tokens.manage`
* `secrets.delete`
* `secrets.list`
* `config.read`
* `service.health`

## Замечания По Авторизации

* `GET /api/v1/health` не требует токена.
* Создание первого токена может быть доступно без авторизации.
* Когда хотя бы один токен уже есть, создание новых токенов требует `tokens.manage`.
* Для остальных защищенных операций нужны соответствующие скоупы.
* Проверка Bearer-токена и скоупов выполняется централизованно через middleware.

## Middleware

В API включены базовые middleware:

* `trace-id`: на каждый запрос генерируется `traceId`, возвращается в error body и заголовке `x-trace-id`.
* `authz`: централизованная проверка Bearer-токена и требуемого scope по маршруту.
* `timeout`: ограничение времени обработки запроса согласно `server.request_timeout_secs`.
* `body-limit`: ограничение размера request body согласно `server.max_request_body_kb` (ответ `413 Payload Too Large` при превышении).
* `rate-limit`: ограничение скорости для защищенных endpoint-ов согласно `server.protected_rate_limit_rps` (ответ `429 Too Many Requests` при превышении).
* `metrics`: счётчики запросов/ошибок/таймаутов и суммарной latency по маршрутам.
