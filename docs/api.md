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
