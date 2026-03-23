# CLI

Основной способ запуска CLI после сборки:

```bash
mia-secret <command>
```

Для разработки можно использовать:

```bash
cargo run -- <command>
```

## Общие Опции

* `--config <path>` - использовать конкретный TOML-файл конфигурации.

## Команды

### `serve`

Запускает HTTP API.

Опции:

* `--host <host>` - переопределить адрес сервера.
* `--port <port>` - переопределить порт сервера.

Примеры:

```bash
mia-secret serve
mia-secret serve --host 127.0.0.1 --port 3765
```

### `health`

Проверяет, что сервер отвечает на `/api/v1/health`.

Опции:

* `--port <port>` - порт для проверки.

Пример:

```bash
mia-secret health --port 3765
```

### `init`

Создает конфиг и рабочую структуру, если их еще нет.

Пример:

```bash
mia-secret init
```

### `add`

Создает секрет через локальный HTTP API.

Аргументы:

* `path` - путь секрета.

Опции:

* `--resource <text>`
* `--login <text>`
* `--password <text>` - обязательный.
* `--url <text>`
* `--notes <text>`
* `--tags <a,b,c>` - список через запятую.

Пример:

```bash
mia-secret add apps/prod/db --resource "PostgreSQL" --login admin --password "S3cret!" --tags prod,db
```

### `get`

Получает секрет по пути.

Аргументы:

* `path` - путь секрета.

Пример:

```bash
mia-secret get apps/prod/db
```

### `list`

Показывает все секреты.

Пример:

```bash
mia-secret list
```

### `update`

Обновляет существующий секрет по пути.

Аргументы:

* `path` - текущий путь секрета.

Опции:

* `--new-path <text>`
* `--resource <text>`
* `--login <text>`
* `--password <text>`
* `--url <text>`
* `--notes <text>`
* `--tags <a,b,c>`

Пример:

```bash
mia-secret update apps/prod/db --login readonly --tags prod,db,readonly
```

### `delete`

Удаляет секрет по пути.

Аргументы:

* `path` - путь секрета.

Пример:

```bash
mia-secret delete apps/prod/db
```

### `token`

Подкоманды для работы с токенами.

#### `token create`

Создает токен.

Аргументы:

* `name` - имя токена.

Опции:

* `--scopes <a,b,c>` - список скоупов через запятую.
* `--expires-at <unix_timestamp>` - срок действия в Unix time.

Пример:

```bash
mia-secret token create "ops-token" --scopes secrets.read,secrets.list
```

#### `token list`

Показывает список токенов.

Пример:

```bash
mia-secret token list
```

#### `token revoke`

Отзывает токен по UUID.

Аргументы:

* `id` - UUID токена.

Пример:

```bash
mia-secret token revoke 8ce4eb74-ff4d-4a02-9b2f-5b53a2f2cb87
```

### `config`

Подкоманды для конфига.

#### `config init`

Создает `mia-secret.toml`.

Опции:

* `--force` - перезаписать файл, если он уже существует.

Пример:

```bash
mia-secret config init --force
```

#### `config show`

Печатает итоговый конфиг.

Пример:

```bash
mia-secret config show
```

#### `config validate`

Проверяет, что конфигурация корректна.

Пример:

```bash
mia-secret config validate
```

## Токен Для Клиентских Команд

Команды `add`, `get`, `list`, `update`, `delete`, `token list`, `token revoke` и другие запросы к API используют токен из переменной окружения `MIA_SECRET_TOKEN`.

Пример:

```bash
$env:MIA_SECRET_TOKEN = "eyJ..."
mia-secret list
```

Если токен не задан, защищенные вызовы вернут `401 Unauthorized`.

## Exit Codes

CLI возвращает стабильные коды завершения:

* `0` - успешное выполнение.
* `2` - ошибки конфигурации/валидации/адреса (`config`, `validation`, `address`).
* `3` - ошибки авторизации и прав (`unauthorized`, `forbidden`).
* `4` - ресурс не найден (`not found`).
* `5` - конфликт данных (`conflict`).
* `6` - операционные ошибки (`HTTP`, `I/O`, `storage`, `crypto`, `serialization`, `server`).
