# CLI

Все команды запускаются через `cargo run -- <command>`.

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
cargo run -- serve
cargo run -- serve --host 127.0.0.1 --port 3765
```

### `health`

Проверяет, что сервер отвечает на `/api/v1/health`.

Опции:

* `--port <port>` - порт для проверки.

Пример:

```bash
cargo run -- health --port 3765
```

### `init`

Создает конфиг и рабочую структуру, если их еще нет.

Пример:

```bash
cargo run -- init
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
cargo run -- add apps/prod/db --resource "PostgreSQL" --login admin --password "S3cret!" --tags prod,db
```

### `get`

Получает секрет по пути.

Аргументы:

* `path` - путь секрета.

Пример:

```bash
cargo run -- get apps/prod/db
```

### `list`

Показывает все секреты.

Пример:

```bash
cargo run -- list
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
cargo run -- update apps/prod/db --login readonly --tags prod,db,readonly
```

### `delete`

Удаляет секрет по пути.

Аргументы:

* `path` - путь секрета.

Пример:

```bash
cargo run -- delete apps/prod/db
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
cargo run -- token create "ops-token" --scopes secrets.read,secrets.list
```

#### `token list`

Показывает список токенов.

Пример:

```bash
cargo run -- token list
```

#### `token revoke`

Отзывает токен по UUID.

Аргументы:

* `id` - UUID токена.

Пример:

```bash
cargo run -- token revoke 8ce4eb74-ff4d-4a02-9b2f-5b53a2f2cb87
```

### `config`

Подкоманды для конфига.

#### `config init`

Создает `mia-secret.toml`.

Опции:

* `--force` - перезаписать файл, если он уже существует.

Пример:

```bash
cargo run -- config init --force
```

#### `config show`

Печатает итоговый конфиг.

Пример:

```bash
cargo run -- config show
```

#### `config validate`

Проверяет, что конфигурация корректна.

Пример:

```bash
cargo run -- config validate
```

## Токен Для Клиентских Команд

Команды `add`, `get`, `list`, `update`, `delete`, `token list`, `token revoke` и другие запросы к API используют токен из переменной окружения `MIA_SECRET_TOKEN`.

Пример:

```bash
$env:MIA_SECRET_TOKEN = "eyJ..."
cargo run -- list
```

Если токен не задан, защищенные вызовы вернут `401 Unauthorized`.
