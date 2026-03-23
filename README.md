# MIA Secret

MIA Secret - локальный менеджер секретов на Rust с CLI и HTTP API.

## Сборка

### Linux

```bash
rustup toolchain install stable
cargo build --release
```

Готовый бинарник: `target/release/mia-secret`.

### Windows (PowerShell)

```powershell
rustup toolchain install stable-msvc
cargo build --release
```

Готовый бинарник: `target\release\mia-secret.exe`.

Для CI-проверок качества:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --tests
```

## Быстрый старт

1. Убедитесь, что установлен Rust toolchain.
2. Инициализируйте конфиг и рабочую директорию:

```bash
cargo run -- init
```

3. Запустите сервер:

```bash
cargo run -- serve
```

4. Проверьте здоровье сервиса:

```bash
cargo run -- health
```

По умолчанию сервер слушает `127.0.0.1:3765`, а данные хранятся в `./data/secrets.db`.

## Init И Serve

### Инициализация

Команда `init`:

```bash
cargo run -- init
```

Создаёт структуру данных, файл базы и мастер-ключ, если их еще нет.

### Запуск сервера

Команда `serve`:

```bash
cargo run -- serve
```

Переопределение адреса:

```bash
cargo run -- serve --host 127.0.0.1 --port 3765
```

Команда `health` проверяет уже поднятый сервер:

```bash
cargo run -- health --port 3765
```

### Конфиг

Файл конфигурации по умолчанию ищется как `mia-secret.toml` в текущей папке, затем в системной папке конфигурации.

Полезные команды:

```bash
cargo run -- config init
cargo run -- config show
cargo run -- config validate
```

Для явного файла конфигурации используйте `--config path/to/file.toml`.

## CLI Примеры

### Секреты

Добавить секрет:

```bash
cargo run -- add apps/prod/db --resource "PostgreSQL" --login admin --password "S3cret!" --tags prod,db
```

Получить секрет по пути:

```bash
cargo run -- get apps/prod/db
```

Показать все секреты:

```bash
cargo run -- list
```

Обновить секрет:

```bash
cargo run -- update apps/prod/db --login readonly --tags prod,db,readonly
```

Удалить секрет:

```bash
cargo run -- delete apps/prod/db
```

### Токены

Создать токен:

```bash
cargo run -- token create "ops-token" --scopes secrets.read,secrets.list
```

Показать токены:

```bash
cargo run -- token list
```

Отозвать токен:

```bash
cargo run -- token revoke 2f4c6f3f-1b43-4f89-8d66-3a1f6d7e8f10
```

### Импорт Из Других Менеджеров

Импорт из CSV:

```bash
cargo run -- import csv --file ./exports/generic.csv --source generic
cargo run -- import csv --file ./exports/bitwarden.csv --source bitwarden --on-duplicate update
```

## Токен Через Env

CLI-команды, которые обращаются к локальному HTTP API, читают токен из переменной окружения `MIA_SECRET_TOKEN`.

Пример:

```bash
$env:MIA_SECRET_TOKEN = "eyJ..."
cargo run -- list
```

Если токен не задан, запросы к защищенным эндпоинтам вернут ошибку авторизации.

Также конфиг можно переопределять через переменные окружения формата `MIA_SECRET__SECTION__FIELD`, например:

```bash
$env:MIA_SECRET__SERVER__PORT = "3765"
$env:MIA_SECRET__GENERAL__LOG_LEVEL = "debug"
```

## Безопасность

* Храните `master.key` и файл базы только на локальной машине и не коммитьте их в репозиторий.
* Используйте только loopback-адреса: конфиг валидируется так, чтобы сервер не поднимался на внешнем интерфейсе.
* Токены хранить в переменной окружения удобнее, чем вставлять их в командную строку и историю shell.
* Секреты, заметки и пользовательские поля могут шифроваться в зависимости от конфигурации `crypto`.
* При создании первого токена доступ обычно открыт, а последующие операции с токенами требуют `tokens.manage`.

## API Эндпоинты

Сервер публикует API под префиксом `/api/v1`.

* `GET /api/v1/health` - состояние сервиса.
* `GET /api/v1/ready` - готовность сервиса (БД + миграции).
* `GET /api/v1/metrics` - метрики в формате Prometheus.
* `POST /api/v1/secrets` - создать секрет.
* `GET /api/v1/secrets` - список секретов.
* `GET /api/v1/secrets/{id}` - получить секрет по UUID.
* `PATCH /api/v1/secrets/{id}` - обновить секрет.
* `DELETE /api/v1/secrets/{id}` - удалить секрет.
* `GET /api/v1/secrets/by-path/{path}` - получить секрет по пути.
* `POST /api/v1/tokens` - создать токен.
* `GET /api/v1/tokens` - список токенов.
* `POST /api/v1/tokens/{id}/revoke` - отозвать токен.

Подробные примеры запросов и ответов см. в `docs/api.md`, а справку по CLI - в `docs/cli.md`.
Критерии приемки и релизный процесс: `docs/acceptance-checklist.md`, `docs/release.md`.
Эксплуатационные метрики и диагностика: `docs/observability.md`.
