# Operations Runbook

## Область

Документ покрывает эксплуатационные процедуры:
- backup;
- restore;
- ротация мастер-ключа.

## Подготовка

1. Используйте отдельный каталог данных (по умолчанию `./data`).
2. Убедитесь, что файл `master.key` хранится только локально и имеет строгие права доступа.
3. Перед любыми операциями восстановления/ротации остановите процесс `mia-secret serve`.

## Backup

### Автоматический backup в приложении

Через конфиг:
- `storage.create_backup_before_write = true`
- `storage.max_backups = <N>`

При каждой операции записи SQLite-файл копируется в `${data_dir}/backups`, старые копии ротируются до `max_backups`.

### Ручной backup (рекомендуется периодически)

Скопируйте оба файла:
- `secrets.db`
- `master.key`

Пример PowerShell:

```powershell
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Force -Path ".\backup\$ts" | Out-Null
Copy-Item ".\data\secrets.db" ".\backup\$ts\secrets.db" -Force
Copy-Item ".\data\master.key" ".\backup\$ts\master.key" -Force
```

Пример Linux:

```bash
ts="$(date +%Y%m%d-%H%M%S)"
mkdir -p "./backup/$ts"
cp "./data/secrets.db" "./backup/$ts/secrets.db"
cp "./data/master.key" "./backup/$ts/master.key"
```

## Restore

1. Остановите сервис.
2. Скопируйте `secrets.db` и `master.key` из backup в рабочий `data_dir`.
3. Запустите сервис.
4. Проверьте:
   - `mia-secret health`
   - `GET /api/v1/ready` должен вернуть `status=ready`.

Важно: `secrets.db` и `master.key` всегда восстанавливаются парой из одного и того же backup-снимка.

## Ротация мастер-ключа

### Текущее состояние

Автоматической online-ротации с перешифровкой всех записей в текущей версии нет.

### Безопасная процедура сейчас (maintenance window)

1. Остановить запись в сервис.
2. Сделать полный backup (`secrets.db` + `master.key`).
3. Поднять новую инсталляцию с новым `master.key`.
4. Перенести секреты в новую инсталляцию контролируемой миграцией (например, из доверенного исходного CSV/инвентаря).
5. Проверить целостность (кол-во записей, выборочная проверка decrypt/read).
6. Переключить клиентов на новый инстанс.
7. Старые backup-ы хранить по retention-политике и удалять безопасно.

## Проверки после изменений

После backup/restore/ротации:
- `mia-secret health`
- `mia-secret list` (с валидным токеном)
- выборочно `mia-secret get <path>`
- `curl http://127.0.0.1:3765/api/v1/metrics` (проверка observability)
