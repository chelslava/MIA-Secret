# Release Process

## Версионирование

Используется SemVer:

- `MAJOR` - несовместимые изменения API/CLI/формата данных.
- `MINOR` - новая обратносуместимая функциональность.
- `PATCH` - исправления и hardening без изменения контрактов.

## Подготовка релиза

1. Обновить версию в `Cargo.toml`.
2. Прогнать quality gates:
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test --tests`
3. Проверить `docs/acceptance-checklist.md`.
4. Проверить, что `git status` чистый.

## Сборка артефактов

### Linux

```bash
cargo build --release
```

Артефакт: `target/release/mia-secret`

### Windows

```powershell
cargo build --release
```

Артефакт: `target\release\mia-secret.exe`

## Релизные заметки

В release notes включать:

- версию;
- список ключевых изменений;
- изменения API/CLI;
- миграции/изменения формата данных;
- известные ограничения и риски.
