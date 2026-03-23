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

### Linux (одной командой)

```bash
bash scripts/release-build.sh
```

Артефакты:
- `dist/mia-secret-v<version>-linux-x64.tar.gz`
- `dist/mia-secret-v<version>-linux-x64.tar.gz.sha256`

### Windows (одной командой)

```powershell
pwsh -File scripts/release-build.ps1
```

Артефакты:
- `dist\mia-secret-v<version>-windows-x64.zip`
- `dist\mia-secret-v<version>-windows-x64.zip.sha256`

### Опционально: target triple

Если нужен конкретный target triple:

```bash
bash scripts/release-build.sh x86_64-unknown-linux-gnu
```

```powershell
pwsh -File scripts/release-build.ps1 -Target x86_64-pc-windows-msvc
```

## CI-сборка артефактов

Workflow `.github/workflows/release-artifacts.yml`:
- запускается вручную (`workflow_dispatch`) или при push тега вида `v*`;
- собирает артефакты для Linux и Windows;
- публикует их как GitHub Actions artifacts.

## Релизные заметки

В release notes включать:

- версию;
- список ключевых изменений;
- изменения API/CLI;
- миграции/изменения формата данных;
- известные ограничения и риски.
