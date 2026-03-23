# Binary Quickstart (без `cargo run`)

## Linux

1. Сборка release-бинаря:

```bash
cargo build --release
```

2. Инициализация:

```bash
./target/release/mia-secret config init --force
./target/release/mia-secret init
```

3. Запуск API:

```bash
./target/release/mia-secret serve
```

4. Проверка:

```bash
./target/release/mia-secret health
```

## Windows (PowerShell)

1. Сборка release-бинаря:

```powershell
cargo build --release
```

2. Инициализация:

```powershell
.\target\release\mia-secret.exe config init --force
.\target\release\mia-secret.exe init
```

3. Запуск API:

```powershell
.\target\release\mia-secret.exe serve
```

4. Проверка:

```powershell
.\target\release\mia-secret.exe health
```

## Использование собранных артефактов из `dist/`

После `scripts/release-build.sh` или `scripts/release-build.ps1`:
- Linux: распакуйте `dist/*.tar.gz` и запускайте `mia-secret` из пакета.
- Windows: распакуйте `dist/*.zip` и запускайте `mia-secret.exe`.

Проверка артефакта:
- `mia-secret --version`
- `mia-secret --help`
- `mia-secret health` (при запущенном локальном сервере)
