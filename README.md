# Password Cracker

Подбор паролей: **ZIP** (ZipCrypto / AES), **7z**, **encrypted DOCX/XLSX** (Office OLE).

| Платформа | Сборка | Движок |
|-----------|--------|--------|
| **macOS** | `dist/Password Cracker.dmg` (Go + Fyne) | pure Go |
| **Windows** | `dist/PasswordCracker-gui.exe`, `dist/zip_crack.exe` (Go + Fyne) | pure Go |
| **Android** | `dist/PasswordCracker-1.5.apk` | Kotlin + zip4j / Commons Compress / POI |
| **CLI** | `go build .` | pure Go (тот же `crack/`) |

## macOS

```text
dist/Password Cracker.dmg
dist/Password Cracker.app
dist/zip_crack          # CLI
```

Те же возможности, что у Android-приложения:

| Формат | Движок |
|--------|--------|
| ZIP ZipCrypto | native Go (быстро) |
| ZIP AES | yeka/zip |
| 7z | bodgit/sevenzip |
| DOCX/XLSX encrypted | MS-OFFCRYPTO (agile/standard), pure Go |

Word / Java **не нужны**.

### Установка

1. Откройте `dist/Password Cracker.dmg` → перетащите в **Applications**.
2. При первом запуске: **Системные настройки → Конфиденциальность и безопасность → Всё равно открыть** (ad-hoc подпись).

### Пересборка .app + DMG

```bash
# нужен Go (CGO для Fyne GUI) и Python3+Pillow (иконка)
bash scripts/package-macos.sh
```

Только CLI:

```bash
go build -o dist/zip_crack .
./dist/zip_crack -digits -min 1 -max 4 archive.docx
```

Только GUI без упаковки:

```bash
go run ./cmd/gui
```

## Windows

```text
dist/PasswordCracker-gui.exe  # GUI без консольного окна
dist/zip_crack.exe            # CLI
```

Те же Go-backends, что в macOS/CLI версии: ZIP ZipCrypto, ZIP AES, 7z и encrypted DOCX/XLSX. Java / Word **не нужны**.

Пересборка:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-windows-go.ps1
```

Скрипт собирает оба бинарника в `dist/` с флагами уменьшения размера:
`-buildvcs=false` и `-ldflags "-s -w -buildid="` (`-H=windowsgui` дополнительно для GUI).
На amd64 GUI получается около 25.6 MiB вместо 43.9 MiB без strip-флагов.

Иконки Windows уже лежат в репозитории как `rsrc_windows_*.syso`; пересоздавать их нужно только при смене `macos/icon-runtime.png` или `cmd/gui/icon.png`.

## Android APK

```text
dist/PasswordCracker-1.5.apk
```

- Сборка на телефоне (Termux + Ubuntu proot): **`docs/BUILD-ON-ANDROID-PHONE.md`**
- Что можно удалять: **`docs/CLEANUP.md`** · `bash scripts/cleanup.sh`

### Тестовые файлы

| Файл | Пароль | Тип |
|------|--------|-----|
| `dist/sample_zipcrypto_4821.zip` | `4821` | ZIP · ZipCrypto |
| `dist/sample_zip_aes_4821.zip` | `4821` | ZIP · AES |
| `dist/sample_7z_aes_4821.7z` | `4821` | 7z · AES |
| `dist/test.docx` | `5482` | Word agile AES-256/SHA-512 |

### Backend (Android)

| Формат | Движок |
|--------|--------|
| ZIP ZipCrypto | native (быстро) |
| ZIP AES | zip4j |
| 7z | Commons Compress |
| DOCX/XLSX encrypted | Apache POI |

Пересборка:

```bash
bash scripts/build-android.sh
```

## Go CLI

```bash
go build -o zip_crack .
./zip_crack -digits -min 1 -max 4 archive.zip   # или .7z / .docx
./zip_crack -q -digits -min 4 -max 4 dist/test.docx
```

Тесты ядра:

```bash
go test ./crack/ -count=1
```

## Очистка

```bash
bash scripts/cleanup.sh          # .gradle, build, /tmp workdirs
bash scripts/cleanup.sh --apks   # + dist/*.apk
```
