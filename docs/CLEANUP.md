# Что можно безопасно удалять

## В дереве `zip_crack/`

| Путь | Можно удалить? | Зачем |
|------|----------------|--------|
| `android/.gradle/` | **да** | кэш Gradle проекта |
| `android/build/`, `android/app/build/` | **да** | артефакты сборки |
| `android/local.properties` | **да** (на новом устройстве) | путь к SDK, **пересоздаётся** |
| `dist/*.apk` | **да**, если есть свежий билд | готовые APK |
| `dist/sample_*`, `dist/test.docx` | по желанию | тестовые файлы (пароли в README) |
| `android/zipcrack-release.keystore` | **нет**, если хотите тот же signing | иначе сгенерируете новый |
| `android/app/src/…`, `crack/`, `main.go` | **нет** | исходники |
| `android/gradle/`, `gradlew` | **нет** | wrapper |
| `macos/` | нет, если собираете macOS GUI | иконки для .app/.dmg |
| `build/` | **да** | промежуточная сборка Go GUI |
| `cmd/gui/` | **нет** | исходники macOS GUI (Fyne) |
| `crack/` | **нет** | pure Go ядро (ZIP/7z/Office) |
| `third_party/7zip/` | да (только заметка) | native 7zz больше не используется |

## Вне репозитория (на машине сборки)

| Путь | Можно удалить? |
|------|----------------|
| `/tmp/zip_crack_android.*` | **да** (копии для сборки) |
| `/tmp/zip_crack_go.*`, `/tmp/poi`, `/tmp/jartest` | **да** |
| `~/.gradle/caches/` | да, но Gradle скачает всё заново |
| `/root/android-sdk` | **нет**, если это ваш SDK |

## Быстрая очистка проекта

```bash
cd /path/to/zip_crack
rm -rf android/.gradle android/build android/app/build build
rm -f dist/PasswordCracker-*.apk
# опционально temp:
rm -rf /tmp/zip_crack_android.* /tmp/zip_crack_go.*
```

Сборка снова:

```bash
bash scripts/build-android.sh
```
