# Сборка Password Cracker на Android-смартфоне  
(Termux + proot-distro Ubuntu)

Инструкция «для себя»: перенос папки `zip_crack` на другой телефон и получение **release APK**. 

---

## 0. Что переносить

### Копировать целиком

```
zip_crack/
  android/          # исходники + gradle wrapper + keystore
  crack/            # Go (CLI, опционально)
  scripts/
  docs/
  dist/             # samples (apk можно не тащить)
  src/ main.go …    # desktop, не обязательны для APK
  README.md
```

### Можно **не** копировать (или удалить перед копированием)

```
android/.gradle/
android/build/
android/app/build/
target/
dist/*.apk
.git/               # по желанию
```

### Обязательно иметь на целевом устройстве

- `android/gradlew` + `android/gradle/wrapper/*`
- `android/zipcrack-release.keystore`  
  (если нет – сгенерируете, подпись будет **другая**, обновление поверх старого APK не встанет)
- исходники `android/app/src/...`

### Не тащить как есть

- `android/local.properties` – на новом телефоне путь к SDK **другой** (скрипт/инструкция пересоздаст)

---

## 1. Termux (хост Android)

```bash
# в Termux (не в Ubuntu)
pkg update
pkg install -y proot-distro git
# при необходимости:
# pkg install -y termux-api
```

Рекомендуется хранить исходники на **внутреннем хранилище**, доступном и из proot:

```bash
# пример: /sdcard/zip_crack  или  ~/storage/shared/zip_crack
termux-setup-storage   # один раз, разрешить доступ
```

Скопируйте папку, например:

```text
/sdcard/zip_crack
```

или

```text
/data/data/com.termux/files/home/zip_crack
```

**Важно:** сборку Go/Gradle **не** запускайте напрямую с `/sdcard` (FAT/FUSE, нет нормальных file locks).  
Скрипт `build-android.sh` копирует дерево в `/tmp` внутри Ubuntu – так и нужно.

---

## 2. Ubuntu в proot-distro

```bash
# Termux
proot-distro install ubuntu    # если ещё нет
proot-distro login ubuntu --user root
```

Дальше все команды – **внутри Ubuntu**, если не сказано иное.

### 2.1. Пакеты

```bash
apt update
apt install -y \
  openjdk-21-jdk-headless \
  wget curl unzip zip \
  ca-certificates \
  git \
  aapt \
  aapt2 \
  zipalign \
  apksigner \
  binutils \
  file
```

Проверка:

```bash
java -version    # 21.x, aarch64
which aapt2      # часто /usr/bin/aapt2
```

Если `aapt2` нет в PATH – поставьте пакет `aapt2` или укажите путь в `gradle.properties` (см. ниже).

### 2.2. Android SDK (минимальный набор)

Достаточно **cmdline-tools + platform-tools + platforms;android-34 + build-tools;34.0.0**.  
NDK **не нужен** (native 7zz убран, только Java/Kotlin).

```bash
export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
mkdir -p "$ANDROID_HOME/cmdline-tools"

cd /tmp
# Commandline tools (Google)
wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O cmdtools.zip
unzip -q cmdtools.zip -d "$ANDROID_HOME/cmdline-tools"
# Ожидаемая структура: cmdline-tools/latest/bin/sdkmanager
mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" 2>/dev/null || true
# если после unzip папка уже latest – ок

export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

yes | sdkmanager --licenses
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

Проверка:

```bash
ls "$ANDROID_HOME/platforms/android-34"
ls "$ANDROID_HOME/build-tools/34.0.0/aapt2"   # x86 в SDK – на ARM часто НЕ запускается
```

### 2.3. ARM aapt2 (критично на телефоне)

В SDK `aapt2` часто **linux-x86_64** и на ARM64 **не стартует**.  
На Pad/телефоне используйте **системный** aapt2 из apt:

```bash
which aapt2
aapt2 version || true
```

В проекте:

```bash
# zip_crack/android/gradle.properties
android.aapt2FromMavenOverride=/usr/bin/aapt2
```

Если aapt2 в другом месте – подставьте свой путь.

Также:

```bash
# android/local.properties  (создать заново)
sdk.dir=/root/android-sdk
# или: sdk.dir=/home/…/android-sdk  – абсолютный путь внутри Ubuntu
```

---

## 3. Подготовка исходников

```bash
# Ubuntu: исходники с shared storage
export SRC=/sdcard/zip_crack          # или ваш путь
# shared storage может сбрасывать +x:
chmod +x "$SRC/android/gradlew" "$SRC/scripts/"*.sh 2>/dev/null || true

# local.properties
cat > "$SRC/android/local.properties" <<EOF
sdk.dir=$ANDROID_HOME
EOF

# gradle.properties – aapt2 override (если ещё нет)
grep -q aapt2FromMavenOverride "$SRC/android/gradle.properties" 2>/dev/null || \
  echo "android.aapt2FromMavenOverride=$(which aapt2)" >> "$SRC/android/gradle.properties"
```

### Keystore

Если **перенесли** `android/zipcrack-release.keystore` – пароль по умолчанию в `app/build.gradle`:

- store/key password: `zipcrack`
- alias: `zipcrack`

Иначе создать:

```bash
keytool -genkeypair -v \
  -keystore "$SRC/android/zipcrack-release.keystore" \
  -alias zipcrack \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass zipcrack -keypass zipcrack \
  -dname "CN=ZipCrack, OU=Dev, O=Local, L=Local, ST=Local, C=RU"
```

---

## 4. Сборка APK

### Способ A (рекомендуется) – скрипт

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64
export ANDROID_HOME=$HOME/android-sdk   # как настроили
export ANDROID_SDK_ROOT=$ANDROID_HOME
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

cd "$SRC"
bash scripts/build-android.sh
```

Скрипт:

1. Копирует `android/` → `/tmp/zip_crack_android.XXXX`
2. `./gradlew assembleRelease`
3. Кладёт APK в `dist/PasswordCracker-<version>.apk`

### Способ B – вручную

```bash
WORKDIR=$(mktemp -d /tmp/zip_crack_android.XXXXXX)
cp -a "$SRC/android/." "$WORKDIR/"
cd "$WORKDIR"
chmod +x gradlew
bash ./gradlew assembleRelease --no-daemon

cp -f app/build/outputs/apk/release/app-release.apk \
  "$SRC/dist/PasswordCracker-manual.apk"
ls -lh "$SRC/dist/PasswordCracker-manual.apk"
```

Первая сборка качает Gradle + Maven-зависимости (нужен интернет, 5–20+ минут, сотни МБ).

---

## 5. Установка APK на телефон

Из Termux или файлового менеджера:

```bash
# Termux (если установлен termux-api / или просто откройте файл)
cp /sdcard/zip_crack/dist/PasswordCracker-*.apk /sdcard/Download/
```

На телефоне: открыть APK → установить (разрешить «неизвестные источники»).

Либо:

```bash
# если adb по USB/wireless из Ubuntu
adb install -r /sdcard/zip_crack/dist/PasswordCracker-1.5.apk
```

---

## 6. Типичные проблемы

| Симптом | Что делать |
|---------|------------|
| `RLock … function not implemented` | Сборка с `/sdcard` – только через копию в `/tmp` (скрипт) |
| `aapt2: cannot execute binary file` | `android.aapt2FromMavenOverride=/usr/bin/aapt2` |
| `sdk.dir` not found | `local.properties` → `sdk.dir=…` абсолютный путь в Ubuntu |
| `Unable to find Java` | `export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64` |
| Gradle OOM | в `gradle.properties`: `org.gradle.jvmargs=-Xmx1024m` (на слабом RAM) |
| Нет сети / SSL | время/дата телефона, `ca-certificates`, повтор |
| APK не обновляется поверх | другой keystore → удалить старое приложение |
| `7zzs` / SIGSYS | **не нужно**: в 1.3+ pure Java (POI/zip4j/compress) |

---

## 7. Минимальный чеклист на новом телефоне

1. [ ] Termux + `proot-distro ubuntu`
2. [ ] JDK 21, aapt2 (apt), Android SDK 34 + build-tools
3. [ ] Исходники в `/sdcard/zip_crack` (без `.gradle`/`build`)
4. [ ] `local.properties` + `aapt2FromMavenOverride`
5. [ ] Keystore на месте или сгенерирован
6. [ ] `bash scripts/build-android.sh`
7. [ ] APK из `dist/` установлен

---

## 8. Опционально: Go CLI на телефоне

```bash
apt install -y golang-go
# не с /sdcard:
cp -a /sdcard/zip_crack /tmp/zc && cd /tmp/zc
go test ./crack/ -count=1
go build -o zip_crack .
./zip_crack -digits -min 4 -max 4 /path/to.zip   # только ZipCrypto в Go CLI
```

Office/7z AES в Go CLI **не** портированы – только Android Kotlin + POI/zip4j/compress.

---

## 9. Тестовые пароли (samples)

| Файл | Пароль |
|------|--------|
| `sample_zipcrypto_4821.zip` | `4821` |
| `sample_zip_aes_4821.zip` | `4821` |
| `sample_7z_aes_4821.7z` | `4821` |
| `test.docx` | `5482` |

---

## 10. Оценка места

| Компонент | Порядок |
|-----------|---------|
| Исходники zip_crack | ~10–20 MB |
| Android SDK (min) | ~0.5–1.5 GB |
| Gradle+Maven cache | ~0.5–2 GB после первой сборки |
| JDK 21 | ~200–300 MB |
| Итого комфортно | **≥ 4–6 GB** свободно |

Сборку лучше вести во внутренней памяти Ubuntu (`/root`, `/tmp` на tmpfs/ext4), не на microSD FAT.
