#!/usr/bin/env bash
# Build a signed release APK on this device (Ubuntu proot / Termux host).
# Always copies the tree to /tmp first — shared storage lacks reliable file locks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_DIR="$ROOT/android"
OUT_DIR="$ROOT/dist"
APP_NAME="${APP_NAME:-PasswordCracker}"
VERSION_NAME="$(grep -E 'versionName' "$ANDROID_DIR/app/build.gradle" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-arm64}"
export ANDROID_HOME="${ANDROID_HOME:-/root/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"

if [[ ! -x "$JAVA_HOME/bin/java" ]]; then
  echo "error: JAVA_HOME not usable: $JAVA_HOME" >&2
  exit 1
fi
if [[ ! -d "$ANDROID_HOME" ]]; then
  echo "error: ANDROID_HOME missing: $ANDROID_HOME" >&2
  exit 1
fi
if [[ ! -f "$ANDROID_DIR/zipcrack-release.keystore" ]]; then
  echo "error: keystore missing: $ANDROID_DIR/zipcrack-release.keystore" >&2
  echo "Generate with keytool (see README)." >&2
  exit 1
fi

WORKDIR="$(mktemp -d /tmp/zip_crack_android.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "Copying sources → $WORKDIR"
cp -a "$ANDROID_DIR/." "$WORKDIR/"
chmod +x "$WORKDIR/gradlew" 2>/dev/null || true

cd "$WORKDIR"
echo "Building assembleRelease…"
bash ./gradlew assembleRelease --no-daemon

APK="$WORKDIR/app/build/outputs/apk/release/app-release.apk"
if [[ ! -f "$APK" ]]; then
  echo "error: APK not produced" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
DEST="$OUT_DIR/${APP_NAME}-${VERSION_NAME}.apk"
cp -f "$APK" "$DEST"
echo "OK: $DEST"
ls -la "$DEST"
