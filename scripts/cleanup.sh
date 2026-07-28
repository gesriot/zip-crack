#!/usr/bin/env bash
# Safe cleanup of build artifacts (project + common /tmp leftovers).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Cleaning project caches under $ROOT"
rm -rf \
  "$ROOT/android/.gradle" \
  "$ROOT/android/build" \
  "$ROOT/android/app/build" \
  "$ROOT/build"

echo "Cleaning /tmp zip_crack workdirs (if any)"
rm -rf /tmp/zip_crack_android.* /tmp/zip_crack_go.* /tmp/zip_crack_bench /tmp/zip_crack_build 2>/dev/null || true

if [[ "${1:-}" == "--apks" ]]; then
  echo "Removing dist APKs"
  rm -f "$ROOT"/dist/PasswordCracker-*.apk "$ROOT"/dist/*.apk.idsig
fi

echo "Done. Project size:"
du -sh "$ROOT" "$ROOT"/* 2>/dev/null | sort -hr | head -15
