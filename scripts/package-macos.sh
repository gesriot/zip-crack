#!/usr/bin/env bash
# Build pure-Go Password Cracker GUI → .app + .dmg + .app.zip
set -euo pipefail

APP_NAME="${APP_NAME:-Password Cracker}"
BUNDLE_ID="${BUNDLE_ID:-com.passwordcracker.app}"
VERSION="${VERSION:-1.5.0}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKIP_BUILD="${SKIP_BUILD:-0}"
MACOS_DIR="$ROOT_DIR/macos"
ICON_PNG="${ICON_PNG:-$MACOS_DIR/icon.png}"
ICON_ROUNDED_PNG="${ICON_ROUNDED_PNG:-$MACOS_DIR/icon-rounded.png}"
ICON_RUNTIME_PNG="${ICON_RUNTIME_PNG:-$MACOS_DIR/icon-runtime.png}"
ICON_ICNS="${ICON_ICNS:-$MACOS_DIR/icon.icns}"
ICON_CORNER_RADIUS_RATIO="${ICON_CORNER_RADIUS_RATIO:-0.223}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
BUILD_DIR="$ROOT_DIR/build/macos"
BINARY_PATH="$BUILD_DIR/PasswordCracker"
APP_DIR="$DIST_DIR/$APP_NAME.app"
ZIP_PATH="$DIST_DIR/$APP_NAME.app.zip"
DMG_PATH="$DIST_DIR/$APP_NAME.dmg"

if [[ ! -f "$ICON_PNG" && ! -f "$ICON_ICNS" ]]; then
  echo "error: icon not found: $ICON_PNG or $ICON_ICNS" >&2
  exit 1
fi

mkdir -p "$DIST_DIR" "$BUILD_DIR"
rm -rf "$APP_DIR" "$ZIP_PATH" "$DMG_PATH"

if [[ -f "$ICON_PNG" ]]; then
  python3 - "$ICON_PNG" "$ICON_ROUNDED_PNG" "$ICON_RUNTIME_PNG" "$ICON_ICNS" "$ICON_CORNER_RADIUS_RATIO" <<'PY'
import sys
from pathlib import Path

try:
    from PIL import Image, ImageChops, ImageDraw
except ModuleNotFoundError:
    print("error: python3 Pillow package is required to convert icon.png to icon.icns", file=sys.stderr)
    sys.exit(1)

src = Path(sys.argv[1])
rounded_dst = Path(sys.argv[2])
runtime_dst = Path(sys.argv[3])
icns_dst = Path(sys.argv[4])
corner_radius_ratio = float(sys.argv[5])
if not 0 < corner_radius_ratio < 0.5:
    print("error: ICON_CORNER_RADIUS_RATIO must be between 0 and 0.5", file=sys.stderr)
    sys.exit(1)

image = Image.open(src).convert("RGBA")
side = max(image.size)
canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
canvas.alpha_composite(image, ((side - image.width) // 2, (side - image.height) // 2))

scale = 4
mask_size = side * scale
mask = Image.new("L", (mask_size, mask_size), 0)
draw = ImageDraw.Draw(mask)
radius = int(round(side * corner_radius_ratio * scale))
draw.rounded_rectangle((0, 0, mask_size - 1, mask_size - 1), radius=radius, fill=255)
mask = mask.resize((side, side), Image.Resampling.LANCZOS)
canvas.putalpha(ImageChops.multiply(canvas.getchannel("A"), mask))

canvas.save(rounded_dst)
runtime_icon = canvas.resize((1024, 1024), Image.Resampling.LANCZOS)
runtime_icon.save(runtime_dst)
runtime_icon.save(
    icns_dst,
    format="ICNS",
    sizes=[(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512), (1024, 1024)],
)
PY
fi

if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "Building Go GUI (darwin/$(go env GOARCH))…"
  (
    cd "$ROOT_DIR"
    CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
      -o "$BINARY_PATH" ./cmd/gui
  )
fi

if [[ ! -x "$BINARY_PATH" ]]; then
  echo "error: built binary not found: $BINARY_PATH" >&2
  exit 1
fi

mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$BINARY_PATH" "$APP_DIR/Contents/MacOS/$APP_NAME"
chmod 755 "$APP_DIR/Contents/MacOS/$APP_NAME"
cp "$ICON_ICNS" "$APP_DIR/Contents/Resources/icon.icns"

cat > "$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDisplayName</key>
	<string>$APP_NAME</string>
	<key>CFBundleExecutable</key>
	<string>$APP_NAME</string>
	<key>CFBundleIconFile</key>
	<string>icon.icns</string>
	<key>CFBundleIdentifier</key>
	<string>$BUNDLE_ID</string>
	<key>CFBundleName</key>
	<string>$APP_NAME</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundleVersion</key>
	<string>$VERSION</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSSupportsAutomaticGraphicsSwitching</key>
	<true/>
	<!-- Force light Aqua (title bar / controls) even if system is in dark mode -->
	<key>NSRequiresAquaSystemAppearance</key>
	<true/>
</dict>
</plist>
PLIST

plutil -lint "$APP_DIR/Contents/Info.plist" >/dev/null
xattr -cr "$APP_DIR" 2>/dev/null || true
# ad-hoc sign so Gatekeeper is slightly less noisy on same machine
codesign --force --deep --sign - "$APP_DIR" 2>/dev/null || true

(
  cd "$DIST_DIR"
  COPYFILE_DISABLE=1 zip -qry -X "$APP_NAME.app.zip" "$APP_NAME.app"
)

DMG_STAGE="$(mktemp -d /tmp/password-cracker-dmg.XXXXXX)"
cleanup() {
  rm -rf "$DMG_STAGE"
}
trap cleanup EXIT

cp -R "$APP_DIR" "$DMG_STAGE/"
ln -s /Applications "$DMG_STAGE/Applications"
COPYFILE_DISABLE=1 hdiutil create -volname "$APP_NAME" -srcfolder "$DMG_STAGE" -fs HFS+ -format UDZO -ov "$DMG_PATH" >/dev/null
hdiutil verify "$DMG_PATH" >/dev/null

# also ship CLI next to dmg for power users
echo "Building CLI…"
(
  cd "$ROOT_DIR"
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$DIST_DIR/zip_crack" .
)

echo "App: $APP_DIR"
echo "Zip: $ZIP_PATH"
echo "DMG: $DMG_PATH"
echo "CLI: $DIST_DIR/zip_crack"
