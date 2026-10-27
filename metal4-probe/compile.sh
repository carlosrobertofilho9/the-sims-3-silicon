#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SDK_PATH=$(xcrun --sdk macosx --show-sdk-path)
BUILD_DIR="$SCRIPT_DIR/build"
APP_CONTENTS="$BUILD_DIR/Metal4Probe.app/Contents"

mkdir -p "$BUILD_DIR/ModuleCache" "$APP_CONTENTS/MacOS" "$APP_CONTENTS/Resources"
xcrun --sdk macosx swiftc \
  -parse-as-library \
  -target arm64-apple-macosx26.0 \
  -sdk "$SDK_PATH" \
  -swift-version 5 \
  -O \
  -module-cache-path "$BUILD_DIR/ModuleCache" \
  "$SCRIPT_DIR/main.swift" \
  -o "$APP_CONTENTS/MacOS/metal4-probe" \
  -framework AppKit \
  -framework CoreGraphics \
  -framework ImageIO \
  -framework Metal \
  -framework MetalKit \
  -framework UniformTypeIdentifiers

cat > "$APP_CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>metal4-probe</string>
  <key>CFBundleIdentifier</key>
  <string>community.sims3.metal4probe</string>
  <key>CFBundleName</key>
  <string>Metal 4 Texture Probe</string>
  <key>CFBundleDisplayName</key>
  <string>Metal 4 Texture Probe</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>26.0</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

printf 'Built ARM64 app bundle: %s\n' "$BUILD_DIR/Metal4Probe.app"
