#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="$ROOT/dist"
APP_NAME="Puncture"
APP_DIR="$DIST_DIR/${APP_NAME}.app"
DMG_PATH="$DIST_DIR/${APP_NAME}.dmg"
IOS_PROJECT="$ROOT/ios/EmergencyPuncture/EmergencyPuncture.xcodeproj"
IOS_DERIVED="$ROOT/ios/build-ios"
IOS_SIM_APP="$IOS_DERIVED/Build/Products/Debug-iphonesimulator/EmergencyPuncture.app"

mkdir -p "$DIST_DIR"
rm -rf "$APP_DIR" "$DMG_PATH"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "$ROOT/packaging/macos/Info.plist" "$APP_DIR/Contents/Info.plist"
if [[ -f "$ROOT/packaging/macos/AppIcon.icns" ]]; then
  cp "$ROOT/packaging/macos/AppIcon.icns" "$APP_DIR/Contents/Resources/AppIcon.icns"
fi

pushd "$ROOT" >/dev/null
CGO_ENABLED=1 go build -tags desktop -o "$APP_DIR/Contents/MacOS/$APP_NAME" ./cmd/desktop
popd >/dev/null

# Bundle iOS companion app for automatic Simulator launch from the desktop app.
if command -v xcodebuild >/dev/null 2>&1 && [[ -d "$IOS_PROJECT" ]]; then
  echo "Building iOS simulator companion app..."
  if xcodebuild \
      -project "$IOS_PROJECT" \
      -scheme EmergencyPuncture \
      -configuration Debug \
      -destination "generic/platform=iOS Simulator" \
      -derivedDataPath "$IOS_DERIVED" \
      CODE_SIGNING_ALLOWED=NO \
      build >/dev/null 2>&1; then
    if [[ -d "$IOS_SIM_APP" ]]; then
      rm -rf "$APP_DIR/Contents/Resources/EmergencyPuncture.app"
      cp -R "$IOS_SIM_APP" "$APP_DIR/Contents/Resources/EmergencyPuncture.app"
      echo "Bundled companion app: $IOS_SIM_APP"
    fi
  else
    echo "Warning: could not build iOS simulator companion app; continuing without bundling."
  fi
else
  echo "Warning: xcodebuild or iOS project missing; companion app was not bundled."
fi

chmod +x "$APP_DIR/Contents/MacOS/$APP_NAME"

# Local ad-hoc signing for smoother first launch on macOS.
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APP_DIR" || true
fi

hdiutil create -volname "${APP_NAME}" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG_PATH"

echo "Created app bundle: $APP_DIR"
echo "Created installer DMG: $DMG_PATH"
