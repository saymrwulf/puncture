#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$ROOT/EmergencyPuncture/EmergencyPuncture.xcodeproj"
SCHEME="EmergencyPuncture"
TEAM_ID="${TEAM_ID:-${1:-}}"

if [[ -z "${TEAM_ID}" ]]; then
  echo "Usage:"
  echo "  TEAM_ID=XXXXXXXXXX $0"
  echo "or"
  echo "  $0 XXXXXXXXXX"
  exit 1
fi

DIST_DIR="$ROOT/dist-signed"
ARCHIVE_PATH="$DIST_DIR/EmergencyPuncture-${TEAM_ID}.xcarchive"
EXPORT_DIR="$DIST_DIR/export-debugging"
EXPORT_OPTIONS="$DIST_DIR/exportOptions-debugging.plist"

mkdir -p "$DIST_DIR"

cat > "$EXPORT_OPTIONS" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key>
  <string>debugging</string>
  <key>signingStyle</key>
  <string>automatic</string>
  <key>teamID</key>
  <string>${TEAM_ID}</string>
  <key>stripSwiftSymbols</key>
  <true/>
  <key>compileBitcode</key>
  <false/>
</dict>
</plist>
PLIST

echo "==> Archiving with Team ID ${TEAM_ID}"
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Release \
  -destination "generic/platform=iOS" \
  -archivePath "$ARCHIVE_PATH" \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  CODE_SIGN_STYLE=Automatic \
  -allowProvisioningUpdates \
  clean archive

echo "==> Exporting IPA"
xcodebuild \
  -exportArchive \
  -archivePath "$ARCHIVE_PATH" \
  -exportPath "$EXPORT_DIR" \
  -exportOptionsPlist "$EXPORT_OPTIONS" \
  -allowProvisioningUpdates

IPA_PATH="$(ls -1 "$EXPORT_DIR"/*.ipa | head -n1 || true)"
if [[ -z "$IPA_PATH" ]]; then
  echo "No IPA was produced. Check Xcode export logs for signing/provisioning errors."
  exit 2
fi

echo "Done."
echo "Archive: $ARCHIVE_PATH"
echo "IPA: $IPA_PATH"
