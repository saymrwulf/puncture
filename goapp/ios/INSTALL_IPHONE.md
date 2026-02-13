# EmergencyPuncture iPhone Install Guide

This project already builds successfully for iOS.  
Current local artifacts:

- Unsigned archive: `goapp/ios/dist/EmergencyPuncture.xcarchive`
- Unsigned IPA (not installable as-is): `goapp/ios/dist/EmergencyPuncture-unsigned-proper.ipa`

To install on a real iPhone, you must sign with an Apple Team.

## Option 1: Install directly from Xcode (recommended)

1. Connect your iPhone to the Mac with USB.
2. On iPhone, tap `Trust This Computer` if prompted.
3. Open project:
   - `goapp/ios/EmergencyPuncture/EmergencyPuncture.xcodeproj`
4. In Xcode:
   - Select target `EmergencyPuncture`
   - Open `Signing & Capabilities`
   - Enable `Automatically manage signing`
   - Select your Team (Apple ID Personal Team or paid Developer Team)
5. In the Xcode device selector, choose your connected iPhone.
6. Press `Run` (Cmd+R).
7. If iOS blocks launch the first time:
   - iPhone `Settings > General > VPN & Device Management`
   - Trust your developer certificate
   - Re-run from Xcode.

## Option 2: Build signed IPA from terminal

1. Ensure step 4 above is complete at least once in Xcode (Team selected).
2. Get your Team ID (10 chars) from:
   - Apple Developer account
   - or Xcode `Signing & Capabilities` details.
3. Run:

```bash
cd /Users/oho/GitClone/CodexProjects/puncture/goapp/ios
TEAM_ID=YOURTEAMID ./build_signed_ipa.sh
```

4. Output:
   - Archive: `goapp/ios/dist-signed/EmergencyPuncture-YOURTEAMID.xcarchive`
   - IPA: `goapp/ios/dist-signed/export-debugging/EmergencyPuncture.ipa`

## Install signed IPA to iPhone

Use one of these:

1. Apple Configurator 2 (Mac App Store):
   - Connect iPhone
   - Drag the signed `.ipa` onto the device
2. Xcode Organizer:
   - `Window > Organizer`
   - Select archive
   - `Distribute App` for development/internal flow

## Known failure and meaning

- `No Team Found in Archive`:
  The app was archived without a Team (`DEVELOPMENT_TEAM` empty), so export cannot sign.  
  Fix by selecting Team in Xcode, then rebuild/export.
- `Signing for "EmergencyPuncture" requires a development team`:
  No Team is configured yet for this target.  
  Fix in Xcode `Signing & Capabilities` by selecting your Team.
