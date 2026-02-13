# Puncture Go

Go implementation of the primary puncturable-key system, plus:

- a desktop macOS app build target
- a DMG installer pipeline
- a native iOS emergency puncture companion app

## Layout

- `cmd/server`: headless primary app server (web UI + APIs)
- `cmd/desktop`: macOS desktop target (embedded webview + local server)
- `internal/crypto`: GGM puncturable key manager in Go
- `internal/app`: providers, key journal, assets, encryption/decryption, tree-viz state
- `internal/server`: HTTP routes + embedded web UI
- `packaging/macos`: `.app` and `.dmg` build scripts
- `ios/EmergencyPuncture`: SwiftUI iOS app (generated with xcodegen)

## Run Primary (Go Server)

```bash
cd goapp
go run ./cmd/server --host 0.0.0.0 --port 9122
```

Open: `http://127.0.0.1:9122`

## Local Persistence

State now persists automatically across restarts (frontier, punctures, providers, key journal, asset mappings, history).

- Default state file:
  - if asset root ends with `assets`: sibling `state.json`
  - otherwise: `<asset-root>/.puncture-state.json`
- Override path with `PUNCTURE_STATE_FILE=/absolute/path/state.json`

## Build macOS Desktop App + DMG

```bash
cd goapp
./packaging/macos/build_dmg.sh
```

Output:

- `goapp/dist/Puncture.app`
- `goapp/dist/Puncture.dmg`

Desktop app behavior:

- On launch, `Puncture.app` now auto-starts iOS Simulator.
- It auto-installs/launches the bundled `EmergencyPuncture` iOS app in Simulator.
- It attempts to place macOS + Simulator windows side-by-side.
- For auto window positioning, macOS may ask Accessibility permission for the app.

Runtime toggles (optional):

- `PUNCTURE_WITH_SIMULATOR=0` disables auto-launch.
- `PUNCTURE_SIM_DEVICE="iPhone 17 Pro"` chooses preferred simulator device.
- `PUNCTURE_IOS_SIM_APP=/path/to/EmergencyPuncture.app` overrides bundled app path.

## Build macOS Desktop Binary (without DMG)

```bash
cd goapp
CGO_ENABLED=1 go build -tags desktop -o dist/PunctureDesktop ./cmd/desktop
```

## iOS Emergency Puncture App

Project location:

- `goapp/ios/EmergencyPuncture/EmergencyPuncture.xcodeproj`

Open in Xcode and run on device/simulator.

What it does:

- Connects to master `http://<master-ip>:9122`
- Loads providers from `/api/live/state`
- Sends emergency puncture to `/api/remote/puncture-provider`
- Optional `X-Puncture-Token` header support

iPhone install + signing manual:

- `goapp/ios/INSTALL_IPHONE.md`

Signed IPA build helper:

```bash
cd goapp/ios
TEAM_ID=YOURTEAMID ./build_signed_ipa.sh
```

## API Highlights

- `GET /api/state`
- `POST /api/derive`
- `POST /api/puncture`
- `POST /api/providers/add`
- `POST /api/providers/delete`
- `POST /api/assets/upload`
- `POST /api/assets/encrypt`
- `POST /api/assets/decrypt`
- `POST /api/remote/puncture-provider`

## Tests

```bash
cd goapp
go test ./...
```
