# Puncture (Go)

Go implementation of a puncturable-key system (GGM tree) with:

- primary macOS app/server for key derivation, puncturing, providers, and asset encryption/decryption
- iOS emergency companion app for remote provider-level puncture

## Current architecture

- `goapp/cmd/server`: headless web server (`:9122`)
- `goapp/cmd/desktop`: macOS desktop app (embedded webview + local server)
- `goapp/internal/crypto`: GGM puncturable key manager
- `goapp/internal/app`: provider/key/asset state machine
- `goapp/internal/server`: HTTP API + web UI
- `goapp/ios/EmergencyPuncture`: native iOS app

## Run primary server

```bash
cd goapp
go run ./cmd/server --host 0.0.0.0 --port 9122
```

Open `http://127.0.0.1:9122`.

## Build macOS app + installer

```bash
cd goapp
./packaging/macos/build_dmg.sh
```

Artifacts:

- `goapp/dist/Puncture.app`
- `goapp/dist/Puncture.dmg`

## Persistence

Frontier/puncture/providers/assets are persisted locally and survive restarts.
Default desktop paths:

- assets: `~/Library/Application Support/PunctureGo/assets`
- state: `~/Library/Application Support/PunctureGo/state.json`

## iOS companion

- Xcode project: `goapp/ios/EmergencyPuncture/EmergencyPuncture.xcodeproj`
- iPhone install guide: `goapp/ios/INSTALL_IPHONE.md`

## Legacy Python line

The previous Python implementation is preserved in branch `python-legacy`.
