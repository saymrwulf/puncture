# Puncture: Zero-Trust Cloud-Wide Forward Secrecy

Python implementation of puncturable encryption (PE) over a GGM tree, with:

- a **master app** (key management + provider management + asset encryption mapping)
- a **secondary app** (read-only live mirror with password auth and kill-switch login)

## Core cryptographic model

- 256-bit master seed root.
- HMAC-SHA256 left/right derivation for GGM child nodes.
- Non-sequential puncture with minimal co-path replacement.
- Tag schema: `[7 bits provider_id] | [25 bits file_time_id]`.
- Active-state model stores only active prefix nodes (not per-file keys).
- Immediate zeroization of replaced node material on puncture.
- Puncture log export/import (`list[str]` of bit strings).

## Setup (venv)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Master app on `9122`:

```bash
python -m puncture.web_app --host 0.0.0.0 --port 9122
```

Secondary app on `9222`:

```bash
python -m puncture.view_app --host 0.0.0.0 --port 9222
```

## Master app (`:9122`) workflow

- `/`: main puncture lab (derive/puncture, history, active frontier roots view).
- `/providers`: add/edit/delete providers.
- `/assets`: pick a cleartext file from asset root, select provider/key, encrypt, and register mapping.

### Asset behavior

- Ciphertext is written in the **same folder** as the cleartext file.
- Decryption writes recovered cleartext back into the same folder tree (versioned filenames).
- One cleartext file can have multiple provider-key mappings.
- One provider-key can encrypt multiple files.
- After key puncture:
  - affected mappings are shown in **red** (`blocked by puncture`)
  - if the same cleartext file still has another accessible mapping, that mapping **glows**

## Secondary app (`:9222`) behavior

- Password-gated access.
- Live read-only mirror from master (`GET /api/live/state`).
- No share setup and no independent derivation state.
- Kill-switch login format:
  - normal login: `<password>`
  - kill-switch login: `<password><provider_id>`
  - example: `puncture-view42` punctures provider `42` immediately on master.

## Environment variables

Master app:

- `PUNCTURE_PORT` (default `9122`)
- `PUNCTURE_ASSET_ROOT` (default `<cwd>/assets`)
- `PUNCTURE_REMOTE_TOKEN` (optional; required for remote puncture endpoint)
- `PUNCTURE_VIEW_SYNC_KEY` (optional signing key for `/api/view-bundle`)

Secondary app:

- `PUNCTURE_VIEW_PORT` (default `9222`)
- `PUNCTURE_MASTER_URL` (default `http://127.0.0.1:9122`)
- `PUNCTURE_SECONDARY_PASSWORD` (default `puncture-view`)
- `PUNCTURE_SECONDARY_SECRET` (Flask session secret)
- `PUNCTURE_REMOTE_TOKEN` (optional; sent as `X-Puncture-Token`)

## API quick reference

- `GET /api/state` (master full state)
- `GET /api/live/state` (master live data for secondary app)
- `POST /api/remote/puncture-provider` (master remote provider kill endpoint)
- `GET /api/export` / `POST /api/import`
- `POST /api/puncture-log`
- `GET /api/view-bundle` (legacy signed/unsigned viewer bundle export)

## Tests

```bash
pytest -q
```
