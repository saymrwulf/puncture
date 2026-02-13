"""Secondary read-only live view app with password auth and kill-switch login."""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from flask import Flask, redirect, render_template_string, request, session, url_for


def _master_url() -> str:
    return os.getenv("PUNCTURE_MASTER_URL", "http://127.0.0.1:9122").rstrip("/")


def _master_token() -> str:
    return os.getenv("PUNCTURE_REMOTE_TOKEN", "").strip()


def _viewer_password() -> str:
    return os.getenv("PUNCTURE_SECONDARY_PASSWORD", "puncture-view")


def _build_request(path: str, *, method: str = "GET", payload: Optional[dict] = None) -> urllib.request.Request:
    url = _master_url() + path
    headers = {"Content-Type": "application/json"}
    token = _master_token()
    if token:
        headers["X-Puncture-Token"] = token

    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    return urllib.request.Request(url, method=method, data=data, headers=headers)


def _fetch_master_state() -> Dict[str, Any]:
    req = _build_request("/api/live/state")
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _remote_puncture_provider(provider_id: int) -> Dict[str, Any]:
    req = _build_request(
        "/api/remote/puncture-provider",
        method="POST",
        payload={"provider_id": provider_id},
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _parse_kill_switch(raw_password: str, base_password: str) -> Optional[int]:
    if raw_password == base_password:
        return None
    if not raw_password.startswith(base_password):
        return None

    suffix = raw_password[len(base_password) :]
    if not re.fullmatch(r"\d{1,3}", suffix or ""):
        return None

    provider_id = int(suffix)
    if not (0 <= provider_id <= 127):
        return None
    return provider_id


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("PUNCTURE_SECONDARY_SECRET", "puncture-secondary-secret")

    def _is_auth() -> bool:
        return bool(session.get("auth_ok"))

    def _set_notice(tone: str, message: str) -> None:
        session["notice"] = {"tone": tone, "message": message}

    def _pull_notice() -> Optional[Dict[str, Any]]:
        return session.pop("notice", None)

    @app.get("/login")
    def login_page() -> str:
        if _is_auth():
            return redirect(url_for("dashboard"))
        notice = _pull_notice()
        return render_template_string(LOGIN_HTML, notice=notice, master_url=_master_url())

    @app.post("/login")
    def login_submit() -> Any:
        entered = request.form.get("password", "")
        base = _viewer_password()

        if entered == base:
            session["auth_ok"] = True
            _set_notice("success", "Authenticated.")
            return redirect(url_for("dashboard"))

        kill_provider = _parse_kill_switch(entered, base)
        if kill_provider is not None:
            try:
                result = _remote_puncture_provider(kill_provider)
                if not result.get("ok"):
                    raise ValueError(result.get("error", "kill switch request failed"))
                session["auth_ok"] = True
                _set_notice(
                    "warn",
                    (
                        f"Kill switch activated for provider {kill_provider}. "
                        "All keys under this provider were punctured on master."
                    ),
                )
                return redirect(url_for("dashboard"))
            except Exception as exc:
                _set_notice("danger", f"Kill switch failed: {exc}")
                return redirect(url_for("login_page"))

        _set_notice("danger", "Authentication failed.")
        return redirect(url_for("login_page"))

    @app.post("/logout")
    def logout() -> Any:
        session.clear()
        _set_notice("info", "Logged out.")
        return redirect(url_for("login_page"))

    @app.get("/")
    def dashboard() -> str:
        if not _is_auth():
            return redirect(url_for("login_page"))

        notice = _pull_notice()
        try:
            live = _fetch_master_state()
            providers = live.get("providers", [])
            key_journal = live.get("key_journal", [])
            assets = live.get("assets", {})

            return render_template_string(
                DASHBOARD_HTML,
                notice=notice,
                fetch_error=None,
                generated_at=live.get("generated_at"),
                master_url=_master_url(),
                provider_count=len(providers),
                key_count=len(key_journal),
                mapping_count=int(assets.get("mapping_count", 0)),
                blocked_count=int(assets.get("blocked_count", 0)),
                providers=providers,
                key_journal=key_journal,
                asset_files=assets.get("asset_files", []),
                key_cards=assets.get("key_cards", []),
            )
        except Exception as exc:
            return render_template_string(
                DASHBOARD_HTML,
                notice=notice,
                fetch_error=str(exc),
                generated_at=None,
                master_url=_master_url(),
                provider_count=0,
                key_count=0,
                mapping_count=0,
                blocked_count=0,
                providers=[],
                key_journal=[],
                asset_files=[],
                key_cards=[],
            )

    @app.get("/api/state")
    def api_state() -> Dict[str, Any]:
        if not _is_auth():
            return {"ok": False, "error": "unauthenticated"}, 401
        live = _fetch_master_state()
        return {"ok": True, "live": live}

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run puncture secondary live-view app")
    parser.add_argument("--host", default=os.getenv("PUNCTURE_VIEW_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PUNCTURE_VIEW_PORT", "9222")))
    args = parser.parse_args()

    app = create_app()
    app.run(host=args.host, port=args.port, debug=False)


LOGIN_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Secondary Access</title>
  <style>
    :root {
      --bg: #f5f2e9;
      --card: #fffdf8;
      --ink: #172126;
      --muted: #5e6b70;
      --line: #d8d0bf;
      --teal: #0f766e;
      --danger: #8b1d1d;
      --warn: #9a3412;
      --radius: 14px;
      --sans: "Avenir Next", "Trebuchet MS", "Lucida Grande", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--ink);
      background:
        radial-gradient(860px 430px at -10% -10%, #d7ece8 0%, transparent 60%),
        radial-gradient(680px 350px at 105% 0%, #fae3cf 0%, transparent 55%),
        var(--bg);
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 14px;
    }
    .card {
      width: min(560px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 16px;
    }
    h1 { margin: 0 0 8px; }
    p { margin: 0 0 8px; }
    .muted { color: var(--muted); }
    label { display: block; margin: 9px 0 4px; font-weight: 700; }
    input {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px;
      font: inherit;
      color: var(--ink);
    }
    button {
      margin-top: 10px;
      width: 100%;
      border: 0;
      border-radius: 10px;
      padding: 10px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      color: #fff;
      background: var(--teal);
    }
    .notice {
      border-radius: 10px;
      border: 1px solid var(--line);
      padding: 9px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .notice.success { background: #dcf4ef; color: #0c4f49; border-color: #b7e5dc; }
    .notice.warn { background: #ffeede; color: #6f2d13; border-color: #f0d2bb; }
    .notice.danger { background: #ffe7e7; color: #7f1717; border-color: #efc3c3; }
    .notice.info { background: #edf4ff; color: #23466b; border-color: #cad9ee; }
  </style>
</head>
<body>
  <main class="card">
    <h1>Secondary Live Viewer Login</h1>
    <p class="muted">Master source: {{ master_url }}</p>
    <p class="muted">Kill switch format: `password` + `provider_id` (for example `secret42`).</p>

    {% if notice %}
      <div class="notice {{ notice.tone }}">{{ notice.message }}</div>
    {% endif %}

    <form method="post" action="{{ url_for('login_submit') }}">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required autofocus />
      <button type="submit">Enter</button>
    </form>
  </main>
</body>
</html>
"""


DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Secondary Live Viewer</title>
  <style>
    :root {
      --bg: #f5f2e9;
      --card: #fffdf8;
      --ink: #172126;
      --muted: #5e6b70;
      --line: #d8d0bf;
      --teal: #0f766e;
      --danger: #8b1d1d;
      --warn: #9a3412;
      --radius: 14px;
      --sans: "Avenir Next", "Trebuchet MS", "Lucida Grande", sans-serif;
      --mono: Menlo, Consolas, Monaco, "Liberation Mono", monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--ink);
      background:
        radial-gradient(860px 430px at -10% -10%, #d7ece8 0%, transparent 60%),
        radial-gradient(680px 350px at 105% 0%, #fae3cf 0%, transparent 55%),
        var(--bg);
    }
    .wrap { max-width: 1200px; margin: 0 auto; padding: 14px 14px 30px; }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 14px;
      margin-bottom: 12px;
    }
    h1 { margin: 4px 0 8px; font-size: clamp(1.5rem, 4vw, 2.1rem); }
    h2 { margin: 0 0 8px; font-size: 1.1rem; }
    p { margin: 0 0 8px; }
    .muted { color: var(--muted); }
    .mono { font-family: var(--mono); font-size: 0.82rem; word-break: break-all; }

    .button-row { display: flex; gap: 8px; flex-wrap: wrap; }
    button {
      border: 0;
      border-radius: 10px;
      padding: 9px 12px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    .btn { background: var(--teal); color: #fff; }
    .btn-ghost { background: #fff; color: var(--ink); border: 1px solid var(--line); }

    .stats { display: grid; gap: 8px; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 8px; }
    .stat { border: 1px solid var(--line); border-radius: 10px; padding: 8px; background: #fff; }
    .stat .label { color: var(--muted); font-size: 0.78rem; }
    .stat .value { font-size: 1.2rem; font-weight: 700; }

    .grid { display: grid; gap: 10px; grid-template-columns: 1fr 1fr; }

    .notice {
      border-radius: 10px;
      border: 1px solid var(--line);
      padding: 9px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .notice.success { background: #dcf4ef; color: #0c4f49; border-color: #b7e5dc; }
    .notice.warn { background: #ffeede; color: #6f2d13; border-color: #f0d2bb; }
    .notice.danger { background: #ffe7e7; color: #7f1717; border-color: #efc3c3; }
    .notice.info { background: #edf4ff; color: #23466b; border-color: #cad9ee; }

    .provider, .row {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 8px;
      margin-top: 8px;
      background: #fff;
    }

    .blocked { background: #ffe7e7; border-color: #edc1c1; color: #7b1c1c; }
    .glow { box-shadow: 0 0 0 2px rgba(30, 154, 132, 0.2), 0 0 18px rgba(30, 154, 132, 0.3); }

    @media (max-width: 940px) {
      .stats { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="card">
      <div class="button-row">
        <form method="post" action="{{ url_for('logout') }}"><button class="btn-ghost" type="submit">Logout</button></form>
        <button class="btn" type="button" onclick="window.location.reload()">Refresh Now</button>
      </div>
      <h1>Secondary Live Viewer</h1>
      <p class="muted">Realtime mirror from {{ master_url }} | last fetch: {{ generated_at or 'failed' }}</p>
      {% if notice %}
        <div class="notice {{ notice.tone }}">{{ notice.message }}</div>
      {% endif %}
      {% if fetch_error %}
        <div class="notice danger">Master fetch failed: {{ fetch_error }}</div>
      {% endif %}
      <div class="stats">
        <div class="stat"><div class="label">Providers</div><div class="value">{{ provider_count }}</div></div>
        <div class="stat"><div class="label">Key IDs tracked</div><div class="value">{{ key_count }}</div></div>
        <div class="stat"><div class="label">Ciphertext mappings</div><div class="value">{{ mapping_count }}</div></div>
        <div class="stat"><div class="label">Blocked mappings</div><div class="value">{{ blocked_count }}</div></div>
      </div>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Providers</h2>
        {% if providers %}
          {% for provider in providers %}
            <div class="provider">
              <strong>ID {{ provider.provider_id }} - {{ provider.name }}</strong>
              {% if provider.description %}<div class="muted">{{ provider.description }}</div>{% endif %}
              <div class="mono">Prefix {{ provider.prefix }}</div>
              <div class="muted">Derived IDs: {{ provider.derived_count }} | Punctured IDs: {{ provider.punctured_count }} | Key rows: {{ provider.key_count }}</div>
            </div>
          {% endfor %}
        {% else %}
          <p class="muted">No provider data.</p>
        {% endif %}
      </article>

      <article class="card">
        <h2>Key Journal</h2>
        {% if key_journal %}
          {% for key in key_journal %}
            <div class="row{% if key.ever_punctured %} blocked{% endif %}">
              <strong>Provider {{ key.provider_id }} | Key ID {{ key.file_time_id }}</strong>
              <div class="mono">{{ key.path_provider }} | {{ key.path_resource }}</div>
              <div class="muted">Derived {{ key.derive_count }}x | Punctured {{ key.puncture_count }}x</div>
              {% if key.description %}<div class="muted">Purpose: {{ key.description }}</div>{% endif %}
            </div>
          {% endfor %}
        {% else %}
          <p class="muted">No keys tracked.</p>
        {% endif %}
      </article>
    </section>

    <section class="card">
      <h2>Assets and Ciphertexts</h2>
      {% if asset_files %}
        {% for file in asset_files %}
          <div class="provider">
            <strong>{{ file.plaintext_relpath }}</strong>
            <div class="muted">Mappings: {{ file.mapping_count }} | Blocked: {{ file.blocked_count }}</div>
            {% for row in file.mappings %}
              <div class="row{% if row.show_red %} blocked{% endif %}{% if row.show_glow %} glow{% endif %}">
                <div><strong>Provider {{ row.provider_id }} | Key ID {{ row.file_time_id }}</strong></div>
                <div class="mono">cipher: {{ row.ciphertext_relpath }}</div>
                <div class="mono">tag: {{ row.path_provider }} | {{ row.path_resource }}</div>
                <div class="muted">Status: {{ 'decryptable' if row.is_accessible else 'blocked by puncture' }}</div>
              </div>
            {% endfor %}
          </div>
        {% endfor %}
      {% else %}
        <p class="muted">No asset mappings found.</p>
      {% endif %}
    </section>
  </main>

  <script>
    setTimeout(() => window.location.reload(), 8000);
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
