# Changelog

All notable changes to SprayMaster are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — hosted demo deployment

- **SAFE_DEMO mode** — set `SPRAYMASTER_SAFE_DEMO=1` to disable outbound
  credential attempts while keeping the full UI, history, JSON API, `/metrics`,
  and `/healthz` live. `POST /attacks` returns `403` with a friendly explainer;
  the index page shows a "Demo mode" banner. New `safe_demo` kwarg on
  `create_app()` allows programmatic override (used by tests).
- **`render.yaml` Blueprint** — one-click deploy of the FastAPI web UI to
  Render with persistent SQLite disk and an auto-generated `SPRAYMASTER_AUTH_TOKEN`.
  Configured in demo mode by default; flip the env flag to enable real attacks
  (AUP risk — see `deploy/README.md`).
- **Vercel landing page** (`deploy/vercel/`) — static HTML/CSS pitch page that
  links to the Render demo and the GitHub repo. Ships with a `vercel.json`
  setting security headers (CSP, X-Frame-Options, Referrer-Policy).
- **PaaS-friendly CLI** — `spraymaster-web` now honours `$PORT` and
  auto-binds `0.0.0.0` when running under a managed platform. Public bind is
  also allowed when `SPRAYMASTER_SAFE_DEMO=1` (attacks are gated, so exposure
  is safe).
- **Proxy-aware uvicorn** — `proxy_headers=True` and `forwarded_allow_ips="*"`
  so the app sees the real client IP behind Render's edge.

### Documentation

- New `deploy/README.md` — end-to-end walkthrough for Render + Vercel, local
  verification recipes, and notes on Fly.io / Railway / Koyeb.

## [2.3.0] — 2026-05-17

### Added — Phase 3: enterprise hardening

- **Streaming task submission** — the executor no longer pre-queues the entire
  task list (was O(N) memory on huge wordlists). Bounded in-flight futures
  keep the pool saturated and let cancellation interrupt mid-flight cleanly.
- **Global rate limit** (`--max-rate RPS`) — token-bucket pacer that smooths
  attempts across all threads.
- **Per-host concurrency cap** (`--per-host-rate N`) — a slow target no longer
  monopolises every worker thread while other queued hosts starve.
- **Interruptible retry backoff** — Ctrl+C no longer has to wait through the
  exponential-backoff sleep between retries.
- **Graceful SIGINT** — first ^C requests engine stop; a second ^C force-exits.
- **Argument validation** — `--threads`, `--retries`, `--timeout`, `--port`,
  `--per-host-rate` now reject zero/negative values with a clean error.
- **Structured JSON logs** (`--log-json FILE` or `-`) — JSONL records suitable
  for SIEM / log shippers, with Rich tags stripped.
- **HTTP improvements**
  - Per-thread `requests.Session` pool (HTTP keep-alive — huge win on HTTPS).
  - `--user-agent UA` override, `--http-cookies` for authenticated-session
    spraying, `--http-headers` carried through verbatim.
  - Basic-auth success now treats 401/403 as fail and any other 2xx/3xx as
    success (was strict `== 200`, missed 302 redirect-on-login).
- **LDAP** — removed the double-bind that `auto_bind` + manual `conn.bind()`
  was producing.
- **SNMP** — tries v2c first and falls back to v1 on transient/no-reply errors.
- **Web UI**
  - `GET /metrics` — Prometheus-format gauges/counters (runs, attempts,
    findings, errors, active sessions).
  - `GET /healthz` — unauthenticated liveness probe.
  - Security headers middleware: CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy.
  - Live ETA + rate display on the attack page.
  - Port / `max_rate` / `per_host_rate` form fields are validated server-side
    (was an `int()` crash on garbage).
  - Stop-attack correctly marks the run `cancelled` in history.
- **TUI** — Back from a completed run no longer rewrites the status from
  `done` to `cancelled`.

### Fixed

- `_attempt_with_retries` now respects the stop event during backoff.
- `RunRegistry.stop()` is null-safe if the runner failed to start.
- `attack_done` event now carries `cancelled: bool` for downstream UIs.

## [2.2.0] — 2026-05-17

### Added — Phase 2: UI surfaces

- **Web UI** (`spraymaster-web`) — FastAPI + HTMX + Jinja, WebSocket-driven live progress
  - Single-token auth via `SPRAYMASTER_AUTH_TOKEN` (generated and printed on first boot if unset)
  - Pages: login, new attack, live run view, history
  - JSON API: `GET /api/runs`, `GET /api/runs/{id}/findings`
  - WebSocket: `GET /ws/attacks/{id}` — replays buffered events for late-connecting clients
  - Loopback-only by default; refuses `--host 0.0.0.0` without `--allow-public`
  - Install with `pip install 'spraymaster[web]'`
- **Terminal UI** (`spraymaster-tui`) — Textual-based interactive front-end
  - Screens: Config (form), Run (live progress + event feed), History
  - Subscribes to the engine via the new event hook
  - Install with `pip install 'spraymaster[tui]'`
- **Engine event hook** — `AttackEngine(..., on_event=...)` emits `attack_start`,
  `attempt`, `success`, `error`, `attack_done` events. CLI behavior is unchanged.
- **SQLite history** (`spraymaster/storage/history.py`) — persistent attack runs
  and findings. Default `~/.spraymaster/history.db`, overridable via `$SPRAYMASTER_DB`.
- **AttackEngine.request_stop()** — external stop signal that observers can use
  to halt an in-flight attack (drives the TUI/Web stop button).
- 24 new tests (history round-trip, engine events, runner adapter, web API
  with FastAPI TestClient, WebSocket event fanout).

### Changed

- Bumped to 2.2.0
- `pyproject.toml`: added `[tui]`, `[web]` extras; both bundled into `[all]`
- Added `spraymaster-tui` and `spraymaster-web` console scripts
- Web/TUI both reuse the existing CLI engine — zero breaking change for CLI users

## [2.1.0] — 2026-05-17

### Added
- `pyproject.toml` — modern PEP 621 packaging with `pip install spraymaster` support
- `spraymaster` console script entry point — no more `python -m spraymaster`
- Optional dependency groups: `mysql`, `postgres`, `mssql`, `ldap`, `redis`, `smb`, `vnc`, `snmp`, `socks`, `all`, `dev`
- `--version`, `--list-protocols`, `--quiet`, `--no-banner` flags
- Graceful SIGINT shutdown with proper exit codes (0 = success, 1 = no creds, 2 = bad usage, 130 = interrupt)
- Better error messages for missing wordlist files
- `LICENSE` (MIT), `CHANGELOG.md`, `MANIFEST.in`, `py.typed` marker
- Dockerfile + `.dockerignore` for container distribution (Docker Hub / GHCR)
- npm wrapper package (`npm install -g spraymaster`) that dispatches to the Python CLI
- PyInstaller spec for standalone binaries (Windows / macOS / Linux)
- GitHub Actions: CI (lint + tests across Python 3.9–3.13 and 3 OSes), automated release pipeline (PyPI / npm / Docker / GitHub Releases)
- Test suite covering utils, CLI parsing, engine task generation, output formats

### Changed
- Internal imports now use the fully-qualified `spraymaster.xxx` form — required for `pip install` to work
- Removed the `sys.path.insert(...)` runtime hack from `__main__.py`
- Bumped to v2.1.0

### Fixed
- Package was previously only runnable via `cd spraymaster && python __main__.py` because of the import hack — now properly installable.

## [2.0.0] — earlier

- Initial multi-protocol release. 15 protocols, password spray + brute-force + combo modes, Rich UI, JSON/CSV output, retries, proxy, stop-on-success strategies.
