# Changelog

All notable changes to SprayMaster are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
