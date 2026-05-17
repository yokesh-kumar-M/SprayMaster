# Changelog

All notable changes to SprayMaster are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
