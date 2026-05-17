# SprayMaster

A highly concurrent, multi-protocol network login auditor and password-spraying tool. Built for authorized penetration testing and security auditing.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/badge/PyPI-spraymaster-blue.svg)](https://pypi.org/project/spraymaster/)
[![npm](https://img.shields.io/badge/npm-spraymaster-red.svg)](https://www.npmjs.com/package/spraymaster)
[![Docker](https://img.shields.io/badge/ghcr-spraymaster-blue.svg)](https://ghcr.io/yokesh-kumar-m/spraymaster)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ⚠️ Legal Disclaimer

**SprayMaster is created for authorized penetration testing and security auditing purposes only.** Any usage of this tool against targets without prior, mutual, written consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. The authors assume no liability and are not responsible for any misuse or damage caused by this program.

---

## Features

- **15 protocols** — `ftp`, `ftps`, `ssh`, `telnet`, `smtp`, `smtps`, `pop3`, `pop3s`, `imap`, `imaps`, `http`, `https`, `mysql`, `postgres`, `mssql`, `ldap`, `ldaps`, `redis`, `smb`, `vnc`, `snmp`
- **Three attack modes** — classic brute-force, password spraying (lockout-safe), and combo-list (`user:pass` pairs)
- **Smart stop strategies** — `none` / `user` / `host` / `global`
- **Concurrent threading** — tune with `--threads`, default 16
- **HTTP/HTTPS form attacks** — `^USER^` / `^PASS^` placeholders, fail/success matching, custom headers, proxy
- **Real-time reporting** — Rich-rendered progress + live success banners
- **Export formats** — plain text, JSONL, CSV
- **Production-ready packaging** — installable from PyPI, npm, Docker, or as a standalone binary

---

## Installation

Pick whichever fits your stack. They're all the same tool under the hood.

### 1. pipx (recommended)

```bash
pipx install spraymaster          # base CLI (10 protocols)
pipx install 'spraymaster[all]'   # all optional protocol extras
spraymaster --help
```

### 2. pip

```bash
pip install spraymaster
# or with extras:  pip install 'spraymaster[mysql,postgres,smb]'
# or everything:   pip install 'spraymaster[all]'
```

Optional extras you can mix-and-match: `mysql`, `postgres`, `mssql`, `ldap`, `redis`, `smb`, `vnc`, `snmp`, `socks`, `all`.

### 3. npm (Node.js wrapper)

The npm package is a thin launcher around the Python CLI. On install it tries to set up the Python package automatically (via `pipx` or `pip --user`).

```bash
npm install -g spraymaster
spraymaster --help
```

### 4. Docker

No Python install on the host. Ships with **all** protocol extras pre-installed.

```bash
# GitHub Container Registry
docker pull ghcr.io/yokesh-kumar-m/spraymaster:latest

# Run — mount a directory with your wordlists
docker run --rm -v "$PWD:/workspace" ghcr.io/yokesh-kumar-m/spraymaster \
    -U users.txt -P pass.txt -t 10.0.0.5 --protocol ssh --spray
```

### 5. Standalone binary

Download from the [GitHub Releases](https://github.com/yokesh-kumar-M/SprayMaster/releases) page — no Python required. Builds available for Linux x64, macOS arm64, Windows x64.

### 6. From source (development)

```bash
git clone https://github.com/yokesh-kumar-M/SprayMaster.git
cd SprayMaster
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev,all]"
pytest                                              # run the test suite
spraymaster --version
```

---

## Quick start

```bash
# List loaded protocols and any missing extras
spraymaster --list-protocols

# Password spray SSH across hosts (one password at a time, all users)
spraymaster -U users.txt -P passwords.txt -T targets.txt \
            --protocol ssh --spray --threads 20

# Combo list attack against a MySQL server
spraymaster -C combos.txt -t 10.10.10.50 --protocol mysql

# HTTP login form — ^USER^ / ^PASS^ placeholders
spraymaster -U users.txt -p Summer2024! -t http://example.com \
            --protocol http \
            --http-path /login \
            --http-method POST \
            --http-form-data "username=^USER^&password=^PASS^" \
            --http-fail-string "Invalid credentials"

# Save findings to JSONL as they happen
spraymaster -U users.txt -P pass.txt -t 192.168.1.5 \
            --protocol smb -o results.json --output-format json
```

---

## Core options

| Flag | Description |
|------|-------------|
| `-t`, `--target`      | Single target host or IP |
| `-T`, `--targetlist`  | File with one target per line |
| `-u`, `--user`        | Single username |
| `-U`, `--userlist`    | Username wordlist file |
| `-p`, `--password`    | Single password |
| `-P`, `--passlist`    | Password wordlist file |
| `-C`, `--combo`       | Combo file (`user:pass` per line) |
| `--protocol`          | Target protocol |
| `--spray`             | Enable password-spray mode |
| `--stop-on-success`   | `none` / `user` / `host` / `global` |
| `--threads`           | Concurrent threads (default 16) |
| `--timeout`           | Per-attempt timeout in seconds |
| `--retries`           | Retry count on transient errors |
| `--delay`             | Inter-attempt delay (seconds) |
| `--proxy`             | HTTP/SOCKS proxy (HTTP protocols) |
| `-o`, `--output`      | Write findings to file |
| `--output-format`     | `text` / `json` / `csv` |
| `--verify-ssl`        | Enforce TLS verification (off by default) |
| `--quiet`             | Successes and errors only |
| `--no-banner`         | Suppress startup banner |
| `--list-protocols`    | Show available protocols and exit |
| `-V`, `--version`     | Show version and exit |

Run `spraymaster --help` for the full list, including HTTP-specific flags.

Exit codes: `0` success (at least one valid credential), `1` no credentials found, `2` bad usage / missing wordlist, `130` interrupted (Ctrl-C).

---

## Production deployment

Several paths depending on how you want users to consume it.

| Channel | Audience | What ships | Effort |
|---------|----------|------------|--------|
| **PyPI**         | Python users | `pip install spraymaster` | Push a tag — `release.yml` does the rest |
| **npm**          | JS / Node users | `npm install -g spraymaster` (wraps the Python CLI) | Same tag, same workflow |
| **Docker / GHCR**| CI pipelines, isolated runs, "no native deps please" | `docker pull ghcr.io/.../spraymaster` | Multi-arch (amd64 + arm64), all extras baked in |
| **Docker Hub**   | Same, broader reach | `docker pull yourname/spraymaster` | Set `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN` secrets |
| **GitHub Releases** | "Just give me a binary" users | PyInstaller single-file builds for Linux/macOS/Windows | Built automatically on tag |

### Self-hosted web service (Phase 2 — coming)

The FastAPI web UI + Textual TUI live in a separate phase. The CLI core is engine-agnostic and already exposes a clean `AttackEngine` API, so wiring those on top is additive — no breaking change to existing CLI users.

Planned web deployment options:

- **Vercel / Fly.io / Railway / Render** for the FastAPI front-end (engine runs in a worker)
- **Docker Compose** for self-hosted setups (web + worker + sqlite/postgres)
- **systemd unit** for bare-metal deployments

### Cutting a release

```bash
git tag v2.1.0
git push origin v2.1.0
```

`.github/workflows/release.yml` then runs in this order:

1. Build sdist + wheel → publish to **PyPI** (trusted publishing, no token needed)
2. Publish the **npm** wrapper (needs `NPM_TOKEN` secret)
3. Build multi-arch Docker image → push to **GHCR** (always) and **Docker Hub** (if `DOCKERHUB_USERNAME` secret is set)
4. Build PyInstaller binaries for Linux / macOS / Windows
5. Create a **GitHub Release** with binaries attached and changelog notes

Required GitHub secrets (set in repo Settings → Secrets and variables → Actions):

| Secret | When | What it is |
|--------|------|------------|
| `NPM_TOKEN`           | always (for npm publish) | npm automation token |
| `DOCKERHUB_USERNAME`  | optional | only if you want Docker Hub in addition to GHCR |
| `DOCKERHUB_TOKEN`     | optional | Docker Hub access token |

PyPI uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — configure the project on PyPI once, no long-lived token required.

---

## Architecture

```
spraymaster/
├── __main__.py            CLI entrypoint (argparse + Rich)
├── core/
│   ├── engine.py          AttackEngine — threading, stop strategies, progress
│   ├── output.py          Real-time writers (text / jsonl / csv)
│   └── utils.py           Wordlist + combo loaders
└── protocols/
    ├── __init__.py        Plugin registry — gracefully handles missing deps
    ├── ssh.py, ftp.py, … 15 protocol handlers, each exposing `try_login()`
    └── …

tests/                     pytest suite (offline — no network)
packaging/spraymaster.spec PyInstaller spec for single-file binaries
npm/                       Node wrapper package
Dockerfile                 Multi-stage, all extras included
.github/workflows/         CI + release pipelines
```

Adding a new protocol: drop a module under `spraymaster/protocols/` exposing `try_login(host, username, password, args)` that returns `{"status": "success"/"fail"/"error", "host", "port", "user", "pass", "protocol", "error"}`. Register it in `protocols/__init__.py`. Tests in `tests/test_protocols.py` will pick it up automatically.

---

## Roadmap

- [x] v2.0 — multi-protocol concurrent core
- [x] v2.1 — packaging, PyPI/npm/Docker/binary distribution, CI/CD
- [ ] v2.2 — **Web UI** (FastAPI + React/Vue) for browser-based attack runs and history
- [ ] v2.2 — **Terminal UI** (Textual) for full-screen interactive mode over SSH
- [ ] v2.3 — Resume support, persistent attack history, REST API for automation

---

## Contributing

Issues and PRs welcome. Please run `pytest` and `ruff check spraymaster tests` before submitting.

## License

[MIT](LICENSE) — see file for terms and the usage notice.
