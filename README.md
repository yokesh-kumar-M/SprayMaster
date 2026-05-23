# SprayMaster

A highly concurrent, multi-protocol network login auditor and password-spraying tool. Built for authorized penetration testing and security auditing.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/badge/PyPI-spraymaster-blue.svg)](https://pypi.org/project/spraymaster/)
[![npm](https://img.shields.io/badge/npm-spraymaster-red.svg)](https://www.npmjs.com/package/spraymaster)
[![Docker](https://img.shields.io/badge/ghcr-spraymaster-blue.svg)](https://ghcr.io/yokesh-kumar-m/spraymaster)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

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
- **Three front-ends** — `spraymaster` (CLI), `spraymaster-tui` (Textual TUI), `spraymaster-web` (FastAPI + HTMX)
- **Persistent history** — SQLite-backed history of every run and finding, queryable from TUI and Web
- **Production-ready packaging** — installable from PyPI, npm, Docker, or as a standalone binary

---

## Installation

Pick whichever fits your stack. They're all the same tool under the hood.

### 1. pipx (recommended)

```bash
pipx install spraymaster          # base CLI (10 protocols)
pipx install 'spraymaster[all]'   # CLI + TUI + Web + all protocols
pipx install 'spraymaster[tui]'   # CLI + Terminal UI
pipx install 'spraymaster[web]'   # CLI + Web UI
spraymaster --help
spraymaster-tui                   # interactive full-screen TUI
spraymaster-web --port 8000       # browser dashboard at http://127.0.0.1:8000
```

### 2. pip

```bash
pip install spraymaster
# or with extras:  pip install 'spraymaster[mysql,postgres,smb]'
# or everything:   pip install 'spraymaster[all]'
```

Optional extras you can mix-and-match:
- Protocols: `mysql`, `postgres`, `mssql`, `ldap`, `redis`, `smb`, `vnc`, `snmp`, `socks`
- UIs: `tui` (Textual), `web` (FastAPI + HTMX)
- Catch-all: `all` (all protocols + TUI + Web)

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

## Three ways to use it

| Front-end | Best for | Launch |
|-----------|----------|--------|
| **CLI** (`spraymaster`)   | Scripting, CI pipelines, one-off runs | `spraymaster --protocol ssh ...` |
| **TUI** (`spraymaster-tui`)   | SSH sessions, fast solo pentest work, no browser needed | `spraymaster-tui` |
| **Web** (`spraymaster-web`)   | Team self-hosted dashboard, browsable history, multi-watcher | `spraymaster-web --port 8000` |

All three drive the same `AttackEngine`. The Web and TUI persist every run to
`~/.spraymaster/history.db` (override with `$SPRAYMASTER_DB`); the CLI is
stateless by default but can write findings to `-o FILE`.

### TUI quick start

```bash
spraymaster-tui
```

Fill the form, press **Ctrl+R** to run, **Ctrl+H** for history, **q** to quit.
Use `,`-separated values or a file path in any of the targets/users/passwords
fields.

### Web UI quick start

```bash
# Set a strong token (or let the server generate one and print it to stderr)
export SPRAYMASTER_AUTH_TOKEN="$(openssl rand -hex 32)"
spraymaster-web --port 8000

# Open http://127.0.0.1:8000  →  enter the token  →  configure  →  Start attack
```

The web server binds to **127.0.0.1 only** by default. To expose it on a LAN/VPN
you must explicitly pass `--allow-public --host 0.0.0.0`. The auth model is a
single bearer token — it is not safe to put on the open internet without a
front-door (VPN, SSH tunnel, reverse proxy with mTLS).

#### JSON API

```bash
# Bearer token works in header for scripted access
curl -H "Authorization: Bearer $SPRAYMASTER_AUTH_TOKEN" \
     http://127.0.0.1:8000/api/runs
curl -H "Authorization: Bearer $SPRAYMASTER_AUTH_TOKEN" \
     http://127.0.0.1:8000/api/runs/1/findings
```

## CLI quick start

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

### Hosted demo (Render + Vercel)

A SAFE_DEMO instance of the FastAPI web UI is deployable to Render with one click using the Blueprint at the repo root:

- **`render.yaml`** — Docker web service, 1 GB persistent disk for SQLite history, auto-generated auth token, `SPRAYMASTER_SAFE_DEMO=1` (UI/history/API/metrics are live; outbound attack submissions return `403`).
- **`deploy/vercel/`** — static landing page (HTML + CSS, no build step) that pitches the project and links to the Render demo + GitHub repo. Deploy with `cd deploy/vercel && vercel deploy --prod`.

See [`deploy/README.md`](deploy/README.md) for the full walkthrough, security caveats, and other PaaS targets (Fly.io, Railway, Koyeb).

> **Why SAFE_DEMO?** SprayMaster is a credential-testing tool. Render and Vercel — like most PaaS — prohibit outbound credential attacks in their AUPs, regardless of intent. The demo deployment proves the UI works without putting your account at risk. Real attacks must run from a host you control, against systems you are authorized to test.

Other deployment options also available:

- **Docker Compose** for self-hosted setups (web + worker + sqlite/postgres)
- **systemd unit** for bare-metal deployments
- **Fly.io / Railway / Koyeb** — same Dockerfile, same env vars; see `deploy/README.md`

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
│   ├── engine.py          AttackEngine — threading, stop strategies, on_event hook
│   ├── output.py          Real-time writers (text / jsonl / csv)
│   └── utils.py           Wordlist + combo loaders
├── protocols/
│   ├── __init__.py        Plugin registry — gracefully handles missing deps
│   └── ssh.py, ftp.py, … 15 protocol handlers, each exposing `try_login()`
├── storage/
│   └── history.py         SQLite-backed run + finding history
├── tui/                   Textual TUI
│   ├── app.py             Three screens: Config / Run / History
│   └── runner.py          Adapter: AttackEngine in a background thread
└── web/                   FastAPI + HTMX web UI
    ├── app.py             Routes (HTML pages + JSON API + WebSocket)
    ├── auth.py            Single-token auth (cookie / header / ?token=)
    ├── runs.py            Active-run registry, worker-thread → asyncio bridge
    ├── cli.py             `spraymaster-web` entry point
    ├── templates/         Jinja templates (base, login, index, attack, history)
    └── static/            CSS + assets

tests/                     pytest suite (offline — 46 tests, no network)
packaging/spraymaster.spec PyInstaller spec for single-file binaries
npm/                       Node wrapper package
Dockerfile                 Multi-stage, all extras included
.github/workflows/         CI + release pipelines
```

### Engine event hook (for integrations)

```python
from spraymaster.core.engine import AttackEngine

def my_observer(event):
    # event["type"] in {attack_start, attempt, success, error, attack_done}
    print(event)

engine = AttackEngine(args, targets, users, passwords, console, on_event=my_observer)
engine.run()
engine.request_stop()  # external stop from another thread
```

Both the TUI and Web UI consume the engine through this hook — no special async
or framework wiring. Build your own integration (Slack notifier, webhook
forwarder, custom dashboard) by subscribing the same way.

Adding a new protocol: drop a module under `spraymaster/protocols/` exposing `try_login(host, username, password, args)` that returns `{"status": "success"/"fail"/"error", "host", "port", "user", "pass", "protocol", "error"}`. Register it in `protocols/__init__.py`. Tests in `tests/test_protocols.py` will pick it up automatically.

---

## Roadmap

- [x] v2.0 — multi-protocol concurrent core
- [x] v2.1 — packaging, PyPI/npm/Docker/binary distribution, CI/CD
- [x] v2.2 — Web UI (FastAPI + HTMX), Terminal UI (Textual), SQLite history, JSON API
- [ ] v2.3 — Resume in-flight attacks, scheduled runs, multi-user auth (RBAC), Slack/webhook notifiers

---

## Contributing

Issues and PRs welcome. Please run `pytest` and `ruff check spraymaster tests` before submitting.

## Related projects

Part of an authorised-pentest toolkit:

- [PIIcasso](https://github.com/yokesh-kumar-M/Piicasso) — adversarial wordlist generator and PII intelligence platform. Generate target-aware wordlists, then feed them to SprayMaster.
- [Clavis](https://github.com/yokesh-kumar-M/clavis) — HSM key-migration testbed with built-in VAPT suite (defender side).

## License

[Apache License 2.0](LICENSE) — see file for terms and the authorised-testing-only usage notice.

> **Note for downstream users:** SprayMaster `< 2.2.x` on PyPI / npm / GHCR was published under MIT. Releases tagged `2.3.0+` are under Apache 2.0 (adds an explicit patent grant; remains permissive).
