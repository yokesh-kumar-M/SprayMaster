"""CLI entry point for the SprayMaster web UI.

Run with:  ``spraymaster-web``  or  ``python -m spraymaster.web``
"""

from __future__ import annotations

import argparse
import os
import sys

from spraymaster import __version__


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _build_parser() -> argparse.ArgumentParser:
    # $PORT (Render/Heroku/Fly/Vercel/etc.) wins over the static default.
    default_port = int(os.environ.get("PORT") or 8000)
    # When deployed behind a managed PaaS the host MUST be 0.0.0.0; we default
    # accordingly if PORT is set or the deploy explicitly opts in via env.
    paas_mode = bool(os.environ.get("PORT")) or _env_truthy("SPRAYMASTER_ALLOW_PUBLIC")
    default_host = "0.0.0.0" if paas_mode else "127.0.0.1"

    p = argparse.ArgumentParser(
        prog="spraymaster-web",
        description=f"SprayMaster v{__version__} — web UI",
    )
    p.add_argument("--host", default=default_host,
                   help="Bind address (default: 127.0.0.1 locally, 0.0.0.0 when $PORT is set)")
    p.add_argument("--port", type=int, default=default_port,
                   help="Listen port (default: $PORT or 8000)")
    p.add_argument("--db", default=None, help="Path to SQLite history DB (overrides $SPRAYMASTER_DB)")
    p.add_argument("--allow-public", action="store_true",
                   help="Allow binding to a non-loopback address (dangerous — auth token only)")
    p.add_argument("-V", "--version", action="version", version=f"SprayMaster Web {__version__}")
    return p


def main() -> int:
    args = _build_parser().parse_args()

    public_bind = args.host not in {"127.0.0.1", "::1", "localhost"}
    # Public binds need an explicit signal:
    #   --allow-public, SPRAYMASTER_ALLOW_PUBLIC, SPRAYMASTER_SAFE_DEMO (attacks
    #   are gated, so exposure is safe), or a managed-PaaS $PORT (Render et al.).
    public_ok = (
        args.allow_public
        or _env_truthy("SPRAYMASTER_ALLOW_PUBLIC")
        or _env_truthy("SPRAYMASTER_SAFE_DEMO")
        or bool(os.environ.get("PORT"))
    )
    if public_bind and not public_ok:
        sys.stderr.write(
            "\n  refusing to bind to a non-loopback address without --allow-public.\n"
            "  the auth model is a single bearer token; only expose this on a\n"
            "  network you trust (VPN / SSH tunnel / reverse proxy with mTLS).\n\n"
        )
        return 2

    try:
        import uvicorn
    except ImportError:
        sys.stderr.write(
            "\n  uvicorn is required to run the web UI.\n"
            "  install it with:  pip install 'spraymaster[web]'\n\n"
        )
        return 1

    from spraymaster.web.app import create_app

    app = create_app(db_path=args.db)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", proxy_headers=True, forwarded_allow_ips="*")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
