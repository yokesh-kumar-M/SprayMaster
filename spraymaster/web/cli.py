"""CLI entry point for the SprayMaster web UI.

Run with:  ``spraymaster-web``  or  ``python -m spraymaster.web``
"""

from __future__ import annotations

import argparse
import sys

from spraymaster import __version__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spraymaster-web",
        description=f"SprayMaster v{__version__} — web UI",
    )
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind address (default: 127.0.0.1 — refuse public bind unless --allow-public is set)")
    p.add_argument("--port", type=int, default=8000, help="Listen port (default: 8000)")
    p.add_argument("--db", default=None, help="Path to SQLite history DB (overrides $SPRAYMASTER_DB)")
    p.add_argument("--allow-public", action="store_true",
                   help="Allow binding to a non-loopback address (dangerous — auth token only)")
    p.add_argument("-V", "--version", action="version", version=f"SprayMaster Web {__version__}")
    return p


def main() -> int:
    args = _build_parser().parse_args()

    if args.host not in {"127.0.0.1", "::1", "localhost"} and not args.allow_public:
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
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
