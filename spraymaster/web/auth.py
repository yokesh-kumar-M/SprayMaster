"""Single-shared-token auth.

The web UI is meant for self-hosting by a pentest team behind some kind of
front door (VPN, SSH tunnel, reverse proxy with mTLS). The auth model is
deliberately simple: one bearer token, configured via the ``SPRAYMASTER_AUTH_TOKEN``
env var. If none is set when the server starts, we generate a random one and
print it to stderr so the operator can grab it from the boot log.
"""

from __future__ import annotations

import os
import secrets
import sys

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

COOKIE_NAME = "spraymaster_session"
TOKEN_HEADER = "X-SprayMaster-Token"
ENV_VAR = "SPRAYMASTER_AUTH_TOKEN"


def resolve_token() -> str:
    """Return the configured auth token, generating one if unset."""
    token = os.environ.get(ENV_VAR)
    if token:
        return token
    generated = secrets.token_urlsafe(24)
    os.environ[ENV_VAR] = generated
    sys.stderr.write(
        "\n"
        "  ┌── SprayMaster Web — auth token (no SPRAYMASTER_AUTH_TOKEN was set) ──\n"
        f"  │  Token:  {generated}\n"
        "  │  Use this once at /login. Set SPRAYMASTER_AUTH_TOKEN in env to override.\n"
        "  └─────────────────────────────────────────────────────────────────────\n\n"
    )
    return generated


def request_token(request: Request) -> str | None:
    """Pull the caller's claimed token from cookie, header, or ?token= query."""
    if (val := request.cookies.get(COOKIE_NAME)):
        return val
    if (val := request.headers.get(TOKEN_HEADER)):
        return val
    if (val := request.headers.get("Authorization", "")).lower().startswith("bearer "):
        return val.split(" ", 1)[1]
    if (val := request.query_params.get("token")):  # used by WebSocket clients
        return val
    return None


def is_authenticated(request: Request, expected: str) -> bool:
    candidate = request_token(request)
    return candidate is not None and secrets.compare_digest(candidate, expected)


def require_auth(request: Request, expected: str) -> None:
    if not is_authenticated(request, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


def redirect_to_login() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
