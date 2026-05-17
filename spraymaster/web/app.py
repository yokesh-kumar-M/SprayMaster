"""FastAPI app — SprayMaster web UI.

Routes:
  GET  /                    config form (Jinja)
  GET  /login               token entry page
  POST /login               sets session cookie if token matches
  POST /attacks             starts a new attack, redirects to /attacks/{id}
  GET  /attacks/{id}        live status page (HTMX + WS)
  GET  /history             list of past runs (HTMX-friendly)
  GET  /history/{id}        findings for a run
  POST /history/{id}/delete delete a run + its findings
  WS   /ws/attacks/{id}     event stream

Auth: single bearer token via cookie / header / ?token=. See web/auth.py.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from spraymaster import __version__
from spraymaster.core.utils import load_combo_list, load_list
from spraymaster.protocols import PROTOCOL_REGISTRY
from spraymaster.storage.history import History
from spraymaster.web.auth import (
    COOKIE_NAME,
    is_authenticated,
    redirect_to_login,
    request_token,
    resolve_token,
)
from spraymaster.web.runs import RunRegistry

_PKG_DIR = Path(__file__).parent
_TEMPLATES_DIR = _PKG_DIR / "templates"
_STATIC_DIR = _PKG_DIR / "static"


def _parse_targets_field(value: str) -> list[str]:
    """A user-entered target / user / password field is either:
    - whitespace/comma-separated values, or
    - a path to a wordlist file (one entry per line).
    """
    if not value:
        return []
    p = Path(value.strip()).expanduser()
    if p.exists() and p.is_file():
        return load_list(str(p))
    out = []
    for chunk in value.replace("\r", "\n").split("\n"):
        for piece in chunk.split(","):
            piece = piece.strip()
            if piece:
                out.append(piece)
    return out


def create_app(*, db_path: Path | None = None, auth_token: str | None = None) -> FastAPI:
    history = History(db_path=db_path)
    token = auth_token or resolve_token()
    registry = RunRegistry(history)

    app = FastAPI(title="SprayMaster Web", version=__version__)
    app.state.history = history
    app.state.registry = registry
    app.state.auth_token = token

    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    templates.env.globals["spraymaster_version"] = __version__

    # ---------- auth dep ----------
    # JSON API uses 401 (machine-readable). HTML pages do their own
    # is_authenticated/redirect dance so unauthenticated humans land on /login.
    def auth_dep(request: Request) -> None:
        if not is_authenticated(request, token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )

    # ---------- pages ----------

    @app.get("/login", response_class=HTMLResponse)
    async def login_get(request: Request):
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login")
    async def login_post(request: Request, response: Response, token_value: str = Form(...)):
        if token_value != token:
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Invalid token."},
                status_code=401,
            )
        resp = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        resp.set_cookie(
            COOKIE_NAME,
            token_value,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 24 * 30,
        )
        return resp

    @app.post("/logout")
    async def logout():
        resp = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        resp.delete_cookie(COOKIE_NAME)
        return resp

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        if not is_authenticated(request, token):
            return redirect_to_login()
        protocols = sorted(PROTOCOL_REGISTRY.keys())
        return templates.TemplateResponse(
            request, "index.html", {"protocols": protocols}
        )

    @app.post("/attacks")
    async def start_attack(
        request: Request,
        protocol: str = Form(...),
        targets: str = Form(""),
        users: str = Form(""),
        passwords: str = Form(""),
        combo: str = Form(""),
        threads: int = Form(16),
        timeout: int = Form(10),
        retries: int = Form(3),
        port: str = Form(""),
        stop_on_success: str = Form("none"),
        spray: str = Form(""),
        ssl: str = Form(""),
        http_path: str = Form("/"),
        http_form_data: str = Form(""),
        http_fail_string: str = Form(""),
    ):
        if not is_authenticated(request, token):
            return redirect_to_login()
        if protocol not in PROTOCOL_REGISTRY:
            raise HTTPException(400, f"Unknown protocol: {protocol}")

        target_list = _parse_targets_field(targets)
        if combo.strip():
            p = Path(combo.strip()).expanduser()
            if not p.exists():
                raise HTTPException(400, f"Combo file not found: {combo}")
            pairs = load_combo_list(str(p))
            user_list = [u for u, _ in pairs]
            pass_list = [p for _, p in pairs]
        else:
            user_list = _parse_targets_field(users)
            pass_list = _parse_targets_field(passwords)

        if not target_list:
            raise HTTPException(400, "At least one target required")
        if not user_list or not pass_list:
            raise HTTPException(400, "Users and passwords required (or use a combo file)")

        form = {
            "protocol": protocol,
            "spray": bool(spray),
            "ssl": bool(ssl),
            "combo": combo or None,
            "threads": threads,
            "timeout": timeout,
            "retries": retries,
            "stop_on_success": stop_on_success,
            "port": int(port) if port.strip() else None,
            "http_path": http_path or "/",
            "http_form_data": http_form_data or None,
            "http_fail_string": http_fail_string or None,
        }

        loop = asyncio.get_running_loop()
        active = registry.start(form, target_list, user_list, pass_list, loop)
        return RedirectResponse(f"/attacks/{active.run_id}", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/attacks/{run_id}", response_class=HTMLResponse)
    async def attack_page(request: Request, run_id: int):
        if not is_authenticated(request, token):
            return redirect_to_login()
        run = history.get_run(run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        findings = history.findings_for(run_id)
        return templates.TemplateResponse(
            request,
            "attack.html",
            {
                "run": run,
                "findings": findings,
                "active": registry.get(run_id) is not None,
            },
        )

    @app.post("/attacks/{run_id}/stop")
    async def stop_attack(request: Request, run_id: int):
        if not is_authenticated(request, token):
            return redirect_to_login()
        stopped = registry.stop(run_id)
        if not stopped:
            raise HTTPException(404, "No active run with that id")
        return RedirectResponse(f"/attacks/{run_id}", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/history", response_class=HTMLResponse)
    async def history_list(request: Request):
        if not is_authenticated(request, token):
            return redirect_to_login()
        runs = history.list_runs(limit=200)
        return templates.TemplateResponse(
            request, "history.html", {"runs": runs}
        )

    @app.post("/history/{run_id}/delete")
    async def history_delete(request: Request, run_id: int):
        if not is_authenticated(request, token):
            return redirect_to_login()
        history.delete_run(run_id)
        return RedirectResponse("/history", status_code=status.HTTP_303_SEE_OTHER)

    # ---------- JSON API (handy for scripting / integrations) ----------

    @app.get("/api/runs", dependencies=[Depends(auth_dep)])
    async def api_runs():
        return [
            {
                "id": r.id,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "status": r.status,
                "protocol": r.protocol,
                "success_count": r.success_count,
                "total_attempts": r.total_attempts,
            }
            for r in history.list_runs()
        ]

    @app.get("/api/runs/{run_id}/findings", dependencies=[Depends(auth_dep)])
    async def api_findings(run_id: int):
        return [
            {
                "host": f.host,
                "port": f.port,
                "user": f.username,
                "pass": f.password,
                "protocol": f.protocol,
                "found_at": f.found_at,
            }
            for f in history.findings_for(run_id)
        ]

    # ---------- WebSocket: live event stream ----------

    @app.websocket("/ws/attacks/{run_id}")
    async def ws_attack(websocket: WebSocket, run_id: int):
        # Cookie or ?token= for WS — browsers can't set custom headers on WS.
        if not is_authenticated(websocket, token):  # type: ignore[arg-type]
            await websocket.close(code=4401)
            return
        active = registry.get(run_id)
        if active is None:
            await websocket.accept()
            await websocket.send_text(json.dumps({"type": "not_active", "run_id": run_id}))
            await websocket.close()
            return

        await websocket.accept()
        queue = active.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    # heartbeat so intermediaries don't close the socket
                    await websocket.send_text(json.dumps({"type": "ping"}))
                    continue
                await websocket.send_text(json.dumps(event))
                if event.get("type") == "attack_done":
                    break
        except WebSocketDisconnect:
            pass
        finally:
            active.unsubscribe(queue)

    return app


# Re-export the request-token helper for the auth dep above to work with
# WebSocket (it has the same .cookies/.headers/.query_params interface).
_ = request_token  # silence ruff F401
