"""Web UI tests via FastAPI's TestClient. No real network — uses a fake
protocol handler patched into the registry.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app(tmp_path, monkeypatch):
    # Always-fail fake login keeps tests fast and deterministic.
    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY",
        {
            "ssh": lambda h, u, p, a: {
                "status": "success" if u == "admin" else "fail",
                "host": h,
                "port": 22,
                "user": u,
                "pass": p,
                "protocol": "ssh",
                "error": None,
            }
        },
    )
    # Also patch the auth/registry-side import so /attacks accepts "ssh".
    monkeypatch.setattr(
        "spraymaster.web.app.PROTOCOL_REGISTRY",
        {"ssh": object()},
    )

    from spraymaster.web.app import create_app

    return create_app(db_path=tmp_path / "h.db", auth_token="test-token")


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def auth_client(app):
    c = TestClient(app)
    c.cookies.set("spraymaster_session", "test-token")
    return c


# ---------- auth ----------

def test_index_redirects_to_login_when_unauthenticated(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_login_get_renders_form(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "Auth token" in r.text


def test_login_rejects_wrong_token(client):
    r = client.post("/login", data={"token_value": "wrong"}, follow_redirects=False)
    assert r.status_code == 401
    assert "Invalid token" in r.text


def test_login_sets_cookie_on_correct_token(client):
    r = client.post(
        "/login", data={"token_value": "test-token"}, follow_redirects=False
    )
    assert r.status_code == 303
    assert "spraymaster_session=test-token" in r.headers["set-cookie"]


def test_api_requires_auth(client):
    r = client.get("/api/runs")
    assert r.status_code in (303, 401)


def test_api_accepts_bearer_header(client):
    r = client.get("/api/runs", headers={"Authorization": "Bearer test-token"})
    assert r.status_code == 200
    assert r.json() == []


# ---------- index page ----------

def test_index_lists_protocols_when_authenticated(auth_client):
    r = auth_client.get("/")
    assert r.status_code == 200
    assert "New attack" in r.text
    assert "ssh" in r.text


# ---------- attack lifecycle ----------

def test_start_attack_redirects_to_status_page(auth_client):
    r = auth_client.post(
        "/attacks",
        data={
            "protocol": "ssh",
            "targets": "10.0.0.1",
            "users": "admin, guest",
            "passwords": "hunter2",
            "threads": 2,
            "timeout": 1,
            "retries": 1,
            "stop_on_success": "none",
            "http_path": "/",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"].startswith("/attacks/")
    run_id = int(r.headers["location"].rsplit("/", 1)[1])
    assert run_id > 0


def test_start_attack_rejects_missing_targets(auth_client):
    r = auth_client.post(
        "/attacks",
        data={
            "protocol": "ssh",
            "targets": "",
            "users": "admin",
            "passwords": "x",
        },
    )
    assert r.status_code == 400


def test_start_attack_then_findings_appear_in_history(auth_client, app):
    r = auth_client.post(
        "/attacks",
        data={
            "protocol": "ssh",
            "targets": "10.0.0.1",
            "users": "admin, guest",
            "passwords": "hunter2",
            "threads": 2,
            "timeout": 1,
            "retries": 1,
            "stop_on_success": "none",
        },
        follow_redirects=False,
    )
    run_id = int(r.headers["location"].rsplit("/", 1)[1])

    # Wait briefly for the worker thread to complete.
    deadline = time.time() + 10
    while time.time() < deadline:
        run = app.state.history.get_run(run_id)
        if run and run.status == "done":
            break
        time.sleep(0.05)

    findings = app.state.history.findings_for(run_id)
    assert len(findings) == 1
    assert findings[0].username == "admin"


# ---------- history ----------

def test_history_page_renders_runs(auth_client, app):
    app.state.history.start_run("ssh", 1, 1, 1, {})
    r = auth_client.get("/history")
    assert r.status_code == 200
    assert "Attack history" in r.text


def test_api_findings_returns_run_findings(auth_client, app):
    run_id = app.state.history.start_run("ssh", 1, 1, 1, {})
    app.state.history.record_finding(run_id, "h", 22, "u", "p", "ssh")

    r = auth_client.get(f"/api/runs/{run_id}/findings")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["user"] == "u"
