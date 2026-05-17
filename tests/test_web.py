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


# ---------- ops endpoints ----------

def test_healthz_is_unauthenticated_and_returns_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.text == "ok"


def test_metrics_requires_auth(client):
    r = client.get("/metrics")
    assert r.status_code == 401


def test_metrics_emits_prometheus_format(auth_client, app):
    app.state.history.start_run("ssh", 1, 1, 1, {})
    r = auth_client.get("/metrics")
    assert r.status_code == 200
    body = r.text
    assert "spraymaster_runs_total" in body
    assert "spraymaster_findings_total" in body
    assert "spraymaster_runs_active" in body
    assert 'spraymaster_info{version="' in body


def test_security_headers_set_on_html_responses(auth_client):
    r = auth_client.get("/")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers


# ---------- validation ----------

def test_start_attack_rejects_bad_port(auth_client):
    r = auth_client.post(
        "/attacks",
        data={
            "protocol": "ssh",
            "targets": "10.0.0.1",
            "users": "admin",
            "passwords": "x",
            "port": "not-a-number",
        },
    )
    assert r.status_code == 400


def test_start_attack_rejects_negative_max_rate(auth_client):
    r = auth_client.post(
        "/attacks",
        data={
            "protocol": "ssh",
            "targets": "10.0.0.1",
            "users": "admin",
            "passwords": "x",
            "max_rate": "-5",
        },
    )
    assert r.status_code == 400


def test_start_attack_rejects_bad_threads(auth_client):
    r = auth_client.post(
        "/attacks",
        data={
            "protocol": "ssh",
            "targets": "10.0.0.1",
            "users": "admin",
            "passwords": "x",
            "threads": 0,
        },
    )
    assert r.status_code == 400


# ---------- SAFE_DEMO mode ----------

@pytest.fixture
def demo_app(tmp_path, monkeypatch):
    """Same as the `app` fixture but with SAFE_DEMO mode flipped on.

    Patches the protocol registries even though attacks should never reach
    them — keeps the test honest if the gate ever regresses.
    """
    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY",
        {"ssh": lambda h, u, p, a: {"status": "fail"}},
    )
    monkeypatch.setattr(
        "spraymaster.web.app.PROTOCOL_REGISTRY",
        {"ssh": object()},
    )
    from spraymaster.web.app import create_app

    return create_app(db_path=tmp_path / "demo.db", auth_token="demo-token", safe_demo=True)


@pytest.fixture
def demo_auth_client(demo_app):
    c = TestClient(demo_app)
    c.cookies.set("spraymaster_session", "demo-token")
    return c


def test_demo_mode_blocks_attack_with_403(demo_auth_client):
    r = demo_auth_client.post(
        "/attacks",
        data={
            "protocol": "ssh",
            "targets": "10.0.0.1",
            "users": "admin",
            "passwords": "x",
        },
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert "SAFE_DEMO" in r.text


def test_demo_mode_shows_banner_on_index(demo_auth_client):
    r = demo_auth_client.get("/")
    assert r.status_code == 200
    assert "Demo mode" in r.text
    assert "outbound attacks are disabled" in r.text


def test_demo_mode_history_and_metrics_still_work(demo_auth_client, demo_app):
    demo_app.state.history.start_run("ssh", 1, 1, 1, {})
    r = demo_auth_client.get("/history")
    assert r.status_code == 200

    r = demo_auth_client.get("/metrics")
    assert r.status_code == 200
    assert "spraymaster_runs_total" in r.text


def test_demo_mode_healthz_still_works(demo_auth_client):
    r = demo_auth_client.get("/healthz")
    assert r.status_code == 200
    assert r.text == "ok"


def test_safe_demo_env_var_enables_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("SPRAYMASTER_SAFE_DEMO", "1")
    monkeypatch.setattr("spraymaster.web.app.PROTOCOL_REGISTRY", {"ssh": object()})
    from spraymaster.web.app import create_app

    a = create_app(db_path=tmp_path / "envdemo.db", auth_token="t")
    assert a.state.safe_demo is True

    c = TestClient(a)
    c.cookies.set("spraymaster_session", "t")
    r = c.post(
        "/attacks",
        data={"protocol": "ssh", "targets": "1.1.1.1", "users": "u", "passwords": "p"},
    )
    assert r.status_code == 403


def test_default_app_is_not_in_demo_mode(app):
    assert app.state.safe_demo is False
