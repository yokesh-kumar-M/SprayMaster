import argparse

from spraymaster.tui.runner import EngineRunner, build_args


def test_build_args_translates_form_to_namespace():
    args = build_args({"protocol": "ssh", "threads": 32, "spray": True})
    assert isinstance(args, argparse.Namespace)
    assert args.protocol == "ssh"
    assert args.threads == 32
    assert args.spray is True
    # Defaults are applied for fields not present in the form
    assert args.timeout == 10
    assert args.retries == 3
    assert args.stop_on_success == "none"


def test_engine_runner_executes_and_collects_events(monkeypatch):
    fake = {
        "status": "fail",
        "host": "h1",
        "port": 22,
        "user": "u",
        "pass": "p",
        "protocol": "ssh",
        "error": None,
    }
    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY",
        {"ssh": lambda h, u, p, a: {**fake, "host": h, "user": u, "pass": p}},
    )

    events = []
    runner = EngineRunner(
        build_args({"protocol": "ssh", "threads": 2, "timeout": 1, "retries": 1}),
        ["h1"],
        ["u1", "u2"],
        ["p1"],
        on_event=events.append,
    )
    runner.start()
    runner.join(timeout=10)

    assert not runner.is_alive
    types = [e["type"] for e in events]
    assert types[0] == "attack_start"
    assert types[-1] == "attack_done"
    assert types.count("attempt") == 2  # 1 host * 2 users * 1 pass


def test_engine_runner_persists_findings_to_history(monkeypatch, tmp_path):
    from spraymaster.storage.history import History

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

    history = History(db_path=tmp_path / "h.db")
    run_id = history.start_run("ssh", 1, 2, 1, {})

    runner = EngineRunner(
        build_args({"protocol": "ssh", "threads": 2, "timeout": 1, "retries": 1}),
        ["10.0.0.1"],
        ["admin", "guest"],
        ["hunter2"],
        on_event=lambda _e: None,
        history=history,
        run_id=run_id,
    )
    runner.start()
    runner.join(timeout=10)

    findings = history.findings_for(run_id)
    assert len(findings) == 1
    assert findings[0].username == "admin"
    assert findings[0].host == "10.0.0.1"
