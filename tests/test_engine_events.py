import argparse

from rich.console import Console

from spraymaster.core.engine import (
    EVENT_ATTACK_DONE,
    EVENT_ATTACK_START,
    EVENT_ATTEMPT,
    EVENT_SUCCESS,
    AttackEngine,
)


def _args(**overrides):
    base = {
        "protocol": "ssh",
        "spray": False,
        "combo": None,
        "threads": 2,
        "delay": 0.0,
        "timeout": 1,
        "retries": 1,
        "stop_on_success": "none",
        "output": None,
        "output_format": "text",
        "verbose": False,
        "quiet": True,
        "port": None,
        "ssl": False,
        "proxy": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


class _FakeRegistry(dict):
    """Patch-friendly stand-in for PROTOCOL_REGISTRY."""


def test_event_callback_receives_start_and_done(monkeypatch):
    events = []

    def fake_login(host, user, password, args):
        # Mix in some successes so we exercise success + attempt + done
        status = "success" if user == "admin" else "fail"
        return {
            "status": status,
            "host": host,
            "port": 22,
            "user": user,
            "pass": password,
            "protocol": "ssh",
            "error": None,
        }

    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY",
        {"ssh": fake_login},
    )

    eng = AttackEngine(
        _args(),
        ["host1"],
        ["admin", "guest"],
        ["p1"],
        Console(quiet=True),
        on_event=events.append,
    )
    eng.run()

    types = [e["type"] for e in events]
    assert types[0] == EVENT_ATTACK_START
    assert types[-1] == EVENT_ATTACK_DONE
    assert EVENT_SUCCESS in types
    assert EVENT_ATTEMPT in types


def test_attack_start_payload_describes_the_run(monkeypatch):
    events = []

    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY",
        {
            "ssh": lambda h, u, p, a: {
                "status": "fail",
                "host": h,
                "port": 22,
                "user": u,
                "pass": p,
                "protocol": "ssh",
                "error": None,
            }
        },
    )

    eng = AttackEngine(
        _args(spray=True, threads=8, stop_on_success="user"),
        ["h1", "h2"],
        ["alice", "bob", "carol"],
        ["pw1", "pw2"],
        Console(quiet=True),
        on_event=events.append,
    )
    eng.run()

    start = next(e for e in events if e["type"] == EVENT_ATTACK_START)
    assert start["protocol"] == "ssh"
    assert start["targets"] == 2
    assert start["users"] == 3
    assert start["passwords"] == 2
    assert start["total"] == 12
    assert start["spray"] is True
    assert start["threads"] == 8
    assert start["stop_on_success"] == "user"


def test_observer_exceptions_do_not_break_attack(monkeypatch):
    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY",
        {
            "ssh": lambda h, u, p, a: {
                "status": "fail",
                "host": h,
                "port": 22,
                "user": u,
                "pass": p,
                "protocol": "ssh",
                "error": None,
            }
        },
    )

    def angry_observer(_event):
        raise RuntimeError("observer is broken")

    eng = AttackEngine(
        _args(),
        ["host"],
        ["u"],
        ["p"],
        Console(quiet=True),
        on_event=angry_observer,
    )
    # Should NOT raise — observer failures must be swallowed.
    eng.run()


def test_request_stop_sets_stop_event():
    eng = AttackEngine(
        _args(),
        ["h"],
        ["u"],
        ["p"],
        Console(quiet=True),
    )
    assert not eng._stop_event.is_set()
    eng.request_stop()
    assert eng._stop_event.is_set()
