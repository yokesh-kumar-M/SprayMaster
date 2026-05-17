"""End-to-end engine tests covering cancellation + rate limiting."""

import argparse
import threading
import time

from rich.console import Console

from spraymaster.core.engine import EVENT_ATTACK_DONE, AttackEngine


def _args(**overrides):
    base = {
        "protocol": "ssh",
        "spray": False,
        "combo": None,
        "threads": 4,
        "delay": 0.0,
        "timeout": 5,
        "retries": 1,
        "stop_on_success": "none",
        "output": None,
        "output_format": "text",
        "verbose": False,
        "quiet": True,
        "port": None,
        "ssl": False,
        "proxy": None,
        "max_rate": 0.0,
        "per_host_rate": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_external_stop_halts_in_flight_attack(monkeypatch):
    barrier = threading.Event()
    started = threading.Event()

    def slow_login(host, user, password, args):
        started.set()
        barrier.wait(timeout=2)
        return {
            "status": "fail",
            "host": host,
            "port": 22,
            "user": user,
            "pass": password,
            "protocol": "ssh",
            "error": None,
        }

    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY",
        {"ssh": slow_login},
    )

    eng = AttackEngine(
        _args(threads=2),
        ["h1"],
        [f"u{i}" for i in range(20)],
        ["p"],
        Console(quiet=True),
    )
    t = threading.Thread(target=eng.run, daemon=True)
    t.start()
    assert started.wait(timeout=2)
    eng.request_stop()
    barrier.set()  # unblock any threads still parked in login
    t.join(timeout=5)
    assert not t.is_alive()
    assert eng.stopped is True


def test_attack_done_event_carries_cancelled_flag(monkeypatch):
    def login(host, user, password, args):
        return {
            "status": "fail",
            "host": host,
            "port": 22,
            "user": user,
            "pass": password,
            "protocol": "ssh",
            "error": None,
        }

    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY", {"ssh": login}
    )

    events = []
    eng = AttackEngine(
        _args(),
        ["h"],
        ["u"],
        ["p"],
        Console(quiet=True),
        on_event=events.append,
    )
    eng.run()
    done = next(e for e in events if e["type"] == EVENT_ATTACK_DONE)
    assert done["cancelled"] is False


def test_rate_limit_caps_throughput(monkeypatch):
    """With max_rate=20 and 40 attempts, total elapsed must be >= ~1s."""

    def login(host, user, password, args):
        return {
            "status": "fail",
            "host": host,
            "port": 22,
            "user": user,
            "pass": password,
            "protocol": "ssh",
            "error": None,
        }

    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY", {"ssh": login}
    )

    eng = AttackEngine(
        _args(threads=8, max_rate=20.0),
        ["h"],
        [f"u{i}" for i in range(40)],
        ["p"],
        Console(quiet=True),
    )
    start = time.monotonic()
    eng.run()
    elapsed = time.monotonic() - start
    # 40 attempts / 20 RPS = 2.0s ideal. Allow slack but require the cap held.
    assert elapsed >= 1.0
    assert len(eng.results) == 40


def test_per_host_concurrency_cap_respected(monkeypatch):
    in_flight = {"n": 0}
    peak = {"n": 0}
    lock = threading.Lock()

    def login(host, user, password, args):
        with lock:
            in_flight["n"] += 1
            if in_flight["n"] > peak["n"]:
                peak["n"] = in_flight["n"]
        time.sleep(0.02)
        with lock:
            in_flight["n"] -= 1
        return {
            "status": "fail",
            "host": host,
            "port": 22,
            "user": user,
            "pass": password,
            "protocol": "ssh",
            "error": None,
        }

    monkeypatch.setattr(
        "spraymaster.core.engine.PROTOCOL_REGISTRY", {"ssh": login}
    )

    eng = AttackEngine(
        _args(threads=16, per_host_rate=3),
        ["h1"],
        [f"u{i}" for i in range(40)],
        ["p"],
        Console(quiet=True),
    )
    eng.run()
    assert peak["n"] <= 3
    assert len(eng.results) == 40
