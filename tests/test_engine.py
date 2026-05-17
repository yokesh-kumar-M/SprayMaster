import argparse

from rich.console import Console

from spraymaster.core.engine import AttackEngine


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
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _engine(args, targets, users, passwords):
    return AttackEngine(args, targets, users, passwords, Console(quiet=True))


def test_brute_force_task_matrix_is_full_cross_product():
    eng = _engine(_args(), ["h1", "h2"], ["u1", "u2"], ["p1", "p2"])

    tasks = eng._build_tasks()

    assert len(tasks) == 8
    assert ("h1", "u1", "p1") in tasks
    assert ("h2", "u2", "p2") in tasks


def test_spray_mode_iterates_passwords_outermost():
    eng = _engine(_args(spray=True), ["h1"], ["u1", "u2"], ["pA", "pB"])

    tasks = eng._build_tasks()

    # In spray mode the first two tasks should share password pA across both users
    assert tasks[0] == ("h1", "u1", "pA")
    assert tasks[1] == ("h1", "u2", "pA")
    assert tasks[2] == ("h1", "u1", "pB")
    assert tasks[3] == ("h1", "u2", "pB")


def test_combo_mode_zips_users_and_passwords():
    eng = _engine(
        _args(combo="combo.txt"),
        ["h1", "h2"],
        ["alice", "bob"],
        ["pass1", "pass2"],
    )

    tasks = eng._build_tasks()

    # 2 targets * 2 combo pairs = 4 tasks; passwords zip with users, not cross.
    assert len(tasks) == 4
    assert ("h1", "alice", "pass1") in tasks
    assert ("h1", "bob", "pass2") in tasks
    assert ("h1", "alice", "pass2") not in tasks


def test_compute_skip_key_strategies():
    assert AttackEngine._compute_skip_key("none", "u", "h") is None
    assert AttackEngine._compute_skip_key("user", "u", "h") == "u"
    assert AttackEngine._compute_skip_key("host", "u", "h") == ("u", "h")
    assert AttackEngine._compute_skip_key("global", "u", "h") is None


def test_global_stop_sets_stop_event():
    eng = _engine(_args(stop_on_success="global"), ["h"], ["u"], ["p"])
    result = {
        "status": "success",
        "host": "h",
        "port": 22,
        "user": "u",
        "pass": "p",
        "protocol": "ssh",
    }

    eng._record_success(result, "global", None)

    assert eng._stop_event.is_set()


def test_user_skip_records_skip_key():
    eng = _engine(_args(stop_on_success="user"), ["h"], ["u"], ["p"])
    result = {
        "status": "success",
        "host": "h",
        "port": 22,
        "user": "alice",
        "pass": "p",
        "protocol": "ssh",
    }

    eng._record_success(result, "user", "alice")

    assert "alice" in eng._skipped
    assert eng._is_skipped("alice")
    assert not eng._stop_event.is_set()
