from spraymaster.storage.history import History


def test_round_trip_run_with_findings(tmp_path):
    h = History(db_path=tmp_path / "h.db")

    run_id = h.start_run(
        protocol="ssh",
        target_count=2,
        user_count=3,
        password_count=4,
        config={"threads": 16, "spray": True},
    )
    assert isinstance(run_id, int) and run_id > 0

    h.record_finding(run_id, "10.0.0.1", 22, "admin", "hunter2", "ssh")
    h.record_finding(run_id, "10.0.0.2", 22, "root", "toor", "ssh")
    h.finish_run(run_id, "done", total_attempts=24, success_count=2, error_count=0)

    runs = h.list_runs()
    assert len(runs) == 1
    assert runs[0].id == run_id
    assert runs[0].status == "done"
    assert runs[0].success_count == 2
    assert runs[0].config == {"threads": 16, "spray": True}

    findings = h.findings_for(run_id)
    assert len(findings) == 2
    assert findings[0].host == "10.0.0.1"
    assert findings[0].username == "admin"
    assert findings[1].password == "toor"


def test_findings_cascade_on_run_delete(tmp_path):
    h = History(db_path=tmp_path / "h.db")
    run_id = h.start_run("ftp", 1, 1, 1, {})
    h.record_finding(run_id, "x", 21, "u", "p", "ftp")

    h.delete_run(run_id)

    assert h.list_runs() == []
    assert h.findings_for(run_id) == []


def test_list_runs_orders_by_most_recent_first(tmp_path):
    h = History(db_path=tmp_path / "h.db")
    a = h.start_run("ssh", 1, 1, 1, {})
    b = h.start_run("ftp", 1, 1, 1, {})

    rows = h.list_runs()
    assert [r.id for r in rows] == [b, a]


def test_default_path_can_be_overridden_via_env(tmp_path, monkeypatch):
    target = tmp_path / "custom" / "h.db"
    monkeypatch.setenv("SPRAYMASTER_DB", str(target))

    from spraymaster.storage.history import default_db_path

    assert default_db_path() == target


def test_history_observer_writes_findings_for_success_events(tmp_path):
    from spraymaster.storage.history import history_observer

    h = History(db_path=tmp_path / "h.db")
    run_id = h.start_run("ssh", 1, 1, 1, {})

    obs = history_observer(h, run_id)
    obs({"type": "attempt", "host": "x", "port": 22, "user": "u", "pass": "p", "protocol": "ssh", "status": "fail"})
    obs({"type": "success", "host": "10.0.0.1", "port": 22, "user": "admin", "pass": "hunter2", "protocol": "ssh", "status": "success"})

    findings = h.findings_for(run_id)
    assert len(findings) == 1
    assert findings[0].username == "admin"
