import csv
import json

from spraymaster.core.output import OutputManager


def _sample(user="admin", host="10.0.0.1", port=22, password="hunter2"):
    return {
        "status": "success",
        "host": host,
        "port": port,
        "user": user,
        "pass": password,
        "protocol": "ssh",
    }


def test_text_output_writes_one_line_per_record(tmp_path):
    f = tmp_path / "out.txt"
    mgr = OutputManager(str(f), "text")
    mgr.write(_sample())
    mgr.write(_sample(user="root", password="toor"))
    mgr.close()

    lines = f.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert "admin:hunter2" in lines[0]
    assert "root:toor" in lines[1]


def test_json_output_is_jsonl(tmp_path):
    f = tmp_path / "out.json"
    mgr = OutputManager(str(f), "json")
    mgr.write(_sample())
    mgr.write(_sample(user="root"))
    mgr.close()

    records = [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 2
    assert records[0]["user"] == "admin"
    assert records[1]["user"] == "root"


def test_csv_output_has_header_and_rows(tmp_path):
    f = tmp_path / "out.csv"
    mgr = OutputManager(str(f), "csv")
    mgr.write(_sample())
    mgr.close()

    with open(f, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    assert len(rows) == 1
    assert rows[0]["user"] == "admin"
    assert rows[0]["pass"] == "hunter2"
    assert rows[0]["host"] == "10.0.0.1"
