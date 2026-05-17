import json
import logging

from spraymaster.core.logging_utils import JsonFormatter, install_json_handler


def test_json_formatter_strips_rich_tags_and_emits_jsonl():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="SprayMaster",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="[bold green]ok[/bold green] %s",
        args=("hello",),
        exc_info=None,
    )
    out = formatter.format(record)
    payload = json.loads(out)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "SprayMaster"
    assert payload["message"] == "ok hello"
    assert "ts" in payload


def test_install_json_handler_writes_to_file(tmp_path):
    target = tmp_path / "spray.jsonl"
    install_json_handler(str(target))
    logger = logging.getLogger("SprayMaster")
    logger.setLevel(logging.INFO)
    logger.info("hello [bold]world[/bold]")
    # Detach the handler so subsequent tests don't keep writing here.
    for h in list(logger.handlers):
        if getattr(h, "baseFilename", "") == str(target):
            h.flush()
            logger.removeHandler(h)
            h.close()

    lines = target.read_text(encoding="utf-8").splitlines()
    assert lines, "expected at least one JSON line"
    rec = json.loads(lines[-1])
    assert rec["message"] == "hello world"
    assert rec["level"] == "INFO"
