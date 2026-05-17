"""SQLite-backed attack history for the TUI and Web UI.

Stdlib-only. The DB lives at ``~/.spraymaster/history.db`` by default; override
with ``$SPRAYMASTER_DB``. Schema is intentionally small — one row per attack
run, one row per finding.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    REAL    NOT NULL,
    finished_at   REAL,
    status        TEXT    NOT NULL,           -- running | done | failed | cancelled
    protocol      TEXT    NOT NULL,
    target_count  INTEGER NOT NULL,
    user_count    INTEGER NOT NULL,
    password_count INTEGER NOT NULL,
    total_attempts INTEGER,
    success_count INTEGER DEFAULT 0,
    error_count   INTEGER DEFAULT 0,
    config_json   TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host      TEXT    NOT NULL,
    port      INTEGER NOT NULL,
    username  TEXT    NOT NULL,
    password  TEXT    NOT NULL,
    protocol  TEXT    NOT NULL,
    found_at  REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC);
"""


def default_db_path() -> Path:
    override = os.environ.get("SPRAYMASTER_DB")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".spraymaster" / "history.db"


@dataclass
class RunRow:
    id: int
    started_at: float
    finished_at: float | None
    status: str
    protocol: str
    target_count: int
    user_count: int
    password_count: int
    total_attempts: int | None
    success_count: int
    error_count: int
    config: dict


@dataclass
class FindingRow:
    id: int
    run_id: int
    host: str
    port: int
    username: str
    password: str
    protocol: str
    found_at: float


class History:
    """Thread-safe SQLite history store.

    Why per-thread connections: sqlite3 connections in stdlib are not safe
    across threads by default. We open one connection per accessing thread
    via thread-local storage; this also avoids locking overhead on the read
    path (browser polling, TUI history view).
    """

    def __init__(self, db_path: Path | None = None):
        self.db_path = Path(db_path) if db_path else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        # Initialise schema on the calling thread's connection.
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES,
                isolation_level=None,  # autocommit; we manage transactions explicitly
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            self._local.conn = conn
        return conn

    # ---------------- writes ----------------

    def start_run(
        self,
        protocol: str,
        target_count: int,
        user_count: int,
        password_count: int,
        config: dict,
    ) -> int:
        with self._write_lock:
            cur = self._conn().execute(
                """
                INSERT INTO runs (started_at, status, protocol, target_count,
                                  user_count, password_count, config_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    "running",
                    protocol,
                    target_count,
                    user_count,
                    password_count,
                    json.dumps(config, default=str),
                ),
            )
            return int(cur.lastrowid)

    def record_finding(
        self,
        run_id: int,
        host: str,
        port: int,
        username: str,
        password: str,
        protocol: str,
    ) -> None:
        with self._write_lock:
            self._conn().execute(
                """
                INSERT INTO findings (run_id, host, port, username, password,
                                      protocol, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, host, port, username, password, protocol, time.time()),
            )

    def finish_run(
        self,
        run_id: int,
        status: str,
        total_attempts: int,
        success_count: int,
        error_count: int,
    ) -> None:
        with self._write_lock:
            self._conn().execute(
                """
                UPDATE runs
                   SET finished_at = ?, status = ?, total_attempts = ?,
                       success_count = ?, error_count = ?
                 WHERE id = ?
                """,
                (
                    time.time(),
                    status,
                    total_attempts,
                    success_count,
                    error_count,
                    run_id,
                ),
            )

    # ---------------- reads ----------------

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> RunRow:
        return RunRow(
            id=row["id"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            status=row["status"],
            protocol=row["protocol"],
            target_count=row["target_count"],
            user_count=row["user_count"],
            password_count=row["password_count"],
            total_attempts=row["total_attempts"],
            success_count=row["success_count"] or 0,
            error_count=row["error_count"] or 0,
            config=json.loads(row["config_json"]) if row["config_json"] else {},
        )

    def list_runs(self, limit: int = 50) -> list[RunRow]:
        rows = self._conn().execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_run(r) for r in rows]

    def get_run(self, run_id: int) -> RunRow | None:
        row = self._conn().execute(
            "SELECT * FROM runs WHERE id = ?", (run_id,)
        ).fetchone()
        return self._row_to_run(row) if row else None

    def findings_for(self, run_id: int) -> list[FindingRow]:
        rows = self._conn().execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY found_at",
            (run_id,),
        ).fetchall()
        return [
            FindingRow(
                id=r["id"],
                run_id=r["run_id"],
                host=r["host"],
                port=r["port"],
                username=r["username"],
                password=r["password"],
                protocol=r["protocol"],
                found_at=r["found_at"],
            )
            for r in rows
        ]

    def delete_run(self, run_id: int) -> None:
        with self._write_lock:
            self._conn().execute("DELETE FROM runs WHERE id = ?", (run_id,))

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


def history_observer(history: History, run_id: int) -> Iterable:
    """Build an engine event observer that mirrors successes into ``history``."""

    def _observer(event: dict) -> None:
        if event.get("type") == "success":
            history.record_finding(
                run_id=run_id,
                host=event["host"],
                port=event["port"],
                username=event["user"],
                password=event["pass"],
                protocol=event["protocol"],
            )

    return _observer
