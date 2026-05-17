"""Persistence layer — currently SQLite-backed attack history."""

from spraymaster.storage.history import History, default_db_path

__all__ = ["History", "default_db_path"]
