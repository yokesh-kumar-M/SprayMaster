"""Adapter that runs an AttackEngine in a background thread and forwards its
events to a Textual-friendly callback (called from the worker thread).

Kept separate from the screens so it can be unit-tested without booting Textual.
"""

from __future__ import annotations

import argparse
import logging
import threading
from typing import Callable

from rich.console import Console

from spraymaster.core.engine import AttackEngine
from spraymaster.storage.history import History, history_observer

EventSink = Callable[[dict], None]


def build_args(form: dict) -> argparse.Namespace:
    """Translate a TUI/Web config dict into the Namespace AttackEngine expects."""
    return argparse.Namespace(
        protocol=form["protocol"],
        spray=bool(form.get("spray", False)),
        combo=form.get("combo"),
        threads=int(form.get("threads", 16)),
        delay=float(form.get("delay", 0.0)),
        timeout=int(form.get("timeout", 10)),
        retries=int(form.get("retries", 3)),
        stop_on_success=form.get("stop_on_success", "none"),
        output=form.get("output"),
        output_format=form.get("output_format", "text"),
        verbose=False,
        quiet=True,
        port=form.get("port"),
        ssl=bool(form.get("ssl", False)),
        proxy=form.get("proxy"),
        smb_domain=form.get("smb_domain"),
        verify_ssl=bool(form.get("verify_ssl", False)),
        http_path=form.get("http_path", "/"),
        http_method=form.get("http_method", "POST"),
        http_form_data=form.get("http_form_data"),
        http_fail_string=form.get("http_fail_string"),
        http_success_string=form.get("http_success_string"),
        http_headers=form.get("http_headers"),
    )


class EngineRunner:
    """Runs an attack on a background thread and exposes a stop() method.

    All ``on_event`` calls happen on the worker thread. TUI consumers should
    marshal back to the UI thread (Textual: ``app.call_from_thread``); web
    consumers can queue them onto an asyncio queue with ``loop.call_soon_threadsafe``.
    """

    def __init__(
        self,
        args: argparse.Namespace,
        targets: list[str],
        users: list[str],
        passwords: list[str],
        on_event: EventSink,
        *,
        history: History | None = None,
        run_id: int | None = None,
    ):
        self._engine = AttackEngine(
            args,
            targets,
            users,
            passwords,
            Console(quiet=True),
            on_event=self._compose_observers(on_event, history, run_id),
        )
        self._thread: threading.Thread | None = None
        self._logger = logging.getLogger("SprayMaster.runner")

    @staticmethod
    def _compose_observers(
        primary: EventSink,
        history: History | None,
        run_id: int | None,
    ) -> EventSink:
        if history is None or run_id is None:
            return primary
        persist = history_observer(history, run_id)

        def _both(event: dict) -> None:
            persist(event)
            primary(event)

        return _both

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("runner already started")
        self._thread = threading.Thread(target=self._engine.run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._engine.request_stop()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    @property
    def results(self) -> list[dict]:
        return self._engine.results

    @property
    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
