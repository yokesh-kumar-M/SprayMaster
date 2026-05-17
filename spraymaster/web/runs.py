"""Active-run registry bridging worker-thread engine events to asyncio queues.

Each browser session watching a run gets its own ``asyncio.Queue`` of events.
The engine produces events on a worker thread; we marshal each one onto the
event loop via ``loop.call_soon_threadsafe`` so subscriber queues receive them
without cross-thread fuss.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Callable

from spraymaster.storage.history import History
from spraymaster.tui.runner import EngineRunner, build_args


class ActiveRun:
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        run_id: int,
        on_done: Callable[[dict], None] | None = None,
    ):
        self.runner: EngineRunner | None = None
        self.run_id = run_id
        self._loop = loop
        self._lock = threading.Lock()
        self._subscribers: list[asyncio.Queue] = []
        self._buffer: list[dict] = []  # replay buffer for newly-connecting clients
        self._buffer_cap = 500
        self._on_done = on_done  # fired on attack_done, in the event-loop thread
        self.finished = False

    # ---------- subscriber side (asyncio) ----------
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        with self._lock:
            # Replay buffered events so a late-connecting browser sees the run
            # history (the progress bar value, prior findings, etc.).
            for ev in self._buffer:
                q.put_nowait(ev)
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    # ---------- producer side (worker thread) ----------
    def _on_engine_event(self, event: dict) -> None:
        # Called on the engine's worker thread. Push onto the event loop.
        try:
            self._loop.call_soon_threadsafe(self._fanout, event)
        except RuntimeError:
            # Loop already closed (e.g. server shutting down) — drop the event.
            pass

    def _fanout(self, event: dict) -> None:
        with self._lock:
            if len(self._buffer) < self._buffer_cap:
                self._buffer.append(event)
            for q in list(self._subscribers):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:  # pragma: no cover - unbounded queues
                    pass
        if event.get("type") == "attack_done":
            self.finished = True
            if self._on_done is not None:
                self._on_done(event)


class RunRegistry:
    def __init__(self, history: History):
        self.history = history
        self._lock = threading.Lock()
        self._runs: dict[int, ActiveRun] = {}

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._runs)

    def start(
        self,
        form: dict,
        targets: list[str],
        users: list[str],
        passwords: list[str],
        loop: asyncio.AbstractEventLoop,
    ) -> ActiveRun:
        run_id = self.history.start_run(
            protocol=form["protocol"],
            target_count=len(targets),
            user_count=len(users),
            password_count=len(passwords),
            config=form,
        )

        def _on_done(event: dict) -> None:
            status = "cancelled" if event.get("cancelled") else "done"
            self.history.finish_run(
                run_id,
                status=status,
                total_attempts=event.get("total", 0),
                success_count=event.get("successes", 0),
                error_count=event.get("errors", 0),
            )
            with self._lock:
                self._runs.pop(run_id, None)

        active = ActiveRun(loop=loop, run_id=run_id, on_done=_on_done)
        active.runner = EngineRunner(
            build_args(form),
            targets,
            users,
            passwords,
            on_event=active._on_engine_event,
            history=self.history,
            run_id=run_id,
        )

        with self._lock:
            self._runs[run_id] = active
        active.runner.start()
        return active

    def get(self, run_id: int) -> ActiveRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def stop(self, run_id: int) -> bool:
        active = self.get(run_id)
        if active is None or active.runner is None:
            return False
        active.runner.stop()
        return True
