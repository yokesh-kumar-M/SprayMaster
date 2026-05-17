"""Rate-limiting primitives for the attack engine.

Two independent throttles:

* :class:`TokenBucket` — global requests-per-second cap. Producers acquire one
  token per attempt and block until the bucket refills. Implements a classic
  leaky-bucket / token-bucket with monotonic time and a single lock.
* :class:`HostSemaphores` — per-host concurrency cap. Workers acquire a slot
  for the host they're hitting, so a slow target doesn't monopolise every
  thread when many hosts are queued.

Both are safe to use across the worker threads spawned by ThreadPoolExecutor
and both honour a ``threading.Event`` so cancellation interrupts a long wait.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager


class TokenBucket:
    """Thread-safe token bucket with monotonic-time refill.

    ``rate`` is tokens/second. ``capacity`` defaults to ``rate`` (one second's
    worth of burst). ``acquire`` blocks until a token is available or the
    supplied ``stop_event`` (if any) is set, in which case it returns ``False``.
    """

    def __init__(self, rate: float, capacity: float | None = None):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = float(capacity) if capacity is not None else float(rate)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last = now

    def acquire(self, stop_event: threading.Event | None = None) -> bool:
        """Block until one token is available. Returns False if stopped."""
        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                deficit = 1.0 - self._tokens
                wait = deficit / self.rate
            # Sleep in short hops so a stop request is honoured promptly.
            slept = 0.0
            chunk = 0.05
            while slept < wait:
                if stop_event is not None and stop_event.is_set():
                    return False
                time.sleep(min(chunk, wait - slept))
                slept += chunk


class HostSemaphores:
    """Lazy per-host semaphore registry.

    A bounded concurrency limit per host — without this, a target that hangs
    until ``timeout`` can soak up every worker thread while other queued hosts
    starve.
    """

    def __init__(self, per_host: int):
        if per_host <= 0:
            raise ValueError("per_host must be > 0")
        self.per_host = int(per_host)
        self._lock = threading.Lock()
        self._sems: dict[str, threading.BoundedSemaphore] = {}

    def _get(self, host: str) -> threading.BoundedSemaphore:
        with self._lock:
            sem = self._sems.get(host)
            if sem is None:
                sem = threading.BoundedSemaphore(self.per_host)
                self._sems[host] = sem
            return sem

    @contextmanager
    def slot(self, host: str, stop_event: threading.Event | None = None):
        sem = self._get(host)
        acquired = False
        # Poll-acquire so a stop request can break us out of an idle wait.
        while not acquired:
            if stop_event is not None and stop_event.is_set():
                yield False
                return
            acquired = sem.acquire(timeout=0.1)
        try:
            yield True
        finally:
            sem.release()
