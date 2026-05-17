import threading
import time

import pytest

from spraymaster.core.ratelimit import HostSemaphores, TokenBucket


def test_token_bucket_paces_acquires_to_configured_rate():
    bucket = TokenBucket(rate=20, capacity=1)
    # Drain the initial token, then time the next four — should take ~4/20 s.
    assert bucket.acquire()
    start = time.monotonic()
    for _ in range(4):
        bucket.acquire()
    elapsed = time.monotonic() - start
    # Be generous (CI clocks are messy): lower bound only.
    assert elapsed >= 4 / 20 * 0.5


def test_token_bucket_respects_stop_event():
    bucket = TokenBucket(rate=1, capacity=1)
    assert bucket.acquire()  # drain
    stop = threading.Event()

    def stopper():
        time.sleep(0.05)
        stop.set()

    threading.Thread(target=stopper, daemon=True).start()
    # Next acquire would have to wait ~1s; stop fires after 50ms.
    start = time.monotonic()
    granted = bucket.acquire(stop_event=stop)
    elapsed = time.monotonic() - start
    assert granted is False
    assert elapsed < 0.6  # released early, well before the 1s refill


def test_token_bucket_rejects_non_positive_rate():
    with pytest.raises(ValueError):
        TokenBucket(rate=0)


def test_host_semaphores_cap_concurrency_per_host():
    sems = HostSemaphores(per_host=2)
    in_flight = 0
    peak = 0
    lock = threading.Lock()

    def worker():
        nonlocal in_flight, peak
        with sems.slot("h1") as ok:
            assert ok
            with lock:
                in_flight += 1
                if in_flight > peak:
                    peak = in_flight
            time.sleep(0.05)
            with lock:
                in_flight -= 1

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak <= 2


def test_host_semaphores_independent_across_hosts():
    sems = HostSemaphores(per_host=1)
    barrier = threading.Barrier(2, timeout=1.0)

    # Two hosts, one slot each — both holders should reach the barrier at the
    # same time, proving the locks are per-host and not global.
    def worker(host):
        with sems.slot(host) as ok:
            assert ok
            barrier.wait()

    a = threading.Thread(target=worker, args=("h1",))
    b = threading.Thread(target=worker, args=("h2",))
    a.start()
    b.start()
    a.join(timeout=2)
    b.join(timeout=2)
    assert not a.is_alive() and not b.is_alive()


def test_host_semaphores_respect_stop_event():
    sems = HostSemaphores(per_host=1)
    stop = threading.Event()

    # Hold the only slot for "h1" until we release it.
    holder_done = threading.Event()
    holder_release = threading.Event()

    def hold():
        with sems.slot("h1") as ok:
            assert ok
            holder_done.set()
            holder_release.wait()

    threading.Thread(target=hold, daemon=True).start()
    holder_done.wait(1.0)

    def stop_soon():
        time.sleep(0.05)
        stop.set()

    threading.Thread(target=stop_soon, daemon=True).start()

    start = time.monotonic()
    with sems.slot("h1", stop_event=stop) as ok:
        assert ok is False
    elapsed = time.monotonic() - start
    assert elapsed < 0.5
    holder_release.set()
