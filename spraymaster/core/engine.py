import concurrent.futures
import logging
import threading
import time
from collections.abc import Iterable, Iterator
from typing import Callable, Optional

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from spraymaster.core.output import OutputManager
from spraymaster.core.ratelimit import HostSemaphores, TokenBucket
from spraymaster.protocols import PROTOCOL_REGISTRY, PROTOCOL_REQUIRES

# Engine event types — stable contract for TUI / Web observers.
EVENT_ATTACK_START = "attack_start"
EVENT_ATTEMPT = "attempt"
EVENT_SUCCESS = "success"
EVENT_ERROR = "error"
EVENT_ATTACK_DONE = "attack_done"

EventCallback = Callable[[dict], None]


class AttackEngine:
    def __init__(
        self,
        args,
        targets,
        users,
        passwords,
        console,
        on_event: Optional[EventCallback] = None,
    ):
        self.args = args
        self.targets = targets
        self.users = users
        self.passwords = passwords
        self.console = console
        self.logger = logging.getLogger("SprayMaster")
        self.results = []
        self._results_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._skipped = set()
        self._skip_lock = threading.Lock()
        self.start_time = None
        self.output_manager = None
        self._on_event = on_event

        max_rate = float(getattr(args, "max_rate", 0) or 0)
        self._bucket: TokenBucket | None = (
            TokenBucket(max_rate) if max_rate > 0 else None
        )
        per_host = int(getattr(args, "per_host_rate", 0) or 0)
        self._host_sems: HostSemaphores | None = (
            HostSemaphores(per_host) if per_host > 0 else None
        )

    def request_stop(self) -> None:
        """External stop signal — observers can halt an in-flight attack."""
        self._stop_event.set()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def _emit(self, event_type: str, **payload) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event({"type": event_type, **payload})
        except Exception:
            self.logger.debug("on_event observer raised; ignoring", exc_info=True)

    # ------------------------------------------------------------------
    def _build_tasks(self):
        if getattr(self.args, "combo", None):
            return [
                (t, u, p)
                for t in self.targets
                for u, p in zip(self.users, self.passwords)
            ]
        if self.args.spray:
            return [
                (t, u, p)
                for p in self.passwords
                for t in self.targets
                for u in self.users
            ]
        return [
            (t, u, p)
            for t in self.targets
            for u in self.users
            for p in self.passwords
        ]

    def _resolve_login_func(self):
        login_func = PROTOCOL_REGISTRY.get(self.args.protocol)
        if not login_func:
            dep = PROTOCOL_REQUIRES.get(self.args.protocol, "unknown")
            self.logger.error(
                f"Protocol [bold]{self.args.protocol}[/bold] is not available. "
                f"Install the required dependency: [cyan]pip install {dep}[/cyan]"
            )
        return login_func

    # ------------------------------------------------------------------
    def _execute_attack(self, login_func, tasks: Iterable):
        total = len(tasks) if hasattr(tasks, "__len__") else None
        # In-flight cap: keep the executor saturated but never queue the whole
        # task list up front. Critical for million-task wordlists.
        threads = max(1, int(self.args.threads))
        in_flight_cap = max(threads * 4, 32)

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, style="cyan", complete_style="green"),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        ) as progress:
            ptask = progress.add_task(
                f"  [bold cyan]{self.args.protocol.upper()}[/bold cyan]",
                total=total,
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                self._drive_executor(
                    executor, login_func, iter(tasks), progress, ptask, in_flight_cap
                )

    def _drive_executor(
        self,
        executor: concurrent.futures.ThreadPoolExecutor,
        login_func,
        task_iter: Iterator,
        progress,
        ptask,
        in_flight_cap: int,
    ) -> None:
        pending: set[concurrent.futures.Future] = set()
        exhausted = False

        def submit_one() -> bool:
            nonlocal exhausted
            try:
                task = next(task_iter)
            except StopIteration:
                exhausted = True
                return False
            fut = executor.submit(self._worker, login_func, *task, progress, ptask)
            pending.add(fut)
            return True

        # Prime the pipeline.
        while len(pending) < in_flight_cap and not self._stop_event.is_set():
            if not submit_one():
                break

        while pending:
            done, pending = concurrent.futures.wait(
                pending,
                timeout=0.25,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if self._stop_event.is_set():
                for f in pending:
                    f.cancel()
                pending.clear()
                break
            for _ in done:
                if exhausted or self._stop_event.is_set():
                    continue
                submit_one()

    # ------------------------------------------------------------------
    def run(self):
        login_func = self._resolve_login_func()
        if not login_func:
            return

        self.start_time = time.time()
        tasks = self._build_tasks()

        if getattr(self.args, "output", None):
            self.output_manager = OutputManager(
                self.args.output,
                getattr(self.args, "output_format", "text"),
            )

        self._emit(
            EVENT_ATTACK_START,
            protocol=self.args.protocol,
            total=len(tasks),
            targets=len(self.targets),
            users=len(self.users),
            passwords=len(self.passwords),
            threads=self.args.threads,
            spray=bool(self.args.spray),
            combo=bool(getattr(self.args, "combo", None)),
            stop_on_success=getattr(self.args, "stop_on_success", "none"),
        )

        self._print_header(len(tasks))
        try:
            self._execute_attack(login_func, tasks)
        finally:
            self._generate_report()

            duration = time.time() - self.start_time
            successes = [r for r in self.results if r["status"] == "success"]
            errors = [r for r in self.results if r["status"] == "error"]
            self._emit(
                EVENT_ATTACK_DONE,
                duration=duration,
                total=len(self.results),
                successes=len(successes),
                errors=len(errors),
                findings=successes,
                cancelled=self._stop_event.is_set(),
            )

            if self.output_manager:
                self.output_manager.close()

    # ------------------------------------------------------------------
    @staticmethod
    def _compute_skip_key(stop_mode, user, target):
        if stop_mode == "user":
            return user
        if stop_mode == "host":
            return (user, target)
        return None

    def _is_skipped(self, skip_key):
        if skip_key is None:
            return False
        with self._skip_lock:
            return skip_key in self._skipped

    def _interruptible_sleep(self, duration: float) -> bool:
        """Sleep up to ``duration`` seconds, returning False if stopped."""
        if duration <= 0:
            return not self._stop_event.is_set()
        deadline = time.monotonic() + duration
        chunk = 0.1
        while True:
            if self._stop_event.is_set():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return True
            time.sleep(min(chunk, remaining))

    def _attempt_with_retries(self, login_func, target, user, password):
        retries = max(1, int(getattr(self.args, "retries", 3) or 1))
        result = None
        for attempt in range(retries):
            if self._stop_event.is_set():
                break
            result = login_func(target, user, password, self.args)
            if result["status"] != "error":
                return result
            if attempt < retries - 1:
                # Exponential backoff capped, but interruptible.
                backoff = min(5.0, 0.5 * (2**attempt))
                if not self._interruptible_sleep(backoff):
                    break
        return result

    def _record_success(self, result, stop_mode, skip_key):
        host_port = f"{result['host']}:{result['port']}"
        creds = f"[yellow]{result['user']}[/yellow]:[green]{result['pass']}[/green]"
        self.logger.info(
            f"[bold green]  ✓  SUCCESS[/bold green]  {host_port}  {creds}"
        )
        if stop_mode == "global":
            self._stop_event.set()
        elif skip_key is not None:
            with self._skip_lock:
                self._skipped.add(skip_key)
        if self.output_manager:
            self.output_manager.write(result)
        self._emit(EVENT_SUCCESS, **result)

    def _log_non_success(self, result):
        host_port = f"{result['host']}:{result['port']}"
        if result["status"] == "error":
            creds = f"[yellow]{result['user']}[/yellow]:[green]{result['pass']}[/green]"
            self.logger.debug(
                f"[red]  ✗  ERROR  [/red]  {host_port}  {creds}  "
                f"[dim]→ {result.get('error', '')}[/dim]"
            )
        else:
            self.logger.debug(
                f"[dim]  ·  FAIL    {host_port}  {result['user']}:{result['pass']}[/dim]"
            )

    def _worker(self, login_func, target, user, password, progress, task_id):
        if self._stop_event.is_set():
            progress.update(task_id, advance=1)
            return

        stop_mode = getattr(self.args, "stop_on_success", "none")
        skip_key = self._compute_skip_key(stop_mode, user, target)

        if self._is_skipped(skip_key):
            progress.update(task_id, advance=1)
            return

        # Global RPS pacing first — token bucket honours stop.
        if self._bucket is not None:
            if not self._bucket.acquire(self._stop_event):
                progress.update(task_id, advance=1)
                return

        # Per-host concurrency cap.
        if self._host_sems is not None:
            with self._host_sems.slot(target, self._stop_event) as ok:
                if not ok:
                    progress.update(task_id, advance=1)
                    return
                self._do_attempt(login_func, target, user, password, stop_mode, skip_key)
        else:
            self._do_attempt(login_func, target, user, password, stop_mode, skip_key)

        progress.update(task_id, advance=1)

    def _do_attempt(self, login_func, target, user, password, stop_mode, skip_key) -> None:
        delay = float(getattr(self.args, "delay", 0) or 0)
        if delay > 0 and not self._interruptible_sleep(delay):
            return

        result = self._attempt_with_retries(login_func, target, user, password)
        if result is None:
            # Stopped before the first attempt could run.
            return

        with self._results_lock:
            self.results.append(result)

        if result["status"] == "success":
            self._record_success(result, stop_mode, skip_key)
        else:
            self._log_non_success(result)
            if result["status"] == "error":
                self._emit(EVENT_ERROR, **result)

        self._emit(
            EVENT_ATTEMPT,
            status=result["status"],
            host=result["host"],
            port=result["port"],
            user=result["user"],
            **{"pass": result["pass"]},
            protocol=result["protocol"],
        )

    # ------------------------------------------------------------------
    def _print_header(self, total: int):
        self.console.rule("[bold cyan]Attack Configuration[/bold cyan]")
        rows = [
            ("Protocol", f"[cyan]{self.args.protocol.upper()}[/cyan]"),
            (
                "Mode",
                (
                    "[yellow]Spray[/yellow]"
                    if self.args.spray
                    else "[white]Brute-force[/white]"
                ),
            ),
            ("Targets", str(len(self.targets))),
            ("Users", f"{len(self.users):,}"),
            ("Passwords", f"{len(self.passwords):,}"),
            ("Threads", str(self.args.threads)),
            ("Total tasks", f"[bold]{total:,}[/bold]"),
        ]
        if self.args.delay > 0:
            rows.append(("Delay", f"{self.args.delay}s"))
        if self._bucket is not None:
            rows.append(("Max RPS", f"{self._bucket.rate:g}"))
        if self._host_sems is not None:
            rows.append(("Per-host cap", str(self._host_sems.per_host)))
        if getattr(self.args, "proxy", None):
            rows.append(("Proxy", self.args.proxy))
        if getattr(self.args, "output", None):
            rows.append(
                (
                    "Output",
                    f"{self.args.output} ({getattr(self.args, 'output_format', 'text')})",
                )
            )
        stop = getattr(self.args, "stop_on_success", "none")
        if stop != "none":
            rows.append(("Stop-on-success", f"[yellow]{stop}[/yellow]"))

        for label, value in rows:
            self.console.print(f"  [dim]{label:<16}[/dim] {value}")
        self.console.rule()

    # ------------------------------------------------------------------
    def _generate_report(self):
        duration = time.time() - self.start_time
        successes = [r for r in self.results if r["status"] == "success"]
        errors = [r for r in self.results if r["status"] == "error"]
        total = len(self.results)
        speed = total / duration if duration > 0 else 0

        self.console.rule("[bold cyan]Results[/bold cyan]")

        table = Table(
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            padding=(0, 1),
        )
        table.add_column("Metric", style="dim", width=20)
        table.add_column("Value", style="white")

        table.add_row("Attempts", f"{total:,}")
        table.add_row(
            "Valid credentials",
            (
                f"[bold green]{len(successes)}[/bold green]"
                if successes
                else f"[dim]{len(successes)}[/dim]"
            ),
        )
        table.add_row("Errors", f"[red]{len(errors)}[/red]" if errors else "0")
        table.add_row("Duration", f"{duration:.2f}s")
        table.add_row("Speed", f"{speed:.1f} req/s")
        if self._stop_event.is_set():
            table.add_row("Status", "[yellow]cancelled[/yellow]")
        if getattr(self.args, "output", None) and successes:
            table.add_row("Saved to", self.args.output)

        self.console.print(table)

        if successes:
            self.console.print()
            self.console.rule("[bold green]Valid Credentials Found[/bold green]")
            for s in successes:
                self.console.print(
                    f"  [bold green]✓[/bold green]  "
                    f"[cyan]{s['host']}:{s['port']}[/cyan]  "
                    f"[yellow]{s['user']}[/yellow]:[green]{s['pass']}[/green]"
                )
            self.console.rule()
        else:
            self.console.print("\n  [dim]No valid credentials found.[/dim]\n")
