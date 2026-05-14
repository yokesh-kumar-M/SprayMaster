import concurrent.futures
import logging
import time
import threading

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)
from rich.table import Table

from protocols import PROTOCOL_REGISTRY, PROTOCOL_REQUIRES
from core.output import OutputManager


class AttackEngine:
    def __init__(self, args, targets, users, passwords, console):
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

    # ------------------------------------------------------------------
    def run(self):
        login_func = PROTOCOL_REGISTRY.get(self.args.protocol)
        if not login_func:
            dep = PROTOCOL_REQUIRES.get(self.args.protocol, "unknown")
            self.logger.error(
                f"Protocol [bold]{self.args.protocol}[/bold] is not available. "
                f"Install the required dependency: [cyan]pip install {dep}[/cyan]"
            )
            return

        self.start_time = time.time()

        if getattr(self.args, "combo", None):
            tasks = [
                (t, u, p)
                for t in self.targets
                for u, p in zip(self.users, self.passwords)
            ]
        elif self.args.spray:
            tasks = [
                (t, u, p)
                for p in self.passwords
                for t in self.targets
                for u in self.users
            ]
        else:
            tasks = [
                (t, u, p)
                for t in self.targets
                for u in self.users
                for p in self.passwords
            ]

        total = len(tasks)

        if getattr(self.args, "output", None):
            self.output_manager = OutputManager(
                self.args.output,
                getattr(self.args, "output_format", "text"),
            )

        self._print_header(total)

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
                f"  [bold cyan]{self.args.protocol.upper()}[/bold cyan]", total=total
            )

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.args.threads
            ) as executor:
                futures = []
                for task in tasks:
                    if self._stop_event.is_set():
                        break
                    fut = executor.submit(
                        self._worker, login_func, *task, progress, ptask
                    )
                    futures.append(fut)

                for fut in concurrent.futures.as_completed(futures):
                    if self._stop_event.is_set():
                        for pending in futures:
                            pending.cancel()
                        break

        self._generate_report()
        if self.output_manager:
            self.output_manager.close()

    # ------------------------------------------------------------------
    def _worker(self, login_func, target, user, password, progress, task_id):
        if self._stop_event.is_set():
            progress.update(task_id, advance=1)
            return

        stop_mode = getattr(self.args, "stop_on_success", "none")
        skip_key = None
        if stop_mode == "user":
            skip_key = user
        elif stop_mode == "host":
            skip_key = (user, target)

        if skip_key is not None:
            with self._skip_lock:
                if skip_key in self._skipped:
                    progress.update(task_id, advance=1)
                    return

        if self.args.delay > 0:
            time.sleep(self.args.delay)

        retries = getattr(self.args, "retries", 3)
        result = None
        for attempt in range(max(1, retries)):
            result = login_func(target, user, password, self.args)
            if result["status"] != "error":
                break
            if attempt < retries - 1:
                time.sleep(0.5 * (2**attempt))

        with self._results_lock:
            self.results.append(result)

        host_port = f"{result['host']}:{result['port']}"
        creds = f"[yellow]{result['user']}[/yellow]:[green]{result['pass']}[/green]"

        if result["status"] == "success":
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
        elif result["status"] == "error":
            self.logger.debug(
                f"[red]  ✗  ERROR  [/red]  {host_port}  {creds}  "
                f"[dim]→ {result.get('error', '')}[/dim]"
            )
        else:
            self.logger.debug(
                f"[dim]  ·  FAIL    {host_port}  {result['user']}:{result['pass']}[/dim]"
            )

        progress.update(task_id, advance=1)

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
