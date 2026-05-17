"""SprayMaster TUI — Textual-based interactive front-end.

Boot it with: ``spraymaster-tui``  (or ``python -m spraymaster.tui``)

Architecture:
  - ConfigScreen  collects the attack parameters
  - RunScreen     drives an EngineRunner, displays live progress + findings
  - HistoryScreen reads runs/findings from the SQLite history store

All engine events arrive on a worker thread; we marshal back to the UI thread
via ``app.call_from_thread`` so widget updates are safe.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    ProgressBar,
    Select,
    Static,
    Switch,
)

from spraymaster import __version__
from spraymaster.core.utils import load_combo_list, load_list
from spraymaster.protocols import PROTOCOL_REGISTRY
from spraymaster.storage.history import History
from spraymaster.tui.runner import EngineRunner, build_args

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _read_or_split(value: str) -> list[str]:
    """If ``value`` is an existing path, read lines from it; else split on commas."""
    if not value:
        return []
    p = Path(value).expanduser()
    if p.exists() and p.is_file():
        return load_list(str(p))
    return [v.strip() for v in value.split(",") if v.strip()]


def _fmt_ts(epoch: float | None) -> str:
    if not epoch:
        return "—"
    return _dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# Config screen
# --------------------------------------------------------------------------- #

class ConfigScreen(Screen):
    BINDINGS = [
        Binding("ctrl+r", "start", "Run"),
        Binding("ctrl+h", "history", "History"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        protocols = sorted(PROTOCOL_REGISTRY.keys()) or ["ftp"]
        with VerticalScroll(id="config-form"):
            yield Static(
                f"[b cyan]SprayMaster TUI[/]  [dim]v{__version__}[/]  "
                "[dim]— configure your attack[/]",
                id="title",
            )
            yield Label("Protocol")
            yield Select(
                [(p, p) for p in protocols],
                value=("ssh" if "ssh" in protocols else protocols[0]),
                id="protocol",
            )

            yield Label("Targets  [dim](host, host, …  OR  /path/to/targets.txt)[/]")
            yield Input(placeholder="10.0.0.1, 10.0.0.2", id="targets")

            yield Label("Users  [dim](alice, bob  OR  /path/to/users.txt)[/]")
            yield Input(placeholder="admin, root, guest", id="users")

            yield Label("Passwords  [dim](pw1, pw2  OR  /path/to/pass.txt)[/]")
            yield Input(placeholder="Summer2024!, password123", id="passwords")

            yield Label("Combo file  [dim](optional — user:pass per line; overrides users/passwords)[/]")
            yield Input(placeholder="/path/to/combos.txt", id="combo")

            with Horizontal(classes="row"):
                with Vertical(classes="col"):
                    yield Label("Threads")
                    yield Input(value="16", id="threads")
                with Vertical(classes="col"):
                    yield Label("Timeout (s)")
                    yield Input(value="10", id="timeout")
                with Vertical(classes="col"):
                    yield Label("Retries")
                    yield Input(value="3", id="retries")
                with Vertical(classes="col"):
                    yield Label("Port  [dim](blank=default)[/]")
                    yield Input(placeholder="22", id="port")

            with Horizontal(classes="row"):
                with Vertical(classes="col"):
                    yield Label("Stop on success")
                    yield Select(
                        [("none", "none"), ("user", "user"), ("host", "host"), ("global", "global")],
                        value="none",
                        id="stop_on_success",
                    )
                with Vertical(classes="col"):
                    yield Label("Spray mode")
                    yield Switch(value=False, id="spray")
                with Vertical(classes="col"):
                    yield Label("SSL/TLS")
                    yield Switch(value=False, id="ssl")

            with Horizontal(id="actions"):
                yield Button("Run attack [Ctrl+R]", variant="success", id="run-btn")
                yield Button("History [Ctrl+H]", variant="primary", id="history-btn")
                yield Button("Quit [q]", variant="error", id="quit-btn")
        yield Footer()

    # ----- actions -----

    def action_start(self) -> None:
        self._launch_attack()

    def action_history(self) -> None:
        self.app.push_screen(HistoryScreen())

    def action_quit(self) -> None:
        self.app.exit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-btn":
            self._launch_attack()
        elif event.button.id == "history-btn":
            self.app.push_screen(HistoryScreen())
        elif event.button.id == "quit-btn":
            self.app.exit()

    # ----- internal -----

    def _value(self, widget_id: str) -> str:
        w = self.query_one(f"#{widget_id}")
        return getattr(w, "value", "") or ""

    def _launch_attack(self) -> None:
        protocol = self._value("protocol")
        targets = _read_or_split(self._value("targets"))
        combo = self._value("combo").strip() or None

        if combo:
            try:
                pairs = load_combo_list(combo)
            except FileNotFoundError:
                self.notify("Combo file not found", severity="error")
                return
            users = [u for u, _ in pairs]
            passwords = [p for _, p in pairs]
        else:
            users = _read_or_split(self._value("users"))
            passwords = _read_or_split(self._value("passwords"))

        if not targets:
            self.notify("At least one target required", severity="error")
            return
        if not users or not passwords:
            self.notify("Users and passwords required (or use a combo file)", severity="error")
            return

        port_raw = self._value("port").strip()
        form = {
            "protocol": protocol,
            "spray": bool(self.query_one("#spray", Switch).value),
            "ssl": bool(self.query_one("#ssl", Switch).value),
            "combo": combo,
            "threads": int(self._value("threads") or 16),
            "timeout": int(self._value("timeout") or 10),
            "retries": int(self._value("retries") or 3),
            "stop_on_success": self._value("stop_on_success") or "none",
            "port": int(port_raw) if port_raw else None,
        }

        self.app.push_screen(RunScreen(form, targets, users, passwords))


# --------------------------------------------------------------------------- #
# Run screen — live attack
# --------------------------------------------------------------------------- #

class RunScreen(Screen):
    BINDINGS = [
        Binding("s", "stop", "Stop"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, form: dict, targets: list[str], users: list[str], passwords: list[str]):
        super().__init__()
        self._form = form
        self._targets = targets
        self._users = users
        self._passwords = passwords
        self._runner: EngineRunner | None = None
        self._history = History()
        self._run_id: int | None = None
        self._completed = 0
        self._successes = 0
        self._errors = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="run-wrap"):
            yield Static(self._summary(), id="summary")
            yield ProgressBar(total=100, show_eta=True, id="bar")
            with Horizontal(id="counters"):
                yield Static("Successes: [b green]0[/]", id="cnt-success")
                yield Static("Errors: [b red]0[/]", id="cnt-error")
                yield Static("Attempts: [b]0[/]", id="cnt-attempts")
            yield Log(highlight=True, id="event-log")
            with Horizontal(id="run-actions"):
                yield Button("Stop [s]", variant="error", id="stop-btn")
                yield Button("Back [Esc]", variant="primary", id="back-btn")
        yield Footer()

    def on_mount(self) -> None:
        total_tasks = len(self._targets) * len(self._users) * len(self._passwords)
        self._run_id = self._history.start_run(
            protocol=self._form["protocol"],
            target_count=len(self._targets),
            user_count=len(self._users),
            password_count=len(self._passwords),
            config=self._form,
        )
        self.query_one("#bar", ProgressBar).update(total=total_tasks)

        args = build_args(self._form)
        self._runner = EngineRunner(
            args,
            self._targets,
            self._users,
            self._passwords,
            on_event=self._on_event,
            history=self._history,
            run_id=self._run_id,
        )
        self._runner.start()

    # Events arrive on the worker thread — bounce to the UI thread.
    def _on_event(self, event: dict) -> None:
        self.app.call_from_thread(self._handle_event, event)

    def _handle_event(self, event: dict) -> None:
        et = event.get("type")
        log = self.query_one("#event-log", Log)
        bar = self.query_one("#bar", ProgressBar)

        if et == "attempt":
            self._completed += 1
            bar.advance(1)
        elif et == "success":
            self._successes += 1
            log.write_line(
                f"✓ SUCCESS  {event['host']}:{event['port']}  "
                f"{event['user']}:{event['pass']}"
            )
        elif et == "error":
            self._errors += 1
            if self._errors <= 50:  # avoid log spam on totally-broken targets
                log.write_line(
                    f"✗ ERROR    {event['host']}:{event['port']}  "
                    f"{event['user']}  →  {event.get('error', '')[:80]}"
                )
        elif et == "attack_done":
            self._history.finish_run(
                self._run_id,
                status="done",
                total_attempts=event.get("total", self._completed),
                success_count=event.get("successes", self._successes),
                error_count=event.get("errors", self._errors),
            )
            log.write_line(
                f"\n[b cyan]Attack finished[/]  "
                f"{event['successes']} valid / {event['total']} attempts "
                f"in {event['duration']:.1f}s"
            )

        self.query_one("#cnt-success", Static).update(
            f"Successes: [b green]{self._successes}[/]"
        )
        self.query_one("#cnt-error", Static).update(
            f"Errors: [b red]{self._errors}[/]"
        )
        self.query_one("#cnt-attempts", Static).update(
            f"Attempts: [b]{self._completed}[/]"
        )

    def _summary(self) -> str:
        return (
            f"[b cyan]{self._form['protocol'].upper()}[/]  "
            f"targets=[b]{len(self._targets)}[/]  "
            f"users=[b]{len(self._users)}[/]  "
            f"pass=[b]{len(self._passwords)}[/]  "
            f"threads=[b]{self._form['threads']}[/]  "
            f"mode=[b]{'spray' if self._form.get('spray') else 'brute'}[/]"
        )

    def action_stop(self) -> None:
        if self._runner is not None:
            self._runner.stop()
            self.notify("Stop requested — finishing in-flight attempts...")

    def action_back(self) -> None:
        if self._runner is not None and self._runner.is_alive:
            self._runner.stop()
        if self._run_id is not None:
            self._history.finish_run(
                self._run_id,
                status="cancelled" if self._runner and self._runner.is_alive else "done",
                total_attempts=self._completed,
                success_count=self._successes,
                error_count=self._errors,
            )
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "stop-btn":
            self.action_stop()
        elif event.button.id == "back-btn":
            self.action_back()


# --------------------------------------------------------------------------- #
# History screen
# --------------------------------------------------------------------------- #

class HistoryScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back"), Binding("d", "delete", "Delete")]

    def __init__(self):
        super().__init__()
        self._history = History()

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="history-wrap"):
            yield Static("[b cyan]Attack history[/]", id="history-title")
            yield DataTable(id="runs-table", cursor_type="row")
            yield Static("", id="findings-title")
            yield DataTable(id="findings-table")
        yield Footer()

    def on_mount(self) -> None:
        runs = self.query_one("#runs-table", DataTable)
        runs.add_columns("ID", "Started", "Protocol", "Status", "Found", "Attempts", "Targets")
        for r in self._history.list_runs():
            runs.add_row(
                str(r.id),
                _fmt_ts(r.started_at),
                r.protocol,
                r.status,
                str(r.success_count),
                str(r.total_attempts or 0),
                str(r.target_count),
                key=str(r.id),
            )

        findings = self.query_one("#findings-table", DataTable)
        findings.add_columns("Host", "Port", "User", "Password", "Protocol", "Found at")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.control.id != "runs-table":
            return
        run_id = int(event.row_key.value)
        ftable = self.query_one("#findings-table", DataTable)
        ftable.clear()
        run = self._history.get_run(run_id)
        title = self.query_one("#findings-title", Static)
        title.update(f"[dim]Findings for run #{run_id}  ({run.protocol if run else '?'})[/]")
        for f in self._history.findings_for(run_id):
            ftable.add_row(
                f.host, str(f.port), f.username, f.password, f.protocol, _fmt_ts(f.found_at)
            )

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_delete(self) -> None:
        table = self.query_one("#runs-table", DataTable)
        if table.cursor_row is None:
            return
        try:
            row_key = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key
        except Exception:
            return
        if row_key is None or row_key.value is None:
            return
        self._history.delete_run(int(row_key.value))
        table.remove_row(row_key)


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

CSS = """
Screen { layout: vertical; }

#config-form { padding: 1 2; height: 1fr; }
#title { padding: 0 0 1 0; }
.row  { height: auto; padding: 1 0; }
.col  { width: 1fr; padding: 0 1; }
#actions { height: auto; padding: 1 0; }
#actions Button { margin-right: 2; }

#run-wrap { padding: 1 2; }
#counters Static { width: 1fr; padding: 0 1; }
#event-log { height: 1fr; border: tall $accent; margin-top: 1; }
#run-actions { height: auto; padding-top: 1; }
#run-actions Button { margin-right: 2; }

#history-wrap { padding: 1 2; height: 1fr; }
#runs-table { height: 50%; }
#findings-table { height: 50%; margin-top: 1; }
#findings-title { padding: 1 0 0 0; }
"""


class SprayMasterTUI(App):
    CSS = CSS
    TITLE = f"SprayMaster v{__version__}"
    SUB_TITLE = "Multi-protocol login auditor — TUI"

    def on_mount(self) -> None:
        self.push_screen(ConfigScreen())


def run() -> int:
    SprayMasterTUI().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
