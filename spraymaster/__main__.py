from __future__ import annotations

import argparse
import logging
import signal
import sys
import warnings

# Force UTF-8 on stdout/stderr so Rich's Unicode glyphs (✓, ✗, →) don't crash
# under Windows cp1252 when output is piped or redirected. Must happen before
# we import Console.
for _stream in (sys.stdout, sys.stderr):
    reconfigure = getattr(_stream, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

from rich.console import Console
from rich.logging import RichHandler

warnings.filterwarnings("ignore", category=UserWarning, module="requests")
warnings.filterwarnings("ignore", message=".*urllib3.*")

from spraymaster import __version__
from spraymaster.core.engine import AttackEngine
from spraymaster.core.logging_utils import install_json_handler
from spraymaster.core.utils import load_combo_list, load_list
from spraymaster.protocols import PROTOCOL_REGISTRY, PROTOCOL_REQUIRES

_BANNER = r"""
 ____                       __  __           _
/ ___| _ __  _ __ __ _ _   _|  \/  | __ _ ___| |_ ___ _ __
\___ \| '_ \| '__/ _` | | | | |\/| |/ _` / __| __/ _ \ '__|
 ___) | |_) | | | (_| | |_| | |  | | (_| \__ \ ||  __/ |
|____/| .__/|_|  \__,_|\__, |_|  |_|\__,_|___/\__\___|_|
      |_|               |___/"""


def _print_banner(console: Console) -> None:
    console.print(f"[bold cyan]{_BANNER}[/bold cyan]")
    console.print(
        f"  [bold white]v{__version__}[/bold white]  "
        f"[dim]Network Login Auditor[/dim]  "
        f"[dim]|  For authorized penetration testing only[/dim]"
    )
    available = sorted(PROTOCOL_REGISTRY.keys())
    console.print(
        "\n  [dim]Loaded protocols:[/dim] "
        + "  ".join(f"[cyan]{p}[/cyan]" for p in available)
    )
    missing = sorted(k for k in PROTOCOL_REQUIRES if k not in PROTOCOL_REGISTRY)
    if missing:
        console.print(
            "  [dim]Unavailable (missing deps):[/dim] "
            + "  ".join(f"[red dim]{p}[/red dim]" for p in missing)
        )
    console.print()


def _print_protocols(console: Console) -> None:
    available = sorted(PROTOCOL_REGISTRY.keys())
    missing = sorted(k for k in PROTOCOL_REQUIRES if k not in PROTOCOL_REGISTRY)
    console.print("[bold cyan]Available protocols:[/bold cyan]")
    for p in available:
        console.print(f"  [green]✓[/green] {p}")
    if missing:
        console.print("\n[bold yellow]Unavailable (install extras):[/bold yellow]")
        for p in missing:
            dep = PROTOCOL_REQUIRES.get(p, "unknown")
            console.print(f"  [red]✗[/red] {p}   [dim]→ pip install {dep}[/dim]")
        console.print(
            "\n[dim]Or install all extras at once:[/dim] "
            "[cyan]pip install 'spraymaster[all]'[/cyan]"
        )


def _positive_int(value: str) -> int:
    try:
        ivalue = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from exc
    if ivalue < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1 (got {ivalue})")
    return ivalue


def _non_negative_float(value: str) -> float:
    try:
        fvalue = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a number, got {value!r}") from exc
    if fvalue < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0 (got {fvalue})")
    return fvalue


def _build_parser(available_protocols):
    parser = argparse.ArgumentParser(
        prog="spraymaster",
        description=f"SprayMaster v{__version__} — Network Login Auditor",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
    )

    parser.add_argument(
        "-V", "--version", action="version", version=f"SprayMaster {__version__}"
    )
    parser.add_argument(
        "--list-protocols",
        dest="list_protocols",
        action="store_true",
        help="List supported protocols and exit",
    )
    parser.add_argument(
        "--no-banner",
        dest="no_banner",
        action="store_true",
        help="Suppress the startup banner",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-essential output (only show successes and errors)",
    )
    parser.add_argument(
        "--log-json",
        dest="log_json",
        metavar="FILE",
        help="Also emit structured JSON-line logs to FILE (use '-' for stderr)",
    )

    t = parser.add_argument_group("Targets")
    t.add_argument(
        "-t", "--target", metavar="HOST", help="Single target host or IP address"
    )
    t.add_argument(
        "-T", "--targetlist", metavar="FILE", help="File containing one target per line"
    )

    c = parser.add_argument_group("Credentials")
    c.add_argument("-u", "--user", metavar="USER", help="Single username")
    c.add_argument("-U", "--userlist", metavar="FILE", help="Username wordlist")
    c.add_argument("-p", "--password", metavar="PASS", help="Single password")
    c.add_argument("-P", "--passlist", metavar="FILE", help="Password wordlist")
    c.add_argument(
        "-C", "--combo", metavar="FILE", help="Combo file — one user:pass pair per line"
    )

    a = parser.add_argument_group("Attack")
    a.add_argument(
        "--protocol",
        choices=available_protocols,
        default="ftp",
        metavar="PROTO",
        help="Target protocol. Available: " + ", ".join(available_protocols),
    )
    a.add_argument(
        "--spray",
        action="store_true",
        help="Password spray mode — one password tried against all users\n"
        "before moving to the next (avoids lockouts)",
    )
    a.add_argument(
        "--port",
        type=_positive_int,
        metavar="PORT",
        help="Custom port (overrides protocol default)",
    )
    a.add_argument(
        "--ssl",
        action="store_true",
        help="Enable SSL/TLS for protocols that support it",
    )
    a.add_argument(
        "--stop-on-success",
        dest="stop_on_success",
        choices=["none", "user", "host", "global"],
        default="none",
        metavar="MODE",
        help=(
            "Stop strategy when a valid credential is found:\n"
            "  none    — keep trying everything (default)\n"
            "  user    — skip remaining passwords for that user\n"
            "  host    — skip remaining passwords for that user on that host\n"
            "  global  — stop the entire attack immediately"
        ),
    )

    perf = parser.add_argument_group("Performance")
    perf.add_argument(
        "--threads",
        type=_positive_int,
        default=16,
        metavar="N",
        help="Concurrent threads (default: 16)",
    )
    perf.add_argument(
        "--delay",
        type=_non_negative_float,
        default=0.0,
        metavar="SECS",
        help="Delay between each attempt in seconds (default: 0)",
    )
    perf.add_argument(
        "--timeout",
        type=_positive_int,
        default=10,
        metavar="SECS",
        help="Connection timeout in seconds (default: 10)",
    )
    perf.add_argument(
        "--retries",
        type=_positive_int,
        default=3,
        metavar="N",
        help="Retry count on connection error (default: 3)",
    )
    perf.add_argument(
        "--max-rate",
        dest="max_rate",
        type=_non_negative_float,
        default=0.0,
        metavar="RPS",
        help="Global rate cap in requests per second (0 = unlimited)",
    )
    perf.add_argument(
        "--per-host-rate",
        dest="per_host_rate",
        type=_positive_int,
        metavar="N",
        help="Maximum concurrent attempts against any single host",
    )

    http = parser.add_argument_group("HTTP Options  (--protocol http / https)")
    http.add_argument(
        "--http-path",
        dest="http_path",
        default="/",
        metavar="PATH",
        help="URL path to attack (default: /)",
    )
    http.add_argument(
        "--http-method",
        dest="http_method",
        choices=["GET", "POST"],
        default="POST",
        help="HTTP method for form-based auth (default: POST)",
    )
    http.add_argument(
        "--http-form-data",
        dest="http_form_data",
        metavar="DATA",
        help=(
            "Form body — use ^USER^ and ^PASS^ as placeholders\n"
            "Example: 'username=^USER^&password=^PASS^'"
        ),
    )
    http.add_argument(
        "--http-fail-string",
        dest="http_fail_string",
        metavar="STR",
        help="Substring in response body that indicates a FAILED login",
    )
    http.add_argument(
        "--http-success-string",
        dest="http_success_string",
        metavar="STR",
        help="Substring in response body that indicates a SUCCESSFUL login",
    )
    http.add_argument(
        "--http-headers",
        dest="http_headers",
        metavar="JSON",
        help="Extra request headers as a JSON object\n"
        'Example: \'{"X-Forwarded-For": "1.2.3.4"}\'',
    )
    http.add_argument(
        "--http-cookies",
        dest="http_cookies",
        metavar="STR",
        help='Cookie header value sent with every request, e.g. "sid=abc; csrf=def"',
    )
    http.add_argument(
        "--user-agent",
        dest="user_agent",
        metavar="UA",
        help="Override the User-Agent header on HTTP requests",
    )
    http.add_argument(
        "--verify-ssl",
        dest="verify_ssl",
        action="store_true",
        help=(
            "Enforce TLS certificate verification on HTTPS requests.\n"
            "Default OFF — pen-test targets often present self-signed certs."
        ),
    )

    net = parser.add_argument_group("Network")
    net.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/SOCKS proxy for HTTP/HTTPS protocols\n"
        "Example: socks5://127.0.0.1:1080",
    )
    net.add_argument(
        "--smb-domain",
        dest="smb_domain",
        metavar="DOMAIN",
        help="Windows domain for SMB authentication",
    )

    out = parser.add_argument_group("Output")
    out.add_argument(
        "-o", "--output", metavar="FILE", help="Write found credentials to file"
    )
    out.add_argument(
        "--output-format",
        dest="output_format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output file format — text, json (JSONL), or csv (default: text)",
    )
    out.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all attempts including failures",
    )

    return parser


def _load_targets(args):
    if args.targetlist:
        return load_list(args.targetlist)
    if args.target:
        return [args.target]
    return []


def _load_single_or_file(file_path, single_value):
    if file_path:
        return load_list(file_path)
    if single_value:
        return [single_value]
    return []


def _load_combo(args, logger):
    try:
        pairs = load_combo_list(args.combo)
    except FileNotFoundError:
        logger.error(f"Combo file not found: [bold]{args.combo}[/bold]")
        sys.exit(2)
    if not pairs:
        logger.error("Combo file is empty or has no valid user:pass lines.")
        sys.exit(2)
    users = [u for u, _ in pairs]
    passwords = [p for _, p in pairs]
    return users, passwords


def _load_credentials(args, logger):
    if args.combo:
        return _load_combo(args, logger)
    try:
        users = _load_single_or_file(args.userlist, args.user)
        passwords = _load_single_or_file(args.passlist, args.password)
    except FileNotFoundError as e:
        logger.error(f"Wordlist not found: [bold]{e.filename}[/bold]")
        sys.exit(2)
    return users, passwords


def _validate_inputs(target_list, user_list, pass_list, has_combo):
    errors = []
    if not target_list:
        errors.append(
            "Specify at least one target:  [cyan]-t HOST[/cyan]  or  [cyan]-T FILE[/cyan]"
        )
    if not user_list:
        errors.append(
            "Specify users:  [cyan]-u USER[/cyan]  or  [cyan]-U FILE[/cyan]  or  [cyan]-C COMBO[/cyan]"
        )
    if not pass_list and not has_combo:
        errors.append(
            "Specify passwords:  [cyan]-p PASS[/cyan]  or  [cyan]-P FILE[/cyan]  or  [cyan]-C COMBO[/cyan]"
        )
    return errors


def _configure_logging(console, verbose, quiet, json_log: str | None = None):
    if quiet:
        log_level = "WARNING"
    elif verbose:
        log_level = "DEBUG"
    else:
        log_level = "INFO"
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console, rich_tracebacks=True, show_path=False, markup=True
            )
        ],
    )
    if json_log:
        install_json_handler(json_log)
    return logging.getLogger("SprayMaster")


def _install_sigint_handler(console: Console, engine_ref: list) -> None:
    """SIGINT: request graceful stop the first time, hard-exit on a repeat."""

    state = {"received": 0}

    def _handler(signum, frame):
        state["received"] += 1
        if state["received"] == 1 and engine_ref and engine_ref[0] is not None:
            console.print(
                "\n[bold yellow]  ⚠  Interrupt received — stopping gracefully "
                "(Ctrl+C again to force).[/bold yellow]"
            )
            engine_ref[0].request_stop()
            return
        console.print("\n[bold red]  ⚠  Force-exit.[/bold red]")
        sys.exit(130)

    signal.signal(signal.SIGINT, _handler)


def main() -> int:
    # When stdout is piped to a tool that closes the pipe early (`| head`),
    # Rich's Windows renderer raises OSError(22). Force the modern renderer
    # when not attached to a real terminal so output is plain UTF-8 text.
    is_tty = sys.stdout.isatty()
    console = Console(legacy_windows=False if not is_tty else None, force_terminal=is_tty or None)

    engine_ref: list = [None]
    _install_sigint_handler(console, engine_ref)

    available = sorted(PROTOCOL_REGISTRY.keys())
    parser = _build_parser(available)
    args = parser.parse_args()

    if args.list_protocols:
        _print_protocols(console)
        return 0

    if not args.no_banner and not args.quiet:
        _print_banner(console)

    logger = _configure_logging(
        console, args.verbose, args.quiet, getattr(args, "log_json", None)
    )

    target_list = _load_targets(args)
    user_list, pass_list = _load_credentials(args, logger)

    errors = _validate_inputs(target_list, user_list, pass_list, bool(args.combo))
    if errors:
        for msg in errors:
            logger.error(msg)
        return 2

    engine = AttackEngine(args, target_list, user_list, pass_list, console)
    engine_ref[0] = engine
    engine.run()
    successes = [r for r in engine.results if r["status"] == "success"]
    if engine.stopped and not successes:
        return 130
    return 0 if successes else 1


def _entrypoint() -> int:
    try:
        return main()
    except BrokenPipeError:
        # Downstream consumer (e.g. `| head`) closed the pipe. Exit cleanly.
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(_entrypoint())
