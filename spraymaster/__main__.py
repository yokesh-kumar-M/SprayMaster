import argparse
import logging
import os
import sys
import warnings

from rich.console import Console
from rich.logging import RichHandler

# Ensure this package directory is on the path regardless of how the script is invoked
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

warnings.filterwarnings("ignore", category=UserWarning, module="requests")
warnings.filterwarnings("ignore", message=".*urllib3.*")

from protocols import PROTOCOL_REGISTRY, PROTOCOL_REQUIRES  # noqa: E402
from core.engine import AttackEngine  # noqa: E402
from core.utils import load_list, load_combo_list  # noqa: E402

VERSION = "2.0.0"

_BANNER = r"""
 ____                       __  __           _
/ ___| _ __  _ __ __ _ _   _|  \/  | __ _ ___| |_ ___ _ __
\___ \| '_ \| '__/ _` | | | | |\/| |/ _` / __| __/ _ \ '__|
 ___) | |_) | | | (_| | |_| | |  | | (_| \__ \ ||  __/ |
|____/| .__/|_|  \__,_|\__, |_|  |_|\__,_|___/\__\___|_|
      |_|               |___/"""


def _print_banner(console: Console):
    console.print(f"[bold cyan]{_BANNER}[/bold cyan]")
    console.print(
        f"  [bold white]v{VERSION}[/bold white]  "
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


def _build_parser(available_protocols):
    parser = argparse.ArgumentParser(
        prog="spraymaster",
        description="SprayMaster v{} — Network Login Auditor".format(VERSION),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
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
        type=int,
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
        type=int,
        default=16,
        metavar="N",
        help="Concurrent threads (default: 16)",
    )
    perf.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SECS",
        help="Delay between each attempt in seconds (default: 0)",
    )
    perf.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECS",
        help="Connection timeout in seconds (default: 10)",
    )
    perf.add_argument(
        "--retries",
        type=int,
        default=3,
        metavar="N",
        help="Retry count on connection error (default: 3)",
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
        sys.exit(1)
    if not pairs:
        logger.error("Combo file is empty or has no valid user:pass lines.")
        sys.exit(1)
    users = [u for u, _ in pairs]
    passwords = [p for _, p in pairs]
    return users, passwords


def _load_credentials(args, logger):
    if args.combo:
        return _load_combo(args, logger)
    users = _load_single_or_file(args.userlist, args.user)
    passwords = _load_single_or_file(args.passlist, args.password)
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


def _configure_logging(console, verbose):
    log_level = "DEBUG" if verbose else "INFO"
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
    return logging.getLogger("SprayMaster")


def main():
    console = Console()
    available = sorted(PROTOCOL_REGISTRY.keys())

    _print_banner(console)

    parser = _build_parser(available)
    args = parser.parse_args()

    logger = _configure_logging(console, args.verbose)

    target_list = _load_targets(args)
    user_list, pass_list = _load_credentials(args, logger)

    errors = _validate_inputs(target_list, user_list, pass_list, bool(args.combo))
    if errors:
        for msg in errors:
            logger.error(msg)
        sys.exit(1)

    engine = AttackEngine(args, target_list, user_list, pass_list, console)
    engine.run()


if __name__ == "__main__":
    main()
