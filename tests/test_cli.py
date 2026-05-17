import subprocess
import sys

import pytest

from spraymaster import __version__
from spraymaster.__main__ import _build_parser


def test_parser_accepts_minimal_brute_force_args():
    parser = _build_parser(["ftp", "ssh"])
    args = parser.parse_args(
        ["-t", "10.0.0.1", "-u", "admin", "-p", "hunter2", "--protocol", "ssh"]
    )

    assert args.target == "10.0.0.1"
    assert args.user == "admin"
    assert args.password == "hunter2"
    assert args.protocol == "ssh"
    assert args.spray is False
    assert args.threads == 16
    assert args.stop_on_success == "none"


def test_parser_accepts_spray_mode_with_wordlists():
    parser = _build_parser(["ssh"])
    args = parser.parse_args(
        [
            "-T", "targets.txt",
            "-U", "users.txt",
            "-P", "passes.txt",
            "--protocol", "ssh",
            "--spray",
            "--threads", "32",
            "--stop-on-success", "user",
        ]
    )

    assert args.spray is True
    assert args.threads == 32
    assert args.stop_on_success == "user"
    assert args.targetlist == "targets.txt"


def test_parser_rejects_unknown_protocol():
    parser = _build_parser(["ftp", "ssh"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--protocol", "nope", "-t", "h", "-u", "u", "-p", "p"])


def test_version_flag_exits_cleanly_via_subprocess():
    # Exercise the installed entry point semantics: python -m spraymaster --version
    result = subprocess.run(
        [sys.executable, "-m", "spraymaster", "--version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert __version__ in result.stdout


def test_list_protocols_flag_exits_zero():
    result = subprocess.run(
        [sys.executable, "-m", "spraymaster", "--list-protocols", "--no-banner"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "ssh" in result.stdout.lower() or "ftp" in result.stdout.lower()
