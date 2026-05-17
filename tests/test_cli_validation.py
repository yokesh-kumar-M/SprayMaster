import pytest

from spraymaster.__main__ import _build_parser


def _parser():
    return _build_parser(["ssh", "ftp"])


def test_threads_must_be_positive():
    with pytest.raises(SystemExit):
        _parser().parse_args(
            ["-t", "h", "-u", "u", "-p", "p", "--protocol", "ssh", "--threads", "0"]
        )


def test_threads_must_be_integer():
    with pytest.raises(SystemExit):
        _parser().parse_args(
            ["-t", "h", "-u", "u", "-p", "p", "--protocol", "ssh", "--threads", "abc"]
        )


def test_delay_rejects_negative():
    with pytest.raises(SystemExit):
        _parser().parse_args(
            ["-t", "h", "-u", "u", "-p", "p", "--protocol", "ssh", "--delay", "-1"]
        )


def test_max_rate_accepts_zero_for_unlimited():
    args = _parser().parse_args(
        ["-t", "h", "-u", "u", "-p", "p", "--protocol", "ssh", "--max-rate", "0"]
    )
    assert args.max_rate == 0.0


def test_max_rate_parses_fractional():
    args = _parser().parse_args(
        ["-t", "h", "-u", "u", "-p", "p", "--protocol", "ssh", "--max-rate", "12.5"]
    )
    assert args.max_rate == 12.5


def test_per_host_rate_must_be_positive():
    with pytest.raises(SystemExit):
        _parser().parse_args(
            ["-t", "h", "-u", "u", "-p", "p", "--protocol", "ssh", "--per-host-rate", "0"]
        )
