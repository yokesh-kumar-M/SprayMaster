from spraymaster.protocols import (
    PROTOCOL_DEFAULT_PORTS,
    PROTOCOL_REGISTRY,
    PROTOCOL_REQUIRES,
)


def test_always_available_protocols_are_registered():
    # These depend only on the stdlib and should always load.
    for proto in ["ftp", "ftps", "ssh", "telnet", "smtp", "smtps", "pop3", "pop3s", "imap", "imaps"]:
        assert proto in PROTOCOL_REGISTRY, f"{proto} should be in registry"


def test_default_ports_match_well_known_assignments():
    expected = {
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "http": 80,
        "https": 443,
        "imap": 143,
        "imaps": 993,
        "smb": 445,
        "mssql": 1433,
        "mysql": 3306,
        "postgres": 5432,
        "redis": 6379,
        "ldap": 389,
        "ldaps": 636,
    }
    for proto, port in expected.items():
        assert PROTOCOL_DEFAULT_PORTS[proto] == port


def test_optional_protocols_list_their_dependency():
    # Every optional protocol should have an install hint, even if not loaded.
    assert PROTOCOL_REQUIRES["smb"] == "impacket"
    assert PROTOCOL_REQUIRES["mysql"] == "pymysql"
    assert PROTOCOL_REQUIRES["postgres"] == "psycopg2-binary"


def test_every_registered_protocol_is_callable():
    for proto, fn in PROTOCOL_REGISTRY.items():
        assert callable(fn), f"{proto} handler must be callable"
