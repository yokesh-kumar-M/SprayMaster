PROTOCOL_REGISTRY = {}

PROTOCOL_DEFAULT_PORTS = {
    "ftp": 21,
    "ftps": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "smtps": 465,
    "http": 80,
    "https": 443,
    "pop3": 110,
    "pop3s": 995,
    "imap": 143,
    "imaps": 993,
    "smb": 445,
    "mssql": 1433,
    "mysql": 3306,
    "vnc": 5900,
    "redis": 6379,
    "postgres": 5432,
    "ldap": 389,
    "ldaps": 636,
    "snmp": 161,
}

PROTOCOL_REQUIRES = {
    "smb": "impacket",
    "mysql": "pymysql",
    "postgres": "psycopg2-binary",
    "mssql": "pymssql",
    "ldap": "ldap3",
    "ldaps": "ldap3",
    "redis": "redis",
    "vnc": "pycryptodome",
    "snmp": "pysnmp",
}


def _load():
    from . import ftp, ssh, telnet, smtp, pop3, imap

    PROTOCOL_REGISTRY.update(
        {
            "ftp": ftp.try_login,
            "ftps": ftp.try_login,
            "ssh": ssh.try_login,
            "telnet": telnet.try_login,
            "smtp": smtp.try_login,
            "smtps": smtp.try_login,
            "pop3": pop3.try_login,
            "pop3s": pop3.try_login,
            "imap": imap.try_login,
            "imaps": imap.try_login,
        }
    )

    _try(".http", ["http", "https"])
    _try(".smb", ["smb"])
    _try(".mysql", ["mysql"])
    _try(".postgres", ["postgres"])
    _try(".mssql", ["mssql"])
    _try(".ldap", ["ldap", "ldaps"])
    _try(".redis_proto", ["redis"])
    _try(".vnc", ["vnc"])
    _try(".snmp", ["snmp"])


def _try(relative_module, registry_keys):
    # Optional protocol — skip it if its dependency is missing or fails to
    # initialise. We deliberately tolerate any import-time failure here because
    # an unrelated optional protocol must never prevent SprayMaster from
    # starting; the user is informed via the "Unavailable" banner instead.
    import importlib

    try:
        mod = importlib.import_module(relative_module, package=__name__)
    except (ImportError, ModuleNotFoundError, OSError):
        return
    except Exception:  # noqa: BLE001 - optional plugin must not break startup
        return

    for key in registry_keys:
        PROTOCOL_REGISTRY[key] = mod.try_login


_load()
