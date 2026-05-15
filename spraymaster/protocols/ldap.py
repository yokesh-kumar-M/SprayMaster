from ldap3 import Server, Connection, SIMPLE, AUTO_BIND_NO_TLS
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError, LDAPException


def try_login(host, username, password, args):
    use_ssl = getattr(args, "ssl", False) or getattr(args, "protocol", "") == "ldaps"
    default_port = 636 if use_ssl else 389
    port = args.port if args.port else default_port
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": getattr(args, "protocol", "ldap"),
        "error": None,
    }
    try:
        server = Server(host, port=port, use_ssl=use_ssl, connect_timeout=timeout)
        conn = Connection(
            server,
            user=username,
            password=password,
            authentication=SIMPLE,
            auto_bind=AUTO_BIND_NO_TLS,
        )
        conn.bind()
        if conn.result["result"] == 0:
            result["status"] = "success"
        else:
            result["status"] = "fail"
        conn.unbind()
    except LDAPBindError:
        result["status"] = "fail"
    except LDAPSocketOpenError as e:
        result["status"] = "error"
        result["error"] = str(e)
    except LDAPException as e:
        err = str(e).lower()
        if "invalidcredentials" in err or "49" in err:
            result["status"] = "fail"
        else:
            result["status"] = "error"
            result["error"] = str(e)
    return result
