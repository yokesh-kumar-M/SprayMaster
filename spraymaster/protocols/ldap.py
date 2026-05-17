from ldap3 import SIMPLE, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError


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
        # auto_bind=False so we drive the bind ourselves; that way the success
        # path is explicit and we don't double-bind (which used to happen when
        # AUTO_BIND_NO_TLS plus a manual conn.bind() were combined).
        conn = Connection(
            server,
            user=username,
            password=password,
            authentication=SIMPLE,
            auto_bind=False,
            receive_timeout=timeout,
        )
        if conn.bind():
            result["status"] = "success"
        else:
            # bind() returns False on InvalidCredentials; result["result"] is 49.
            result["status"] = "fail"
        try:
            conn.unbind()
        except LDAPException:
            pass
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
