import imaplib


def try_login(host, username, password, args):
    use_ssl = getattr(args, "ssl", False) or getattr(args, "protocol", "") == "imaps"
    default_port = 993 if use_ssl else 143
    port = args.port if args.port else default_port
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": getattr(args, "protocol", "imap"),
        "error": None,
    }
    try:
        if use_ssl:
            imap = imaplib.IMAP4_SSL(host, port)
        else:
            imap = imaplib.IMAP4(host, port)
        imap.socket().settimeout(timeout)
        imap.login(username, password)
        imap.logout()
        result["status"] = "success"
    except imaplib.IMAP4.error as e:
        err = str(e).lower()
        if any(
            x in err
            for x in [
                "authentication",
                "invalid",
                "authenticationfailed",
                "credentials",
                "denied",
            ]
        ):
            result["status"] = "fail"
        else:
            result["status"] = "error"
            result["error"] = str(e)
    except OSError as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
