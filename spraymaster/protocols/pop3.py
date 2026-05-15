import poplib


def try_login(host, username, password, args):
    use_ssl = getattr(args, "ssl", False) or getattr(args, "protocol", "") == "pop3s"
    default_port = 995 if use_ssl else 110
    port = args.port if args.port else default_port
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": getattr(args, "protocol", "pop3"),
        "error": None,
    }
    try:
        if use_ssl:
            pop = poplib.POP3_SSL(host, port, timeout=timeout)
        else:
            pop = poplib.POP3(host, port, timeout=timeout)
        pop.user(username)
        pop.pass_(password)
        pop.quit()
        result["status"] = "success"
    except poplib.error_proto as e:
        err = str(e).lower()
        if any(
            x in err for x in ["-err", "invalid", "authentication", "wrong", "denied"]
        ):
            result["status"] = "fail"
        else:
            result["status"] = "error"
            result["error"] = str(e)
    except OSError as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
