import pymssql


def try_login(host, username, password, args):
    port = args.port if args.port else 1433
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "mssql",
        "error": None,
    }
    try:
        conn = pymssql.connect(
            server=host,
            port=str(port),
            user=username,
            password=password,
            database="master",
            login_timeout=timeout,
        )
        conn.close()
        result["status"] = "success"
    except pymssql.OperationalError as e:
        err = str(e).lower()
        if any(
            x in err for x in ["login failed", "password", "invalid", "authentication"]
        ):
            result["status"] = "fail"
        else:
            result["status"] = "error"
            result["error"] = str(e)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
