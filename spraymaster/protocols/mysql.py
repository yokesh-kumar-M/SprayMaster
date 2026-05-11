import pymysql
import pymysql.err


def try_login(host, username, password, args):
    port = args.port if args.port else 3306
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "mysql",
        "error": None,
    }
    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout,
        )
        conn.close()
        result["status"] = "success"
    except pymysql.err.OperationalError as e:
        code = e.args[0]
        if code in (1045, 1044, 1698):  # Access denied / auth errors
            result["status"] = "fail"
        else:
            result["status"] = "error"
            result["error"] = str(e)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
