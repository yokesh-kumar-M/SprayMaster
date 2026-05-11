import psycopg2
import psycopg2.extras


def try_login(host, username, password, args):
    port = args.port if args.port else 5432
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "postgres",
        "error": None,
    }
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            dbname="postgres",
            connect_timeout=timeout,
        )
        conn.close()
        result["status"] = "success"
    except psycopg2.OperationalError as e:
        err = str(e).lower()
        if any(
            x in err
            for x in [
                "authentication failed",
                "password authentication",
                "no pg_hba.conf",
                "invalid password",
                "role",
            ]
        ):
            result["status"] = "fail"
        else:
            result["status"] = "error"
            result["error"] = str(e)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
