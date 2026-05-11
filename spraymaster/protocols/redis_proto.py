import redis as redis_lib
from redis.exceptions import (
    AuthenticationError,
    ConnectionError as RedisConnError,
    ResponseError,
)


def try_login(host, username, password, args):
    port = args.port if args.port else 6379
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "redis",
        "error": None,
    }
    try:
        r = redis_lib.Redis(
            host=host,
            port=port,
            password=password,
            socket_timeout=timeout,
            socket_connect_timeout=timeout,
        )
        r.ping()
        r.close()
        result["status"] = "success"
    except AuthenticationError:
        result["status"] = "fail"
    except ResponseError as e:
        err = str(e).lower()
        if "auth" in err or "password" in err or "wrong" in err:
            result["status"] = "fail"
        else:
            result["status"] = "error"
            result["error"] = str(e)
    except RedisConnError as e:
        result["status"] = "error"
        result["error"] = str(e)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
