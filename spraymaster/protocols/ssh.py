import paramiko


def try_login(host, username, password, args):
    port = args.port if args.port else 22
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "ssh",
        "error": None,
    }
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        result["status"] = "success"
    except paramiko.AuthenticationException:
        result["status"] = "fail"
    except (paramiko.SSHException, OSError, EOFError) as e:
        result["status"] = "error"
        result["error"] = str(e)
    finally:
        client.close()
    return result
