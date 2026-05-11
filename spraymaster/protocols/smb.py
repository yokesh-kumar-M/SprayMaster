from impacket.smbconnection import SMBConnection


def try_login(host, username, password, args):
    port = args.port if args.port else 445
    timeout = getattr(args, "timeout", 10)
    domain = getattr(args, "smb_domain", "") or ""

    user = username
    if "\\" in username:
        domain, user = username.split("\\", 1)

    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "smb",
        "error": None,
    }
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        conn.login(user, password, domain=domain)
        conn.logoff()
        result["status"] = "success"
    except Exception as e:
        err = str(e).lower()
        if any(
            x in err
            for x in [
                "status_logon_failure",
                "wrong password",
                "access_denied",
                "invalid credentials",
                "authentication_failed",
            ]
        ):
            result["status"] = "fail"
        elif any(x in err for x in ["connection", "timeout", "refused", "unreachable"]):
            result["status"] = "error"
            result["error"] = str(e)
        else:
            result["status"] = "fail"
    return result
