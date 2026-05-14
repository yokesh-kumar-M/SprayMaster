import ftplib
import socket


def try_login(host, username, password, args):
    use_ssl = getattr(args, "ssl", False) or getattr(args, "protocol", "") == "ftps"
    port = args.port if args.port else 21
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": getattr(args, "protocol", "ftp"),
        "error": None,
    }
    try:
        if use_ssl:
            ftp = ftplib.FTP_TLS()
            ftp.connect(host, port, timeout=timeout)
            ftp.auth()
            ftp.prot_p()
        else:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        result["status"] = "success"
        ftp.quit()
    except ftplib.error_perm:
        result["status"] = "fail"
    except ftplib.all_errors as e:
        result["status"] = "error"
        result["error"] = str(e)
    except (socket.error, OSError) as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
