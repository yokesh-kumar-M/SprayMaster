import smtplib
import socket


def try_login(host, username, password, args):
    use_ssl = getattr(args, "ssl", False) or getattr(args, "protocol", "") == "smtps"
    port = args.port if args.port else (465 if use_ssl else 587)
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": getattr(args, "protocol", "smtp"),
        "error": None,
    }
    try:
        if use_ssl:
            smtp = smtplib.SMTP_SSL(host, port, timeout=timeout)
        else:
            smtp = smtplib.SMTP(host, port, timeout=timeout)
            try:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
            except smtplib.SMTPException:
                pass
        smtp.login(username, password)
        smtp.quit()
        result["status"] = "success"
    except smtplib.SMTPAuthenticationError:
        result["status"] = "fail"
    except (smtplib.SMTPException, socket.error, OSError) as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
