import socket
import time


def _handle_negotiation(sock, data):
    IAC, WILL, WONT, DO, DONT = 0xFF, 0xFB, 0xFC, 0xFD, 0xFE
    i, clean = 0, b""
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            cmd, opt = data[i + 1], data[i + 2]
            if cmd == WILL:
                sock.sendall(bytes([IAC, DONT, opt]))
            elif cmd == DO:
                sock.sendall(bytes([IAC, WONT, opt]))
            i += 3
        else:
            clean += bytes([data[i]])
            i += 1
    return clean


def _recv_until(sock, keywords, timeout):
    buf, end = b"", time.time() + timeout
    while time.time() < end:
        sock.settimeout(min(1.0, end - time.time()))
        try:
            chunk = sock.recv(2048)
            if not chunk:
                break
            buf += chunk
            lower = buf.lower()
            if any(k in lower for k in keywords):
                break
        except socket.timeout:
            break
    return buf


def try_login(host, username, password, args):
    port = args.port if args.port else 23
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "telnet",
        "error": None,
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))

        raw = _recv_until(sock, [b"login:", b"username:", b"user:"], timeout)
        _handle_negotiation(sock, raw)

        sock.sendall(username.encode("utf-8") + b"\r\n")

        _recv_until(sock, [b"password:", b"passwd:"], timeout)
        sock.sendall(password.encode("utf-8") + b"\r\n")

        raw = _recv_until(
            sock,
            [
                b"$",
                b"#",
                b">",
                b"%",
                b"last login",
                b"welcome",
                b"incorrect",
                b"failed",
                b"denied",
                b"invalid",
            ],
            4,
        )
        resp = raw.decode("utf-8", errors="ignore").lower()

        success_signs = ["$ ", "# ", "> ", "% ", "last login", "welcome", "logged in"]
        fail_signs = [
            "login incorrect",
            "authentication failed",
            "access denied",
            "invalid password",
            "login failed",
            "bad password",
        ]

        if any(s in resp for s in success_signs):
            result["status"] = "success"
        elif any(s in resp for s in fail_signs):
            result["status"] = "fail"
        # else: stays "fail" by default
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        result["status"] = "error"
        result["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return result
