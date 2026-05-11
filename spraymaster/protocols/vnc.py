import socket
import struct
from Crypto.Cipher import DES  # requires pycryptodome


def _reverse_bits(b):
    return int(f"{b:08b}"[::-1], 2)


def _make_des_key(password):
    raw = (password.encode("utf-8") + b"\x00" * 8)[:8]
    return bytes(_reverse_bits(b) for b in raw)


def try_login(host, username, password, args):
    port = args.port if args.port else 5900
    timeout = getattr(args, "timeout", 10)
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "vnc",
        "error": None,
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))

        version = sock.recv(12)
        if not version.startswith(b"RFB "):
            raise ConnectionError("Not a VNC server")

        sock.sendall(b"RFB 003.003\n")

        sec_type = struct.unpack(">I", sock.recv(4))[0]

        if sec_type == 0:
            length = struct.unpack(">I", sock.recv(4))[0]
            msg = sock.recv(length).decode("utf-8", errors="replace")
            raise ConnectionError(f"Server refused connection: {msg}")
        elif sec_type == 1:
            result["status"] = "success"
        elif sec_type == 2:
            challenge = sock.recv(16)
            key = _make_des_key(password)
            cipher = DES.new(key, DES.MODE_ECB)
            response = cipher.encrypt(challenge[:8]) + cipher.encrypt(challenge[8:])
            sock.sendall(response)
            auth_result = struct.unpack(">I", sock.recv(4))[0]
            result["status"] = "success" if auth_result == 0 else "fail"
        else:
            raise NotImplementedError(f"Unsupported VNC security type: {sec_type}")

    except (ConnectionError, NotImplementedError) as e:
        if "refused" in str(e).lower() or "server" in str(e).lower():
            result["status"] = "error"
            result["error"] = str(e)
    except (socket.timeout, OSError) as e:
        result["status"] = "error"
        result["error"] = str(e)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result
