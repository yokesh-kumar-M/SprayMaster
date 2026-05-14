import socket
import struct

# NOTE: DES in ECB mode is intentionally used here because the VNC RFB
# protocol (RFC 6143, section 7.2.2) MANDATES it for the VNC Authentication
# security type. Replacing it with a modern cipher would break interoperability
# with every VNC server in existence. This is a wire-format requirement, not
# an application choice, and the secret transmitted is a one-shot 16-byte
# server challenge — not user data. Static analyzers should treat the following
# imports and Cipher calls as protocol-required and not as a vulnerability.
from Crypto.Cipher import DES  # noqa: S413  # nosec B413 - required by VNC RFB protocol


def _reverse_bits(byte):
    return int(f"{byte:08b}"[::-1], 2)


def _make_des_key(password):
    # VNC keys are exactly 8 bytes, padded with NULs, with each byte bit-reversed
    # — also part of the RFB authentication spec.
    raw = (password.encode("utf-8") + b"\x00" * 8)[:8]
    return bytes(_reverse_bits(b) for b in raw)


def _vnc_encrypt(challenge, password):
    key = _make_des_key(password)
    # DES-ECB is the cipher mandated by RFB §7.2.2. See module docstring above.
    cipher = DES.new(key, DES.MODE_ECB)  # noqa: S305  # nosec B305 - protocol-mandated
    return cipher.encrypt(challenge[:8]) + cipher.encrypt(challenge[8:])


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
            sock.sendall(_vnc_encrypt(challenge, password))
            auth_result = struct.unpack(">I", sock.recv(4))[0]
            result["status"] = "success" if auth_result == 0 else "fail"
        else:
            raise NotImplementedError(f"Unsupported VNC security type: {sec_type}")

    except (ConnectionError, NotImplementedError) as e:
        if "refused" in str(e).lower() or "server" in str(e).lower():
            result["status"] = "error"
            result["error"] = str(e)
    except (socket.timeout, OSError, struct.error) as e:
        result["status"] = "error"
        result["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return result
