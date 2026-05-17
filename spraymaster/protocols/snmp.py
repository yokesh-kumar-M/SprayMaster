from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
)

_TRANSIENT_ERRORS = ("timeout", "no snmp", "unreachable", "no response")


def _probe(host, port, community, mp_model, timeout):
    """Run one SNMP GET; returns (status, error_text)."""
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=mp_model),
            UdpTransportTarget((host, port), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )
        error_indication, error_status, _idx, _binds = next(iterator)
    except (OSError, StopIteration) as e:
        return "error", str(e)

    if error_indication:
        err = str(error_indication).lower()
        if any(marker in err for marker in _TRANSIENT_ERRORS):
            return "error", str(error_indication)
        return "fail", None
    if error_status:
        return "fail", None
    return "success", None


def try_login(host, username, password, args):
    # SNMP "auth" is the community string; we try v2c first (the modern
    # default), and fall back to v1 only if v2c returns a transient/no-reply
    # error — many legacy switches accept only v1 and the agent on those
    # devices does not respond to v2c GetRequests at all.
    port = args.port if args.port else 161
    timeout = getattr(args, "timeout", 10)
    community = password
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": "snmp",
        "error": None,
    }

    status, error = _probe(host, port, community, mp_model=1, timeout=timeout)  # v2c
    if status == "error":
        # Retry with SNMPv1.
        status_v1, error_v1 = _probe(host, port, community, mp_model=0, timeout=timeout)
        if status_v1 in ("success", "fail"):
            status, error = status_v1, error_v1
        else:
            error = error_v1 or error

    result["status"] = status
    if status == "error":
        result["error"] = error
    return result
