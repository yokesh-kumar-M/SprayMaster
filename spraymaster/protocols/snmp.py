from pysnmp.hlapi import (
    getCmd,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
)


def try_login(host, username, password, args):
    # For SNMP v1/v2c, 'password' is the community string; username is ignored
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
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0),
            UdpTransportTarget((host, port), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            err = str(error_indication).lower()
            if "timeout" in err or "no snmp" in err or "unreachable" in err:
                result["status"] = "error"
                result["error"] = str(error_indication)
            else:
                result["status"] = "fail"
        elif error_status:
            result["status"] = "fail"
        else:
            result["status"] = "success"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
