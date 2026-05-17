import json as _json

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _parse_headers(headers_raw):
    if not headers_raw:
        return {}
    try:
        return _json.loads(headers_raw)
    except (_json.JSONDecodeError, TypeError):
        return {}


def _parse_form_body_as_params(body):
    return dict(
        pair.split("=", 1) for pair in body.split("&") if "=" in pair
    )


def _send_form_request(session, url, body, method, headers, request_kwargs):
    if method == "GET":
        return session.get(
            url, params=_parse_form_body_as_params(body), **request_kwargs
        )
    if "json" in headers.get("Content-Type", "").lower():
        return session.post(url, json=_json.loads(body), **request_kwargs)
    return session.post(url, data=body, **request_kwargs)


def _classify_form_response(resp, success_str, fail_str):
    if success_str:
        return "success" if success_str in resp.text else "fail"
    if fail_str:
        return "fail" if fail_str in resp.text else "success"
    return "success" if resp.status_code < 400 else "fail"


def try_login(host, username, password, args):
    proto = getattr(args, "protocol", "http")
    use_ssl = getattr(args, "ssl", False) or proto == "https"
    default_port = 443 if use_ssl else 80
    port = args.port or default_port
    timeout = getattr(args, "timeout", 10)
    path = getattr(args, "http_path", "/") or "/"
    method = (getattr(args, "http_method", "POST") or "POST").upper()
    form_data = getattr(args, "http_form_data", None)
    fail_str = getattr(args, "http_fail_string", None)
    success_str = getattr(args, "http_success_string", None)
    headers = _parse_headers(getattr(args, "http_headers", None))
    proxy_url = getattr(args, "proxy", None)
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    # SECURITY: TLS verification defaults to disabled because this tool is used
    # against authorized targets that commonly present self-signed / expired
    # certificates (lab environments, internal infra). Pass --verify-ssl to
    # enforce verification when auditing public-facing services.
    verify_ssl = getattr(args, "verify_ssl", False)

    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}{path}"
    result = {
        "status": "fail",
        "host": host,
        "port": port,
        "user": username,
        "pass": password,
        "protocol": proto,
        "error": None,
    }

    request_kwargs = {
        "headers": headers,
        "timeout": timeout,
        "verify": verify_ssl,
        "proxies": proxies,
        "allow_redirects": True,
    }

    try:
        session = requests.Session()
        if form_data:
            body = form_data.replace("^USER^", username).replace("^PASS^", password)
            resp = _send_form_request(
                session, url, body, method, headers, request_kwargs
            )
            result["status"] = _classify_form_response(resp, success_str, fail_str)
        else:
            resp = session.get(
                url,
                auth=HTTPBasicAuth(username, password),
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
                proxies=proxies,
            )
            result["status"] = "success" if resp.status_code == 200 else "fail"

    except requests.exceptions.ProxyError as e:
        result["status"] = "error"
        result["error"] = f"Proxy error: {e}"
    except requests.exceptions.ConnectionError as e:
        result["status"] = "error"
        result["error"] = str(e)
    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["error"] = "Connection timed out"
    except requests.exceptions.RequestException as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
