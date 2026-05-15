import json as _json
import urllib3
import requests
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def try_login(host, username, password, args):
    proto = getattr(args, "protocol", "http")
    use_ssl = getattr(args, "ssl", False) or proto == "https"
    default_port = 443 if use_ssl else 80
    port = args.port if args.port else default_port
    timeout = getattr(args, "timeout", 10)
    path = getattr(args, "http_path", "/") or "/"
    method = (getattr(args, "http_method", "POST") or "POST").upper()
    form_data = getattr(args, "http_form_data", None)
    fail_str = getattr(args, "http_fail_string", None)
    success_str = getattr(args, "http_success_string", None)
    headers_raw = getattr(args, "http_headers", None)
    proxy_url = getattr(args, "proxy", None)

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

    headers = {}
    if headers_raw:
        try:
            headers = _json.loads(headers_raw)
        except (_json.JSONDecodeError, TypeError):
            headers = {}

    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    try:
        session = requests.Session()

        if form_data:
            body = form_data.replace("^USER^", username).replace("^PASS^", password)
            if method == "GET":
                params = {
                    k: v
                    for k, v in (
                        pair.split("=", 1)
                        for pair in body.split("&")
                        if "=" in pair
                    )
                }
                resp = session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                    proxies=proxies,
                    allow_redirects=True,
                )
            else:
                ct = headers.get("Content-Type", "").lower()
                if "json" in ct:
                    resp = session.post(
                        url,
                        json=_json.loads(body),
                        headers=headers,
                        timeout=timeout,
                        verify=False,
                        proxies=proxies,
                        allow_redirects=True,
                    )
                else:
                    resp = session.post(
                        url,
                        data=body,
                        headers=headers,
                        timeout=timeout,
                        verify=False,
                        proxies=proxies,
                        allow_redirects=True,
                    )

            if success_str:
                result["status"] = "success" if success_str in resp.text else "fail"
            elif fail_str:
                result["status"] = "fail" if fail_str in resp.text else "success"
            else:
                result["status"] = "success" if resp.status_code < 400 else "fail"
        else:
            resp = session.get(
                url,
                auth=HTTPBasicAuth(username, password),
                headers=headers,
                timeout=timeout,
                verify=False,
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
