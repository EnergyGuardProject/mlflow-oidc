import base64
import hmac
import json
import os
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response


MLFLOW_UPSTREAM_URL = os.getenv("MLFLOW_UPSTREAM_URL", "https://mlflow.energy-guard.eu").rstrip("/")
ADMIN_GROUP_NAME = os.getenv("ADMIN_GROUP_NAME", "mlflow-admins")
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "60"))
KEYCLOAK_LOGOUT_CLIENT_ID = os.getenv("KEYCLOAK_LOGOUT_CLIENT_ID", "").strip()
KEYCLOAK_LOGOUT_ID_TOKEN_HEADER_CANDIDATES = tuple(
    header.strip().lower()
    for header in os.getenv(
        "KEYCLOAK_LOGOUT_ID_TOKEN_HEADER_CANDIDATES",
        "x-auth-request-id-token,x-forwarded-id-token,authorization",
    ).split(",")
    if header.strip()
)
KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME = os.getenv("KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME", "").strip()
MLFLOW_TRACKING_USERNAME = os.getenv("MLFLOW_TRACKING_USERNAME", "").strip()
MLFLOW_TRACKING_PASSWORD = os.getenv("MLFLOW_TRACKING_PASSWORD", "").strip()

ALL_METHODS = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
UI_PATHS = ("/oidc/ui", "/oidc/ui/")
BLOCKED_EXACT_PATHS = {
    "/api/2.0/mlflow/experiments/create",
    "/api/2.0/mlflow/experiments/update",
    "/api/2.0/mlflow/experiments/delete",
    "/api/2.0/mlflow/experiments/set-experiment-tag",
    "/ajax-api/2.0/mlflow/experiments/create",
    "/ajax-api/2.0/mlflow/experiments/update",
    "/ajax-api/2.0/mlflow/experiments/delete",
    "/ajax-api/2.0/mlflow/experiments/set-experiment-tag",
}
BLOCKED_PREFIXES = (
    "/api/2.0/mlflow/permissions/",
    "/ajax-api/2.0/mlflow/permissions/",
)

app = FastAPI(title="MLflow Role Proxy")


def _split_jwt(token: str) -> list[str]:
    parts = token.split(".")
    return parts if len(parts) == 3 else []

def _decode_basic_auth_credentials(request: Request) -> tuple[str, str] | None:
    raw_authorization = request.headers.get("authorization", "")
    scheme, _, encoded_credentials = raw_authorization.partition(" ")
    if scheme.lower() != "basic" or not encoded_credentials:
        return None
    try:
        decoded = base64.b64decode(encoded_credentials.strip()).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def _is_service_account_request(request: Request) -> bool:
    if not MLFLOW_TRACKING_USERNAME or not MLFLOW_TRACKING_PASSWORD:
        return False

    credentials = _decode_basic_auth_credentials(request)
    if not credentials:
        return False

    username, password = credentials
    return hmac.compare_digest(username, MLFLOW_TRACKING_USERNAME) and hmac.compare_digest(
        password, MLFLOW_TRACKING_PASSWORD
    )


def _decode_flask_session_payload(cookie_value: str) -> dict:
    if not cookie_value:
        return {}

    payload_segment = cookie_value.split(".", 1)[0].strip()
    if not payload_segment:
        return {}

    padding = "=" * (-len(payload_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_segment + padding).decode("utf-8")
        payload = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}

    return payload if isinstance(payload, dict) else {}


def _extract_session_username(request: Request) -> str:
    session_payload = _decode_flask_session_payload(request.cookies.get("session", ""))
    username = session_payload.get("username", "")
    return username.strip().lower() if isinstance(username, str) else ""


def _is_ui_request(path: str) -> bool:
    return path in UI_PATHS or path.startswith("/oidc/ui/")


def _is_blocked_for_non_admin(path: str) -> bool:
    # if _is_ui_request(path):
    #     return True
    if path in BLOCKED_EXACT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in BLOCKED_PREFIXES)


def _forbidden_message(path: str) -> str:
    # if _is_ui_request(path):
    #     return f"MLflow UI access is restricted to members of the {ADMIN_GROUP_NAME} Keycloak group."
    if path.startswith("/api/2.0/mlflow/permissions/") or path.startswith("/ajax-api/2.0/mlflow/permissions/"):
        return f"Permission management is restricted to members of the {ADMIN_GROUP_NAME} Keycloak group."
    return f"This MLflow action is restricted to members of the {ADMIN_GROUP_NAME} Keycloak group."


def _forbidden_api_response(path: str) -> Response:
    message = _forbidden_message(path)
    return JSONResponse(
        status_code=403,
        content={
            "error_code": "PERMISSION_DENIED",
            "message": message,
        },
        headers={"X-MLflow-Proxy-Error": message},
    )


def _inject_ui_error_overlay(html: str, message: str) -> str:
    message_json = json.dumps(message)
    overlay = f"""
<style>
  #eg-mlflow-denied {{
    position: fixed;
    inset: 0;
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: rgba(15, 23, 42, 0.72);
    font-family: Arial, sans-serif;
  }}
  #eg-mlflow-denied-card {{
    max-width: 680px;
    padding: 28px 32px;
    border-radius: 14px;
    background: #ffffff;
    color: #111827;
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.28);
  }}
  #eg-mlflow-denied-card h1 {{
    margin: 0 0 12px;
    font-size: 28px;
  }}
  #eg-mlflow-denied-card p {{
    margin: 0;
    line-height: 1.5;
    font-size: 16px;
  }}
</style>
<script>
  document.addEventListener("DOMContentLoaded", function () {{
    if (document.getElementById("eg-mlflow-denied")) {{
      return;
    }}
    document.documentElement.style.overflow = "hidden";
    var overlay = document.createElement("div");
    var card = document.createElement("div");
    var title = document.createElement("h1");
    var text = document.createElement("p");
    overlay.id = "eg-mlflow-denied";
    card.id = "eg-mlflow-denied-card";
    title.textContent = "Access denied";
    text.textContent = {message_json};
    card.appendChild(title);
    card.appendChild(text);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
  }});
</script>
""".strip()
    if "</body>" in html:
        return html.replace("</body>", f"{overlay}</body>", 1)
    return f"{html}{overlay}"


def _fallback_ui_html(message: str) -> str:
    return f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>MLflow</title>
  </head>
  <body>
    <div id="root"></div>
    {_inject_ui_error_overlay('', message)}
  </body>
</html>
""".strip()


def _build_upstream_headers(request: Request) -> dict[str, str]:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() != "content-length"
    }

    original_host = request.headers.get("host", "").strip()
    if original_host:
        headers["host"] = original_host
        headers.setdefault("x-forwarded-host", original_host)

        host_name, _, host_port = original_host.partition(":")
        if host_name:
            headers.setdefault("x-forwarded-server", host_name)
        if host_port:
            headers.setdefault("x-forwarded-port", host_port)
        else:
            proto = headers.get("x-forwarded-proto", request.url.scheme).lower()
            headers.setdefault("x-forwarded-port", "443" if proto == "https" else "80")

    headers.setdefault("x-forwarded-proto", request.url.scheme)
    return headers


async def _is_admin_api_call(request: Request, username) -> set[str]:
    users_url = httpx.URL(f"{MLFLOW_UPSTREAM_URL}/api/2.0/mlflow/users/{username}")
    headers = _build_upstream_headers(request)
    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            response = await client.get(users_url, headers=headers)
    except httpx.HTTPError:
        return set()

    print("response", response)
    if response.status_code != 200:
        return set()

    try:
        payload = response.json()
        print(payload)
        is_admin = payload['is_admin']
        print(is_admin)
    except json.JSONDecodeError:
        is_admin = False
    if not isinstance(payload, dict):
        is_admin = False

    return is_admin


async def _is_admin(request: Request) -> bool:
    session_username = _extract_session_username(request)
    print("session_username", session_username)
    if not session_username:
        return False

    if MLFLOW_TRACKING_USERNAME and session_username == MLFLOW_TRACKING_USERNAME.lower():
        return True

    return await _is_admin_api_call(request, session_username)


def _extract_logout_id_token(request: Request) -> str | None:
    for header_name in KEYCLOAK_LOGOUT_ID_TOKEN_HEADER_CANDIDATES:
        raw_value = request.headers.get(header_name)
        if not raw_value:
            continue
        if header_name == "authorization":
            scheme, _, token = raw_value.partition(" ")
            if scheme.lower() != "bearer" or not token:
                continue
            candidate = token.strip()
        else:
            candidate = raw_value.strip()

        if _split_jwt(candidate):
            return candidate

    if KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME:
        cookie_value = request.cookies.get(KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME, "").strip()
        if cookie_value and _split_jwt(cookie_value):
            return cookie_value

    return None


def _rewrite_logout_location(path: str, request: Request, headers: dict[str, str]) -> dict[str, str]:
    if path != "/logout":
        return headers

    location_key = next((key for key in headers if key.lower() == "location"), None)
    if not location_key:
        return headers

    location = headers[location_key]
    parsed = urlsplit(location)
    if "/protocol/openid-connect/logout" not in parsed.path:
        return headers

    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = {key for key, _ in query_items}
    if "id_token_hint" in query_keys:
        return headers
    if "post_logout_redirect_uri" not in query_keys:
        return headers

    id_token_hint = _extract_logout_id_token(request)
    if id_token_hint:
        query_items.append(("id_token_hint", id_token_hint))
    elif "client_id" not in query_keys and KEYCLOAK_LOGOUT_CLIENT_ID:
        query_items.append(("client_id", KEYCLOAK_LOGOUT_CLIENT_ID))
    else:
        return headers

    headers[location_key] = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query_items, doseq=True),
            parsed.fragment,
        )
    )
    return headers


async def _forbidden_ui_response(request: Request, path: str) -> Response:
    message = _forbidden_message(path)
    upstream_url = httpx.URL(f"{MLFLOW_UPSTREAM_URL}/{path.lstrip('/')}")
    if request.url.query:
        upstream_url = upstream_url.copy_with(query=request.url.query.encode("utf-8"))

    headers = _build_upstream_headers(request)

    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
    html = None
    content_type = "text/html; charset=utf-8"

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            upstream_response = await client.get(upstream_url, headers=headers)
        upstream_content_type = upstream_response.headers.get("content-type", "")
        if upstream_response.content and "text/html" in upstream_content_type.lower():
            html = upstream_response.text
            content_type = upstream_content_type
    except httpx.HTTPError:
        html = None

    if html is None:
        html = _fallback_ui_html(message)
    else:
        html = _inject_ui_error_overlay(html, message)

    return HTMLResponse(
        content=html,
        status_code=403,
        headers={"X-MLflow-Proxy-Error": message},
        media_type=content_type.split(";", 1)[0],
    )


async def _forward_request(request: Request, path: str) -> Response:
    upstream_url = httpx.URL(f"{MLFLOW_UPSTREAM_URL}/{path.lstrip('/')}")
    query_string = request.url.query.encode("utf-8")
    if query_string:
        upstream_url = upstream_url.copy_with(query=query_string)

    body = await request.body()
    headers = _build_upstream_headers(request)

    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            content=body,
            headers=headers,
        )

    response_headers = {
        key: value
        for key, value in upstream_response.headers.items()
        if key.lower() not in {"content-encoding", "content-length", "transfer-encoding", "connection"}
    }
    response_headers = _rewrite_logout_location(path, request, response_headers)
    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )


@app.get("/healthz")
async def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=ALL_METHODS)
async def proxy(path: str, request: Request) -> Response:
    normalized_path = "/" + path.lstrip("/")

    if _is_blocked_for_non_admin(normalized_path) and not _is_service_account_request(request) and not await _is_admin(
        request
    ):
        if _is_ui_request(normalized_path):
            return await _forbidden_ui_response(request, normalized_path)
        return _forbidden_api_response(normalized_path)

    return await _forward_request(request, normalized_path)
